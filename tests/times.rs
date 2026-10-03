//! Modification times from archives written by Info-ZIP (extended
//! timestamp), 7-Zip (NTFS extra field) and Python's zipfile (DOS fields
//! only, invalid dates, hostile extra fields). See `fixtures/make-times.sh`.

use std::io::Cursor;

use common::time::{Precision, Semantic, Ts};
use sootmark_zip::Archive;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

/// Each entry's name and modification time.
fn times(name: &str) -> Vec<(String, Option<Ts>)> {
    let archive = Archive::open(Cursor::new(fixture(name))).unwrap();
    archive
        .entries()
        .iter()
        .map(|e| (e.name.clone(), e.modified))
        .collect()
}

/// Each entry's name and modification time in ISO 8601 (no `Z`: local time
/// in an unknown zone).
fn iso_times(name: &str) -> Vec<(String, Option<String>)> {
    times(name)
        .into_iter()
        .map(|(name, ts)| (name, ts.map(|ts| ts.to_string())))
        .collect()
}

/// The first entry's modification time.
fn first_time(name: &str) -> Ts {
    times(name)[0].1.expect("a time")
}

fn expected(times: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
    times
        .iter()
        .map(|(name, iso)| ((*name).to_owned(), iso.map(str::to_owned)))
        .collect()
}

#[test]
fn ntfs_times_from_7zip_are_utc_to_100_ns() {
    assert_eq!(
        iso_times("times-7zip-ntfs.zip"),
        expected(&[
            ("a.txt", Some("2021-03-04T05:06:07.1234567Z")),
            ("b.txt", Some("1999-12-31T23:59:58.0000000Z")),
        ])
    );
    let ts = first_time("times-7zip-ntfs.zip");
    assert_eq!(ts.semantic(), Semantic::Utc);
    assert_eq!(ts.precision(), Precision::Tick);
}

#[test]
fn extended_timestamps_from_info_zip_are_utc_to_the_second() {
    assert_eq!(
        iso_times("times-infozip.zip"),
        expected(&[
            ("a.txt", Some("2021-03-04T05:06:07.0000000Z")),
            ("b.txt", Some("1999-12-31T23:59:58.0000000Z")),
        ])
    );
    let ts = first_time("times-infozip.zip");
    assert_eq!(ts.semantic(), Semantic::Utc);
    assert_eq!(ts.precision(), Precision::Second);
}

#[test]
fn dos_times_are_local_to_an_unknown_zone() {
    // Zipped in Europe/Paris (UTC+1): the wall clock, not UTC.
    assert_eq!(
        iso_times("times-python-dos.zip"),
        expected(&[
            ("a.txt", Some("2021-03-04T06:06:06.0000000")),
            ("b.txt", Some("2000-01-01T00:59:58.0000000")),
        ])
    );
    let ts = first_time("times-python-dos.zip");
    assert_eq!(ts.semantic(), Semantic::LocalUnknownZone);
    assert_eq!(ts.precision(), Precision::TwoSeconds);
    assert_eq!(
        ts.assume_offset(60).to_string(),
        "2021-03-04T05:06:06.0000000Z"
    );
}

#[test]
fn invalid_or_zero_dos_dates_are_no_time() {
    assert_eq!(
        iso_times("times-invalid-dos.zip"),
        expected(&[
            ("month-13.txt", None),
            ("february-30.txt", None),
            ("hour-25.txt", None),
            ("zero.txt", None),
        ])
    );
}

#[test]
fn malformed_extra_fields_fall_through_to_the_next_source() {
    const DOS: Option<&str> = Some("2020-01-02T03:04:06.0000000");
    const UT: Option<&str> = Some("2020-09-13T12:26:40.0000000Z");
    assert_eq!(
        iso_times("times-malformed-extra.zip"),
        expected(&[
            ("ntfs-truncated-attribute.txt", UT),
            ("ntfs-attribute-overrun.txt", DOS),
            ("ntfs-zero.txt", UT),
            ("ntfs-sentinel.txt", DOS),
            (
                "ntfs-other-tag-first.txt",
                Some("2020-09-13T12:26:40.0000001Z")
            ),
            ("ut-then-ntfs.txt", Some("2020-09-13T12:26:40.0000000Z")),
            ("ut-without-mtime.txt", DOS),
            ("ut-flag-clear.txt", DOS),
            ("ut-zero.txt", DOS),
            ("duplicate-ut.txt", Some("2023-11-14T22:13:20.0000000Z")),
            ("trailing-bytes.txt", UT),
        ])
    );
}
