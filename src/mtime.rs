//! Modification times, from the most precise source a central directory
//! entry records:
//!
//! 1. the NTFS extra field (0x000A): a FILETIME, UTC, 100 ns;
//! 2. the Info-ZIP extended timestamp (0x5455, "UT"): Unix seconds, UTC;
//! 3. the MS-DOS date and time: the zipping machine's wall clock, zone
//!    unknown, 2 s.
//!
//! A source that is missing, malformed, zero or not a valid date falls
//! through to the next. When a field appears more than once, the last
//! well-formed one counts, as with Info-ZIP's `zipinfo`.
//!
//! [`Encoded`] is the other direction, for the writer.

use common::bytes::Reader;
use common::time::{civil_from_days, Semantic, Ts, TICKS_PER_DAY, TICKS_PER_SECOND};

const NTFS_ID: u16 = 0x000a;
/// NTFS attribute holding the modification, access and creation times.
const NTFS_TIMES_TAG: u16 = 0x0001;
const EXTENDED_TIMESTAMP_ID: u16 = 0x5455;
/// Extended-timestamp flag: a modification time follows.
const MTIME_PRESENT: u8 = 0x01;
/// NTFS extra field data: 4 reserved bytes, then the times attribute.
const NTFS_SIZE: u16 = 4 + 4 + NTFS_TIMES_SIZE;
/// NTFS times attribute: modification, access and creation FILETIMEs.
const NTFS_TIMES_SIZE: u16 = 24;
/// Extended timestamp data: the flags, then the modification time.
const EXTENDED_TIMESTAMP_SIZE: u16 = 1 + 4;
/// 100 ns ticks from 1601-01-01 (the FILETIME epoch) to 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;
/// The earliest DOS date and time: 1980-01-01 00:00:00.
const DOS_FIRST: (u16, u16) = dos_fields(1980, 1, 1, 0, 0, 0);
/// The latest DOS date and time: 2107-12-31 23:59:58.
const DOS_LAST: (u16, u16) = dos_fields(2107, 12, 31, 23, 59, 58);

/// The modification time recorded by an entry's `extra` field and DOS
/// `date` and `time`, or `None` when none of them is a valid time.
pub(crate) fn parse(extra: &[u8], date: u16, time: u16) -> Option<Ts> {
    let mut ntfs = None;
    let mut unix = None;
    for (id, field) in fields(extra) {
        match id {
            NTFS_ID => ntfs = ntfs_mtime(field).or(ntfs),
            EXTENDED_TIMESTAMP_ID => unix = extended_mtime(field).or(unix),
            _ => {}
        }
    }
    ntfs.or(unix).or_else(|| valid(Ts::from_dos(date, time)))
}

/// Each extra field's ID and data, up to the first truncated one.
fn fields(extra: &[u8]) -> impl Iterator<Item = (u16, Reader<'_>)> {
    let mut r = Reader::new(extra);
    std::iter::from_fn(move || {
        let id = r.u16_le().ok()?;
        let length = usize::from(r.u16_le().ok()?);
        Some((id, r.sub(length).ok()?))
    })
}

/// An NTFS extra field: 4 reserved bytes, then tagged attributes.
fn ntfs_mtime(mut field: Reader<'_>) -> Option<Ts> {
    field.skip(4).ok()?;
    loop {
        let tag = field.u16_le().ok()?;
        let size = usize::from(field.u16_le().ok()?);
        let mut attribute = field.sub(size).ok()?;
        if tag == NTFS_TIMES_TAG {
            return valid(Ts::from_filetime(attribute.u64_le().ok()?));
        }
    }
}

/// An extended timestamp: flags, then (in the central directory) only the
/// modification time, as unsigned Unix seconds.
fn extended_mtime(mut field: Reader<'_>) -> Option<Ts> {
    if field.u8().ok()? & MTIME_PRESENT == 0 {
        return None;
    }
    valid(Ts::from_unix_seconds(i64::from(field.u32_le().ok()?)))
}

/// `ts` when it is a time: not zero, a sentinel or an impossible date.
fn valid(ts: Ts) -> Option<Ts> {
    ts.ticks().is_some().then_some(ts)
}

/// A modification time as a writer records it in an entry's DOS fields and
/// extra field: the same in the local header and the central directory.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Encoded {
    pub(crate) date: u16,
    pub(crate) time: u16,
    filetime: Option<u64>,
    unix_seconds: Option<u32>,
}

impl Encoded {
    /// A UTC time goes in the NTFS extra field, in the extended timestamp
    /// when it is in 1970–2038 (where signed and unsigned readers agree), and
    /// in the DOS fields as a UTC wall clock. A local time of unknown zone
    /// goes only in the DOS fields, which have that meaning. No time, or a
    /// value that is not one, is DOS 1980-01-01 00:00:00 and no extra field.
    pub(crate) fn new(modified: Option<Ts>) -> Self {
        let wall_clock = modified.and_then(|ts| ts.ticks());
        let utc = modified
            .filter(|ts| ts.semantic() == Semantic::Utc)
            .and_then(|ts| ts.ticks());
        let (date, time) = wall_clock.map_or(DOS_FIRST, dos);
        Self {
            date,
            time,
            filetime: utc.and_then(filetime),
            unix_seconds: utc.and_then(unix_seconds),
        }
    }

    /// The extra fields recording the time, if any.
    pub(crate) fn extra(&self) -> Vec<u8> {
        let ntfs = self.filetime.map(|filetime| {
            [
                &NTFS_ID.to_le_bytes()[..],
                &NTFS_SIZE.to_le_bytes(),
                &[0; 4], // reserved
                &NTFS_TIMES_TAG.to_le_bytes(),
                &NTFS_TIMES_SIZE.to_le_bytes(),
                &filetime.to_le_bytes(),
                &[0; 16], // access and creation times: not known, so not set
            ]
            .concat()
        });
        let extended = self.unix_seconds.map(|seconds| {
            [
                &EXTENDED_TIMESTAMP_ID.to_le_bytes()[..],
                &EXTENDED_TIMESTAMP_SIZE.to_le_bytes(),
                &[MTIME_PRESENT],
                &seconds.to_le_bytes(),
            ]
            .concat()
        });
        ntfs.into_iter().chain(extended).flatten().collect()
    }
}

/// The DOS date and time of a wall clock `ticks` past 1970-01-01, rounded
/// down to 2 s and clamped to the years DOS can hold (1980–2107).
fn dos(ticks: i64) -> (u16, u16) {
    let (year, month, day) = civil_from_days(ticks.div_euclid(TICKS_PER_DAY));
    if year < 1980 {
        return DOS_FIRST;
    }
    if year > 2107 {
        return DOS_LAST;
    }
    let seconds = ticks.rem_euclid(TICKS_PER_DAY) / TICKS_PER_SECOND;
    dos_fields(
        year as u16,
        month as u16,
        day as u16,
        (seconds / 3600) as u16,
        (seconds / 60 % 60) as u16,
        (seconds % 60) as u16,
    )
}

/// The DOS date and time words of a wall clock in 1980–2107, to 2 s.
const fn dos_fields(
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
) -> (u16, u16) {
    (
        ((year - 1980) << 9) | (month << 5) | day,
        (hour << 11) | (minute << 5) | (second / 2),
    )
}

/// The FILETIME of a UTC `ticks`, unless it would read back as no time
/// (before 1601, zero or the sentinel).
fn filetime(ticks: i64) -> Option<u64> {
    ticks
        .checked_add(FILETIME_UNIX_OFFSET)
        .filter(|&filetime| filetime > 0 && filetime != i64::MAX)
        .map(|filetime| filetime as u64)
}

/// The Unix seconds of a UTC `ticks`, rounded down, when they are positive
/// and fit a signed 32-bit field.
fn unix_seconds(ticks: i64) -> Option<u32> {
    i32::try_from(ticks.div_euclid(TICKS_PER_SECOND))
        .ok()
        .filter(|&seconds| seconds > 0)
        .map(|seconds| seconds as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::time::Precision;
    use proptest::prelude::*;

    /// DOS 2020-01-02 03:04:06.
    const DATE: u16 = (40 << 9) | (1 << 5) | 2;
    const TIME: u16 = (3 << 11) | (4 << 5) | 3;

    #[test]
    fn a_field_overrunning_the_extra_data_falls_back_to_dos() {
        let extra = [0x55, 0x54, 0xff, 0xff, 1, 0, 0, 0, 0x60];
        let ts = parse(&extra, DATE, TIME).unwrap();
        assert_eq!(ts.to_string(), "2020-01-02T03:04:06.0000000");
    }

    #[test]
    fn nothing_valid_is_none() {
        assert_eq!(parse(&[], 0, 0), None);
        assert_eq!(parse(&[0x55, 0x54, 1, 0, 1], 0, 0), None);
    }

    /// The time an entry written with `modified` reads back as.
    fn round_trip(modified: Option<Ts>) -> Option<Ts> {
        let encoded = Encoded::new(modified);
        parse(&encoded.extra(), encoded.date, encoded.time)
    }

    #[test]
    fn no_time_is_the_first_dos_time() {
        let none = round_trip(None).unwrap();
        assert_eq!(none.to_string(), "1980-01-01T00:00:00.0000000");
        assert!(Encoded::new(None).extra().is_empty());
        assert_eq!(round_trip(Some(Ts::from_filetime(0))), Some(none));
    }

    #[test]
    fn utc_goes_in_the_dos_fields_as_the_wall_clock_rounded_down() {
        let encoded = Encoded::new(Some(Ts::from_unix_seconds(1_577_934_247)));
        assert_eq!((encoded.date, encoded.time), (DATE, TIME));
    }

    #[test]
    fn a_local_time_goes_only_in_the_dos_fields() {
        let ticks = 1_577_934_247 * TICKS_PER_SECOND + 5_000_000;
        let local = Ts::from_local_ticks(ticks, Precision::Tick);
        assert!(Encoded::new(Some(local)).extra().is_empty());
        let read = round_trip(Some(local)).unwrap();
        assert_eq!(read.to_string(), "2020-01-02T03:04:06.0000000");
    }

    #[test]
    fn dos_fields_are_clamped_to_their_years() {
        assert_eq!(dos(i64::MIN), DOS_FIRST);
        assert_eq!(dos(-TICKS_PER_SECOND), DOS_FIRST);
        assert_eq!(dos(i64::MAX), DOS_LAST);
        let last = Ts::from_dos(DOS_LAST.0, DOS_LAST.1).to_string();
        assert_eq!(last, "2107-12-31T23:59:58.0000000");
    }

    #[test]
    fn the_extended_timestamp_is_left_out_beyond_2038() {
        let ts = Ts::from_unix_seconds(i64::from(i32::MAX) + 1);
        assert_eq!(Encoded::new(Some(ts)).unix_seconds, None);
        assert_eq!(
            round_trip(Some(ts)),
            Some(Ts::from_ticks(ts.ticks().unwrap(), Precision::Tick))
        );
    }

    /// Time fields (and others) with random data and declared lengths that
    /// may overrun it.
    fn hostile_extra() -> impl Strategy<Value = Vec<u8>> {
        let id = prop_oneof![Just(NTFS_ID), Just(EXTENDED_TIMESTAMP_ID), any::<u16>()];
        let field = (id, 0..48u16, proptest::collection::vec(any::<u8>(), 0..40));
        proptest::collection::vec(field, 0..6).prop_map(|fields| {
            fields
                .into_iter()
                .flat_map(|(id, length, data)| {
                    [id.to_le_bytes(), length.to_le_bytes()]
                        .concat()
                        .into_iter()
                        .chain(data)
                })
                .collect()
        })
    }

    proptest! {
        #[test]
        fn hostile_extra_fields_never_panic(extra in hostile_extra(), date in any::<u16>(), time in any::<u16>()) {
            let _ = parse(&extra, date, time);
        }

        #[test]
        fn utc_times_read_back_to_100_ns(ticks in -FILETIME_UNIX_OFFSET + 1..i64::MAX - FILETIME_UNIX_OFFSET) {
            let ts = Ts::from_ticks(ticks, Precision::Tick);
            prop_assert_eq!(round_trip(Some(ts)), Some(ts));
        }
    }
}
