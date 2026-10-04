//! Archives written by [`Writer`] and read back by [`Archive`]: names,
//! sizes, CRC-32, contents and modification times survive; hostile names,
//! failing reads and failing writes are handled.

use std::io::{self, Cursor, Read, Write};

use common::checksum::Crc32;
use common::time::{Precision, Ts, TICKS_PER_SECOND};
use proptest::prelude::*;
use sootmark_zip::write::{Entry, Truncated};
use sootmark_zip::{Archive, Writer};

/// An entry to write: name, modification time, content.
type Input = (String, Option<Ts>, Vec<u8>);

/// `length` bytes that don't repeat with the copy buffer.
fn pseudo_random(length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn write(inputs: &[Input]) -> (Vec<u8>, Vec<Entry>) {
    let mut writer = Writer::new(Vec::new());
    let entries = inputs
        .iter()
        .map(|(name, modified, content)| writer.add(name, *modified, &mut content.as_slice()))
        .collect::<io::Result<_>>()
        .unwrap();
    (writer.finish().unwrap(), entries)
}

/// Each entry's name, modification time and content, reading every entry
/// to its end (which verifies its size and CRC-32).
fn read(bytes: Vec<u8>) -> Vec<Input> {
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    let listed: Vec<_> = archive
        .entries()
        .iter()
        .map(|e| (e.name.clone(), e.modified))
        .collect();
    listed
        .into_iter()
        .enumerate()
        .map(|(index, (name, modified))| {
            let mut content = Vec::new();
            archive
                .reader(index)
                .unwrap()
                .read_to_end(&mut content)
                .unwrap();
            (name, modified, content)
        })
        .collect()
}

/// 2021-03-04T05:06:07.1234567Z.
fn utc() -> Ts {
    Ts::from_ticks(
        1_614_834_367 * TICKS_PER_SECOND + 1_234_567,
        Precision::Tick,
    )
}

fn samples() -> Vec<Input> {
    vec![
        (
            "C/Windows/System32/winevt/Logs/Security.evtx".to_owned(),
            Some(utc()),
            pseudo_random(200_000),
        ),
        ("empty".to_owned(), None, Vec::new()),
        (
            "C/$Extend/$UsnJrnl:$J".to_owned(),
            Some(utc()),
            pseudo_random(1 << 16),
        ),
        (
            "Users/Zoë/桌面/notes.txt".to_owned(),
            Some(utc()),
            b"hello\n".to_vec(),
        ),
    ]
}

#[test]
fn entries_read_back_with_their_names_contents_and_times() {
    let inputs = samples();
    let (bytes, entries) = write(&inputs);
    let mut expected = inputs.clone();
    // No time reads back as the DOS fields' 1980-01-01 00:00:00.
    expected[1].1 = Some(Ts::from_dos((1 << 5) | 1, 0));
    assert_eq!(read(bytes.clone()), expected);
    let archive = Archive::open(Cursor::new(&bytes)).unwrap();
    for ((listed, written), (name, _, content)) in
        archive.entries().iter().zip(&entries).zip(&inputs)
    {
        assert_eq!(written.size, content.len() as u64);
        assert_eq!(written.crc32, Crc32::of(content));
        assert_eq!((listed.size, listed.crc32), (written.size, written.crc32));
        let header = &bytes[written.offset as usize..];
        assert_eq!(&header[..4], b"PK\x03\x04");
        assert_eq!(&header[30..30 + name.len()], name.as_bytes());
    }
}

#[test]
fn a_local_time_reads_back_from_the_dos_fields() {
    let local = Ts::from_local_ticks(1_614_834_367 * TICKS_PER_SECOND, Precision::Second);
    let (bytes, _) = write(&[("a".to_owned(), Some(local), Vec::new())]);
    let read = read(bytes)[0].1.unwrap();
    assert_eq!(read.to_string(), "2021-03-04T05:06:06.0000000");
}

#[test]
fn the_same_inputs_give_the_same_bytes() {
    assert_eq!(write(&samples()).0, write(&samples()).0);
}

#[test]
fn an_empty_archive_is_valid() {
    let (bytes, _) = write(&[]);
    assert_eq!(bytes.len(), 22);
    assert!(read(bytes).is_empty());
}

#[test]
fn zip64_end_records_hold_65535_entries_and_more() {
    let inputs: Vec<Input> = (0..0x1_0001)
        .map(|i| {
            (
                format!("logs/{i:05}.log"),
                None,
                (i as u32).to_le_bytes().to_vec(),
            )
        })
        .collect();
    let (bytes, _) = write(&inputs);
    let archive = Archive::open(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.entries().len(), inputs.len());
    let last = archive.entries().last().unwrap();
    assert_eq!((last.name.as_str(), last.size), ("logs/65536.log", 4));
}

/// Yields `length` bytes of content, then fails with `kind`, or a single
/// interruption when `kind` is `Interrupted`.
struct Failing {
    content: Cursor<Vec<u8>>,
    kind: io::ErrorKind,
}

impl Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.content.read(buf)? {
            0 if self.kind == io::ErrorKind::Interrupted => {
                self.kind = io::ErrorKind::UnexpectedEof;
                Err(io::ErrorKind::Interrupted.into())
            }
            0 => Err(self.kind.into()),
            count => Ok(count),
        }
    }
}

#[test]
fn a_failing_read_leaves_a_consistent_truncated_entry() {
    let read_so_far = pseudo_random(100_000);
    let mut writer = Writer::new(Vec::new());
    let mut failing = Failing {
        content: Cursor::new(read_so_far.clone()),
        kind: io::ErrorKind::PermissionDenied,
    };
    let error = writer.add("locked.dat", None, &mut failing).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let truncated = Truncated::of(&error).expect("a truncation");
    assert_eq!(truncated.entry.size, 100_000);
    assert_eq!(truncated.entry.crc32, Crc32::of(&read_so_far));
    assert_eq!(truncated.source.kind(), io::ErrorKind::PermissionDenied);
    assert!(Truncated::of(&io::Error::other("other")).is_none());
    writer.add("next", None, &mut &b"next"[..]).unwrap();
    let entries = read(writer.finish().unwrap());
    assert_eq!(entries[0].2, read_so_far);
    assert_eq!(entries[1].2, b"next");
}

#[test]
fn interrupted_reads_are_retried() {
    let mut writer = Writer::new(Vec::new());
    let mut interrupted = Failing {
        content: Cursor::new(b"abc".to_vec()),
        kind: io::ErrorKind::Interrupted,
    };
    let error = writer.add("a", None, &mut interrupted).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(Truncated::of(&error).unwrap().entry.size, 3);
}

/// Accepts `capacity` bytes, then fails.
struct Full {
    capacity: usize,
}

impl Write for Full {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.capacity == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "full"));
        }
        let count = buf.len().min(self.capacity);
        self.capacity -= count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failed_write_fails_every_later_call() {
    let mut writer = Writer::new(Full { capacity: 1_000 });
    let error = writer
        .add("a", None, &mut pseudo_random(5_000).as_slice())
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert!(Truncated::of(&error).is_none());
    assert!(writer.add("b", None, &mut &b""[..]).is_err());
    assert!(writer.finish().is_err());
}

const HOSTILE_NAMES: &[&str] = &[
    "",
    "/etc/passwd",
    "../evil",
    "a/../../evil",
    "a/..",
    "./a",
    "a/./b",
    "a//b",
    "a/",
    "..\\evil",
    "a\\b",
    "a\0b",
    "C:/Windows",
    "c:evil",
];

#[test]
fn hostile_names_are_rejected_before_anything_is_written() {
    let mut writer = Writer::new(Vec::new());
    let too_long = "a".repeat(65_536);
    for name in HOSTILE_NAMES.iter().copied().chain([too_long.as_str()]) {
        let error = writer.add(name, None, &mut &b"x"[..]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name:?}");
    }
    assert_eq!(writer.finish().unwrap().len(), 22);
}

/// One path component: no separator, NUL, or dot-only name.
fn component() -> impl Strategy<Value = String> {
    "[^/\\\\\\x00]{1,12}".prop_filter("dot component", |c| c != "." && c != "..")
}

fn clean_name() -> impl Strategy<Value = String> {
    proptest::collection::vec(component(), 1..5)
        .prop_map(|components| components.join("/"))
        .prop_filter(
            "drive letter",
            |name| !matches!(name.as_bytes(), [letter, b':', ..] if letter.is_ascii_alphabetic()),
        )
}

proptest! {
    #[test]
    fn arbitrary_entries_read_back(
        entries in proptest::collection::vec(
            (clean_name(), proptest::option::of(1i64..4_000_000_000), proptest::collection::vec(any::<u8>(), 0..3_000)),
            0..8,
        ),
    ) {
        let inputs: Vec<Input> = entries
            .into_iter()
            .map(|(name, seconds, content)| {
                let modified = seconds.map(|s| Ts::from_ticks(s * TICKS_PER_SECOND + 7, Precision::Tick));
                (name, modified, content)
            })
            .collect();
        let (bytes, _) = write(&inputs);
        let read = read(bytes);
        prop_assert_eq!(read.len(), inputs.len());
        for ((name, modified, content), (read_name, read_modified, read_content)) in inputs.iter().zip(&read) {
            prop_assert_eq!(name, read_name);
            prop_assert_eq!(content, read_content);
            if modified.is_some() {
                prop_assert_eq!(modified, read_modified);
            }
        }
    }

    #[test]
    fn names_with_a_hostile_part_are_rejected(
        before in clean_name(),
        hostile in prop_oneof![Just("/../"), Just("/./"), Just("//"), Just("\\"), Just("\0")],
        after in proptest::option::of(clean_name()),
        leading_slash in any::<bool>(),
    ) {
        let name = format!(
            "{}{before}{hostile}{}",
            if leading_slash { "/" } else { "" },
            after.unwrap_or_default(),
        );
        let mut writer = Writer::new(Vec::new());
        let error = writer.add(&name, None, &mut &b""[..]).unwrap_err();
        prop_assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
