//! Streaming zip writer, for collection: entries of any size go from a
//! reader to a plain [`Write`] (a file, a pipe, a socket) without temporary
//! copies, holding one 64 KiB buffer and the central directory in memory.
//!
//! - entries are stored (not compressed), with UTF-8 names;
//! - sizes and CRC-32 follow each entry's data in a data descriptor, so the
//!   output needs no seeking; every entry is zip64-ready, and the zip64 end
//!   records are written when the archive needs them (65,535 entries or
//!   more, or offsets and sizes of 4 GiB or more);
//! - modification times go in the NTFS extra field (UTC, 100 ns), the
//!   Info-ZIP extended timestamp (1970–2038) and the DOS fields;
//! - the same inputs always give the same bytes: nothing depends on the
//!   clock or the machine.
//!
//! Wrap a file in a [`BufWriter`](std::io::BufWriter): each header and data
//! descriptor is a small write of its own.

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};

use common::checksum::Crc32;
use common::time::Ts;

use crate::mtime;
use crate::{
    method, CENTRAL_SIGNATURE, EOCD_SIGNATURE, FLAG_UTF8, LOCAL_SIGNATURE, ZIP64_EOCD_SIGNATURE,
    ZIP64_EXTRA_ID, ZIP64_LOCATOR_SIGNATURE, ZIP64_U16, ZIP64_U32,
};

const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
/// Version 4.5 of the specification: zip64. Also the "made by" version,
/// with the MS-DOS host (no Unix permissions).
const VERSION: u16 = 45;
/// Sizes and CRC-32 are in a data descriptor after the data.
const FLAG_DESCRIPTOR: u16 = 0x0008;
const FLAGS: u16 = FLAG_DESCRIPTOR | FLAG_UTF8;
/// Size of the zip64 end of central directory record after its first 12
/// bytes.
const ZIP64_EOCD_REMAINING: u64 = 44;
/// Bytes copied at a time.
const BUFFER_SIZE: usize = 1 << 16;

/// Writes a zip archive to `W`, one entry at a time.
pub struct Writer<W: Write> {
    out: Output<W>,
    records: Vec<Record>,
    buffer: Box<[u8]>,
}

/// What [`Writer::add`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Size of the content in bytes.
    pub size: u64,
    /// CRC-32 of the content.
    pub crc32: u32,
    /// Offset of the entry's local header in the archive.
    pub offset: u64,
}

/// An entry kept for the central directory.
struct Record {
    name: String,
    modified: mtime::Encoded,
    entry: Entry,
}

impl<W: Write> Writer<W> {
    /// A writer of a new archive to `out`.
    pub fn new(out: W) -> Self {
        Self {
            out: Output {
                inner: out,
                position: 0,
                failed: false,
            },
            records: Vec::new(),
            buffer: vec![0; BUFFER_SIZE].into_boxed_slice(),
        }
    }

    /// Stream `content` to its end into a new stored entry named `name`, a
    /// clean relative path: `/`-separated, without empty, `.` or `..`
    /// components, backslashes, NUL or a drive letter. Duplicate names are
    /// not detected.
    ///
    /// `modified` goes in the NTFS extra field, the Info-ZIP extended
    /// timestamp and the DOS fields when it is UTC, in the DOS fields only
    /// when it is local to an unknown zone; `None` is DOS 1980-01-01
    /// 00:00:00, which readers show as that time.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] for a name that isn't clean, before
    /// anything is written.
    ///
    /// When reading `content` fails, the entry is completed with the bytes
    /// read so far and the archive stays valid: the error has the read
    /// error's kind and carries a [`Truncated`] with the entry written.
    ///
    /// When writing to the output fails, the archive is unusable, and every
    /// later call fails.
    pub fn add(
        &mut self,
        name: &str,
        modified: Option<Ts>,
        content: &mut dyn Read,
    ) -> io::Result<Entry> {
        check_name(name)?;
        let modified = mtime::Encoded::new(modified);
        let offset = self.out.position;
        self.out.write(&local_header(name, &modified))?;
        let copied = self.copy(content)?;
        self.out.write(&descriptor(copied.crc32, copied.size))?;
        let entry = Entry {
            size: copied.size,
            crc32: copied.crc32,
            offset,
        };
        self.records.push(Record {
            name: name.to_owned(),
            modified,
            entry,
        });
        match copied.read_error {
            None => Ok(entry),
            Some(source) => Err(io::Error::new(source.kind(), Truncated { entry, source })),
        }
    }

    /// Write the central directory and the end records, flush, and return
    /// the output.
    ///
    /// # Errors
    /// On write errors, or when an earlier write failed.
    pub fn finish(mut self) -> io::Result<W> {
        let start = self.out.position;
        for record in &self.records {
            self.out.write(&central_header(record))?;
        }
        let directory = Directory {
            count: self.records.len() as u64,
            size: self.out.position - start,
            offset: start,
        };
        let end = end_records(&directory, self.out.position);
        self.out.write(&end)?;
        self.out.inner.flush()?;
        Ok(self.out.inner)
    }

    /// Copy `content` to the output up to its end or its first read error,
    /// which is returned with what was copied rather than as a failure.
    fn copy(&mut self, content: &mut dyn Read) -> io::Result<Copied> {
        let mut crc = Crc32::new();
        let mut size = 0u64;
        let read_error = loop {
            let count = match content.read(&mut self.buffer) {
                Ok(0) => break None,
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => break Some(error),
            };
            crc.update(&self.buffer[..count]);
            self.out.write(&self.buffer[..count])?;
            size += count as u64;
        };
        Ok(Copied {
            size,
            crc32: crc.finalize(),
            read_error,
        })
    }
}

/// The output, and how far into it the archive is.
struct Output<W> {
    inner: W,
    position: u64,
    /// A write failed: what reached `inner` is unknown.
    failed: bool,
}

impl<W: Write> Output<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other(
                "an earlier write of this zip archive failed",
            ));
        }
        if let Err(error) = self.inner.write_all(bytes) {
            self.failed = true;
            return Err(error);
        }
        self.position += bytes.len() as u64;
        Ok(())
    }
}

/// What [`Writer::copy`] copied.
struct Copied {
    size: u64,
    crc32: u32,
    read_error: Option<io::Error>,
}

/// The error [`Writer::add`] returns when reading the content failed: the
/// entry is in the archive, consistent, with the bytes read before the
/// failure.
#[derive(Debug)]
pub struct Truncated {
    /// The entry as written.
    pub entry: Entry,
    /// The read error.
    pub source: io::Error,
}

impl Truncated {
    /// The truncation `error` reports, if it reports one.
    #[must_use]
    pub fn of(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
}

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "zip entry truncated to {} bytes: reading its content failed: {}",
            self.entry.size, self.source
        )
    }
}

impl Error for Truncated {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Reject a name that isn't a clean relative path: extracted, it could land
/// outside the destination, or name different files on different systems.
fn check_name(name: &str) -> io::Result<()> {
    if name.len() > usize::from(u16::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zip entry name longer than 65,535 bytes",
        ));
    }
    let drive = matches!(name.as_bytes(), [letter, b':', ..] if letter.is_ascii_alphabetic());
    let clean = !drive
        && !name.contains(['\\', '\0'])
        && name
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."));
    if clean {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("zip entry name {name:?} is not a clean relative path"),
        ))
    }
}

/// A local header announcing a data descriptor. Its zip64 extra field,
/// sizes zero until the descriptor, lets the entry grow past 4 GiB.
fn local_header(name: &str, modified: &mtime::Encoded) -> Vec<u8> {
    let zip64 = [
        &ZIP64_EXTRA_ID.to_le_bytes()[..],
        &16u16.to_le_bytes(),
        &[0; 16], // size, compressed size
    ]
    .concat();
    let extra = [zip64, modified.extra()].concat();
    [
        &LOCAL_SIGNATURE.to_le_bytes()[..],
        &VERSION.to_le_bytes(),
        &FLAGS.to_le_bytes(),
        &method::STORED.to_le_bytes(),
        &modified.time.to_le_bytes(),
        &modified.date.to_le_bytes(),
        &0u32.to_le_bytes(), // CRC-32: in the descriptor
        &ZIP64_U32.to_le_bytes(),
        &ZIP64_U32.to_le_bytes(),
        &(name.len() as u16).to_le_bytes(),
        &(extra.len() as u16).to_le_bytes(),
        name.as_bytes(),
        &extra,
    ]
    .concat()
}

/// A zip64 data descriptor: the local header has a zip64 extra field.
fn descriptor(crc32: u32, size: u64) -> Vec<u8> {
    [
        &DESCRIPTOR_SIGNATURE.to_le_bytes()[..],
        &crc32.to_le_bytes(),
        &size.to_le_bytes(), // compressed
        &size.to_le_bytes(),
    ]
    .concat()
}

/// A central directory header, with a zip64 extra field for the values that
/// don't fit 32 bits.
fn central_header(record: &Record) -> Vec<u8> {
    let Entry {
        size,
        crc32,
        offset,
    } = record.entry;
    let mut zip64_values = Vec::new();
    if size >= u64::from(ZIP64_U32) {
        zip64_values.extend([size, size]); // size, compressed size
    }
    if offset >= u64::from(ZIP64_U32) {
        zip64_values.push(offset);
    }
    let zip64 = if zip64_values.is_empty() {
        Vec::new()
    } else {
        let values: Vec<u8> = zip64_values.iter().flat_map(|v| v.to_le_bytes()).collect();
        [
            &ZIP64_EXTRA_ID.to_le_bytes()[..],
            &(values.len() as u16).to_le_bytes(),
            &values,
        ]
        .concat()
    };
    let extra = [zip64, record.modified.extra()].concat();
    [
        &CENTRAL_SIGNATURE.to_le_bytes()[..],
        &VERSION.to_le_bytes(), // made by
        &VERSION.to_le_bytes(), // needed
        &FLAGS.to_le_bytes(),
        &method::STORED.to_le_bytes(),
        &record.modified.time.to_le_bytes(),
        &record.modified.date.to_le_bytes(),
        &crc32.to_le_bytes(),
        &u32_or_zip64(size).to_le_bytes(), // compressed
        &u32_or_zip64(size).to_le_bytes(),
        &(record.name.len() as u16).to_le_bytes(),
        &(extra.len() as u16).to_le_bytes(),
        &0u16.to_le_bytes(), // comment length
        &0u16.to_le_bytes(), // disk
        &0u16.to_le_bytes(), // internal attributes
        &0u32.to_le_bytes(), // external attributes
        &u32_or_zip64(offset).to_le_bytes(),
        record.name.as_bytes(),
        &extra,
    ]
    .concat()
}

/// Where the central directory is, and how many entries it lists.
struct Directory {
    count: u64,
    size: u64,
    offset: u64,
}

/// The end of central directory record, preceded by the zip64 record and
/// its locator (at `position`) when a value doesn't fit the classic one.
fn end_records(directory: &Directory, position: u64) -> Vec<u8> {
    let zip64 = directory.count >= u64::from(ZIP64_U16)
        || directory.size >= u64::from(ZIP64_U32)
        || directory.offset >= u64::from(ZIP64_U32);
    let zip64_records = if zip64 {
        [
            &ZIP64_EOCD_SIGNATURE.to_le_bytes()[..],
            &ZIP64_EOCD_REMAINING.to_le_bytes(),
            &VERSION.to_le_bytes(),         // made by
            &VERSION.to_le_bytes(),         // needed
            &0u32.to_le_bytes(),            // this disk
            &0u32.to_le_bytes(),            // the directory's disk
            &directory.count.to_le_bytes(), // on this disk
            &directory.count.to_le_bytes(),
            &directory.size.to_le_bytes(),
            &directory.offset.to_le_bytes(),
            // Locator.
            &ZIP64_LOCATOR_SIGNATURE.to_le_bytes(),
            &0u32.to_le_bytes(), // the record's disk
            &position.to_le_bytes(),
            &1u32.to_le_bytes(), // disks
        ]
        .concat()
    } else {
        Vec::new()
    };
    let count = directory.count.min(u64::from(ZIP64_U16)) as u16;
    let eocd = [
        &EOCD_SIGNATURE.to_le_bytes()[..],
        &0u16.to_le_bytes(),  // this disk
        &0u16.to_le_bytes(),  // the directory's disk
        &count.to_le_bytes(), // on this disk
        &count.to_le_bytes(),
        &u32_or_zip64(directory.size).to_le_bytes(),
        &u32_or_zip64(directory.offset).to_le_bytes(),
        &0u16.to_le_bytes(), // comment length
    ]
    .concat();
    [zip64_records, eocd].concat()
}

/// `value`, or the marker sending readers to the zip64 field.
fn u32_or_zip64(value: u64) -> u32 {
    value.min(u64::from(ZIP64_U32)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(size: u64, offset: u64) -> Record {
        Record {
            name: "a".to_owned(),
            modified: mtime::Encoded::new(None),
            entry: Entry {
                size,
                crc32: 0,
                offset,
            },
        }
    }

    /// The size, compressed size and local header offset a reader gets
    /// from `record`'s central header.
    fn read_back(record: &Record) -> (u64, u64, u64) {
        let header = central_header(record);
        let field = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
        let extra = &header[46 + record.name.len()..];
        crate::apply_zip64(extra, field(24), field(20), field(42)).unwrap()
    }

    #[test]
    fn values_of_4_gib_and_more_go_in_zip64_fields() {
        let large = u64::from(ZIP64_U32);
        for (size, offset) in [(1, 2), (large, 2), (1, large), (large + 1, large << 4)] {
            assert_eq!(read_back(&record(size, offset)), (size, size, offset));
        }
        // Below 4 GiB, no zip64 field: the fixed part and the name only.
        assert_eq!(central_header(&record(large - 1, large - 1)).len(), 46 + 1);
    }

    #[test]
    fn the_zip64_end_records_come_when_needed() {
        let directory = |count, size, offset| Directory {
            count,
            size,
            offset,
        };
        let classic = 22;
        let zip64 = 56 + 20 + 22;
        let large = u64::from(ZIP64_U32);
        assert_eq!(end_records(&directory(0xfffe, 1, 1), 2).len(), classic);
        assert_eq!(end_records(&directory(0xffff, 1, 1), 2).len(), zip64);
        assert_eq!(end_records(&directory(1, large, 1), 2).len(), zip64);
        assert_eq!(end_records(&directory(1, 1, large), 2).len(), zip64);
    }
}
