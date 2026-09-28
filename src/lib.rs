//! Read-only zip archives for forensic intake.
//!
//! - zip64, UTF-8 and code page 437 file names, data descriptors;
//! - stored, DEFLATE and Deflate64 entries, decompressed while streaming;
//! - **every entry's CRC-32 and size are verified** when it's read to the
//!   end: a corrupted or altered evidence archive is reported, not trusted.
//!
//! Encrypted entries (ZipCrypto, AES) are listed but not readable yet.

mod cp437;
mod inflate;

use std::io::{self, Read, Seek, SeekFrom, Take};

use common::bytes::Reader;
use common::checksum::Crc32;

pub use inflate::{Inflate, Variant};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const EOCD_SIZE: usize = 22;
/// The EOCD may be followed by a comment of up to 65,535 bytes.
const EOCD_SEARCH: u64 = EOCD_SIZE as u64 + 0xffff;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_LOCATOR_SIZE: u64 = 20;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_HEADER_SIZE: usize = 46;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const LOCAL_HEADER_SIZE: usize = 30;
const ZIP64_EXTRA_ID: u16 = 0x0001;
/// Marks a field whose real value is in the zip64 extra field.
const ZIP64_U32: u32 = 0xffff_ffff;
const ZIP64_U16: u16 = 0xffff;
const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_UTF8: u16 = 0x0800;

/// Compression methods.
mod method {
    pub const STORED: u16 = 0;
    pub const DEFLATE: u16 = 8;
    pub const DEFLATE64: u16 = 9;
}

/// One entry of the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Path inside the archive, `/`-separated.
    pub name: String,
    /// Uncompressed size in bytes.
    pub size: u64,
    /// Compressed size in bytes.
    pub compressed_size: u64,
    /// CRC-32 of the uncompressed content.
    pub crc32: u32,
    /// Compression method.
    pub method: u16,
    /// Whether the entry is encrypted (not readable yet).
    pub encrypted: bool,
    local_header_offset: u64,
}

impl Entry {
    /// Whether the entry is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.name.ends_with('/')
    }
}

/// An open archive.
pub struct Archive<R> {
    inner: R,
    entries: Vec<Entry>,
}

impl<R: Read + Seek> Archive<R> {
    /// Read the central directory of the archive read by `inner`.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidData`] when there is no readable central
    /// directory, or on read errors.
    pub fn open(mut inner: R) -> io::Result<Self> {
        let length = inner.seek(SeekFrom::End(0))?;
        let directory = locate_central_directory(&mut inner, length)?;
        let bytes = read_at(&mut inner, directory.offset, directory.size)?;
        let entries = parse_central_directory(&bytes, directory.count)?;
        Ok(Self { inner, entries })
    }

    /// Every entry, in central-directory order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// A reader over the content of entry `index`. Reading it to the end
    /// verifies its size and CRC-32.
    ///
    /// # Errors
    /// When the entry is encrypted, uses an unsupported method, or its local
    /// header can't be read.
    pub fn reader(&mut self, index: usize) -> io::Result<EntryReader<'_, R>> {
        let entry = self
            .entries
            .get(index)
            .cloned()
            .ok_or_else(|| invalid("no such entry"))?;
        if entry.encrypted {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "encrypted zip entry",
            ));
        }
        let data_offset = self.data_offset(&entry)?;
        self.inner.seek(SeekFrom::Start(data_offset))?;
        let compressed = (&mut self.inner).take(entry.compressed_size);
        let decoder = match entry.method {
            method::STORED => Decoder::Stored(compressed),
            method::DEFLATE => Decoder::Inflate(Inflate::new(compressed, Variant::Deflate)),
            method::DEFLATE64 => Decoder::Inflate(Inflate::new(compressed, Variant::Deflate64)),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported zip compression method",
                ))
            }
        };
        Ok(EntryReader {
            decoder,
            crc: Crc32::new(),
            read: 0,
            entry,
        })
    }

    /// Where an entry's data starts: after its local header.
    fn data_offset(&mut self, entry: &Entry) -> io::Result<u64> {
        let header = read_at(
            &mut self.inner,
            entry.local_header_offset,
            LOCAL_HEADER_SIZE as u64,
        )?;
        let mut r = Reader::new(&header);
        if r.u32_le().map_err(read_error)? != LOCAL_SIGNATURE {
            return Err(invalid("bad local header signature"));
        }
        r.seek(26).map_err(read_error)?;
        let name_length = u64::from(r.u16_le().map_err(read_error)?);
        let extra_length = u64::from(r.u16_le().map_err(read_error)?);
        Ok(entry.local_header_offset + LOCAL_HEADER_SIZE as u64 + name_length + extra_length)
    }
}

enum Decoder<'a, R> {
    Stored(Take<&'a mut R>),
    Inflate(Inflate<Take<&'a mut R>>),
}

/// Streams an entry's content, verifying size and CRC-32 at the end.
pub struct EntryReader<'a, R> {
    decoder: Decoder<'a, R>,
    crc: Crc32,
    read: u64,
    entry: Entry,
}

impl<R: Read> Read for EntryReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = self.entry.size.saturating_sub(self.read);
        let wanted = buf.len().min(usize::try_from(limit).unwrap_or(usize::MAX));
        let count = if wanted == 0 {
            0
        } else {
            match &mut self.decoder {
                Decoder::Stored(inner) => inner.read(&mut buf[..wanted])?,
                Decoder::Inflate(inner) => inner.read(&mut buf[..wanted])?,
            }
        };
        self.crc.update(&buf[..count]);
        self.read += count as u64;
        if count == 0 && !buf.is_empty() {
            self.verify()?;
        }
        Ok(count)
    }
}

impl<R> EntryReader<'_, R> {
    fn verify(&self) -> io::Result<()> {
        if self.read != self.entry.size {
            return Err(invalid("zip entry shorter than its declared size"));
        }
        if self.crc.finalize() != self.entry.crc32 {
            return Err(invalid(
                "zip entry CRC-32 mismatch: content corrupted or altered",
            ));
        }
        Ok(())
    }
}

struct CentralDirectory {
    offset: u64,
    size: u64,
    count: u64,
}

fn locate_central_directory<R: Read + Seek>(
    inner: &mut R,
    length: u64,
) -> io::Result<CentralDirectory> {
    let search_start = length.saturating_sub(EOCD_SEARCH);
    let tail = read_at(inner, search_start, length - search_start)?;
    let eocd_at = (0..=tail.len().saturating_sub(EOCD_SIZE))
        .rev()
        .find(|&i| tail[i..i + 4] == EOCD_SIGNATURE.to_le_bytes())
        .ok_or_else(|| invalid("not a zip archive (no end of central directory)"))?;
    let mut r = Reader::new(&tail[eocd_at..]);
    r.seek(10).map_err(read_error)?;
    let count = r.u16_le().map_err(read_error)?;
    let size = r.u32_le().map_err(read_error)?;
    let offset = r.u32_le().map_err(read_error)?;
    let eocd_offset = search_start + eocd_at as u64;
    let directory = if count == ZIP64_U16 || size == ZIP64_U32 || offset == ZIP64_U32 {
        zip64_directory(inner, eocd_offset)?
    } else {
        CentralDirectory {
            offset: u64::from(offset),
            size: u64::from(size),
            count: u64::from(count),
        }
    };
    let fits = directory
        .offset
        .checked_add(directory.size)
        .is_some_and(|end| end <= length);
    if !fits || directory.count > directory.size / CENTRAL_HEADER_SIZE as u64 {
        return Err(invalid("central directory outside the archive"));
    }
    Ok(directory)
}

fn zip64_directory<R: Read + Seek>(
    inner: &mut R,
    eocd_offset: u64,
) -> io::Result<CentralDirectory> {
    let locator_offset = eocd_offset
        .checked_sub(ZIP64_LOCATOR_SIZE)
        .ok_or_else(|| invalid("missing zip64 locator"))?;
    let locator = read_at(inner, locator_offset, ZIP64_LOCATOR_SIZE)?;
    let mut r = Reader::new(&locator);
    if r.u32_le().map_err(read_error)? != ZIP64_LOCATOR_SIGNATURE {
        return Err(invalid("missing zip64 locator"));
    }
    r.skip(4).map_err(read_error)?;
    let record_offset = r.u64_le().map_err(read_error)?;
    let record = read_at(inner, record_offset, 56)?;
    let mut r = Reader::new(&record);
    if r.u32_le().map_err(read_error)? != ZIP64_EOCD_SIGNATURE {
        return Err(invalid("bad zip64 end of central directory"));
    }
    r.seek(32).map_err(read_error)?;
    let count = r.u64_le().map_err(read_error)?;
    let size = r.u64_le().map_err(read_error)?;
    let offset = r.u64_le().map_err(read_error)?;
    Ok(CentralDirectory {
        offset,
        size,
        count,
    })
}

fn parse_central_directory(bytes: &[u8], count: u64) -> io::Result<Vec<Entry>> {
    let mut r = Reader::new(bytes);
    (0..count)
        .map(|_| {
            parse_central_entry(&mut r)
                .map_err(read_error)?
                .ok_or_else(|| invalid("bad central directory entry"))
        })
        .collect()
}

fn parse_central_entry(r: &mut Reader<'_>) -> common::bytes::Result<Option<Entry>> {
    if r.u32_le()? != CENTRAL_SIGNATURE {
        return Ok(None);
    }
    r.skip(4)?; // versions
    let flags = r.u16_le()?;
    let method = r.u16_le()?;
    r.skip(4)?; // time, date
    let crc32 = r.u32_le()?;
    let compressed_size = r.u32_le()?;
    let size = r.u32_le()?;
    let name_length = usize::from(r.u16_le()?);
    let extra_length = usize::from(r.u16_le()?);
    let comment_length = usize::from(r.u16_le()?);
    r.skip(8)?; // disk, internal and external attributes
    let local_header_offset = r.u32_le()?;
    let raw_name = r.bytes(name_length)?;
    let extra = r.bytes(extra_length)?;
    r.skip(comment_length)?;
    let name = if flags & FLAG_UTF8 != 0 {
        String::from_utf8_lossy(raw_name).into_owned()
    } else {
        cp437::decode(raw_name)
    };
    let (size, compressed_size, local_header_offset) =
        apply_zip64(extra, size, compressed_size, local_header_offset)?;
    Ok(Some(Entry {
        name,
        size,
        compressed_size,
        crc32,
        method,
        encrypted: flags & FLAG_ENCRYPTED != 0,
        local_header_offset,
    }))
}

/// Replace 32-bit fields marked `0xFFFFFFFF` with their zip64 values, which
/// appear in this order: size, compressed size, local header offset.
fn apply_zip64(
    extra: &[u8],
    size: u32,
    compressed: u32,
    offset: u32,
) -> common::bytes::Result<(u64, u64, u64)> {
    let mut values = (u64::from(size), u64::from(compressed), u64::from(offset));
    let mut r = Reader::new(extra);
    while r.remaining() >= 4 {
        let id = r.u16_le()?;
        let length = usize::from(r.u16_le()?);
        let mut field = r.sub(length)?;
        if id != ZIP64_EXTRA_ID {
            continue;
        }
        if size == ZIP64_U32 {
            values.0 = field.u64_le()?;
        }
        if compressed == ZIP64_U32 {
            values.1 = field.u64_le()?;
        }
        if offset == ZIP64_U32 {
            values.2 = field.u64_le()?;
        }
    }
    Ok(values)
}

fn read_at<R: Read + Seek>(inner: &mut R, offset: u64, length: u64) -> io::Result<Vec<u8>> {
    inner.seek(SeekFrom::Start(offset))?;
    let mut buffer = Vec::new();
    inner.take(length).read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` adapter
fn read_error(error: common::bytes::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
