//! Zip archives for forensic intake and collection.
//!
//! Reading ([`Archive`]):
//!
//! - zip64, UTF-8 and code page 437 file names, data descriptors;
//! - stored, DEFLATE and Deflate64 entries, decompressed while streaming;
//! - **every entry's CRC-32 and size are verified** when it's read to the
//!   end: a corrupted or altered evidence archive is reported, not trusted;
//! - WinZip AES encrypted entries (AE-1, AE-2), authenticated by their
//!   HMAC; legacy ZipCrypto entries are listed but not readable;
//! - stored entries opened as seekable streams, so a zip inside a zip
//!   (such as an encrypted Velociraptor collection) is read in place;
//! - each entry's modification time, from its NTFS, Info-ZIP or DOS fields,
//!   UTC or local to an unknown zone as recorded.
//!
//! Writing ([`Writer`], see [`mod@write`]): entries of any size streamed
//! into a stored archive on a plain [`Write`](std::io::Write), zip64 when
//! needed, with UTC modification times to 100 ns.

mod cp437;
mod mtime;
mod winzip_aes;
pub mod write;

use std::io::{self, Read, Seek, SeekFrom, Take};

use common::bytes::Reader;
use common::checksum::Crc32;
use common::time::Ts;
use hmac::{Hmac, Mac};
use sha1::Sha1;

pub use common::deflate::{Inflate, Variant};
pub use winzip_aes::{Aes, Strength};
pub use write::Writer;

use winzip_aes::{Cipher, Decrypt};

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
    /// Compression method (for AES entries, the one applied before
    /// encryption).
    pub method: u16,
    /// How the entry is encrypted, if it is.
    pub encryption: Option<Encryption>,
    /// When the entry was last modified, from the most precise record: the
    /// NTFS extra field (UTC, 100 ns), the Info-ZIP extended timestamp (UTC,
    /// 1 s), else the DOS fields: the zipping machine's wall clock, 2 s,
    /// [`LocalUnknownZone`](common::time::Semantic::LocalUnknownZone). The
    /// precision tells which source it is. `None` when no valid time is
    /// recorded.
    pub modified: Option<Ts>,
    local_header_offset: u64,
}

/// How an entry is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// WinZip AES: readable with the password.
    Aes(Aes),
    /// Legacy ZipCrypto, PKWARE strong encryption, or a malformed AES
    /// header: not readable.
    Unsupported,
}

impl Entry {
    /// Whether the entry is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.name.ends_with('/')
    }

    /// Whether the stored CRC-32 is meaningful (AE-2 zeroes it).
    fn has_crc(&self) -> bool {
        !matches!(
            self.encryption,
            Some(Encryption::Aes(Aes { ae2: true, .. }))
        )
    }

    fn aes(&self) -> io::Result<Option<Aes>> {
        match self.encryption {
            None => Ok(None),
            Some(Encryption::Aes(aes)) => Ok(Some(aes)),
            Some(Encryption::Unsupported) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "zip entry uses an unsupported encryption (ZipCrypto or PKWARE)",
            )),
        }
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
        self.open_reader(index, None)
    }

    /// A reader over the content of entry `index`, decrypting it with
    /// `password` if it's encrypted. Reading it to the end verifies its
    /// size, and its CRC-32 and/or authentication code.
    ///
    /// # Errors
    /// [`io::ErrorKind::PermissionDenied`] for a wrong password; otherwise as
    /// [`Archive::reader`].
    pub fn reader_with_password(
        &mut self,
        index: usize,
        password: &[u8],
    ) -> io::Result<EntryReader<'_, R>> {
        self.open_reader(index, Some(password))
    }

    fn open_reader(
        &mut self,
        index: usize,
        password: Option<&[u8]>,
    ) -> io::Result<EntryReader<'_, R>> {
        let entry = self.entry(index)?;
        let aes = entry.aes()?;
        let data_offset = self.data_offset(&entry)?;
        let source = match aes {
            None => {
                self.inner.seek(SeekFrom::Start(data_offset))?;
                Source::Plain((&mut self.inner).take(entry.compressed_size))
            }
            Some(aes) => {
                let password = password.ok_or_else(password_needed)?;
                let header = read_at(&mut self.inner, data_offset, aes.header_size())?;
                let keys = winzip_aes::keys(aes, password, &header)?;
                let length = ciphertext_length(&entry, aes)?;
                Source::Aes(Box::new(Decrypt::new(
                    (&mut self.inner).take(length + winzip_aes::AUTH_CODE_SIZE),
                    keys,
                    length,
                )))
            }
        };
        let decoder = match entry.method {
            method::STORED => Decoder::Stored(source),
            method::DEFLATE => Decoder::Inflate(Inflate::new(source, Variant::Deflate)),
            method::DEFLATE64 => Decoder::Inflate(Inflate::new(source, Variant::Deflate64)),
            _ => return Err(unsupported_method()),
        };
        Ok(EntryReader {
            decoder,
            crc: Crc32::new(),
            read: 0,
            entry,
        })
    }

    /// Turn the archive into a seekable stream over stored (uncompressed)
    /// entry `index`, decrypting it with `password` if it's encrypted. This
    /// is how an archive inside an archive is opened without extracting it.
    ///
    /// Random access can't check the CRC-32 or authentication code as it
    /// goes: call [`StoredEntry::verify`] for a full integrity pass.
    ///
    /// # Errors
    /// When the entry is compressed, needs a password that wasn't given, or
    /// the password is wrong.
    pub fn into_stored(
        mut self,
        index: usize,
        password: Option<&[u8]>,
    ) -> io::Result<StoredEntry<R>> {
        let entry = self.entry(index)?;
        if entry.method != method::STORED {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only stored zip entries can be opened as seekable streams",
            ));
        }
        let aes = entry.aes()?;
        let mut start = self.data_offset(&entry)?;
        let (cipher, mac) = match aes {
            None => (None, None),
            Some(aes) => {
                let password = password.ok_or_else(password_needed)?;
                let header = read_at(&mut self.inner, start, aes.header_size())?;
                let keys = winzip_aes::keys(aes, password, &header)?;
                start += aes.header_size();
                (Some(keys.cipher), Some(keys.mac))
            }
        };
        let length = match aes {
            None => entry.compressed_size,
            Some(aes) => ciphertext_length(&entry, aes)?,
        };
        if length != entry.size {
            return Err(invalid("stored zip entry sizes disagree"));
        }
        // Every later offset is at most this: checked once, here.
        let archive_length = self.inner.seek(SeekFrom::End(0))?;
        let end = start
            .checked_add(length)
            .and_then(|end| end.checked_add(aes.map_or(0, |_| winzip_aes::AUTH_CODE_SIZE)));
        if end.map_or(true, |end| end > archive_length) {
            return Err(invalid("stored zip entry extends past the archive"));
        }
        Ok(StoredEntry {
            inner: self.inner,
            start,
            length,
            position: 0,
            cipher,
            mac,
            entry,
        })
    }

    fn entry(&self, index: usize) -> io::Result<Entry> {
        self.entries
            .get(index)
            .cloned()
            .ok_or_else(|| invalid("no such entry"))
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

/// An entry's raw data, decrypted if needed.
enum Source<'a, R> {
    Plain(Take<&'a mut R>),
    // Boxed: the key schedule is large and plain entries are the norm.
    Aes(Box<Decrypt<Take<&'a mut R>>>),
}

impl<R: Read> Read for Source<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(inner) => inner.read(buf),
            Self::Aes(inner) => inner.read(buf),
        }
    }
}

enum Decoder<'a, R> {
    Stored(Source<'a, R>),
    Inflate(Inflate<Source<'a, R>>),
}

/// Streams an entry's content, verifying its size, CRC-32 and (encrypted
/// entries) authentication code at the end.
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

impl<R: Read> EntryReader<'_, R> {
    fn verify(&mut self) -> io::Result<()> {
        if self.read != self.entry.size {
            return Err(invalid("zip entry shorter than its declared size"));
        }
        let source = match &mut self.decoder {
            Decoder::Stored(source) => source,
            Decoder::Inflate(inflate) => inflate.get_mut(),
        };
        if let Source::Aes(decrypt) = source {
            decrypt.finish()?;
        }
        if self.entry.has_crc() && self.crc.finalize() != self.entry.crc32 {
            return Err(invalid(
                "zip entry CRC-32 mismatch: content corrupted or altered",
            ));
        }
        Ok(())
    }
}

/// A stored entry read as a seekable stream (see [`Archive::into_stored`]).
pub struct StoredEntry<R> {
    inner: R,
    /// Offset of the (cipher)text in `inner`.
    start: u64,
    length: u64,
    position: u64,
    cipher: Option<Cipher>,
    mac: Option<Hmac<Sha1>>,
    entry: Entry,
}

impl<R: Read + Seek> StoredEntry<R> {
    /// Read the whole entry once and check its CRC-32 and, when encrypted,
    /// its authentication code. Leaves the position unchanged.
    ///
    /// # Errors
    /// On read errors or when the entry is corrupted or altered.
    pub fn verify(&mut self) -> io::Result<()> {
        let mut crc = Crc32::new();
        let mut mac = self.mac.clone();
        let mut buffer = vec![0u8; VERIFY_BUFFER];
        let mut offset = 0;
        while offset < self.length {
            let chunk = (self.length - offset).min(VERIFY_BUFFER as u64) as usize;
            self.inner.seek(SeekFrom::Start(self.start + offset))?;
            self.inner.read_exact(&mut buffer[..chunk])?;
            if let Some(mac) = &mut mac {
                mac.update(&buffer[..chunk]);
            }
            if let Some(cipher) = &mut self.cipher {
                cipher.seek(offset);
                cipher.apply(&mut buffer[..chunk]);
            }
            crc.update(&buffer[..chunk]);
            offset += chunk as u64;
        }
        if let Some(mac) = mac {
            let mut stored = [0u8; winzip_aes::AUTH_CODE_SIZE as usize];
            self.inner.seek(SeekFrom::Start(self.start + self.length))?;
            self.inner.read_exact(&mut stored)?;
            winzip_aes::check_auth_code(mac, &stored)?;
        }
        if self.entry.has_crc() && crc.finalize() != self.entry.crc32 {
            return Err(invalid(
                "zip entry CRC-32 mismatch: content corrupted or altered",
            ));
        }
        Ok(())
    }

    /// The entry this stream reads.
    #[must_use]
    pub const fn entry(&self) -> &Entry {
        &self.entry
    }
}

impl<R: Read + Seek> Read for StoredEntry<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.length.saturating_sub(self.position);
        let wanted = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        if wanted == 0 {
            return Ok(0);
        }
        self.inner
            .seek(SeekFrom::Start(self.start + self.position))?;
        let count = self.inner.read(&mut buf[..wanted])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stored zip entry truncated",
            ));
        }
        if let Some(cipher) = &mut self.cipher {
            cipher.seek(self.position);
            cipher.apply(&mut buf[..count]);
        }
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: Read + Seek> Seek for StoredEntry<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.length.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the entry",
            )
        })?;
        Ok(self.position)
    }
}

/// Chunk size of [`StoredEntry::verify`].
const VERIFY_BUFFER: usize = 1 << 16;

/// Length of an AES entry's ciphertext.
fn ciphertext_length(entry: &Entry, aes: Aes) -> io::Result<u64> {
    entry
        .compressed_size
        .checked_sub(aes.overhead())
        .ok_or_else(|| invalid("encrypted zip entry too short"))
}

fn password_needed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "encrypted zip entry: a password is needed",
    )
}

fn unsupported_method() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "unsupported zip compression method",
    )
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
    let dos_time = r.u16_le()?;
    let dos_date = r.u16_le()?;
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
    let aes = (method == winzip_aes::METHOD)
        .then(|| winzip_aes::parse_extra(extra))
        .flatten();
    let encryption = (flags & FLAG_ENCRYPTED != 0).then_some(match aes {
        Some(aes) => Encryption::Aes(aes),
        None => Encryption::Unsupported,
    });
    Ok(Some(Entry {
        name,
        size,
        compressed_size,
        crc32,
        method: aes.map_or(method, |aes| aes.method),
        encryption,
        modified: mtime::parse(extra, dos_date, dos_time),
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
        // A field running past the extra data ends it: what came before
        // still counts, and the entry stays readable.
        let Ok(mut field) = r.sub(length) else { break };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overrunning_extra_field_keeps_the_entry() {
        // An extended timestamp declaring 0xffff bytes it doesn't have.
        let extra = [0x55, 0x54, 0xff, 0xff, 1, 0, 0, 0, 0x60];
        assert_eq!(apply_zip64(&extra, 5, 7, 9).unwrap(), (5, 7, 9));
        // A ZIP64 field before it still counts.
        let mut zip64 = vec![0x01, 0x00, 8, 0];
        zip64.extend_from_slice(&42u64.to_le_bytes());
        zip64.extend_from_slice(&extra);
        assert_eq!(apply_zip64(&zip64, ZIP64_U32, 7, 9).unwrap(), (42, 7, 9));
    }
}
