# zip

Zip archives for forensic intake and collection, written from scratch (DEFLATE included) on [`Sootmark/common`](https://github.com/Sootmark/common). Cryptography is not written in-house: WinZip AES uses RustCrypto's `aes`, `ctr`, `hmac`, `pbkdf2` and `sha1` (MIT OR Apache-2.0).

```toml
[dependencies]
sootmark-zip = "0.4"
```

```rust
let mut archive = sootmark_zip::Archive::open(std::io::BufReader::new(std::fs::File::open("Collection-FS01.zip")?))?;
for index in 0..archive.entries().len() {
    let name = archive.entries()[index].name.clone();
    let mut reader = archive.reader(index)?; // streams; verifies size and CRC-32 at the end
    let copied = std::io::copy(&mut reader, &mut std::io::sink())?;
    println!("{name}: {copied} bytes, CRC-32 verified");
}
```

- zip64 (end-of-central-directory records and extra fields), UTF-8 and code page 437 names, data descriptors.
- Stored, **DEFLATE** (RFC 1951) and **Deflate64** entries, decompressed while streaming. Nothing is extracted to disk.
- **Every entry's CRC-32 and size are verified** when read to the end: a corrupted or altered evidence archive is reported ("CRC-32 mismatch: content corrupted or altered"), never silently trusted.
- **WinZip AES** entries (AES-128/192/256, AE-1 and AE-2), as written by 7-Zip, WinZip, libarchive and Velociraptor: `reader_with_password`. The HMAC is checked at the end, so altered ciphertext is reported, not decrypted into plausible garbage. A wrong password is `PermissionDenied`. Legacy ZipCrypto is listed (`Encryption::Unsupported`) but not readable.
- **Zips inside zips, read in place:** `into_stored` turns a stored entry (encrypted or not) into a `Read + Seek` stream, so a nested archive such as an encrypted Velociraptor collection's `data.zip` opens with `Archive::open` without being extracted. `StoredEntry::verify` checks its CRC-32 / HMAC in one pass.
- **Modification times** (`Entry::modified`, a `sootmark_common::time::Ts`) from the most precise record: the NTFS extra field (UTC, 100 ns, written by 7-Zip), else the Info-ZIP extended timestamp (UTC, 1 s), else the MS-DOS fields. DOS times are the zipping machine's wall clock in an unknown zone, so they stay `LocalUnknownZone` (convert with `assume_offset` once the zone is known), never passed off as UTC. A zero, sentinel or impossible value, or a malformed extra field, falls through to the next source; `None` when none is left.

## Verification

| Check | Result |
|---|---|
| Archives from Python `zipfile`/zlib: stored, DEFLATE on text, random and mixed data, empty file, Unicode and URL-encoded names | every entry decompresses to the expected SHA-256 |
| Forced zip64 archive | read correctly |
| Deflate64 archive from 7-Zip | decompresses to the expected SHA-256 |
| Info-ZIP archive | read correctly |
| AES-256 (deflated and stored) and AES-128 archives from 7-Zip (AE-2), AES-256 from libarchive/bsdtar (AE-1) | every entry decrypts to the expected SHA-256 |
| One ciphertext byte altered | authentication failure reported (streaming and `verify`) |
| Random access into a stored AES entry at unaligned offsets | matches the streamed plaintext |
| One byte of content altered | CRC-32 mismatch reported |
| Modification times from 7-Zip (NTFS), Info-ZIP (extended timestamp) and Python `zipfile` (DOS), cross-checked with `zipinfo` | UTC to 100 ns / 1 s; DOS kept as local time |
| Impossible DOS dates (month 13, 30 February, hour 25), zero, and hostile NTFS / extended-timestamp fields (truncated, overrunning, duplicated, zero, sentinel) | no time, or the next source; never panics |
| Corrupted and truncated archives (plain and encrypted), random compressed streams | errors, never panics |
| Throughput (release, one thread) | ~165 MiB/s on DEFLATE-compressed event logs |
| Written archives read back by this crate: arbitrary names, contents and times (property tests), 65,537 entries | names, sizes, CRC-32, contents and times (100 ns) preserved |
| Written archives on Debian 13 (`examples/write_archive.rs`): names, times, empty entry; a 4.5 GiB entry followed by one past 4 GiB; 70,000 entries | `unzip -t`, `7z t` (7-Zip 25.01) and Python 3.13 `zipfile.testzip()` report no error; `zipinfo` and 7-Zip show the expected times, sizes and offsets |
| Writing the 4.5 GiB archive (release, one thread) | ~17 s, 11 MiB peak memory |

## Writing

```rust
let file = std::io::BufWriter::new(std::fs::File::create("collection.zip")?);
let mut writer = sootmark_zip::Writer::new(file);
let mut source = std::fs::File::open(r"C:\Windows\System32\winevt\Logs\Security.evtx")?; // any `Read`
let entry = writer.add("C/Windows/System32/winevt/Logs/Security.evtx", modified, &mut source)?; // modified: Option<Ts>, UTC
println!("{} bytes, CRC-32 {:08x}", entry.size, entry.crc32);
writer.finish()?;
```

- **Streaming:** entries of any size go from a `Read` to a plain `Write` (file, pipe, socket: no `Seek`), through one 64 KiB buffer. Only the central directory (one small record per entry) is kept in memory. Sizes and CRC-32 follow the data in zip64 data descriptors.
- **zip64 when needed:** every local header carries a zip64 field, so an entry can grow past 4 GiB; the central directory and end records use zip64 only for entries, offsets or counts that need it (4 GiB, 65,535 entries).
- **Stored** (not compressed), **UTF-8 names**. Names must be clean relative paths (`/`-separated, no empty, `.` or `..` component, no backslash, NUL or drive letter): anything else is `InvalidInput`, before anything is written. Duplicate names are not detected.
- **Modification times:** a UTC `Ts` goes in the NTFS extra field (100 ns), the Info-ZIP extended timestamp (when in 1970–2038) and the DOS fields (as a UTC wall clock, clamped to 1980–2107). A local time of unknown zone goes in the DOS fields only. `None` is DOS 1980-01-01 00:00:00.
- **A failing source doesn't break the archive:** when reading the content fails part-way, the entry is completed with the bytes read so far (correct size and CRC-32) and `add` returns the read error carrying a `write::Truncated` with the entry. A failed write to the output makes every later call fail.
- **Deterministic:** the same inputs give the same bytes.

Not supported: compression, encryption, comments, Unix permissions, access and creation times (left unset). Stored entries with a data descriptor can only be read through the central directory, as `unzip`, 7-Zip, Python and this crate do: forward-only readers (Java's `ZipInputStream`, extraction from a pipe) can't find where they end.

Declared sizes and compression ratios are not limits: consumers must bound what they read (zip bombs), as the fuzz tests do.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
