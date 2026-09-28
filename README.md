# zip

Read-only zip archives for forensic intake, written from scratch (DEFLATE included) on [`Sootmark/common`](https://github.com/Sootmark/common). Cryptography is not written in-house: WinZip AES uses RustCrypto's `aes`, `ctr`, `hmac`, `pbkdf2` and `sha1` (MIT OR Apache-2.0).

```rust
let mut archive = zip::Archive::open(std::io::BufReader::new(std::fs::File::open("Collection-FS01.zip")?))?;
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
| Corrupted and truncated archives (plain and encrypted), random compressed streams | errors, never panics |
| Throughput (release, one thread) | ~165 MiB/s on DEFLATE-compressed event logs |

Declared sizes and compression ratios are not limits: consumers must bound what they read (zip bombs), as the fuzz tests do.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
