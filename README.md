# zip

Read-only zip archives for forensic intake, written from scratch (DEFLATE included). The only dependency is [`Sootmark/common`](https://github.com/Sootmark/common).

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
- Encrypted entries (ZipCrypto, AES) are listed but not readable yet.

## Verification

| Check | Result |
|---|---|
| Archives from Python `zipfile`/zlib: stored, DEFLATE on text, random and mixed data, empty file, Unicode and URL-encoded names | every entry decompresses to the expected SHA-256 |
| Forced zip64 archive | read correctly |
| Deflate64 archive from 7-Zip | decompresses to the expected SHA-256 |
| Info-ZIP archive | read correctly |
| One byte of content altered | CRC-32 mismatch reported |
| Corrupted and truncated archives, random compressed streams | errors, never panics |
| Throughput (release, one thread) | ~165 MiB/s on DEFLATE-compressed event logs |

Declared sizes and compression ratios are not limits: consumers must bound what they read (zip bombs), as the fuzz tests do.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
