//! WinZip AES archives written by 7-Zip (AE-2) and libarchive/bsdtar
//! (AE-1): every entry must decrypt to the content it was made from.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use common::sha256::{hex, Sha256};
use sootmark_zip::{Aes, Archive, Encryption, Strength};

const PASSWORD: &[u8] = b"correct horse";
/// `shasum -a 256` of the files the fixtures were made from.
const EXPECTED: [(&str, &str); 3] = [
    (
        "notes.txt",
        "2085fe49c540e83be59dd33e66615b6e30fedd239023dfc7f79edc885d246025",
    ),
    (
        "random.bin",
        "97b09d08daf88c6622d8cc2d60e57e4d24fff4e52fa386d79162c9c5206fe581",
    ),
    (
        "empty.txt",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
];

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

fn open(bytes: Vec<u8>) -> Archive<Cursor<Vec<u8>>> {
    Archive::open(Cursor::new(bytes)).unwrap()
}

fn expected(name: &str) -> &'static str {
    EXPECTED.iter().find(|(n, _)| *n == name).unwrap().1
}

fn sha256(reader: &mut dyn Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(reader, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

#[test]
fn every_writer_decrypts_to_the_original_content() {
    for name in [
        "aes256-7zip.zip",
        "aes128-stored-7zip.zip",
        "aes256-libarchive.zip",
    ] {
        let mut archive = open(fixture(name));
        for index in 0..archive.entries().len() {
            let entry = archive.entries()[index].clone();
            let mut reader = archive.reader_with_password(index, PASSWORD).unwrap();
            assert_eq!(
                sha256(&mut reader).unwrap(),
                expected(&entry.name),
                "{name}: {}",
                entry.name
            );
        }
    }
}

#[test]
fn entries_describe_their_encryption() {
    let archive = open(fixture("aes256-7zip.zip"));
    let notes = archive
        .entries()
        .iter()
        .find(|e| e.name == "notes.txt")
        .unwrap();
    assert_eq!(
        notes.encryption,
        Some(Encryption::Aes(Aes {
            strength: Strength::Aes256,
            ae2: true,
            method: 8,
        }))
    );
    assert_eq!(notes.method, 8, "the real method, not the AES marker");
    let libarchive = open(fixture("aes256-libarchive.zip"));
    assert!(matches!(
        libarchive.entries()[0].encryption,
        Some(Encryption::Aes(Aes { ae2: false, .. }))
    ));
}

#[test]
fn a_wrong_or_missing_password_is_refused() {
    let mut archive = open(fixture("aes256-7zip.zip"));
    let error = archive.reader_with_password(0, b"wrong").err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let error = archive.reader(0).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn zipcrypto_is_listed_but_not_read() {
    let mut archive = open(fixture("zipcrypto.zip"));
    assert_eq!(
        archive.entries()[0].encryption,
        Some(Encryption::Unsupported)
    );
    let error = archive.reader_with_password(0, PASSWORD).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

/// Flip one ciphertext byte of every entry in turn: reading it to the end
/// must fail, never return altered content as good.
#[test]
fn altered_ciphertext_is_detected() {
    for name in ["aes256-7zip.zip", "aes256-libarchive.zip"] {
        let original = fixture(name);
        let entries = open(original.clone()).entries().to_vec();
        for (index, entry) in entries.iter().enumerate() {
            if entry.size == 0 {
                continue;
            }
            // The last ciphertext byte, just before the 10-byte HMAC.
            let end = data_start(&original, &entry.name) + entry.compressed_size as usize;
            let mut altered = original.clone();
            altered[end - 11] ^= 0x40;
            let mut archive = open(altered);
            let outcome = archive
                .reader_with_password(index, PASSWORD)
                .and_then(|mut reader| sha256(&mut reader));
            assert!(
                outcome.is_err(),
                "{name}: {} altered but accepted",
                entry.name
            );
        }
    }
}

/// Where an entry's data starts: after its local header, name and extra
/// field. (Sizes come from the central directory: writers that stream,
/// like libarchive, leave them zero in the local header.)
fn data_start(archive: &[u8], name: &str) -> usize {
    let signature = [0x50, 0x4b, 0x03, 0x04];
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([archive[at], archive[at + 1]]));
    let mut at = 0;
    loop {
        let header = at
            + archive[at..]
                .windows(4)
                .position(|w| w == signature)
                .unwrap();
        let name_length = u16_at(header + 26);
        let extra_length = u16_at(header + 28);
        if &archive[header + 30..header + 30 + name_length] == name.as_bytes() {
            return header + 30 + name_length + extra_length;
        }
        at = header + 4;
    }
}

#[test]
fn a_stored_encrypted_entry_seeks_like_a_file() {
    let bytes = fixture("aes128-stored-7zip.zip");
    let archive = open(bytes.clone());
    let index = archive
        .entries()
        .iter()
        .position(|e| e.name == "random.bin")
        .unwrap();
    let mut plain = Vec::new();
    open(bytes.clone())
        .reader_with_password(index, PASSWORD)
        .unwrap()
        .read_to_end(&mut plain)
        .unwrap();

    let mut stored = archive.into_stored(index, Some(PASSWORD)).unwrap();
    stored.verify().unwrap();
    // Unaligned offsets across AES block boundaries, forwards and back.
    for offset in [0u64, 1, 15, 16, 17, 4095, 65_537, 69_990, 5] {
        let mut buf = [0u8; 23];
        stored.seek(SeekFrom::Start(offset)).unwrap();
        let count = stored.read(&mut buf).unwrap();
        let start = offset as usize;
        assert_eq!(&buf[..count], &plain[start..start + count], "at {offset}");
    }
    stored.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(
        sha256(&mut stored).unwrap(),
        expected("random.bin"),
        "whole stream"
    );
}

#[test]
fn verify_catches_altered_stored_entries() {
    let original = fixture("aes128-stored-7zip.zip");
    let start = data_start(&original, "random.bin");
    let mut altered = original;
    altered[start + 5_000] ^= 1;
    let archive = open(altered);
    let index = archive
        .entries()
        .iter()
        .position(|e| e.name == "random.bin")
        .unwrap();
    let mut stored = archive.into_stored(index, Some(PASSWORD)).unwrap();
    assert!(stored.verify().is_err());
}

#[test]
fn only_stored_entries_become_streams() {
    let archive = open(fixture("aes256-7zip.zip"));
    let deflated = archive
        .entries()
        .iter()
        .position(|e| e.name == "notes.txt")
        .unwrap();
    let error = archive.into_stored(deflated, Some(PASSWORD)).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}
