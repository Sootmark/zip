//! Archives written by Python's zipfile (zlib), Info-ZIP and 7-Zip
//! (Deflate64): every entry must decompress to the expected content.

use std::io::{Cursor, Read};

use common::json::{self, Json};
use common::sha256::{hex, Sha256};
use zip::Archive;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

fn sha256_of_entry(
    archive: &mut Archive<Cursor<Vec<u8>>>,
    index: usize,
) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut archive.reader(index)?, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

fn hashes(bytes: Vec<u8>) -> Vec<(String, String)> {
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    let names: Vec<String> = archive.entries().iter().map(|e| e.name.clone()).collect();
    names
        .into_iter()
        .enumerate()
        .map(|(i, name)| (name, sha256_of_entry(&mut archive, i).unwrap()))
        .collect()
}

#[test]
fn python_zipfile_entries_match_their_hashes() {
    let expected =
        json::parse(&String::from_utf8(fixture("mixed.expected.json")).unwrap()).unwrap();
    let Json::Object(expected) = expected else {
        panic!("an object")
    };
    let actual = hashes(fixture("mixed.zip"));
    assert_eq!(actual.len(), expected.len());
    for (name, sha256) in actual {
        let want = expected
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v.as_str());
        assert_eq!(Some(sha256.as_str()), want, "{name}");
    }
}

#[test]
fn utf8_and_url_encoded_names_are_kept() {
    let archive = Archive::open(Cursor::new(fixture("mixed.zip"))).unwrap();
    let names: Vec<&str> = archive.entries().iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"unicode/café-日本.txt"));
    assert!(names.contains(&"C%3A/Windows/System32/winevt/Logs/Security.evtx"));
}

#[test]
fn zip64_records_are_followed() {
    let actual = hashes(fixture("zip64.zip"));
    assert_eq!(actual.len(), 1);
    let text = "The quick brown fox jumps over the lazy dog. ".repeat(2000);
    assert_eq!(actual[0].1, hex(&Sha256::digest(text.as_bytes())));
}

#[test]
fn deflate64_from_7zip() {
    let actual = hashes(fixture("deflate64.zip"));
    let find = |name: &str| {
        actual
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, h)| h.as_str())
    };
    assert_eq!(
        find("big.txt"),
        Some("cb89bc31e25dc01d55e415160be6096641f96f5e476010c24bcd75c8f0354217")
    );
    assert_eq!(
        find("rand.bin"),
        Some("6ccafd54474debe1f85a9b312cbbc3f33e8aceb77bffe28c00d2ec8519203e55")
    );
}

#[test]
fn info_zip_archives_read() {
    let mut archive = Archive::open(Cursor::new(fixture("legacy-infozip.zip"))).unwrap();
    assert_eq!(archive.entries()[0].name, "note.txt");
    let mut text = String::new();
    archive
        .reader(0)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "hello from macOS zip\n");
}

#[test]
fn altered_content_fails_the_crc_check() {
    let mut bytes = fixture("mixed.zip");
    let archive = Archive::open(Cursor::new(bytes.clone())).unwrap();
    let index = archive
        .entries()
        .iter()
        .position(|e| e.name == "stored.bin")
        .unwrap();
    let stored = &archive.entries()[index];
    // Stored data starts right after the 30-byte local header and the name.
    let data_start = find(&bytes, b"stored.bin").unwrap() + "stored.bin".len();
    assert_eq!(stored.method, 0);
    bytes[data_start + 1000] ^= 0xff;
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    let error =
        std::io::copy(&mut archive.reader(index).unwrap(), &mut std::io::sink()).unwrap_err();
    assert!(error.to_string().contains("CRC-32 mismatch"), "{error}");
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn rejects_non_zip_data() {
    assert!(Archive::open(Cursor::new(b"definitely not a zip archive".to_vec())).is_err());
}
