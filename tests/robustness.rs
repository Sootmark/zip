//! Hostile archives and compressed streams: errors, never panics.

use std::io::{Cursor, Read};

use proptest::prelude::*;
use zip::{Archive, Inflate, Variant};

const MIXED: &[u8] = include_bytes!("fixtures/mixed.zip");
const ENCRYPTED: &[u8] = include_bytes!("fixtures/aes256-7zip.zip");
const PASSWORD: &[u8] = b"correct horse";
/// Bytes read per entry, as a consumer would budget (zip bombs).
const READ_BUDGET: u64 = 8 << 20;

/// Read every entry to the end, then open every entry as a seekable
/// stream and verify it. Errors are fine; panics and hangs are not.
fn read_everything(bytes: &[u8]) {
    let Ok(mut archive) = Archive::open(Cursor::new(bytes)) else {
        return;
    };
    let count = archive.entries().len();
    for index in 0..count {
        if let Ok(reader) = archive.reader_with_password(index, PASSWORD) {
            let _ = reader.take(READ_BUDGET).read_to_end(&mut Vec::new());
        }
    }
    for index in 0..count {
        let Ok(archive) = Archive::open(Cursor::new(bytes)) else {
            return;
        };
        if let Ok(mut stored) = archive.into_stored(index, Some(PASSWORD)) {
            let _ = stored.verify();
            let _ = (&mut stored).take(READ_BUDGET).read_to_end(&mut Vec::new());
        }
    }
}

fn corrupt(original: &[u8], flips: Vec<(usize, u8)>) -> Vec<u8> {
    let mut bytes = original.to_vec();
    for (at, value) in flips {
        let length = bytes.len();
        bytes[at % length] = value;
    }
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn corrupted_archives_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..24)) {
        read_everything(&corrupt(MIXED, flips));
    }

    #[test]
    fn corrupted_encrypted_archives_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..24)) {
        read_everything(&corrupt(ENCRYPTED, flips));
    }

    #[test]
    fn truncated_archives_never_panic(len in 0..MIXED.len()) {
        read_everything(&MIXED[..len]);
    }

    #[test]
    fn truncated_encrypted_archives_never_panic(len in 0..ENCRYPTED.len()) {
        read_everything(&ENCRYPTED[..len]);
    }

    #[test]
    fn random_compressed_streams_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096), deflate64 in any::<bool>()) {
        let variant = if deflate64 { Variant::Deflate64 } else { Variant::Deflate };
        let _ = Inflate::new(data.as_slice(), variant).take(READ_BUDGET).read_to_end(&mut Vec::new());
    }
}
