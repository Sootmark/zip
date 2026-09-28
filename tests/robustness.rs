//! Hostile archives and compressed streams: errors, never panics.

use std::io::{Cursor, Read};

use proptest::prelude::*;
use zip::{Archive, Inflate, Variant};

const MIXED: &[u8] = include_bytes!("fixtures/mixed.zip");
/// Bytes read per entry, as a consumer would budget (zip bombs).
const READ_BUDGET: u64 = 8 << 20;

fn read_everything(bytes: Vec<u8>) {
    let Ok(mut archive) = Archive::open(Cursor::new(bytes)) else {
        return;
    };
    for index in 0..archive.entries().len() {
        if let Ok(reader) = archive.reader(index) {
            let _ = reader.take(READ_BUDGET).read_to_end(&mut Vec::new());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn corrupted_archives_never_panic(flips in proptest::collection::vec((0..MIXED.len(), any::<u8>()), 1..24)) {
        let mut bytes = MIXED.to_vec();
        for (at, value) in flips {
            bytes[at] = value;
        }
        read_everything(bytes);
    }

    #[test]
    fn truncated_archives_never_panic(len in 0..MIXED.len()) {
        read_everything(MIXED[..len].to_vec());
    }

    #[test]
    fn random_compressed_streams_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096), deflate64 in any::<bool>()) {
        let variant = if deflate64 { Variant::Deflate64 } else { Variant::Deflate };
        let _ = Inflate::new(data.as_slice(), variant).take(READ_BUDGET).read_to_end(&mut Vec::new());
    }
}
