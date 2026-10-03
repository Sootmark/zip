//! Modification times, from the most precise source a central directory
//! entry records:
//!
//! 1. the NTFS extra field (0x000A): a FILETIME, UTC, 100 ns;
//! 2. the Info-ZIP extended timestamp (0x5455, "UT"): Unix seconds, UTC;
//! 3. the MS-DOS date and time: the zipping machine's wall clock, zone
//!    unknown, 2 s.
//!
//! A source that is missing, malformed, zero or not a valid date falls
//! through to the next. When a field appears more than once, the last
//! well-formed one counts, as with Info-ZIP's `zipinfo`.

use common::bytes::Reader;
use common::time::Ts;

const NTFS_ID: u16 = 0x000a;
/// NTFS attribute holding the modification, access and creation times.
const NTFS_TIMES_TAG: u16 = 0x0001;
const EXTENDED_TIMESTAMP_ID: u16 = 0x5455;
/// Extended-timestamp flag: a modification time follows.
const MTIME_PRESENT: u8 = 0x01;

/// The modification time recorded by an entry's `extra` field and DOS
/// `date` and `time`, or `None` when none of them is a valid time.
pub(crate) fn parse(extra: &[u8], date: u16, time: u16) -> Option<Ts> {
    let mut ntfs = None;
    let mut unix = None;
    for (id, field) in fields(extra) {
        match id {
            NTFS_ID => ntfs = ntfs_mtime(field).or(ntfs),
            EXTENDED_TIMESTAMP_ID => unix = extended_mtime(field).or(unix),
            _ => {}
        }
    }
    ntfs.or(unix).or_else(|| valid(Ts::from_dos(date, time)))
}

/// Each extra field's ID and data, up to the first truncated one.
fn fields(extra: &[u8]) -> impl Iterator<Item = (u16, Reader<'_>)> {
    let mut r = Reader::new(extra);
    std::iter::from_fn(move || {
        let id = r.u16_le().ok()?;
        let length = usize::from(r.u16_le().ok()?);
        Some((id, r.sub(length).ok()?))
    })
}

/// An NTFS extra field: 4 reserved bytes, then tagged attributes.
fn ntfs_mtime(mut field: Reader<'_>) -> Option<Ts> {
    field.skip(4).ok()?;
    loop {
        let tag = field.u16_le().ok()?;
        let size = usize::from(field.u16_le().ok()?);
        let mut attribute = field.sub(size).ok()?;
        if tag == NTFS_TIMES_TAG {
            return valid(Ts::from_filetime(attribute.u64_le().ok()?));
        }
    }
}

/// An extended timestamp: flags, then (in the central directory) only the
/// modification time, as unsigned Unix seconds.
fn extended_mtime(mut field: Reader<'_>) -> Option<Ts> {
    if field.u8().ok()? & MTIME_PRESENT == 0 {
        return None;
    }
    valid(Ts::from_unix_seconds(i64::from(field.u32_le().ok()?)))
}

/// `ts` when it is a time: not zero, a sentinel or an impossible date.
fn valid(ts: Ts) -> Option<Ts> {
    ts.ticks().is_some().then_some(ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// DOS 2020-01-02 03:04:06.
    const DATE: u16 = (40 << 9) | (1 << 5) | 2;
    const TIME: u16 = (3 << 11) | (4 << 5) | 3;

    #[test]
    fn a_field_overrunning_the_extra_data_falls_back_to_dos() {
        let extra = [0x55, 0x54, 0xff, 0xff, 1, 0, 0, 0, 0x60];
        let ts = parse(&extra, DATE, TIME).unwrap();
        assert_eq!(ts.to_string(), "2020-01-02T03:04:06.0000000");
    }

    #[test]
    fn nothing_valid_is_none() {
        assert_eq!(parse(&[], 0, 0), None);
        assert_eq!(parse(&[0x55, 0x54, 1, 0, 1], 0, 0), None);
    }

    /// Time fields (and others) with random data and declared lengths that
    /// may overrun it.
    fn hostile_extra() -> impl Strategy<Value = Vec<u8>> {
        let id = prop_oneof![Just(NTFS_ID), Just(EXTENDED_TIMESTAMP_ID), any::<u16>()];
        let field = (id, 0..48u16, proptest::collection::vec(any::<u8>(), 0..40));
        proptest::collection::vec(field, 0..6).prop_map(|fields| {
            fields
                .into_iter()
                .flat_map(|(id, length, data)| {
                    [id.to_le_bytes(), length.to_le_bytes()]
                        .concat()
                        .into_iter()
                        .chain(data)
                })
                .collect()
        })
    }

    proptest! {
        #[test]
        fn hostile_extra_fields_never_panic(extra in hostile_extra(), date in any::<u16>(), time in any::<u16>()) {
            let _ = parse(&extra, date, time);
        }
    }
}
