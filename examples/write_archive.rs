//! Write test archives for checking with other tools:
//! `cargo run --release --example write_archive -- <sample|large|many> <out.zip>`.
//!
//! - `sample`: names, contents and modification times of every kind;
//! - `large`: a 4.5 GiB entry, then one past 4 GiB (zip64 sizes and offsets);
//! - `many`: 70,000 entries (zip64 end records).
//!
//! Then `unzip -t`, `zipinfo -v`, `7z t` and Python's `zipfile` `testzip()`.

use std::fs::File;
use std::io::{self, BufWriter, Read};

use common::time::{Precision, Ts, TICKS_PER_SECOND};
use sootmark_zip::Writer;

/// `remaining` bytes of a repeating pattern, generated, not stored.
struct Synthetic {
    remaining: u64,
}

impl Read for Synthetic {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        for (i, byte) in buf[..count].iter_mut().enumerate() {
            *byte = ((self.remaining - i as u64) % 251) as u8;
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

fn utc(unix_seconds: i64, fraction_ticks: i64) -> Ts {
    Ts::from_ticks(
        unix_seconds * TICKS_PER_SECOND + fraction_ticks,
        Precision::Tick,
    )
}

fn sample(writer: &mut Writer<BufWriter<File>>) -> io::Result<()> {
    let local = Ts::from_local_ticks(1_614_834_367 * TICKS_PER_SECOND, Precision::Second);
    let entries: [(&str, Option<Ts>, u64); 8] = [
        (
            "C/Windows/System32/winevt/Logs/Security.evtx",
            Some(utc(1_614_834_367, 1_234_567)),
            200_000,
        ),
        ("C/$Extend/$UsnJrnl:$J", Some(utc(946_684_798, 0)), 70_000),
        ("Users/Zoë/桌面/notes.txt", Some(utc(1_700_000_000, 5)), 6),
        ("empty", Some(utc(1_614_834_367, 0)), 0),
        ("no-time", None, 10),
        ("local-time", Some(local), 10),
        ("before-1980", Some(utc(157_766_400, 0)), 10),
        ("after-2038", Some(utc(4_102_444_800, 0)), 10),
    ];
    for (name, modified, size) in entries {
        let entry = writer.add(name, modified, &mut Synthetic { remaining: size })?;
        println!("{name}: {} bytes, CRC-32 {:08x}", entry.size, entry.crc32);
    }
    Ok(())
}

fn large(writer: &mut Writer<BufWriter<File>>) -> io::Result<()> {
    for (name, size) in [("large.bin", 9 << 29), ("after.bin", 1_000)] {
        let entry = writer.add(
            name,
            Some(utc(1_614_834_367, 0)),
            &mut Synthetic { remaining: size },
        )?;
        println!(
            "{name}: {} bytes at {}, CRC-32 {:08x}",
            entry.size, entry.offset, entry.crc32
        );
    }
    Ok(())
}

fn many(writer: &mut Writer<BufWriter<File>>) -> io::Result<()> {
    for i in 0..70_000 {
        let name = format!("logs/{:02}/{i:05}.log", i % 100);
        writer.add(
            &name,
            Some(utc(1_614_834_367 + i, 0)),
            &mut Synthetic {
                remaining: i as u64 % 64,
            },
        )?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: write_archive <sample|large|many> <out.zip>";
    let mut args = std::env::args().skip(1);
    let (kind, path) = (args.next().ok_or(usage)?, args.next().ok_or(usage)?);
    let mut writer = Writer::new(BufWriter::new(File::create(path)?));
    match kind.as_str() {
        "sample" => sample(&mut writer)?,
        "large" => large(&mut writer)?,
        "many" => many(&mut writer)?,
        _ => return Err(usage.into()),
    }
    writer.finish()?;
    Ok(())
}
