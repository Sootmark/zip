//! Measure decompression speed: `cargo run --release --example inflate_speed -- <archive.zip>`.

use std::io::Read;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: inflate_speed <archive.zip>")?;
    let mut archive = zip::Archive::open(std::io::BufReader::new(std::fs::File::open(path)?))?;
    let started = Instant::now();
    let mut total = 0u64;
    for index in 0..archive.entries().len() {
        total += std::io::copy(
            &mut archive.reader(index)?.take(u64::MAX),
            &mut std::io::sink(),
        )?;
    }
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "{:.1} MiB in {seconds:.2}s: {:.0} MiB/s",
        total as f64 / 1_048_576.0,
        total as f64 / 1_048_576.0 / seconds
    );
    Ok(())
}
