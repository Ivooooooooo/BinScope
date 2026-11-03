use binscope_common::CancelToken;
use binscope_core::{analyze_file, AnalysisOptions};
use binscope_hashing::hash_bytes;
use binscope_pe::{parse_default, PeBuilder};
use binscope_strings::{extract_reader, StringOptions};
use std::io::Cursor;
use std::time::Instant;

fn main() -> std::io::Result<()> {
    let large_mb: usize = std::env::args()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    println!("BinScope stage benchmark");
    println!("large buffer: {large_mb} MiB");
    println!();

    let large = synthetic_buffer(large_mb * 1024 * 1024);

    let start = Instant::now();
    let hashes = hash_bytes(&large);
    println!(
        "hash_bytes (SHA-256+SHA-1+MD5): {:>8.2} ms  sha256={}",
        start.elapsed().as_secs_f64() * 1000.0,
        &hashes.sha256[..16]
    );

    let opts = StringOptions::default();
    let start = Instant::now();
    let strings = extract_reader(
        Cursor::new(large.as_slice()),
        &opts,
        &CancelToken::new(),
        None,
    )
    .expect("strings");
    println!(
        "string extraction:             {:>8.2} ms  {} strings, {} MiB scanned",
        start.elapsed().as_secs_f64() * 1000.0,
        strings.items.len(),
        strings.bytes_scanned / (1024 * 1024)
    );

    let fixture = PeBuilder::pe64()
        .with_export("BenchExport")
        .with_pdb(r"C:\bench\fixture.pdb")
        .with_section(".comment", b"GCC: (GNU) 13.2.0\0".to_vec(), 0x4000_0040)
        .build();
    let iterations = 2_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let pe = parse_default(&fixture).expect("fixture parses");
        std::hint::black_box(pe.entry_point_rva);
    }
    println!(
        "PE header parser:              {:>8.2} ms  {} iterations ({:.1} µs/op)",
        start.elapsed().as_secs_f64() * 1000.0,
        iterations,
        start.elapsed().as_secs_f64() * 1_000_000.0 / iterations as f64
    );

    let dir = std::env::temp_dir().join("binscope-benchmark");
    std::fs::create_dir_all(&dir)?;
    let large_path = dir.join("large-pe.bin");
    let mut builder = PeBuilder::pe64();
    builder
        .extra_sections
        .push((".bigdata".to_string(), large.clone(), 0x4000_0040));
    let image = builder.build();
    std::fs::write(&large_path, &image)?;
    let start = Instant::now();
    let report = analyze_file(
        &large_path,
        &AnalysisOptions::default(),
        &CancelToken::new(),
        None,
    )
    .expect("analysis");
    println!(
        "full analysis ({} MiB):        {:>8.2} ms  {} sections, {} strings",
        image.len() / (1024 * 1024),
        start.elapsed().as_secs_f64() * 1000.0,
        report.pe.as_ref().map(|p| p.sections.len()).unwrap_or(0),
        report
            .strings
            .as_ref()
            .map(|s| s.summary.total)
            .unwrap_or(0)
    );
    let start = Instant::now();
    let report = analyze_file(
        &large_path,
        &AnalysisOptions::default(),
        &CancelToken::new(),
        None,
    )
    .expect("analysis");
    println!(
        "full analysis, second run:     {:>8.2} ms  sha256={}…",
        start.elapsed().as_secs_f64() * 1000.0,
        &report.file.sha256[..16]
    );
    println!();
    println!("Note: wall-clock only; run docs/benchmarks.md's sampler for peak RSS.");
    Ok(())
}

fn synthetic_buffer(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut block = 0usize;
    while data.len() < size {
        let text = format!("binscope-benchmark-string-{block:08}");
        data.extend_from_slice(text.as_bytes());
        data.push(0);

        let target = ((block + 1) * 1024).min(size);
        data.resize(target, 0);
        block += 1;
    }
    data.truncate(size);
    data
}
