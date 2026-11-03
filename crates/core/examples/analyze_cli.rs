use binscope_common::CancelToken;
use binscope_core::{analyze_file, AnalysisOptions, AnalysisStatus};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!(
            "BinScope CLI\n\nUsage:\n  analyze_cli <file> [--json out.json] [--txt out.txt]\n              [--yara dir] [--die dir] [--pebear SIG.txt] [--no-strings] [--min-len N] [--no-signatures]"
        );
        std::process::exit(if args.is_empty() { 2 } else { 0 });
    }
    let mut path = None;
    let mut json_out = None;
    let mut txt_out = None;
    let mut yara_dirs = Vec::new();
    let mut options = AnalysisOptions {
        yara_enabled: false,
        ..Default::default()
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                index += 1;
                json_out = args.get(index).map(PathBuf::from);
            }
            "--txt" => {
                index += 1;
                txt_out = args.get(index).map(PathBuf::from);
            }
            "--yara" => {
                index += 1;
                if let Some(dir) = args.get(index) {
                    yara_dirs.push(PathBuf::from(dir));
                    options.yara_enabled = true;
                }
            }
            "--no-strings" => options.include_strings = false,
            "--no-signatures" => options.signatures_enabled = false,
            "--die" => {
                index += 1;
                if let Some(dir) = args.get(index) {
                    options.die_signature_dir = Some(PathBuf::from(dir));
                }
            }
            "--pebear" => {
                index += 1;
                if let Some(path) = args.get(index) {
                    options.pebear_sig_path = Some(PathBuf::from(path));
                }
            }
            "--min-len" => {
                index += 1;
                if let Some(value) = args.get(index).and_then(|v| v.parse().ok()) {
                    options.min_string_len = value;
                }
            }
            other => path = Some(PathBuf::from(other)),
        }
        index += 1;
    }
    let Some(path) = path else {
        eprintln!("error: no input file");
        std::process::exit(2);
    };
    options.yara_rule_dirs = yara_dirs;

    let started = std::time::Instant::now();
    let report = match analyze_file(&path, &options, &CancelToken::new(), None) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("analysis failed: {e}");
            std::process::exit(1);
        }
    };
    println!("File:      {}", report.file.path);
    println!(
        "Size:      {} ({})",
        report.file.size, report.file.size_human
    );
    println!("SHA-256:   {}", report.file.sha256);
    println!("SHA-1:     {}", report.file.sha1);
    println!("MD5:       {}", report.file.md5);
    println!(
        "Format:    {} — {} ({}-bit, {})",
        report.format.label,
        report.format.description,
        report.format.bits,
        report.format.operating_system
    );
    println!("Type:      {}", report.format.file_type);
    println!("Managed:   {}", report.format.managedness);
    println!("Status:    {:?}", report.analysis.status);
    if let Some(pe) = &report.pe {
        println!("Machine:   {} ({})", pe.machine_name, pe.architecture);
        println!("Entry RVA: {:#x}", pe.entry_point_rva);
        println!("ImageBase: {:#x}", pe.image_base);
        println!("Sections:  {}", pe.sections.len());
        println!("Imports:   {}", pe.imports.len());
        println!("Exports:   {}", pe.exports.len());
        println!(
            "Checksum:  {:#010x} ({})",
            pe.checksum,
            if pe.checksum_valid {
                "valid"
            } else {
                "not validated"
            }
        );
    }
    if let Some(dn) = &report.dotnet {
        if let Some(assembly) = &dn.assembly {
            println!(
                "Assembly:  {} {} (runtime {})",
                assembly.name, assembly.version, dn.runtime_version
            );
        }
    }
    println!("Detections ({}):", report.detections.len());
    for detection in &report.detections {
        println!(
            "  [{:?}] {}{} — {}% ({})",
            detection.category,
            detection.name,
            detection
                .version
                .as_ref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default(),
            detection.confidence,
            detection.source
        );
        for evidence in &detection.evidence {
            println!("      · {}", evidence.description);
        }
    }
    if report.yara.enabled {
        println!(
            "YARA matches: {} ({} rules)",
            report.yara.matches.len(),
            report.yara.rule_count
        );
        for m in &report.yara.matches {
            println!("  · {} [{}]", m.rule, m.namespace);
        }
    }
    if let Some(strings) = &report.strings {
        println!(
            "Strings:   {} (ASCII {}, UTF-16LE {}, truncated: {})",
            strings.summary.total,
            strings.summary.ascii,
            strings.summary.utf16le,
            strings.summary.truncated
        );
    }
    if let Some(pe) = &report.pe {
        println!("Anomalies: {}", pe.anomalies.len());
        for anomaly in &pe.anomalies {
            println!(
                "  [{:?}] {}: {}",
                anomaly.severity, anomaly.code, anomaly.message
            );
        }
    }
    println!("Duration:  {} ms", started.elapsed().as_millis());

    if let Some(target) = json_out {
        match report.to_json_pretty() {
            Ok(json) => {
                if let Err(e) = std::fs::write(&target, json) {
                    eprintln!("could not write {}: {e}", target.display());
                    std::process::exit(1);
                }
                println!("JSON report: {}", target.display());
            }
            Err(e) => {
                eprintln!("could not serialize report: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(target) = txt_out {
        if let Err(e) = std::fs::write(&target, report.render_text()) {
            eprintln!("could not write {}: {e}", target.display());
            std::process::exit(1);
        }
        println!("Text report: {}", target.display());
    }
    if report.analysis.status == AnalysisStatus::Failed {
        std::process::exit(1);
    }
}
