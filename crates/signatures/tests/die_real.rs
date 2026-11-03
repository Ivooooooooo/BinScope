use binscope_common::CancelToken;
use binscope_pe::{parse_default, PeBuilder};
use binscope_signatures::die::{evaluate_die, load_die_directory};
use binscope_signatures::SignatureContext;
use binscope_strings::{extract_reader, StringOptions};
use std::io::Cursor;
use std::path::PathBuf;

fn die_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("databases")
        .join("die")
        .join("PE")
}

const PATTERN: &str = "60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? ?? ?? ?? 68";

fn fixture_bytes(mut text: Vec<u8>) -> Vec<u8> {
    text.resize(64, 0x90);
    let mut builder = PeBuilder::pe32();
    builder.text_bytes = text;
    builder.build()
}

#[test]
fn real_die_database_loads_offline_and_reports_compatibility() {
    let db = load_die_directory(&die_dir(), "db@2026-04-16");
    assert!(db.stats.files >= 900, "files={}", db.stats.files);
    assert!(
        db.stats.compatible >= 20,
        "compatible={} stats={:?}",
        db.stats.compatible,
        db.stats
    );
    assert!(db.stats.incompatible > 0);
    assert!(db
        .signatures
        .iter()
        .any(|s| s.name == "32LiTe" && s.version.as_deref() == Some("0.03a")));
}

#[test]
fn real_die_signature_matches_and_negative_does_not() {
    let db = load_die_directory(&die_dir(), "db@2026-04-16");
    let data = fixture_bytes(
        PATTERN
            .split_whitespace()
            .map(|t| {
                if t == "??" {
                    0x00
                } else {
                    u8::from_str_radix(t, 16).unwrap()
                }
            })
            .collect(),
    );
    let pe = parse_default(&data).expect("PE");
    let strings = extract_reader(
        Cursor::new(data.as_slice()),
        &StringOptions::default(),
        &CancelToken::new(),
        None,
    )
    .unwrap()
    .items;
    let ctx = SignatureContext {
        file_bytes: &data,
        pe: Some(&pe),
        elf: None,
        macho: None,
        strings: &strings,
        dotnet_present: false,
        dotnet_kind: None,
    };
    let detections = evaluate_die(&db, &ctx);
    let hit = detections
        .iter()
        .find(|d| d.name == "32LiTe")
        .expect("32LiTe detection");
    assert_eq!(hit.version.as_deref(), Some("0.03a"));
    assert!(hit.source.starts_with("DIE "));
    assert!(hit.compatibility.is_some());
    assert_eq!(hit.evidence[0].condition, "die_compare_ep");
    assert_eq!(
        hit.evidence[0].offset,
        Some(pe.entry_point_file_offset.unwrap())
    );

    let plain = PeBuilder::pe32().build();
    let pe = parse_default(&plain).expect("PE");
    let strings = extract_reader(
        Cursor::new(plain.as_slice()),
        &StringOptions::default(),
        &CancelToken::new(),
        None,
    )
    .unwrap()
    .items;
    let ctx = SignatureContext {
        file_bytes: &plain,
        pe: Some(&pe),
        elf: None,
        macho: None,
        strings: &strings,
        dotnet_present: false,
        dotnet_kind: None,
    };
    assert!(evaluate_die(&db, &ctx).iter().all(|d| d.name != "32LiTe"));
}

#[test]
fn malformed_die_files_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("broken.sg"),
        "meta(\"packer\", \"Broken\"); function detect(){ for(var i=0;i<2;i++){} }",
    )
    .unwrap();
    let db = load_die_directory(temp.path(), "test");
    assert_eq!(db.stats.compatible, 0);
    assert_eq!(db.stats.incompatible, 1);
    assert!(db.stats.reasons.keys().any(|r| r.contains("loops")));
}
