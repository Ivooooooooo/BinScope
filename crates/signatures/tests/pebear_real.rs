use binscope_signatures::pebear::parse_pebear;

#[test]
fn real_pebear_signature_file_if_available() {
    let Ok(path) = std::env::var("PEBEAR_SIG_PATH") else {
        eprintln!("PEBEAR_SIG_PATH not set; skipping optional real SIG.txt test");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read SIG.txt");
    let db = parse_pebear(&text);
    assert!(db.total_blocks > 1000, "blocks={}", db.total_blocks);
    assert!(db.signatures.len() > 500, "loaded={}", db.signatures.len());
    assert!(db.signatures.iter().any(|s| s.name.contains("ASPack")));
    assert!(db
        .signatures
        .iter()
        .any(|s| s.name.contains("UPX") || s.name.contains("ASPack")));
    let sig = db
        .signatures
        .iter()
        .find(|s| s.name.contains("ASPack"))
        .expect("ASPack signature");
    let mut buffer = vec![0u8; sig.pattern.len() + 16];
    let start = 6;
    for (i, byte) in sig.pattern.iter().enumerate() {
        buffer[start + i] = byte.unwrap_or(0);
    }
    let hits = binscope_signatures::pebear::scan_bytes(&db, &buffer, 20);
    assert!(
        hits.iter()
            .any(|(idx, off)| db.signatures[*idx].name == sig.name && *off == start),
        "real ASPack signature did not match its own bytes"
    );
    eprintln!(
        "PE-bear: {} blocks, {} loaded, {} skipped",
        db.total_blocks,
        db.signatures.len(),
        db.skipped
    );
}
