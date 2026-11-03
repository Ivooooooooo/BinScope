use binscope_common::CancelToken;
use binscope_core::{analyze_file, AnalysisOptions};
use binscope_rules::{collect_yara_roots, RuleManager};

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
#[ignore = "requires rule repositories installed by the desktop app in %APPDATA%"]
fn probe_installed_yara_repositories() {
    let data_dir =
        std::path::PathBuf::from(std::env::var("APPDATA").unwrap()).join("com.binscope.analyzer");
    let manager = RuleManager::new(&data_dir);
    let prefs = manager.load_preferences();
    let bundled = workspace_root().join("rules/yara");
    let roots = collect_yara_roots(&manager, &[bundled]);
    assert!(!roots.is_empty(), "no YARA roots are configured");
    let external_roots = roots
        .iter()
        .filter(|root| !matches!(root.source_id.as_str(), "bundled" | "custom" | "legacy"))
        .count();
    if external_roots == 0 {
        eprintln!("no external repositories installed; skipping live match probe");
        return;
    }

    println!("enabled_sources = {:?}", prefs.enabled_sources);
    println!(
        "roots = {:?}",
        roots
            .iter()
            .map(|root| (&root.source_id, &root.path))
            .collect::<Vec<_>>()
    );
    let dirs: Vec<_> = roots.iter().map(|root| root.path.clone()).collect();
    let provenance: Vec<_> = roots
        .iter()
        .map(|root| binscope_core::YaraRootProvenance {
            source_id: root.source_id.clone(),
            path: root.path.clone(),
        })
        .collect();

    let rules = binscope_yara::YaraRuleSet::compile_dirs_cached(&dirs).expect("compile roots");
    println!(
        "rules={} files={} sources={} revision={} errors={}",
        rules.rule_count(),
        rules.report.files,
        rules.sources.len(),
        rules.revision,
        rules.report.errors.len()
    );
    for error in rules.report.errors.iter().take(10) {
        println!("compile error: {error:?}");
    }
    assert!(
        rules.rule_count() > 0,
        "no rules compiled from installed roots"
    );

    let fixture = workspace_root().join("tests/fixtures/pe32-x86.exe");
    let mut bytes = std::fs::read(&fixture).unwrap();

    let marker = b"!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]";
    let marker_offset = bytes.len() as u64;
    bytes.extend_from_slice(marker);
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("external-rule-marker.exe");
    std::fs::write(&target, &bytes).unwrap();

    let options = AnalysisOptions {
        include_strings: false,
        yara_enabled: true,
        yara_rule_dirs: dirs,
        yara_provenance: provenance,
        ..Default::default()
    };
    let report = analyze_file(&target, &options, &CancelToken::new(), None).unwrap();
    println!(
        "matches={} internal={} external={} sources={} internal_sources={} external_sources={} marker_offset={marker_offset:#x}",
        report.yara.matches.len(),
        report.yara.internal_matches,
        report.yara.external_matches,
        report.yara.sources.len(),
        report.yara.internal_sources,
        report.yara.external_sources
    );
    for matched in &report.yara.matches {
        println!(
            "match scope={} source={} rule={} origin={} strings={:?}",
            matched.scope,
            matched.source_id,
            matched.rule,
            matched.origin,
            matched
                .strings
                .iter()
                .map(|item| (&item.identifier, item.offset, &item.data))
                .collect::<Vec<_>>()
        );
    }
    if report
        .yara
        .sources
        .iter()
        .any(|source| source.source_id == "eset-ioc")
    {
        let external = report
            .yara
            .matches
            .iter()
            .find(|matched| matched.rule == "ramFS")
            .expect("eset-ioc ramFS external match");
        assert_eq!(external.scope, "external");
        assert_eq!(external.source_id, "eset-ioc");
        assert!(
            external
                .strings
                .iter()
                .any(|item| item.offset == marker_offset),
            "match evidence offsets must point at the crafted marker"
        );
        assert_eq!(report.yara.external_matches, 1);
    }
}
