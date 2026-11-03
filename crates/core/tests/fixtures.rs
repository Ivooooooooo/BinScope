use binscope_common::CancelToken;
use binscope_core::{analyze_file, AnalysisOptions, AnalysisStatus, Report};
use binscope_file_detect::FormatKind;
use binscope_hashing::hash_bytes;
use binscope_pe::PeBuilder;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn fixture(name: &str) -> PathBuf {
    workspace_root().join("tests").join("fixtures").join(name)
}

fn malformed(name: &str) -> PathBuf {
    workspace_root()
        .join("tests")
        .join("malformed-files")
        .join(name)
}

fn options() -> AnalysisOptions {
    AnalysisOptions {
        yara_enabled: true,
        yara_rule_dirs: vec![workspace_root().join("rules").join("yara")],
        die_signature_dir: Some(workspace_root().join("databases").join("die").join("PE")),
        ..Default::default()
    }
}

fn analyze(path: &std::path::Path) -> Report {
    analyze_file(path, &options(), &CancelToken::new(), None)
        .unwrap_or_else(|e| panic!("analysis of {} failed: {e}", path.display()))
}

#[test]
fn self_signed_fixture_reports_valid_signature_with_untrusted_chain() {
    let report = analyze(&fixture("authenticode/self-signed.exe"));
    let auth = report.authenticode.as_ref().expect("authenticode report");
    assert_eq!(
        auth.presence,
        binscope_authenticode::SignaturePresence::Present
    );
    assert_eq!(
        auth.signature,
        binscope_authenticode::SignatureValidity::Valid
    );
    assert_eq!(auth.chain, binscope_authenticode::ChainTrust::Untrusted);
    assert_eq!(auth.digest_matches, Some(true));
    assert!(auth.signer.is_some());
    assert!(!report
        .pe
        .as_ref()
        .unwrap()
        .anomalies
        .iter()
        .any(|anomaly| anomaly.code == "directory_inconsistent"));
    let json = report.to_json_pretty().unwrap();
    assert!(json.contains("\"authenticode\""));
    assert!(json.contains("\"codeviewRecords\""));
}

#[test]
fn pe32_fixture_regression() {
    let report = analyze(&fixture("pe32-x86.exe"));
    assert_eq!(report.format.kind, FormatKind::Pe);
    assert_eq!(report.format.architecture, "x86");
    assert_eq!(report.format.operating_system, "Windows");
    assert_eq!(report.format.file_type, "EXE");
    assert_eq!(
        report.file.sha256,
        "aa3063b1e06367d805e6ff38998e0ac8c61e42ebbe80aee3aa635b84287298f7"
    );
    let pe = report.pe.expect("PE info");
    assert_eq!(pe.entry_point_rva, 0x1000);
    assert_eq!(pe.image_base, 0x0040_0000);
    assert_eq!(pe.machine, 0x014c);
    assert_eq!(pe.linker_version, "14.29");
    assert!(pe.checksum_valid);
    assert!(pe.imports.iter().any(|lib| lib.name == "KERNEL32.dll"));
    assert!(pe
        .imports
        .iter()
        .flat_map(|l| l.functions.iter())
        .any(|f| f.name.as_deref() == Some("ExitProcess")));
    assert_eq!(pe.exports.len(), 1);
    assert_eq!(pe.exports[0].name.as_deref(), Some("FixtureExport"));
    assert_eq!(pe.exports[0].rva, 0x1010);
    assert_eq!(
        pe.version_info.as_ref().unwrap().company_name.as_deref(),
        Some("BinScope Test")
    );
    assert_eq!(
        pe.pdb.as_ref().unwrap().path,
        r"C:\build\binscope\pe32-fixture.pdb"
    );
    assert!(report.detections.iter().any(|d| d.id == "compiler.msvc"));
    assert!(report.strings.is_some());
}

#[test]
fn msvc_rich_header_fixture_detects_linker() {
    let report = analyze(&fixture("msvc-rich.exe"));
    let rich = report
        .pe
        .as_ref()
        .unwrap()
        .rich_header
        .as_ref()
        .expect("rich");
    assert_eq!(rich.product_ids, vec![0x00C9, 0x00FF]);
    let linker = report
        .detections
        .iter()
        .find(|d| d.id == "linker.msvc")
        .expect("linker detection");
    assert_eq!(linker.confidence, 85);
    assert_eq!(linker.version.as_deref(), Some("14.29"));
}

#[test]
fn pe64_dll_fixture_regression() {
    let report = analyze(&fixture("pe64-x64.dll"));
    assert_eq!(
        report.file.sha256,
        "906a0270bcc27c6c1133a62284cbf90c1c0b997aef87a80faf41af5587347f2e"
    );
    let pe = report.pe.expect("PE info");
    assert!(pe.is_64);
    assert!(pe.is_dll);
    assert_eq!(pe.architecture, "x86-64");
    assert_eq!(pe.machine, 0x8664);
    assert_eq!(pe.image_base, 0x0000_0001_4000_0000);
    assert_eq!(report.format.file_type, "DLL");
    assert_eq!(pe.exports[0].name.as_deref(), Some("FixtureExport"));
}

#[test]
fn managed_assembly_metadata_regression() {
    let report = analyze(&fixture("dotnet-managed.dll"));
    assert_eq!(
        report.file.sha256.to_uppercase(),
        "0F9446E8CA0767D9279615BE819201FC643EB7A2F362163DB6515D98778B6F25"
    );
    assert!(report.format.is_dotnet);
    assert!(report.format.managedness.contains("Managed"));
    let dn = report.dotnet.expect(".NET metadata");
    assert_eq!(dn.runtime_version, "v2.5");
    assert_eq!(dn.metadata_version.as_deref(), Some("v4.0.30319"));
    assert_eq!(dn.kind, "managed");
    assert_eq!(dn.assembly.as_ref().unwrap().name, "FixtureAssembly");
    assert_eq!(dn.assembly.as_ref().unwrap().version, "1.0.0.0");
    assert_eq!(dn.module_name.as_deref(), Some("FixtureModule"));
    assert!(dn.strong_name_signed);
    assert_eq!(dn.entry_point_kind, "MethodDef token 0x06000001 (row 1)");
    let runtime = report
        .detections
        .iter()
        .find(|d| d.id == "runtime.dotnet")
        .expect("runtime detection");
    assert_eq!(runtime.confidence, 100);
    assert!(runtime.version.is_some());
    assert!(report
        .yara
        .matches
        .iter()
        .any(|m| m.rule == "binscope_dotnet_metadata"));
}

#[test]
fn mixed_mode_assembly_is_classified_as_such() {
    let report = analyze(&fixture("dotnet-mixed.dll"));
    let dn = report.dotnet.expect(".NET metadata");
    assert_eq!(dn.kind, "mixed_mode");
    assert!(report.format.managedness.contains("Mixed-mode"));
    assert!(report
        .pe
        .expect("PE")
        .imports
        .iter()
        .any(|lib| lib.name == "mscoree.dll"));
}

#[test]
fn upx_like_fixture_is_detected_with_evidence() {
    let report = analyze(&fixture("upx-like.exe"));
    assert_eq!(
        report.file.sha256,
        "fb672fd1ddb48de95299abf4a29b13c449415a0f0457467dce66407526415a84"
    );
    let upx = report
        .detections
        .iter()
        .find(|d| d.id == "packer.upx")
        .expect("UPX detection");
    assert_eq!(upx.confidence, 98);
    assert!(upx
        .evidence
        .iter()
        .any(|e| e.description.contains("UPX0") || e.description.contains("UPX1")));
    assert!(report
        .yara
        .matches
        .iter()
        .any(|m| m.rule == "binscope_pe_upx_sections"));
    assert!(report
        .detections
        .iter()
        .all(|d| d.id != "die-heuristic.vmprotect"));
}

#[test]
fn msvc_linker_inference_covers_binaries_without_rich_or_pdb() {
    let report = analyze(&fixture("upx-like.exe"));
    let compiler = report
        .detections
        .iter()
        .find(|d| d.id == "compiler.msvc_inferred")
        .expect("MSVC compiler inference");
    assert_eq!(compiler.name, "Microsoft Visual C/C++ (inferred)");
    assert_eq!(compiler.confidence, 55);
    assert_eq!(compiler.version.as_deref(), Some("14.29"));
    let linker = report
        .detections
        .iter()
        .find(|d| d.id == "linker.msvc_version")
        .expect("MSVC linker inference");
    assert_eq!(linker.version.as_deref(), Some("14.29"));
    let language = report
        .detections
        .iter()
        .find(|d| d.id == "language.c_cpp_inferred")
        .expect("C/C++ inference");
    assert!(
        language.version.is_none(),
        "languages have no toolchain version"
    );

    let managed = analyze(&fixture("dotnet-managed.dll"));
    assert!(managed
        .detections
        .iter()
        .all(|d| d.id != "compiler.msvc_inferred"));
    let gcc = analyze(&fixture("gcc-like.exe"));
    assert!(gcc
        .detections
        .iter()
        .all(|d| d.id != "compiler.msvc_inferred"));
}

#[test]
fn die_vmprotect_heuristic_is_reported_with_warning() {
    let bytes = PeBuilder::pe64()
        .with_section(".ofme0", vec![0x90; 16], 0x6000_0020)
        .with_section(".ofme1", vec![0x90; 16], 0xE000_0020)
        .with_section(".ofme2", vec![0x90; 16], 0x6800_0060)
        .build();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vmprotect-like.dll");
    std::fs::write(&path, &bytes).unwrap();
    let report = analyze(&path);
    let detection = report
        .detections
        .iter()
        .find(|d| d.id == "die-heuristic.vmprotect")
        .expect("VMProtect heuristic");
    assert_eq!(detection.name, "VMProtect (heuristic)");
    assert_eq!(detection.confidence, 50);
    assert_eq!(detection.version.as_deref(), Some("2.XX-3.XX"));
    assert!(detection.description.contains("not proof"));
    assert!(detection
        .compatibility
        .as_deref()
        .unwrap()
        .contains("not definitive"));
}

#[test]
fn rule_filters_keep_yara_and_signatures_independent() {
    let path = fixture("upx-like.exe");

    let mut signature_off = options();
    signature_off.rule_filter.disabled_signature_categories = vec!["packers".into()];
    let report = analyze_file(&path, &signature_off, &CancelToken::new(), None).unwrap();
    assert!(report.detections.iter().all(|d| d.id != "packer.upx"));
    assert!(report
        .yara
        .matches
        .iter()
        .any(|m| m.rule == "binscope_pe_upx_sections"));

    let mut yara_off = options();
    yara_off.rule_filter.disabled_yara_categories = vec!["anti-analysis".into()];
    let report = analyze_file(&path, &yara_off, &CancelToken::new(), None).unwrap();
    assert!(report.detections.iter().any(|d| d.id == "packer.upx"));
    assert!(report
        .yara
        .matches
        .iter()
        .all(|m| m.rule != "binscope_pe_upx_sections"));

    let mut individual = options();
    individual
        .rule_filter
        .disabled_signatures
        .push("packer.upx".into());
    individual
        .rule_filter
        .disabled_yara_rules
        .push("binscope_pe_upx_sections".into());
    let report = analyze_file(&path, &individual, &CancelToken::new(), None).unwrap();
    assert!(report.detections.iter().all(|d| d.id != "packer.upx"));
    assert!(report
        .yara
        .matches
        .iter()
        .all(|m| m.rule != "binscope_pe_upx_sections"));
}

#[test]
fn gcc_like_fixture_reports_compiler_version() {
    let report = analyze(&fixture("gcc-like.exe"));
    let gcc = report
        .detections
        .iter()
        .find(|d| d.id == "compiler.gcc")
        .expect("GCC detection");
    assert_eq!(gcc.version.as_deref(), Some("13.2.0"));
    assert!(gcc.evidence.iter().any(|e| e.description.contains("GCC:")));
}

#[test]
fn strings_fixture_contains_ascii_and_utf16() {
    let report = analyze(&fixture("strings.bin"));
    let strings = report.strings.expect("strings");
    let ascii: Vec<&str> = strings
        .items
        .iter()
        .filter(|s| s.encoding == binscope_strings::StringEncoding::Ascii)
        .map(|s| s.value.as_str())
        .collect();
    let wide: Vec<&str> = strings
        .items
        .iter()
        .filter(|s| s.encoding == binscope_strings::StringEncoding::Utf16Le)
        .map(|s| s.value.as_str())
        .collect();
    assert!(ascii.iter().any(|s| s.contains("BinScope")));
    assert!(ascii.iter().any(|s| s.contains("completely-benign-marker")));
    assert!(wide.iter().any(|s| s.contains("análisis")));
    assert!(ascii.iter().all(|s| s.len() >= 4));
}

#[test]
fn elf_fixture_regression() {
    let report = analyze(&fixture("elf64-x86_64"));
    assert_eq!(report.format.kind, FormatKind::Elf);
    assert_eq!(report.format.architecture, "x86-64");
    assert_eq!(report.format.bits, 64);
    assert_eq!(report.format.operating_system, "Linux");
    let elf = report.elf.expect("ELF");
    assert_eq!(elf.entry_point, 0x401000);
    assert_eq!(elf.class, "ELF64");
    assert_eq!(elf.object_type_name, "ET_EXEC (executable)");
    assert_eq!(elf.endianness, "little-endian");
    assert_eq!(elf.os_abi, "Linux");
    assert!(elf.interpreter.is_none());
}

#[test]
fn macho_fixture_regression() {
    let report = analyze(&fixture("macho64-x86_64"));
    assert_eq!(report.format.kind, FormatKind::MachO);
    assert_eq!(report.format.architecture, "x86-64");
    assert_eq!(report.format.operating_system, "macOS");
    let macho = report.macho.expect("Mach-O");
    assert!(!macho.is_fat);
    assert_eq!(macho.slices.len(), 1);
    assert_eq!(macho.slices[0].file_type_name, "MH_EXECUTE");
}

#[test]
fn die_database_detects_real_signature_fixture() {
    let report = analyze(&fixture("die-32lite.exe"));
    let die = report.signatures.die.expect("DIE summary");
    assert!(die.files >= 900, "DIE files={}", die.files);
    assert!(die.compatible >= 20, "compatible={}", die.compatible);
    assert!(die.incompatible > 0);
    let hit = report
        .detections
        .iter()
        .find(|d| d.id.starts_with("die:PE/packer_32LiTe"))
        .expect("DIE 32LiTe detection");
    assert_eq!(hit.name, "32LiTe");
    assert_eq!(hit.version.as_deref(), Some("0.03a"));
    assert!(hit.source.contains("DIE"));
    assert!(hit.compatibility.is_some());
    assert!(hit.evidence[0].description.contains("entry-point"));
}

#[test]
fn pebear_sig_integration_produces_normalized_detection() {
    let dir = tempfile::tempdir().unwrap();
    let sig = dir.path().join("SIG.txt");
    std::fs::write(
        &sig,
        "TestPacker 1.0\n18\n60 06 FC 1E 07 BE 11 22 33 44 6A 04 68 55 66 77 88 68\n",
    )
    .unwrap();
    let path = fixture("die-32lite.exe");
    let settings = AnalysisOptions {
        yara_enabled: false,
        die_signature_dir: None,
        pebear_sig_path: Some(sig),
        ..Default::default()
    };
    let report = analyze_file(&path, &settings, &CancelToken::new(), None).unwrap();
    let summary = report.signatures.pebear.expect("PE-bear summary");
    assert_eq!(summary.loaded, 1);
    let hit = report
        .detections
        .iter()
        .find(|d| d.id == "pebear:TestPacker 1.0")
        .expect("PE-bear detection");
    assert_eq!(hit.category, binscope_signatures::Category::Packer);
    assert!(hit.compatibility.as_deref().unwrap().contains("Historical"));
    assert!(hit.evidence[0].offset.is_some());
}

#[test]
fn default_yara_rules_compile_without_errors() {
    let rules =
        binscope_yara::YaraRuleSet::compile_dir(&workspace_root().join("rules").join("yara"))
            .expect("compile default rules");
    assert!(rules.rule_count() >= 25, "rules={}", rules.rule_count());
    assert!(
        rules.report.errors.is_empty(),
        "YARA compile errors: {:?}",
        rules.report.errors
    );
}

#[test]
fn malformed_files_never_panic_and_report_status() {
    let samples = [
        "truncated-pe.bin",
        "mz-truncated.bin",
        "bad-e-lfanew.exe",
        "bad-optional-magic.exe",
        "zero-sections.exe",
        "truncated-elf.bin",
        "truncated-macho.bin",
        "random.bin",
        "huge-directory-count.exe",
    ];
    for name in samples {
        let path = malformed(name);
        let report = analyze_file(&path, &options(), &CancelToken::new(), None);
        match report {
            Ok(report) => {
                assert!(
                    matches!(
                        report.analysis.status,
                        AnalysisStatus::Complete | AnalysisStatus::Partial
                    ),
                    "{name} produced status {:?}",
                    report.analysis.status
                );
                assert_eq!(
                    report.file.sha256,
                    hash_bytes(&std::fs::read(&path).unwrap()).sha256,
                    "{name} hash mismatch"
                );
            }
            Err(e) => panic!("{name} panicked or failed unexpectedly: {e}"),
        }
    }
}

#[test]
fn json_and_text_exports_are_consistent() {
    let report = analyze(&fixture("pe32-x86.exe"));
    let json = report.to_json_pretty().expect("JSON");
    let parsed: Report = serde_json::from_str(&json).expect("JSON roundtrip");
    assert_eq!(parsed.file.sha256, report.file.sha256);
    assert_eq!(parsed.pe.unwrap().entry_point_rva, 0x1000);
    assert_eq!(parsed.analysis.status, report.analysis.status);
    let text = report.render_text();
    assert!(text.contains(&report.file.sha256));
    assert!(text.contains("Entry point: RVA 0x1000"));
    assert!(text.contains("UPX") || text.contains("Detections"));
}

#[test]
fn every_fixture_produces_a_report() {
    for entry in std::fs::read_dir(workspace_root().join("tests").join("fixtures")).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_file() || path.extension().map(|e| e == "md").unwrap_or(false) {
            continue;
        }
        let report = analyze(&path);
        assert!(!report.file.sha256.is_empty());
        assert_eq!(report.file.size, std::fs::metadata(&path).unwrap().len());
    }
}

#[test]
fn external_yara_rule_is_compiled_and_executed_by_the_real_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("external");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("fixture.yar"),
        r#"rule binscope_external_fixture_marker {
    meta:
        description = "External integration rule"
    strings:
        $marker = "FixtureExport"
    condition:
        $marker
}
"#,
    )
    .unwrap();
    let source = fixture("pe32-x86.exe");
    let bytes = std::fs::read(&source).unwrap();
    let expected_offset = bytes
        .windows("FixtureExport".len())
        .position(|window| window == b"FixtureExport")
        .expect("fixture marker") as u64;
    let options = AnalysisOptions {
        include_strings: false,
        yara_enabled: true,
        yara_rule_dirs: vec![rules.clone()],
        yara_provenance: vec![binscope_core::YaraRootProvenance {
            source_id: "integration-source".into(),
            path: rules,
        }],
        ..Default::default()
    };
    let report = analyze_file(&source, &options, &CancelToken::new(), None).unwrap();
    let matched = report
        .yara
        .matches
        .iter()
        .find(|matched| matched.rule == "binscope_external_fixture_marker")
        .expect("external rule match");
    assert_eq!(matched.scope, "external");
    assert_eq!(matched.source_id, "integration-source");
    assert_eq!(matched.strings.len(), 1);
    assert_eq!(matched.strings[0].offset, expected_offset);
    assert_eq!(matched.strings[0].data, "FixtureExport");
    assert_eq!(report.yara.external_matches, 1);
    assert_eq!(report.yara.internal_matches, 0);
    assert_eq!(report.yara.external_sources, 1);
    assert_eq!(report.yara.revision.len(), 64);
    assert!(report.yara.compile.as_ref().unwrap().errors.is_empty());
}

fn themida_structural_fixture() -> Vec<u8> {
    let mut builder = PeBuilder::pe32();
    builder.text_bytes = (0..0x800).map(|index| (index % 256) as u8).collect();
    let mut data = builder
        .with_section("code0", vec![0x90; 0x200], 0xE000_0020)
        .build();
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = pe + 4 + 20;
    let size = u16::from_le_bytes(data[pe + 20..pe + 22].try_into().unwrap()) as usize;
    let table = opt + size;
    let section_va = |index: usize| {
        u32::from_le_bytes(
            data[table + index * 40 + 12..table + index * 40 + 16]
                .try_into()
                .unwrap(),
        )
    };
    let dirs = opt + 96;
    let resource = section_va(1);
    let import = section_va(2);
    let entry = section_va(3);
    data[dirs + 16..dirs + 20].copy_from_slice(&resource.to_le_bytes());
    data[dirs + 20..dirs + 24].copy_from_slice(&0x20u32.to_le_bytes());
    data[dirs + 8..dirs + 12].copy_from_slice(&import.to_le_bytes());
    data[dirs + 12..dirs + 16].copy_from_slice(&0x20u32.to_le_bytes());
    data[opt + 16..opt + 20].copy_from_slice(&entry.to_le_bytes());
    data
}

#[test]
fn themida_structural_detection_runs_through_analyze_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("themida-structural.exe");
    std::fs::write(&path, themida_structural_fixture()).unwrap();
    let options = AnalysisOptions {
        include_strings: false,
        yara_enabled: false,
        die_signature_dir: Some(workspace_root().join("databases/die/PE")),
        ..Default::default()
    };
    let report = analyze_file(&path, &options, &CancelToken::new(), None).unwrap();
    let detection = report
        .detections
        .iter()
        .find(|detection| detection.id == "die-heuristic.themida")
        .expect("Themida structural detection");
    assert_eq!(detection.category, binscope_signatures::Category::Protector);
    assert_eq!(detection.version.as_deref(), Some("1.X"));
    assert_eq!(detection.vendor.as_deref(), Some("Oreans Technologies"));
    assert_eq!(
        detection.certainty,
        binscope_signatures::DetectionCertainty::StrongHeuristic
    );
    assert_eq!(
        detection.engine,
        binscope_signatures::DetectionEngine::DieHeuristic
    );
    assert!(detection.evidence.len() >= 4);

    let clean = analyze(&fixture("pe32-x86.exe"));
    assert!(clean
        .detections
        .iter()
        .all(|detection| detection.id != "die-heuristic.themida"));
}
