use binscope_common::CancelToken;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use thiserror::Error;
use yara_x::{Compiler, Rules, Scanner, SourceCode};

pub const ENGINE_VERSION: &str = "1.22.1";
const MAX_RULE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RULE_FILES: usize = 2048;

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("no YARA rules could be compiled")]
    NoRules,
    #[error("YARA scan failed: {0}")]
    Scan(String),
    #[error("I/O error reading rules: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraDiagnostic {
    pub source: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraCompileReport {
    pub files: usize,
    pub errors: Vec<YaraDiagnostic>,
    pub warnings: Vec<YaraDiagnostic>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraSourceFile {
    pub origin: String,
    #[serde(default)]
    pub source_id: String,
    #[serde(default)]
    pub scope: String,
    pub sha256: String,
    pub bytes: u64,
    pub text: Option<String>,
    pub truncated: bool,
}

const MAX_SOURCE_TEXT_BYTES: usize = 256 * 1024;

fn source_record(origin: &str, text: &str, sha256: String) -> YaraSourceFile {
    let bytes = text.len() as u64;
    let (source_text, truncated) = if text.len() > MAX_SOURCE_TEXT_BYTES {
        let mut end = MAX_SOURCE_TEXT_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        (Some(text[..end].to_string()), true)
    } else {
        (Some(text.to_string()), false)
    };
    YaraSourceFile {
        origin: origin.to_string(),
        source_id: String::new(),
        scope: String::new(),
        sha256,
        bytes,
        text: source_text,
        truncated,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn manifest_revision(sources: &[YaraSourceFile]) -> String {
    let mut lines: Vec<String> = sources
        .iter()
        .map(|source| format!("{}\0{}", normalize_origin(&source.origin), source.sha256))
        .collect();
    lines.sort();
    sha256_hex(lines.join("\n").as_bytes())
}

fn normalize_origin(origin: &str) -> String {
    origin.replace('\\', "/").to_ascii_lowercase()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,

    pub data: String,

    pub hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Option<String>,
    pub metadata: serde_json::Value,
    pub source: String,

    pub origin: String,

    #[serde(default)]
    pub source_id: String,
    #[serde(default)]
    pub scope: String,

    #[serde(default)]
    pub strings: Vec<YaraStringMatch>,
}

pub struct YaraRuleSet {
    rules: Rules,
    pub report: YaraCompileReport,
    pub namespaces: Vec<String>,

    pub sources: Vec<YaraSourceFile>,

    pub revision: String,
}

impl YaraRuleSet {
    pub fn compile_dir(dir: &Path) -> Result<Self, YaraError> {
        let mut files = Vec::new();
        collect_rule_files(dir, &mut files)?;
        files.sort();
        Self::compile_files(&files)
    }

    fn rule_cache() -> &'static Mutex<HashMap<String, Arc<YaraRuleSet>>> {
        static CACHE: OnceLock<Mutex<HashMap<String, Arc<YaraRuleSet>>>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn revision_for_dirs(dirs: &[PathBuf]) -> Result<String, YaraError> {
        let mut files = Vec::new();
        for dir in dirs {
            collect_rule_files(dir, &mut files)?;
        }
        files.sort();
        files.dedup();
        let mut sources = Vec::with_capacity(files.len());
        for file in files {
            let origin = file.display().to_string();
            match std::fs::metadata(&file) {
                Ok(metadata) if metadata.len() > MAX_RULE_FILE_BYTES => {
                    sources.push(YaraSourceFile {
                        origin,
                        source_id: String::new(),
                        scope: String::new(),
                        sha256: format!("oversize:{}", metadata.len()),
                        bytes: metadata.len(),
                        text: None,
                        truncated: true,
                    });
                }
                Ok(_) => match std::fs::read_to_string(&file) {
                    Ok(text) => {
                        let hash = sha256_hex(text.as_bytes());
                        sources.push(source_record(&origin, &text, hash));
                    }
                    Err(error) => sources.push(YaraSourceFile {
                        origin,
                        source_id: String::new(),
                        scope: String::new(),
                        sha256: format!("unreadable:{}", error.kind()),
                        bytes: 0,
                        text: None,
                        truncated: true,
                    }),
                },
                Err(error) => sources.push(YaraSourceFile {
                    origin,
                    source_id: String::new(),
                    scope: String::new(),
                    sha256: format!("missing:{}", error.kind()),
                    bytes: 0,
                    text: None,
                    truncated: true,
                }),
            }
        }
        Ok(manifest_revision(&sources))
    }

    pub fn compile_dirs(dirs: &[PathBuf]) -> Result<Self, YaraError> {
        let mut files = Vec::new();
        for dir in dirs {
            collect_rule_files(dir, &mut files)?;
        }
        files.sort();
        files.dedup();
        Self::compile_files(&files)
    }

    pub fn compile_files(files: &[PathBuf]) -> Result<Self, YaraError> {
        let mut compiler = Compiler::new();
        let mut report = YaraCompileReport {
            files: files.len(),
            ..Default::default()
        };
        let mut namespaces = Vec::new();
        let mut sources = Vec::new();
        for file in files {
            let metadata = match std::fs::metadata(file) {
                Ok(m) => m,
                Err(e) => {
                    report.errors.push(YaraDiagnostic {
                        source: file.display().to_string(),
                        message: e.to_string(),
                    });
                    continue;
                }
            };
            if metadata.len() > MAX_RULE_FILE_BYTES {
                report.errors.push(YaraDiagnostic {
                    source: file.display().to_string(),
                    message: format!(
                        "rule file is {} bytes, above the {} byte limit",
                        metadata.len(),
                        MAX_RULE_FILE_BYTES
                    ),
                });
                continue;
            }
            let text = match std::fs::read_to_string(file) {
                Ok(t) => t,
                Err(e) => {
                    report.errors.push(YaraDiagnostic {
                        source: file.display().to_string(),
                        message: e.to_string(),
                    });
                    continue;
                }
            };
            let origin = file.display().to_string();
            let hash = sha256_hex(text.as_bytes());
            compiler.new_namespace(origin.as_str());
            match compiler.add_source(SourceCode::from(text.as_str()).with_origin(origin.as_str()))
            {
                Ok(_) => {
                    if !namespaces.contains(&origin) {
                        namespaces.push(origin.clone());
                    }
                    sources.push(source_record(&origin, &text, hash));
                }
                Err(e) => {
                    report.errors.push(YaraDiagnostic {
                        source: origin,
                        message: e.to_string(),
                    });
                }
            }
        }
        let revision = manifest_revision(&sources);
        let rules = compiler.build();
        if rules.iter().count() == 0 {
            return Err(YaraError::NoRules);
        }
        Ok(Self {
            rules,
            report,
            namespaces,
            sources,
            revision,
        })
    }

    pub fn compile_dirs_cached(dirs: &[PathBuf]) -> Result<Arc<Self>, YaraError> {
        let revision = Self::revision_for_dirs(dirs)?;
        let key = format!("{}:{revision}", ENGINE_VERSION);
        let cache = Self::rule_cache();
        if let Ok(guard) = cache.lock() {
            if let Some(rules) = guard.get(&key) {
                return Ok(Arc::clone(rules));
            }
        }
        let compiled = Arc::new(Self::compile_dirs(dirs)?);
        if let Ok(mut guard) = cache.lock() {
            if guard.len() >= 4 {
                guard.clear();
            }
            guard.insert(key, Arc::clone(&compiled));
        }
        Ok(compiled)
    }

    pub fn compile_source(origin: &str, source: &str) -> Result<Self, YaraError> {
        let mut compiler = Compiler::new();
        let mut report = YaraCompileReport {
            files: 1,
            ..Default::default()
        };
        compiler.new_namespace(origin);
        match compiler.add_source(SourceCode::from(source).with_origin(origin)) {
            Ok(_) => {}
            Err(e) => {
                report.errors.push(YaraDiagnostic {
                    source: origin.to_string(),
                    message: e.to_string(),
                });
                return Err(YaraError::NoRules);
            }
        }
        let sources = vec![source_record(origin, source, sha256_hex(source.as_bytes()))];
        let revision = manifest_revision(&sources);
        let rules = compiler.build();
        Ok(Self {
            rules,
            report,
            namespaces: vec![origin.to_string()],
            sources,
            revision,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().count()
    }

    pub fn scan(
        &self,
        data: &[u8],
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        cancel
            .check()
            .map_err(|_| YaraError::Scan("cancelled".into()))?;
        let mut scanner = Scanner::new(&self.rules);
        scanner.set_timeout(timeout);
        let results = scanner
            .scan(data)
            .map_err(|e| YaraError::Scan(e.to_string()))?;
        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            let metadata = rule.metadata().into_json();
            let description = metadata_string(&metadata, "description");
            let author = metadata_string(&metadata, "author");
            let reference = metadata_string(&metadata, "reference");
            let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();
            matches.push(YaraMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags,
                description,
                author,
                reference,
                metadata,
                source: "YARA-X".to_string(),
                origin: rule.namespace().to_string(),
                source_id: String::new(),
                scope: String::new(),
                strings: collect_string_matches(&rule),
            });
        }
        matches.sort_by(|a, b| a.rule.cmp(&b.rule));
        Ok(matches)
    }
}

fn collect_string_matches(rule: &yara_x::Rule<'_, '_>) -> Vec<YaraStringMatch> {
    const MAX_MATCHES: usize = 128;
    let mut out = Vec::new();
    for pattern in rule.patterns() {
        let identifier = pattern.identifier().to_string();
        for matched in pattern.matches() {
            let range = matched.range();
            let data = matched.data();
            out.push(YaraStringMatch {
                identifier: identifier.clone(),
                offset: range.start as u64,
                length: range.len(),
                data: printable_preview(data, 48),
                hex: hex_preview(data, 64),
            });
            if out.len() >= MAX_MATCHES {
                return out;
            }
        }
    }
    out
}

fn printable_preview(data: &[u8], limit: usize) -> String {
    let mut out: String = data
        .iter()
        .take(limit)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect();
    if data.len() > limit {
        out.push_str("...");
    }
    out
}

fn hex_preview(data: &[u8], limit: usize) -> String {
    let mut out = data
        .iter()
        .take(limit)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    if data.len() > limit {
        out.push_str(" ...");
    }
    out
}

fn metadata_string(metadata: &serde_json::Value, key: &str) -> Option<String> {
    metadata
        .as_array()?
        .iter()
        .find(|pair| pair.get(0).and_then(|v| v.as_str()) == Some(key))
        .and_then(|pair| pair.get(1))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), YaraError> {
    if out.len() >= MAX_RULE_FILES {
        return Ok(());
    }
    if dir.is_file() {
        out.push(dir.to_path_buf());
        return Ok(());
    }
    let entries = std::fs::read_dir(dir)?;
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if out.len() >= MAX_RULE_FILES {
            break;
        }
        if path.is_dir() {
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    continue;
                }
            }
            collect_rule_files(&path, out)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule matches_mz {
    meta:
        description = "Test rule for MZ files"
        author = "BinScope tests"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule does_not_match {
    strings:
        $needle = "this string is definitely absent"
    condition:
        $needle
}
"#;

    #[test]
    fn matching_and_non_matching_rules_are_separated() {
        let rules = YaraRuleSet::compile_source("test.yar", RULES).expect("compile");
        let matches = rules
            .scan(
                b"MZ\x90\x00payload",
                Duration::from_secs(5),
                &CancelToken::new(),
            )
            .expect("scan");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "matches_mz");
        assert_eq!(
            matches[0].description.as_deref(),
            Some("Test rule for MZ files")
        );
        assert_eq!(matches[0].author.as_deref(), Some("BinScope tests"));
    }

    #[test]
    fn rules_do_not_match_unrelated_data() {
        let rules = YaraRuleSet::compile_source("test.yar", RULES).expect("compile");
        let matches = rules
            .scan(
                b"not a PE file",
                Duration::from_secs(5),
                &CancelToken::new(),
            )
            .expect("scan");
        assert!(matches.is_empty());
    }

    #[test]
    fn broken_rules_report_diagnostics_without_hiding_valid_ones() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("good.yar"), RULES).unwrap();
        std::fs::write(
            temp.path().join("bad.yar"),
            "rule broken { condition: $undefined }",
        )
        .unwrap();
        let rules = YaraRuleSet::compile_dir(temp.path()).expect("compile dir");
        assert_eq!(rules.report.errors.len(), 1);
        assert!(rules.report.errors[0].source.ends_with("bad.yar"));
        assert_eq!(rules.rule_count(), 2);
    }

    #[test]
    fn nested_directories_and_multiple_repositories_compile_together() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(first.path().join("nested/deeper")).unwrap();
        std::fs::write(
            first.path().join("root.yar"),
            "rule root_rule { condition: true }",
        )
        .unwrap();
        std::fs::write(
            first.path().join("nested/deeper/child.yara"),
            "rule child_rule { condition: true }",
        )
        .unwrap();
        std::fs::write(
            second.path().join("other.yara"),
            "rule other_repo_rule { condition: true }",
        )
        .unwrap();
        let rules =
            YaraRuleSet::compile_dirs(&[first.path().to_path_buf(), second.path().to_path_buf()])
                .expect("compile both repositories");
        assert_eq!(rules.rule_count(), 3);
        assert_eq!(rules.report.files, 3);
        assert!(rules.report.errors.is_empty());
        assert_eq!(rules.sources.len(), 3);
    }

    #[test]
    fn empty_rule_directory_reports_no_rules_without_panicking() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            YaraRuleSet::compile_dir(temp.path()),
            Err(YaraError::NoRules)
        ));
    }

    #[test]
    fn unsupported_modules_are_rejected_without_dropping_valid_rules() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("good.yar"),
            "rule good_rule { condition: true }",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("unsupported.yar"),
            "import \"binscope_no_such_module\"\nrule broken_import { condition: binscope_no_such_module.some_function() }",
        )
        .unwrap();
        let rules = YaraRuleSet::compile_dir(temp.path()).expect("compile dir");
        assert_eq!(rules.rule_count(), 1);
        assert_eq!(rules.report.errors.len(), 1);
        assert!(rules.report.errors[0].source.ends_with("unsupported.yar"));
    }

    #[test]
    fn missing_directory_is_an_io_error() {
        assert!(matches!(
            YaraRuleSet::compile_dir(Path::new("definitely-not-a-real-directory")),
            Err(YaraError::Io(_))
        ));
    }

    #[test]
    fn metadata_json_is_preserved() {
        let rules = YaraRuleSet::compile_source("test.yar", RULES).expect("compile");
        let matches = rules
            .scan(b"MZ", Duration::from_secs(5), &CancelToken::new())
            .expect("scan");
        let meta = matches[0].metadata.as_array().expect("metadata array");
        assert!(meta
            .iter()
            .any(|p| p.get(0).and_then(|v| v.as_str()) == Some("author")));
    }

    #[test]
    fn match_evidence_records_real_offsets_and_bytes() {
        let source = r#"
rule evidence {
    strings:
        $text = "hello"
        $mz = { 4D 5A }
    condition:
        any of them
}
"#;
        let rules = YaraRuleSet::compile_source("evidence.yar", source).expect("compile");
        let matches = rules
            .scan(
                b"..hello..MZ..",
                Duration::from_secs(5),
                &CancelToken::new(),
            )
            .expect("scan");
        assert_eq!(matches.len(), 1);
        let evidence = &matches[0].strings;
        let text = evidence
            .iter()
            .find(|item| item.identifier == "$text")
            .expect("text evidence");
        assert_eq!(text.offset, 2);
        assert_eq!(text.length, 5);
        assert_eq!(text.data, "hello");
        let mz = evidence
            .iter()
            .find(|item| item.identifier == "$mz")
            .expect("mz evidence");
        assert_eq!(mz.offset, 9);
        assert_eq!(mz.hex, "4D 5A");
    }

    #[test]
    fn rules_without_patterns_have_no_fake_evidence() {
        let rules =
            YaraRuleSet::compile_source("plain.yar", "rule plain { condition: true }").unwrap();
        let matches = rules
            .scan(b"anything", Duration::from_secs(5), &CancelToken::new())
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].strings.is_empty());
    }

    #[test]
    fn revision_is_content_addressed_and_deterministic() {
        let first = YaraRuleSet::compile_source("a.yar", RULES).unwrap();
        let second = YaraRuleSet::compile_source("a.yar", RULES).unwrap();
        assert_eq!(first.revision, second.revision);
        assert_eq!(first.sources.len(), 1);
        assert_eq!(first.sources[0].text.as_deref(), Some(RULES));
        assert!(!first.sources[0].truncated);

        let changed = YaraRuleSet::compile_source(
            "a.yar",
            "rule changed { strings: $a = \"changed\" condition: $a }",
        )
        .unwrap();
        assert_ne!(first.revision, changed.revision);
    }

    #[test]
    fn compiled_rule_sets_are_cached_by_content_and_invalidated() {
        let dir = tempfile::tempdir().unwrap();
        let rule = dir.path().join("one.yar");
        std::fs::write(&rule, "rule one { condition: true }").unwrap();
        let first = YaraRuleSet::compile_dirs_cached(&[dir.path().to_path_buf()]).unwrap();
        let second = YaraRuleSet::compile_dirs_cached(&[dir.path().to_path_buf()]).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.revision, second.revision);

        std::fs::write(&rule, "rule two { condition: true }").unwrap();
        let third = YaraRuleSet::compile_dirs_cached(&[dir.path().to_path_buf()]).unwrap();
        assert_ne!(first.revision, third.revision);
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(third.rule_count(), 1);
    }
    #[test]
    fn moving_a_source_changes_the_manifest_revision() {
        let first = YaraRuleSet::compile_source("one/a.yar", RULES).unwrap();
        let second = YaraRuleSet::compile_source("two/a.yar", RULES).unwrap();
        assert_ne!(first.revision, second.revision);
        assert_eq!(first.sources[0].sha256, second.sources[0].sha256);
    }

    #[test]
    fn oversized_source_text_is_bounded_but_hash_is_complete() {
        let mut source = String::from("rule big { strings:\n");
        for index in 0..20_000 {
            source.push_str(&format!("$a{index} = \"v{index}\"\n"));
        }
        source.push_str("condition: any of them }\n");
        let rules = YaraRuleSet::compile_source("big.yar", &source).unwrap();
        let record = &rules.sources[0];
        assert!(record.truncated);
        assert!(record.text.as_ref().unwrap().len() <= 256 * 1024);
        assert_eq!(record.bytes, source.len() as u64);
        assert_eq!(record.sha256.len(), 64);
    }
}
