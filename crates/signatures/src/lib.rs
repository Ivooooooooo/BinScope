use binscope_common::{find_pattern, parse_hex_pattern};
use binscope_elfmach::{ElfInfo, MachOInfo};
use binscope_pe::PeInfo;
use binscope_strings::ExtractedString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const BUILTIN_DATABASE: &str = include_str!("../../../databases/signatures/builtin.json");

pub mod die;
pub mod die_heuristics;
pub mod heuristics;
pub mod pebear;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("failed to read signature database {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid signature database {path}: {message}")]
    Json { path: PathBuf, message: String },
    #[error("signature {id}: {message}")]
    Invalid { id: String, message: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Packer,
    Protector,
    Compiler,
    Linker,
    Runtime,
    Framework,
    Installer,
    Tool,
    Signer,
    Format,
    Language,
    Library,
    Other,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Packer => "Packer",
            Category::Protector => "Protector",
            Category::Compiler => "Compiler",
            Category::Linker => "Linker",
            Category::Runtime => "Runtime",
            Category::Framework => "Framework",
            Category::Installer => "Installer",
            Category::Tool => "Tool",
            Category::Signer => "Signer",
            Category::Format => "Format",
            Category::Language => "Language",
            Category::Library => "Library",
            Category::Other => "Other",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureDatabase {
    pub schema: u32,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub updated: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub category: Category,
    #[serde(default)]
    pub description: String,
    pub confidence: u8,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub all: Vec<Condition>,
    #[serde(default)]
    pub any: Vec<Condition>,
    #[serde(default)]
    pub none: Vec<Condition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    SectionName {
        value: String,
        #[serde(default)]
        match_mode: MatchMode,
        #[serde(default)]
        negate: bool,
    },
    Import {
        value: String,
        #[serde(default)]
        target: ImportTarget,
        #[serde(default)]
        match_mode: MatchMode,
    },
    Export {
        value: String,
        #[serde(default)]
        match_mode: MatchMode,
    },
    String {
        value: String,
        #[serde(default)]
        match_mode: MatchMode,
        #[serde(default)]
        extract_version: bool,
        #[serde(default)]
        negate: bool,
    },
    Bytes {
        pattern: String,
        #[serde(default)]
        scope: ByteScope,
        #[serde(default)]
        section: Option<String>,
        #[serde(default)]
        offset: Option<u32>,
    },
    Entropy {
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
        #[serde(default)]
        scope: EntropyScope,
        #[serde(default)]
        section: Option<String>,
    },
    RichHeader {
        #[serde(default = "default_true")]
        present: bool,
    },
    PdbPath {
        value: String,
        #[serde(default)]
        match_mode: MatchMode,
    },
    LinkerVersion {
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
    },
    #[serde(rename = "dotnet")]
    DotNet {
        #[serde(default = "default_true")]
        present: bool,
        #[serde(default)]
        clr_kind: Option<String>,
    },
    Machine {
        values: Vec<String>,
    },
    Authenticode {
        #[serde(default = "default_true")]
        present: bool,
    },
    TlsCallbacks {
        #[serde(default = "default_true")]
        present: bool,
    },
    Subsystem {
        value: String,
    },
    SectionCount {
        #[serde(default)]
        min: Option<u32>,
        #[serde(default)]
        max: Option<u32>,
    },
    FileSize {
        #[serde(default)]
        min: Option<u64>,
        #[serde(default)]
        max: Option<u64>,
    },
    ResourceType {
        value: String,
    },
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    Equals,
    StartsWith,
    EndsWith,
    #[default]
    Contains,
}

impl MatchMode {
    fn matches(self, haystack: &str, needle: &str) -> bool {
        let h = haystack.to_lowercase();
        let n = needle.to_lowercase();
        match self {
            MatchMode::Equals => h == n,
            MatchMode::StartsWith => h.starts_with(&n),
            MatchMode::EndsWith => h.ends_with(&n),
            MatchMode::Contains => h.contains(&n),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportTarget {
    Library,
    Function,
    #[default]
    Any,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteScope {
    #[default]
    File,
    Entry,
    Section,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyScope {
    File,
    #[default]
    Section,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub condition: String,
    pub description: String,
    pub offset: Option<u64>,
    pub value: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionCertainty {
    Exact,
    StrongHeuristic,
    Possible,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionEngine {
    #[default]
    InternalSignatures,
    DetectItEasy,
    Pebear,
    StructuralHeuristic,
    DieHeuristic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub description: String,
    pub confidence: u8,
    pub version: Option<String>,
    pub options: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub source: String,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub certainty: DetectionCertainty,
    #[serde(default)]
    pub engine: DetectionEngine,

    pub compatibility: Option<String>,
}

pub struct SignatureContext<'a> {
    pub file_bytes: &'a [u8],
    pub pe: Option<&'a PeInfo>,
    pub elf: Option<&'a ElfInfo>,
    pub macho: Option<&'a MachOInfo>,
    pub strings: &'a [ExtractedString],
    pub dotnet_present: bool,
    pub dotnet_kind: Option<&'a str>,
}

impl SignatureDatabase {
    pub fn parse(json: &str, path: &Path) -> Result<Self, SignatureError> {
        let db: SignatureDatabase =
            serde_json::from_str(json).map_err(|e| SignatureError::Json {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        db.validate()?;
        Ok(db)
    }

    pub fn load_file(path: &Path) -> Result<Self, SignatureError> {
        let text = std::fs::read_to_string(path).map_err(|source| SignatureError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text, path)
    }

    pub fn builtin() -> Result<Self, SignatureError> {
        Self::parse(BUILTIN_DATABASE, Path::new("<builtin>"))
    }

    fn validate(&self) -> Result<(), SignatureError> {
        if self.schema != 1 {
            return Err(SignatureError::Invalid {
                id: "<database>".into(),
                message: format!("unsupported schema version {} (expected 1)", self.schema),
            });
        }
        let mut seen = BTreeSet::new();
        for sig in &self.signatures {
            if sig.id.trim().is_empty() {
                return Err(SignatureError::Invalid {
                    id: "<empty>".into(),
                    message: "signature id must not be empty".into(),
                });
            }
            if !seen.insert(sig.id.clone()) {
                return Err(SignatureError::Invalid {
                    id: sig.id.clone(),
                    message: "duplicate signature id".into(),
                });
            }
            if sig.name.trim().is_empty() {
                return Err(SignatureError::Invalid {
                    id: sig.id.clone(),
                    message: "signature name must not be empty".into(),
                });
            }
            if sig.confidence > 100 {
                return Err(SignatureError::Invalid {
                    id: sig.id.clone(),
                    message: "confidence must be 0..=100".into(),
                });
            }
            if sig.all.is_empty() && sig.any.is_empty() {
                return Err(SignatureError::Invalid {
                    id: sig.id.clone(),
                    message: "signature needs at least one all/any condition".into(),
                });
            }
            for cond in sig.all.iter().chain(&sig.any).chain(&sig.none) {
                validate_condition(&sig.id, cond)?;
            }
        }
        Ok(())
    }
}

fn validate_condition(id: &str, cond: &Condition) -> Result<(), SignatureError> {
    if let Condition::Bytes { pattern, .. } = cond {
        if parse_hex_pattern(pattern).is_none() {
            return Err(SignatureError::Invalid {
                id: id.to_string(),
                message: format!("invalid byte pattern '{pattern}'"),
            });
        }
    }
    if let Condition::Bytes {
        scope: ByteScope::Section,
        section: None,
        ..
    } = cond
    {
        return Err(SignatureError::Invalid {
            id: id.to_string(),
            message: "byte condition with scope=section requires a section name".into(),
        });
    }
    if let Condition::Entropy { scope, section, .. } = cond {
        if *scope == EntropyScope::Section && section.is_none() {}
    }
    Ok(())
}

pub fn load_databases(paths: &[PathBuf]) -> Result<Vec<SignatureDatabase>, SignatureError> {
    let mut out = Vec::new();
    let mut ids = BTreeSet::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|source| SignatureError::Io {
                    path: path.clone(),
                    source,
                })?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .map(|e| e.eq_ignore_ascii_case("json"))
                        .unwrap_or(false)
                })
                .collect();
            entries.sort();
            files.extend(entries);
        } else {
            files.push(path.clone());
        }
    }
    for file in files {
        let db = SignatureDatabase::load_file(&file)?;
        for sig in &db.signatures {
            if !ids.insert(sig.id.clone()) {
                return Err(SignatureError::Invalid {
                    id: sig.id.clone(),
                    message: format!(
                        "duplicate signature id across databases ({})",
                        file.display()
                    ),
                });
            }
        }
        out.push(db);
    }
    Ok(out)
}

pub fn evaluate(databases: &[SignatureDatabase], ctx: &SignatureContext<'_>) -> Vec<Detection> {
    let mut detections = Vec::new();
    for db in databases {
        let source = match &db.source {
            Some(s) => format!("{} {} ({s})", db.name, db.version),
            None => format!("{} {}", db.name, db.version),
        };
        for sig in &db.signatures {
            if let Some(detection) = evaluate_signature(sig, ctx, &source) {
                detections.push(detection);
            }
        }
    }
    detections.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then(b.confidence.cmp(&a.confidence))
            .then(a.name.cmp(&b.name))
    });
    detections
}

fn evaluate_signature(
    sig: &Signature,
    ctx: &SignatureContext<'_>,
    source: &str,
) -> Option<Detection> {
    let mut evidence = Vec::new();
    let mut dynamic_version: Option<String> = None;
    let mut all_ok = true;
    for cond in &sig.all {
        match evaluate_condition(cond, ctx) {
            ConditionResult::Matched(matched) => {
                if dynamic_version.is_none() {
                    dynamic_version = matched.version_hint.clone();
                }
                evidence.extend(matched.evidence);
            }
            ConditionResult::NotMatched => {
                all_ok = false;
                break;
            }
        }
    }
    if !all_ok {
        return None;
    }
    if !sig.any.is_empty() {
        let mut any_evidence = Vec::new();
        let mut any_matched = false;
        for cond in &sig.any {
            if let ConditionResult::Matched(matched) = evaluate_condition(cond, ctx) {
                any_matched = true;
                if dynamic_version.is_none() {
                    dynamic_version = matched.version_hint.clone();
                }
                any_evidence.extend(matched.evidence);
            }
        }
        if !any_matched {
            return None;
        }
        evidence.append(&mut any_evidence);
    }
    for cond in &sig.none {
        if matches!(evaluate_condition(cond, ctx), ConditionResult::Matched(_)) {
            return None;
        }
    }
    if evidence.is_empty() {
        return None;
    }
    Some(Detection {
        id: sig.id.clone(),
        name: sig.name.clone(),
        category: sig.category,
        description: sig.description.clone(),
        confidence: sig.confidence,
        version: if sig.category == Category::Language {
            sig.version.clone()
        } else {
            sig.version.clone().or(dynamic_version)
        },
        options: Vec::new(),
        evidence,
        source: source.to_string(),
        vendor: None,
        certainty: DetectionCertainty::Exact,
        engine: DetectionEngine::InternalSignatures,
        compatibility: None,
    })
}

enum ConditionResult {
    Matched(MatchedEvidenceList),
    NotMatched,
}

struct MatchedEvidenceList {
    evidence: Vec<Evidence>,
    version_hint: Option<String>,
}

fn match_condition(ev: Evidence) -> ConditionResult {
    ConditionResult::Matched(MatchedEvidenceList {
        evidence: vec![ev],
        version_hint: None,
    })
}

fn evaluate_condition(cond: &Condition, ctx: &SignatureContext<'_>) -> ConditionResult {
    match cond {
        Condition::SectionName {
            value,
            match_mode,
            negate,
        } => {
            let found = ctx
                .pe
                .map(|pe| {
                    pe.sections.iter().any(|s| {
                        match_mode.matches(&s.name, value)
                            || match_mode.matches(&s.name, &format!(".{value}"))
                    })
                })
                .unwrap_or_else(|| {
                    ctx.elf
                        .map(|e| {
                            e.sections
                                .iter()
                                .any(|s| match_mode.matches(&s.name, value))
                        })
                        .unwrap_or(false)
                });
            let matched = found != *negate;
            if !matched {
                return ConditionResult::NotMatched;
            }
            match_condition(Evidence {
                condition: "section_name".into(),
                description: if *negate {
                    format!("Section matching '{value}' is absent")
                } else {
                    format!("Section matching '{value}' is present")
                },
                offset: None,
                value: Some(value.clone()),
            })
        }
        Condition::Import {
            value,
            target,
            match_mode,
        } => {
            let mut matched_value = None;
            if let Some(pe) = ctx.pe {
                for lib in pe.imports.iter().chain(pe.delay_imports.iter()) {
                    if matches!(*target, ImportTarget::Library | ImportTarget::Any)
                        && match_mode.matches(&lib.name, value)
                    {
                        matched_value = Some(lib.name.clone());
                        break;
                    }
                    if matches!(*target, ImportTarget::Function | ImportTarget::Any) {
                        if let Some(f) = lib
                            .functions
                            .iter()
                            .filter_map(|f| f.name.as_deref())
                            .find(|n| match_mode.matches(n, value))
                        {
                            matched_value = Some(format!("{}!{}", lib.name, f));
                            break;
                        }
                    }
                }
            }
            if matched_value.is_none() {
                if let Some(elf) = ctx.elf {
                    if matches!(*target, ImportTarget::Library | ImportTarget::Any) {
                        matched_value = elf
                            .needed_libraries
                            .iter()
                            .find(|n| match_mode.matches(n, value))
                            .cloned();
                    }
                    if matched_value.is_none()
                        && matches!(*target, ImportTarget::Function | ImportTarget::Any)
                    {
                        matched_value = elf
                            .imports
                            .iter()
                            .find(|n| match_mode.matches(n, value))
                            .cloned();
                    }
                }
            }
            if matched_value.is_none() {
                if let Some(macho) = ctx.macho {
                    for slice in &macho.slices {
                        if matches!(*target, ImportTarget::Library | ImportTarget::Any) {
                            if let Some(n) = slice
                                .libraries
                                .iter()
                                .find(|n| match_mode.matches(n, value))
                            {
                                matched_value = Some(n.clone());
                                break;
                            }
                        }
                        if matches!(*target, ImportTarget::Function | ImportTarget::Any) {
                            if let Some(n) =
                                slice.imports.iter().find(|n| match_mode.matches(n, value))
                            {
                                matched_value = Some(n.clone());
                                break;
                            }
                        }
                    }
                }
            }
            match matched_value {
                Some(v) => match_condition(Evidence {
                    condition: "import".into(),
                    description: format!("Import matches '{v}'"),
                    offset: None,
                    value: Some(v),
                }),
                None => ConditionResult::NotMatched,
            }
        }
        Condition::Export { value, match_mode } => {
            let mut found = None;
            if let Some(pe) = ctx.pe {
                found = pe
                    .exports
                    .iter()
                    .filter_map(|e| e.name.as_deref())
                    .find(|n| match_mode.matches(n, value))
                    .map(|s| s.to_string());
            }
            if found.is_none() {
                if let Some(elf) = ctx.elf {
                    found = elf
                        .exports
                        .iter()
                        .find(|n| match_mode.matches(n, value))
                        .cloned();
                }
            }
            if found.is_none() {
                if let Some(macho) = ctx.macho {
                    found = macho
                        .slices
                        .iter()
                        .flat_map(|s| s.exports.iter())
                        .find(|n| match_mode.matches(n, value))
                        .cloned();
                }
            }
            match found {
                Some(v) => match_condition(Evidence {
                    condition: "export".into(),
                    description: format!("Export matches '{v}'"),
                    offset: None,
                    value: Some(v),
                }),
                None => ConditionResult::NotMatched,
            }
        }
        Condition::String {
            value,
            match_mode,
            extract_version,
            negate,
        } => {
            let hit = ctx
                .strings
                .iter()
                .find(|s| match_mode.matches(&s.value, value));
            if *negate {
                return if hit.is_none() {
                    match_condition(Evidence {
                        condition: "string".into(),
                        description: format!("String '{value}' is absent"),
                        offset: None,
                        value: None,
                    })
                } else {
                    ConditionResult::NotMatched
                };
            }
            match hit {
                Some(s) => {
                    let version_hint = if *extract_version {
                        extract_version_hint(&s.value, value)
                    } else {
                        None
                    };
                    ConditionResult::Matched(MatchedEvidenceList {
                        evidence: vec![Evidence {
                            condition: "string".into(),
                            description: format!(
                                "{} string '{}' found at offset {:#x}",
                                s.encoding.label(),
                                truncate(&s.value, 160),
                                s.offset
                            ),
                            offset: Some(s.offset),
                            value: Some(truncate(&s.value, 160)),
                        }],
                        version_hint,
                    })
                }
                None => ConditionResult::NotMatched,
            }
        }
        Condition::Bytes {
            pattern,
            scope,
            section,
            offset,
        } => {
            let Some(tokens) = parse_hex_pattern(pattern) else {
                return ConditionResult::NotMatched;
            };
            let mut region: Option<(&[u8], u64)> = None;
            match scope {
                ByteScope::File => region = Some((ctx.file_bytes, 0)),
                ByteScope::Entry => {
                    if let Some(pe) = ctx.pe {
                        if let Some(off) = pe.entry_point_file_offset {
                            let start = off as usize;
                            if let Some(bytes) = ctx.file_bytes.get(start..) {
                                region = Some((&bytes[..bytes.len().min(4096)], off));
                            }
                        }
                    }
                }
                ByteScope::Section => {
                    if let Some(pe) = ctx.pe {
                        let section_name = section.as_deref().unwrap_or("");
                        if let Some(s) = pe.sections.iter().find(|s| s.name == section_name) {
                            let start = s.raw_offset as usize;
                            let end = start.saturating_add(s.raw_size as usize);
                            if let Some(bytes) = ctx.file_bytes.get(start..end) {
                                region = Some((bytes, s.raw_offset as u64));
                            }
                        }
                    }
                }
            }
            let Some((bytes, base)) = region else {
                return ConditionResult::NotMatched;
            };
            let relative = offset.unwrap_or(0) as usize;
            if relative >= bytes.len() {
                return ConditionResult::NotMatched;
            }
            let hits = find_pattern(&bytes[relative..], &tokens, 1);
            match hits.first() {
                Some(pos) => match_condition(Evidence {
                    condition: "bytes".into(),
                    description: format!(
                        "Byte pattern '{pattern}' found at file offset {:#x}",
                        base + (relative + pos) as u64
                    ),
                    offset: Some(base + (relative + pos) as u64),
                    value: Some(pattern.clone()),
                }),
                None => ConditionResult::NotMatched,
            }
        }
        Condition::Entropy {
            min,
            max,
            scope,
            section,
        } => {
            let candidates: Vec<(String, f64)> = match scope {
                EntropyScope::File => {
                    vec![("file".to_string(), binscope_common::entropy(ctx.file_bytes))]
                }
                EntropyScope::Section => {
                    if let Some(pe) = ctx.pe {
                        pe.sections
                            .iter()
                            .filter(|s| {
                                section.as_ref().map(|name| &s.name == name).unwrap_or(true)
                            })
                            .map(|s| (s.name.clone(), s.entropy))
                            .collect()
                    } else if let Some(elf) = ctx.elf {
                        elf.sections
                            .iter()
                            .filter(|s| {
                                section.as_ref().map(|name| &s.name == name).unwrap_or(true)
                            })
                            .map(|s| (s.name.clone(), s.entropy))
                            .collect()
                    } else {
                        Vec::new()
                    }
                }
            };
            for (name, value) in candidates {
                let above = min.map(|m| value >= m).unwrap_or(true);
                let below = max.map(|m| value <= m).unwrap_or(true);
                if above && below {
                    return match_condition(Evidence {
                        condition: "entropy".into(),
                        description: format!("Entropy of '{name}' is {value:.3} bits/byte"),
                        offset: None,
                        value: Some(format!("{value:.3}")),
                    });
                }
            }
            ConditionResult::NotMatched
        }
        Condition::RichHeader { present } => {
            let has = ctx.pe.and_then(|p| p.rich_header.as_ref()).is_some();
            if has != *present {
                return ConditionResult::NotMatched;
            }
            match_condition(Evidence {
                condition: "rich_header".into(),
                description: if *present {
                    format!(
                        "Rich header present with {} entries",
                        ctx.pe
                            .and_then(|p| p.rich_header.as_ref())
                            .map(|r| r.entries.len())
                            .unwrap_or(0)
                    )
                } else {
                    "Rich header absent".into()
                },
                offset: ctx
                    .pe
                    .and_then(|p| p.rich_header.as_ref())
                    .map(|r| r.offset),
                value: None,
            })
        }
        Condition::PdbPath { value, match_mode } => match ctx.pe.and_then(|p| p.pdb.as_ref()) {
            Some(pdb) if match_mode.matches(&pdb.path, value) => match_condition(Evidence {
                condition: "pdb_path".into(),
                description: format!("Embedded PDB path '{}'", pdb.path),
                offset: pdb.data_file_offset,
                value: Some(pdb.path.clone()),
            }),
            _ => ConditionResult::NotMatched,
        },
        Condition::LinkerVersion { min, max } => {
            let Some(pe) = ctx.pe else {
                return ConditionResult::NotMatched;
            };
            let Some(version) = parse_linker_version(&pe.linker_version) else {
                return ConditionResult::NotMatched;
            };
            let above = min.map(|m| version >= m).unwrap_or(true);
            let below = max.map(|m| version <= m).unwrap_or(true);
            if !above || !below {
                return ConditionResult::NotMatched;
            }
            ConditionResult::Matched(MatchedEvidenceList {
                evidence: vec![Evidence {
                    condition: "linker_version".into(),
                    description: format!("PE linker version {}", pe.linker_version),
                    offset: None,
                    value: Some(pe.linker_version.clone()),
                }],
                version_hint: Some(pe.linker_version.clone()),
            })
        }
        Condition::DotNet { present, clr_kind } => {
            if ctx.dotnet_present != *present {
                return ConditionResult::NotMatched;
            }
            if let Some(expected) = clr_kind {
                if ctx.dotnet_kind != Some(expected.as_str()) {
                    return ConditionResult::NotMatched;
                }
            }
            match_condition(Evidence {
                condition: "dotnet".into(),
                description: if *present {
                    format!(
                        "CLR metadata present (type: {})",
                        ctx.dotnet_kind.unwrap_or("unknown")
                    )
                } else {
                    "CLR metadata absent".into()
                },
                offset: None,
                value: ctx.dotnet_kind.map(|s| s.to_string()),
            })
        }
        Condition::Machine { values } => {
            let arch = ctx
                .pe
                .map(|p| p.architecture.as_str())
                .or_else(|| ctx.elf.map(|e| e.architecture.as_str()))
                .or_else(|| {
                    ctx.macho
                        .and_then(|m| m.slices.first().map(|s| s.architecture.as_str()))
                });
            match arch {
                Some(a) if values.iter().any(|v| v.eq_ignore_ascii_case(a)) => {
                    match_condition(Evidence {
                        condition: "machine".into(),
                        description: format!("Architecture is {a}"),
                        offset: None,
                        value: Some(a.to_string()),
                    })
                }
                _ => ConditionResult::NotMatched,
            }
        }
        Condition::Authenticode { present } => {
            let has = ctx.pe.map(|p| p.certificate.present).unwrap_or(false);
            if has != *present {
                return ConditionResult::NotMatched;
            }
            match_condition(Evidence {
                condition: "authenticode".into(),
                description: if *present {
                    "Authenticode certificate table present".into()
                } else {
                    "No Authenticode certificate table".into()
                },
                offset: None,
                value: None,
            })
        }
        Condition::TlsCallbacks { present } => {
            let has = ctx.pe.map(|p| !p.tls_callbacks.is_empty()).unwrap_or(false);
            if has != *present {
                return ConditionResult::NotMatched;
            }
            match_condition(Evidence {
                condition: "tls_callbacks".into(),
                description: if *present {
                    format!(
                        "{} TLS callback(s) registered",
                        ctx.pe.map(|p| p.tls_callbacks.len()).unwrap_or(0)
                    )
                } else {
                    "No TLS callbacks".into()
                },
                offset: None,
                value: None,
            })
        }
        Condition::Subsystem { value } => match ctx.pe {
            Some(pe)
                if pe
                    .subsystem_name
                    .to_lowercase()
                    .contains(&value.to_lowercase()) =>
            {
                match_condition(Evidence {
                    condition: "subsystem".into(),
                    description: format!("Subsystem is '{}'", pe.subsystem_name),
                    offset: None,
                    value: Some(pe.subsystem_name.clone()),
                })
            }
            _ => ConditionResult::NotMatched,
        },
        Condition::SectionCount { min, max } => {
            let count = ctx
                .pe
                .map(|p| p.sections.len() as u32)
                .or_else(|| ctx.elf.map(|e| e.sections.len() as u32))
                .unwrap_or(0);
            let above = min.map(|m| count >= m).unwrap_or(true);
            let below = max.map(|m| count <= m).unwrap_or(true);
            if !above || !below {
                return ConditionResult::NotMatched;
            }
            match_condition(Evidence {
                condition: "section_count".into(),
                description: format!("{count} sections"),
                offset: None,
                value: Some(count.to_string()),
            })
        }
        Condition::FileSize { min, max } => {
            let size = ctx.file_bytes.len() as u64;
            let above = min.map(|m| size >= m).unwrap_or(true);
            let below = max.map(|m| size <= m).unwrap_or(true);
            if !above || !below {
                return ConditionResult::NotMatched;
            }
            match_condition(Evidence {
                condition: "file_size".into(),
                description: format!("File size is {size} bytes"),
                offset: None,
                value: Some(size.to_string()),
            })
        }
        Condition::ResourceType { value } => {
            let found = ctx.pe.map(|pe| {
                pe.resources.iter().any(|r| {
                    r.type_name.eq_ignore_ascii_case(value)
                        || r.type_id
                            .map(|id| id.to_string() == *value)
                            .unwrap_or(false)
                })
            });
            match found {
                Some(true) => match_condition(Evidence {
                    condition: "resource_type".into(),
                    description: format!("Resource type '{value}' is present"),
                    offset: None,
                    value: Some(value.clone()),
                }),
                _ => ConditionResult::NotMatched,
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

fn parse_linker_version(s: &str) -> Option<f64> {
    let mut parts = s.split('.');
    let major: f64 = parts.next()?.parse().ok()?;
    let minor: f64 = parts.next().unwrap_or("0").parse().ok()?;
    Some(major + minor / 100.0)
}

fn extract_version_hint(found: &str, needle: &str) -> Option<String> {
    let lower = found.to_lowercase();
    let needle_lower = needle.to_lowercase();
    let pos = lower.find(&needle_lower)?;
    let rest = &found[pos + needle.len()..];
    let digit = rest.find(|c: char| c.is_ascii_digit())?;
    let token: String = rest[digit..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '_')
        .collect();
    let trimmed = token.trim_end_matches(['.', '-', '_']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn signature_count(databases: &[SignatureDatabase]) -> usize {
    databases.iter().map(|d| d.signatures.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use binscope_common::CancelToken;
    use binscope_pe::{parse_default, PeBuilder};
    use binscope_strings::{extract_reader, StringOptions};
    use std::io::Cursor;

    fn strings_of(data: &[u8]) -> Vec<ExtractedString> {
        extract_reader(
            Cursor::new(data),
            &StringOptions::default(),
            &CancelToken::new(),
            None,
        )
        .unwrap()
        .items
    }

    fn context<'a>(
        data: &'a [u8],
        pe: &'a PeInfo,
        strings: &'a [ExtractedString],
    ) -> SignatureContext<'a> {
        SignatureContext {
            file_bytes: data,
            pe: Some(pe),
            elf: None,
            macho: None,
            strings,
            dotnet_present: pe.clr.is_some(),
            dotnet_kind: Some("managed"),
        }
    }

    #[test]
    fn builtin_database_is_valid() {
        let db = SignatureDatabase::builtin().expect("builtin DB");
        assert!(db.signatures.len() >= 15);
        assert!(db.signatures.iter().any(|s| s.id == "packer.upx"));
        assert!(db.signatures.iter().any(|s| s.id == "compiler.msvc"));
    }

    #[test]
    fn upx_fixture_is_detected_by_section_names() {
        let data = PeBuilder::pe32()
            .with_section("UPX0", vec![], 0xE000_0020)
            .with_section("UPX1", vec![0x90; 512], 0xE000_0020)
            .build();
        let pe = parse_default(&data).unwrap();
        let strings = strings_of(&data);
        let db = SignatureDatabase::builtin().unwrap();
        let detections = evaluate(&[db], &context(&data, &pe, &strings));
        let upx = detections
            .iter()
            .find(|d| d.id == "packer.upx")
            .expect("UPX detection");
        assert_eq!(upx.confidence, 98);
        assert!(upx.evidence.iter().any(|e| e.description.contains("UPX")));
    }

    #[test]
    fn msvc_is_detected_with_linker_version_and_pdb() {
        let mut builder = PeBuilder::pe64().with_pdb(r"C:\src\binscope\sample.pdb");
        builder.rich = true;
        let data = builder.build();
        let pe = parse_default(&data).unwrap();
        let strings = strings_of(&data);
        let db = SignatureDatabase::builtin().unwrap();
        let detections = evaluate(&[db], &context(&data, &pe, &strings));
        let msvc = detections
            .iter()
            .find(|d| d.id == "compiler.msvc")
            .expect("MSVC detection");
        assert_eq!(msvc.version.as_deref(), Some("14.29"));
        assert!(msvc
            .evidence
            .iter()
            .any(|e| e.description.contains("Rich header")));
        assert!(msvc
            .evidence
            .iter()
            .any(|e| e.description.contains("sample.pdb")));
    }

    #[test]
    fn gcc_string_is_detected_with_version() {
        let data = PeBuilder::pe32()
            .with_section(".comment", b"GCC: (GNU) 13.2.0\0".to_vec(), 0x4000_0040)
            .build();
        let pe = parse_default(&data).unwrap();
        let strings = strings_of(&data);
        let db = SignatureDatabase::builtin().unwrap();
        let detections = evaluate(&[db], &context(&data, &pe, &strings));
        let gcc = detections
            .iter()
            .find(|d| d.id == "compiler.gcc")
            .expect("GCC detection");
        assert_eq!(gcc.version.as_deref(), Some("13.2.0"));
    }

    #[test]
    fn plain_fixture_does_not_trigger_packer_or_rust_signatures() {
        let data = PeBuilder::pe32().build();
        let pe = parse_default(&data).unwrap();
        let strings = strings_of(&data);
        let db = SignatureDatabase::builtin().unwrap();
        let detections = evaluate(&[db], &context(&data, &pe, &strings));
        for forbidden in [
            "packer.upx",
            "compiler.rust",
            "compiler.go",
            "packer.themida",
            "compiler.msvc",
        ] {
            assert!(
                detections.iter().all(|d| d.id != forbidden),
                "unexpected {forbidden}"
            );
        }
    }

    #[test]
    fn byte_pattern_with_wildcard_matches_entry_scope() {
        let data = PeBuilder::pe32().build();
        let pe = parse_default(&data).unwrap();
        let strings = strings_of(&data);
        let sig = Signature {
            id: "test.entry".into(),
            name: "Entry test".into(),
            category: Category::Other,
            description: String::new(),
            confidence: 50,
            version: None,
            all: vec![Condition::Bytes {
                pattern: "90 90 ?? 31".into(),
                scope: ByteScope::Entry,
                section: None,
                offset: Some(0),
            }],
            any: vec![],
            none: vec![],
        };
        let db = SignatureDatabase {
            schema: 1,
            name: "test".into(),
            version: "1".into(),
            updated: None,
            license: None,
            source: None,
            signatures: vec![sig],
        };
        let detections = evaluate(&[db], &context(&data, &pe, &strings));
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].id, "test.entry");
    }

    #[test]
    fn invalid_byte_pattern_is_rejected() {
        let json = r#"{
            "schema": 1,
            "name": "broken",
            "version": "1",
            "signatures": [{
                "id": "x", "name": "X", "category": "other", "confidence": 5,
                "all": [{"kind": "bytes", "pattern": "ZZ"}]
            }]
        }"#;
        let err = SignatureDatabase::parse(json, Path::new("test.json")).unwrap_err();
        assert!(err.to_string().contains("invalid byte pattern"));
    }

    #[test]
    fn version_extraction_stops_at_punctuation() {
        assert_eq!(
            extract_version_hint("GCC: (GNU) 13.2.0", "GCC: ("),
            Some("13.2.0".into())
        );
        assert_eq!(
            extract_version_hint("UPX 3.96 Copyright", "UPX "),
            Some("3.96".into())
        );
        assert_eq!(extract_version_hint("no digits here", "no"), None);
    }
}
