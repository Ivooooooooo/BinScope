pub mod report;

pub use report::*;

use binscope_common::{CancelToken, Deadline, Error as CommonError};
use binscope_dotnet::DotNetInfo;
use binscope_file_detect::{detect, FormatKind};
use binscope_hashing::{hash_bytes, hash_file, FileHashes};
use binscope_signatures::die::{evaluate_die, load_die_directory, DieDatabase};
use binscope_signatures::die_heuristics::{evaluate_themida, evaluate_vmprotect};
use binscope_signatures::heuristics::evaluate_structural;
use binscope_signatures::pebear::{evaluate_pebear, parse_pebear};
use binscope_signatures::{
    evaluate, load_databases, Detection, SignatureContext, SignatureDatabase,
};
use binscope_strings::{extract_file, extract_reader, StringOptions};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnalysisOptions {
    pub include_strings: bool,
    pub min_string_len: usize,
    pub max_strings: usize,
    pub max_string_bytes: usize,
    pub parse_limit_bytes: u64,
    pub max_stream_bytes: u64,
    pub time_budget_secs: u64,
    pub max_entries: usize,
    pub signatures_enabled: bool,
    pub builtin_signatures: bool,

    pub signature_dirs: Vec<PathBuf>,

    pub die_signature_dir: Option<PathBuf>,

    pub pebear_sig_path: Option<PathBuf>,
    pub yara_enabled: bool,
    pub yara_rule_dirs: Vec<PathBuf>,

    #[serde(default)]
    pub yara_provenance: Vec<YaraRootProvenance>,
    pub yara_timeout_ms: u64,

    pub rule_filter: binscope_rules::RuleFilter,

    pub rule_profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraRootProvenance {
    pub source_id: String,
    pub path: PathBuf,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            include_strings: true,
            min_string_len: 4,
            max_strings: 100_000,
            max_string_bytes: 16 * 1024 * 1024,
            parse_limit_bytes: 512 * 1024 * 1024,
            max_stream_bytes: 4 * 1024 * 1024 * 1024,
            time_budget_secs: 180,
            max_entries: 65_536,
            signatures_enabled: true,
            builtin_signatures: true,
            signature_dirs: Vec::new(),
            die_signature_dir: None,
            pebear_sig_path: None,
            yara_enabled: false,
            yara_rule_dirs: Vec::new(),
            yara_provenance: Vec::new(),
            yara_timeout_ms: 10_000,
            rule_filter: binscope_rules::RuleFilter::default(),
            rule_profile: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisProgress {
    pub stage: String,
    pub percent: u8,
    pub message: String,
}

pub type ProgressSink = Arc<dyn Fn(AnalysisProgress) + Send + Sync>;

fn verify_authenticode(
    path: &Path,
    data: &[u8],
    pe: &binscope_pe::PeInfo,
) -> binscope_authenticode::AuthenticodeReport {
    binscope_authenticode::verify(
        Some(path),
        data,
        &pe.certificate,
        binscope_authenticode::PeHashLayout {
            optional_header_offset: pe.optional_header_offset,
            is_64: pe.is_64,
            certificate_offset: pe.certificate.directory_offset as u64,
            certificate_size: pe.certificate.directory_size as u64,
        },
    )
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("analysis cancelled")]
    Cancelled,
    #[error("analysis time budget exceeded")]
    Timeout,
    #[error("cannot open {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("file is {size} bytes, above the configured streaming limit of {limit} bytes")]
    TooLarge { size: u64, limit: u64 },
    #[error("internal analysis error: {0}")]
    Internal(String),
}

pub fn analyze_file(
    path: &Path,
    options: &AnalysisOptions,
    cancel: &CancelToken,
    progress: Option<&ProgressSink>,
) -> Result<Report, AnalysisError> {
    let started = Instant::now();
    let started_utc = Utc::now();
    let deadline = Deadline::after(Duration::from_secs(options.time_budget_secs.max(1)));
    let emit = |percent: u8, stage: &str, message: &str| {
        if let Some(sink) = progress {
            sink(AnalysisProgress {
                stage: stage.to_string(),
                percent,
                message: message.to_string(),
            });
        }
    };

    let mut issues = Vec::new();
    let mut notes = Vec::new();
    let metadata = std::fs::metadata(path).map_err(|source| AnalysisError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    let size = metadata.len();
    if size > options.max_stream_bytes {
        return Err(AnalysisError::TooLarge {
            size,
            limit: options.max_stream_bytes,
        });
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let modified_utc = metadata.modified().ok().map(|t| {
        DateTime::<Utc>::from(t)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    });

    emit(2, "open", "Reading file");
    cancel.check().map_err(|_| AnalysisError::Cancelled)?;
    deadline.check().map_err(|_| AnalysisError::Timeout)?;

    let read_limit = options.parse_limit_bytes;
    let mut full_bytes: Option<Vec<u8>> = None;
    if size <= read_limit {
        match read_all(path, read_limit) {
            Ok(bytes) => full_bytes = Some(bytes),
            Err(ReadError::TooLarge) => {
                issues.push(issue(
                    "open",
                    IssueLevel::Warning,
                    format!(
                        "File grew beyond the {read_limit} byte parse limit while reading; structured analysis will be skipped."
                    ),
                ));
            }
            Err(ReadError::Io(e)) => {
                return Err(AnalysisError::Read {
                    path: path.to_path_buf(),
                    source: e,
                })
            }
        }
    }

    emit(8, "hash", "Calculating SHA-256, SHA-1 and MD5");
    let hashes: FileHashes = match &full_bytes {
        Some(bytes) => hash_bytes(bytes),
        None => hash_file(path, cancel, Some(&deadline)).map_err(map_common)?,
    };
    deadline.check().map_err(|_| AnalysisError::Timeout)?;
    cancel.check().map_err(|_| AnalysisError::Cancelled)?;

    let head: Vec<u8> = match &full_bytes {
        Some(bytes) => bytes[..bytes.len().min(4096)].to_vec(),
        None => read_head(path, 4096).map_err(|source| AnalysisError::Read {
            path: path.to_path_buf(),
            source,
        })?,
    };
    let detection = detect(full_bytes.as_deref().unwrap_or(&head));
    let mut format = FormatInfo::from_detection(detection);

    emit(20, "strings", "Extracting strings");
    let mut strings = if options.include_strings {
        let string_opts = StringOptions {
            min_len: options.min_string_len,
            max_strings: options.max_strings,
            max_bytes: options.max_string_bytes,
            include_ascii: true,
            include_utf16le: true,
            chunk_size: 1024 * 1024,
        };
        let result = match &full_bytes {
            Some(bytes) => extract_reader(
                Cursor::new(bytes.as_slice()),
                &string_opts,
                cancel,
                Some(&deadline),
            ),
            None => extract_file(path, &string_opts, cancel, Some(&deadline)),
        };
        match result {
            Ok(mut r) => {
                if let Some(bytes) = &full_bytes {
                    let extra = binscope_strings::extract_utf8_bytes(
                        bytes,
                        string_opts.min_len,
                        binscope_strings::MAX_STRING_LEN,
                    );
                    if !extra.is_empty() {
                        r.total_found = r.total_found.saturating_add(extra.len() as u64);
                        r.items.extend(extra);
                        r.items.sort_by_key(|item| item.offset);
                        let mut kept = Vec::with_capacity(r.items.len());
                        let mut used = 0usize;
                        for item in r.items.drain(..) {
                            if kept.len() >= string_opts.max_strings
                                || used >= string_opts.max_bytes
                            {
                                r.truncated = true;
                                break;
                            }
                            used = used.saturating_add(item.value.len());
                            kept.push(item);
                        }
                        r.items = kept;
                    }
                    binscope_strings::classify_items(&mut r.items);
                }
                Some(r)
            }
            Err(CommonError::Cancelled) => return Err(AnalysisError::Cancelled),
            Err(CommonError::Timeout) => {
                issues.push(issue(
                    "strings",
                    IssueLevel::Warning,
                    "String extraction hit the time budget and was stopped.",
                ));
                None
            }
            Err(e) => {
                issues.push(issue(
                    "strings",
                    IssueLevel::Warning,
                    format!("String extraction failed: {e}"),
                ));
                None
            }
        }
    } else {
        None
    };
    cancel.check().map_err(|_| AnalysisError::Cancelled)?;

    emit(38, "format", "Parsing binary structures");
    let mut pe_info = None;
    let mut authenticode = None;
    let mut elf_info = None;
    let mut macho_info = None;
    let mut dotnet_info: Option<DotNetInfo> = None;

    if full_bytes.is_none() && size > read_limit {
        issues.push(issue(
            "parse",
            IssueLevel::Warning,
            "The file exceeds the configured parse limit; structural analysis and YARA scanning were skipped."
                .to_string(),
        ));
    } else if let Some(bytes) = &full_bytes {
        match format.kind {
            FormatKind::Pe => match binscope_pe::parse(bytes, options.max_entries) {
                Ok(pe) => {
                    format.architecture = pe.architecture.clone();
                    format.bits = pe.bits;
                    format.operating_system = "Windows".into();
                    if pe.is_dll {
                        format.file_type = "DLL".into();
                    } else if pe.is_driver {
                        format.file_type = "Driver".into();
                    } else {
                        format.file_type = "EXE".into();
                    }
                    format.description = format!(
                        "{} {}-bit {} ({})",
                        pe.pe_kind,
                        pe.bits,
                        if pe.is_dll {
                            "DLL"
                        } else if pe.is_driver {
                            "driver"
                        } else {
                            "executable"
                        },
                        pe.subsystem_name
                    );
                    if let Some(clr) = &pe.clr {
                        match binscope_dotnet::parse(bytes, clr) {
                            Ok(dn) => {
                                format.is_dotnet = true;
                                format.managedness = match dn.kind.as_str() {
                                    "managed" => "Managed (.NET, IL-only)".to_string(),
                                    "mixed_mode" => "Mixed-mode (.NET + native code)".to_string(),
                                    "native_entry_point" => {
                                        "Managed (.NET) with native entry point".to_string()
                                    }
                                    other => format!("Managed (.NET): {other}"),
                                };
                                dotnet_info = Some(dn);
                            }
                            Err(e) => {
                                format.is_dotnet = true;
                                format.managedness = "Managed (.NET), metadata unreadable".into();
                                issues.push(issue(
                                    "dotnet",
                                    IssueLevel::Warning,
                                    format!(
                                        "CLR header found but .NET metadata parsing failed: {e}"
                                    ),
                                ));
                            }
                        }
                    } else {
                        format.managedness = "Native (no CLR header)".into();
                    }
                    format.supported = true;
                    authenticode = Some(verify_authenticode(path, bytes, &pe));
                    pe_info = Some(pe);
                }
                Err(e) => {
                    format.supported = false;
                    format.description = format!("Malformed PE image: {e}");
                    issues.push(issue(
                        "pe",
                        IssueLevel::Error,
                        format!("PE parsing failed: {e}"),
                    ));
                }
            },
            FormatKind::Elf => match binscope_elfmach::parse_elf(bytes) {
                Ok(elf) => {
                    format.architecture = elf.architecture.clone();
                    format.bits = elf.bits;
                    format.operating_system = elf_operating_system(&elf);
                    format.file_type = elf.object_type_name.clone();
                    format.managedness = "Not applicable (ELF is not .NET)".into();
                    format.supported = true;
                    elf_info = Some(elf);
                }
                Err(e) => {
                    issues.push(issue(
                        "elf",
                        IssueLevel::Error,
                        format!("ELF parsing failed: {e}"),
                    ));
                    format.supported = false;
                }
            },
            FormatKind::MachO | FormatKind::MachOFat => {
                match binscope_elfmach::parse_macho(bytes) {
                    Ok(macho) => {
                        if let Some(first) = macho.slices.first() {
                            format.architecture = first.architecture.clone();
                            format.bits = first.bits;
                            format.file_type = first.file_type_name.clone();
                        }
                        format.operating_system = "macOS".into();
                        format.managedness = "Not applicable (Mach-O is not .NET)".into();
                        format.supported = true;
                        macho_info = Some(macho);
                    }
                    Err(e) => {
                        issues.push(issue(
                            "macho",
                            IssueLevel::Error,
                            format!("Mach-O parsing failed: {e}"),
                        ));
                        format.supported = false;
                    }
                }
            }
            _ => {
                format.managedness = "Not applicable".into();
                notes.push(format!(
                    "Structural analysis is not implemented for {}; hashes, strings and generic signatures are still available.",
                    format.label
                ));
            }
        }
    }

    cancel.check().map_err(|_| AnalysisError::Cancelled)?;
    deadline.check().map_err(|_| AnalysisError::Timeout)?;

    emit(62, "signatures", "Evaluating signatures");
    let mut signature_summary = SignatureSummary {
        enabled: options.signatures_enabled,
        ..Default::default()
    };
    let mut detections = Vec::new();
    if options.signatures_enabled {
        let mut databases: Vec<SignatureDatabase> = Vec::new();
        if options.builtin_signatures {
            match SignatureDatabase::builtin() {
                Ok(db) => {
                    signature_summary.databases.push(SignatureDatabaseInfo {
                        name: db.name.clone(),
                        version: db.version.clone(),
                        source: "built-in".into(),
                        signatures: db.signatures.len(),
                    });
                    databases.push(db);
                }
                Err(e) => {
                    signature_summary
                        .errors
                        .push(format!("built-in database: {e}"));
                    issues.push(issue(
                        "signatures",
                        IssueLevel::Error,
                        format!("Built-in signature database could not be loaded: {e}"),
                    ));
                }
            }
        }
        if !options.signature_dirs.is_empty() {
            match load_databases(&options.signature_dirs) {
                Ok(dbs) => {
                    for db in dbs {
                        signature_summary.databases.push(SignatureDatabaseInfo {
                            name: db.name.clone(),
                            version: db.version.clone(),
                            source: db.source.clone().unwrap_or_else(|| "external".into()),
                            signatures: db.signatures.len(),
                        });
                        databases.push(db);
                    }
                }
                Err(e) => {
                    signature_summary.errors.push(e.to_string());
                    issues.push(issue(
                        "signatures",
                        IssueLevel::Warning,
                        format!("External signature database could not be loaded: {e}"),
                    ));
                }
            }
        }
        signature_summary.total_signatures = signature_summary
            .databases
            .iter()
            .map(|d| d.signatures)
            .sum();
        let empty_strings = Vec::new();
        let string_items = strings
            .as_ref()
            .map(|s| s.items.as_slice())
            .unwrap_or(empty_strings.as_slice());
        let ctx = SignatureContext {
            file_bytes: full_bytes.as_deref().unwrap_or(&[]),
            pe: pe_info.as_ref(),
            elf: elf_info.as_ref(),
            macho: macho_info.as_ref(),
            strings: string_items,
            dotnet_present: dotnet_info.is_some(),
            dotnet_kind: dotnet_info.as_ref().map(|d| d.kind.as_str()),
        };
        detections = evaluate(&databases, &ctx);
        detections.extend(evaluate_structural(&ctx));

        if let Some(dir) = &options.die_signature_dir {
            if dir.is_dir() {
                let pe_dir = if dir.join("PE").is_dir() {
                    dir.join("PE")
                } else {
                    dir.clone()
                };
                let db = load_die_cached(&pe_dir);
                let die_detections = evaluate_die(&db, &ctx);
                signature_summary.die = Some(DieSummary {
                    version: db.version.clone(),
                    path: pe_dir.display().to_string(),
                    files: db.stats.files,
                    with_metadata: db.stats.with_metadata,
                    compatible: db.stats.compatible,
                    incompatible: db.stats.incompatible,
                    reasons: db
                        .stats
                        .reasons
                        .iter()
                        .map(|(reason, count)| DieReason {
                            reason: reason.clone(),
                            count: *count,
                        })
                        .collect(),
                    errors: db.errors.clone(),
                });
                signature_summary.total_signatures += db.stats.compatible;
                detections.extend(die_detections);
                if !ctx.dotnet_present {
                    if let Some(pe) = ctx.pe {
                        if let Some(detection) = evaluate_vmprotect(pe, ctx.file_bytes) {
                            detections.push(detection);
                        }
                        if let Some(detection) = evaluate_themida(pe, ctx.file_bytes) {
                            detections.push(detection);
                        }
                    }
                }
            } else {
                signature_summary.die = Some(DieSummary {
                    version: "not installed".into(),
                    path: dir.display().to_string(),
                    files: 0,
                    with_metadata: 0,
                    compatible: 0,
                    incompatible: 0,
                    reasons: Vec::new(),
                    errors: vec![format!("DIE directory does not exist: {}", dir.display())],
                });
            }
        }

        if let Some(path) = &options.pebear_sig_path {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    let db = parse_pebear(&text);
                    signature_summary.pebear = Some(PebearSummary {
                        path: path.display().to_string(),
                        total_blocks: db.total_blocks,
                        loaded: db.signatures.len(),
                        skipped: db.skipped,
                        reasons: db
                            .skip_reasons
                            .iter()
                            .map(|(reason, count)| DieReason {
                                reason: reason.clone(),
                                count: *count,
                            })
                            .collect(),
                        errors: Vec::new(),
                        license: "GPLv2 (PE-bear SIG.txt / PEiD UserDB)".into(),
                    });
                    signature_summary.total_signatures += db.signatures.len();
                    detections.extend(evaluate_pebear(&db, &ctx));
                }
                Err(e) => {
                    signature_summary.pebear = Some(PebearSummary {
                        path: path.display().to_string(),
                        total_blocks: 0,
                        loaded: 0,
                        skipped: 0,
                        reasons: Vec::new(),
                        errors: vec![format!("cannot read PE-bear SIG.txt: {e}")],
                        license: "GPLv2 (PE-bear SIG.txt / PEiD UserDB)".into(),
                    });
                }
            }
        }

        detections.retain(|detection| {
            let category = binscope_rules::signature_category_for(detection.category);
            options
                .rule_filter
                .signature_enabled(&detection.id, category)
        });
        detections = dedupe_detections(detections);

        if let Some(dn) = &dotnet_info {
            for d in &mut detections {
                if d.id == "runtime.dotnet" && d.version.is_none() {
                    d.version = Some(match &dn.assembly {
                        Some(a) => format!("{} {}", dn.runtime_version, a.version),
                        None => dn.runtime_version.clone(),
                    });
                }
            }
        }
        if strings.is_none() {
            signature_summary.errors.push(
                "String-based signatures were skipped because string extraction is disabled."
                    .into(),
            );
        }
    }

    emit(80, "yara", "Scanning with YARA-X");
    let mut yara_report = YaraReport {
        enabled: options.yara_enabled,
        engine_version: binscope_yara::ENGINE_VERSION.to_string(),
        ..Default::default()
    };
    if options.yara_enabled {
        if options.yara_rule_dirs.is_empty() {
            yara_report
                .errors
                .push("YARA is enabled but no rule directories are configured.".into());
        } else if full_bytes.is_none() {
            yara_report
                .errors
                .push("YARA scanning requires the file to fit within the parse limit.".into());
        } else {
            let started_yara = Instant::now();
            match binscope_yara::YaraRuleSet::compile_dirs_cached(&options.yara_rule_dirs) {
                Ok(rules) => {
                    yara_report.rule_count = rules.rule_count();
                    yara_report.revision = rules.revision.clone();
                    yara_report.compile = Some(rules.report.clone());
                    if !rules.report.errors.is_empty() {
                        issues.push(issue(
                            "yara",
                            IssueLevel::Warning,
                            format!(
                                "{} YARA rule file(s) failed to compile; valid rules were still applied.",
                                rules.report.errors.len()
                            ),
                        ));
                    }
                    let data = full_bytes.as_deref().unwrap_or(&[]);
                    match rules.scan(
                        data,
                        Duration::from_millis(options.yara_timeout_ms.max(100)),
                        cancel,
                    ) {
                        Ok(matches) => {
                            let mut matches = matches;
                            matches.retain(|matched| {
                                let categories = binscope_rules::classify_yara_match(matched);
                                options
                                    .rule_filter
                                    .yara_rule_enabled(&matched.rule, &categories)
                            });
                            for matched in &mut matches {
                                let (source_id, scope) =
                                    rule_scope(&matched.origin, &options.yara_provenance);
                                matched.source_id = source_id;
                                matched.scope = scope.to_string();
                            }
                            yara_report.external_matches = matches
                                .iter()
                                .filter(|matched| matched.scope == "external")
                                .count();
                            yara_report.internal_matches = matches
                                .iter()
                                .filter(|matched| matched.scope == "internal")
                                .count();
                            let matched_origins: std::collections::BTreeSet<String> = matches
                                .iter()
                                .map(|matched| matched.origin.clone())
                                .collect();
                            for source in &rules.sources {
                                let (source_id, scope) =
                                    rule_scope(&source.origin, &options.yara_provenance);
                                let text = matched_origins
                                    .contains(&source.origin)
                                    .then(|| source.text.clone())
                                    .flatten();
                                yara_report.sources.push(binscope_yara::YaraSourceFile {
                                    origin: source.origin.clone(),
                                    source_id,
                                    scope: scope.to_string(),
                                    sha256: source.sha256.clone(),
                                    bytes: source.bytes,
                                    text,
                                    truncated: source.truncated,
                                });
                            }
                            yara_report.external_sources = yara_report
                                .sources
                                .iter()
                                .filter(|source| source.scope == "external")
                                .count();
                            yara_report.internal_sources = yara_report
                                .sources
                                .iter()
                                .filter(|source| source.scope == "internal")
                                .count();
                            yara_report.matches = matches;
                        }
                        Err(binscope_yara::YaraError::Scan(msg)) if msg == "cancelled" => {
                            return Err(AnalysisError::Cancelled)
                        }
                        Err(e) => {
                            yara_report.errors.push(e.to_string());
                            issues.push(issue(
                                "yara",
                                IssueLevel::Warning,
                                format!("YARA scan failed: {e}"),
                            ));
                        }
                    }
                }
                Err(binscope_yara::YaraError::NoRules) => {
                    yara_report.errors.push(
                        "No valid YARA rules were found in the configured directories.".into(),
                    );
                }
                Err(e) => {
                    yara_report.errors.push(e.to_string());
                    issues.push(issue(
                        "yara",
                        IssueLevel::Warning,
                        format!("YARA rules could not be loaded: {e}"),
                    ));
                }
            }
            yara_report.elapsed_ms = started_yara.elapsed().as_millis() as u64;
        }
    }

    cancel.check().map_err(|_| AnalysisError::Cancelled)?;

    emit(95, "report", "Building report");
    if let (Some(pe), Some(strings)) = (&pe_info, &mut strings) {
        for item in &mut strings.items {
            item.section = pe
                .sections
                .iter()
                .find(|section| {
                    section.raw_size > 0
                        && item.offset >= section.raw_offset as u64
                        && item.offset < section.raw_offset as u64 + section.raw_size as u64
                })
                .map(|section| section.name.clone());
        }
    }
    let summary = DetectionSummary::from_detections(&detections);
    let status = if issues.iter().any(|i| i.level == IssueLevel::Error) {
        AnalysisStatus::Partial
    } else {
        AnalysisStatus::Complete
    };
    let finished_utc = Utc::now();
    let report = Report {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo::default(),
        analysis: AnalysisMeta {
            started_utc: started_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            finished_utc: finished_utc.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            duration_ms: started.elapsed().as_millis() as u64,
            status,
            issues,
            time_budget_ms: options.time_budget_secs * 1000,
            parse_limit_bytes: read_limit,
        },
        file: FileInfo {
            name: file_name,
            path: path.display().to_string(),
            size,
            size_human: binscope_common::human_size(size),
            sha256: hashes.sha256,
            sha1: hashes.sha1,
            md5: hashes.md5,
            modified_utc,
        },
        format,
        summary,
        pe: pe_info,
        elf: elf_info,
        macho: macho_info,
        dotnet: dotnet_info,
        detections,
        signatures: signature_summary,
        yara: yara_report,
        authenticode,
        detection_config: DetectionConfig {
            profile: options.rule_profile.clone(),
            yara_enabled: options.yara_enabled,
            signatures_enabled: options.signatures_enabled,
            disabled_yara_categories: options.rule_filter.disabled_yara_categories.clone(),
            disabled_yara_rules: options.rule_filter.disabled_yara_rules.clone(),
            disabled_signature_categories: options
                .rule_filter
                .disabled_signature_categories
                .clone(),
            disabled_signatures: options.rule_filter.disabled_signatures.clone(),
        },
        strings: strings.map(StringsSection::from_result),
        notes,
    };
    emit(100, "done", "Analysis complete");
    Ok(report)
}

fn issue(stage: &str, level: IssueLevel, message: impl Into<String>) -> AnalysisIssue {
    AnalysisIssue {
        stage: stage.to_string(),
        level,
        message: message.into(),
    }
}

type DieCache = Mutex<Option<(PathBuf, SystemTime, Arc<DieDatabase>)>>;
static DIE_CACHE: OnceLock<DieCache> = OnceLock::new();

pub fn clear_signature_cache() {
    if let Some(cache) = DIE_CACHE.get() {
        if let Ok(mut guard) = cache.lock() {
            *guard = None;
        }
    }
}

fn load_die_cached(dir: &Path) -> Arc<DieDatabase> {
    let modified = std::fs::metadata(dir)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let cache = DIE_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((path, time, db)) = guard.as_ref() {
            if path == dir && *time == modified {
                return Arc::clone(db);
            }
        }
    }
    let version = die_version(dir);
    let db = Arc::new(load_die_directory(dir, &version));
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((dir.to_path_buf(), modified, Arc::clone(&db)));
    }
    db
}

fn die_version(dir: &Path) -> String {
    let manifest = dir
        .parent()
        .map(|p| p.join("manifest.json"))
        .unwrap_or_else(|| dir.join("manifest.json"));
    let text = std::fs::read_to_string(&manifest).ok();
    let value = text.and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
    if let Some(value) = value {
        let tag = value
            .get("releaseTag")
            .and_then(|v| v.as_str())
            .unwrap_or("db");
        if tag.contains('@') {
            return tag.to_string();
        }
        let date = value
            .get("releasedAt")
            .and_then(|v| v.as_str())
            .or_else(|| value.get("installedAt").and_then(|v| v.as_str()))
            .unwrap_or("unknown");
        return format!("{tag} @ {date}");
    }
    "installed (manifest unavailable)".into()
}

fn normalize_rule_path(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

fn rule_scope(origin: &str, provenance: &[YaraRootProvenance]) -> (String, &'static str) {
    let origin = normalize_rule_path(origin);
    let mut best: Option<(&str, usize)> = None;
    for root in provenance {
        let root_path = normalize_rule_path(&root.path.to_string_lossy());
        let prefix = if root_path.ends_with('\\') {
            root_path
        } else {
            format!("{root_path}\\")
        };
        if origin == prefix.trim_end_matches('\\') || origin.starts_with(&prefix) {
            let length = prefix.len();
            if best.is_none_or(|(_, current)| length > current) {
                best = Some((&root.source_id, length));
            }
        }
    }
    let Some((source_id, _)) = best else {
        return (String::new(), "unclassified");
    };
    let scope = match source_id {
        "bundled" => "internal",
        "custom" => "custom",
        "legacy" => "legacy",
        _ => "external",
    };
    (source_id.to_string(), scope)
}
fn dedupe_detections(items: Vec<Detection>) -> Vec<Detection> {
    let mut merged: BTreeMap<(String, String, String, String), Detection> = BTreeMap::new();
    let normalize = |s: &str| {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect::<String>()
    };
    for detection in items {
        let key = (
            format!("{:?}", detection.category),
            normalize(&detection.name),
            detection.version.clone().unwrap_or_default().to_lowercase(),
            format!("{:?}", detection.engine),
        );
        match merged.get_mut(&key) {
            Some(existing) => {
                if detection.confidence > existing.confidence {
                    existing.confidence = detection.confidence;
                }
                if !existing.source.split("; ").any(|s| s == detection.source) {
                    existing.source = format!("{}; {}", existing.source, detection.source);
                }
                for option in detection.options {
                    if !existing.options.contains(&option) {
                        existing.options.push(option);
                    }
                }
                if let Some(note) = detection.compatibility {
                    let already = existing
                        .compatibility
                        .as_ref()
                        .is_some_and(|c| c.contains(&note));
                    if !already {
                        existing.compatibility = Some(match existing.compatibility.take() {
                            Some(c) => format!("{c}; {note}"),
                            None => note,
                        });
                    }
                }
                existing.evidence.extend(detection.evidence);
            }
            None => {
                merged.insert(key, detection);
            }
        }
    }
    let mut out: Vec<Detection> = merged.into_values().collect();
    out.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then(b.confidence.cmp(&a.confidence))
            .then(a.name.cmp(&b.name))
    });
    out
}

enum ReadError {
    TooLarge,
    Io(std::io::Error),
}

fn read_all(path: &Path, limit: u64) -> Result<Vec<u8>, ReadError> {
    let file = File::open(path).map_err(ReadError::Io)?;
    let mut bytes = Vec::new();

    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(ReadError::Io)?;
    if bytes.len() as u64 > limit {
        return Err(ReadError::TooLarge);
    }
    Ok(bytes)
}

fn read_head(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(max);
    file.take(max as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn map_common(e: CommonError) -> AnalysisError {
    match e {
        CommonError::Cancelled => AnalysisError::Cancelled,
        CommonError::Timeout => AnalysisError::Timeout,
        other => AnalysisError::Internal(other.to_string()),
    }
}

fn elf_operating_system(elf: &binscope_elfmach::ElfInfo) -> String {
    let interp = elf.interpreter.as_deref().unwrap_or("");
    if interp.contains("ld-linux") || interp.contains("ld-musl") {
        return "Linux".into();
    }
    match elf.os_abi.as_str() {
        "Linux" => "Linux".into(),
        "FreeBSD" => "FreeBSD".into(),
        "NetBSD" => "NetBSD".into(),
        "OpenBSD" => "OpenBSD".into(),
        "Solaris" => "Solaris".into(),
        "AIX" => "AIX".into(),
        other if other != "System V" && other != "Unknown ABI" => other.to_string(),
        _ => "Unix (System V ABI)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binscope_pe::PeBuilder;
    use std::io::Write;

    fn analyze_bytes(name: &str, bytes: &[u8]) -> Report {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        analyze_file(
            &path,
            &AnalysisOptions::default(),
            &CancelToken::new(),
            None,
        )
        .expect("analysis")
    }

    #[test]
    fn analyzes_pe32_fixture_end_to_end() {
        let data = PeBuilder::pe32()
            .with_export("FixtureExport")
            .with_pdb(r"C:\build\fixture.pdb")
            .build();
        let report = analyze_bytes("fixture.exe", &data);
        assert_eq!(report.format.kind, FormatKind::Pe);
        assert_eq!(report.format.architecture, "x86");
        assert_eq!(report.format.operating_system, "Windows");
        assert_eq!(report.format.file_type, "EXE");
        assert_eq!(
            report.file.sha256,
            binscope_hashing::hash_bytes(&data).sha256
        );
        let pe = report.pe.as_ref().expect("PE");
        assert_eq!(pe.machine, 0x014c);
        assert_eq!(pe.image_base, 0x0040_0000);
        assert!(pe
            .exports
            .iter()
            .any(|e| e.name.as_deref() == Some("FixtureExport")));
        assert!(report.strings.is_some());
        assert!(report.detections.iter().any(|d| d.id == "compiler.msvc"));
    }

    #[test]
    fn analyzes_pe64_dll_with_dotnet_metadata() {
        let data = PeBuilder::pe64().dll().with_clr(0x1).build();
        let report = analyze_bytes("fixture.dll", &data);
        assert_eq!(report.format.architecture, "x86-64");
        assert_eq!(report.format.file_type, "DLL");
        assert!(report.format.is_dotnet);
        assert!(report.format.managedness.starts_with("Managed"));
        let dn = report.dotnet.as_ref().expect(".NET info");
        assert_eq!(dn.assembly.as_ref().unwrap().name, "FixtureAssembly");
        assert!(report.detections.iter().any(|d| d.id == "runtime.dotnet"));
    }

    #[test]
    fn plain_pe_still_produces_a_complete_report() {
        let report = analyze_bytes("plain.exe", &PeBuilder::pe32().build());
        assert_eq!(report.analysis.status, AnalysisStatus::Complete);
        assert!(report.pe.is_some());
        assert!(report.yara.matches.is_empty());
        assert!(!report.yara.enabled);
    }

    #[test]
    fn empty_file_is_handled() {
        let report = analyze_bytes("empty.bin", b"");
        assert_eq!(report.format.kind, FormatKind::Unknown);
        assert_eq!(report.file.size, 0);
        assert_eq!(
            report.file.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(report.strings.as_ref().unwrap().items.is_empty());
        assert_eq!(report.analysis.status, AnalysisStatus::Complete);
    }

    #[test]
    fn truncated_pe_is_reported_without_panicking() {
        let report = analyze_bytes("truncated.exe", b"MZ\x90\x00");
        assert_eq!(report.format.kind, FormatKind::DosMz);
        assert!(report.pe.is_none());
        assert!(report.notes.iter().any(|n| n.contains("not implemented")));
        assert_eq!(report.analysis.status, AnalysisStatus::Complete);
    }

    #[test]
    fn corrupt_pe_internals_produce_partial_status() {
        let mut data = PeBuilder::pe32().build();

        let pe_offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
        data[pe_offset + 24] = 0;
        data[pe_offset + 25] = 0;
        let report = analyze_bytes("corrupt.exe", &data);
        assert_eq!(report.format.kind, FormatKind::Pe);
        assert!(report.pe.is_none());
        assert_eq!(report.analysis.status, AnalysisStatus::Partial);
        assert!(report
            .analysis
            .issues
            .iter()
            .any(|i| i.stage == "pe" && i.level == IssueLevel::Error));
    }

    #[test]
    fn parse_limit_skips_structures_but_keeps_hashes_and_strings() {
        let data = PeBuilder::pe32().build();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.exe");
        std::fs::write(&path, &data).unwrap();
        let options = AnalysisOptions {
            parse_limit_bytes: 64,
            ..Default::default()
        };
        let report = analyze_file(&path, &options, &CancelToken::new(), None).unwrap();
        assert!(report.pe.is_none());
        assert_eq!(
            report.file.sha256,
            binscope_hashing::hash_bytes(&data).sha256
        );
        assert!(report.strings.is_some());
        assert!(report
            .analysis
            .issues
            .iter()
            .any(|i| i.message.contains("parse limit")));
    }

    #[test]
    fn cancellation_is_propagated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cancel.exe");
        std::fs::write(&path, PeBuilder::pe32().build()).unwrap();
        let cancel = CancelToken::new();
        cancel.cancel();
        assert!(matches!(
            analyze_file(&path, &AnalysisOptions::default(), &cancel, None),
            Err(AnalysisError::Cancelled)
        ));
    }

    #[test]
    fn dedupe_merges_equivalent_detections_and_keeps_distinct_ones() {
        use binscope_signatures::{Category, Detection, DetectionEngine, Evidence};
        let make = |category, name: &str, source: &str, desc: &str, engine| Detection {
            id: "test".into(),
            name: name.into(),
            category,
            description: desc.into(),
            confidence: 50,
            version: None,
            options: vec![],
            evidence: vec![Evidence {
                condition: "test".into(),
                description: desc.into(),
                offset: None,
                value: None,
            }],
            source: source.into(),
            vendor: None,
            certainty: binscope_signatures::DetectionCertainty::Exact,
            engine,
            compatibility: None,
        };
        let merged = dedupe_detections(vec![
            make(
                Category::Packer,
                "UPX",
                "A",
                "from A",
                DetectionEngine::InternalSignatures,
            ),
            make(
                Category::Packer,
                "UPX",
                "B",
                "from B",
                DetectionEngine::InternalSignatures,
            ),
            make(
                Category::Protector,
                "UPX",
                "C",
                "different fact",
                DetectionEngine::InternalSignatures,
            ),
            make(
                Category::Packer,
                "UPX",
                "DIE",
                "from DIE",
                DetectionEngine::DetectItEasy,
            ),
        ]);
        assert_eq!(merged.len(), 3);
        let engines: Vec<_> = merged.iter().map(|d| d.engine).collect();
        assert!(engines.contains(&DetectionEngine::InternalSignatures));
        assert!(engines.contains(&DetectionEngine::DetectItEasy));
        let packer = merged
            .iter()
            .find(|d| {
                d.category == Category::Packer && d.engine == DetectionEngine::InternalSignatures
            })
            .unwrap();
        assert!(packer.source.contains("A") && packer.source.contains("B"));
        assert_eq!(packer.evidence.len(), 2);
    }

    #[test]
    fn progress_callback_can_cancel_a_running_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-cancel.bin");
        std::fs::write(&path, vec![b'A'; 2 * 1024 * 1024]).unwrap();
        let cancel = CancelToken::new();
        let cancel_from_sink = cancel.clone();
        let sink: ProgressSink = Arc::new(move |update| {
            if update.percent >= 20 {
                cancel_from_sink.cancel();
            }
        });
        let result = analyze_file(&path, &AnalysisOptions::default(), &cancel, Some(&sink));
        assert!(matches!(result, Err(AnalysisError::Cancelled)));
    }

    #[test]
    fn yara_rules_are_compiled_and_applied() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(
            rules.join("test.yar"),
            r#"rule binscope_test_mz { meta: description = "MZ header" condition: uint16(0) == 0x5A4D }"#,
        )
        .unwrap();
        let file_path = dir.path().join("sample.exe");
        std::fs::write(&file_path, PeBuilder::pe32().build()).unwrap();
        let options = AnalysisOptions {
            yara_enabled: true,
            yara_rule_dirs: vec![rules],
            ..Default::default()
        };
        let report = analyze_file(&file_path, &options, &CancelToken::new(), None).unwrap();
        assert_eq!(report.yara.matches.len(), 1);
        assert_eq!(report.yara.matches[0].rule, "binscope_test_mz");
        assert_eq!(report.yara.rule_count, 1);
    }

    #[test]
    fn text_export_contains_key_sections() {
        let report = analyze_bytes("export.exe", &PeBuilder::pe32().build());
        let text = report.render_text();
        assert!(text.contains("SHA-256"));
        assert!(text.contains("Entry point"));
        assert!(text.contains("Sections"));
        assert!(text.contains("YARA"));
        let json = report.to_json_pretty().unwrap();
        assert!(json.contains("\"schemaVersion\": 1"));
    }

    #[test]
    fn elf_fixture_is_detected() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[7] = 3;
        data[16..18].copy_from_slice(&2u16.to_le_bytes());
        data[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes());
        data[58..60].copy_from_slice(&64u16.to_le_bytes());
        let report = analyze_bytes("sample.elf", &data);
        assert_eq!(report.format.kind, FormatKind::Elf);
        assert_eq!(report.format.architecture, "x86-64");
        assert_eq!(report.format.operating_system, "Linux");
        assert!(report.elf.is_some());
    }
}
