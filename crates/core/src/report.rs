use binscope_dotnet::DotNetInfo;
use binscope_elfmach::{ElfInfo, MachOInfo};
use binscope_file_detect::{FormatDetection, FormatKind};
use binscope_pe::{PeInfo, Severity};
use binscope_signatures::{Category, Detection};
use binscope_strings::{ExtractedString, StringEncoding, StringsResult};
use binscope_yara::{YaraCompileReport, YaraMatch};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub engine: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            name: "BinScope".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            engine: format!("binscope-core {}", env!("CARGO_PKG_VERSION")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub size_human: String,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub modified_utc: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatInfo {
    pub kind: FormatKind,
    pub label: String,
    pub description: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
    pub supported: bool,
    pub executable: bool,
    pub architecture: String,
    pub bits: u8,
    pub operating_system: String,
    pub file_type: String,
    pub is_dotnet: bool,
    pub managedness: String,
}

impl FormatInfo {
    pub fn from_detection(detection: FormatDetection) -> Self {
        let executable = detection.kind.is_executable_container();
        Self {
            kind: detection.kind,
            label: detection.label,
            description: detection.description,
            confidence: detection.confidence,
            evidence: detection.evidence,
            supported: detection.supported,
            executable,
            architecture: "Unknown".into(),
            bits: 0,
            operating_system: "Unknown".into(),
            file_type: detection.kind.label().to_string(),
            is_dotnet: false,
            managedness: "Unknown".into(),
        }
    }

    pub fn not_applicable(&mut self, reason: &str) {
        self.managedness = reason.to_string();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Complete,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueLevel {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisIssue {
    pub stage: String,
    pub level: IssueLevel,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisMeta {
    pub started_utc: String,
    pub finished_utc: String,
    pub duration_ms: u64,
    pub status: AnalysisStatus,
    pub issues: Vec<AnalysisIssue>,
    pub time_budget_ms: u64,
    pub parse_limit_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionSummary {
    pub compilers: Vec<String>,
    pub linkers: Vec<String>,
    pub packers: Vec<String>,
    pub protectors: Vec<String>,
    pub runtimes: Vec<String>,
    pub frameworks: Vec<String>,
    pub installers: Vec<String>,
    pub tools: Vec<String>,
    pub languages: Vec<String>,
    pub libraries: Vec<String>,
    pub formats: Vec<String>,
    pub other: Vec<String>,
}

impl DetectionSummary {
    pub fn from_detections(detections: &[Detection]) -> Self {
        let mut s = Self::default();
        for d in detections {
            let label = match &d.version {
                Some(v) => format!("{} {}", d.name, v),
                None => d.name.clone(),
            };
            match d.category {
                Category::Compiler => s.compilers.push(label),
                Category::Linker => s.linkers.push(label),
                Category::Packer => s.packers.push(label),
                Category::Protector => s.protectors.push(label),
                Category::Runtime => s.runtimes.push(label),
                Category::Framework => s.frameworks.push(label),
                Category::Installer => s.installers.push(label),
                Category::Tool => s.tools.push(label),
                Category::Language => s.languages.push(label),
                Category::Library => s.libraries.push(label),
                Category::Format => s.formats.push(label),
                Category::Signer | Category::Other => s.other.push(label),
            }
        }
        s
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureDatabaseInfo {
    pub name: String,
    pub version: String,
    pub source: String,
    pub signatures: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureSummary {
    pub enabled: bool,
    pub databases: Vec<SignatureDatabaseInfo>,
    pub total_signatures: usize,
    pub errors: Vec<String>,
    pub die: Option<DieSummary>,
    pub pebear: Option<PebearSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DieSummary {
    pub version: String,
    pub path: String,
    pub files: usize,
    pub with_metadata: usize,
    pub compatible: usize,
    pub incompatible: usize,
    pub reasons: Vec<DieReason>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DieReason {
    pub reason: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PebearSummary {
    pub path: String,
    pub total_blocks: usize,
    pub loaded: usize,
    pub skipped: usize,
    pub reasons: Vec<DieReason>,
    pub errors: Vec<String>,
    pub license: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StringsSummary {
    pub total: usize,
    pub ascii: usize,
    pub utf8: usize,
    pub utf16le: usize,
    pub truncated: bool,
    pub total_found: u64,
    pub bytes_scanned: u64,
    pub elapsed_ms: u64,
    pub min_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StringsSection {
    pub summary: StringsSummary,
    pub items: Vec<ExtractedString>,
}

impl StringsSection {
    pub fn from_result(result: StringsResult) -> Self {
        let (ascii, utf8, utf16le) = result.count_by_encoding();
        Self {
            summary: StringsSummary {
                total: result.items.len(),
                ascii,
                utf8,
                utf16le,
                truncated: result.truncated,
                total_found: result.total_found,
                bytes_scanned: result.bytes_scanned,
                elapsed_ms: result.elapsed_ms,
                min_len: result.min_len,
            },
            items: result.items,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionConfig {
    pub profile: Option<String>,
    pub yara_enabled: bool,
    pub signatures_enabled: bool,
    pub disabled_yara_categories: Vec<String>,
    pub disabled_yara_rules: Vec<String>,
    pub disabled_signature_categories: Vec<String>,
    pub disabled_signatures: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraReport {
    pub enabled: bool,
    pub engine_version: String,
    pub matches: Vec<YaraMatch>,
    pub rule_count: usize,
    pub compile: Option<YaraCompileReport>,

    #[serde(default)]
    pub revision: String,

    #[serde(default)]
    pub sources: Vec<binscope_yara::YaraSourceFile>,
    #[serde(default)]
    pub external_matches: usize,
    #[serde(default)]
    pub internal_matches: usize,
    #[serde(default)]
    pub external_sources: usize,
    #[serde(default)]
    pub internal_sources: usize,
    pub errors: Vec<String>,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub analysis: AnalysisMeta,
    pub file: FileInfo,
    pub format: FormatInfo,
    pub summary: DetectionSummary,
    pub pe: Option<PeInfo>,
    pub elf: Option<ElfInfo>,
    pub macho: Option<MachOInfo>,
    pub dotnet: Option<DotNetInfo>,
    pub detections: Vec<Detection>,
    pub signatures: SignatureSummary,
    pub yara: YaraReport,

    #[serde(default)]
    pub authenticode: Option<binscope_authenticode::AuthenticodeReport>,
    pub detection_config: DetectionConfig,
    pub strings: Option<StringsSection>,
    pub notes: Vec<String>,
}

impl Report {
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "BinScope analysis report");
        let _ = writeln!(out, "========================");
        let _ = writeln!(out, "Tool:        {} {}", self.tool.name, self.tool.version);
        let _ = writeln!(out, "Analyzed:    {}", self.analysis.finished_utc);
        let _ = writeln!(out, "Status:      {:?}", self.analysis.status);
        let _ = writeln!(out, "Duration:    {} ms", self.analysis.duration_ms);
        if let Some(profile) = &self.detection_config.profile {
            let _ = writeln!(out, "Profile:     {profile}");
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "File");
        let _ = writeln!(out, "----");
        let _ = writeln!(out, "Name:        {}", self.file.name);
        let _ = writeln!(out, "Path:        {}", self.file.path);
        let _ = writeln!(
            out,
            "Size:        {} bytes ({})",
            self.file.size, self.file.size_human
        );
        let _ = writeln!(out, "SHA-256:     {}", self.file.sha256);
        let _ = writeln!(out, "SHA-1:       {}", self.file.sha1);
        let _ = writeln!(out, "MD5:         {}", self.file.md5);
        if let Some(modified) = &self.file.modified_utc {
            let _ = writeln!(out, "Modified:    {modified}");
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "Identification");
        let _ = writeln!(out, "--------------");
        let _ = writeln!(
            out,
            "Format:      {} ({})",
            self.format.label, self.format.description
        );
        let _ = writeln!(
            out,
            "Architecture:{} {} ({}-bit)",
            if self.format.architecture.len() < 8 {
                "\t"
            } else {
                " "
            },
            self.format.architecture,
            self.format.bits
        );
        let _ = writeln!(out, "OS:          {}", self.format.operating_system);
        let _ = writeln!(out, "File type:   {}", self.format.file_type);
        let _ = writeln!(out, ".NET:        {}", self.format.managedness);
        let _ = writeln!(out, "Detection:   {}% confidence", self.format.confidence);
        for ev in &self.format.evidence {
            let _ = writeln!(out, "  - {ev}");
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "Detections ({})", self.detections.len());
        let _ = writeln!(out, "------------");
        if self.detections.is_empty() {
            let _ = writeln!(out, "No signature or heuristic matched.");
        }
        for d in &self.detections {
            let version = d
                .version
                .as_ref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "[{}] {}{} ({}% confidence, {})",
                d.category.label(),
                d.name,
                version,
                d.confidence,
                d.source
            );
            if !d.description.is_empty() {
                let _ = writeln!(out, "  {}", d.description);
            }
            for ev in &d.evidence {
                let _ = writeln!(out, "  - {}", ev.description);
            }
        }
        let _ = writeln!(out);

        if let Some(pe) = &self.pe {
            let _ = writeln!(out, "PE");
            let _ = writeln!(out, "--");
            let _ = writeln!(out, "Kind:        {}", pe.pe_kind);
            let _ = writeln!(
                out,
                "Machine:     {} ({})",
                pe.machine_name, pe.architecture
            );
            let _ = writeln!(
                out,
                "Timestamp:   {}",
                pe.time_date_stamp_utc.as_deref().unwrap_or("not set")
            );
            let _ = writeln!(out, "Entry point: RVA {:#x}", pe.entry_point_rva);
            if let Some(off) = pe.entry_point_file_offset {
                let _ = writeln!(out, "             file offset {off:#x}");
            }
            let _ = writeln!(out, "ImageBase:   {:#x}", pe.image_base);
            let _ = writeln!(out, "Subsystem:   {} ({})", pe.subsystem_name, pe.subsystem);
            let _ = writeln!(out, "Linker:      {}", pe.linker_version);
            let _ = writeln!(out, "SizeOfImage: {:#x}", pe.size_of_image);
            let _ = writeln!(
                out,
                "Checksum:    {:#010x} ({})",
                pe.checksum,
                if pe.checksum_valid {
                    "valid"
                } else {
                    "not validated"
                }
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "Sections");
            let _ = writeln!(out, "--------");
            for s in &pe.sections {
                let _ = writeln!(
                    out,
                    "{:<10} RVA {:#010x} VSize {:#010x} Raw {:#010x}+{:#x} {:<3} entropy {:.3}",
                    s.name,
                    s.virtual_address,
                    s.virtual_size,
                    s.raw_offset,
                    s.raw_size,
                    s.permissions,
                    s.entropy
                );
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "Imports ({})", pe.imports.len());
            let _ = writeln!(out, "-------------");
            for lib in &pe.imports {
                let _ = writeln!(out, "{} ({} functions)", lib.name, lib.functions.len());
                for f in lib.functions.iter().take(500) {
                    match (&f.name, f.ordinal) {
                        (Some(n), _) => {
                            let _ = writeln!(out, "  {n}");
                        }
                        (None, Some(o)) => {
                            let _ = writeln!(out, "  #{o}");
                        }
                        _ => {}
                    }
                }
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "Exports ({})", pe.exports.len());
            let _ = writeln!(out, "-------------");
            for e in &pe.exports {
                let _ = writeln!(
                    out,
                    "{} (ordinal {}) RVA {:#x}{}",
                    e.name.as_deref().unwrap_or("<unnamed>"),
                    e.ordinal,
                    e.rva,
                    e.forwarder
                        .as_ref()
                        .map(|f| format!(" -> {f}"))
                        .unwrap_or_default()
                );
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "Anomalies ({})", pe.anomalies.len());
            let _ = writeln!(out, "-----------");
            for a in &pe.anomalies {
                let _ = writeln!(
                    out,
                    "[{:?}] {} ({}) {}: {}",
                    a.severity, a.rule_id, a.code, a.title, a.message
                );
                if !a.explanation.is_empty() {
                    let _ = writeln!(out, "  {}", a.explanation);
                }
                if let Some(expected) = &a.expected {
                    let _ = writeln!(out, "  expected: {expected}");
                }
                if let Some(observed) = &a.observed {
                    let _ = writeln!(out, "  observed: {observed}");
                }
                for evidence in &a.evidence {
                    let location = match (evidence.file_offset, evidence.rva) {
                        (Some(offset), _) => format!(" @ {offset:#x}"),
                        (None, Some(rva)) => format!(" @ RVA {rva:#x}"),
                        _ => String::new(),
                    };
                    let _ = writeln!(
                        out,
                        "  - {:?} {}: {}{location}",
                        evidence.kind, evidence.label, evidence.value
                    );
                }
                if !a.false_positive_notes.is_empty() {
                    let _ = writeln!(out, "  false positives: {}", a.false_positive_notes);
                }
            }
            let _ = writeln!(out);
        } else {
            let _ = writeln!(out, "PE\n--\nNot applicable: the file is not a PE image.\n");
        }

        if let Some(auth) = &self.authenticode {
            let _ = writeln!(out, "Authenticode");
            let _ = writeln!(out, "------------");
            let _ = writeln!(out, "Presence:    {:?}", auth.presence);
            let _ = writeln!(out, "Signature:   {:?}", auth.signature);
            let _ = writeln!(out, "Chain:       {:?}", auth.chain);
            let _ = writeln!(out, "Certificate: {:?}", auth.certificate_time);
            let _ = writeln!(out, "Revocation:  {:?}", auth.revocation);
            let _ = writeln!(out, "Backend:     {:?}", auth.backend);
            let _ = writeln!(
                out,
                "Digest:      {} (signed {}, computed {})",
                match auth.digest_matches {
                    Some(true) => "matches",
                    Some(false) => "MISMATCH",
                    None => "not compared",
                },
                auth.signed_digest.as_deref().unwrap_or("unavailable"),
                auth.computed_digest.as_deref().unwrap_or("unavailable")
            );
            if let Some(signer) = &auth.signer {
                let _ = writeln!(
                    out,
                    "Signer:      {}",
                    signer.subject.as_deref().unwrap_or("unknown")
                );
            }
            for check in &auth.signatures {
                let _ = writeln!(
                    out,
                    "  entry {}: {} ({}) {}",
                    check.entry_index, check.status, check.certificate_type, check.note
                );
            }
            for note in &auth.notes {
                let _ = writeln!(out, "  note: {note}");
            }
            let _ = writeln!(out);
        }

        if let Some(elf) = &self.elf {
            let _ = writeln!(out, "ELF");
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "Class:       {} {}", elf.class, elf.endianness);
            let _ = writeln!(out, "Type:        {}", elf.object_type_name);
            let _ = writeln!(
                out,
                "Machine:     {} ({})",
                elf.machine_name, elf.architecture
            );
            let _ = writeln!(out, "Entry:       {:#x}", elf.entry_point);
            let _ = writeln!(
                out,
                "Interpreter: {}",
                elf.interpreter.as_deref().unwrap_or("none")
            );
            let _ = writeln!(out, "Needed:      {}", elf.needed_libraries.join(", "));
            if let Some(build_id) = &elf.build_id {
                let _ = writeln!(out, "Build ID:    {build_id}");
            }
            let _ = writeln!(out);
        }

        if let Some(macho) = &self.macho {
            let _ = writeln!(out, "Mach-O");
            let _ = writeln!(out, "------");
            let _ = writeln!(
                out,
                "Universal:   {}",
                if macho.is_fat { "yes" } else { "no" }
            );
            for slice in &macho.slices {
                let _ = writeln!(
                    out,
                    "Slice:       {} ({}-bit) {} entry {:#x}",
                    slice.architecture, slice.bits, slice.file_type_name, slice.entry_point
                );
                if !slice.libraries.is_empty() {
                    let _ = writeln!(out, "Libraries:   {}", slice.libraries.join(", "));
                }
            }
            let _ = writeln!(out);
        }

        if let Some(dn) = &self.dotnet {
            let _ = writeln!(out, ".NET metadata");
            let _ = writeln!(out, "-------------");
            let _ = writeln!(out, "Runtime:     {}", dn.runtime_version);
            let _ = writeln!(
                out,
                "Metadata:    {}",
                dn.metadata_version.as_deref().unwrap_or("unknown")
            );
            let _ = writeln!(out, "Kind:        {}", dn.kind);
            let _ = writeln!(out, "Entry point: {}", dn.entry_point_kind);
            let _ = writeln!(out, "Strong name: {}", dn.strong_name_signed);
            if let Some(a) = &dn.assembly {
                let _ = writeln!(out, "Assembly:    {} {}", a.name, a.version);
            }
            if let Some(m) = &dn.module_name {
                let _ = writeln!(out, "Module:      {m}");
            }
            let _ = writeln!(
                out,
                "Types:       {}  Methods: {}",
                dn.type_definition_count, dn.method_definition_count
            );
            let _ = writeln!(out);
        }

        let _ = writeln!(out, "Strings");
        let _ = writeln!(out, "-------");
        match &self.strings {
            Some(s) => {
                let _ = writeln!(
                    out,
                    "Total: {} (ASCII {}, UTF-16LE {}) min length {}{}",
                    s.summary.total,
                    s.summary.ascii,
                    s.summary.utf16le,
                    s.summary.min_len,
                    if s.summary.truncated {
                        ", truncated"
                    } else {
                        ""
                    }
                );
                for item in s.items.iter().take(5000) {
                    let enc = match item.encoding {
                        StringEncoding::Ascii => "A",
                        StringEncoding::Utf8 => "U",
                        StringEncoding::Utf16Le => "W",
                    };
                    let _ = writeln!(out, "{:#010x} [{enc}] {}", item.offset, item.value);
                }
            }
            None => {
                let _ = writeln!(out, "Not extracted.");
            }
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "YARA ({})", self.yara.matches.len());
        let _ = writeln!(out, "----");
        if !self.yara.enabled {
            let _ = writeln!(out, "YARA scanning was disabled for this analysis.");
        } else if self.yara.matches.is_empty() {
            let _ = writeln!(out, "No rules matched.");
        }
        for m in &self.yara.matches {
            let _ = writeln!(out, "{} [{}]", m.rule, m.namespace);
            if let Some(d) = &m.description {
                let _ = writeln!(out, "  {d}");
            }
        }
        let _ = writeln!(out);

        if !self.analysis.issues.is_empty() {
            let _ = writeln!(out, "Analysis issues");
            let _ = writeln!(out, "---------------");
            for issue in &self.analysis.issues {
                let _ = writeln!(
                    out,
                    "[{:?}] {}: {}",
                    issue.level, issue.stage, issue.message
                );
            }
        }
        out
    }

    pub fn anomaly_count(&self) -> usize {
        self.pe.as_ref().map(|p| p.anomalies.len()).unwrap_or(0)
    }

    pub fn highest_anomaly_severity(&self) -> Option<Severity> {
        self.pe
            .as_ref()
            .and_then(|p| p.anomalies.iter().map(|a| a.severity).max())
    }
}
