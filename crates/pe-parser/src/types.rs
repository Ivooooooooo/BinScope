use serde::{Deserialize, Serialize};

pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_SECURITY: usize = 4;
pub const DIR_DEBUG: usize = 6;
pub const DIR_TLS: usize = 9;
pub const DIR_DELAY_IMPORT: usize = 13;
pub const DIR_CLR: usize = 14;

pub const DATA_DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "Base Relocation",
    "Debug",
    "Architecture",
    "Global Pointer",
    "TLS",
    "Load Configuration",
    "Bound Import",
    "Import Address Table",
    "Delay Import",
    "CLR Runtime",
    "Reserved",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataDirectoryInfo {
    pub index: usize,
    pub name: String,

    pub rva: u32,
    pub size: u32,

    pub file_offset: Option<u64>,
    pub present: bool,
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionInfo {
    pub index: usize,
    pub name: String,

    pub name_is_irregular: bool,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,

    pub permissions: String,
    pub flags: Vec<String>,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
    pub readable: bool,

    pub is_bss: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportLibrary {
    pub name: String,

    pub descriptor_rva: u32,
    pub functions: Vec<ImportFunction>,

    pub name_is_irregular: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportInfo {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub file_offset: Option<u32>,
    pub forwarder: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceEntry {
    pub type_id: Option<u32>,
    pub type_name: String,
    pub name_id: Option<u32>,
    pub name: String,
    pub language: u32,
    pub codepage: u32,
    pub rva: u32,
    pub size: u32,
    pub file_offset: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub fixed_file_version: Option<String>,
    pub fixed_product_version: Option<String>,
    pub company_name: Option<String>,
    pub product_name: Option<String>,
    pub file_description: Option<String>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub internal_name: Option<String>,
    pub original_filename: Option<String>,
    pub legal_copyright: Option<String>,
    pub comments: Option<String>,

    pub entries: Vec<KeyValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdbInfo {
    pub path: String,
    pub guid: Option<String>,
    pub age: Option<u32>,
    pub signature: String,
    pub debug_directory_rva: u32,
    pub data_file_offset: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeViewRecord {
    pub debug_index: usize,

    pub signature: String,
    pub pdb_path: Option<String>,
    pub guid: Option<String>,
    pub age: Option<u32>,

    pub timestamp: Option<u32>,
    pub timestamp_utc: Option<String>,
    pub data_offset: Option<u64>,
    pub data_size: u32,

    pub status: String,

    pub primary: bool,

    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugEntryInfo {
    pub index: usize,
    pub debug_type: u32,
    pub type_name: String,
    pub timestamp: u32,

    pub timestamp_utc: Option<String>,
    pub major_version: u16,
    pub minor_version: u16,
    pub size_of_data: u32,
    pub address_rva: u32,
    pub file_offset: Option<u64>,

    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RichEntry {
    pub product_id: u16,
    pub build_number: u16,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RichHeaderInfo {
    pub offset: u64,

    pub key: u32,
    pub entries: Vec<RichEntry>,
    pub product_ids: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateEntry {
    pub offset: u64,
    pub length: u32,
    pub revision: u16,
    pub revision_name: String,
    pub certificate_type: u16,
    pub certificate_type_name: String,
    pub contains_nested_signature_oid: bool,

    #[serde(default)]
    pub data_offset: u64,

    #[serde(default)]
    pub data_length: u32,

    #[serde(default)]
    pub in_bounds: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub present: bool,
    pub directory_offset: u32,
    pub directory_size: u32,
    pub entries: Vec<CertificateEntry>,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClrDirectory {
    pub header_size: u32,
    pub runtime_version: String,
    pub metadata_rva: u32,
    pub metadata_size: u32,

    pub metadata_file_offset: Option<u64>,
    pub flags: u32,
    pub flag_names: Vec<String>,
    pub entry_point_token: u32,
    pub entry_point_kind: String,
    pub resources_rva: u32,
    pub resources_size: u32,
    pub strong_name_rva: u32,
    pub strong_name_size: u32,
    pub strong_name_signed: bool,

    pub metadata_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayInfo {
    pub offset: u64,
    pub size: u64,

    #[serde(default)]
    pub entropy: Option<f64>,

    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyCategory {
    Malformed,

    Suspicious,

    Informational,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    SectionHeader,
    FileRange,
    Rva,
    DataDirectory,
    HeaderField,
    Overlay,
    CertificateTable,
    DebugDirectory,
    Entropy,
    Checksum,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyEvidence {
    pub kind: EvidenceKind,
    pub label: String,
    pub value: String,
    pub file_offset: Option<u64>,
    pub rva: Option<u32>,
    pub section: Option<String>,
}

impl AnomalyEvidence {
    pub fn new(kind: EvidenceKind, label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            kind,
            label: label.into(),
            value: value.into(),
            file_offset: None,
            rva: None,
            section: None,
        }
    }

    pub fn at_offset(mut self, offset: u64) -> Self {
        self.file_offset = Some(offset);
        self
    }

    pub fn maybe_at_offset(mut self, offset: Option<u64>) -> Self {
        self.file_offset = offset;
        self
    }

    pub fn at_rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    pub fn in_section(mut self, name: impl Into<String>) -> Self {
        self.section = Some(name.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anomaly {
    #[serde(default)]
    pub rule_id: String,

    pub code: String,
    pub severity: Severity,

    #[serde(default)]
    pub title: String,

    pub message: String,

    #[serde(default)]
    pub explanation: String,
    #[serde(default)]
    pub category: Option<AnomalyCategory>,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    #[serde(default)]
    pub evidence: Vec<AnomalyEvidence>,

    #[serde(default)]
    pub file_offset: Option<u64>,

    #[serde(default)]
    pub rva: Option<u32>,

    #[serde(default)]
    pub sections: Vec<String>,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub observed: Option<String>,

    #[serde(default)]
    pub false_positive_notes: String,
}

impl Anomaly {
    pub fn new(code: &str, severity: Severity, message: impl Into<String>) -> Self {
        Self::build(code, severity, message, AnomalyCategory::Informational)
    }

    pub fn build(
        code: &str,
        severity: Severity,
        message: impl Into<String>,
        category: AnomalyCategory,
    ) -> Self {
        let message = message.into();
        Self {
            rule_id: String::new(),
            code: code.to_string(),
            severity,
            title: message.clone(),
            message,
            explanation: String::new(),
            category: Some(category),
            confidence: None,
            evidence: Vec::new(),
            file_offset: None,
            rva: None,
            sections: Vec::new(),
            expected: None,
            observed: None,
            false_positive_notes: String::new(),
        }
    }

    pub fn with_rule(mut self, rule_id: impl Into<String>, title: impl Into<String>) -> Self {
        self.rule_id = rule_id.into();
        self.title = title.into();
        self
    }

    pub fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = explanation.into();
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    pub fn with_evidence(mut self, evidence: AnomalyEvidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_offset(mut self, offset: u64) -> Self {
        self.file_offset = Some(offset);
        self
    }

    pub fn with_rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    pub fn with_section(mut self, name: impl Into<String>) -> Self {
        self.sections.push(name.into());
        self
    }

    pub fn with_expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self
    }

    pub fn with_observed(mut self, observed: impl Into<String>) -> Self {
        self.observed = Some(observed.into());
        self
    }

    pub fn with_false_positive_notes(mut self, notes: impl Into<String>) -> Self {
        self.false_positive_notes = notes.into();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeInfo {
    pub pe_kind: String,
    pub is_64: bool,
    pub machine: u16,
    pub machine_name: String,
    pub architecture: String,
    pub bits: u8,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub time_date_stamp_utc: Option<String>,
    pub characteristics: u16,
    pub characteristic_names: Vec<String>,
    pub dll_characteristics: u16,
    pub dll_characteristic_names: Vec<String>,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub entry_point_file_offset: Option<u64>,
    pub size_of_image: u32,
    pub size_of_headers: u32,

    #[serde(default)]
    pub optional_header_offset: u64,

    #[serde(default)]
    pub section_table_offset: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsystem: u16,
    pub subsystem_name: String,
    pub is_dll: bool,
    pub is_driver: bool,
    pub linker_version: String,
    pub os_version: String,
    pub image_version: String,
    pub subsystem_version: String,
    pub checksum: u32,
    pub computed_checksum: u32,
    pub checksum_valid: bool,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectoryInfo>,
    pub sections: Vec<SectionInfo>,
    pub exports_dll_name: Option<String>,
    pub exports: Vec<ExportInfo>,
    pub imports: Vec<ImportLibrary>,
    pub delay_imports: Vec<ImportLibrary>,
    pub resources: Vec<ResourceEntry>,
    pub version_info: Option<VersionInfo>,
    pub manifest: Option<String>,
    pub pdb: Option<PdbInfo>,

    #[serde(default)]
    pub codeview_records: Vec<CodeViewRecord>,

    #[serde(default)]
    pub debug_entries: Vec<DebugEntryInfo>,

    #[serde(default)]
    pub pdb_path_warning: Option<String>,
    pub rich_header: Option<RichHeaderInfo>,
    pub clr: Option<ClrDirectory>,
    pub certificate: CertificateInfo,
    pub tls_callbacks: Vec<u64>,
    pub overlay: Option<OverlayInfo>,
    pub anomalies: Vec<Anomaly>,
    pub parse_notes: Vec<String>,
}

impl PeInfo {
    pub fn directory(&self, index: usize) -> Option<&DataDirectoryInfo> {
        self.data_directories.iter().find(|d| d.index == index)
    }

    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| {
            let start = s.virtual_address;
            let size = s.virtual_size.max(s.raw_size);
            rva >= start && (rva as u64) < start as u64 + size as u64
        })
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Option<u64> {
        if rva < self.size_of_headers {
            return Some(rva as u64);
        }
        let section = self.section_for_rva(rva)?;
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.raw_size {
            return None;
        }
        Some(section.raw_offset as u64 + delta as u64)
    }

    pub fn import_libraries(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.imports.iter().map(|i| i.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    pub fn imported_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .imports
            .iter()
            .flat_map(|lib| lib.functions.iter().filter_map(|f| f.name.as_deref()))
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

pub fn machine_info(machine: u16) -> (&'static str, &'static str, u8) {
    match machine {
        0x0000 => ("Unknown", "unknown", 0),
        0x014c => ("IMAGE_FILE_MACHINE_I386", "x86", 32),
        0x0162 => ("IMAGE_FILE_MACHINE_R3000", "MIPS R3000", 32),
        0x0166 => ("IMAGE_FILE_MACHINE_R4000", "MIPS R4000", 32),
        0x0168 => ("IMAGE_FILE_MACHINE_R10000", "MIPS R10000", 32),
        0x0169 => ("IMAGE_FILE_MACHINE_WCEMIPSV2", "MIPS WCE v2", 32),
        0x0184 => ("IMAGE_FILE_MACHINE_ALPHA", "Alpha", 32),
        0x01a2 => ("IMAGE_FILE_MACHINE_SH3", "SuperH 3", 32),
        0x01a3 => ("IMAGE_FILE_MACHINE_SH3DSP", "SuperH 3 DSP", 32),
        0x01a6 => ("IMAGE_FILE_MACHINE_SH4", "SuperH 4", 32),
        0x01c0 => ("IMAGE_FILE_MACHINE_ARM", "ARM", 32),
        0x01c2 => ("IMAGE_FILE_MACHINE_THUMB", "ARM Thumb", 32),
        0x01c4 => ("IMAGE_FILE_MACHINE_ARMNT", "ARM Thumb-2", 32),
        0x01d3 => ("IMAGE_FILE_MACHINE_AM33", "Matsushita AM33", 32),
        0x01f0 => ("IMAGE_FILE_MACHINE_POWERPC", "PowerPC", 32),
        0x01f1 => ("IMAGE_FILE_MACHINE_POWERPCFP", "PowerPC FP", 32),
        0x0200 => ("IMAGE_FILE_MACHINE_IA64", "Itanium", 64),
        0x0266 => ("IMAGE_FILE_MACHINE_MIPS16", "MIPS16", 32),
        0x0284 => ("IMAGE_FILE_MACHINE_ALPHA64", "Alpha64", 64),
        0x0366 => ("IMAGE_FILE_MACHINE_MIPSFPU", "MIPS FPU", 32),
        0x0466 => ("IMAGE_FILE_MACHINE_MIPSFPU16", "MIPS FPU16", 32),
        0x0ebc => ("IMAGE_FILE_MACHINE_EBC", "EFI Byte Code", 64),
        0x5032 => ("IMAGE_FILE_MACHINE_RISCV32", "RISC-V 32", 32),
        0x5064 => ("IMAGE_FILE_MACHINE_RISCV64", "RISC-V 64", 64),
        0x5128 => ("IMAGE_FILE_MACHINE_RISCV128", "RISC-V 128", 128),
        0x6232 => ("IMAGE_FILE_MACHINE_LOONGARCH32", "LoongArch 32", 32),
        0x6264 => ("IMAGE_FILE_MACHINE_LOONGARCH64", "LoongArch 64", 64),
        0x8664 => ("IMAGE_FILE_MACHINE_AMD64", "x86-64", 64),
        0x9041 => ("IMAGE_FILE_MACHINE_M32R", "Mitsubishi M32R", 32),
        0xaa64 => ("IMAGE_FILE_MACHINE_ARM64", "ARM64", 64),
        0xc0ee => ("IMAGE_FILE_MACHINE_CEE", "CLR pure IL", 0),
        _ => ("Unknown machine", "unknown", 0),
    }
}

pub fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "Unknown",
        1 => "Native (drivers)",
        2 => "Windows GUI",
        3 => "Windows CUI (console)",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        8 => "Native Windows",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows Boot Application",
        17 => "Xbox Code Catalog",
        _ => "Unknown subsystem",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooSmall,
    InvalidDosHeader,
    InvalidPeHeader,
    InvalidOptionalHeader,
    TooManySections,
    Io,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            ParseError::TooSmall => "file is too small to contain a DOS header",
            ParseError::InvalidDosHeader => "invalid DOS header (missing MZ signature)",
            ParseError::InvalidPeHeader => "invalid PE header (missing or truncated NT headers)",
            ParseError::InvalidOptionalHeader => "unsupported or truncated optional header",
            ParseError::TooManySections => "section count exceeds the configured limit",
            ParseError::Io => "unexpected end of file while reading PE structures",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ParseError {}
