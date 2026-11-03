use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const YARA_SCHEMA: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Compatible,
    Invalid,
    Incompatible,
    Pending,
    Quarantined,
    Duplicate,
    LicenseBlocked,
    Obsolete,
}

impl RuleStatus {
    pub fn label(self) -> &'static str {
        match self {
            RuleStatus::Compatible => "compatible",
            RuleStatus::Invalid => "invalid",
            RuleStatus::Incompatible => "incompatible",
            RuleStatus::Pending => "pending",
            RuleStatus::Quarantined => "quarantined",
            RuleStatus::Duplicate => "duplicate",
            RuleStatus::LicenseBlocked => "license_blocked",
            RuleStatus::Obsolete => "obsolete",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Exact,
    Probable,
    Heuristic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraRuleEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub categories: Vec<String>,
    pub tags: Vec<String>,
    pub source_id: String,
    pub source: String,
    pub path: String,
    pub author: Option<String>,
    pub license: Option<String>,
    pub hash: String,
    pub added: Option<String>,
    pub modified: Option<String>,
    pub status: RuleStatus,
    pub enabled: bool,
    pub namespace: String,

    #[serde(default)]
    pub revision: String,
    pub severity: Option<String>,
    pub confidence: Option<u8>,
    pub dependencies: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub format: Option<String>,
    pub version: Option<String>,
    pub source_id: String,
    pub source: String,
    pub license: Option<String>,
    pub status: RuleStatus,
    pub enabled: bool,
    pub confidence: u8,
    pub kind: MatchKind,
    pub pattern: Option<String>,
    pub offsets: Option<String>,
    pub product: Option<String>,
    pub evidence: Vec<String>,
    pub compatibility: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryInfo {
    pub id: String,
    pub label: String,
    pub description: String,
    pub total: usize,
    pub enabled: usize,
    pub invalid: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryStats {
    pub yara_installed: usize,
    pub yara_enabled: usize,
    pub yara_disabled: usize,
    pub yara_invalid: usize,
    pub signatures_installed: usize,
    pub signatures_enabled: usize,
    pub signatures_disabled: usize,
    pub signatures_invalid: usize,
    pub sources_enabled: usize,
    pub sources_total: usize,
    pub pending_updates: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInventory {
    pub generated_at: String,

    #[serde(default)]
    pub revision: String,
    pub yara_rules: Vec<YaraRuleEntry>,
    pub signatures: Vec<SignatureEntry>,
    pub yara_categories: Vec<CategoryInfo>,
    pub signature_categories: Vec<CategoryInfo>,
    pub sources: Vec<SourceStatus>,
    pub signature_sources: Vec<SignatureSourceInfo>,
    pub source_errors: Vec<String>,
    pub stats: InventoryStats,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureSourceInfo {
    pub id: String,
    pub name: String,
    pub license: Option<String>,
    pub version: Option<String>,
    pub installed: usize,
    pub compatible: usize,
    pub incompatible: usize,
    pub last_update: Option<String>,
    pub notes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceDefinition {
    pub id: String,
    pub name: String,
    pub url: String,
    pub kind: String,
    pub method: String,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub asset: Option<String>,
    pub include_prefixes: Vec<String>,
    pub license: Option<String>,
    pub license_url: Option<String>,
    pub default_enabled: bool,
    pub implemented: bool,
    pub notes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    #[serde(flatten)]
    pub definition: SourceDefinition,
    pub enabled: bool,
    pub last_check: Option<String>,
    pub last_success: Option<String>,
    pub version: Option<String>,
    pub commit: Option<String>,
    pub artifact_sha256: Option<String>,
    pub imported: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub duplicates: usize,
    pub compatibility: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub pending: bool,
}

impl SourceStatus {
    pub fn from_definition(definition: SourceDefinition) -> Self {
        Self {
            enabled: definition.default_enabled,
            definition,
            last_check: None,
            last_success: None,
            version: None,
            commit: None,
            artifact_sha256: None,
            imported: 0,
            accepted: 0,
            rejected: 0,
            duplicates: 0,
            compatibility: "pending".into(),
            errors: Vec::new(),
            warnings: Vec::new(),
            pending: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePreferences {
    pub auto_check: bool,
    pub interval_hours: u64,
    pub last_check: Option<String>,
    pub last_update: Option<String>,
}

impl Default for UpdatePreferences {
    fn default() -> Self {
        Self {
            auto_check: true,
            interval_hours: 24,
            last_check: None,
            last_update: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FalsePositive {
    pub rule_id: String,
    pub sha256: Option<String>,
    pub name: String,
    pub marked_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub yara_categories: Vec<String>,
    pub signature_categories: Vec<String>,
    pub builtin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulePreferences {
    pub schema: u32,
    pub yara_enabled: bool,
    pub signatures_enabled: bool,
    pub disabled_yara_categories: Vec<String>,
    pub disabled_yara_rules: Vec<String>,
    pub disabled_signature_categories: Vec<String>,
    pub disabled_signatures: Vec<String>,
    pub enabled_sources: Vec<String>,
    pub update: UpdatePreferences,
    pub profile: String,
    pub custom_profiles: Vec<Profile>,
    pub false_positives: Vec<FalsePositive>,
}

impl Default for RulePreferences {
    fn default() -> Self {
        Self {
            schema: YARA_SCHEMA,
            yara_enabled: true,
            signatures_enabled: true,
            disabled_yara_categories: Vec::new(),
            disabled_yara_rules: Vec::new(),
            disabled_signature_categories: Vec::new(),
            disabled_signatures: Vec::new(),
            enabled_sources: Vec::new(),
            update: UpdatePreferences::default(),
            profile: "balanced".into(),
            custom_profiles: Vec::new(),
            false_positives: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangelogEntry {
    pub at: String,
    pub source_id: String,
    pub source_name: String,
    pub from_version: Option<String>,
    pub version: String,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub invalid: usize,
    pub status: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLogEntry {
    pub at: String,
    pub source_id: String,
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleFilter {
    pub yara_enabled: bool,
    pub signatures_enabled: bool,
    pub disabled_yara_categories: Vec<String>,
    pub disabled_yara_rules: Vec<String>,
    pub disabled_signature_categories: Vec<String>,
    pub disabled_signatures: Vec<String>,
    pub false_positive_rules: Vec<String>,
}

impl Default for RuleFilter {
    fn default() -> Self {
        Self {
            yara_enabled: true,
            signatures_enabled: true,
            disabled_yara_categories: Vec::new(),
            disabled_yara_rules: Vec::new(),
            disabled_signature_categories: Vec::new(),
            disabled_signatures: Vec::new(),
            false_positive_rules: Vec::new(),
        }
    }
}

impl RuleFilter {
    pub fn from_preferences(prefs: &RulePreferences) -> Self {
        Self {
            yara_enabled: prefs.yara_enabled,
            signatures_enabled: prefs.signatures_enabled,
            disabled_yara_categories: prefs.disabled_yara_categories.clone(),
            disabled_yara_rules: prefs.disabled_yara_rules.clone(),
            disabled_signature_categories: prefs.disabled_signature_categories.clone(),
            disabled_signatures: prefs.disabled_signatures.clone(),
            false_positive_rules: prefs
                .false_positives
                .iter()
                .map(|fp| fp.rule_id.clone())
                .collect(),
        }
    }

    pub fn yara_rule_enabled(&self, rule: &str, categories: &[String]) -> bool {
        if !self.yara_enabled {
            return false;
        }
        if self.disabled_yara_rules.iter().any(|r| r == rule)
            || self.false_positive_rules.iter().any(|r| r == rule)
        {
            return false;
        }
        !categories
            .iter()
            .any(|c| self.disabled_yara_categories.iter().any(|d| d == c))
    }

    pub fn signature_enabled(&self, id: &str, category: &str) -> bool {
        if !self.signatures_enabled {
            return false;
        }
        if self.disabled_signatures.iter().any(|s| s == id)
            || self.false_positive_rules.iter().any(|s| s == id)
        {
            return false;
        }
        !self
            .disabled_signature_categories
            .iter()
            .any(|c| c == category)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub accepted: usize,
    pub rejected: usize,
    pub files: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledUpdateResult {
    pub checked: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub errors: usize,
    pub records: Vec<SourceUpdateResult>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceUpdateResult {
    pub source_id: String,
    pub status: String,
    pub version: Option<String>,
    pub accepted: usize,
    pub rejected: usize,
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceConfigInput {
    pub name: String,
    pub repo_url: String,
    pub branch: String,
    pub license: Option<String>,
    pub include_prefixes: Vec<String>,
}

pub type SourceMap = BTreeMap<String, SourceStatus>;
