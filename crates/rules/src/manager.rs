use crate::model::{
    ChangelogEntry, FalsePositive, ImportResult, Profile, RulePreferences, RuleStatus,
    SourceStatus, UpdateLogEntry,
};
use crate::sources::{default_profiles, default_sources};
use binscope_yara::YaraRuleSet;
use chrono::{SecondsFormat, Utc};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_CUSTOM_RULE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ManagerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid rule preferences: {0}")]
    Invalid(String),
    #[error("YARA validation failed: {0}")]
    Yara(String),
}

pub type Result<T> = std::result::Result<T, ManagerError>;

pub struct RuleManager {
    pub data_dir: PathBuf,
}

impl RuleManager {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    pub fn preferences_path(&self) -> PathBuf {
        self.data_dir.join("rules").join("preferences.json")
    }

    pub fn sources_path(&self) -> PathBuf {
        self.data_dir.join("rules").join("sources.json")
    }

    pub fn changelog_path(&self) -> PathBuf {
        self.data_dir.join("rules").join("changelog.json")
    }

    pub fn logs_path(&self) -> PathBuf {
        self.data_dir.join("rules").join("update.log.jsonl")
    }

    pub fn custom_yara_dir(&self) -> PathBuf {
        self.data_dir.join("yara").join("custom")
    }

    pub fn source_dir(&self, id: &str) -> PathBuf {
        self.data_dir.join("yara").join("sources").join(safe_id(id))
    }

    pub fn legacy_yara_dir(&self) -> PathBuf {
        self.data_dir.join("yara").join("legacy")
    }

    pub fn migrate_legacy_yara(&self) -> Result<()> {
        let root = self.data_dir.join("yara");
        let legacy = self.legacy_yara_dir();
        if !root.is_dir() {
            return Ok(());
        }
        std::fs::create_dir_all(&legacy)?;
        let entries = std::fs::read_dir(&root)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path == legacy
                || path == self.custom_yara_dir()
                || path == root.join("sources")
                || !path.is_file()
            {
                continue;
            }
            let is_rule = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"));
            if is_rule {
                let name = path
                    .file_name()
                    .map(|n| n.to_os_string())
                    .unwrap_or_default();
                std::fs::rename(&path, legacy.join(name))?;
            }
        }
        Ok(())
    }

    pub fn load_preferences(&self) -> RulePreferences {
        let path = self.preferences_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<RulePreferences>(&text).ok())
            .map(normalize_preferences)
            .unwrap_or_else(default_preferences)
    }

    pub fn save_preferences(&self, preferences: &RulePreferences) -> Result<()> {
        let text = serde_json::to_string_pretty(&normalize_preferences(preferences.clone()))?;
        atomic_write(&self.preferences_path(), text.as_bytes())
    }

    pub fn restore_defaults(&self) -> Result<RulePreferences> {
        let defaults = default_preferences();
        self.save_preferences(&defaults)?;
        Ok(defaults)
    }

    pub fn load_sources(&self) -> Vec<SourceStatus> {
        let defaults = default_sources();
        let saved = std::fs::read_to_string(self.sources_path())
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<SourceStatus>>(&text).ok())
            .unwrap_or_default();
        let mut out = Vec::new();
        for mut source in defaults {
            if let Some(previous) = saved
                .iter()
                .find(|item| item.definition.id == source.definition.id)
            {
                source.enabled = previous.enabled;
                source.last_check = previous.last_check.clone();
                source.last_success = previous.last_success.clone();
                source.version = previous.version.clone();
                source.commit = previous.commit.clone();
                source.artifact_sha256 = previous.artifact_sha256.clone();
                source.imported = previous.imported;
                source.accepted = previous.accepted;
                source.rejected = previous.rejected;
                source.duplicates = previous.duplicates;
                source.compatibility = previous.compatibility.clone();
                source.errors = previous.errors.clone();
                source.warnings = previous.warnings.clone();
                source.pending = previous.pending;
            }
            out.push(source);
        }

        for previous in saved {
            if !out
                .iter()
                .any(|item| item.definition.id == previous.definition.id)
            {
                out.push(previous);
            }
        }

        let preferences = self.load_preferences();
        if !preferences.enabled_sources.is_empty() {
            for source in &mut out {
                source.enabled = preferences
                    .enabled_sources
                    .iter()
                    .any(|id| id == &source.definition.id);
            }
        }
        out
    }

    pub fn save_sources(&self, sources: &[SourceStatus]) -> Result<()> {
        let text = serde_json::to_string_pretty(sources)?;
        atomic_write(&self.sources_path(), text.as_bytes())
    }

    pub fn add_source(&self, mut source: SourceStatus) -> Result<Vec<SourceStatus>> {
        let mut sources = self.load_sources();
        if sources
            .iter()
            .any(|item| item.definition.id == source.definition.id)
        {
            return Err(ManagerError::Invalid(format!(
                "source '{}' already exists",
                source.definition.id
            )));
        }
        source.enabled = false;
        source.pending = true;
        sources.push(source);
        self.save_sources(&sources)?;
        Ok(sources)
    }

    pub fn remove_source(&self, id: &str) -> Result<Vec<SourceStatus>> {
        if default_sources()
            .iter()
            .any(|source| source.definition.id == id)
        {
            return Err(ManagerError::Invalid(
                "built-in sources can be disabled but not removed".into(),
            ));
        }
        let mut sources = self.load_sources();
        sources.retain(|item| item.definition.id != id);
        self.save_sources(&sources)?;
        let _ = std::fs::remove_dir_all(self.source_dir(id));
        Ok(sources)
    }

    pub fn active_yara_roots(&self, bundled: &[PathBuf]) -> Vec<PathBuf> {
        let legacy_root = self.data_dir.join("yara");
        let mut roots: Vec<PathBuf> = bundled
            .iter()
            .filter(|path| path.as_path() != legacy_root.as_path())
            .cloned()
            .collect();
        let custom = self.custom_yara_dir();
        if custom.is_dir() {
            roots.push(custom);
        }
        for source in self.load_sources() {
            if source.enabled {
                let dir = self.source_dir(&source.definition.id);
                if dir.is_dir() {
                    roots.push(dir);
                }
            }
        }
        let legacy = self.legacy_yara_dir();
        if legacy.is_dir()
            && !roots
                .iter()
                .any(|path| path == &legacy || path.starts_with(&legacy))
        {
            roots.push(legacy);
        }
        roots.sort();
        roots.dedup();
        roots
    }

    pub fn profiles(&self) -> Vec<Profile> {
        let mut profiles = default_profiles();
        profiles.extend(self.load_preferences().custom_profiles);
        profiles
    }

    pub fn apply_profile(&self, profile_id: &str) -> Result<RulePreferences> {
        let mut prefs = self.load_preferences();
        let profile = self
            .profiles()
            .into_iter()
            .find(|profile| profile.id == profile_id)
            .ok_or_else(|| ManagerError::Invalid(format!("unknown profile '{profile_id}'")))?;
        prefs.yara_enabled = true;
        prefs.signatures_enabled = true;
        prefs.disabled_yara_categories = crate::classify::YARA_CATEGORIES
            .iter()
            .map(|(id, _, _)| (*id).to_string())
            .filter(|id| !profile.yara_categories.contains(id))
            .collect();
        prefs.disabled_signature_categories = crate::classify::SIGNATURE_CATEGORIES
            .iter()
            .map(|(id, _, _)| (*id).to_string())
            .filter(|id| !profile.signature_categories.contains(id))
            .collect();
        prefs.profile = profile.id;
        self.save_preferences(&prefs)?;
        Ok(prefs)
    }

    pub fn save_custom_profile(
        &self,
        name: &str,
        description: &str,
        prefs: &RulePreferences,
    ) -> Result<RulePreferences> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ManagerError::Invalid("profile name is empty".into()));
        }
        let mut updated = self.load_preferences();
        let id = format!(
            "custom-{}",
            name.to_ascii_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>()
                .trim_matches('-')
        );
        let enabled_yara = enabled_categories(
            crate::classify::YARA_CATEGORIES,
            &prefs.disabled_yara_categories,
        );
        let enabled_signatures = enabled_categories(
            crate::classify::SIGNATURE_CATEGORIES,
            &prefs.disabled_signature_categories,
        );
        updated.custom_profiles.retain(|profile| profile.id != id);
        updated.custom_profiles.push(Profile {
            id: id.clone(),
            name: name.to_string(),
            description: description.to_string(),
            yara_categories: enabled_yara,
            signature_categories: enabled_signatures,
            builtin: false,
        });
        updated.profile = id;
        self.save_preferences(&updated)?;
        Ok(updated)
    }

    pub fn mark_false_positive(
        &self,
        rule_id: &str,
        name: &str,
        sha256: Option<&str>,
    ) -> Result<RulePreferences> {
        if rule_id.trim().is_empty() {
            return Err(ManagerError::Invalid("empty rule id".into()));
        }
        let mut prefs = self.load_preferences();
        if !prefs
            .false_positives
            .iter()
            .any(|item| item.rule_id == rule_id && item.sha256.as_deref() == sha256)
        {
            prefs.false_positives.push(FalsePositive {
                rule_id: rule_id.to_string(),
                sha256: sha256.map(str::to_string),
                name: name.to_string(),
                marked_at: now_utc(),
            });
        }
        if !prefs.disabled_yara_rules.iter().any(|item| item == rule_id) {
            prefs.disabled_yara_rules.push(rule_id.to_string());
        }
        if !prefs.disabled_signatures.iter().any(|item| item == rule_id) {
            prefs.disabled_signatures.push(rule_id.to_string());
        }
        self.save_preferences(&prefs)?;
        Ok(prefs)
    }

    pub fn import_custom_rules(&self, paths: &[PathBuf]) -> Result<ImportResult> {
        let dir = self.custom_yara_dir();
        std::fs::create_dir_all(&dir)?;
        let mut result = ImportResult::default();
        for path in paths {
            match import_one_rule(path, &dir) {
                Ok(name) => {
                    result.accepted += 1;
                    result.files.push(name);
                }
                Err(error) => {
                    result.rejected += 1;
                    result.errors.push(format!("{}: {error}", path.display()));
                }
            }
        }
        Ok(result)
    }

    pub fn export_preferences(&self, path: &Path) -> Result<()> {
        let prefs = self.load_preferences();
        let text = serde_json::to_string_pretty(&prefs)?;
        atomic_write(path, text.as_bytes())
    }

    pub fn import_preferences(&self, path: &Path) -> Result<RulePreferences> {
        let mut file = std::fs::File::open(path)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let prefs: RulePreferences = serde_json::from_str(&text)?;
        if prefs.schema != crate::model::YARA_SCHEMA {
            return Err(ManagerError::Invalid(format!(
                "unsupported preferences schema {}",
                prefs.schema
            )));
        }
        let prefs = normalize_preferences(prefs);
        self.save_preferences(&prefs)?;
        Ok(prefs)
    }

    pub fn changelog(&self) -> Vec<ChangelogEntry> {
        std::fs::read_to_string(self.changelog_path())
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<ChangelogEntry>>(&text).ok())
            .unwrap_or_default()
    }

    pub fn append_changelog(&self, entry: ChangelogEntry) -> Result<()> {
        let mut entries = self.changelog();
        entries.insert(0, entry);
        entries.truncate(500);
        atomic_write(
            &self.changelog_path(),
            serde_json::to_string_pretty(&entries)?.as_bytes(),
        )
    }

    pub fn logs(&self) -> Vec<UpdateLogEntry> {
        let Ok(text) = std::fs::read_to_string(self.logs_path()) else {
            return Vec::new();
        };
        text.lines()
            .rev()
            .filter_map(|line| serde_json::from_str::<UpdateLogEntry>(line).ok())
            .take(500)
            .collect()
    }

    pub fn append_log(&self, source_id: &str, level: &str, message: &str) -> Result<()> {
        let entry = UpdateLogEntry {
            at: now_utc(),
            source_id: source_id.to_string(),
            level: level.to_string(),
            message: message.to_string(),
        };
        let path = self.logs_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(())
    }

    pub fn record_source_check(&self, source_id: &str, version: Option<&str>, unchanged: bool) {
        let mut sources = self.load_sources();
        if let Some(source) = sources
            .iter_mut()
            .find(|item| item.definition.id == source_id)
        {
            source.last_check = Some(now_utc());
            if unchanged {
                source.pending = false;
                source.compatibility = "up_to_date".into();
            }
            if let Some(version) = version {
                source.version = Some(version.to_string());
            }
            source.errors.clear();
        }
        let _ = self.save_sources(&sources);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_source_install(
        &self,
        source_id: &str,
        version: &str,
        commit: Option<&str>,
        sha256: Option<&str>,
        imported: usize,
        accepted: usize,
        rejected: usize,
        errors: &[String],
    ) {
        let mut sources = self.load_sources();
        if let Some(source) = sources
            .iter_mut()
            .find(|item| item.definition.id == source_id)
        {
            source.last_check = Some(now_utc());
            source.last_success = Some(now_utc());
            source.version = Some(version.to_string());
            source.commit = commit.map(str::to_string);
            source.artifact_sha256 = sha256.map(str::to_string);
            source.imported = imported;
            source.accepted = accepted;
            source.rejected = rejected;
            source.compatibility = "compatible".into();
            source.errors = errors.to_vec();
            source.pending = false;
        }
        let _ = self.save_sources(&sources);
        let mut prefs = self.load_preferences();
        prefs.update.last_update = Some(now_utc());
        let _ = self.save_preferences(&prefs);
    }
}

fn default_preferences() -> RulePreferences {
    let mut prefs = RulePreferences::default();
    let sources = default_sources();
    prefs.enabled_sources = sources
        .iter()
        .filter(|source| source.enabled)
        .map(|source| source.definition.id.clone())
        .collect();
    prefs
}

fn normalize_preferences(mut prefs: RulePreferences) -> RulePreferences {
    let yara_ids = crate::classify::YARA_CATEGORIES
        .iter()
        .map(|(id, _, _)| (*id).to_string());
    let signature_ids = crate::classify::SIGNATURE_CATEGORIES
        .iter()
        .map(|(id, _, _)| (*id).to_string());
    let yara_valid: BTreeSet<String> = yara_ids.collect();
    let signature_valid: BTreeSet<String> = signature_ids.collect();
    prefs
        .disabled_yara_categories
        .retain(|id| yara_valid.contains(id));
    prefs
        .disabled_signature_categories
        .retain(|id| signature_valid.contains(id));
    prefs.disabled_yara_categories.sort();
    prefs.disabled_yara_categories.dedup();
    prefs.disabled_signature_categories.sort();
    prefs.disabled_signature_categories.dedup();
    prefs.disabled_yara_rules.sort();
    prefs.disabled_yara_rules.dedup();
    prefs.disabled_signatures.sort();
    prefs.disabled_signatures.dedup();
    prefs
        .false_positives
        .retain(|fp| !fp.rule_id.trim().is_empty());
    if prefs.update.interval_hours == 0 {
        prefs.update.interval_hours = 24;
    }
    prefs
}

fn enabled_categories(catalog: &[(&str, &str, &str)], disabled: &[String]) -> Vec<String> {
    catalog
        .iter()
        .map(|(id, _, _)| (*id).to_string())
        .filter(|id| !disabled.contains(id))
        .collect()
}

fn import_one_rule(path: &Path, target_dir: &Path) -> Result<String> {
    if !path.is_file() {
        return Err(ManagerError::Invalid("not a file".into()));
    }
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_CUSTOM_RULE_BYTES {
        return Err(ManagerError::Invalid(format!(
            "file exceeds the {} byte limit",
            MAX_CUSTOM_RULE_BYTES
        )));
    }
    let text = std::fs::read_to_string(path)?;
    YaraRuleSet::compile_source(&path.display().to_string(), &text)
        .map_err(|error| ManagerError::Yara(error.to_string()))?;
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "custom".into());
    let safe_stem: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let mut name = format!("{safe_stem}.yar");
    let mut index = 1;
    while target_dir.join(&name).exists() {
        name = format!("{safe_stem}-{index}.yar");
        index += 1;
    }
    atomic_write(&target_dir.join(&name), text.as_bytes())?;
    Ok(name)
}

fn safe_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temp, bytes)?;
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(temp, path)?;
    Ok(())
}

pub fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn status_label(status: RuleStatus) -> &'static str {
    status.label()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> (tempfile::TempDir, RuleManager) {
        let dir = tempfile::tempdir().unwrap();
        let manager = RuleManager::new(dir.path().join("data"));
        (dir, manager)
    }

    #[test]
    fn preferences_round_trip_and_normalize_unknown_categories() {
        let (_dir, manager) = manager();
        let mut prefs = manager.load_preferences();
        prefs.disabled_yara_categories.push("unknown".into());
        prefs.disabled_yara_categories.push("malware".into());
        prefs.disabled_yara_categories.push("malware".into());
        manager.save_preferences(&prefs).unwrap();
        let loaded = manager.load_preferences();
        assert_eq!(loaded.disabled_yara_categories, vec!["malware"]);
    }

    #[test]
    fn profiles_change_categories_and_preserve_individual_preferences() {
        let (_dir, manager) = manager();
        let mut prefs = manager.load_preferences();
        prefs.disabled_yara_rules.push("keep_me_off".into());
        manager.save_preferences(&prefs).unwrap();
        let applied = manager.apply_profile("networking").unwrap();
        assert_eq!(applied.profile, "networking");
        assert!(applied
            .disabled_yara_rules
            .contains(&"keep_me_off".to_string()));
        assert!(applied
            .disabled_yara_categories
            .contains(&"persistence".to_string()));
    }

    #[test]
    fn default_enabled_sources_are_included_when_the_list_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let manager = RuleManager::new(dir.path());
        let mut prefs = manager.load_preferences();
        prefs.enabled_sources.clear();
        manager.save_preferences(&prefs).unwrap();
        let source_dir = manager.source_dir("reversinglabs");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(
            source_dir.join("family.yar"),
            "rule family { condition: true }",
        )
        .unwrap();
        let roots = manager.active_yara_roots(&[]);
        assert!(roots.contains(&source_dir), "roots: {roots:?}");
    }
    #[test]
    fn custom_rule_import_validates_before_copy() {
        let (dir, manager) = manager();
        let good = dir.path().join("good.yar");
        std::fs::write(
            &good,
            "rule binscope_custom_test { condition: uint16(0) == 0x5A4D }",
        )
        .unwrap();
        let bad = dir.path().join("bad.yar");
        std::fs::write(&bad, "rule broken { condition: $missing }").unwrap();
        let result = manager
            .import_custom_rules(&[good, bad])
            .expect("import result");
        assert_eq!(result.accepted, 1);
        assert_eq!(result.rejected, 1);
        assert!(manager.custom_yara_dir().join("good.yar").is_file());
        assert!(!manager.custom_yara_dir().join("bad.yar").exists());
    }

    #[test]
    fn source_merge_keeps_new_defaults_and_user_state() {
        let (_dir, manager) = manager();
        let mut sources = manager.load_sources();
        let id = sources[0].definition.id.clone();
        sources[0].enabled = false;
        manager.save_sources(&sources).unwrap();
        let loaded = manager.load_sources();
        assert!(
            !loaded
                .iter()
                .find(|s| s.definition.id == id)
                .unwrap()
                .enabled
        );
        assert!(loaded.len() >= 10);
    }
}
