use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::AppPaths;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AppSettings {
    pub include_strings: bool,
    pub min_string_len: usize,
    pub max_strings: usize,
    pub signatures_enabled: bool,
    pub builtin_signatures: bool,
    pub signature_dirs: Vec<PathBuf>,
    pub die_enabled: bool,
    pub die_signature_dir: Option<PathBuf>,
    pub pebear_enabled: bool,
    pub pebear_sig_path: Option<PathBuf>,
    pub yara_enabled: bool,
    pub yara_rule_dirs: Vec<PathBuf>,
    pub virustotal_enabled: bool,

    pub theme: String,

    pub retain_history: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            include_strings: true,
            min_string_len: 4,
            max_strings: 100_000,
            signatures_enabled: true,
            builtin_signatures: true,
            signature_dirs: Vec::new(),
            die_enabled: true,
            die_signature_dir: None,
            pebear_enabled: false,
            pebear_sig_path: None,
            yara_enabled: true,
            yara_rule_dirs: Vec::new(),
            virustotal_enabled: false,
            theme: "system".into(),
            retain_history: true,
        }
    }
}

impl AppSettings {
    pub fn defaults(paths: &AppPaths) -> Self {
        let yara_enabled = paths.bundled_yara_dir.is_some();
        let yara_rule_dirs = paths
            .bundled_yara_dir
            .clone()
            .map(|dir| vec![dir])
            .unwrap_or_default();
        Self {
            die_signature_dir: paths.bundled_die_dir.clone(),
            pebear_sig_path: Some(paths.data_dir.join("pebear").join("SIG.txt")),
            yara_enabled,
            yara_rule_dirs,
            ..Self::default()
        }
    }

    pub fn repair_portable_paths(&mut self, paths: &AppPaths) {
        if let Some(bundled) = &paths.bundled_yara_dir {
            for dir in &mut self.yara_rule_dirs {
                if !dir.exists() {
                    *dir = bundled.clone();
                }
            }
            if self.yara_rule_dirs.is_empty() {
                self.yara_rule_dirs.push(bundled.clone());
            }
        }
        if let Some(die) = &paths.bundled_die_dir {
            if self
                .die_signature_dir
                .as_ref()
                .is_none_or(|path| !path.exists())
            {
                self.die_signature_dir = Some(die.clone());
            }
        }
        let pebear = paths.data_dir.join("pebear").join("SIG.txt");
        if self
            .pebear_sig_path
            .as_ref()
            .is_none_or(|path| !path.exists())
            && pebear.exists()
        {
            self.pebear_sig_path = Some(pebear);
        }
    }

    pub fn clamped(mut self) -> Self {
        self.min_string_len = self.min_string_len.clamp(1, 1024);
        self.max_strings = self.max_strings.clamp(1_000, 500_000);
        self.theme = normalize_theme(&self.theme);
        self.signature_dirs = sanitize_dirs(self.signature_dirs);
        self.yara_rule_dirs = sanitize_dirs(self.yara_rule_dirs);
        self
    }
}

pub fn normalize_theme(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "light" => "light".into(),
        "dark" => "dark".into(),
        _ => "system".into(),
    }
}

fn sanitize_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in dirs {
        let text = dir.to_string_lossy().trim().to_string();
        if text.is_empty() {
            continue;
        }
        let path = PathBuf::from(text);
        if !out.contains(&path) {
            out.push(path);
        }
        if out.len() >= 32 {
            break;
        }
    }
    out
}

pub fn settings_file(paths: &AppPaths) -> PathBuf {
    paths.config_dir.join("settings.json")
}

pub fn load(paths: &AppPaths) -> Result<AppSettings, String> {
    let file = settings_file(paths);
    if !file.exists() {
        return Ok(AppSettings::defaults(paths));
    }
    let text = std::fs::read_to_string(&file)
        .map_err(|e| format!("could not read {}: {e}", file.display()))?;
    let settings: AppSettings = serde_json::from_str(&text)
        .map_err(|e| format!("invalid settings file {}: {e}", file.display()))?;
    Ok(settings.clamped())
}

pub fn save(paths: &AppPaths, settings: &AppSettings) -> Result<(), String> {
    std::fs::create_dir_all(&paths.config_dir)
        .map_err(|e| format!("could not create {}: {e}", paths.config_dir.display()))?;
    let file = settings_file(paths);
    let text = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("could not serialize settings: {e}"))?;
    let temp = file.with_extension("json.tmp");
    std::fs::write(&temp, text).map_err(|e| format!("could not write {}: {e}", temp.display()))?;
    if file.exists() {
        let _ = std::fs::remove_file(&file);
    }
    std::fs::rename(&temp, &file)
        .map_err(|e| format!("could not replace {}: {e}", file.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths() -> AppPaths {
        AppPaths {
            config_dir: PathBuf::from("C:\\temp\\binscope-test"),
            data_dir: PathBuf::from("C:\\temp\\binscope-data"),
            bundled_die_dir: None,
            bundled_yara_dir: None,
            bundled_signature_dir: None,
            portable: false,
        }
    }

    #[test]
    fn clamps_limits_and_deduplicates_dirs() {
        let settings = AppSettings {
            min_string_len: 0,
            max_strings: 10,
            signature_dirs: vec![
                PathBuf::from(" C:\\rules "),
                PathBuf::from("C:\\rules"),
                PathBuf::new(),
            ],
            yara_rule_dirs: vec![PathBuf::from("C:\\yara")],
            ..Default::default()
        }
        .clamped();
        assert_eq!(settings.min_string_len, 1);
        assert_eq!(settings.max_strings, 1_000);
        assert_eq!(settings.signature_dirs, vec![PathBuf::from("C:\\rules")]);
        assert_eq!(settings.yara_rule_dirs, vec![PathBuf::from("C:\\yara")]);
    }

    #[test]
    fn defaults_disable_yara_when_no_rules_are_bundled() {
        let settings = AppSettings::defaults(&test_paths());
        assert!(!settings.yara_enabled);
        assert!(settings.yara_rule_dirs.is_empty());
    }

    #[test]
    fn settings_never_contain_api_keys() {
        let json = serde_json::to_string(&AppSettings::default()).unwrap();
        assert!(!json.to_lowercase().contains("apikey"));
        assert!(!json.to_lowercase().contains("api_key"));
        assert!(!json.to_lowercase().contains("secret"));

        assert!(json.contains("virustotalEnabled"));
    }

    #[test]
    fn rejects_unknown_fields_silently_for_forward_compatibility() {
        let json = r#"{"minStringLen": 6, "futureField": true}"#;
        let settings: AppSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.min_string_len, 6);
    }

    #[test]
    fn portable_paths_follow_a_moved_folder() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("rules/yara")).unwrap();
        std::fs::create_dir_all(root.join("databases/die")).unwrap();
        std::fs::create_dir_all(root.join("data/pebear")).unwrap();
        std::fs::write(root.join("data/pebear/SIG.txt"), "sig").unwrap();
        let paths = AppPaths {
            config_dir: root.join("data/config"),
            data_dir: root.join("data"),
            bundled_die_dir: Some(root.join("databases/die")),
            bundled_yara_dir: Some(root.join("rules/yara")),
            bundled_signature_dir: None,
            portable: true,
        };
        let mut settings = AppSettings::defaults(&paths);
        settings.yara_rule_dirs = vec![PathBuf::from("D:\\OldPortable\\rules\\yara")];
        settings.die_signature_dir = Some(PathBuf::from("D:\\OldPortable\\databases\\die"));
        settings.pebear_sig_path = Some(PathBuf::from("D:\\OldPortable\\data\\pebear\\SIG.txt"));

        settings.repair_portable_paths(&paths);

        assert_eq!(settings.yara_rule_dirs, vec![root.join("rules/yara")]);
        assert_eq!(settings.die_signature_dir, Some(root.join("databases/die")));
        assert_eq!(
            settings.pebear_sig_path,
            Some(root.join("data/pebear/SIG.txt"))
        );
    }

    #[test]
    fn portable_repair_keeps_existing_custom_paths() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom-rules");
        std::fs::create_dir_all(&custom).unwrap();
        let paths = test_paths();
        let mut settings = AppSettings {
            yara_rule_dirs: vec![custom.clone()],
            ..AppSettings::default()
        };
        settings.repair_portable_paths(&paths);
        assert_eq!(settings.yara_rule_dirs, vec![custom]);
    }
}
