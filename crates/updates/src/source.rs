use binscope_rules::{now_utc, RuleManager, SourceDefinition, SourceStatus, SourceUpdateResult};
use binscope_yara::YaraRuleSet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;
use zip::ZipArchive;

const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXTRACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RULE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 5000;
const MAX_RULE_FILES: usize = 2048;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceVersion {
    pub version: String,
    pub commit: Option<String>,
    pub url: String,
    pub artifact_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchedSource {
    pub version: SourceVersion,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub fn fetch_source_version(source: &SourceStatus) -> Result<SourceVersion, String> {
    match source.definition.method.as_str() {
        "github_archive" => {
            let repo = source
                .definition
                .repo
                .as_deref()
                .ok_or_else(|| "source has no GitHub repository".to_string())?;
            let branch = source.definition.branch.as_deref().unwrap_or("main");
            let commit = github_json(&format!(
                "https://api.github.com/repos/{repo}/commits/{branch}"
            ))?;
            let sha = commit
                .get("sha")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "GitHub commit response has no sha".to_string())?;
            Ok(SourceVersion {
                version: sha.to_string(),
                commit: Some(sha.to_string()),
                url: format!("https://codeload.github.com/{repo}/zip/{sha}"),
                artifact_sha256: None,
            })
        }
        "github_release_zip" => {
            let repo = source
                .definition
                .repo
                .as_deref()
                .ok_or_else(|| "source has no GitHub repository".to_string())?;
            let release = github_json(&format!(
                "https://api.github.com/repos/{repo}/releases/latest"
            ))?;
            let tag = release
                .get("tag_name")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "release has no tag".to_string())?;
            let asset_name = source
                .definition
                .asset
                .as_deref()
                .ok_or_else(|| "release source has no asset name".to_string())?;
            let asset = release
                .get("assets")
                .and_then(|value| value.as_array())
                .and_then(|assets| {
                    assets.iter().find(|asset| {
                        asset.get("name").and_then(|name| name.as_str()) == Some(asset_name)
                    })
                })
                .ok_or_else(|| format!("release has no asset '{asset_name}'"))?;
            let url = asset
                .get("browser_download_url")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "asset has no download URL".to_string())?;
            let digest = asset
                .get("digest")
                .and_then(|value| value.as_str())
                .and_then(|value| value.strip_prefix("sha256:"))
                .map(|value| value.to_ascii_lowercase());
            Ok(SourceVersion {
                version: tag.to_string(),
                commit: None,
                url: url.to_string(),
                artifact_sha256: digest,
            })
        }
        other => Err(format!("source method '{other}' is not implemented")),
    }
}

pub fn download_source(source: &SourceStatus) -> Result<FetchedSource, String> {
    let version = fetch_source_version(source)?;
    let bytes = download_bytes(&version.url, MAX_ARCHIVE_BYTES)?;
    let sha256 = hex_sha256(&bytes);
    if let Some(expected) = &version.artifact_sha256 {
        if !sha256.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "artifact hash mismatch: expected {expected}, got {sha256}"
            ));
        }
    }
    Ok(FetchedSource {
        version,
        bytes,
        sha256,
    })
}

pub fn update_source(
    manager: &RuleManager,
    source: &SourceStatus,
) -> Result<SourceUpdateResult, String> {
    let fetched = download_source(source)?;
    manager
        .append_log(
            &source.definition.id,
            "info",
            &format!(
                "downloaded {} bytes for version {}",
                fetched.bytes.len(),
                fetched.version.version
            ),
        )
        .map_err(|error| error.to_string())?;
    let result = install_source_bytes(
        manager,
        &source.definition,
        &fetched.bytes,
        &fetched.version,
        &fetched.sha256,
    )?;
    manager.record_source_install(
        &source.definition.id,
        &fetched.version.version,
        fetched.version.commit.as_deref(),
        Some(&fetched.sha256),
        result.installed,
        result.accepted,
        result.rejected,
        &result.errors,
    );
    manager
        .append_log(
            &source.definition.id,
            "info",
            &format!(
                "installed {} rules ({} rejected)",
                result.accepted, result.rejected
            ),
        )
        .map_err(|error| error.to_string())?;
    Ok(result.result)
}

#[derive(Clone, Debug, Default)]
pub struct InstallOutcome {
    pub installed: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub errors: Vec<String>,
    pub result: SourceUpdateResult,
}

pub fn install_source_bytes(
    manager: &RuleManager,
    definition: &SourceDefinition,
    bytes: &[u8],
    version: &SourceVersion,
    sha256: &str,
) -> Result<InstallOutcome, String> {
    let temp_dir = manager.data_dir.join("rules").join("tmp");
    fs::create_dir_all(&temp_dir).map_err(|error| error.to_string())?;
    let zip_path = temp_dir.join(format!(
        "{}-{}.zip",
        sanitize(&definition.id),
        std::process::id()
    ));
    fs::write(&zip_path, bytes).map_err(|error| error.to_string())?;
    let result = install_source_zip(
        manager,
        definition,
        &zip_path,
        &version.version,
        version.commit.as_deref(),
        sha256,
    );
    let _ = fs::remove_file(&zip_path);
    result
}

fn install_source_zip(
    manager: &RuleManager,
    definition: &SourceDefinition,
    zip_path: &Path,
    version: &str,
    commit: Option<&str>,
    sha256: &str,
) -> Result<InstallOutcome, String> {
    let target = manager.source_dir(&definition.id);
    let parent = target
        .parent()
        .ok_or_else(|| "source target has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let staging = parent.join(format!(
        ".{}-staging-{}",
        sanitize(&definition.id),
        std::process::id()
    ));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|error| error.to_string())?;
    }
    fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    extract_rule_files(zip_path, &staging, &definition.include_prefixes)?;
    flatten_single_root(&staging)?;

    let (mut rejected_files, mut validation_errors) = quarantine_invalid(&staging)?;
    let rules = YaraRuleSet::compile_dir(&staging).map_err(|error| {
        let _ = fs::remove_dir_all(&staging);
        format!("staging compilation failed: {error}")
    })?;
    if rules.rule_count() == 0 {
        let _ = fs::remove_dir_all(&staging);
        return Err("source contains no valid YARA rules".into());
    }

    if !rules.report.errors.is_empty() {
        let mut removed = Vec::new();
        for error in &rules.report.errors {
            let path = PathBuf::from(&error.source);
            if path.starts_with(&staging) && path.is_file() {
                removed.push(path);
            }
        }
        for path in removed {
            let _ = fs::remove_file(path);
        }
        rejected_files += rules.report.errors.len();
        validation_errors.extend(
            rules
                .report
                .errors
                .iter()
                .map(|error| format!("{}: {}", error.source, error.message)),
        );
        let recheck = YaraRuleSet::compile_dir(&staging)
            .map_err(|error| format!("staging recompilation failed: {error}"))?;
        if recheck.rule_count() == 0 {
            let _ = fs::remove_dir_all(&staging);
            return Err("all rules in the source failed validation".into());
        }
    }
    let accepted_rules = YaraRuleSet::compile_dir(&staging)
        .map(|rules| rules.rule_count())
        .unwrap_or(0);
    if accepted_rules == 0 {
        let _ = fs::remove_dir_all(&staging);
        return Err("source contains no valid YARA rules".into());
    }
    let manifest = serde_json::json!({
        "source": definition.id,
        "version": version,
        "commit": commit,
        "sha256": sha256,
        "installedAt": now_utc(),
        "rules": accepted_rules,
        "rejectedFiles": rejected_files,
    });
    fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    replace_directory(&staging, &target)?;
    let outcome = SourceUpdateResult {
        source_id: definition.id.clone(),
        status: "installed".into(),
        version: Some(version.to_string()),
        accepted: accepted_rules,
        rejected: rejected_files,
        message: format!("{accepted_rules} rules active; {rejected_files} invalid files removed"),
    };
    Ok(InstallOutcome {
        installed: accepted_rules,
        accepted: accepted_rules,
        rejected: rejected_files,
        errors: validation_errors,
        result: outcome,
    })
}

fn extract_rule_files(zip_path: &Path, staging: &Path, prefixes: &[String]) -> Result<(), String> {
    let file = File::open(zip_path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if metadata.len() > MAX_ARCHIVE_BYTES {
        return Err("archive exceeds the size limit".into());
    }
    let mut archive = ZipArchive::new(file).map_err(|error| error.to_string())?;
    if archive.len() > MAX_ENTRIES {
        return Err("archive has too many entries".into());
    }
    let mut total = 0u64;
    let mut files = 0usize;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| error.to_string())?;
        let Some(name) = entry
            .enclosed_name()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
        else {
            return Err("unsafe archive path".into());
        };
        if !is_rule_path(&name) {
            continue;
        }
        if !prefixes.is_empty()
            && !prefixes.iter().any(|prefix| {
                let prefix = prefix.trim_matches('/');
                let normalized = normalize_archive_path(&name);
                let without_root = normalized
                    .split_once('/')
                    .map(|(_, rest)| rest)
                    .unwrap_or(normalized.as_str());
                normalized.starts_with(prefix) || without_root.starts_with(prefix)
            })
        {
            continue;
        }
        if let Some(mode) = entry.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                return Err("symbolic link in archive".into());
            }
        }
        if entry.size() > MAX_RULE_BYTES {
            return Err(format!("rule file too large: {name}"));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_EXTRACT_BYTES {
            return Err("extracted rules exceed the size limit".into());
        }
        files += 1;
        if files > MAX_RULE_FILES {
            return Err("archive contains too many rule files".into());
        }
        let relative = sanitize_archive_path(&name)?;
        let destination = staging.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut out = File::create(&destination).map_err(|error| error.to_string())?;
        std::io::copy(&mut entry, &mut out).map_err(|error| error.to_string())?;
    }
    if files == 0 {
        return Err("archive contains no .yar/.yara files".into());
    }
    Ok(())
}

fn quarantine_invalid(dir: &Path) -> Result<(usize, Vec<String>), String> {
    let rules = YaraRuleSet::compile_dir(dir)
        .map_err(|error| format!("staging compilation failed: {error}"))?;
    if rules.report.errors.is_empty() {
        return Ok((0, Vec::new()));
    }
    let mut rejected = 0;
    let mut messages = Vec::new();
    for error in &rules.report.errors {
        let path = PathBuf::from(&error.source);
        messages.push(format!("{}: {}", error.source, error.message));
        if path.starts_with(dir) && path.is_file() && fs::remove_file(&path).is_ok() {
            rejected += 1;
        }
    }
    Ok((rejected, messages))
}

fn flatten_single_root(staging: &Path) -> Result<(), String> {
    let entries: Vec<PathBuf> = fs::read_dir(staging)
        .map_err(|error| error.to_string())?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    if entries.len() != 1 || !entries[0].is_dir() {
        return Ok(());
    }
    let root = &entries[0];
    let children: Vec<PathBuf> = fs::read_dir(root)
        .map_err(|error| error.to_string())?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    for child in children {
        let name = child
            .file_name()
            .ok_or_else(|| "invalid source path".to_string())?;
        let destination = staging.join(name);
        if destination.exists() {
            return Err("source archive has colliding top-level paths".into());
        }
        fs::rename(&child, &destination).map_err(|error| error.to_string())?;
    }
    let _ = fs::remove_dir(root);
    Ok(())
}

fn is_rule_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".yar") || lower.ends_with(".yara")
}

fn normalize_archive_path(name: &str) -> String {
    let name = name.replace('\\', "/");
    name.trim_start_matches('/').to_string()
}

fn sanitize_archive_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            _ => return Err(format!("path traversal rejected: {name}")),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("empty archive path".into());
    }
    Ok(out)
}

fn replace_directory(new: &Path, live: &Path) -> Result<(), String> {
    let backup = live.with_extension(format!("backup-{}", std::process::id()));
    let had_live = live.exists();
    if had_live {
        if backup.exists() {
            fs::remove_dir_all(&backup).map_err(|error| error.to_string())?;
        }
        fs::rename(live, &backup).map_err(|error| error.to_string())?;
    }
    if let Err(error) = fs::rename(new, live) {
        if had_live {
            let _ = fs::rename(&backup, live);
        }
        return Err(error.to_string());
    }
    if had_live {
        let _ = fs::remove_dir_all(&backup);
    }
    Ok(())
}

fn download_bytes(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") {
        return Err("only HTTPS downloads are accepted".into());
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|error| error.to_string())?;
    let mut last_error = String::new();
    for attempt in 0..3 {
        let response = client
            .get(url)
            .header(
                "User-Agent",
                concat!("BinScope/", env!("CARGO_PKG_VERSION")),
            )
            .send();
        match response {
            Ok(response) if response.status().is_success() => {
                if let Some(length) = response.content_length() {
                    if length > limit {
                        return Err("download exceeds the size limit".into());
                    }
                }
                let bytes = response
                    .bytes()
                    .map_err(|error| format!("download failed: {error}"))?;
                if bytes.len() as u64 > limit {
                    return Err("download exceeds the size limit".into());
                }
                return Ok(bytes.to_vec());
            }
            Ok(response) => {
                let status = response.status();
                last_error = format!("HTTP {status} from {url}");
                if status.as_u16() == 429 || status.as_u16() == 403 {
                    sleep(Duration::from_secs(2 + attempt as u64 * 2));
                }
            }
            Err(error) => last_error = error.to_string(),
        }
        sleep(Duration::from_secs(1 + attempt as u64 * 2));
    }
    Err(last_error)
}

fn github_json(url: &str) -> Result<serde_json::Value, String> {
    let bytes = download_bytes(url, 4 * 1024 * 1024)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid GitHub JSON: {error}"))
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use binscope_rules::SourceDefinition;
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    fn definition() -> SourceDefinition {
        SourceDefinition {
            id: "test-source".into(),
            name: "Test source".into(),
            url: "https://example.invalid".into(),
            kind: "yara".into(),
            method: "github_archive".into(),
            repo: Some("owner/repo".into()),
            branch: Some("main".into()),
            asset: None,
            include_prefixes: Vec::new(),
            license: Some("MIT".into()),
            license_url: None,
            default_enabled: false,
            implemented: true,
            notes: String::new(),
        }
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            for (name, bytes) in entries {
                writer
                    .start_file(*name, SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut writer, bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn version() -> SourceVersion {
        SourceVersion {
            version: "abc123".into(),
            commit: Some("abc123".into()),
            url: "https://example.invalid/archive.zip".into(),
            artifact_sha256: None,
        }
    }

    #[test]
    fn install_keeps_valid_rules_and_removes_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let manager = RuleManager::new(dir.path().join("data"));
        let bytes = zip_bytes(&[
            (
                "repo-abc/rules/good.yar",
                b"rule good_rule { condition: uint16(0) == 0x5A4D }",
            ),
            (
                "repo-abc/rules/bad.yar",
                b"rule bad_rule { condition: $missing }",
            ),
        ]);
        let outcome =
            install_source_bytes(&manager, &definition(), &bytes, &version(), "sha").unwrap();
        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.rejected, 1);
        assert!(manager
            .source_dir("test-source")
            .join("rules/good.yar")
            .is_file());
        assert!(!manager
            .source_dir("test-source")
            .join("rules/bad.yar")
            .exists());
    }

    #[test]
    fn invalid_update_keeps_previous_source() {
        let dir = tempfile::tempdir().unwrap();
        let manager = RuleManager::new(dir.path().join("data"));
        let live = manager.source_dir("test-source");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("keep.yar"), "rule keep { condition: true }").unwrap();
        let bytes = zip_bytes(&[("repo-abc/bad.yar", b"rule bad { condition: $missing }")]);
        assert!(install_source_bytes(&manager, &definition(), &bytes, &version(), "sha").is_err());
        assert!(live.join("keep.yar").is_file());
    }

    #[test]
    fn path_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manager = RuleManager::new(dir.path().join("data"));
        let bytes = zip_bytes(&[("../escape.yar", b"rule escape { condition: true }")]);
        assert!(install_source_bytes(&manager, &definition(), &bytes, &version(), "sha").is_err());
        assert!(!dir
            .path()
            .join("data")
            .join("yara")
            .join("escape.yar")
            .exists());
    }

    #[test]
    fn include_prefixes_strip_the_archive_root() {
        let def = SourceDefinition {
            include_prefixes: vec!["rules/".into()],
            ..definition()
        };
        let bytes = zip_bytes(&[
            ("repo-abc/rules/keep.yar", b"rule keep { condition: true }"),
            ("repo-abc/all.yar", b"rule all_rules { condition: true }"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let manager = RuleManager::new(dir.path().join("data"));
        install_source_bytes(&manager, &def, &bytes, &version(), "sha").unwrap();
        assert!(manager
            .source_dir("test-source")
            .join("rules/keep.yar")
            .is_file());
        assert!(!manager.source_dir("test-source").join("all.yar").exists());
    }
}
