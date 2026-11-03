pub mod source;

use binscope_signatures::die::load_die_directory;
use binscope_signatures::pebear::parse_pebear;
use binscope_yara::YaraRuleSet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zip::ZipArchive;

const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EXTRACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid archive: {0}")]
    Archive(String),
    #[error("download failed: {0}")]
    Network(String),
    #[error("integrity check failed: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("update validation failed: {0}")]
    Validation(String),
    #[error("update source is not available: {0}")]
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, UpdateError>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecord {
    pub source: String,
    pub version: String,
    pub updated_at: String,
    pub archive_sha256: Option<String>,
    pub files: usize,
    #[serde(default)]
    pub added: usize,
    #[serde(default)]
    pub removed: usize,
    #[serde(default)]
    pub modified: usize,
    #[serde(default)]
    pub excluded: usize,
    pub status: String,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateState {
    pub die: Option<UpdateRecord>,
    pub pebear: Option<UpdateRecord>,
    pub yara: Option<UpdateRecord>,
}

pub struct UpdateManager {
    pub data_dir: PathBuf,
}

impl UpdateManager {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    pub fn state_path(&self) -> PathBuf {
        self.data_dir.join("updates.json")
    }

    pub fn die_dir(&self) -> PathBuf {
        self.data_dir.join("die")
    }

    pub fn pebear_path(&self) -> PathBuf {
        self.data_dir.join("pebear").join("SIG.txt")
    }

    pub fn yara_dir(&self) -> PathBuf {
        self.data_dir.join("yara").join("legacy")
    }

    pub fn load_state(&self) -> UpdateState {
        fs::read_to_string(self.state_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, state: &UpdateState) -> Result<()> {
        fs::create_dir_all(&self.data_dir)?;
        let text = serde_json::to_string_pretty(state)
            .map_err(|e| UpdateError::Validation(format!("state serialization: {e}")))?;
        atomic_write(&self.state_path(), text.as_bytes())
    }

    pub fn install_die_zip(&self, zip_path: &Path, version: &str) -> Result<UpdateRecord> {
        let sha = sha256_file(zip_path)?;
        let target = self.die_dir();
        let staging = sibling_staging(&target, "die")?;
        fs::create_dir_all(&staging)?;
        let extracted = extract_zip_filtered(zip_path, &staging, |name| {
            name == "db/PE" || name.starts_with("db/PE/")
        })?;
        if extracted == 0 {
            let _ = fs::remove_dir_all(&staging);
            return Err(UpdateError::Validation(
                "archive did not contain db/PE signatures".into(),
            ));
        }

        let staged_db = staging.join("db");
        if !staged_db.join("PE").is_dir() {
            let _ = fs::remove_dir_all(&staging);
            return Err(UpdateError::Validation(
                "archive does not contain db/PE directory".into(),
            ));
        }
        let db = load_die_directory(&staged_db.join("PE"), version);
        if db.stats.compatible == 0 {
            let _ = fs::remove_dir_all(&staging);
            return Err(UpdateError::Validation(
                "DIE archive contains no signatures supported by the adapter".into(),
            ));
        }
        let manifest = serde_json::json!({
            "source": "Detect It Easy release db",
            "repository": "https://github.com/horsicq/Detect-It-Easy",
            "releaseTag": version.split('@').next().unwrap_or(version),
            "archiveSha256": sha,
            "installedAt": now_utc(),
            "releasedAt": version.split('@').nth(1).unwrap_or("unknown"),
            "fileCount": db.stats.files,
            "compatible": db.stats.compatible,
            "incompatible": db.stats.incompatible,
        });
        fs::write(
            staged_db.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)
                .map_err(|e| UpdateError::Validation(e.to_string()))?,
        )?;

        let live_pe = target.join("PE");
        let staged_pe = staged_db.join("PE");
        let old_files = hash_files(&live_pe, "sg");
        let new_files = hash_files(&staged_pe, "sg");
        let (added, removed, modified) = diff_counts(&old_files, &new_files);
        fs::create_dir_all(&target)?;
        replace_directory(&staged_pe, &live_pe)?;
        atomic_write(
            &target.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)
                .map_err(|e| UpdateError::Validation(e.to_string()))?
                .as_slice(),
        )?;
        if staged_db.join("LICENSE").is_file() {
            let _ = fs::copy(staged_db.join("LICENSE"), target.join("LICENSE"));
        }
        let _ = fs::remove_dir_all(&staging);
        let record = UpdateRecord {
            source: "DIE db release".into(),
            version: version.to_string(),
            updated_at: now_utc(),
            archive_sha256: Some(sha),
            files: db.stats.files,
            added,
            removed,
            modified,
            excluded: db.stats.incompatible,
            status: "installed".into(),
            message: Some(format!(
                "{} compatible / {} incompatible signatures",
                db.stats.compatible, db.stats.incompatible
            )),
        };
        self.record("die", record.clone())?;
        Ok(record)
    }

    pub fn install_pebear_sig(&self, text: &str, version: &str) -> Result<UpdateRecord> {
        let db = parse_pebear(text);
        if db.signatures.len() < 100 {
            return Err(UpdateError::Validation(format!(
                "only {} valid PE-bear signatures found; refusing to activate",
                db.signatures.len()
            )));
        }
        let target = self.pebear_path();
        let old_text = fs::read_to_string(&target).ok();
        let old_hash = old_text.as_ref().map(|t| hex_sha256(t.as_bytes()));
        let new_hash = hex_sha256(text.as_bytes());
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(&target, text.as_bytes())?;
        let meta = serde_json::json!({
            "source": "PE-bear SIG.txt (PEiD UserDB)",
            "repository": "https://github.com/hasherezade/pe-bear",
            "commit": version,
            "installedAt": now_utc(),
            "signatures": db.signatures.len(),
            "skipped": db.skipped,
            "license": "GPLv2",
            "sha256": hex_sha256(text.as_bytes()),
        });
        atomic_write(
            &target.with_extension("json"),
            serde_json::to_vec_pretty(&meta)
                .map_err(|e| UpdateError::Validation(e.to_string()))?
                .as_slice(),
        )?;
        let record = UpdateRecord {
            source: "PE-bear SIG.txt".into(),
            version: version.to_string(),
            updated_at: now_utc(),
            archive_sha256: Some(hex_sha256(text.as_bytes())),
            files: db.signatures.len(),
            added: usize::from(old_text.is_none()),
            removed: 0,
            modified: usize::from(old_hash.as_ref().is_some_and(|h| h != &new_hash)),
            excluded: db.skipped,
            status: "installed".into(),
            message: Some(format!(
                "{} signatures, {} skipped",
                db.signatures.len(),
                db.skipped
            )),
        };
        self.record("pebear", record.clone())?;
        Ok(record)
    }

    pub fn install_yara_zip(&self, zip_path: &Path, version: &str) -> Result<UpdateRecord> {
        let sha = sha256_file(zip_path)?;
        let target = self.yara_dir();
        let staging = sibling_staging(&target, "yara")?;
        fs::create_dir_all(&staging)?;
        let extracted = extract_zip_filtered(zip_path, &staging, |name| {
            name.ends_with(".yar") || name.ends_with(".yara")
        })?;
        if extracted == 0 {
            let _ = fs::remove_dir_all(&staging);
            return Err(UpdateError::Validation(
                "archive contains no .yar/.yara files".into(),
            ));
        }
        let rules = YaraRuleSet::compile_dir(&staging)
            .map_err(|e| UpdateError::Validation(format!("YARA compilation failed: {e}")))?;
        if !rules.report.errors.is_empty() {
            let detail = rules
                .report
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.source, e.message))
                .collect::<Vec<_>>()
                .join("; ");
            let _ = fs::remove_dir_all(&staging);
            return Err(UpdateError::Validation(format!(
                "new rules failed to compile: {detail}"
            )));
        }
        let count = rules.rule_count();
        let mut old_rules = hash_files(&target, "yar");
        old_rules.extend(hash_files(&target, "yara"));
        let mut new_rules = hash_files(&staging, "yar");
        new_rules.extend(hash_files(&staging, "yara"));
        let (added, removed, modified) = diff_counts(&old_rules, &new_rules);
        replace_directory(&staging, &target)?;
        let meta = serde_json::json!({
            "source": "configured YARA source",
            "version": version,
            "installedAt": now_utc(),
            "rules": count,
            "sha256": sha,
        });
        atomic_write(
            &target.join("manifest.json"),
            serde_json::to_vec_pretty(&meta)
                .map_err(|e| UpdateError::Validation(e.to_string()))?
                .as_slice(),
        )?;
        let record = UpdateRecord {
            source: "YARA rules".into(),
            version: version.to_string(),
            updated_at: now_utc(),
            archive_sha256: Some(sha),
            files: count,
            added,
            removed,
            modified,
            excluded: 0,
            status: "installed".into(),
            message: Some(format!("{count} rules compiled")),
        };
        self.record("yara", record.clone())?;
        Ok(record)
    }

    fn record(&self, which: &str, record: UpdateRecord) -> Result<()> {
        let mut state = self.load_state();
        match which {
            "die" => state.die = Some(record),
            "pebear" => state.pebear = Some(record),
            "yara" => state.yara = Some(record),
            _ => return Err(UpdateError::Validation("unknown update target".into())),
        }
        self.save_state(&state)
    }
}

pub fn download(url: &str, expected_sha256: Option<&str>) -> Result<Vec<u8>> {
    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .get(url)
        .header(
            "User-Agent",
            concat!("BinScope/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .map_err(|e| UpdateError::Network(e.to_string()))?;
    if !response.status().is_success() {
        return Err(UpdateError::Network(format!(
            "HTTP {} from {url}",
            response.status()
        )));
    }
    if let Some(length) = response.content_length() {
        if length > MAX_ARCHIVE_BYTES {
            return Err(UpdateError::Validation(
                "download Content-Length exceeds size limit".into(),
            ));
        }
    }
    let bytes = response
        .bytes()
        .map_err(|e| UpdateError::Network(e.to_string()))?;
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(UpdateError::Validation(
            "download exceeds size limit".into(),
        ));
    }
    if let Some(expected) = expected_sha256 {
        let actual = hex_sha256(&bytes);
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(UpdateError::HashMismatch {
                expected: expected.to_string(),
                actual,
            });
        }
    }
    Ok(bytes.to_vec())
}

fn extract_zip_filtered(
    zip_path: &Path,
    staging: &Path,
    keep: impl Fn(&str) -> bool,
) -> Result<usize> {
    let file = File::open(zip_path)?;
    let meta = file.metadata()?;
    if meta.len() > MAX_ARCHIVE_BYTES {
        return Err(UpdateError::Archive("archive exceeds size limit".into()));
    }
    let mut archive = ZipArchive::new(file).map_err(|e| UpdateError::Archive(e.to_string()))?;
    if archive.len() > MAX_ENTRIES {
        return Err(UpdateError::Archive("too many archive entries".into()));
    }
    let mut count = 0;
    let mut total_bytes: u64 = 0;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UpdateError::Archive(e.to_string()))?;
        let Some(name) = entry
            .enclosed_name()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
        else {
            return Err(UpdateError::Archive(format!(
                "unsafe archive path at entry {i}"
            )));
        };
        if !keep(&name) {
            continue;
        }
        if entry.is_dir() {
            continue;
        }
        if let Some(mode) = entry.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                return Err(UpdateError::Archive(format!(
                    "symbolic link entry rejected: {name}"
                )));
            }
        }
        if entry.size() > MAX_ENTRY_BYTES {
            return Err(UpdateError::Archive(format!("entry too large: {name}")));
        }
        let relative = sanitize_relative(&name)?;
        let destination = staging.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = File::create(&destination)?;
        let written = std::io::copy(&mut entry, &mut out)?;
        if written != entry.size() {
            return Err(UpdateError::Archive(format!(
                "short read while extracting {name}"
            )));
        }
        total_bytes = total_bytes.saturating_add(written);
        if total_bytes > MAX_EXTRACT_BYTES {
            return Err(UpdateError::Archive(
                "archive extracts beyond the configured size limit".into(),
            ));
        }
        count += 1;
    }
    Ok(count)
}

fn sanitize_relative(name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            _ => {
                return Err(UpdateError::Archive(format!(
                    "path traversal or absolute path rejected: {name}"
                )))
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(UpdateError::Archive("empty archive path".into()));
    }
    Ok(out)
}

fn replace_directory(new: &Path, live: &Path) -> Result<()> {
    let backup = live.with_extension(format!("backup-{}", std::process::id()));
    let had_live = live.exists();
    if had_live {
        if backup.exists() {
            fs::remove_dir_all(&backup)?;
        }
        fs::rename(live, &backup)?;
    }
    if let Err(e) = fs::rename(new, live) {
        if had_live {
            let _ = fs::rename(&backup, live);
        }
        return Err(UpdateError::Io(e));
    }
    if had_live {
        let _ = fs::remove_dir_all(&backup);
    }
    Ok(())
}

fn hash_files(dir: &Path, extension: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    fn walk(
        dir: &Path,
        root: &Path,
        extension: &str,
        out: &mut std::collections::BTreeMap<String, String>,
    ) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                walk(&path, root, extension, out);
                continue;
            }
            if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case(extension))
            {
                let key = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if let Ok(hash) = sha256_file(&path) {
                    out.insert(key, hash);
                }
            }
            if out.len() > 20_000 {
                return;
            }
        }
    }
    walk(dir, dir, extension, &mut out);
    out
}

fn diff_counts(
    old: &std::collections::BTreeMap<String, String>,
    new: &std::collections::BTreeMap<String, String>,
) -> (usize, usize, usize) {
    let added = new.keys().filter(|k| !old.contains_key(*k)).count();
    let removed = old.keys().filter(|k| !new.contains_key(*k)).count();
    let modified = old
        .iter()
        .filter(|(k, v)| new.get(*k).is_some_and(|n| n != *v))
        .count();
    (added, removed, modified)
}

fn sibling_staging(target: &Path, label: &str) -> Result<PathBuf> {
    let parent = target
        .parent()
        .ok_or_else(|| UpdateError::Validation("target has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let path = parent.join(format!(
        ".{label}-staging-{}-{}",
        std::process::id(),
        now_utc().replace([':', '-'], "")
    ));
    if path.exists() {
        fs::remove_dir_all(&path)?;
    }
    Ok(path)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&temp, path)?;
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub const DIE_DB_URL: &str =
    "https://github.com/horsicq/Detect-It-Easy/releases/download/db/db.zip";

pub const DIE_DB_SHA256: &str = "6c16af091b984e74b782bfe74a880cf95bc9a34043a18191616ce15c8862cebd";
pub const DIE_DB_VERSION: &str = "db@2026-04-16";
pub const DIE_RELEASE_API: &str =
    "https://api.github.com/repos/horsicq/Detect-It-Easy/releases/tags/db";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DieRelease {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

pub fn fetch_die_release() -> Result<DieRelease> {
    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .get(DIE_RELEASE_API)
        .header(
            "User-Agent",
            concat!("BinScope/", env!("CARGO_PKG_VERSION")),
        )
        .header("Accept", "application/vnd.github+json")
        .send()
        .map_err(|e| UpdateError::Network(e.to_string()))?;
    if !response.status().is_success() {
        return Err(UpdateError::Network(format!(
            "GitHub release API returned HTTP {}",
            response.status()
        )));
    }
    let value: serde_json::Value = response
        .json()
        .map_err(|e| UpdateError::Network(format!("invalid release metadata: {e}")))?;
    parse_die_release(&value)
}

pub fn parse_die_release(value: &serde_json::Value) -> Result<DieRelease> {
    let tag = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("db");
    let published = value
        .get("published_at")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let asset = value
        .get("assets")
        .and_then(|v| v.as_array())
        .and_then(|assets| {
            assets
                .iter()
                .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("db.zip"))
        })
        .ok_or_else(|| UpdateError::Unavailable("db.zip asset not found".into()))?;
    let url = asset
        .get("browser_download_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| UpdateError::Unavailable("db.zip URL missing".into()))?;
    let digest = asset
        .get("digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            UpdateError::Validation(
                "release metadata does not provide a SHA-256 digest for db.zip".into(),
            )
        })?;
    let sha256 = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| UpdateError::Validation("unsupported digest algorithm".into()))?;
    Ok(DieRelease {
        version: format!("{tag}@{published}"),
        url: url.to_string(),
        sha256: sha256.to_ascii_lowercase(),
    })
}

pub const PEBEAR_SIG_URL: &str =
    "https://raw.githubusercontent.com/hasherezade/pe-bear/b90f1d7d96635e7a029f424a0d1d11a104821685/SIG.txt";

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn zip_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for (name, data) in entries {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("evil.zip");
        zip_with_entries(&zip_path, &[("../evil.sg", b"x")]);
        let manager = UpdateManager::new(dir.path().join("data"));
        let err = manager.install_die_zip(&zip_path, "test").unwrap_err();
        assert!(
            err.to_string().contains("path traversal")
                || err.to_string().contains("unsafe")
                || err.to_string().contains("not contain")
                || err.to_string().contains("did not contain")
        );
    }

    #[test]
    fn die_install_is_atomic_and_validates_content() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("db.zip");
        let sample = b"meta(\"packer\", \"X\");\nfunction detect(){ if (PE.compareEP(\"60E8AABBCCDDEEFF00112233\")) { bDetected=true; } return result(); }\n";
        zip_with_entries(&zip_path, &[("db/PE/packer_X.2.sg", sample)]);
        let manager = UpdateManager::new(dir.path().join("data"));
        let record = manager.install_die_zip(&zip_path, "test").unwrap();
        assert_eq!(record.files, 1);
        assert!(manager.die_dir().join("PE").is_dir());
        assert!(manager.die_dir().join("manifest.json").is_file());
        assert!(manager.load_state().die.unwrap().status == "installed");
    }

    #[test]
    fn failed_die_validation_keeps_previous_database() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().join("data"));
        let good = manager.die_dir().join("PE");
        fs::create_dir_all(&good).unwrap();
        fs::write(good.join("keep.sg"), b"old").unwrap();
        let zip_path = dir.path().join("empty.zip");
        zip_with_entries(&zip_path, &[("README.txt", b"no signatures")]);
        assert!(manager.install_die_zip(&zip_path, "bad").is_err());
        assert!(good.join("keep.sg").is_file());
    }

    #[test]
    fn pebear_requires_a_plausible_database() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().join("data"));
        assert!(manager
            .install_pebear_sig("A\n12\n60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 00\n", "test")
            .is_err());
    }

    #[test]
    fn yara_install_compiles_before_activation() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().join("data"));
        let zip_path = dir.path().join("rules.zip");
        zip_with_entries(
            &zip_path,
            &[(
                "rules/test.yar",
                b"rule binscope_update_test { condition: uint16(0) == 0x5A4D }",
            )],
        );
        let record = manager.install_yara_zip(&zip_path, "test").unwrap();
        assert_eq!(record.files, 1);
        assert!(manager.yara_dir().join("manifest.json").is_file());
    }

    #[test]
    fn invalid_yara_archive_is_rejected_without_activation() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().join("data"));
        let zip_path = dir.path().join("bad.zip");
        zip_with_entries(
            &zip_path,
            &[("bad.yar", b"rule broken { condition: $missing }")],
        );
        assert!(manager.install_yara_zip(&zip_path, "test").is_err());
        assert!(!manager.yara_dir().exists());
    }

    #[test]
    fn parses_die_release_metadata() {
        let value = serde_json::json!({
            "tag_name": "db",
            "published_at": "2026-04-16T14:23:53Z",
            "assets": [{
                "name": "db.zip",
                "browser_download_url": "https://example.invalid/db.zip",
                "digest": "sha256:6c16af091b984e74b782bfe74a880cf95bc9a34043a18191616ce15c8862cebd"
            }]
        });
        let release = parse_die_release(&value).unwrap();
        assert_eq!(release.version, "db@2026-04-16T14:23:53Z");
        assert!(release.url.ends_with("db.zip"));
        assert_eq!(release.sha256.len(), 64);
        let missing = serde_json::json!({"tag_name":"db","assets":[]});
        assert!(parse_die_release(&missing).is_err());
    }

    #[test]
    fn hashes_are_stable() {
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
