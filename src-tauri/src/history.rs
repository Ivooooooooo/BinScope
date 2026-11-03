use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: String,
    pub analyzed_at: String,
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub size_human: String,
    pub format: String,
    pub status: String,
    pub detections: usize,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryFile {
    entries: Vec<HistoryEntry>,
}

pub fn history_path(data_dir: &Path) -> PathBuf {
    data_dir.join("history.json")
}

pub fn load(data_dir: &Path) -> Vec<HistoryEntry> {
    let Ok(text) = std::fs::read_to_string(history_path(data_dir)) else {
        return Vec::new();
    };
    serde_json::from_str::<HistoryFile>(&text)
        .map(|file| file.entries)
        .unwrap_or_default()
}

pub fn record(data_dir: &Path, entry: HistoryEntry) -> Result<(), String> {
    let mut entries = load(data_dir);
    entries.retain(|item| item.id != entry.id);
    entries.insert(0, entry);
    entries.truncate(MAX_ENTRIES);
    save(data_dir, &entries)
}

pub fn remove(data_dir: &Path, id: &str) -> Result<Vec<HistoryEntry>, String> {
    let mut entries = load(data_dir);
    entries.retain(|item| item.id != id);
    save(data_dir, &entries)?;
    Ok(entries)
}

pub fn clear(data_dir: &Path) -> Result<(), String> {
    let path = history_path(data_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("could not clear {}: {error}", path.display())),
    }
}

fn save(data_dir: &Path, entries: &[HistoryEntry]) -> Result<(), String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|error| format!("could not create {}: {error}", data_dir.display()))?;
    let path = history_path(data_dir);
    let text = serde_json::to_string_pretty(&HistoryFile {
        entries: entries.to_vec(),
    })
    .map_err(|error| format!("could not serialize history: {error}"))?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, text)
        .map_err(|error| format!("could not write {}: {error}", temp.display()))?;
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    std::fs::rename(&temp, &path)
        .map_err(|error| format!("could not replace {}: {error}", path.display()))
}

pub fn entry_id(sha256: &str, analyzed_at: &str) -> String {
    format!("{sha256}-{analyzed_at}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, at: &str) -> HistoryEntry {
        HistoryEntry {
            id: id.into(),
            analyzed_at: at.into(),
            name: "sample.exe".into(),
            path: r"C:\samples\sample.exe".into(),
            sha256: "a".repeat(64),
            size: 10,
            size_human: "10 B".into(),
            format: "PE".into(),
            status: "complete".into(),
            detections: 3,
            duration_ms: 42,
        }
    }

    #[test]
    fn records_newest_first_and_caps_entries() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..(MAX_ENTRIES + 5) {
            let id = format!("id-{index}");
            record(
                dir.path(),
                entry(&id, &format!("2026-01-01T00:00:{index:02}Z")),
            )
            .unwrap();
        }
        let entries = load(dir.path());
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(entries[0].id, format!("id-{}", MAX_ENTRIES + 4));
    }

    #[test]
    fn records_are_deduplicated_by_id() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), entry("same", "2026-01-01T00:00:00Z")).unwrap();
        record(dir.path(), entry("same", "2026-01-01T00:00:01Z")).unwrap();
        assert_eq!(load(dir.path()).len(), 1);
    }

    #[test]
    fn removal_and_clear_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), entry("a", "2026-01-01T00:00:00Z")).unwrap();
        record(dir.path(), entry("b", "2026-01-01T00:00:01Z")).unwrap();
        let left = remove(dir.path(), "a").unwrap();
        assert_eq!(left.len(), 1);
        assert!(remove(dir.path(), "missing").unwrap().len() == 1);
        clear(dir.path()).unwrap();
        clear(dir.path()).unwrap();
        assert!(load(dir.path()).is_empty());
    }

    #[test]
    fn corrupt_history_is_reported_as_empty_and_recovered_on_write() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(history_path(dir.path()), "{not json").unwrap();
        assert!(load(dir.path()).is_empty());
        record(dir.path(), entry("a", "2026-01-01T00:00:00Z")).unwrap();
        assert_eq!(load(dir.path()).len(), 1);
    }
}
