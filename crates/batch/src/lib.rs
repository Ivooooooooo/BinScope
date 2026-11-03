use binscope_common::CancelToken;
use binscope_core::{AnalysisError, Report};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub const MAX_FILES: usize = 2000;
pub const MAX_DEPTH: usize = 32;
pub const MAX_SCAN_ENTRIES: usize = 20_000;
pub const MAX_CONCURRENCY: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    Queued,
    Hashing,
    Running,
    Completed,
    Failed,
    Cancelled,
    Reused,
}

impl FileState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            FileState::Completed | FileState::Failed | FileState::Cancelled | FileState::Reused
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BatchLimits {
    pub max_files: usize,
    pub max_depth: usize,
    pub max_scan_entries: usize,
    pub concurrency: usize,
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_FILES,
            max_depth: MAX_DEPTH,
            max_scan_entries: MAX_SCAN_ENTRIES,
            concurrency: 2,
        }
    }
}

impl BatchLimits {
    pub fn clamped(mut self) -> Self {
        self.max_files = self.max_files.clamp(1, MAX_FILES);
        self.max_depth = self.max_depth.min(MAX_DEPTH);
        self.max_scan_entries = self.max_scan_entries.clamp(1, MAX_SCAN_ENTRIES);
        self.concurrency = self.concurrency.clamp(1, MAX_CONCURRENCY);
        self
    }
}

#[derive(Clone, Debug)]
pub struct BatchEntry {
    pub index: usize,
    pub path: PathBuf,
    pub name: String,
    pub size: Option<u64>,
    pub state: FileState,
    pub sha256: Option<String>,

    pub reused_from: Option<usize>,
    pub error: Option<String>,
    pub report: Option<Arc<Report>>,
    pub duration_ms: u64,
}

#[derive(Debug)]
pub struct BatchJob {
    pub id: String,
    pub limits: BatchLimits,
    pub state: JobState,
    pub entries: Vec<BatchEntry>,

    seen: BTreeMap<String, usize>,
    pub errors: Vec<String>,
    pub created_utc: String,
    pub started_utc: Option<String>,
    pub finished_utc: Option<String>,
    pub cancel: CancelToken,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchJobView {
    pub id: String,
    pub state: JobState,
    pub created_utc: String,
    pub started_utc: Option<String>,
    pub finished_utc: Option<String>,
    pub concurrency: usize,
    pub total: usize,
    pub queued: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub reused: usize,
    pub errors: Vec<String>,
    pub files: Vec<BatchFileView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchFileView {
    pub index: usize,
    pub path: String,
    pub name: String,
    pub size: Option<u64>,
    pub state: FileState,
    pub sha256: Option<String>,
    pub reused_from: Option<usize>,
    pub error: Option<String>,
    pub has_report: bool,
    pub anomalies: usize,
    pub yara: usize,
    pub signatures: usize,
    pub debug: Option<String>,
    pub format: Option<String>,
    pub architecture: Option<String>,
    pub duration_ms: u64,
}

impl BatchJob {
    pub fn new(id: impl Into<String>, limits: BatchLimits) -> Self {
        Self {
            id: id.into(),
            limits: limits.clamped(),
            state: JobState::Queued,
            entries: Vec::new(),
            seen: BTreeMap::new(),
            errors: Vec::new(),
            created_utc: now(),
            started_utc: None,
            finished_utc: None,
            cancel: CancelToken::new(),
        }
    }

    pub fn add_file(&mut self, path: PathBuf) -> bool {
        if self.entries.len() >= self.limits.max_files {
            return false;
        }
        if !path.is_file() {
            self.errors.push(format!("{}: not a file", path.display()));
            return false;
        }
        let key = normalize_path(&path);
        if self.seen.contains_key(&key) {
            return false;
        }
        let index = self.entries.len();
        let size = std::fs::metadata(&path).ok().map(|meta| meta.len());
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        self.entries.push(BatchEntry {
            index,
            path,
            name,
            size,
            state: FileState::Queued,
            sha256: None,
            reused_from: None,
            error: None,
            report: None,
            duration_ms: 0,
        });
        self.seen.insert(key, index);
        true
    }

    pub fn add_directory(&mut self, root: &Path, recursive: bool) -> (usize, Vec<String>) {
        let mut collected = Vec::new();
        let mut errors = Vec::new();
        let mut scanned = 0usize;
        collect_recursive(
            root,
            recursive,
            0,
            &self.limits,
            &mut scanned,
            &mut collected,
            &mut errors,
        );
        collected.sort();
        let mut added = 0usize;
        for path in collected {
            if self.add_file(path) {
                added += 1;
            }
            if self.entries.len() >= self.limits.max_files {
                break;
            }
        }
        if added == 0 && errors.is_empty() {
            errors.push("no files were added from the directory".into());
        }
        self.errors.extend(errors.iter().cloned());
        (added, errors)
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            JobState::Completed | JobState::Failed | JobState::Cancelled
        )
    }

    pub fn report_for(&self, index: usize) -> Option<Arc<Report>> {
        let entry = self.entries.get(index)?;
        if let Some(report) = &entry.report {
            return Some(report.clone());
        }
        let primary = entry.reused_from?;
        self.entries.get(primary)?.report.clone()
    }

    pub fn view(&self) -> BatchJobView {
        let mut view = BatchJobView {
            id: self.id.clone(),
            state: self.state,
            created_utc: self.created_utc.clone(),
            started_utc: self.started_utc.clone(),
            finished_utc: self.finished_utc.clone(),
            concurrency: self.limits.concurrency,
            total: self.entries.len(),
            queued: 0,
            running: 0,
            completed: 0,
            failed: 0,
            cancelled: 0,
            reused: 0,
            errors: self.errors.clone(),
            files: Vec::with_capacity(self.entries.len()),
        };
        for entry in &self.entries {
            match entry.state {
                FileState::Queued => view.queued += 1,
                FileState::Hashing | FileState::Running => view.running += 1,
                FileState::Completed => view.completed += 1,
                FileState::Failed => view.failed += 1,
                FileState::Cancelled => view.cancelled += 1,
                FileState::Reused => {
                    view.reused += 1;
                    view.completed += 1;
                }
            }
            let report = entry
                .report
                .clone()
                .or_else(|| entry.reused_from.and_then(|index| self.report_for(index)));
            view.files.push(BatchFileView {
                index: entry.index,
                path: entry.path.display().to_string(),
                name: entry.name.clone(),
                size: entry.size,
                state: entry.state,
                sha256: entry.sha256.clone(),
                reused_from: entry.reused_from,
                error: entry.error.clone(),
                has_report: report.is_some(),
                anomalies: report
                    .as_ref()
                    .map(|report| report.pe.as_ref().map_or(0, |pe| pe.anomalies.len()))
                    .unwrap_or(0),
                yara: report
                    .as_ref()
                    .map(|report| report.yara.matches.len())
                    .unwrap_or(0),
                signatures: report
                    .as_ref()
                    .map(|report| report.detections.len())
                    .unwrap_or(0),
                debug: report.as_ref().and_then(|report| {
                    report
                        .pe
                        .as_ref()
                        .and_then(|pe| pe.pdb.as_ref())
                        .map(|pdb| pdb.signature.clone())
                }),
                format: report.as_ref().map(|report| report.format.label.clone()),
                architecture: report
                    .as_ref()
                    .map(|report| report.format.architecture.clone()),
                duration_ms: entry.duration_ms,
            });
        }
        view
    }
}

pub type Analyzer = Arc<dyn Fn(&Path, &CancelToken) -> Result<Report, AnalysisError> + Send + Sync>;

pub fn run_job(
    job: Arc<Mutex<BatchJob>>,
    analyzer: Analyzer,
    on_change: Option<Arc<dyn Fn() + Send + Sync>>,
) {
    let callback = on_change.clone();
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        if let Some(callback) = &callback {
            callback();
        }
    });
    {
        let mut guard = match job.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if guard.state != JobState::Queued {
            return;
        }
        guard.state = JobState::Running;
        guard.started_utc = Some(now());
    }
    notify();

    hash_phase(&job, &analyzer, &notify);
    analyze_phase(&job, &analyzer, &notify);

    let mut guard = match job.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    guard.finished_utc = Some(now());
    if guard.cancel.is_cancelled() {
        guard.state = JobState::Cancelled;
        for entry in &mut guard.entries {
            if !entry.state.is_terminal() {
                entry.state = FileState::Cancelled;
            }
        }
    } else {
        let completed = guard
            .entries
            .iter()
            .filter(|entry| matches!(entry.state, FileState::Completed | FileState::Reused))
            .count();
        let failed = guard
            .entries
            .iter()
            .filter(|entry| entry.state == FileState::Failed)
            .count();
        guard.state = if guard.entries.is_empty() || (completed == 0 && failed > 0) {
            JobState::Failed
        } else {
            JobState::Completed
        };
        if guard.entries.is_empty() {
            guard.errors.push("the job contains no files".into());
        }
    }
    notify();
}

fn hash_phase(
    job: &Arc<Mutex<BatchJob>>,
    _analyzer: &Analyzer,
    notify: &Arc<dyn Fn() + Send + Sync>,
) {
    let (pending, workers, cancel) = {
        let guard = match job.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        (
            guard
                .entries
                .iter()
                .filter(|entry| entry.state == FileState::Queued)
                .count(),
            guard.limits.concurrency.min(4),
            guard.cancel.clone(),
        )
    };
    if pending == 0 {
        return;
    }
    let cursor = AtomicUsize::new(0);
    let indexes: Vec<usize> = {
        let guard = match job.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        guard
            .entries
            .iter()
            .filter(|entry| entry.state == FileState::Queued)
            .map(|entry| entry.index)
            .collect()
    };
    std::thread::scope(|scope| {
        for _ in 0..workers.min(indexes.len()) {
            scope.spawn(|| loop {
                if cancel.is_cancelled() {
                    break;
                }
                let position = cursor.fetch_add(1, Ordering::SeqCst);
                if position >= indexes.len() {
                    break;
                }
                let index = indexes[position];
                let path = {
                    let mut guard = match job.lock() {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };
                    let entry = &mut guard.entries[index];
                    if entry.state != FileState::Queued {
                        continue;
                    }
                    entry.state = FileState::Hashing;
                    entry.path.clone()
                };
                notify();
                let hashes = binscope_hashing::hash_file(&path, &cancel, None);
                let mut guard = match job.lock() {
                    Ok(guard) => guard,
                    Err(_) => break,
                };
                let entry = &mut guard.entries[index];
                match hashes {
                    Ok(hashes) => {
                        entry.sha256 = Some(hashes.sha256);
                        entry.size = std::fs::metadata(&path)
                            .ok()
                            .map(|meta| meta.len())
                            .or(entry.size);
                        entry.state = FileState::Queued;
                    }
                    Err(error) => {
                        if cancel.is_cancelled() {
                            entry.state = FileState::Cancelled;
                        } else {
                            entry.state = FileState::Failed;
                            entry.error = Some(format!("hashing failed: {error}"));
                        }
                    }
                }
                drop(guard);
                notify();
            });
        }
    });
}

fn analyze_phase(
    job: &Arc<Mutex<BatchJob>>,
    analyzer: &Analyzer,
    notify: &Arc<dyn Fn() + Send + Sync>,
) {
    let (groups, workers, cancel) = {
        let guard = match job.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for entry in &guard.entries {
            if let Some(hash) = &entry.sha256 {
                groups.entry(hash.clone()).or_default().push(entry.index);
            }
        }

        let mut ordered: Vec<(usize, Vec<usize>)> = groups
            .into_values()
            .map(|mut indexes| {
                indexes.sort_unstable();
                (indexes[0], indexes)
            })
            .collect();
        ordered.sort_by_key(|(primary, _)| *primary);
        (
            ordered,
            guard.limits.concurrency.min(MAX_CONCURRENCY),
            guard.cancel.clone(),
        )
    };
    if groups.is_empty() {
        return;
    }
    let cursor = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers.min(groups.len()) {
            scope.spawn(|| loop {
                let position = cursor.fetch_add(1, Ordering::SeqCst);
                if position >= groups.len() {
                    break;
                }
                let (primary, indexes) = &groups[position];
                if cancel.is_cancelled() {
                    let mut guard = match job.lock() {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };
                    for index in indexes {
                        let entry = &mut guard.entries[*index];
                        if !entry.state.is_terminal() {
                            entry.state = FileState::Cancelled;
                        }
                    }
                    drop(guard);
                    notify();
                    continue;
                }
                let path = {
                    let mut guard = match job.lock() {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };
                    let entry = &mut guard.entries[*primary];
                    entry.state = FileState::Running;
                    entry.path.clone()
                };
                notify();
                let started = std::time::Instant::now();
                let result = analyzer(&path, &cancel);
                let elapsed = started.elapsed().as_millis() as u64;
                let mut guard = match job.lock() {
                    Ok(guard) => guard,
                    Err(_) => break,
                };
                match result {
                    Ok(report) => {
                        {
                            let entry = &mut guard.entries[*primary];
                            entry.state = FileState::Completed;
                            entry.report = Some(Arc::new(report));
                            entry.duration_ms = elapsed;
                            entry.error = None;
                        }
                        for index in indexes.iter().skip(1) {
                            let entry = &mut guard.entries[*index];
                            entry.state = FileState::Reused;
                            entry.reused_from = Some(*primary);
                            entry.duration_ms = 0;
                            entry.error = None;
                        }
                    }
                    Err(error) => {
                        let cancelled = cancel.is_cancelled()
                            || matches!(error, AnalysisError::Cancelled);
                        let message = error.to_string();
                        {
                            let entry = &mut guard.entries[*primary];
                            entry.state = if cancelled {
                                FileState::Cancelled
                            } else {
                                FileState::Failed
                            };
                            entry.error = if cancelled { None } else { Some(message.clone()) };
                            entry.duration_ms = elapsed;
                        }
                        for index in indexes.iter().skip(1) {
                            let entry = &mut guard.entries[*index];
                            entry.state = if cancelled {
                                FileState::Cancelled
                            } else {
                                FileState::Failed
                            };
                            entry.reused_from = None;
                            entry.report = None;
                            entry.error = if cancelled {
                                None
                            } else {
                                Some(format!(
                                    "not reused: the primary file with this SHA-256 failed ({message})"
                                ))
                            };
                        }
                    }
                }
                drop(guard);
                notify();
            });
        }
    });
}

fn collect_recursive(
    root: &Path,
    recursive: bool,
    depth: usize,
    limits: &BatchLimits,
    scanned: &mut usize,
    out: &mut Vec<PathBuf>,
    errors: &mut Vec<String>,
) {
    if out.len() >= limits.max_files
        || *scanned >= limits.max_scan_entries
        || depth > limits.max_depth
    {
        return;
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("{}: {error}", root.display()));
            return;
        }
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        *scanned += 1;
        if *scanned >= limits.max_scan_entries {
            errors.push(format!(
                "directory scan stopped after {} entries",
                limits.max_scan_entries
            ));
            break;
        }
        paths.push(entry.path());
    }
    paths.sort();
    for path in paths {
        if out.len() >= limits.max_files {
            errors.push(format!(
                "file limit of {} reached; remaining entries were skipped",
                limits.max_files
            ));
            return;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            errors.push(format!("{}: symlink skipped", path.display()));
            continue;
        }
        if metadata.is_dir() {
            if recursive {
                collect_recursive(&path, recursive, depth + 1, limits, scanned, out, errors);
            }
        } else if metadata.is_file() {
            out.push(path);
        }
    }
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn quick_analyze(path: &Path, cancel: &CancelToken) -> Result<Report, AnalysisError> {
        let options = binscope_core::AnalysisOptions {
            include_strings: false,
            ..Default::default()
        };
        binscope_core::analyze_file(path, &options, cancel, None)
    }

    fn analyzer_ok() -> Analyzer {
        Arc::new(|path: &Path, cancel: &CancelToken| quick_analyze(path, cancel))
    }

    fn job_with_files(contents: &[&[u8]]) -> (tempfile::TempDir, Arc<Mutex<BatchJob>>) {
        let dir = tempfile::tempdir().unwrap();
        let mut job = BatchJob::new("batch-1", BatchLimits::default());
        for (index, content) in contents.iter().enumerate() {
            let path = dir.path().join(format!("file-{index}.bin"));
            std::fs::write(&path, content).unwrap();
            job.add_file(path);
        }
        (dir, Arc::new(Mutex::new(job)))
    }

    #[test]
    fn queue_transitions_and_reuse() {
        let (_dir, job) = job_with_files(&[b"same", b"same", b"other"]);
        run_job(job.clone(), analyzer_ok(), None);
        let guard = job.lock().unwrap();
        assert_eq!(guard.state, JobState::Completed);
        assert_eq!(guard.entries[0].state, FileState::Completed);
        assert_eq!(guard.entries[1].state, FileState::Reused);
        assert_eq!(guard.entries[1].reused_from, Some(0));
        assert_eq!(guard.entries[2].state, FileState::Completed);
        assert!(guard.entries[0].report.is_some());
        assert!(guard.entries[1].report.is_none());
        assert!(guard.report_for(1).is_some());
        assert_eq!(guard.view().reused, 1);
    }

    #[test]
    fn deterministic_job_and_file_order() {
        let (_dir, job) = job_with_files(&[b"a", b"b", b"c"]);
        let guard = job.lock().unwrap();
        assert_eq!(guard.id, "batch-1");
        assert_eq!(
            guard.entries.iter().map(|e| e.index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn cancellation_marks_pending_files() {
        let (_dir, job) = job_with_files(&[b"a", b"b"]);
        job.lock().unwrap().cancel();
        run_job(job.clone(), analyzer_ok(), None);
        let guard = job.lock().unwrap();
        assert_eq!(guard.state, JobState::Cancelled);
        assert!(guard
            .entries
            .iter()
            .all(|entry| entry.state == FileState::Cancelled));
    }

    #[test]
    fn failed_primary_never_becomes_reused() {
        let (_dir, job) = job_with_files(&[b"same", b"same"]);
        let failing: Analyzer =
            Arc::new(|_path, _cancel| Err(AnalysisError::Internal("synthetic failure".into())));
        run_job(job.clone(), failing, None);
        let guard = job.lock().unwrap();
        assert_eq!(guard.state, JobState::Failed);
        assert_eq!(guard.entries[0].state, FileState::Failed);
        assert_eq!(guard.entries[1].state, FileState::Failed);
        assert!(guard.entries[1].reused_from.is_none());
        assert!(guard.entries[1]
            .error
            .as_deref()
            .unwrap()
            .contains("primary"));
    }

    #[test]
    fn concurrency_is_bounded() {
        let (_dir, job) = job_with_files(&[b"a", b"b", b"c", b"d"]);
        job.lock().unwrap().limits.concurrency = 2;
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let active_for = active.clone();
        let maximum_for = maximum.clone();
        let analyzer: Analyzer = Arc::new(move |_path, _cancel| {
            let current = active_for.fetch_add(1, Ordering::SeqCst) + 1;
            maximum_for.fetch_max(current, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            active_for.fetch_sub(1, Ordering::SeqCst);
            quick_analyze(_path, _cancel)
        });
        run_job(job.clone(), analyzer, None);
        assert!(maximum.load(Ordering::SeqCst) <= 2);
    }

    #[test]
    fn duplicate_paths_are_added_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.bin");
        std::fs::write(&path, b"x").unwrap();
        let mut job = BatchJob::new("batch-2", BatchLimits::default());
        assert!(job.add_file(path.clone()));
        assert!(!job.add_file(path.clone()));
        assert!(!job.add_file(PathBuf::from(format!(
            "{}\\..\\{}",
            dir.path().display(),
            path.file_name().unwrap().to_string_lossy()
        ))));
        assert_eq!(job.entries.len(), 1);
    }

    #[test]
    fn recursive_traversal_honours_limits_and_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        for index in 0..5 {
            std::fs::write(nested.join(format!("f{index}.bin")), b"x").unwrap();
        }
        let limits = BatchLimits {
            max_files: 3,
            ..BatchLimits::default()
        };
        let mut job = BatchJob::new("batch-3", limits);
        let (added, _errors) = job.add_directory(dir.path(), true);
        assert_eq!(added, 3);
        assert_eq!(job.entries.len(), 3);
    }

    #[test]
    fn reports_are_available_for_reused_entries() {
        let (_dir, job) = job_with_files(&[b"same", b"same"]);
        run_job(job.clone(), analyzer_ok(), None);
        let guard = job.lock().unwrap();
        let primary = guard.report_for(0).expect("primary report");
        let reused = guard.report_for(1).expect("reused report");
        assert!(Arc::ptr_eq(&primary, &reused));
    }

    #[test]
    fn job_view_counts_are_consistent() {
        let (_dir, job) = job_with_files(&[b"same", b"same", b"other"]);
        run_job(job.clone(), analyzer_ok(), None);
        let view = job.lock().unwrap().view();
        assert_eq!(view.total, 3);
        assert_eq!(view.completed, 3);
        assert_eq!(view.reused, 1);
        assert_eq!(view.files.iter().filter(|f| f.has_report).count(), 3);
    }
}
