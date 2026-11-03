use binscope_batch::{Analyzer, BatchJob, BatchJobView, BatchLimits, JobState};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub struct BatchManager {
    jobs: Mutex<HashMap<String, Arc<Mutex<BatchJob>>>>,
    sequence: AtomicU64,
    shutting_down: AtomicBool,
}

impl Default for BatchManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchManager {
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            sequence: AtomicU64::new(0),
            shutting_down: AtomicBool::new(false),
        }
    }

    pub fn create(&self, limits: BatchLimits) -> Result<BatchJobView, String> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err("the application is shutting down".into());
        }
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let id = format!("batch-{sequence}");
        let job = Arc::new(Mutex::new(BatchJob::new(id.clone(), limits)));
        let view = job
            .lock()
            .map_err(|_| "batch state is poisoned".to_string())?
            .view();
        self.jobs
            .lock()
            .map_err(|_| "batch registry is poisoned".to_string())?
            .insert(id, job);
        Ok(view)
    }

    pub fn get(&self, id: &str) -> Result<Arc<Mutex<BatchJob>>, String> {
        self.jobs
            .lock()
            .map_err(|_| "batch registry is poisoned".to_string())?
            .get(id)
            .cloned()
            .ok_or_else(|| format!("no batch job with id '{id}'"))
    }

    pub fn add_paths(
        &self,
        id: &str,
        paths: &[String],
        recursive: bool,
    ) -> Result<BatchJobView, String> {
        if paths.len() > 50_000 {
            return Err("too many paths in one request".into());
        }
        let job = self.get(id)?;
        let mut guard = job
            .lock()
            .map_err(|_| "batch state is poisoned".to_string())?;
        if guard.state != JobState::Queued {
            return Err("files can only be added while the job is queued".into());
        }
        for raw in paths {
            let path = PathBuf::from(raw);
            if path.is_dir() {
                guard.add_directory(&path, recursive);
            } else if path.is_file() {
                guard.add_file(path);
            } else {
                guard
                    .errors
                    .push(format!("'{raw}' is not a file or directory"));
            }
        }
        Ok(guard.view())
    }

    pub fn start(&self, id: &str, analyzer: Analyzer) -> Result<(), String> {
        let job = self.get(id)?;
        {
            let guard = job
                .lock()
                .map_err(|_| "batch state is poisoned".to_string())?;
            if guard.state != JobState::Queued {
                return Err("the job has already started".into());
            }
            if guard.entries.is_empty() {
                return Err("the job contains no files".into());
            }
        }
        let thread_job = job.clone();
        std::thread::Builder::new()
            .name(format!("binscope-batch-{id}"))
            .spawn(move || {
                binscope_batch::run_job(thread_job, analyzer, None);
            })
            .map_err(|error| format!("could not start the batch worker: {error}"))?;
        Ok(())
    }

    pub fn cancel(&self, id: &str) -> Result<(), String> {
        let job = self.get(id)?;
        let guard = job
            .lock()
            .map_err(|_| "batch state is poisoned".to_string())?;
        guard.cancel();
        Ok(())
    }

    pub fn cancel_all(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        if let Ok(jobs) = self.jobs.lock() {
            for job in jobs.values() {
                if let Ok(guard) = job.lock() {
                    guard.cancel();
                }
            }
        }
    }

    pub fn view(&self, id: &str) -> Result<BatchJobView, String> {
        let job = self.get(id)?;
        job.lock()
            .map_err(|_| "batch state is poisoned".to_string())
            .map(|guard| guard.view())
    }

    pub fn list(&self) -> Vec<BatchJobView> {
        let jobs = match self.jobs.lock() {
            Ok(jobs) => jobs.values().cloned().collect::<Vec<_>>(),
            Err(_) => return Vec::new(),
        };
        let mut views: Vec<BatchJobView> = jobs
            .into_iter()
            .filter_map(|job| job.lock().ok().map(|guard| guard.view()))
            .collect();
        views.sort_by(|a, b| a.id.cmp(&b.id));
        views
    }

    pub fn report(&self, id: &str, index: usize) -> Result<binscope_core::Report, String> {
        let job = self.get(id)?;
        let guard = job
            .lock()
            .map_err(|_| "batch state is poisoned".to_string())?;
        guard
            .report_for(index)
            .map(|report| (*report).clone())
            .ok_or_else(|| format!("no report for file {index} in job '{id}'"))
    }

    pub fn clear_finished(&self) -> usize {
        let Ok(mut jobs) = self.jobs.lock() else {
            return 0;
        };
        let before = jobs.len();
        jobs.retain(|_, job| job.lock().map(|guard| !guard.is_terminal()).unwrap_or(true));
        before - jobs.len()
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| "batch registry is poisoned".to_string())?;
        if let Some(job) = jobs.get(id) {
            let terminal = job.lock().map(|guard| guard.is_terminal()).unwrap_or(false);
            if !terminal {
                return Err("cancel the job before removing it".into());
            }
        }
        jobs.remove(id);
        Ok(())
    }
}

impl Drop for BatchManager {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchClearResult {
    pub removed: usize,
    pub remaining: usize,
}
