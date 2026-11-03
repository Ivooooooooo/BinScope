mod batch_manager;
mod context_menu;
mod history;
mod settings;

use binscope_batch::{Analyzer, BatchJobView, BatchLimits};

use binscope_common::CancelToken;
use binscope_core::{
    analyze_file as run_analysis, AnalysisOptions, AnalysisProgress, ProgressSink, Report,
};
use binscope_rules::{
    build_inventory, collect_yara_roots, RuleFilter, RuleInventory, RuleManager, RulePreferences,
    ScheduledUpdateResult, SourceConfigInput, SourceStatus, SourceUpdateResult,
};
use binscope_updates::{UpdateManager, UpdateRecord, UpdateState};
use binscope_virustotal::{VirusTotalClient, VtFileReport, VtUploadReceipt, STANDARD_UPLOAD_LIMIT};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

const KEYRING_SERVICE: &str = "binscope";
const KEYRING_USER: &str = "virustotal-api-key";

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub bundled_die_dir: Option<PathBuf>,
    pub bundled_yara_dir: Option<PathBuf>,
    pub bundled_signature_dir: Option<PathBuf>,

    pub portable: bool,
}

pub struct AppState {
    analyses: Mutex<HashMap<String, CancelToken>>,
    settings: Mutex<settings::AppSettings>,
    paths: AppPaths,
    rule_update_busy: AtomicBool,

    context_menu_busy: AtomicBool,

    batches: batch_manager::BatchManager,

    pending_open: Arc<Mutex<Option<String>>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    bundled_die_dir: Option<String>,
    bundled_yara_dir: Option<String>,
    bundled_signature_dir: Option<String>,
    data_dir: String,
    virus_total_key_configured: bool,
    yara_engine_version: String,

    portable: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    analysis_id: String,
    stage: String,
    percent: u8,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleProgressEvent {
    source_id: String,
    percent: u8,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ExportFormat {
    Json,
    Txt,
}

#[tauri::command]
fn get_app_info(state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        bundled_die_dir: state
            .paths
            .bundled_die_dir
            .as_ref()
            .map(|p| p.display().to_string()),
        bundled_yara_dir: state
            .paths
            .bundled_yara_dir
            .as_ref()
            .map(|p| p.display().to_string()),
        bundled_signature_dir: state
            .paths
            .bundled_signature_dir
            .as_ref()
            .map(|p| p.display().to_string()),
        data_dir: state.paths.data_dir.display().to_string(),
        virus_total_key_configured: api_key().is_ok(),
        yara_engine_version: binscope_yara::ENGINE_VERSION.to_string(),
        portable: state.paths.portable,
    }
}

#[tauri::command]
fn load_settings(state: State<'_, AppState>) -> Result<settings::AppSettings, String> {
    let guard = state
        .settings
        .lock()
        .map_err(|_| "settings state is poisoned".to_string())?;
    Ok(guard.clone())
}

#[tauri::command]
fn save_settings(
    state: State<'_, AppState>,
    settings: settings::AppSettings,
) -> Result<settings::AppSettings, String> {
    let cleaned = settings.clamped();
    settings::save(&state.paths, &cleaned)?;
    let mut guard = state
        .settings
        .lock()
        .map_err(|_| "settings state is poisoned".to_string())?;
    *guard = cleaned.clone();
    Ok(cleaned)
}

#[tauri::command]
fn set_theme(state: State<'_, AppState>, theme: String) -> Result<settings::AppSettings, String> {
    let mut guard = state
        .settings
        .lock()
        .map_err(|_| "settings state is poisoned".to_string())?;
    guard.theme = settings::normalize_theme(&theme);
    let updated = guard.clone();
    settings::save(&state.paths, &updated)?;
    Ok(updated)
}

#[tauri::command]
fn list_history(state: State<'_, AppState>) -> Vec<history::HistoryEntry> {
    history::load(&state.paths.data_dir)
}

#[tauri::command]
fn clear_history(state: State<'_, AppState>) -> Result<(), String> {
    history::clear(&state.paths.data_dir)
}

#[tauri::command]
fn remove_history_entry(
    state: State<'_, AppState>,
    id: String,
) -> Result<Vec<history::HistoryEntry>, String> {
    history::remove(&state.paths.data_dir, &id)
}

#[tauri::command]
async fn analyze_file(
    app: AppHandle,
    state: State<'_, AppState>,
    analysis_id: String,
    path: String,
) -> Result<Report, String> {
    if analysis_id.trim().is_empty() {
        return Err("analysis id must not be empty".into());
    }
    let path_buf = PathBuf::from(&path);
    if !path_buf.is_file() {
        return Err(format!("'{path}' is not an existing file"));
    }
    let (options, retain_history, data_dir) = {
        let guard = state
            .settings
            .lock()
            .map_err(|_| "settings state is poisoned".to_string())?;
        (
            analysis_options(&guard, &state.paths),
            guard.retain_history,
            state.paths.data_dir.clone(),
        )
    };
    let token = CancelToken::new();
    {
        let mut analyses = state
            .analyses
            .lock()
            .map_err(|_| "analysis state is poisoned".to_string())?;
        if analyses.contains_key(&analysis_id) {
            return Err("an analysis with this id is already running".into());
        }
        analyses.insert(analysis_id.clone(), token.clone());
    }

    let event_id = analysis_id.clone();
    let progress: ProgressSink = Arc::new(move |update: AnalysisProgress| {
        let _ = app.emit(
            "analysis://progress",
            ProgressEvent {
                analysis_id: event_id.clone(),
                stage: update.stage,
                percent: update.percent,
                message: update.message,
            },
        );
    });

    let token_for_task = token.clone();
    let id_for_task = analysis_id.clone();
    let join = tauri::async_runtime::spawn_blocking(move || {
        run_analysis(&path_buf, &options, &token_for_task, Some(&progress))
    })
    .await;

    {
        if let Ok(mut analyses) = state.analyses.lock() {
            analyses.remove(&id_for_task);
        }
    }

    match join {
        Ok(Ok(report)) => {
            if retain_history {
                record_history(&report, &data_dir);
            }
            Ok(report)
        }
        Ok(Err(err)) => Err(err.to_string()),
        Err(err) => Err(format!("analysis task failed: {err}")),
    }
}

#[tauri::command]
fn cancel_analysis(state: State<'_, AppState>, analysis_id: String) -> Result<(), String> {
    let analyses = state
        .analyses
        .lock()
        .map_err(|_| "analysis state is poisoned".to_string())?;
    if let Some(token) = analyses.get(&analysis_id) {
        token.cancel();
        Ok(())
    } else {
        Err("no running analysis with that id".into())
    }
}

#[tauri::command]
fn create_batch_job(
    state: State<'_, AppState>,
    limits: Option<BatchLimits>,
) -> Result<BatchJobView, String> {
    state.batches.create(limits.unwrap_or_default())
}

#[tauri::command]
fn add_batch_paths(
    state: State<'_, AppState>,
    job_id: String,
    paths: Vec<String>,
    recursive: bool,
) -> Result<BatchJobView, String> {
    state.batches.add_paths(&job_id, &paths, recursive)
}

#[tauri::command]
fn start_batch_job(state: State<'_, AppState>, job_id: String) -> Result<(), String> {
    let analyzer = batch_analyzer(&state)?;
    state.batches.start(&job_id, analyzer)
}

#[tauri::command]
fn cancel_batch_job(state: State<'_, AppState>, job_id: String) -> Result<(), String> {
    state.batches.cancel(&job_id)
}

#[tauri::command]
fn get_batch_job(state: State<'_, AppState>, job_id: String) -> Result<BatchJobView, String> {
    state.batches.view(&job_id)
}

#[tauri::command]
fn list_batch_jobs(state: State<'_, AppState>) -> Vec<BatchJobView> {
    state.batches.list()
}

#[tauri::command]
fn get_batch_report(
    state: State<'_, AppState>,
    job_id: String,
    index: usize,
) -> Result<Report, String> {
    state.batches.report(&job_id, index)
}

#[tauri::command]
fn clear_batch_jobs(state: State<'_, AppState>) -> batch_manager::BatchClearResult {
    let removed = state.batches.clear_finished();
    batch_manager::BatchClearResult {
        removed,
        remaining: state.batches.list().len(),
    }
}

#[tauri::command]
fn remove_batch_job(state: State<'_, AppState>, job_id: String) -> Result<(), String> {
    state.batches.remove(&job_id)
}

fn batch_analyzer(state: &AppState) -> Result<Analyzer, String> {
    let (options, retain_history, data_dir) = {
        let guard = state
            .settings
            .lock()
            .map_err(|_| "settings state is poisoned".to_string())?;
        (
            analysis_options(&guard, &state.paths),
            guard.retain_history,
            state.paths.data_dir.clone(),
        )
    };
    Ok(Arc::new(move |path, token| {
        let report = run_analysis(path, &options, token, None)?;
        if retain_history {
            record_history(&report, &data_dir);
        }
        Ok(report)
    }))
}

#[tauri::command]
fn export_report(path: String, format: ExportFormat, report: Report) -> Result<(), String> {
    let target = PathBuf::from(&path);
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
        }
    }
    let content = match format {
        ExportFormat::Json => report
            .to_json_pretty()
            .map_err(|e| format!("could not serialize JSON report: {e}"))?,
        ExportFormat::Txt => report.render_text(),
    };
    std::fs::write(&target, content)
        .map_err(|e| format!("could not write {}: {e}", target.display()))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StringsFormat {
    Json,
    Csv,
}

#[tauri::command]
fn export_strings(
    path: String,
    format: StringsFormat,
    items: Vec<binscope_strings::ExtractedString>,
) -> Result<(), String> {
    if items.len() > 500_000 {
        return Err("too many strings to export in one file".into());
    }
    let target = PathBuf::from(&path);
    if target.as_os_str().is_empty() {
        return Err("export path is empty".into());
    }
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
        }
    }
    let content = match format {
        StringsFormat::Json => serde_json::to_string_pretty(&items)
            .map_err(|e| format!("could not serialize strings: {e}"))?,
        StringsFormat::Csv => strings_csv(&items),
    };
    std::fs::write(&target, content)
        .map_err(|e| format!("could not write {}: {e}", target.display()))?;
    Ok(())
}

fn strings_csv(items: &[binscope_strings::ExtractedString]) -> String {
    let mut out =
        String::from("offset_hex,offset,encoding,section,classifications,confidence,value\n");
    for item in items {
        let classes = item
            .classifications
            .iter()
            .map(|c| c.kind.label())
            .collect::<Vec<_>>()
            .join("; ");
        let confidence = item
            .classifications
            .iter()
            .map(|c| c.confidence.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        out.push_str(&format!(
            "{:#010x},{},{},{},{},{},{}\n",
            item.offset,
            item.offset,
            item.encoding.label(),
            csv_escape(item.section.as_deref().unwrap_or("")),
            csv_escape(&classes),
            csv_escape(&confidence),
            csv_escape(&item.value)
        ));
    }
    out
}

fn csv_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryListing {
    files: Vec<String>,
    errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchExportRow {
    file: String,
    path: String,
    sha256: String,
    format: String,
    architecture: String,
    size: u64,
    anomalies: usize,
    yara: usize,
    signatures: usize,
    debug: String,
    status: String,
    reused_from: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum BatchFormat {
    Csv,
    Json,
}

#[tauri::command]
async fn calculate_sha256(path: String) -> Result<String, String> {
    let path_buf = PathBuf::from(&path);
    if !path_buf.is_file() {
        return Err(format!("'{path}' is not an existing file"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        binscope_hashing::hash_file(&path_buf, &CancelToken::new(), None)
            .map(|hashes| hashes.sha256)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("hashing task failed: {error}"))?
}

#[tauri::command]
fn list_directory_files(path: String, recursive: bool) -> Result<DirectoryListing, String> {
    let root = PathBuf::from(&path);
    if !root.is_dir() {
        return Err(format!("'{path}' is not an existing directory"));
    }
    let mut listing = DirectoryListing {
        files: Vec::new(),
        errors: Vec::new(),
    };
    collect_directory_files(&root, recursive, 0, &mut listing);
    listing.files.sort();
    listing.files.dedup();
    Ok(listing)
}

fn collect_directory_files(
    root: &std::path::Path,
    recursive: bool,
    depth: usize,
    listing: &mut DirectoryListing,
) {
    const MAX_FILES: usize = 5000;
    const MAX_DEPTH: usize = 32;
    if listing.files.len() >= MAX_FILES || depth > MAX_DEPTH {
        return;
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            listing.errors.push(format!("{}: {error}", root.display()));
            return;
        }
    };
    for entry in entries.flatten() {
        if listing.files.len() >= MAX_FILES {
            return;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            if recursive {
                collect_directory_files(&path, recursive, depth + 1, listing);
            }
        } else if metadata.is_file() {
            listing.files.push(path.display().to_string());
        }
    }
}

#[tauri::command]
fn export_batch(
    path: String,
    format: BatchFormat,
    rows: Vec<BatchExportRow>,
) -> Result<(), String> {
    if rows.len() > 100_000 {
        return Err("too many rows to export".into());
    }
    let target = PathBuf::from(&path);
    if target.as_os_str().is_empty() {
        return Err("export path is empty".into());
    }
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
    }
    let content = match format {
        BatchFormat::Json => serde_json::to_string_pretty(&rows)
            .map_err(|error| format!("could not serialize batch results: {error}"))?,
        BatchFormat::Csv => {
            let mut out = String::from(
                "file,path,sha256,format,architecture,size,anomalies,yara,signatures,debug,status,reused_from\n",
            );
            for row in &rows {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    csv_escape(&row.file),
                    csv_escape(&row.path),
                    row.sha256,
                    csv_escape(&row.format),
                    csv_escape(&row.architecture),
                    row.size,
                    row.anomalies,
                    row.yara,
                    row.signatures,
                    csv_escape(&row.debug),
                    csv_escape(&row.status),
                    csv_escape(row.reused_from.as_deref().unwrap_or(""))
                ));
            }
            out
        }
    };
    std::fs::write(&target, content)
        .map_err(|error| format!("could not write {}: {error}", target.display()))
}

#[tauri::command]
fn vt_key_configured() -> bool {
    api_key().is_ok()
}

#[tauri::command]
fn get_update_state(state: State<'_, AppState>) -> UpdateState {
    UpdateManager::new(state.paths.data_dir.clone()).load_state()
}

#[tauri::command]
async fn update_die_database(
    state: State<'_, AppState>,
    confirm: bool,
) -> Result<UpdateRecord, String> {
    if !confirm {
        return Err("update cancelled: explicit confirmation was not provided".into());
    }
    let data_dir = state.paths.data_dir.clone();
    let manager = UpdateManager::new(data_dir.clone());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let release = binscope_updates::fetch_die_release().map_err(|e| e.to_string())?;
        let bytes = binscope_updates::download(&release.url, Some(&release.sha256))
            .map_err(|e| e.to_string())?;
        let zip_path = manager
            .data_dir
            .join(format!("die-db-{}.zip", std::process::id()));
        std::fs::create_dir_all(&manager.data_dir).map_err(|e| e.to_string())?;
        std::fs::write(&zip_path, &bytes).map_err(|e| e.to_string())?;
        let record = manager
            .install_die_zip(&zip_path, &release.version)
            .map_err(|e| e.to_string());
        let _ = std::fs::remove_file(&zip_path);
        record
    })
    .await
    .map_err(|e| format!("update task failed: {e}"))??;

    let die_dir = data_dir.join("die");
    {
        let mut settings = state
            .settings
            .lock()
            .map_err(|_| "settings state is poisoned".to_string())?;
        settings.die_enabled = true;
        settings.die_signature_dir = Some(die_dir);
        settings::save(&state.paths, &settings)?;
    }
    binscope_core::clear_signature_cache();
    Ok(result)
}

#[tauri::command]
async fn update_pebear_signatures(
    state: State<'_, AppState>,
    confirm: bool,
    accept_gpl: bool,
) -> Result<UpdateRecord, String> {
    if !confirm || !accept_gpl {
        return Err(
            "PE-bear SIG.txt is GPLv2 data; both confirmation and GPL acceptance are required"
                .into(),
        );
    }
    let data_dir = state.paths.data_dir.clone();
    let manager = UpdateManager::new(data_dir.clone());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let bytes = binscope_updates::download(binscope_updates::PEBEAR_SIG_URL, None)
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8(bytes).map_err(|e| format!("SIG.txt is not UTF-8: {e}"))?;
        manager
            .install_pebear_sig(&text, "b90f1d7d96635e7a029f424a0d1d11a104821685")
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("update task failed: {e}"))??;

    let path = data_dir.join("pebear").join("SIG.txt");
    {
        let mut settings = state
            .settings
            .lock()
            .map_err(|_| "settings state is poisoned".to_string())?;
        settings.pebear_enabled = true;
        settings.pebear_sig_path = Some(path);
        settings::save(&state.paths, &settings)?;
    }
    Ok(result)
}

#[tauri::command]
async fn update_yara_rules(
    state: State<'_, AppState>,
    url: String,
    sha256: Option<String>,
    version: String,
    confirm: bool,
) -> Result<UpdateRecord, String> {
    if !confirm {
        return Err("update cancelled: explicit confirmation was not provided".into());
    }
    if !url.starts_with("https://") {
        return Err("only HTTPS rule sources are accepted".into());
    }
    let data_dir = state.paths.data_dir.clone();
    let manager = UpdateManager::new(data_dir.clone());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let bytes =
            binscope_updates::download(&url, sha256.as_deref()).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&manager.data_dir).map_err(|e| e.to_string())?;
        let zip_path = manager
            .data_dir
            .join(format!("yara-rules-{}.zip", std::process::id()));
        std::fs::write(&zip_path, bytes).map_err(|e| e.to_string())?;
        let record = manager
            .install_yara_zip(&zip_path, &version)
            .map_err(|e| e.to_string());
        let _ = std::fs::remove_file(&zip_path);
        record
    })
    .await
    .map_err(|e| format!("update task failed: {e}"))??;

    let yara_dir = data_dir.join("yara");
    {
        let mut settings = state
            .settings
            .lock()
            .map_err(|_| "settings state is poisoned".to_string())?;
        settings.yara_enabled = true;
        settings.yara_rule_dirs = vec![yara_dir];
        settings::save(&state.paths, &settings)?;
    }
    Ok(result)
}

#[tauri::command]
async fn get_detection_inventory(state: State<'_, AppState>) -> Result<RuleInventory, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "settings state is poisoned".to_string())?
        .clone();
    let data_dir = state.paths.data_dir.clone();
    let bundled = settings.yara_rule_dirs.clone();
    let die = resolved_die_dir(&settings, &state.paths);
    let pebear = resolved_pebear_path(&settings, &state.paths);
    let signature_dirs = settings.signature_dirs.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let manager = RuleManager::new(data_dir);
        build_inventory(
            &manager,
            &bundled,
            die.as_deref(),
            pebear.as_deref(),
            &signature_dirs,
        )
    })
    .await
    .map_err(|error| format!("inventory task failed: {error}"))
}

#[tauri::command]
fn get_yara_rule_source(
    state: State<'_, AppState>,
    path: String,
    sha256: String,
) -> Result<String, String> {
    const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
    let expected = sha256.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("a full SHA-256 of the rule file is required".into());
    }
    let target = PathBuf::from(&path);
    if !target.is_file() {
        return Err(format!("'{path}' is not an existing rule file"));
    }
    let settings = state
        .settings
        .lock()
        .map_err(|_| "settings state is poisoned".to_string())?;
    let mut roots = settings.yara_rule_dirs.clone();
    roots.push(state.paths.data_dir.join("yara"));
    if let Some(bundled) = &state.paths.bundled_yara_dir {
        roots.push(bundled.clone());
    }
    drop(settings);

    let canonical = std::fs::canonicalize(&target)
        .map_err(|error| format!("could not resolve {}: {error}", target.display()))?;
    let allowed = roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .map(|root| path_is_within(&canonical, &root))
            .unwrap_or(false)
    });
    if !allowed {
        return Err("the rule file is outside the configured YARA rule directories".into());
    }
    let metadata = std::fs::metadata(&canonical)
        .map_err(|error| format!("could not inspect {}: {error}", canonical.display()))?;
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(format!(
            "rule source is {} bytes, above the {} byte display limit",
            metadata.len(),
            MAX_SOURCE_BYTES
        ));
    }
    let hashes = binscope_hashing::hash_file(&canonical, &CancelToken::new(), None)
        .map_err(|error| format!("could not hash the rule file: {error}"))?;
    if !hashes.sha256.eq_ignore_ascii_case(&expected) {
        return Err(
            "the rule file changed since the inventory was built; reload the inventory".into(),
        );
    }
    let bytes = std::fs::read(&canonical)
        .map_err(|error| format!("could not read {}: {error}", canonical.display()))?;
    String::from_utf8(bytes).map_err(|_| "the rule file is not valid UTF-8".into())
}

fn path_is_within(candidate: &std::path::Path, root: &std::path::Path) -> bool {
    let candidate = candidate
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase();
    let mut root = root.to_string_lossy().replace('/', "\\").to_lowercase();
    if !root.ends_with('\\') {
        root.push('\\');
    }
    candidate == root.trim_end_matches('\\') || candidate.starts_with(&root)
}

#[tauri::command]
fn get_rule_preferences(state: State<'_, AppState>) -> Result<RulePreferences, String> {
    Ok(RuleManager::new(&state.paths.data_dir).load_preferences())
}

#[tauri::command]
fn save_rule_preferences(
    state: State<'_, AppState>,
    preferences: RulePreferences,
) -> Result<RulePreferences, String> {
    let manager = RuleManager::new(&state.paths.data_dir);
    manager
        .save_preferences(&preferences)
        .map_err(|error| error.to_string())?;
    sync_source_enabled(&manager, &preferences)?;
    Ok(preferences)
}

#[tauri::command]
fn restore_rule_defaults(state: State<'_, AppState>) -> Result<RulePreferences, String> {
    let manager = RuleManager::new(&state.paths.data_dir);
    let preferences = manager
        .restore_defaults()
        .map_err(|error| error.to_string())?;
    sync_source_enabled(&manager, &preferences)?;
    Ok(preferences)
}

#[tauri::command]
fn apply_rule_profile(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<RulePreferences, String> {
    let manager = RuleManager::new(&state.paths.data_dir);
    manager
        .apply_profile(&profile_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn save_rule_profile(
    state: State<'_, AppState>,
    name: String,
    description: String,
    preferences: RulePreferences,
) -> Result<RulePreferences, String> {
    let manager = RuleManager::new(&state.paths.data_dir);
    manager
        .save_custom_profile(&name, &description, &preferences)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_rule_sources(state: State<'_, AppState>) -> Result<Vec<SourceStatus>, String> {
    Ok(RuleManager::new(&state.paths.data_dir).load_sources())
}

#[tauri::command]
fn set_rule_source_enabled(
    state: State<'_, AppState>,
    source_id: String,
    enabled: bool,
) -> Result<Vec<SourceStatus>, String> {
    let manager = RuleManager::new(&state.paths.data_dir);
    let mut sources = manager.load_sources();
    let Some(source) = sources
        .iter_mut()
        .find(|source| source.definition.id == source_id)
    else {
        return Err(format!("unknown source '{source_id}'"));
    };
    source.enabled = enabled;
    source.pending = enabled && source.version.is_none();
    manager
        .save_sources(&sources)
        .map_err(|error| error.to_string())?;
    let mut preferences = manager.load_preferences();
    if enabled {
        if !preferences
            .enabled_sources
            .iter()
            .any(|id| id == &source_id)
        {
            preferences.enabled_sources.push(source_id);
        }
    } else {
        preferences.enabled_sources.retain(|id| id != &source_id);
    }
    manager
        .save_preferences(&preferences)
        .map_err(|error| error.to_string())?;
    Ok(sources)
}

#[tauri::command]
fn add_rule_source(
    state: State<'_, AppState>,
    input: SourceConfigInput,
) -> Result<Vec<SourceStatus>, String> {
    let (repo, id) = parse_github_repo(&input.repo_url)?;
    let branch = input.branch.trim();
    if branch.is_empty() {
        return Err("a branch or tag is required".into());
    }
    let definition = binscope_rules::SourceDefinition {
        id: format!("custom-{id}"),
        name: if input.name.trim().is_empty() {
            repo.clone()
        } else {
            input.name.trim().to_string()
        },
        url: format!("https://github.com/{repo}"),
        kind: "yara".into(),
        method: "github_archive".into(),
        repo: Some(repo),
        branch: Some(branch.to_string()),
        asset: None,
        include_prefixes: input
            .include_prefixes
            .into_iter()
            .map(|prefix| prefix.trim().replace('\\', "/"))
            .filter(|prefix| !prefix.is_empty())
            .collect(),
        license: input.license.filter(|value| !value.trim().is_empty()),
        license_url: None,
        default_enabled: false,
        implemented: true,
        notes: "User-added GitHub source. Disabled until reviewed and enabled.".into(),
    };
    let manager = RuleManager::new(&state.paths.data_dir);
    manager
        .add_source(SourceStatus::from_definition(definition))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn remove_rule_source(
    state: State<'_, AppState>,
    source_id: String,
) -> Result<Vec<SourceStatus>, String> {
    let manager = RuleManager::new(&state.paths.data_dir);
    let sources = manager
        .remove_source(&source_id)
        .map_err(|error| error.to_string())?;
    let mut preferences = manager.load_preferences();
    preferences.enabled_sources.retain(|id| id != &source_id);
    manager
        .save_preferences(&preferences)
        .map_err(|error| error.to_string())?;
    Ok(sources)
}

#[tauri::command]
async fn update_rule_source(
    app: AppHandle,
    state: State<'_, AppState>,
    source_id: String,
    confirm: bool,
) -> Result<SourceUpdateResult, String> {
    if !confirm {
        return Err("update cancelled: explicit confirmation was not provided".into());
    }
    if state.rule_update_busy.swap(true, Ordering::SeqCst) {
        return Err("another rule update is already running".into());
    }
    let data_dir = state.paths.data_dir.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let manager = RuleManager::new(data_dir);
        let source = manager
            .load_sources()
            .into_iter()
            .find(|source| source.definition.id == source_id)
            .ok_or_else(|| format!("unknown source '{source_id}'"))?;
        update_one_source(&app, &manager, &source, 0)
    })
    .await
    .map_err(|error| format!("update task failed: {error}"));
    state.rule_update_busy.store(false, Ordering::SeqCst);
    result?
}

#[tauri::command]
async fn run_scheduled_rule_updates(
    app: AppHandle,
    state: State<'_, AppState>,
    confirm: bool,
) -> Result<ScheduledUpdateResult, String> {
    if state.rule_update_busy.swap(true, Ordering::SeqCst) {
        return Err("another rule update is already running".into());
    }
    let data_dir = state.paths.data_dir.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let manager = RuleManager::new(data_dir);
        run_scheduled(&app, &manager, confirm)
    })
    .await
    .map_err(|error| format!("update task failed: {error}"));
    state.rule_update_busy.store(false, Ordering::SeqCst);
    result?
}

#[tauri::command]
fn get_rule_changelog(
    state: State<'_, AppState>,
) -> Result<Vec<binscope_rules::ChangelogEntry>, String> {
    Ok(RuleManager::new(&state.paths.data_dir).changelog())
}

#[tauri::command]
fn get_rule_logs(
    state: State<'_, AppState>,
) -> Result<Vec<binscope_rules::UpdateLogEntry>, String> {
    Ok(RuleManager::new(&state.paths.data_dir).logs())
}

#[tauri::command]
fn mark_false_positive(
    state: State<'_, AppState>,
    rule_id: String,
    name: String,
    sha256: Option<String>,
) -> Result<RulePreferences, String> {
    RuleManager::new(&state.paths.data_dir)
        .mark_false_positive(&rule_id, &name, sha256.as_deref())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn import_custom_yara_rules(
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<binscope_rules::ImportResult, String> {
    let paths = paths.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    RuleManager::new(&state.paths.data_dir)
        .import_custom_rules(&paths)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn export_rule_preferences_file(state: State<'_, AppState>, path: String) -> Result<(), String> {
    RuleManager::new(&state.paths.data_dir)
        .export_preferences(std::path::Path::new(&path))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn import_rule_preferences_file(
    state: State<'_, AppState>,
    path: String,
) -> Result<RulePreferences, String> {
    let manager = RuleManager::new(&state.paths.data_dir);
    let prefs = manager
        .import_preferences(std::path::Path::new(&path))
        .map_err(|error| error.to_string())?;
    sync_source_enabled(&manager, &prefs)?;
    Ok(prefs)
}

fn sync_source_enabled(manager: &RuleManager, preferences: &RulePreferences) -> Result<(), String> {
    let mut sources = manager.load_sources();
    for source in &mut sources {
        source.enabled = preferences
            .enabled_sources
            .iter()
            .any(|id| id == &source.definition.id);
    }
    manager
        .save_sources(&sources)
        .map_err(|error| error.to_string())
}

fn parse_github_repo(url: &str) -> Result<(String, String), String> {
    let value = url.trim().trim_end_matches('/');
    let path = value
        .strip_prefix("https://github.com/")
        .or_else(|| value.strip_prefix("http://github.com/"))
        .or_else(|| value.strip_prefix("github.com/"))
        .or_else(|| value.strip_prefix("git@github.com:"))
        .unwrap_or(value);
    let path = path.trim_end_matches(".git");
    let mut parts = path.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return Err(
            "expected a GitHub repository URL such as https://github.com/owner/repo".into(),
        );
    }
    if !owner
        .chars()
        .chain(repo.chars())
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err("repository name contains unsupported characters".into());
    }
    let repo_full = format!("{owner}/{repo}");
    let id = repo_full
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    Ok((repo_full, id.trim_matches('-').to_string()))
}

fn update_one_source(
    app: &AppHandle,
    manager: &RuleManager,
    source: &SourceStatus,
    index: usize,
) -> Result<SourceUpdateResult, String> {
    if !source.definition.implemented {
        return Err(format!(
            "source '{}' is not supported automatically: {}",
            source.definition.name, source.definition.notes
        ));
    }
    let _ = app.emit(
        "rules://progress",
        RuleProgressEvent {
            source_id: source.definition.id.clone(),
            percent: 5 + (index.min(20) as u8 * 3),
            message: format!("Checking {}", source.definition.name),
        },
    );
    let latest = binscope_updates::source::fetch_source_version(source)?;
    let unchanged = (source.version.as_deref() == Some(latest.version.as_str())
        || (source.commit.is_some() && source.commit.as_deref() == latest.commit.as_deref()))
        && manager.source_dir(&source.definition.id).is_dir();
    if unchanged {
        manager.record_source_check(&source.definition.id, Some(&latest.version), true);
        let _ = manager.append_log(
            &source.definition.id,
            "info",
            "source is already up to date; no download",
        );
        return Ok(SourceUpdateResult {
            source_id: source.definition.id.clone(),
            status: "unchanged".into(),
            version: Some(latest.version),
            accepted: source.accepted,
            rejected: source.rejected,
            message: "No changes upstream; existing rules kept.".into(),
        });
    }
    let _ = app.emit(
        "rules://progress",
        RuleProgressEvent {
            source_id: source.definition.id.clone(),
            percent: 35 + (index.min(10) as u8 * 4),
            message: format!("Downloading {}", source.definition.name),
        },
    );
    let result = binscope_updates::source::update_source(manager, source)?;
    let _ = app.emit(
        "rules://progress",
        RuleProgressEvent {
            source_id: source.definition.id.clone(),
            percent: 100,
            message: format!("Installed {}", source.definition.name),
        },
    );
    let _ = manager.append_changelog(binscope_rules::ChangelogEntry {
        at: binscope_rules::now_utc(),
        source_id: source.definition.id.clone(),
        source_name: source.definition.name.clone(),
        from_version: source.version.clone(),
        version: result
            .version
            .clone()
            .unwrap_or_else(|| latest.version.clone()),
        added: result.accepted,
        removed: 0,
        modified: 0,
        invalid: result.rejected,
        status: "installed".into(),
        message: result.message.clone(),
    });
    Ok(result)
}

fn run_scheduled(
    app: &AppHandle,
    manager: &RuleManager,
    confirm: bool,
) -> Result<ScheduledUpdateResult, String> {
    let mut preferences = manager.load_preferences();
    if !confirm {
        if !preferences.update.auto_check {
            return Ok(ScheduledUpdateResult::default());
        }
        if !check_due(&preferences) {
            return Ok(ScheduledUpdateResult::default());
        }
    }
    let sources = manager.load_sources();
    let enabled: Vec<SourceStatus> = sources
        .into_iter()
        .filter(|source| {
            source.enabled
                && source.definition.implemented
                && preferences
                    .enabled_sources
                    .iter()
                    .any(|id| id == &source.definition.id)
        })
        .collect();
    preferences.update.last_check = Some(binscope_rules::now_utc());
    let _ = manager.save_preferences(&preferences);
    let mut result = ScheduledUpdateResult::default();
    for (index, source) in enabled.iter().enumerate() {
        result.checked += 1;
        match update_one_source(app, manager, source, index) {
            Ok(record) => {
                if record.status == "installed" {
                    result.updated += 1;
                } else {
                    result.unchanged += 1;
                }
                result.records.push(record);
            }
            Err(error) => {
                result.errors += 1;
                record_source_error(manager, &source.definition.id, &error);
                result.records.push(SourceUpdateResult {
                    source_id: source.definition.id.clone(),
                    status: "error".into(),
                    version: source.version.clone(),
                    accepted: 0,
                    rejected: 0,
                    message: error,
                });
            }
        }
    }
    Ok(result)
}

fn record_source_error(manager: &RuleManager, source_id: &str, message: &str) {
    let mut sources = manager.load_sources();
    if let Some(source) = sources
        .iter_mut()
        .find(|source| source.definition.id == source_id)
    {
        source.last_check = Some(binscope_rules::now_utc());
        source.compatibility = "error".into();
        source.pending = true;
        source.errors = vec![message.to_string()];
    }
    let _ = manager.save_sources(&sources);
    let _ = manager.append_log(source_id, "error", message);
}

fn check_due(preferences: &RulePreferences) -> bool {
    let Some(last) = preferences.update.last_check.as_deref() else {
        return true;
    };
    let Ok(last) = chrono::DateTime::parse_from_rfc3339(last) else {
        return true;
    };
    let elapsed = chrono::Utc::now().signed_duration_since(last.with_timezone(&chrono::Utc));
    elapsed.num_hours() >= preferences.update.interval_hours as i64
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenFileEvent {
    path: String,
}

fn current_executable() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

#[tauri::command]
fn get_context_menu_status(
) -> Result<context_menu::ContextMenuStatus, context_menu::ContextMenuFailure> {
    Ok(context_menu::status(
        &*context_menu::registry(),
        current_executable().as_deref(),
    ))
}

#[tauri::command]
fn enable_context_menu(
    state: State<'_, AppState>,
) -> Result<context_menu::ContextMenuStatus, context_menu::ContextMenuFailure> {
    if state.context_menu_busy.swap(true, Ordering::SeqCst) {
        return Err(context_menu::ContextMenuFailure::busy());
    }
    let result = match current_executable() {
        Some(exe) => context_menu::install(
            &*context_menu::registry(),
            &exe,
            context_menu::BuildProfile::current(),
        ),
        None => Err(context_menu::ContextMenuFailure::new(
            context_menu::FailureKind::ExecutableUnavailable,
            "Windows did not report the running BinScope executable, so the context menu cannot be registered.",
        )),
    };
    state.context_menu_busy.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
fn disable_context_menu(
    state: State<'_, AppState>,
) -> Result<context_menu::ContextMenuStatus, context_menu::ContextMenuFailure> {
    if state.context_menu_busy.swap(true, Ordering::SeqCst) {
        return Err(context_menu::ContextMenuFailure::busy());
    }
    let result = context_menu::remove(&*context_menu::registry());
    state.context_menu_busy.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
fn repair_context_menu_registration(
    state: State<'_, AppState>,
) -> Result<context_menu::ContextMenuStatus, context_menu::ContextMenuFailure> {
    if state.context_menu_busy.swap(true, Ordering::SeqCst) {
        return Err(context_menu::ContextMenuFailure::busy());
    }
    let result = match current_executable() {
        Some(exe) => context_menu::repair(
            &*context_menu::registry(),
            &exe,
            context_menu::BuildProfile::current(),
        ),
        None => Err(context_menu::ContextMenuFailure::new(
            context_menu::FailureKind::ExecutableUnavailable,
            "Windows did not report the running BinScope executable, so the context menu cannot be repaired.",
        )),
    };
    state.context_menu_busy.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
fn take_pending_open_path(state: State<'_, AppState>) -> Option<String> {
    state
        .pending_open
        .lock()
        .ok()
        .and_then(|mut slot| slot.take())
}

#[tauri::command]
fn vt_set_key(key: String) -> Result<(), String> {
    let key = key.trim();
    if key.len() < 20 || key.len() > 512 {
        return Err("the API key length is not plausible (expected 20-512 characters)".into());
    }
    if !key.chars().all(|c| c.is_ascii_graphic()) {
        return Err("the API key contains whitespace or non-printable characters".into());
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| format!("Windows Credential Manager is unavailable: {e}"))?;
    entry
        .set_password(key)
        .map_err(|e| format!("could not store the API key in Windows Credential Manager: {e}"))
}

#[tauri::command]
fn vt_clear_key() -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| format!("Windows Credential Manager is unavailable: {e}"))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("could not remove the API key: {e}")),
    }
}

#[tauri::command]
async fn vt_lookup(
    state: State<'_, AppState>,
    sha256: String,
) -> Result<Option<VtFileReport>, String> {
    require_vt_enabled(&state)?;
    let key = api_key()?;
    let client = VirusTotalClient::new(key).map_err(|e| e.to_string())?;
    client.lookup(&sha256).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn vt_upload(
    state: State<'_, AppState>,
    path: String,
    confirm: bool,
) -> Result<VtUploadReceipt, String> {
    require_vt_enabled(&state)?;
    if !confirm {
        return Err("upload cancelled: explicit confirmation was not provided".into());
    }
    let path_buf = PathBuf::from(&path);
    if !path_buf.is_file() {
        return Err(format!("'{path}' is not an existing file"));
    }
    let size = std::fs::metadata(&path_buf)
        .map_err(|e| format!("could not read file metadata: {e}"))?
        .len();
    if size > STANDARD_UPLOAD_LIMIT {
        return Err(format!(
            "file is {size} bytes; the standard VirusTotal upload limit is {STANDARD_UPLOAD_LIMIT} bytes"
        ));
    }
    let key = api_key()?;
    let client = VirusTotalClient::new(key).map_err(|e| e.to_string())?;
    client.upload(&path_buf).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn vt_analysis(
    state: State<'_, AppState>,
    analysis_id: String,
) -> Result<VtUploadReceipt, String> {
    require_vt_enabled(&state)?;
    let key = api_key()?;
    let client = VirusTotalClient::new(key).map_err(|e| e.to_string())?;
    client
        .analysis(&analysis_id)
        .await
        .map_err(|e| e.to_string())
}

fn require_vt_enabled(state: &State<'_, AppState>) -> Result<(), String> {
    let enabled = state
        .settings
        .lock()
        .map_err(|_| "settings state is poisoned".to_string())?
        .virustotal_enabled;
    if enabled {
        Ok(())
    } else {
        Err("VirusTotal integration is disabled in Settings".into())
    }
}

fn api_key() -> Result<String, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| format!("Windows Credential Manager is unavailable: {e}"))?;
    match entry.get_password() {
        Ok(key) if !key.trim().is_empty() => Ok(key),
        Ok(_) => Err("the stored VirusTotal API key is empty".into()),
        Err(keyring::Error::NoEntry) => {
            Err("no VirusTotal API key is configured; add one in Settings".into())
        }
        Err(e) => Err(format!(
            "could not read the API key from Windows Credential Manager: {e}"
        )),
    }
}

fn record_history(report: &Report, data_dir: &std::path::Path) {
    let status = serde_json::to_value(report.analysis.status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into());
    let entry = history::HistoryEntry {
        id: history::entry_id(&report.file.sha256, &report.analysis.finished_utc),
        analyzed_at: report.analysis.finished_utc.clone(),
        name: report.file.name.clone(),
        path: report.file.path.clone(),
        sha256: report.file.sha256.clone(),
        size: report.file.size,
        size_human: report.file.size_human.clone(),
        format: report.format.label.clone(),
        status,
        detections: report.detections.len(),
        duration_ms: report.analysis.duration_ms,
    };
    let _ = history::record(data_dir, entry);
}

fn analysis_options(settings: &settings::AppSettings, paths: &AppPaths) -> AnalysisOptions {
    let manager = RuleManager::new(&paths.data_dir);
    let prefs = manager.load_preferences();
    let filter = RuleFilter::from_preferences(&prefs);
    let roots = collect_yara_roots(&manager, &settings.yara_rule_dirs);
    let yara_rule_dirs = roots.iter().map(|root| root.path.clone()).collect();
    let yara_provenance = roots
        .iter()
        .map(|root| binscope_core::YaraRootProvenance {
            source_id: root.source_id.clone(),
            path: root.path.clone(),
        })
        .collect();
    AnalysisOptions {
        include_strings: settings.include_strings,
        min_string_len: settings.min_string_len,
        max_strings: settings.max_strings,
        signatures_enabled: settings.signatures_enabled && prefs.signatures_enabled,
        builtin_signatures: settings.builtin_signatures,
        signature_dirs: settings.signature_dirs.clone(),
        die_signature_dir: resolved_die_dir(settings, paths),
        pebear_sig_path: resolved_pebear_path(settings, paths),
        yara_enabled: settings.yara_enabled && prefs.yara_enabled,
        yara_rule_dirs,
        yara_provenance,
        rule_filter: filter,
        rule_profile: Some(prefs.profile.clone()),
        ..Default::default()
    }
}

fn resolved_die_dir(settings: &settings::AppSettings, paths: &AppPaths) -> Option<PathBuf> {
    if !settings.die_enabled {
        return None;
    }
    settings
        .die_signature_dir
        .clone()
        .or_else(|| paths.bundled_die_dir.clone())
}

fn resolved_pebear_path(settings: &settings::AppSettings, _paths: &AppPaths) -> Option<PathBuf> {
    if !settings.pebear_enabled {
        return None;
    }
    settings.pebear_sig_path.clone()
}

fn find_bundled_dir(app: &AppHandle, relative: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(relative));
        }
    }
    if let Ok(resource) = app.path().resource_dir() {
        candidates.push(resource.join(relative));
    }
    #[cfg(debug_assertions)]
    if let Some(dev_root) = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent() {
        candidates.push(dev_root.join(relative));
    }
    candidates.into_iter().find(|path| path.is_dir())
}

fn portable_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.to_path_buf();
    if dir.join("binscope.portable").is_file() {
        Some(dir)
    } else {
        None
    }
}

fn resolve_paths(app: &AppHandle) -> Result<AppPaths, String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("could not resolve application config directory: {e}"))?;
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve application data directory: {e}"))?;

    let portable = portable_root().is_some();
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("could not create {}: {e}", config_dir.display()))?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("could not create {}: {e}", data_dir.display()))?;

    Ok(AppPaths {
        config_dir,
        data_dir,
        bundled_die_dir: find_bundled_dir(app, "databases/die"),
        bundled_yara_dir: find_bundled_dir(app, "rules/yara"),
        bundled_signature_dir: find_bundled_dir(app, "databases/signatures"),
        portable,
    })
}

pub fn run() {
    let webview_cache = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("com.binscope.analyzer")
        .join("webview2");
    let _ = std::fs::create_dir_all(&webview_cache);
    std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &webview_cache);
    let pending_open: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(
        context_menu::extract_file_argument(std::env::args_os())
            .map(|path| path.to_string_lossy().into_owned()),
    ));
    let pending_for_instance = pending_open.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(
            move |app, argv, _cwd| {
                if let Some(path) = context_menu::extract_file_argument(argv.iter().cloned())
                    .map(|path| path.to_string_lossy().into_owned())
                {
                    if let Ok(mut slot) = pending_for_instance.lock() {
                        *slot = Some(path.clone());
                    }
                    let _ = app.emit("app://open-file", OpenFileEvent { path });
                }
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.unminimize();
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            },
        ))
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let paths = resolve_paths(app.handle()).map_err(|e| e.to_string())?;
            let mut loaded = settings::load(&paths).unwrap_or_else(|e| {
                eprintln!("BinScope: falling back to default settings: {e}");
                settings::AppSettings::defaults(&paths)
            });
            if paths.portable {
                loaded.repair_portable_paths(&paths);
                let _ = settings::save(&paths, &loaded);
            }
            let manager = RuleManager::new(&paths.data_dir);
            let _ = manager.migrate_legacy_yara();
            let _ = manager.load_sources();
            app.manage(AppState {
                analyses: Mutex::new(HashMap::new()),
                settings: Mutex::new(loaded),
                paths,
                rule_update_busy: AtomicBool::new(false),
                context_menu_busy: AtomicBool::new(false),
                batches: batch_manager::BatchManager::new(),
                pending_open: pending_open.clone(),
            });

            if let Some(exe) = current_executable() {
                if let Some(message) = context_menu::startup(
                    &*context_menu::registry(),
                    &exe,
                    context_menu::BuildProfile::current(),
                ) {
                    eprintln!("BinScope: {message}");
                }
            }

            #[cfg(windows)]
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.with_webview(|webview| {
                    let controller = webview.controller();
                    unsafe {
                        if let Ok(core) = controller.CoreWebView2() {
                            if let Ok(settings) = core.Settings() {
                                let _ = settings.SetAreDefaultContextMenusEnabled(false);
                            }
                        }
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_info,
            load_settings,
            save_settings,
            set_theme,
            list_history,
            clear_history,
            remove_history_entry,
            analyze_file,
            cancel_analysis,
            create_batch_job,
            add_batch_paths,
            start_batch_job,
            cancel_batch_job,
            get_batch_job,
            list_batch_jobs,
            get_batch_report,
            clear_batch_jobs,
            remove_batch_job,
            export_report,
            export_strings,
            calculate_sha256,
            list_directory_files,
            export_batch,
            vt_key_configured,
            get_update_state,
            update_die_database,
            update_pebear_signatures,
            update_yara_rules,
            get_detection_inventory,
            get_yara_rule_source,
            get_rule_preferences,
            save_rule_preferences,
            restore_rule_defaults,
            apply_rule_profile,
            save_rule_profile,
            get_rule_sources,
            set_rule_source_enabled,
            add_rule_source,
            remove_rule_source,
            update_rule_source,
            run_scheduled_rule_updates,
            get_rule_changelog,
            get_rule_logs,
            mark_false_positive,
            import_custom_yara_rules,
            export_rule_preferences_file,
            import_rule_preferences_file,
            get_context_menu_status,
            enable_context_menu,
            disable_context_menu,
            repair_context_menu_registration,
            take_pending_open_path,
            vt_set_key,
            vt_clear_key,
            vt_lookup,
            vt_upload,
            vt_analysis
        ])
        .build(tauri::generate_context!())
        .expect("error while building BinScope")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
                if let Some(state) = app.try_state::<AppState>() {
                    state.batches.cancel_all();
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use binscope_strings::{ExtractedString, StringEncoding};

    fn string(offset: u64, value: &str) -> ExtractedString {
        ExtractedString {
            offset,
            encoding: StringEncoding::Ascii,
            value: value.into(),
            truncated: false,
            section: Some(".rdata".into()),
            classifications: Vec::new(),
        }
    }

    #[test]
    fn csv_escaping_quotes_and_unicode() {
        assert_eq!(csv_escape("plain"), "\"plain\"");
        assert_eq!(csv_escape("a\"b,ñ"), "\"a\"\"b,ñ\"");
    }

    #[test]
    fn strings_csv_has_a_header_and_escaped_values() {
        let csv = strings_csv(&[string(0x40, "Hello, \"world\"")]);
        assert!(csv
            .starts_with("offset_hex,offset,encoding,section,classifications,confidence,value\n"));
        assert!(csv.contains("0x00000040,64,ASCII,\".rdata\""));
        assert!(csv.contains("\"Hello, \"\"world\"\"\""));
    }

    #[test]
    fn batch_export_writes_csv_and_refuses_empty_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("batch.csv");
        let rows = vec![BatchExportRow {
            file: "a, b.exe".into(),
            path: r"C:\samples\a, b.exe".into(),
            sha256: "ab".repeat(32),
            format: "PE".into(),
            architecture: "x86".into(),
            size: 10,
            anomalies: 1,
            yara: 2,
            signatures: 3,
            debug: "none".into(),
            status: "completed".into(),
            reused_from: None,
        }];
        export_batch(path.display().to_string(), BatchFormat::Csv, rows).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"a, b.exe\""));
        assert!(text.contains("\"completed\""));
        assert!(export_batch(String::new(), BatchFormat::Json, Vec::new()).is_err());
    }
}
