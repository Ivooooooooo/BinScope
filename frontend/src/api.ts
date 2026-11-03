import { invoke } from "@tauri-apps/api/core";
import type {
  AnalysisProgress,
  AppInfo,
  AppSettings,
  ChangelogEntry,
  BatchExportRow,
  ContextMenuStatus,
  DirectoryListing,
  ExtractedString,
  HistoryEntry,
  Report,
  RuleImportResult,
  RuleInventory,
  RulePreferences,
  BatchClearResult,
  BatchJobView,
  BatchLimits,
  ScheduledUpdateResult,
  SourceConfigInput,
  SourceStatus,
  SourceUpdateResult,
  UpdateLogEntry,
  UpdateRecord,
  UpdateState,
  VtFileReport,
  VtUploadReceipt,
} from "./types";

const tauriAvailable = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const previewSettings: AppSettings = {
  includeStrings: true,
  minStringLen: 4,
  maxStrings: 100000,
  signaturesEnabled: true,
  builtinSignatures: true,
  signatureDirs: [],
  dieEnabled: true,
  dieSignatureDir: null,
  pebearEnabled: false,
  pebearSigPath: null,
  yaraEnabled: true,
  yaraRuleDirs: [],
  virustotalEnabled: false,
  theme: "system",
  retainHistory: true,
};

const previewInfo: AppInfo = {
  version: "0.1.0",
  bundledDieDir: null,
  bundledYaraDir: null,
  bundledSignatureDir: null,
  dataDir: "preview",
  virusTotalKeyConfigured: false,
  yaraEngineVersion: "1.22.1",
  portable: false,
};

const previewContextMenuStatus: ContextMenuStatus = {
  supported: false,
  installed: false,
  foreignEntry: false,
  canWrite: false,
  requiresAdmin: false,
  preferenceEnabled: false,
  state: "unavailable",
  partial: false,
  executable: null,
  registeredExecutable: null,
  executableExists: false,
  stale: false,
  registrations: [],
  missingTargets: [],
  staleTargets: [],
  diagnostics: [],
  conflicts: [],
  registryKey: "Software\\Classes\\*\\shell\\BinScope.Analyze",
  detail: "Windows integration is only available in the packaged desktop application.",
};

export const analyzeFile = (
  analysisId: string,
  path: string,
  options?: Partial<AppSettings>,
) => invoke<Report>("analyze_file", { analysisId, path, options });

export const createBatchJob = (limits?: Partial<BatchLimits>) =>
  invoke<BatchJobView>("create_batch_job", { limits });

export const addBatchPaths = (jobId: string, paths: string[], recursive: boolean) =>
  invoke<BatchJobView>("add_batch_paths", { jobId, paths, recursive });

export const startBatchJob = (jobId: string) =>
  invoke<void>("start_batch_job", { jobId });

export const cancelBatchJob = (jobId: string) =>
  invoke<void>("cancel_batch_job", { jobId });

export const getBatchJob = (jobId: string) =>
  invoke<BatchJobView>("get_batch_job", { jobId });

export const listBatchJobs = () => invoke<BatchJobView[]>("list_batch_jobs");

export const getBatchReport = (jobId: string, index: number) =>
  invoke<Report>("get_batch_report", { jobId, index });

export const clearBatchJobs = () => invoke<BatchClearResult>("clear_batch_jobs");

export const removeBatchJob = (jobId: string) =>
  invoke<void>("remove_batch_job", { jobId });

export const getYaraRuleSource = (path: string, sha256: string) =>
  invoke<string>("get_yara_rule_source", { path, sha256 });

export const cancelAnalysis = (analysisId: string) =>
  invoke<void>("cancel_analysis", { analysisId });

export const loadSettings = () =>
  tauriAvailable ? invoke<AppSettings>("load_settings") : Promise.resolve(previewSettings);

export const saveSettings = (settings: AppSettings) =>
  invoke<AppSettings>("save_settings", { settings });

export const getAppInfo = () =>
  tauriAvailable ? invoke<AppInfo>("get_app_info") : Promise.resolve(previewInfo);

export const exportStrings = (path: string, format: "csv" | "json", items: ExtractedString[]) =>
  invoke<void>("export_strings", { path, format, items });

export const calculateSha256 = (path: string) =>
  invoke<string>("calculate_sha256", { path });

export const listDirectoryFiles = (path: string, recursive: boolean) =>
  invoke<DirectoryListing>("list_directory_files", { path, recursive });

export const exportBatch = (path: string, format: "csv" | "json", rows: BatchExportRow[]) =>
  invoke<void>("export_batch", { path, format, rows });

export const exportReport = (path: string, format: "json" | "txt", report: Report) =>
  invoke<void>("export_report", { path, format, report });

export const vtKeyConfigured = () =>
  tauriAvailable ? invoke<boolean>("vt_key_configured") : Promise.resolve(false);

export const vtSetKey = (key: string) => invoke<void>("vt_set_key", { key });

export const vtClearKey = () => invoke<void>("vt_clear_key");

export const vtLookup = (sha256: string) =>
  invoke<VtFileReport | null>("vt_lookup", { sha256 });

export const vtUpload = (path: string, confirm: boolean) =>
  invoke<VtUploadReceipt>("vt_upload", { path, confirm });

export const vtAnalysis = (analysisId: string) =>
  invoke<VtUploadReceipt>("vt_analysis", { analysisId });

export const getUpdateState = () => invoke<UpdateState>("get_update_state");

export const updateDieDatabase = (confirm: boolean) =>
  invoke<UpdateRecord>("update_die_database", { confirm });

export const updatePebearSignatures = (confirm: boolean, acceptGpl: boolean) =>
  invoke<UpdateRecord>("update_pebear_signatures", { confirm, acceptGpl });

export const updateYaraRules = (
  url: string,
  sha256: string | null,
  version: string,
  confirm: boolean,
) => invoke<UpdateRecord>("update_yara_rules", { url, sha256, version, confirm });

export const getDetectionInventory = () =>
  tauriAvailable
    ? invoke<RuleInventory>("get_detection_inventory")
    : Promise.resolve(null as unknown as RuleInventory);

export const getRulePreferences = () =>
  tauriAvailable
    ? invoke<RulePreferences>("get_rule_preferences")
    : Promise.resolve(null as unknown as RulePreferences);

export const saveRulePreferences = (preferences: RulePreferences) =>
  invoke<RulePreferences>("save_rule_preferences", { preferences });

export const restoreRuleDefaults = () =>
  invoke<RulePreferences>("restore_rule_defaults");

export const applyRuleProfile = (profileId: string) =>
  invoke<RulePreferences>("apply_rule_profile", { profileId });

export const saveRuleProfile = (
  name: string,
  description: string,
  preferences: RulePreferences,
) => invoke<RulePreferences>("save_rule_profile", { name, description, preferences });

export const getRuleSources = () => invoke<SourceStatus[]>("get_rule_sources");

export const setRuleSourceEnabled = (sourceId: string, enabled: boolean) =>
  invoke<SourceStatus[]>("set_rule_source_enabled", { sourceId, enabled });

export const addRuleSource = (input: SourceConfigInput) =>
  invoke<SourceStatus[]>("add_rule_source", { input });

export const removeRuleSource = (sourceId: string) =>
  invoke<SourceStatus[]>("remove_rule_source", { sourceId });

export const updateRuleSource = (sourceId: string, confirm: boolean) =>
  invoke<SourceUpdateResult>("update_rule_source", { sourceId, confirm });

export const runScheduledRuleUpdates = (confirm: boolean) =>
  invoke<ScheduledUpdateResult>("run_scheduled_rule_updates", { confirm });

export const getRuleChangelog = () => invoke<ChangelogEntry[]>("get_rule_changelog");

export const getRuleLogs = () => invoke<UpdateLogEntry[]>("get_rule_logs");

export const markFalsePositive = (
  ruleId: string,
  name: string,
  sha256: string | null,
) => invoke<RulePreferences>("mark_false_positive", { ruleId, name, sha256 });

export const importCustomYaraRules = (paths: string[]) =>
  invoke<RuleImportResult>("import_custom_yara_rules", { paths });

export const exportRulePreferencesFile = (path: string) =>
  invoke<void>("export_rule_preferences_file", { path });

export const importRulePreferencesFile = (path: string) =>
  invoke<RulePreferences>("import_rule_preferences_file", { path });

export const getContextMenuStatus = () =>
  tauriAvailable
    ? invoke<ContextMenuStatus>("get_context_menu_status")
    : Promise.resolve(previewContextMenuStatus);

export const enableContextMenu = () =>
  invoke<ContextMenuStatus>("enable_context_menu");

export const disableContextMenu = () =>
  invoke<ContextMenuStatus>("disable_context_menu");

export const repairContextMenuRegistration = () =>
  invoke<ContextMenuStatus>("repair_context_menu_registration");

export const takePendingOpenPath = () =>
  tauriAvailable
    ? invoke<string | null>("take_pending_open_path")
    : Promise.resolve(null);

export const setTheme = (theme: string) =>
  invoke<AppSettings>("set_theme", { theme });

export const listHistory = () =>
  tauriAvailable ? invoke<HistoryEntry[]>("list_history") : Promise.resolve([]);

export const clearHistory = () => invoke<void>("clear_history");

export const removeHistoryEntry = (id: string) =>
  invoke<HistoryEntry[]>("remove_history_entry", { id });

export type { AnalysisProgress };
