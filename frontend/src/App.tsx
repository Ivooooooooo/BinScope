import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  analyzeFile,
  cancelAnalysis,
  clearHistory,
  disableContextMenu,
  enableContextMenu,
  repairContextMenuRegistration,
  exportReport,
  getAppInfo,
  getContextMenuStatus,
  getRulePreferences,
  getUpdateState,
  listHistory,
  loadSettings,
  removeHistoryEntry,
  runScheduledRuleUpdates,
  saveRulePreferences,
  saveSettings,
  setTheme,
  takePendingOpenPath,
  updateDieDatabase,
  updatePebearSignatures,
  updateYaraRules,
  vtClearKey,
  vtKeyConfigured,
  vtSetKey,
} from "./api";
import type {
  AnalysisProgress,
  AppInfo,
  AppSettings,
  ContextMenuStatus,
  HistoryEntry,
  Report,
  RulePreferences,
  UpdateState,
} from "./types";
import { fmtHex, fmtNum, statusLabel } from "./format";
import { DetectionRulesView } from "./rules";
import { BatchView } from "./batch";
import { Badge, CopyButton, Toggle } from "./ui";
import {
  ImportsTab,
  PeTab,
  SectionsTab,
  SignaturesTab,
  StringsTab,
  SummaryTab,
  VirusTotalTab,
  YaraTab,
} from "./tabs";

type ViewId = "analyze" | "batch" | "signatures" | "yara" | "sources" | "history" | "settings";

type TabId = "summary" | "pe" | "strings" | "imports" | "sections" | "signatures" | "yara" | "virustotal" | "logs";

const TABS: Array<{ id: TabId; label: string }> = [
  { id: "summary", label: "Overview" },
  { id: "pe", label: "PE" },
  { id: "signatures", label: "Signatures" },
  { id: "yara", label: "YARA" },
  { id: "strings", label: "Strings" },
  { id: "imports", label: "Imports" },
  { id: "sections", label: "Sections" },
  { id: "virustotal", label: "VirusTotal" },
  { id: "logs", label: "Logs" },
];

function applyTheme(theme: string) {
  const root = document.documentElement;
  if (theme === "light" || theme === "dark") {
    root.dataset.theme = theme;
  } else {
    delete root.dataset.theme;
  }
  try {
    localStorage.setItem("binscope.theme", theme);
  } catch {
    

  }
}

function errorText(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}





function contextMenuErrorText(error: unknown): string {
  if (error && typeof error === "object") {
    const failure = error as { message?: unknown; remaining?: unknown };
    const base =
      typeof failure.message === "string" ? failure.message : errorText(error);
    if (Array.isArray(failure.remaining) && failure.remaining.length > 0) {
      return `${base} Entries still present: ${failure.remaining.join(", ")}`;
    }
    return base;
  }
  return errorText(error);
}

function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

export default function App() {
  const [report, setReport] = useState<Report | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("summary");
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [keyConfigured, setKeyConfigured] = useState(false);
  const [view, setView] = useState<ViewId>("analyze");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const analysisIdRef = useRef<string | null>(null);
  const cancelRequestedRef = useRef(false);
  const toastTimer = useRef<number | null>(null);

  const notify = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 3200);
  }, []);

  useEffect(() => {
    let disposed = false;
    Promise.all([loadSettings(), getAppInfo()])
      .then(([loadedSettings, info]) => {
        if (disposed) return;
        setSettings(loadedSettings);
        setAppInfo(info);
        setKeyConfigured(info.virusTotalKeyConfigured);
      })
      .catch((err) => {
        if (!disposed) setError(`Could not load application settings: ${errorText(err)}`);
      });
    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
    const timer = window.setTimeout(() => {
      void runScheduledRuleUpdates(false)
        .then((result) => {
          if (result.updated > 0) notify(`Updated ${result.updated} rule source(s)`);
        })
        .catch(() => {
          

        });
    }, 6000);
    return () => window.clearTimeout(timer);
  }, [notify]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let disposed = false;
    try {
      listen<AnalysisProgress>("analysis://progress", (event) => {
        if (!analysisIdRef.current) return;
        if (event.payload?.analysisId && event.payload.analysisId !== analysisIdRef.current) return;
        setProgress(event.payload);
      })
        .then((fn) => {
          if (disposed) fn();
          else unlisten = fn;
        })
        .catch(() => {
          

        });
    } catch {
      

    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const refreshHistory = useCallback(async () => {
    setHistoryBusy(true);
    try {
      setHistory(await listHistory());
    } catch (err) {
      setError(`Could not load analysis history: ${errorText(err)}`);
    } finally {
      setHistoryBusy(false);
    }
  }, []);

  useEffect(() => {
    if (settings) applyTheme(settings.theme);
  }, [settings]);

  useEffect(() => {
    void refreshHistory();
  }, [refreshHistory]);

  useEffect(() => {
    if (view === "history") void refreshHistory();
  }, [view, refreshHistory]);

  const startAnalysis = useCallback(
    async (path: string) => {
      if (!path) return;
      if (analysisIdRef.current) return;
      setView("analyze");
      setError(null);
      setCancelling(false);
      cancelRequestedRef.current = false;
      const id = `analysis-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      analysisIdRef.current = id;
      setAnalyzing(true);
      setProgress({ stage: "open", percent: 0, message: "Starting analysis" });
      try {
        const result = await analyzeFile(id, path);
        setReport(result);
        setActiveTab("summary");
        notify(
          result.analysis.status === "partial"
            ? "Analysis completed with warnings"
            : "Analysis complete",
        );
        void refreshHistory();
      } catch (err) {
        const message = errorText(err);
        if (cancelRequestedRef.current || message.toLowerCase().includes("cancel")) {
          notify("Analysis cancelled");
        } else {
          setError(message);
        }
      } finally {
        if (analysisIdRef.current === id) {
          analysisIdRef.current = null;
          setAnalyzing(false);
          setProgress(null);
          setCancelling(false);
        }
      }
    },
    [notify, refreshHistory],
  );

  const openFile = useCallback(async () => {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        title: "Open a binary for static analysis",
        filters: [
          { name: "Executables and libraries", extensions: ["exe", "dll", "sys", "ocx", "cpl", "scr", "efi"] },
          { name: "ELF / Mach-O / binaries", extensions: ["elf", "so", "bin", "dylib", "o", "ko"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof selected === "string") {
        await startAnalysis(selected);
      }
    } catch (err) {
      setError(`Could not open the file dialog: ${errorText(err)}`);
    }
  }, [startAnalysis]);

  




  const openFromShell = useCallback(
    (path: string) => {
      if (!path) return;
      if (analysisIdRef.current) {
        notify("An analysis is already running; finish or cancel it before opening another file.");
        return;
      }
      void startAnalysis(path);
    },
    [notify, startAnalysis],
  );

  useEffect(() => {
    

    

    

    void takePendingOpenPath()
      .then((path) => {
        if (path) openFromShell(path);
      })
      .catch((err) => {
        setError(`Could not open the file passed by Windows: ${errorText(err)}`);
      });
  }, [openFromShell]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let disposed = false;
    try {
      listen<{ path: string }>("app://open-file", (event) => {
        const path = event.payload?.path;
        if (path) openFromShell(path);
      })
        .then((fn) => {
          if (disposed) fn();
          else unlisten = fn;
        })
        .catch(() => {
          

        });
    } catch {
      

    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [openFromShell]);

  const cancel = useCallback(async () => {
    const id = analysisIdRef.current;
    if (!id || cancelling) return;
    cancelRequestedRef.current = true;
    setCancelling(true);
    try {
      await cancelAnalysis(id);
      notify("Cancellation requested");
    } catch (err) {
      setError(`Could not cancel the analysis: ${errorText(err)}`);
      setCancelling(false);
    }
  }, [cancelling, notify]);

  const reopenFromHistory = useCallback(
    (entry: HistoryEntry) => {
      if (analysisIdRef.current) {
        notify("An analysis is already running; finish or cancel it before reopening another file.");
        return;
      }
      void startAnalysis(entry.path);
    },
    [notify, startAnalysis],
  );

  const removeHistory = useCallback(async (id: string) => {
    try {
      setHistory(await removeHistoryEntry(id));
    } catch (err) {
      setError(`Could not remove the history entry: ${errorText(err)}`);
    }
  }, []);

  const clearAllHistory = useCallback(async () => {
    if (
      !window.confirm(
        "Delete all local analysis history? Only metadata is stored; file contents are never kept.",
      )
    ) {
      return;
    }
    try {
      await clearHistory();
      setHistory([]);
      notify("Analysis history cleared");
    } catch (err) {
      setError(`Could not clear history: ${errorText(err)}`);
    }
  }, [notify]);

  const changeTheme = useCallback(async (theme: string) => {
    applyTheme(theme);
    setSettings((current) => (current ? { ...current, theme } : current));
    try {
      const stored = await setTheme(theme);
      setSettings(stored);
    } catch (err) {
      setError(`Could not save the theme: ${errorText(err)}`);
    }
  }, []);

  const doExport = useCallback(
    async (format: "json" | "txt") => {
      if (!report) return;
      try {
        const base = report.file.name.replace(/\.[^.]+$/, "") || "binscope-report";
        const target = await save({
          title: `Export ${format.toUpperCase()} report`,
          defaultPath: `${base}.binscope.${format}`,
          filters: [
            {
              name: format === "json" ? "JSON report" : "Text report",
              extensions: [format],
            },
          ],
        });
        if (typeof target !== "string") return;
        await exportReport(target, format, report);
        notify(`Report exported to ${baseName(target)}`);
      } catch (err) {
        setError(`Export failed: ${errorText(err)}`);
      }
    },
    [report, notify],
  );

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let disposed = false;
    try {
      getCurrentWebview()
        .onDragDropEvent((event) => {
          const payload = event.payload;
          if (payload.type === "drop") {
            setDragging(false);
            if (payload.paths.length > 0) {
              void startAnalysis(payload.paths[0]);
            }
          } else if (payload.type === "enter" || payload.type === "over") {
            setDragging(true);
          } else {
            setDragging(false);
          }
        })
        .then((fn) => {
          if (disposed) fn();
          else unlisten = fn;
        })
        .catch(() => {
          

          

        });
    } catch {
      

    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [startAnalysis]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "o") {
        event.preventDefault();
        void openFile();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openFile]);

  const settingsSaved = useCallback(
    (updated: AppSettings) => {
      setSettings(updated);
      notify("Settings saved");
    },
    [notify],
  );

  const refreshKeyState = useCallback(async () => {
    try {
      setKeyConfigured(await vtKeyConfigured());
    } catch {
      setKeyConfigured(false);
    }
  }, []);

  

  

  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
    void getContextMenuStatus()
      .then((status) => {
        if (!status) return;
        if (status.installed && (!status.executableExists || status.stale)) {
          notify(
            "The Explorer integration points to a different BinScope executable. Open Settings → Windows Integration to repair it.",
          );
        }
      })
      .catch(() => {
        

      });
  }, [notify]);

  const tabs = useMemo(() => TABS, []);

  const navGroups: Array<{
    label: string;
    items: Array<{ id: ViewId; label: string; index: string }>;
  }> = [
    {
      label: "Specimen",
      items: [
        { id: "analyze", label: "Analyze", index: "01" },
        { id: "batch", label: "Batch", index: "02" },
        { id: "history", label: "History", index: "03" },
      ],
    },
    {
      label: "Evidence",
      items: [
        { id: "signatures", label: "Signatures", index: "04" },
        { id: "yara", label: "YARA Rules", index: "05" },
        { id: "sources", label: "Sources", index: "06" },
      ],
    },
    {
      label: "System",
      items: [{ id: "settings", label: "Settings", index: "07" }],
    },
  ];

  const headings: Record<ViewId, string> = {
    analyze: "Analyze",
    batch: "Batch",
    signatures: "Signatures",
    yara: "YARA Rules",
    sources: "Sources",
    history: "History",
    settings: "Settings",
  };

  const toolbarContext =
    view === "analyze"
      ? report
        ? `${report.format.label}, ${report.format.architecture || "unknown arch"}`
        : "No file selected"
      : view === "batch"
        ? "Queue, concurrency and exports"
      : view === "history"
        ? `${fmtNum(history.length)} local entries`
        : view === "settings"
          ? "Preferences are stored locally"
          : "Detection rules and sources";

  const entryPoint = report?.pe
    ? fmtHex(report.pe.entryPointRva, 8)
    : report?.elf?.entryPoint
      ? fmtHex(report.elf.entryPoint, 8)
      : null;

  return (
    <div className={`shell ${dragging ? "is-dragging" : ""}`}>
      <aside className="rail">
        <div className="rail-brand">
          <span className="rail-mark mono" aria-hidden="true">
            BS
          </span>
          <span className="rail-name">BinScope</span>
        </div>
        <nav className="rail-nav" aria-label="Primary">
          {navGroups.map((group) => (
            <div className="rail-group" key={group.label}>
              <div className="rail-group-label">{group.label}</div>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={`rail-item ${view === item.id ? "active" : ""}`}
                  aria-current={view === item.id ? "page" : undefined}
                  onClick={() => setView(item.id)}
                >
                  <span className="rail-index mono" aria-hidden="true">
                    {item.index}
                  </span>
                  <span className="rail-label">{item.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="rail-foot">
          <strong>YARA-X {appInfo?.yaraEngineVersion ?? ""}</strong>
          <span>{settings?.yaraEnabled ? "engine ready" : "engine disabled"}</span>
          <span>
            {report
              ? `${fmtNum(report.yara.ruleCount)} rules · ${fmtNum(report.yara.externalSources)} external files`
              : settings?.yaraEnabled
                ? "no specimen loaded"
                : "scanning off"}
          </span>
        </div>
      </aside>

      <div className="work">
        <header className="app-toolbar">
          <div className="app-toolbar-title">
            <h1>{headings[view]}</h1>
            <span className="app-toolbar-context">{toolbarContext}</span>
          </div>
          <div className="app-toolbar-actions">
            {view === "analyze" && (
              <>
                <button type="button" className="primary" onClick={openFile} disabled={analyzing}>
                  Open file
                </button>
                {report && (
                  <>
                    <button type="button" className="ghost" onClick={() => void doExport("json")}>
                      Export JSON
                    </button>
                    <button type="button" className="ghost" onClick={() => void doExport("txt")}>
                      Export TXT
                    </button>
                  </>
                )}
              </>
            )}
            {view === "history" && (
              <>
                <button type="button" className="ghost" onClick={() => void refreshHistory()} disabled={historyBusy}>
                  Refresh
                </button>
                <button type="button" className="ghost" onClick={() => void clearAllHistory()} disabled={historyBusy || history.length === 0}>
                  Clear history
                </button>
              </>
            )}
          </div>
        </header>

        <main className="stage" aria-label={headings[view]}>
          <h2 className="visually-hidden">{headings[view]} workspace</h2>
          {error && (
            <div className="error-banner" role="alert">
              <span>{error}</span>
              <button type="button" className="ghost small-button" onClick={() => setError(null)}>
                Dismiss
              </button>
            </div>
          )}

          {view === "analyze" && (
            <section className="analyze">
              {analyzing && progress && (
                <div className="progress-strip" role="status" aria-live="polite">
                  <div className="progress-label">
                    <span>{progress.message}</span>
                    <span className="mono">{progress.percent}%</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${Math.max(progress.percent, 2)}%` }} />
                  </div>
                  <button type="button" className="ghost small-button" onClick={() => void cancel()} disabled={cancelling}>
                    {cancelling ? "Cancelling…" : "Cancel"}
                  </button>
                </div>
              )}

              {report ? (
                <>
                  <section className="file-strip specimen-head">
                    <div className="file-strip-main">
                      <div className="file-strip-name">
                        <strong title={report.file.path}>{report.file.name}</strong>
                        <span className="specimen-kind mono">
                          {report.format.label} · {report.file.sizeHuman}
                        </span>
                        <span
                          className={`specimen-status ${
                            report.analysis.status === "complete"
                              ? "is-ok"
                              : report.analysis.status === "partial"
                                ? "is-warn"
                                : "is-bad"
                          }`}
                        >
                          STATIC {statusLabel(report.analysis.status).toUpperCase()}
                        </span>
                      </div>
                      <div className="file-strip-path" title={report.file.path}>
                        {report.file.path}
                      </div>
                    </div>
                    <div className="file-strip-actions">
                      <button type="button" className="ghost small-button" onClick={() => setReport(null)}>
                        Close
                      </button>
                    </div>
                  </section>

                  <section className="meta-grid">
                    <div className="meta-cell">
                      <span className="meta-label">File type</span>
                      <span className="meta-value" title={report.format.description}>{report.format.fileType}</span>
                    </div>
                    <div className="meta-cell">
                      <span className="meta-label">Architecture</span>
                      <span className="meta-value">
                        {report.format.architecture || "unknown"}
                        {report.format.bits ? `, ${report.format.bits}-bit` : ""}
                      </span>
                    </div>
                    <div className="meta-cell">
                      <span className="meta-label">Size</span>
                      <span className="meta-value mono">{report.file.sizeHuman}</span>
                    </div>
                    <div className="meta-cell">
                      <span className="meta-label">Entry point</span>
                      <span className="meta-value mono">{entryPoint ?? "—"}</span>
                    </div>
                    <div className="meta-cell">
                      <span className="meta-label">
                        {report.pe ? "PE TimeDateStamp" : "Modified"}
                      </span>
                      <span
                        className="meta-value mono"
                        title={
                          report.pe
                            ? "COFF TimeDateStamp. Attacker-controllable; not proof of compilation."
                            : "Filesystem modification time."
                        }
                      >
                        {shortStamp(report.pe?.timeDateStampUtc ?? report.file.modifiedUtc)}
                      </span>
                    </div>
                    <div className="meta-cell">
                      <span className="meta-label">SHA-256</span>
                      <span className="meta-value">
                        <code className="mono" title={report.file.sha256}>
                          {report.file.sha256.slice(0, 20)}…{report.file.sha256.slice(-12)}
                        </code>
                        <CopyButton value={report.file.sha256} label="copy" onCopied={notify} />
                      </span>
                    </div>
                  </section>

                  <div className="verdict-line">
                    <QuickStat label="Compiler" values={report.summary.compilers} />
                    <QuickStat label="Linker" values={report.summary.linkers} />
                    <QuickStat label="Packer" values={report.summary.packers} />
                    <QuickStat label="Protector" values={report.summary.protectors} />
                    <QuickStat label="Runtime" values={report.summary.runtimes} />
                    <QuickStat label="Language" values={report.summary.languages} />
                    <div className="verdict">
                      <span>YARA</span>
                      <strong>{report.yara.enabled ? `${fmtNum(report.yara.matches.length)} matches` : "disabled"}</strong>
                    </div>
                    <div className="verdict">
                      <span>Structural anomalies</span>
                      <strong>{fmtNum(report.pe?.anomalies.length ?? 0)}</strong>
                    </div>
                  </div>
                  <p className="evidence-caveat">
                    Static structural evidence, not a malware verdict. Detection provenance is
                    preserved per engine.
                  </p>

                  <nav className="tabs" role="tablist" aria-label="Analysis results">
                    {tabs.map((tab, index) => (
                      <button
                        key={tab.id}
                        type="button"
                        role="tab"
                        aria-selected={activeTab === tab.id}
                        className={`tab ${
                          ["pe", "signatures", "virustotal", "logs"].includes(tab.id)
                            ? "tab-group-start"
                            : ""
                        } ${activeTab === tab.id ? "active" : ""}`}
                        onClick={() => setActiveTab(tab.id)}
                      >
                        <span className="tab-index mono" aria-hidden="true">
                          {String(index + 1).padStart(2, "0")}
                        </span>
                        {tab.label}
                        {tab.id === "signatures" && report.detections.length > 0 && (
                          <span className="tab-count">{report.detections.length}</span>
                        )}
                        {tab.id === "yara" && report.yara.matches.length > 0 && (
                          <span className="tab-count">{report.yara.matches.length}</span>
                        )}
                      </button>
                    ))}
                  </nav>

                  <section className="tab-content">
                    {activeTab === "summary" && <SummaryTab report={report} onNotify={notify} />}
                    {activeTab === "pe" && <PeTab report={report} onNotify={notify} />}
                    {activeTab === "strings" && <StringsTab report={report} onNotify={notify} />}
                    {activeTab === "imports" && <ImportsTab report={report} />}
                    {activeTab === "sections" && <SectionsTab report={report} />}
                    {activeTab === "signatures" && <SignaturesTab report={report} />}
                    {activeTab === "yara" && <YaraTab report={report} />}
                    {activeTab === "logs" && <LogsTab report={report} />}
                    {activeTab === "virustotal" && (
                      <VirusTotalTab
                        report={report}
                        settings={settings}
                        keyConfigured={keyConfigured}
                        onOpenSettings={() => setView("settings")}
                        onNotify={notify}
                      />
                    )}
                  </section>
                </>
              ) : (
                <div className="analyze-idle">
                  <section
                    className={`intake-ledger ${dragging ? "is-dragging" : ""}`}
                    onDragOver={(event) => event.preventDefault()}
                    onDrop={(event) => event.preventDefault()}
                  >
                    <div className="intake-primary">
                      <div className="intake-index mono">INTAKE / 01</div>
                      <h2>{analyzing ? "Analyzing specimen" : "Record a specimen"}</h2>
                      <p>
                        PE, .NET, ELF, Mach-O, archives, scripts and unknown files are parsed
                        statically. Nothing is executed, loaded or uploaded.
                      </p>
                      <div className="intake-actions">
                        <button type="button" className="primary" onClick={openFile} disabled={analyzing}>
                          Open file
                        </button>
                        <span className="muted small">or drop a file anywhere in this window</span>
                      </div>
                      <ol className="intake-steps">
                        <li>
                          <span className="mono">01</span>
                          <div>
                            <strong>Identity</strong>
                            <p>Format, architecture, size and SHA-256.</p>
                          </div>
                        </li>
                        <li>
                          <span className="mono">02</span>
                          <div>
                            <strong>Structure</strong>
                            <p>Headers, sections, imports, exports, resources, CLR and debug data.</p>
                          </div>
                        </li>
                        <li>
                          <span className="mono">03</span>
                          <div>
                            <strong>Evidence</strong>
                            <p>Signatures, packers, protectors and YARA-X, each with its engine and source.</p>
                          </div>
                        </li>
                        <li>
                          <span className="mono">04</span>
                          <div>
                            <strong>Provenance</strong>
                            <p>Database revisions, rule-set revision, offsets and confidence.</p>
                          </div>
                        </li>
                      </ol>
                    </div>
                    <aside className="intake-record" aria-label="Recent specimens">
                      <div className="intake-record-head">
                        <span className="mono">RECENT SPECIMENS</span>
                        <button
                          type="button"
                          className="ghost small-button"
                          onClick={() => setView("history")}
                        >
                          Open history
                        </button>
                      </div>
                      {history.length === 0 ? (
                        <p className="intake-empty">
                          No specimens recorded yet. History stores metadata only, never file
                          contents.
                        </p>
                      ) : (
                        <div className="intake-recent">
                          {history.slice(0, 5).map((entry) => (
                            <button
                              key={entry.id}
                              type="button"
                              className="intake-recent-row"
                              onClick={() => reopenFromHistory(entry)}
                              title={entry.path}
                            >
                              <span className="intake-recent-name">{entry.name}</span>
                              <span className="mono intake-recent-hash">
                                {entry.sha256.slice(0, 12)}
                              </span>
                              <span className="mono intake-recent-meta">
                                {entry.format} · {entry.sizeHuman}
                              </span>
                            </button>
                          ))}
                        </div>
                      )}
                      <p className="intake-local">
                        Local by default. VirusTotal is opt-in and receives only the SHA-256 after
                        confirmation.
                      </p>
                    </aside>
                  </section>
                </div>
              )}
            </section>
          )}

          {view === "batch" && (
            <BatchView
              onOpenReport={(next) => {
                setReport(next);
                setActiveTab("summary");
                setView("analyze");
              }}
              onNotify={notify}
            />
          )}

          {(view === "signatures" || view === "yara" || view === "sources") && (
            

            

            <DetectionRulesView section={view} onNotify={notify} />
          )}
          {view === "history" && (
            <HistoryView
              entries={history}
              busy={historyBusy}
              onReopen={reopenFromHistory}
              onRemove={(id) => void removeHistory(id)}
              onRefresh={() => void refreshHistory()}
            />
          )}
          {view === "settings" && (
            <SettingsView
              settings={settings}
              appInfo={appInfo}
              keyConfigured={keyConfigured}
              onSaved={settingsSaved}
              onKeyChanged={(configured) => {
                setKeyConfigured(configured);
                void refreshKeyState();
              }}
              onNotify={notify}
              onThemeChange={(theme) => void changeTheme(theme)}
              onOpenView={(next) => setView(next)}
            />
          )}
        </main>

        <footer className="statusbar">
          <span className="status-brand">BinScope {appInfo?.version ?? ""}</span>
          <span>YARA-X {report?.yara.engineVersion ?? appInfo?.yaraEngineVersion ?? ""}</span>
          {report && (
            <>
              <span>
                {view === "analyze" ? "" : "last report · "}
                {fmtNum(report.detections.length)}{" "}
                {report.detections.length === 1 ? "detection" : "detections"}
              </span>
              <span>{fmtNum(report.analysis.durationMs)} ms</span>
              <span className="mono" title={report.yara.revision}>
                rev {report.yara.revision ? report.yara.revision.slice(0, 8) : "unavailable"}
              </span>
              <span>
                {fmtNum(report.yara.ruleCount)} rules ·{" "}
                {fmtNum(report.yara.compile?.errors.length ?? 0)} rejected
              </span>
            </>
          )}
          <span className="spacer" />
          <span>{settings?.virustotalEnabled ? "VirusTotal enabled" : "Local only"}</span>
          <span>{history.length > 0 ? `${fmtNum(history.length)} in history` : "History empty"}</span>
        </footer>
      </div>

      {toast && (
        <div className="toast" role="status" aria-live="polite">
          {toast}
        </div>
      )}
    </div>
  );
}

function QuickStat({
  label,
  values,
  hideWhenEmpty = true,
}: {
  label: string;
  values: string[];
  hideWhenEmpty?: boolean;
}) {
  const text = values.join(", ");
  if (hideWhenEmpty && values.length === 0) {
    return null;
  }
  return (
    <div className="verdict">
      <span>{label}</span>
      <strong title={text}>{text || "none"}</strong>
    </div>
  );
}

function contextMenuLabel(status: ContextMenuStatus | null): string {
  if (!status) return "Checking";
  switch (status.state) {
    case "unavailable":
      return "Unavailable";
    case "enabled":
      return "Enabled";
    case "stale":
      return "Enabled (stale path)";
    case "partial":
      return "Enabled (incomplete)";
    case "foreign":
      return "Conflicting registration";
    case "failed":
      return "State unreadable";
    default:
      return status.requiresAdmin ? "Disabled (permission required)" : "Disabled";
  }
}

function contextMenuTone(
  status: ContextMenuStatus | null,
): "ok" | "warn" | "danger" | "neutral" {
  if (!status || !status.supported) return "neutral";
  switch (status.state) {
    case "enabled":
      return "ok";
    case "stale":
    case "partial":
      return "warn";
    case "foreign":
    case "failed":
      return "danger";
    default:
      return status.requiresAdmin ? "warn" : "neutral";
  }
}
function SettingsView({
  settings,
  appInfo,
  keyConfigured,
  onSaved,
  onKeyChanged,
  onNotify,
  onThemeChange,
  onOpenView,
}: {
  settings: AppSettings | null;
  appInfo: AppInfo | null;
  keyConfigured: boolean;
  onSaved: (settings: AppSettings) => void;
  onKeyChanged: (configured: boolean) => void;
  onNotify: (message: string) => void;
  onThemeChange: (theme: string) => void;
  onOpenView: (view: ViewId) => void;
}) {
  const [draft, setDraft] = useState<AppSettings | null>(settings);
  const [saving, setSaving] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [keyBusy, setKeyBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updates, setUpdates] = useState<UpdateState | null>(null);
  const [updateBusy, setUpdateBusy] = useState<string | null>(null);
  const [yaraUrl, setYaraUrl] = useState("");
  const [yaraVersion, setYaraVersion] = useState("");
  const [yaraSha, setYaraSha] = useState("");
  const [menuStatus, setMenuStatus] = useState<ContextMenuStatus | null>(null);
  const [menuBusy, setMenuBusy] = useState(false);
  const [menuError, setMenuError] = useState<string | null>(null);
  const [menuNotice, setMenuNotice] = useState<string | null>(null);
  const [rulePrefs, setRulePrefs] = useState<RulePreferences | null>(null);

  useEffect(() => {
    getRulePreferences()
      .then(setRulePrefs)
      .catch(() => setRulePrefs(null));
  }, []);

  const saveUpdatePolicy = async (next: RulePreferences) => {
    setRulePrefs(next);
    try {
      const stored = await saveRulePreferences(next);
      setRulePrefs(stored);
      onNotify("Update policy saved");
    } catch (err) {
      setError(errorText(err));
    }
  };

  useEffect(() => {
    getUpdateState().then(setUpdates).catch(() => setUpdates(null));
  }, []);

  

  

  const refreshMenuStatus = useCallback(async () => {
    try {
      const status = await getContextMenuStatus();
      setMenuStatus(status);
    } catch (err) {
      setMenuError(contextMenuErrorText(err));
    }
  }, []);

  useEffect(() => {
    void refreshMenuStatus();
  }, [refreshMenuStatus]);

  const applyContextMenu = async (enabled: boolean) => {
    if (menuBusy) return;
    const confirmed = window.confirm(
      enabled
        ? 'Add "Analyze with BinScope" to the right-click menu for files, for the current Windows user?'
        : "Remove the BinScope Explorer entry that BinScope installed? Entries from other programs are not touched.",
    );
    if (!confirmed) return;
    setMenuBusy(true);
    setMenuError(null);
    setMenuNotice(null);
    try {
      const next = enabled ? await enableContextMenu() : await disableContextMenu();
      setMenuStatus(next);
      const message = enabled
        ? "Added \"Analyze with BinScope\" to the Windows context menu"
        : "Removed the BinScope Windows context-menu entry";
      setMenuNotice(message);
      onNotify(message);
    } catch (err) {
      setMenuError(contextMenuErrorText(err));
      

      await refreshMenuStatus();
    } finally {
      setMenuBusy(false);
    }
  };

  const applyContextMenuRepair = async () => {
    if (menuBusy) return;
    setMenuBusy(true);
    setMenuError(null);
    setMenuNotice(null);
    try {
      const next = await repairContextMenuRegistration();
      setMenuStatus(next);
      setMenuNotice(`Explorer registration repaired for ${next.registeredExecutable ?? "this executable"}.`);
      onNotify("Windows context-menu registration repaired");
    } catch (err) {
      setMenuError(contextMenuErrorText(err));
      await refreshMenuStatus();
    } finally {
      setMenuBusy(false);
    }
  };

  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  if (!draft) {
    return (
      <div className="settings-view">
        <div className="settings-scroll">
          <p className="muted">Loading settings…</p>
        </div>
      </div>
    );
  }

  const update = <K extends keyof AppSettings,>(key: K, value: AppSettings[K]) => {
    setDraft({ ...draft, [key]: value });
  };

  const dirty = settings ? JSON.stringify(draft) !== JSON.stringify(settings) : true;

  const saveAll = async () => {
    setSaving(true);
    setError(null);
    const minLen = Math.min(1024, Math.max(1, Number(draft.minStringLen) || 4));
    const maxStrings = Math.min(500_000, Math.max(1000, Number(draft.maxStrings) || 100_000));
    const cleaned: AppSettings = {
      ...draft,
      minStringLen: minLen,
      maxStrings,
      yaraRuleDirs: draft.yaraRuleDirs.map((path) => path.trim()).filter(Boolean),
      signatureDirs: draft.signatureDirs.map((path) => path.trim()).filter(Boolean),
    };
    try {
      const stored = await saveSettings(cleaned);
      onSaved(stored);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setSaving(false);
    }
  };

  const storeKey = async () => {
    if (!apiKey.trim()) return;
    setKeyBusy(true);
    setError(null);
    try {
      await vtSetKey(apiKey.trim());
      setApiKey("");
      onKeyChanged(true);
      onNotify("VirusTotal API key stored in Windows Credential Manager");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setKeyBusy(false);
    }
  };

  const clearKey = async () => {
    setKeyBusy(true);
    setError(null);
    try {
      await vtClearKey();
      onKeyChanged(false);
      onNotify("VirusTotal API key removed");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setKeyBusy(false);
    }
  };

  const restoreBundled = () => {
    setDraft({
      ...draft,
      yaraRuleDirs: appInfo?.bundledYaraDir ? [appInfo.bundledYaraDir] : draft.yaraRuleDirs,
      dieSignatureDir: appInfo?.bundledDieDir ?? draft.dieSignatureDir,
      signatureDirs: [],
    });
  };

  const runDieUpdate = async () => {
    if (!window.confirm("Download and install the official DIE database release? The archive is verified by SHA-256 before activation.")) return;
    setUpdateBusy("die");
    setError(null);
    try {
      await updateDieDatabase(true);
      setUpdates(await getUpdateState());
      const settings = await loadSettings();
      setDraft(settings);
      onNotify("DIE database updated. Run a new analysis to use it.");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setUpdateBusy(null);
    }
  };

  const runPebearUpdate = async () => {
    if (!window.confirm("Download PE-bear SIG.txt (GPLv2, derived from PEiD UserDB)?")) return;
    if (!window.confirm("PE-bear SIG.txt is GPLv2 data and is NOT redistributed with BinScope. Do you accept its license and want to install it locally?")) return;
    setUpdateBusy("pebear");
    setError(null);
    try {
      await updatePebearSignatures(true, true);
      setUpdates(await getUpdateState());
      const settings = await loadSettings();
      setDraft(settings);
      onNotify("PE-bear signatures installed. Run a new analysis to use them.");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setUpdateBusy(null);
    }
  };

  const runYaraUpdate = async () => {
    if (!yaraUrl.trim() || !yaraUrl.startsWith("https://")) {
      setError("Enter an HTTPS URL for a ZIP containing .yar/.yara files.");
      return;
    }
    if (!window.confirm("Download, compile-test and atomically activate this YARA rule archive?")) return;
    setUpdateBusy("yara");
    setError(null);
    try {
      await updateYaraRules(
        yaraUrl.trim(),
        yaraSha.trim() || null,
        yaraVersion.trim() || "custom",
        true,
      );
      setUpdates(await getUpdateState());
      const settings = await loadSettings();
      setDraft(settings);
      onNotify("YARA rules updated and compiled successfully.");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setUpdateBusy(null);
    }
  };

  return (
    <div className="settings-view">
      <div className="settings-scroll">
        {error && <div className="error-box">{error}</div>}

        <section className="settings-section">
          <h3>Appearance</h3>
          <p className="muted small">
            Choose how BinScope looks. System follows the Windows color scheme; the change applies
            immediately and is stored with the rest of the preferences.
          </p>
          <div className="segmented" role="group" aria-label="Theme">
            {[
              ["system", "System"],
              ["light", "Light"],
              ["dark", "Dark"],
            ].map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={`segmented-item ${draft.theme === value ? "active" : ""}`}
                aria-pressed={draft.theme === value}
                onClick={() => {
                  update("theme", value);
                  onThemeChange(value);
                }}
              >
                {label}
              </button>
            ))}
          </div>
        </section>

        <section className="settings-section">
          <h3>Detection Rules</h3>
          <p className="muted small">
            Choose YARA-X categories and signatures independently, inspect sources, import your own rules
            and manage automatic updates.
          </p>
          <div className="toolbar">
            <button type="button" onClick={() => onOpenView("yara")}>
              YARA Rules
            </button>
            <button type="button" className="ghost" onClick={() => onOpenView("signatures")}>
              Signatures
            </button>
            <button type="button" className="ghost" onClick={() => onOpenView("sources")}>
              Sources
            </button>
          </div>
        </section>

        <section className="settings-section">
          <h3>Windows Integration</h3>
          <Toggle
            checked={menuStatus?.preferenceEnabled ?? false}
            onChange={(value) => void applyContextMenu(value)}
            label='Add "Analyze with BinScope" to Windows context menu'
            hint="Adds per-user Explorer entries for executable and binary files. The enabled preference is stored per user and survives moving the portable folder."
            disabled={menuBusy || !menuStatus?.supported}
          />
          <div className="integration-status">
            <Badge tone={contextMenuTone(menuStatus)}>{contextMenuLabel(menuStatus)}</Badge>
            <span className="muted small">
              {menuBusy
                ? "Applying the change to the Windows registry…"
                : menuStatus?.detail ?? "Reading the current Windows registration…"}
            </span>
          </div>
          {menuStatus?.installed && menuStatus.registeredExecutable && (
            <p className="muted small mono integration-path">{menuStatus.registeredExecutable}</p>
          )}
          {appInfo?.portable && menuStatus?.preferenceEnabled && (
            <p className="muted small">
              Portable entry: it always points to the current BinScope.exe. BinScope repairs a moved
              path automatically on the next launch; <strong>Repair registration</strong> does it
              immediately.
            </p>
          )}
          {menuStatus?.conflicts.map((conflict) => (
            <p className="warning-box" key={conflict}>
              {conflict}
            </p>
          ))}
          {menuError && <div className="error-box">{menuError}</div>}
          {menuNotice && !menuError && <p className="muted small">{menuNotice}</p>}
          <div className="toolbar">
            <button
              type="button"
              className="ghost"
              onClick={() => void refreshMenuStatus()}
              disabled={menuBusy}
            >
              Re-check status
            </button>
            {menuStatus?.preferenceEnabled && menuStatus.state !== "enabled" && (
              <button
                type="button"
                onClick={() => void applyContextMenuRepair()}
                disabled={menuBusy}
              >
                Repair registration
              </button>
            )}
          </div>
          <p className="muted small">
            Windows 10 shows the entry in the classic context menu. Windows 11 lists it under{" "}
            <strong>Show more options</strong>: the first-level Windows 11 menu needs a packaged shell
            extension, which BinScope does not install. Only files are registered, and BinScope analyses the
            selected file without executing it.
          </p>
          {menuStatus && menuStatus.supported && (
            <p className="muted small mono">
              {menuStatus.registrations.filter((item) => item.installed && item.current && item.commandOk).length}
              /{menuStatus.registrations.length} targets current
              {menuStatus.missingTargets.length > 0
                ? ` · ${menuStatus.missingTargets.length} missing`
                : ""}
              {menuStatus.staleTargets.length > 0
                ? ` · ${menuStatus.staleTargets.length} stale`
                : ""}
            </p>
          )}
          {menuStatus?.diagnostics.length ? (
            <details className="integration-diagnostics">
              <summary>Registration diagnostics</summary>
              <ul className="plain-list">
                {menuStatus.diagnostics.map((line, index) => (
                  <li key={`${line}-${index}`} className="mono small">{line}</li>
                ))}
              </ul>
            </details>
          ) : null}
        </section>

        <section className="settings-section">
          <h3>Analysis</h3>
          <Toggle
            checked={draft.includeStrings}
            onChange={(value) => update("includeStrings", value)}
            label="Extract strings"
            hint="Required for the Strings tab and string-based signatures."
          />
          <div className="settings-grid">
            <label>
              Minimum string length
              <input
                type="number"
                min={1}
                max={1024}
                value={draft.minStringLen}
                onChange={(event) => update("minStringLen", Number(event.target.value))}
              />
            </label>
            <label>
              Maximum strings
              <input
                type="number"
                min={1000}
                max={500000}
                step={1000}
                value={draft.maxStrings}
                onChange={(event) => update("maxStrings", Number(event.target.value))}
              />
            </label>
          </div>
          <p className="muted small">
            Files up to 512 MiB are parsed structurally. Larger files are streamed for hashing and strings; structural
            analysis is skipped and reported explicitly.
          </p>
        </section>

        <section className="settings-section">
          <h3>Signatures</h3>
          <Toggle
            checked={draft.signaturesEnabled}
            onChange={(value) => update("signaturesEnabled", value)}
            label="Enable signature engine"
          />
          <Toggle
            checked={draft.builtinSignatures}
            onChange={(value) => update("builtinSignatures", value)}
            label="Use built-in signature database"
            hint="Compilers, linkers, packers, protectors and installers."
            disabled={!draft.signaturesEnabled}
          />
          <label className="stacked-label">
            Additional signature directories (one path per line)
            <textarea
              rows={3}
              spellCheck={false}
              value={draft.signatureDirs.join("\n")}
              onChange={(event) => update("signatureDirs", event.target.value.split("\n"))}
              placeholder="C:\\rules\\binscope-signatures"
            />
          </label>
        </section>

        <section className="settings-section">
          <h3>Signature databases</h3>
          <Toggle
            checked={draft.dieEnabled}
            onChange={(value) => update("dieEnabled", value)}
            label="Use Detect It Easy signatures"
            hint="Official DIE database, evaluated through a documented subset adapter. Full DiE-JS compatibility is not claimed."
          />
          <label className="stacked-label">
            DIE database directory (contains PE/*.sg)
            <input
              type="text"
              value={draft.dieSignatureDir ?? ""}
              onChange={(event) => update("dieSignatureDir", event.target.value || null)}
              placeholder={appInfo?.bundledDieDir ?? "databases\\die\\PE"}
            />
          </label>
          <div className="toolbar">
            <button type="button" onClick={() => void runDieUpdate()} disabled={updateBusy !== null}>
              {updateBusy === "die" ? "Updating DIE…" : "Update DIE database"}
            </button>
            <span className="muted small">
              {updates?.die
                ? `${updates.die.version}, ${updates.die.files} files, +${updates.die.added} ~${updates.die.modified} -${updates.die.removed}, ${updates.die.updatedAt}`
                : "No downloaded update yet; bundled database is used."}
            </span>
          </div>

          <Toggle
            checked={draft.pebearEnabled}
            onChange={(value) => update("pebearEnabled", value)}
            label="Use PE-bear SIG.txt"
            hint="Optional GPLv2 data derived from PEiD UserDB. Not redistributed with BinScope; download explicitly."
          />
          <label className="stacked-label">
            PE-bear SIG.txt path
            <input
              type="text"
              value={draft.pebearSigPath ?? ""}
              onChange={(event) => update("pebearSigPath", event.target.value || null)}
              placeholder="%APPDATA%\\...\\pebear\\SIG.txt"
            />
          </label>
          <div className="toolbar">
            <button type="button" onClick={() => void runPebearUpdate()} disabled={updateBusy !== null}>
              {updateBusy === "pebear" ? "Downloading PE-bear…" : "Download PE-bear signatures"}
            </button>
            <span className="muted small">
              {updates?.pebear
                ? `${updates.pebear.files} signatures, +${updates.pebear.added} ~${updates.pebear.modified}, ${updates.pebear.updatedAt}`
                : "Not installed."}
            </span>
          </div>
          {appInfo?.bundledDieDir && (
            <button type="button" className="ghost" onClick={restoreBundled}>
              Restore bundled DIE path
            </button>
          )}
        </section>

        <section className="settings-section">
          <h3>YARA-X</h3>
          <Toggle
            checked={draft.yaraEnabled}
            onChange={(value) => update("yaraEnabled", value)}
            label="Enable YARA-X scanning"
          />
          <label className="stacked-label">
            Rule directories (one path per line, scanned recursively)
            <textarea
              rows={3}
              spellCheck={false}
              value={draft.yaraRuleDirs.join("\n")}
              onChange={(event) => update("yaraRuleDirs", event.target.value.split("\n"))}
              placeholder="C:\\rules\\yara"
            />
          </label>
          <div className="toolbar">
            <button type="button" className="ghost" onClick={restoreBundled} disabled={!appInfo?.bundledYaraDir}>
              Restore bundled rules path
            </button>
            <span className="muted small">Bundled: {appInfo?.bundledYaraDir ?? "not found"}</span>
          </div>
          <div className="settings-grid">
            <label>
              Rule archive URL (HTTPS ZIP)
              <input
                type="text"
                value={yaraUrl}
                onChange={(event) => setYaraUrl(event.target.value)}
                placeholder="https://example.org/rules.zip"
              />
            </label>
            <label>
              Version label
              <input
                type="text"
                value={yaraVersion}
                onChange={(event) => setYaraVersion(event.target.value)}
                placeholder="2026-10"
              />
            </label>
            <label>
              SHA-256 (optional)
              <input
                type="text"
                value={yaraSha}
                onChange={(event) => setYaraSha(event.target.value)}
                placeholder="hex digest"
              />
            </label>
          </div>
          <div className="toolbar">
            <button type="button" onClick={() => void runYaraUpdate()} disabled={updateBusy !== null}>
              {updateBusy === "yara" ? "Compiling rules…" : "Update YARA rules"}
            </button>
            <span className="muted small">
              {updates?.yara
                ? `${updates.yara.files} rules, +${updates.yara.added} ~${updates.yara.modified} -${updates.yara.removed}, ${updates.yara.updatedAt}`
                : "Using bundled rules until an update is installed."}
            </span>
          </div>
          <p className="muted small">
            The archive is compiled in a staging directory with YARA-X before activation. If any rule
            fails to compile, the previous rule set remains active.
          </p>
          <p className="muted small">
            Broken rule files are reported individually; valid rules in the same run are still applied. Scanning is
            bounded by a timeout.
          </p>
        </section>

        <section className="settings-section">
          <h3>VirusTotal (optional)</h3>
          <Toggle
            checked={draft.virustotalEnabled}
            onChange={(value) => update("virustotalEnabled", value)}
            label="Enable VirusTotal integration"
            hint="Disabled by default. Local analysis works fully offline."
          />
          <p className="muted small">
            The API key is stored in the Windows Credential Manager (service <code>binscope</code>), never in settings
            files, reports or source code. Lookups send only the SHA-256. Uploads require a separate confirmation.
          </p>
          <div className="toolbar">
            <input
              type="password"
              autoComplete="off"
              placeholder={keyConfigured ? "Key configured — enter a new key to replace" : "VirusTotal API key"}
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              className="key-input"
            />
            <button type="button" onClick={() => void storeKey()} disabled={keyBusy || !apiKey.trim()}>
              Store key
            </button>
            <button type="button" className="ghost" onClick={() => void clearKey()} disabled={keyBusy || !keyConfigured}>
              Remove key
            </button>
            <Badge tone={keyConfigured ? "ok" : "neutral"}>{keyConfigured ? "key configured" : "no key"}</Badge>
          </div>
        </section>

        <section className="settings-section">
          <h3>Automatic Updates</h3>
          <p className="muted small">
            Checks run at startup and at the selected interval. A check without upstream changes keeps
            the installed rules; a failed update never removes the previous database.
          </p>
          {rulePrefs ? (
            <div className="settings-row">
              <Toggle
                checked={rulePrefs.update.autoCheck}
                onChange={(value) =>
                  void saveUpdatePolicy({
                    ...rulePrefs,
                    update: { ...rulePrefs.update, autoCheck: value },
                  })
                }
                label="Check for rule updates automatically"
                hint="Sources are checked in the background; failures are logged, not hidden."
              />
              <label className="stacked-label">
                Frequency
                <select
                  value={rulePrefs.update.intervalHours}
                  onChange={(event) =>
                    void saveUpdatePolicy({
                      ...rulePrefs,
                      update: {
                        ...rulePrefs.update,
                        intervalHours: Number(event.target.value),
                      },
                    })
                  }
                >
                  <option value={6}>Every 6 hours</option>
                  <option value={12}>Every 12 hours</option>
                  <option value={24}>Once a day</option>
                  <option value={72}>Every 3 days</option>
                  <option value={168}>Weekly</option>
                </select>
              </label>
              <span className="muted small">
                Last check: {rulePrefs.update.lastCheck ?? "never"}. Last install:{" "}
                {rulePrefs.update.lastUpdate ?? "never"}
              </span>
            </div>
          ) : (
            <p className="muted small">Update preferences are unavailable.</p>
          )}
        </section>

        <section className="settings-section">
          <h3>Storage</h3>
          <div className="settings-grid">
            <label className="stacked-label">
              Mode
              <input
                type="text"
                value={
                  appInfo?.portable
                    ? "Portable (per-user data)"
                    : "Per-user installation"
                }
                readOnly
              />
            </label>
            <label className="stacked-label">
              Application data
              <input type="text" value={appInfo?.dataDir ?? ""} readOnly />
            </label>
            <label className="stacked-label">
              Bundled YARA rules
              <input type="text" value={appInfo?.bundledYaraDir ?? "not bundled"} readOnly />
            </label>
            <label className="stacked-label">
              Bundled DIE database
              <input type="text" value={appInfo?.bundledDieDir ?? "not bundled"} readOnly />
            </label>
            <label className="stacked-label">
              Bundled signatures
              <input type="text" value={appInfo?.bundledSignatureDir ?? "not bundled"} readOnly />
            </label>
          </div>
          <p className="muted small">
            Databases, imported rules and preferences stay on this machine. Paths are shown for
            diagnostics only; there is no cloud storage.
          </p>
          {appInfo?.portable && (
            <p className="muted small">
              Portable mode: settings, rules and history live in the per-user folder shown above, not in
              the application folder. The folder can be moved or run from removable media; Explorer
              registration repairs itself on the next launch.
            </p>
          )}
        </section>

        <section className="settings-section">
          <h3>Privacy</h3>
          <Toggle
            checked={draft.retainHistory}
            onChange={(value) => update("retainHistory", value)}
            label="Keep local analysis history"
            hint="Stores name, path, hashes, size and detection counts only. File contents are never stored."
          />
          <p className="muted small">
            Analysis is local. VirusTotal lookups send only the SHA-256 and require the integration to be
            enabled. Uploads never happen automatically and need an explicit confirmation.
          </p>
        </section>

        <section className="settings-section">
          <h3>Diagnostics</h3>
          <div className="settings-grid">
            <label className="stacked-label">
              Application version
              <input type="text" value={appInfo?.version ?? ""} readOnly />
            </label>
            <label className="stacked-label">
              YARA-X engine
              <input type="text" value={appInfo?.yaraEngineVersion ?? ""} readOnly />
            </label>
            <label className="stacked-label">
              DIE database last update
              <input type="text" value={updates?.die?.updatedAt ?? "never"} readOnly />
            </label>
            <label className="stacked-label">
              YARA rules last update
              <input type="text" value={updates?.yara?.updatedAt ?? "never"} readOnly />
            </label>
          </div>
        </section>
      </div>

      <div className={`settings-actions ${dirty ? "is-dirty" : ""}`}>
        <span className="muted small">
          {dirty ? "Unsaved changes" : "No unsaved changes"} · settings apply to the next analysis.
        </span>
        <button
          type="button"
          className="primary"
          onClick={() => void saveAll()}
          disabled={saving || !dirty}
        >
          {saving ? "Saving…" : dirty ? "Save settings" : "Settings saved"}
        </button>
      </div>
    </div>
  );
}

function formatHistoryTime(value: string): string {
  return value.replace("T", " ").replace("Z", "");
}


function shortStamp(value: string | null | undefined): string {
  if (!value) return "—";
  return value.replace("T", " ").replace("Z", "").slice(0, 16);
}

function HistoryView({
  entries,
  busy,
  onReopen,
  onRemove,
  onRefresh,
}: {
  entries: HistoryEntry[];
  busy: boolean;
  onReopen: (entry: HistoryEntry) => void;
  onRemove: (id: string) => void;
  onRefresh: () => void;
}) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return entries;
    return entries.filter((entry) =>
      [entry.name, entry.path, entry.sha256, entry.format, entry.status]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [entries, query]);

  return (
    <section className="history-view">
      <div className="history-toolbar">
        <input
          type="search"
          className="search-input"
          value={query}
          placeholder="Search name, path or SHA-256"
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Search analysis history"
        />
        <span className="muted small">
          {filtered.length} of {entries.length} entries. Reopen runs the analysis again from the
          recorded path.
        </span>
      </div>
      <div className="history-table-wrap">
        <div className="history-row head" role="row">
          <span>Analyzed</span>
          <span>File</span>
          <span>SHA-256</span>
          <span>Status</span>
          <span>Detections</span>
          <span />
        </div>
        {filtered.map((entry) => (
          <div className="history-row" key={entry.id}>
            <span className="mono">{formatHistoryTime(entry.analyzedAt)}</span>
            <span className="history-name" title={entry.path}>
              {entry.name}
              <span className="muted small">, {entry.sizeHuman}, {entry.format}</span>
            </span>
            <span className="history-hash" title={entry.sha256}>
              {entry.sha256.slice(0, 16)}…
            </span>
            <Badge
              tone={
                entry.status === "complete" ? "ok" : entry.status === "partial" ? "warn" : "neutral"
              }
            >
              {entry.status}
            </Badge>
            <span className="mono">{fmtNum(entry.detections)}</span>
            <span className="history-actions">
              <button type="button" className="ghost small-button" onClick={() => onReopen(entry)}>
                Reopen
              </button>
              <button
                type="button"
                className="ghost small-button danger"
                onClick={() => onRemove(entry.id)}
                aria-label={`Remove ${entry.name} from history`}
              >
                Remove
              </button>
            </span>
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="history-empty">
            <p className="muted">
              {entries.length === 0
                ? "No analyses recorded yet. History keeps metadata only, never file contents."
                : "No entries match this search."}
            </p>
            {entries.length === 0 && (
              <button type="button" className="ghost" onClick={onRefresh} disabled={busy}>
                {busy ? "Loading…" : "Refresh"}
              </button>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function LogsTab({ report }: { report: Report }) {
  const issues = report.analysis.issues;
  return (
    <div className="logs">
      <div className="log-summary">
        <span>
          Started <span className="mono">{formatHistoryTime(report.analysis.startedUtc)}</span>
        </span>
        <span>
          Finished <span className="mono">{formatHistoryTime(report.analysis.finishedUtc)}</span>
        </span>
        <span>
          Duration <span className="mono">{fmtNum(report.analysis.durationMs)} ms</span>
        </span>
        <span>
          Parse limit <span className="mono">{fmtNum(report.analysis.parseLimitBytes)} bytes</span>
        </span>
      </div>
      <div className="log-lines">
        {issues.length === 0 && <p className="muted small">No issues were reported for this analysis.</p>}
        {issues.map((issue, index) => (
          <div className={`log-line level-${issue.level}`} key={`${issue.stage}-${index}`}>
            <span className="mono log-level">{issue.level}</span>
            <span className="mono log-stage">{issue.stage}</span>
            <span>{issue.message}</span>
          </div>
        ))}
        {report.notes.map((note, index) => (
          <div className="log-line" key={`note-${index}`}>
            <span className="mono log-level">note</span>
            <span className="mono log-stage">engine</span>
            <span>{note}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
