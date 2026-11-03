import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  addBatchPaths,
  cancelBatchJob,
  clearBatchJobs,
  createBatchJob,
  exportBatch,
  getBatchJob,
  getBatchReport,
  listBatchJobs,
  removeBatchJob,
  startBatchJob,
} from "./api";
import type {
  BatchExportRow,
  BatchFileState,
  BatchJobView,
  Report,
} from "./types";
import { fmtBytes, fmtNum } from "./format";
import { Badge } from "./ui";

const POLL_INTERVAL_MS = 400;

const STATE_TONE: Record<BatchFileState, string> = {
  queued: "neutral",
  hashing: "info",
  running: "info",
  completed: "ok",
  failed: "danger",
  cancelled: "warn",
  reused: "info",
};

function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

export function BatchView({
  onOpenReport,
  onNotify,
}: {
  onOpenReport: (report: Report) => void;
  onNotify: (message: string) => void;
}) {
  const [job, setJob] = useState<BatchJobView | null>(null);
  const [limit, setLimit] = useState(2);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const polling = useRef<number | null>(null);

  const running = job?.state === "running";
  const queued = job?.state === "queued";

  const refresh = useCallback(async (jobId: string) => {
    try {
      setJob(await getBatchJob(jobId));
    } catch (err) {
      

      setError(String(err));
    }
  }, []);

  useEffect(() => {
    let disposed = false;
    void listBatchJobs()
      .then((jobs) => {
        if (disposed || jobs.length === 0) return;
        const latest = [...jobs].sort((a, b) => a.id.localeCompare(b.id)).at(-1);
        if (latest) setJob(latest);
      })
      .catch(() => {});
    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    if (!job || job.state !== "running") {
      if (polling.current !== null) {
        window.clearInterval(polling.current);
        polling.current = null;
      }
      return;
    }
    const jobId = job.id;
    polling.current = window.setInterval(() => void refresh(jobId), POLL_INTERVAL_MS);
    return () => {
      if (polling.current !== null) {
        window.clearInterval(polling.current);
        polling.current = null;
      }
    };
  }, [job, refresh]);

  const ensureJob = useCallback(async (): Promise<BatchJobView | null> => {
    if (job && (job.state === "queued" || job.state === "running")) return job;
    const created = await createBatchJob({ concurrency: limit });
    setJob(created);
    return created;
  }, [job, limit]);

  const addFiles = async () => {
    setError(null);
    setBusy(true);
    try {
      const picked = await open({ multiple: true, title: "Add files to the batch" });
      if (!picked) return;
      const paths = Array.isArray(picked) ? picked : [picked];
      const target = await ensureJob();
      if (!target) return;
      setJob(await addBatchPaths(target.id, paths, false));
    } catch (err) {
      setError(`Could not add files: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const addFolder = async () => {
    setError(null);
    setBusy(true);
    try {
      const picked = await open({ directory: true, multiple: false, title: "Add a folder" });
      if (typeof picked !== "string") return;
      const target = await ensureJob();
      if (!target) return;
      setJob(await addBatchPaths(target.id, [picked], true));
    } catch (err) {
      setError(`Could not add the folder: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const run = async () => {
    if (!job || job.state !== "queued" || job.total === 0) return;
    setError(null);
    setBusy(true);
    try {
      await startBatchJob(job.id);
      await refresh(job.id);
    } catch (err) {
      setError(`Could not start the batch: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (!job) return;
    try {
      await cancelBatchJob(job.id);
      await refresh(job.id);
    } catch (err) {
      setError(String(err));
    }
  };

  const clearFinished = async () => {
    try {
      const result = await clearBatchJobs();
      if (job && (job.state === "completed" || job.state === "failed" || job.state === "cancelled")) {
        setJob(null);
      }
      onNotify(`Cleared ${fmtNum(result.removed)} finished job(s); ${fmtNum(result.remaining)} remaining.`);
    } catch (err) {
      setError(String(err));
    }
  };

  const closeJob = async () => {
    if (!job) return;
    try {
      await removeBatchJob(job.id);
      setJob(null);
    } catch (err) {
      setError(String(err));
    }
  };

  const openReport = async (index: number) => {
    if (!job) return;
    try {
      onOpenReport(await getBatchReport(job.id, index));
    } catch (err) {
      setError(`Could not open the report: ${String(err)}`);
    }
  };

  const exportRows = useMemo<BatchExportRow[]>(() => {
    if (!job) return [];
    return job.files.map((file) => ({
      file: file.name,
      path: file.path,
      sha256: file.sha256 ?? "",
      format: file.format ?? "",
      architecture: file.architecture ?? "",
      size: file.size ?? 0,
      anomalies: file.anomalies,
      yara: file.yara,
      signatures: file.signatures,
      debug: file.debug ?? "",
      status: file.state,
      reusedFrom:
        file.reusedFrom === null ? null : job.files[file.reusedFrom]?.name ?? null,
    }));
  }, [job]);

  const doExport = async (format: "csv" | "json") => {
    try {
      const target = await save({
        title: `Export batch results (${format.toUpperCase()})`,
        defaultPath: `binscope-batch.${format}`,
        filters: [{ name: format === "csv" ? "CSV" : "JSON", extensions: [format] }],
      });
      if (typeof target !== "string") return;
      await exportBatch(target, format, exportRows);
      onNotify(`Batch results exported to ${baseName(target)}`);
    } catch (err) {
      setError(`Export failed: ${String(err)}`);
    }
  };

  return (
    <section className="batch-view">
      <div className="history-toolbar">
        <button type="button" onClick={() => void addFiles()} disabled={running || busy}>
          Add files
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => void addFolder()}
          disabled={running || busy}
        >
          Add folder
        </button>
        <button
          type="button"
          className="primary"
          onClick={() => void run()}
          disabled={!queued || busy || (job?.total ?? 0) === 0}
        >
          {running ? `Running ${fmtNum(job?.running ?? 0)}` : `Analyze ${fmtNum(job?.queued ?? 0)} queued`}
        </button>
        <button type="button" className="ghost" onClick={() => void cancel()} disabled={!running}>
          Cancel
        </button>
        <label className="rules-label">
          Concurrency
          <select
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
            disabled={running || queued}
          >
            <option value={1}>1</option>
            <option value={2}>2</option>
            <option value={3}>3</option>
            <option value={4}>4</option>
          </select>
        </label>
        <span className="muted small">
          {fmtNum(job?.completed ?? 0)} completed · {fmtNum(job?.failed ?? 0)} failed ·{" "}
          {fmtNum(job?.cancelled ?? 0)} cancelled · {fmtNum(job?.reused ?? 0)} reused
        </span>
        <button
          type="button"
          className="ghost small-button"
          onClick={() => void clearFinished()}
          disabled={running}
        >
          Clear finished
        </button>
        <button
          type="button"
          className="ghost small-button"
          onClick={() => void doExport("csv")}
          disabled={!job || job.total === 0}
        >
          Export CSV
        </button>
        <button
          type="button"
          className="ghost small-button"
          onClick={() => void doExport("json")}
          disabled={!job || job.total === 0}
        >
          Export JSON
        </button>
      </div>
      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button type="button" className="ghost small-button" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}
      {job && (job.state === "completed" || job.state === "failed" || job.state === "cancelled") && (
        <div className="batch-summary-row">
          <Badge tone={job.state === "completed" ? "ok" : job.state === "failed" ? "danger" : "warn"}>
            job {job.state}
          </Badge>
          <span className="muted small mono">{job.id}</span>
          <button type="button" className="ghost small-button" onClick={() => void closeJob()}>
            Remove job
          </button>
        </div>
      )}
      {!job || job.total === 0 ? (
        <section className="batch-empty-ledger">
          <div className="batch-empty-index mono">QUEUE / 00</div>
          <h3>No files queued</h3>
          <p>
            Batch uses the same static pipeline as Analyze. Paths are hashed once, concurrency is
            bounded, and identical SHA-256 content reuses the first completed report in the job.
          </p>
          <ol>
            <li>
              <span className="mono">01</span>
              <div>
                <strong>Add files or a folder</strong>
                <p>Recursive traversal is bounded; every path remains visible in the queue.</p>
              </div>
            </li>
            <li>
              <span className="mono">02</span>
              <div>
                <strong>Choose concurrency</strong>
                <p>One to four local workers; cancellation stops the run cooperatively.</p>
              </div>
            </li>
            <li>
              <span className="mono">03</span>
              <div>
                <strong>Export the ledger</strong>
                <p>CSV or JSON with hashes, format, size, detections and per-file errors.</p>
              </div>
            </li>
          </ol>
        </section>
      ) : (
        <div className="batch-table-wrap">
          <table className="batch-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>File</th>
                <th>SHA-256</th>
                <th>Format</th>
                <th>Size</th>
                <th>Anom.</th>
                <th>YARA</th>
                <th>Sig.</th>
                <th>Debug</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {job.files.map((entry) => (
                <tr
                  key={entry.index}
                  className={entry.hasReport ? "selectable-row" : ""}
                  onClick={() => entry.hasReport && void openReport(entry.index)}
                >
                  <td>
                    <Badge tone={STATE_TONE[entry.state]}>{entry.state}</Badge>
                  </td>
                  <td className="batch-file" title={entry.path}>
                    <strong>{entry.name}</strong>
                    <small>{entry.architecture ?? "-"}</small>
                    {entry.reusedFrom !== null && (
                      <small>reused from {job.files[entry.reusedFrom]?.name ?? `#${entry.reusedFrom}`}</small>
                    )}
                    {entry.error && <small className="warn-text">{entry.error}</small>}
                  </td>
                  <td className="mono small" title={entry.sha256 ?? ""}>
                    {entry.sha256 ? entry.sha256.slice(0, 24) : "-"}
                  </td>
                  <td>{entry.format ?? "-"}</td>
                  <td className="mono">{entry.size === null ? "-" : fmtBytes(entry.size)}</td>
                  <td className="mono">{fmtNum(entry.anomalies)}</td>
                  <td className="mono">{fmtNum(entry.yara)}</td>
                  <td className="mono">{fmtNum(entry.signatures)}</td>
                  <td>{entry.debug ?? "-"}</td>
                  <td className="history-actions">
                    <button
                      type="button"
                      className="ghost small-button"
                      disabled={!entry.hasReport}
                      onClick={(event) => {
                        event.stopPropagation();
                        void openReport(entry.index);
                      }}
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {job?.errors.length ? (
        <details className="batch-errors">
          <summary>{job.errors.length} job message(s)</summary>
          <ul className="plain-list">
            {job.errors.slice(0, 50).map((message, index) => (
              <li key={`${message}-${index}`}>{message}</li>
            ))}
          </ul>
        </details>
      ) : null}
      <div className="batch-footer muted small">
        {fmtNum(job?.total ?? 0)} entries · hashes calculated locally · no file contents are copied or
        uploaded · duplicate content reuses the first completed result in this job.
      </div>
    </section>
  );
}
