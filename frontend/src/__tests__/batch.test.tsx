import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { BatchJobView } from "../types";

const api = vi.hoisted(() => ({
  addBatchPaths: vi.fn(),
  cancelBatchJob: vi.fn(),
  clearBatchJobs: vi.fn(),
  createBatchJob: vi.fn(),
  exportBatch: vi.fn(),
  getBatchJob: vi.fn(),
  getBatchReport: vi.fn(),
  listBatchJobs: vi.fn(),
  removeBatchJob: vi.fn(),
  startBatchJob: vi.fn(),
}));

vi.mock("../api", () => api);
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
  save: vi.fn(),
}));

import { open, save } from "@tauri-apps/plugin-dialog";
import { BatchView } from "../batch";

function job(overrides: Partial<BatchJobView> = {}): BatchJobView {
  return {
    id: "batch-1",
    state: "queued",
    createdUtc: "2026-10-31T12:00:00Z",
    startedUtc: null,
    finishedUtc: null,
    concurrency: 2,
    total: 0,
    queued: 0,
    running: 0,
    completed: 0,
    failed: 0,
    cancelled: 0,
    reused: 0,
    errors: [],
    files: [],
    ...overrides,
  };
}

function file(index: number, overrides: Partial<BatchJobView["files"][number]> = {}) {
  return {
    index,
    path: `C:\\samples\\file-${index}.exe`,
    name: `file-${index}.exe`,
    size: 4096,
    state: "queued" as const,
    sha256: null,
    reusedFrom: null,
    error: null,
    hasReport: false,
    anomalies: 0,
    yara: 0,
    signatures: 0,
    debug: null,
    format: null,
    architecture: null,
    durationMs: 0,
    ...overrides,
  };
}

describe("BatchView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.createBatchJob.mockResolvedValue(job());
    api.addBatchPaths.mockResolvedValue(job());
    api.getBatchJob.mockResolvedValue(job());
    api.listBatchJobs.mockResolvedValue([]);
    api.startBatchJob.mockResolvedValue(undefined);
    api.cancelBatchJob.mockResolvedValue(undefined);
    api.clearBatchJobs.mockResolvedValue({ removed: 1, remaining: 0 });
    api.removeBatchJob.mockResolvedValue(undefined);
    api.exportBatch.mockResolvedValue(undefined);
  });

  it("adds files to the Rust job and renders the queue", async () => {
    vi.mocked(open).mockResolvedValue(["C:\\samples\\a.exe", "C:\\samples\\b.exe"]);
    const queued = job({
      total: 2,
      queued: 2,
      files: [file(0, { name: "a.exe" }), file(1, { name: "b.exe" })],
    });
    api.addBatchPaths.mockResolvedValue(queued);

    render(<BatchView onOpenReport={vi.fn()} onNotify={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add files" }));

    expect(await screen.findByText("a.exe")).toBeTruthy();
    expect(screen.getByText("b.exe")).toBeTruthy();
    expect(api.createBatchJob).toHaveBeenCalledTimes(1);
    expect(api.addBatchPaths).toHaveBeenCalledWith(
      "batch-1",
      ["C:\\samples\\a.exe", "C:\\samples\\b.exe"],
      false,
    );
  });

  it("starts the job and sends cancellation to Rust", async () => {
    vi.mocked(open).mockResolvedValue(["C:\\samples\\a.exe"]);
    const queued = job({ total: 1, queued: 1, files: [file(0, { name: "a.exe" })] });
    const running = job({
      state: "running",
      startedUtc: "2026-10-31T12:00:01Z",
      total: 1,
      running: 1,
      files: [file(0, { name: "a.exe", state: "running" })],
    });
    api.addBatchPaths.mockResolvedValue(queued);
    api.getBatchJob.mockResolvedValue(running);

    render(<BatchView onOpenReport={vi.fn()} onNotify={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add files" }));
    await screen.findByText("a.exe");
    fireEvent.click(screen.getByRole("button", { name: /Analyze 1 queued/ }));

    await waitFor(() => expect(api.startBatchJob).toHaveBeenCalledWith("batch-1"));
    await waitFor(() => {
      const button = screen.getByRole("button", { name: "Cancel" }) as HTMLButtonElement;
      expect(button.disabled).toBe(false);
    });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.cancelBatchJob).toHaveBeenCalledWith("batch-1");
  });

  it("renders completed, failed and reused results with their evidence", async () => {
    vi.mocked(open).mockResolvedValue(["C:\\samples\\a.exe"]);
    const finished = job({
      state: "completed",
      total: 3,
      completed: 2,
      failed: 1,
      reused: 1,
      files: [
        file(0, { name: "a.exe", state: "completed", hasReport: true, anomalies: 3, yara: 2 }),
        file(1, {
          name: "a-copy.exe",
          state: "reused",
          reusedFrom: 0,
          sha256: "ab".repeat(32),
          hasReport: true,
        }),
        file(2, {
          name: "broken.exe",
          state: "failed",
          error: "PE parsing failed: truncated",
        }),
      ],
    });
    api.addBatchPaths.mockResolvedValue(finished);

    render(<BatchView onOpenReport={vi.fn()} onNotify={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add files" }));

    expect(await screen.findByText("a-copy.exe")).toBeTruthy();
    expect(screen.getByText("reused from a.exe")).toBeTruthy();
    expect(screen.getByText("PE parsing failed: truncated")).toBeTruthy();
    expect(screen.getByText("job completed")).toBeTruthy();
  });

  it("exports the Rust-side rows as CSV and JSON", async () => {
    vi.mocked(open).mockResolvedValue(["C:\\samples\\a.exe"]);
    vi.mocked(save).mockResolvedValue("C:\\out\\batch.csv");
    const finished = job({
      state: "completed",
      total: 1,
      completed: 1,
      files: [
        file(0, {
          name: "a.exe",
          state: "completed",
          hasReport: true,
          sha256: "ab".repeat(32),
          format: "PE",
          architecture: "x86",
          anomalies: 2,
        }),
      ],
    });
    api.addBatchPaths.mockResolvedValue(finished);

    render(<BatchView onOpenReport={vi.fn()} onNotify={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add files" }));
    await screen.findByText("a.exe");
    fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));

    await waitFor(() =>
      expect(api.exportBatch).toHaveBeenCalledWith(
        "C:\\out\\batch.csv",
        "csv",
        expect.arrayContaining([
          expect.objectContaining({
            file: "a.exe",
            sha256: "ab".repeat(32),
            status: "completed",
            anomalies: 2,
          }),
        ]),
      ),
    );
  });

  it("shows an empty state before a job exists", () => {
    render(<BatchView onOpenReport={vi.fn()} onNotify={vi.fn()} />);
    expect(screen.getByText(/No files queued/)).toBeTruthy();
  });
});
