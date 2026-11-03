import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { PeTab, SummaryTab, YaraTab } from "../tabs";
import {
  makeAnomaly,
  makeCertificate,
  makeCodeView,
  makePe,
  makeReport,
  makeSource,
  makeYaraMatch,
} from "../test/fixtures";

describe("YARA rule inspector", () => {
  it("shows the compiled source, revision and real pattern evidence", () => {
    const report = makeReport();
    render(<YaraTab report={report} />);

    fireEvent.click(screen.getByText("binscope_test_mz"));

    expect(screen.getByText("Rule-set revision")).toBeTruthy();
    expect(screen.getByText("0123456789abcdef")).toBeTruthy();
    expect(screen.getAllByText(/rule binscope_test_mz/).length).toBeGreaterThan(0);
    expect(screen.getByText("4D 5A")).toBeTruthy();
    expect(screen.getAllByText(/SHA-256/).length).toBeGreaterThan(0);
  });

  it("explains when source text is unavailable instead of inventing it", () => {
    const report = makeReport({
      yara: {
        ...makeReport().yara,
        matches: [
          makeYaraMatch(),
          makeYaraMatch({
            rule: "missing_source",
            origin: "C:\\rules\\gone.yar",
            namespace: "C:\\rules\\gone.yar",
          }),
        ],
        sources: [makeSource()],
      },
    });
    render(<YaraTab report={report} />);
    fireEvent.click(screen.getByText("missing_source"));
    expect(screen.getByText(/Source text is unavailable for this rule/)).toBeTruthy();
  });
});

describe("structured anomaly evidence", () => {
  it("expands a finding with typed evidence, expected/observed and false positives", () => {
    render(<SummaryTab report={makeReport()} onNotify={vi.fn()} />);
    fireEvent.click(screen.getByText("BS-PE-008"));
    expect(screen.getByText(/IMAGE_SCN_MEM_WRITE/)).toBeTruthy();
    expect(screen.getByText("writable or executable, not both")).toBeTruthy();
    expect(screen.getByText("RWX section")).toBeTruthy();
    expect(screen.getByText(/JIT runtimes/)).toBeTruthy();
    expect(screen.getByText("0x1A0")).toBeTruthy();
  });

  it("renders an empty anomaly list explicitly", () => {
    const report = makeReport({ pe: makePe({ anomalies: [] }) });
    render(<PeTab report={report} onNotify={vi.fn()} />);
    expect(screen.getByText("No structural anomalies detected.")).toBeTruthy();
  });
});

describe("debug and Authenticode metadata", () => {
  it("shows every CodeView record and marks the primary one", () => {
    const report = makeReport({
      pe: makePe({
        codeviewRecords: [
          makeCodeView(),
          makeCodeView({
            debugIndex: 1,
            signature: "NB10",
            pdbPath: "C:\\b\\second.pdb",
            guid: null,
            timestamp: 0x65000000,
            timestampUtc: "2023-09-12T10:26:40Z",
            primary: false,
          }),
          makeCodeView({
            debugIndex: 2,
            signature: "XXXX",
            pdbPath: null,
            guid: null,
            age: null,
            status: "unknown signature",
            primary: false,
          }),
        ],
      }),
    });
    render(<PeTab report={report} onNotify={vi.fn()} />);
    expect(screen.getByText("NB10")).toBeTruthy();
    expect(screen.getByText("XXXX")).toBeTruthy();
    expect(screen.getByText("primary")).toBeTruthy();
    expect(screen.getByText("unknown signature")).toBeTruthy();
    expect(screen.getByText("C:\\b\\second.pdb")).toBeTruthy();
  });

  it("distinguishes signature validity from chain trust", () => {
    render(<PeTab report={makeReport()} onNotify={vi.fn()} />);
    expect(screen.getByText("signature valid")).toBeTruthy();
    expect(screen.getByText("chain untrusted")).toBeTruthy();
    expect(screen.getByText("digest matches")).toBeTruthy();
    expect(screen.getByText("CN=BinScope Test Signer")).toBeTruthy();
  });

  it("renders empty and malformed metadata states without inventing records", () => {
    const report = makeReport({
      pe: makePe({
        pdb: null,
        codeviewRecords: [],
        anomalies: [],
        certificate: makeCertificate({
          present: true,
          directoryOffset: 0x1000,
          directorySize: 0x40,
          entries: [],
          note: "Certificate table is present but no valid entry could be parsed.",
        }),
      }),
      authenticode: null,
    });
    render(<PeTab report={report} onNotify={vi.fn()} />);
    expect(screen.getByText("No CodeView PDB record found.")).toBeTruthy();
    expect(
      screen.getByText("Authenticode verification was not run because structured parsing was skipped."),
    ).toBeTruthy();
    expect(screen.getByText(/no valid entry could be parsed/)).toBeTruthy();
  });

  it("shows critical anomalies as danger findings", () => {
    const report = makeReport({
      pe: makePe({
        anomalies: [
          makeAnomaly({
            ruleId: "BS-PE-001",
            code: "no_sections",
            severity: "critical",
            title: "No sections declared",
            message: "The PE file declares no sections.",
          }),
        ],
      }),
    });
    render(<PeTab report={report} onNotify={vi.fn()} />);
    expect(screen.getByText("critical")).toBeTruthy();
  });
});
