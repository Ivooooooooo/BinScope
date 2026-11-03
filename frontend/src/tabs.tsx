import { useEffect, useMemo, useState, type ReactNode } from "react";
import type {
  Anomaly,
  AppSettings,
  Detection,
  ExtractedString,
  PeInfo,
  Report,
  VtFileReport,
  VtStats,
  VtUploadReceipt,
} from "./types";
import {
  fmtBytes,
  fmtDate,
  fmtHex,
  fmtNum,
  fmtTimestamp,
  shorten,
  statusLabel,
} from "./format";
import { Badge, CopyButton, EmptyState, Field, Pager, SearchInput, SectionCard } from "./ui";
import { exportStrings, vtAnalysis, vtLookup, vtUpload } from "./api";
import { save } from "@tauri-apps/plugin-dialog";

type Notify = (message: string) => void;

function NotApplicable({ title, reason, children }: { title: string; reason: string; children?: ReactNode }) {
  return (
    <EmptyState title={title}>
      {reason}
      {children && <div className="empty-actions">{children}</div>}
    </EmptyState>
  );
}

function severityTone(severity: string): string {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warn";
  if (severity === "low") return "info";
  return "neutral";
}

function AnomalyFinding({ anomaly, defaultOpen = false }: { anomaly: Anomaly; defaultOpen?: boolean }) {
  const location = anomaly.fileOffset !== null
    ? `offset ${fmtHex(anomaly.fileOffset)}`
    : anomaly.rva !== null
      ? `RVA ${fmtHex(anomaly.rva)}`
      : null;
  return (
    <details className="anomaly-finding" {...(defaultOpen ? { open: true } : {})}>
      <summary>
        <Badge tone={severityTone(anomaly.severity)}>{anomaly.severity}</Badge>
        <span className="anomaly-code mono">{anomaly.ruleId || anomaly.code}</span>
        <strong className="anomaly-title">{anomaly.title || anomaly.message}</strong>
        {anomaly.category && <span className="muted small">{anomaly.category}</span>}
        {location && <span className="muted small mono">{location}</span>}
      </summary>
      <div className="anomaly-body">
        <p>{anomaly.explanation || anomaly.message}</p>
        <div className="anomaly-meta">
          {anomaly.confidence && <span><span className="meta-label">Confidence</span>{anomaly.confidence}</span>}
          {anomaly.expected && <span><span className="meta-label">Expected</span>{anomaly.expected}</span>}
          {anomaly.observed && <span><span className="meta-label">Observed</span>{anomaly.observed}</span>}
          {anomaly.sections.length > 0 && (
            <span><span className="meta-label">Sections</span>{anomaly.sections.join(", ")}</span>
          )}
        </div>
        {anomaly.evidence.length > 0 && (
          <div className="table-wrap">
            <table className="anomaly-evidence-table">
              <thead>
                <tr>
                  <th>Evidence</th>
                  <th>Kind</th>
                  <th>Value</th>
                  <th>Location</th>
                </tr>
              </thead>
              <tbody>
                {anomaly.evidence.map((evidence, index) => (
                  <tr key={`${evidence.kind}-${evidence.label}-${index}`}>
                    <td>{evidence.label}</td>
                    <td className="mono small">{evidence.kind}</td>
                    <td className="mono small">{evidence.value}</td>
                    <td className="mono small">
                      {evidence.fileOffset !== null
                        ? fmtHex(evidence.fileOffset)
                        : evidence.rva !== null
                          ? `RVA ${fmtHex(evidence.rva)}`
                          : evidence.section ?? "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {anomaly.falsePositiveNotes && (
          <p className="muted small">
            <span className="meta-label">False positives</span>
            {anomaly.falsePositiveNotes}
          </p>
        )}
      </div>
    </details>
  );
}

function categoryTone(category: string): string {
  switch (category) {
    case "packer":
    case "protector":
      return "danger";
    case "compiler":
    case "linker":
      return "info";
    case "runtime":
    case "framework":
      return "ok";
    case "installer":
      return "warn";
    default:
      return "neutral";
  }
}



export function SummaryTab({ report, onNotify }: { report: Report; onNotify: Notify }) {
  const grouped: Array<[string, string[]]> = [
    ["Compiler", report.summary.compilers],
    ["Linker", report.summary.linkers],
    ["Packer", report.summary.packers],
    ["Protector", report.summary.protectors],
    ["Language", report.summary.languages],
    ["Library", report.summary.libraries],
    ["Runtime", report.summary.runtimes],
    ["Framework", report.summary.frameworks],
    ["Installer", report.summary.installers],
    ["Format", report.summary.formats],
    ["Tool", report.summary.tools],
    ["Other", report.summary.other],
  ].filter(([, values]) => values.length > 0) as Array<[string, string[]]>;

  const anomalies = report.pe?.anomalies ?? [];

  return (
    <div className="tab-stack">
      <SectionCard title="Identification">
        <div className="field-grid">
          <Field label="Format" value={report.format.label} />
          <Field label="File type" value={report.format.fileType} />
          <Field label="Architecture" value={`${report.format.architecture}${report.format.bits ? ` (${report.format.bits}-bit)` : ""}`} />
          <Field label="Operating system" value={report.format.operatingSystem} />
          <Field label="Managed code" value={report.format.managedness} />
          <Field label="Format confidence" value={`${report.format.confidence}%`} />
          <Field label="Size" value={`${report.file.sizeHuman} (${fmtNum(report.file.size)} bytes)`} />
          <Field label="Modified" value={report.file.modifiedUtc ?? "—"} />
        </div>
        <p className="muted small">{report.format.description}</p>
        {report.format.evidence.length > 0 && (
          <ul className="evidence-list">
            {report.format.evidence.map((item, index) => (
              <li key={`${item}-${index}`}>{item}</li>
            ))}
          </ul>
        )}
      </SectionCard>

      <SectionCard
        title="Hashes"
        extra={<span className="muted small">SHA-256 is the primary identifier</span>}
      >
        <div className="hash-list">
          {[
            ["SHA-256", report.file.sha256],
            ["SHA-1", report.file.sha1],
            ["MD5", report.file.md5],
          ].map(([label, value]) => (
            <div className="hash-row" key={label}>
              <span className="hash-label">{label}</span>
              <code>{value}</code>
              <CopyButton value={value} label="copy" onCopied={onNotify} />
            </div>
          ))}
        </div>
      </SectionCard>

      <div className="two-column">
        <SectionCard title="Detections" extra={<span className="muted small">{report.detections.length}</span>}>
          {grouped.length === 0 ? (
            <p className="muted">No compiler, linker, packer or runtime signature matched.</p>
          ) : (
            <div className="summary-groups">
              {grouped.map(([label, values]) => (
                <div className="summary-group" key={label}>
                  <div className="summary-label">{label}</div>
                  <div className="chips">
                    {values.map((value) => (
                      <Badge key={value} tone={categoryTone(label.toLowerCase())}>
                        {value}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="Analysis">
          <div className="field-grid">
            <Field label="Status" value={<Badge tone={report.analysis.status === "complete" ? "ok" : report.analysis.status === "partial" ? "warn" : "danger"}>{statusLabel(report.analysis.status)}</Badge>} />
            <Field label="Duration" value={`${fmtNum(report.analysis.durationMs)} ms`} />
            <Field label="Started" value={report.analysis.startedUtc} />
            <Field label="Finished" value={report.analysis.finishedUtc} />
            <Field label="Parse limit" value={fmtBytes(report.analysis.parseLimitBytes)} />
            <Field label="Engine" value={`${report.tool.name} ${report.tool.version}`} />
            <Field
              label="Detection profile"
              value={report.detectionConfig.profile ?? "custom"}
            />
          </div>
        </SectionCard>
      </div>

      {report.dotnet && (
        <SectionCard title=".NET assembly">
          <div className="field-grid">
            <Field label="Runtime" value={report.dotnet.runtimeVersion} />
            <Field label="Metadata version" value={report.dotnet.metadataVersion} />
            <Field label="Kind" value={report.dotnet.kind} />
            <Field label="Entry point" value={report.dotnet.entryPointKind} />
            <Field label="Assembly" value={report.dotnet.assembly ? `${report.dotnet.assembly.name} ${report.dotnet.assembly.version}` : "—"} />
            <Field label="Module" value={report.dotnet.moduleName} />
            <Field label="Types" value={fmtNum(report.dotnet.typeDefinitionCount)} />
            <Field label="Methods" value={fmtNum(report.dotnet.methodDefinitionCount)} />
            <Field label="Strong name" value={report.dotnet.strongNameSigned ? "Signed" : "Not signed"} />
          </div>
        </SectionCard>
      )}

      {anomalies.length > 0 && (
        <SectionCard
          title="Structural anomalies"
          extra={<span className="muted small">{anomalies.length} findings</span>}
        >
          <div className="anomaly-list compact">
            {anomalies.slice(0, 5).map((anomaly, index) => (
              <AnomalyFinding key={`${anomaly.ruleId}-${index}`} anomaly={anomaly} />
            ))}
          </div>
          {anomalies.length > 5 && (
            <p className="muted small">
              {anomalies.length - 5} more findings are available in the PE tab. Evidence tables stay
              collapsed until a finding is opened.
            </p>
          )}
        </SectionCard>
      )}

      {report.analysis.issues.length > 0 && (
        <SectionCard title="Analysis issues">
          <ul className="issue-list">
            {report.analysis.issues.map((issue, index) => (
              <li key={`${issue.stage}-${index}`}>
                <Badge tone={issue.level === "error" ? "danger" : issue.level === "warning" ? "warn" : "neutral"}>
                  {issue.level}
                </Badge>
                <span className="issue-stage">{issue.stage}</span>
                <span>{issue.message}</span>
              </li>
            ))}
          </ul>
        </SectionCard>
      )}

      {report.notes.length > 0 && (
        <SectionCard title="Notes">
          <ul className="plain-list">
            {report.notes.map((note, index) => (
              <li key={`${note}-${index}`}>{note}</li>
            ))}
          </ul>
        </SectionCard>
      )}
    </div>
  );
}



function AnomalyList({ pe }: { pe: PeInfo }) {
  if (pe.anomalies.length === 0) {
    return <p className="muted">No structural anomalies detected.</p>;
  }
  return (
    <div className="anomaly-list">
      {pe.anomalies.map((anomaly, index) => (
        <AnomalyFinding key={`${anomaly.ruleId}-${index}`} anomaly={anomaly} />
      ))}
    </div>
  );
}

export function PeTab({ report, onNotify }: { report: Report; onNotify: Notify }) {
  const pe = report.pe;
  if (!pe) {
    return (
      <NotApplicable
        title="Not a PE image"
        reason={`The analyzed file was identified as ${report.format.label}. PE-specific fields are not applicable.`}
      />
    );
  }

  return (
    <div className="tab-stack">
      <SectionCard title="PE headers">
        <div className="field-grid">
          <Field label="PE kind" value={pe.peKind} />
          <Field label="Machine" value={`${pe.machineName} (${fmtHex(pe.machine, 4)})`} />
          <Field label="Architecture" value={`${pe.architecture} (${pe.bits}-bit)`} />
          <Field label="Subsystem" value={`${pe.subsystemName} (${pe.subsystem})`} />
          <Field label="Timestamp" value={pe.timeDateStampUtc ?? fmtHex(pe.timeDateStamp, 8)} />
          <Field label="Linker version" value={pe.linkerVersion} />
          <Field label="Entry point RVA" value={fmtHex(pe.entryPointRva, 8)} copy={fmtHex(pe.entryPointRva, 8)} onCopied={onNotify} mono />
          <Field label="Entry point file offset" value={pe.entryPointFileOffset === null ? "Not backed by raw data" : fmtHex(pe.entryPointFileOffset, 8)} />
          <Field label="ImageBase (VA)" value={fmtHex(pe.imageBase, pe.is64 ? 16 : 8)} copy={fmtHex(pe.imageBase, pe.is64 ? 16 : 8)} onCopied={onNotify} mono />
          <Field label="SizeOfImage" value={`${fmtHex(pe.sizeOfImage)} (${fmtBytes(pe.sizeOfImage)})`} />
          <Field label="SizeOfHeaders" value={fmtHex(pe.sizeOfHeaders)} />
          <Field label="SectionAlignment" value={fmtHex(pe.sectionAlignment)} />
          <Field label="FileAlignment" value={fmtHex(pe.fileAlignment)} />
          <Field label="Checksum" value={`${fmtHex(pe.checksum, 8)} ${pe.checksumValid ? "(valid)" : "(not validated)"}`} />
          <Field label="Computed checksum" value={fmtHex(pe.computedChecksum, 8)} />
          <Field label="Overlay" value={pe.overlay ? `${fmtHex(pe.overlay.offset)} + ${fmtBytes(pe.overlay.size)}` : "None"} />
        </div>
        <div className="chip-block">
          <span className="summary-label">Characteristics</span>
          <div className="chips">
            {pe.characteristicNames.length === 0 ? (
              <span className="muted">None</span>
            ) : (
              pe.characteristicNames.map((name) => <Badge key={name}>{name}</Badge>)
            )}
          </div>
        </div>
        <div className="chip-block">
          <span className="summary-label">DLL characteristics</span>
          <div className="chips">
            {pe.dllCharacteristicNames.length === 0 ? (
              <span className="muted">None</span>
            ) : (
              pe.dllCharacteristicNames.map((name) => <Badge key={name}>{name}</Badge>)
            )}
          </div>
        </div>
      </SectionCard>

      {pe.clr && (
        <SectionCard title="CLR runtime header">
          <div className="field-grid">
            <Field label="Runtime version" value={pe.clr.runtimeVersion} />
            <Field label="Metadata version" value={pe.clr.metadataVersion} />
            <Field label="Metadata RVA" value={fmtHex(pe.clr.metadataRva)} />
            <Field label="Metadata size" value={fmtBytes(pe.clr.metadataSize)} />
            <Field label="Metadata file offset" value={pe.clr.metadataFileOffset === null ? "Not mapped" : fmtHex(pe.clr.metadataFileOffset)} />
            <Field label="Entry point" value={pe.clr.entryPointKind} />
            <Field label="Strong name" value={pe.clr.strongNameSigned ? `Signed (${fmtBytes(pe.clr.strongNameSize)})` : "Not signed"} />
            <Field label="Flags" value={fmtHex(pe.clr.flags, 8)} />
          </div>
          <div className="chip-block">
            <span className="summary-label">CLR flags</span>
            <div className="chips">
              {pe.clr.flagNames.length === 0 ? (
                <span className="muted">None</span>
              ) : (
                pe.clr.flagNames.map((name) => <Badge key={name}>{name}</Badge>)
              )}
            </div>
          </div>
        </SectionCard>
      )}

      <SectionCard title="Data directories">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Directory</th>
                <th>RVA</th>
                <th>Size</th>
                <th>File offset</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {pe.dataDirectories.map((dir) => (
                <tr key={dir.index}>
                  <td className="mono">{dir.index}</td>
                  <td>{dir.name}</td>
                  <td className="mono">{fmtHex(dir.rva)}</td>
                  <td className="mono">{fmtHex(dir.size)}</td>
                  <td className="mono">{dir.fileOffset === null ? "—" : fmtHex(dir.fileOffset)}</td>
                  <td>
                    {dir.note ? <span className="warn-text">{dir.note}</span> : dir.present ? "Present" : "Absent"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <div className="two-column">
        <SectionCard title="Debug metadata">
          {pe.pdbPathWarning && <div className="warning-box">{pe.pdbPathWarning}</div>}
          {pe.debugEntries.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Timestamp</th>
                    <th>Size</th>
                    <th>Offset</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {pe.debugEntries.map((entry) => (
                    <tr key={entry.index}>
                      <td className="mono">{entry.index}</td>
                      <td>{entry.typeName}</td>
                      <td className="mono small">{entry.timestampUtc ?? "—"}</td>
                      <td className="mono">{fmtBytes(entry.sizeOfData)}</td>
                      <td className="mono">{entry.fileOffset === null ? "—" : fmtHex(entry.fileOffset)}</td>
                      <td>{entry.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted">No debug metadata found.</p>
          )}
          {pe.codeviewRecords.length > 0 ? (
            <div className="table-wrap">
              <table className="codeview-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Signature</th>
                    <th>PDB path</th>
                    <th>GUID</th>
                    <th>Age</th>
                    <th>Timestamp</th>
                    <th>Offset</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {pe.codeviewRecords.map((record) => (
                    <tr key={`${record.debugIndex}-${record.signature}`}>
                      <td className="mono">{record.debugIndex}</td>
                      <td className="mono">
                        {record.signature}
                        {record.primary && <Badge tone="info">primary</Badge>}
                      </td>
                      <td className="mono small">
                        {record.pdbPath ?? <span className="muted">unavailable</span>}
                      </td>
                      <td className="mono small">{record.guid ?? "-"}</td>
                      <td className="mono">{record.age ?? "-"}</td>
                      <td className="mono small">{record.timestampUtc ?? "-"}</td>
                      <td className="mono small">
                        {record.dataOffset === null ? "-" : fmtHex(record.dataOffset)}
                      </td>
                      <td className="small" title={record.source}>{record.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : pe.pdb ? (
            <div className="field-grid">
              <Field label="CodeView" value={pe.pdb.signature} />
              <Field label="PDB path" value={pe.pdb.path} copy={pe.pdb.path} onCopied={onNotify} mono />
              <Field label="GUID" value={pe.pdb.guid ?? "-"} />
              <Field label="Age" value={pe.pdb.age ?? "-"} />
              <Field label="Debug data offset" value={pe.pdb.dataFileOffset === null ? "-" : fmtHex(pe.pdb.dataFileOffset)} />
            </div>
          ) : (
            <p className="muted small">No CodeView PDB record found.</p>
          )}
          <p className="muted small">
            Debug timestamps and COFF timestamps are fields, not proof of a compilation date. The PDB path
            is shown exactly as stored; BinScope does not contact symbol servers.
          </p>
        </SectionCard>
        <SectionCard title="Authenticode">
          {report.authenticode ? (
            <>
              <div className="field-grid">
                <Field label="Presence" value={report.authenticode.presence} />
                <Field label="Signature" value={report.authenticode.signature} />
                <Field label="Chain" value={report.authenticode.chain} />
                <Field label="Certificate time" value={report.authenticode.certificateTime} />
                <Field label="Revocation" value={report.authenticode.revocation} />
                <Field label="Backend" value={report.authenticode.backend} />
                <Field label="Signer" value={report.authenticode.signer?.subject ?? "-"} />
                <Field label="Windows status" value={report.authenticode.winverifyStatusText ?? "-"} />
              </div>
              <div className="chips">
                <Badge tone={report.authenticode.signature === "valid" ? "ok" : report.authenticode.signature === "invalid" ? "danger" : "neutral"}>
                  signature {report.authenticode.signature}
                </Badge>
                <Badge tone={report.authenticode.chain === "trusted" ? "ok" : report.authenticode.chain === "untrusted" ? "warn" : "neutral"}>
                  chain {report.authenticode.chain}
                </Badge>
                <Badge tone={report.authenticode.digestMatches === true ? "ok" : report.authenticode.digestMatches === false ? "danger" : "neutral"}>
                  digest {report.authenticode.digestMatches === true ? "matches" : report.authenticode.digestMatches === false ? "mismatch" : "not compared"}
                </Badge>
                <span className="muted small">
                  {report.authenticode.platformSupported
                    ? "Cryptographic check by Windows CryptoAPI"
                    : "Trust verification unavailable on this platform"}
                </span>
              </div>
              {report.authenticode.signatures.length > 0 && (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Type</th>
                        <th>Digest</th>
                        <th>Result</th>
                        <th>Note</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.authenticode.signatures.map((check) => (
                        <tr key={check.entryIndex}>
                          <td className="mono">{check.entryIndex}</td>
                          <td>{check.certificateType}</td>
                          <td className="mono small">{check.digestAlgorithm ?? "-"}</td>
                          <td>{check.status}</td>
                          <td className="small">{check.note}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <details>
                <summary>Digest and verification notes</summary>
                <div className="field-grid">
                  <Field label="Signed digest" value={report.authenticode.signedDigest ?? "unavailable"} mono />
                  <Field label="Computed digest" value={report.authenticode.computedDigest ?? "unavailable"} mono />
                </div>
                <ul className="plain-list">
                  {report.authenticode.notes.map((note, index) => (
                    <li key={`${note}-${index}`}>{note}</li>
                  ))}
                </ul>
              </details>
            </>
          ) : (
            <p className="muted small">
              Authenticode verification was not run because structured parsing was skipped.
            </p>
          )}
          <details>
            <summary>Certificate table ({pe.certificate.entries.length} entries)</summary>
            <div className="field-grid">
              <Field label="Directory" value={pe.certificate.present ? `${fmtBytes(pe.certificate.directorySize)} at ${fmtHex(pe.certificate.directoryOffset)}` : "Absent"} />
            </div>
            {pe.certificate.entries.length > 0 && (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Offset</th>
                      <th>Length</th>
                      <th>Revision</th>
                      <th>Type</th>
                      <th>Nested</th>
                      <th>Bounds</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pe.certificate.entries.map((entry) => (
                      <tr key={entry.offset}>
                        <td className="mono">{fmtHex(entry.offset)}</td>
                        <td className="mono">{fmtHex(entry.length)}</td>
                        <td>{entry.revisionName}</td>
                        <td>{entry.certificateTypeName}</td>
                        <td>{entry.containsNestedSignatureOid ? "Yes" : "No"}</td>
                        <td>{entry.inBounds ? "ok" : "out of bounds"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="muted small">{pe.certificate.note}</p>
          </details>
        </SectionCard>
      </div>

      {pe.versionInfo && (
        <SectionCard title="Version information">
          <div className="field-grid">
            <Field label="File version" value={pe.versionInfo.fileVersion ?? pe.versionInfo.fixedFileVersion} />
            <Field label="Product version" value={pe.versionInfo.productVersion ?? pe.versionInfo.fixedProductVersion} />
            <Field label="Company" value={pe.versionInfo.companyName} />
            <Field label="Product" value={pe.versionInfo.productName} />
            <Field label="Description" value={pe.versionInfo.fileDescription} />
            <Field label="Original filename" value={pe.versionInfo.originalFilename} />
            <Field label="Internal name" value={pe.versionInfo.internalName} />
            <Field label="Copyright" value={pe.versionInfo.legalCopyright} />
          </div>
          {pe.versionInfo.entries.length > 0 && (
            <details>
              <summary>All {pe.versionInfo.entries.length} fields</summary>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Key</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pe.versionInfo.entries.map((entry) => (
                      <tr key={entry.key}>
                        <td>{entry.key}</td>
                        <td className="mono">{entry.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
        </SectionCard>
      )}

      <SectionCard title="Resources" extra={<span className="muted small">{pe.resources.length}</span>}>
        {pe.resources.length === 0 ? (
          <p className="muted">No resources parsed.</p>
        ) : (
          <div className="table-wrap scroll-y">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Name</th>
                  <th>Language</th>
                  <th>Size</th>
                  <th>RVA</th>
                  <th>File offset</th>
                </tr>
              </thead>
              <tbody>
                {pe.resources.map((res, index) => (
                  <tr key={`${res.typeName}-${res.name}-${index}`}>
                    <td>{res.typeName}</td>
                    <td>{res.name}</td>
                    <td className="mono">{res.language}</td>
                    <td className="mono">{fmtBytes(res.size)}</td>
                    <td className="mono">{fmtHex(res.rva)}</td>
                    <td className="mono">{res.fileOffset === null ? "—" : fmtHex(res.fileOffset)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {pe.manifest && (
          <details>
            <summary>Embedded manifest ({fmtBytes(pe.manifest.length)})</summary>
            <pre className="code-block">{pe.manifest}</pre>
          </details>
        )}
      </SectionCard>

      <div className="two-column">
        <SectionCard title="Rich header">
          {pe.richHeader ? (
            <>
              <div className="field-grid">
                <Field label="Offset" value={fmtHex(pe.richHeader.offset)} />
                <Field label="XOR key" value={fmtHex(pe.richHeader.key, 8)} />
                <Field label="Entries" value={pe.richHeader.entries.length} />
              </div>
              <div className="table-wrap scroll-y-small">
                <table>
                  <thead>
                    <tr>
                      <th>Product ID</th>
                      <th>Build</th>
                      <th>Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pe.richHeader.entries.map((entry, index) => (
                      <tr key={`${entry.productId}-${entry.buildNumber}-${index}`}>
                        <td className="mono">{fmtHex(entry.productId, 4)}</td>
                        <td className="mono">{entry.buildNumber}</td>
                        <td className="mono">{entry.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <p className="muted">No Rich header present.</p>
          )}
        </SectionCard>

        <SectionCard title="TLS / overlay">
          <div className="field-grid">
            <Field label="TLS callbacks" value={pe.tlsCallbacks.length === 0 ? "None" : pe.tlsCallbacks.length} />
            <Field label="Overlay offset" value={pe.overlay ? fmtHex(pe.overlay.offset) : "—"} />
            <Field label="Overlay size" value={pe.overlay ? fmtBytes(pe.overlay.size) : "-"} />
            <Field
              label="Overlay SHA-256"
              value={pe.overlay?.sha256 ?? "-"}
              copy={pe.overlay?.sha256 ?? undefined}
              onCopied={onNotify}
              mono
            />
            <Field label="Sections" value={pe.numberOfSections} />
            <Field label="RVA directories" value={pe.numberOfRvaAndSizes} />
          </div>
          {pe.tlsCallbacks.length > 0 && (
            <ul className="plain-list mono">
              {pe.tlsCallbacks.map((callback, index) => (
                <li key={`${callback}-${index}`}>{fmtHex(callback, pe.is64 ? 16 : 8)}</li>
              ))}
            </ul>
          )}
        </SectionCard>
      </div>

      <SectionCard title="Anomalies" extra={<span className="muted small">{pe.anomalies.length}</span>}>
        <AnomalyList pe={pe} />
        {pe.parseNotes.length > 0 && (
          <details>
            <summary>Parser notes ({pe.parseNotes.length})</summary>
            <ul className="plain-list">
              {pe.parseNotes.map((note, index) => (
                <li key={`${note}-${index}`}>{note}</li>
              ))}
            </ul>
          </details>
        )}
      </SectionCard>
    </div>
  );
}



export function SectionsTab({ report }: { report: Report }) {
  const [query, setQuery] = useState("");
  const q = query.toLowerCase();

  if (report.pe) {
    const sections = report.pe.sections.filter((section) => section.name.toLowerCase().includes(q));
    return (
      <div className="tab-stack">
        <SectionCard
          title="PE sections"
          extra={<SearchInput value={query} onChange={setQuery} placeholder="Filter section name…" />}
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Name</th>
                  <th>RVA</th>
                  <th>Virtual size</th>
                  <th>Raw offset</th>
                  <th>Raw size</th>
                  <th>Perms</th>
                  <th>Entropy</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {sections.map((section) => (
                  <tr key={section.index}>
                    <td className="mono">{section.index}</td>
                    <td className="mono">{section.name || "<empty>"}</td>
                    <td className="mono">{fmtHex(section.virtualAddress)}</td>
                    <td className="mono">{fmtHex(section.virtualSize)}</td>
                    <td className="mono">{fmtHex(section.rawOffset)}</td>
                    <td className="mono">{fmtHex(section.rawSize)}</td>
                    <td className="mono">{section.permissions}</td>
                    <td className={`mono ${section.entropy >= 7.2 ? "warn-text" : ""}`}>{section.entropy.toFixed(3)}</td>
                    <td className="small">{section.flags.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted small">
            Entropy is informational. High entropy alone is not evidence of packing or encryption.
          </p>
        </SectionCard>
      </div>
    );
  }

  if (report.elf) {
    const sections = report.elf.sections.filter((section) => section.name.toLowerCase().includes(q));
    return (
      <div className="tab-stack">
        <SectionCard
          title="ELF sections"
          extra={<SearchInput value={query} onChange={setQuery} placeholder="Filter section name…" />}
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Address</th>
                  <th>Offset</th>
                  <th>Size</th>
                  <th>Flags</th>
                  <th>Entropy</th>
                </tr>
              </thead>
              <tbody>
                {sections.map((section) => (
                  <tr key={section.index}>
                    <td className="mono">{section.index}</td>
                    <td className="mono">{section.name || "<empty>"}</td>
                    <td>{section.typeName}</td>
                    <td className="mono">{fmtHex(section.address, 16)}</td>
                    <td className="mono">{fmtHex(section.offset)}</td>
                    <td className="mono">{fmtHex(section.size)}</td>
                    <td className="small">{section.flags.join(", ")}</td>
                    <td className={`mono ${section.entropy >= 7.2 ? "warn-text" : ""}`}>{section.entropy.toFixed(3)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
        <SectionCard title="ELF program headers">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Type</th>
                  <th>Flags</th>
                  <th>Offset</th>
                  <th>Virtual address</th>
                  <th>File size</th>
                  <th>Memory size</th>
                  <th>Align</th>
                </tr>
              </thead>
              <tbody>
                {report.elf.programHeaders.map((ph) => (
                  <tr key={ph.index}>
                    <td className="mono">{ph.index}</td>
                    <td>{ph.typeName}</td>
                    <td className="mono">{ph.flags}</td>
                    <td className="mono">{fmtHex(ph.offset)}</td>
                    <td className="mono">{fmtHex(ph.virtualAddress, 16)}</td>
                    <td className="mono">{fmtHex(ph.fileSize)}</td>
                    <td className="mono">{fmtHex(ph.memorySize)}</td>
                    <td className="mono">{fmtHex(ph.align)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
      </div>
    );
  }

  if (report.macho) {
    return (
      <div className="tab-stack">
        {report.macho.slices.map((slice, index) => (
          <SectionCard key={`${slice.architecture}-${index}`} title={`Mach-O segments — ${slice.architecture}`}>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Virtual address</th>
                    <th>Virtual size</th>
                    <th>File offset</th>
                    <th>File size</th>
                    <th>Protections</th>
                  </tr>
                </thead>
                <tbody>
                  {slice.segments.map((segment, segIndex) => (
                    <tr key={`${segment.name}-${segIndex}`}>
                      <td className="mono">{segment.name}</td>
                      <td className="mono">{fmtHex(segment.virtualAddress, 16)}</td>
                      <td className="mono">{fmtHex(segment.virtualSize)}</td>
                      <td className="mono">{fmtHex(segment.fileOffset)}</td>
                      <td className="mono">{fmtHex(segment.fileSize)}</td>
                      <td className="mono">{segment.protections}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SectionCard>
        ))}
      </div>
    );
  }

  return <NotApplicable title="No section table" reason="This format does not expose a section or segment table." />;
}



export function ImportsTab({ report }: { report: Report }) {
  const [query, setQuery] = useState("");
  const q = query.toLowerCase();

  if (report.pe) {
    const pe = report.pe;
    const imports = pe.imports
      .map((lib) => ({
        ...lib,
        functions: lib.functions.filter(
          (fn) => (fn.name ?? `#${fn.ordinal}`).toLowerCase().includes(q) || lib.name.toLowerCase().includes(q),
        ),
      }))
      .filter((lib) => lib.functions.length > 0 || lib.name.toLowerCase().includes(q));
    const exports = pe.exports.filter(
      (exp) => (exp.name ?? "").toLowerCase().includes(q) || String(exp.ordinal).includes(q),
    );

    return (
      <div className="tab-stack">
        <SectionCard
          title={`Imports (${pe.imports.reduce((sum, lib) => sum + lib.functions.length, 0)} functions in ${pe.imports.length} libraries)`}
          extra={<SearchInput value={query} onChange={setQuery} placeholder="Filter library or function…" />}
        >
          {imports.length === 0 ? (
            <p className="muted">No matching imports.</p>
          ) : (
            <div className="import-list">
              {imports.map((lib, index) => (
                <details key={`${lib.name}-${index}`} open={index < 3}>
                  <summary>
                    <span className="mono">{lib.name}</span>
                    <span className="muted small">{lib.functions.length} functions</span>
                    {lib.nameIsIrregular && <Badge tone="warn">irregular name</Badge>}
                  </summary>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Hint</th>
                          <th>Name / ordinal</th>
                        </tr>
                      </thead>
                      <tbody>
                        {lib.functions.slice(0, 2000).map((fn, fnIndex) => (
                          <tr key={`${fn.name ?? fn.ordinal}-${fnIndex}`}>
                            <td className="mono">{fn.hint === null ? "—" : fmtHex(fn.hint, 4)}</td>
                            <td className="mono">{fn.name ?? `#${fn.ordinal}`}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {lib.functions.length > 2000 && (
                    <p className="muted small">Showing the first 2,000 functions.</p>
                  )}
                </details>
              ))}
            </div>
          )}
          {pe.delayImports.length > 0 && (
            <details>
              <summary>Delay imports ({pe.delayImports.length} libraries)</summary>
              {pe.delayImports.map((lib) => (
                <div key={lib.name} className="delay-import">
                  <strong className="mono">{lib.name}</strong>
                  <span className="muted">, {lib.functions.length} functions</span>
                </div>
              ))}
            </details>
          )}
        </SectionCard>

        <SectionCard title={`Exports${pe.exportsDllName ? ` — ${pe.exportsDllName}` : ""}`} extra={<span className="muted small">{pe.exports.length}</span>}>
          {exports.length === 0 ? (
            <p className="muted">No matching exports.</p>
          ) : (
            <div className="table-wrap scroll-y">
              <table>
                <thead>
                  <tr>
                    <th>Ordinal</th>
                    <th>Name</th>
                    <th>RVA</th>
                    <th>File offset</th>
                    <th>Forwarder</th>
                  </tr>
                </thead>
                <tbody>
                  {exports.map((exp, index) => (
                    <tr key={`${exp.name ?? exp.ordinal}-${index}`}>
                      <td className="mono">{exp.ordinal}</td>
                      <td className="mono">{exp.name ?? "<unnamed>"}</td>
                      <td className="mono">{fmtHex(exp.rva)}</td>
                      <td className="mono">{exp.fileOffset === null ? "—" : fmtHex(exp.fileOffset)}</td>
                      <td className="mono">{exp.forwarder ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>
      </div>
    );
  }

  if (report.elf) {
    const elf = report.elf;
    return (
      <div className="tab-stack">
        <SectionCard title="Dynamic dependencies">
          <div className="field-grid">
            <Field label="Interpreter" value={elf.interpreter ?? "None"} />
            <Field label="SONAME" value={elf.soname ?? "None"} />
            <Field label="RPATH" value={elf.rpaths.join(", ") || "None"} />
            <Field label="RUNPATH" value={elf.runpaths.join(", ") || "None"} />
          </div>
          <div className="chips">
            {elf.neededLibraries.length === 0 ? (
              <span className="muted">No DT_NEEDED entries.</span>
            ) : (
              elf.neededLibraries.map((lib) => <Badge key={lib}>{lib}</Badge>)
            )}
          </div>
        </SectionCard>
        <div className="two-column">
          <SymbolList title={`Dynamic imports (${elf.imports.length})`} items={elf.imports} onQuery={setQuery} query={query} />
          <SymbolList title={`Dynamic exports (${elf.exports.length})`} items={elf.exports} onQuery={setQuery} query={query} />
        </div>
      </div>
    );
  }

  if (report.macho) {
    return (
      <div className="tab-stack">
        {report.macho.slices.map((slice, index) => (
          <SectionCard key={`${slice.architecture}-${index}`} title={`Mach-O symbols — ${slice.architecture}`}>
            <Field label="Install name" value={slice.installName ?? "—"} />
            <div className="chips">
              {slice.libraries.map((lib) => (
                <Badge key={lib}>{lib}</Badge>
              ))}
            </div>
            <div className="two-column">
              <div>
                <h4>Imports ({slice.imports.length})</h4>
                <ul className="symbol-list mono">
                  {slice.imports.slice(0, 2000).map((name) => (
                    <li key={name}>{name}</li>
                  ))}
                </ul>
              </div>
              <div>
                <h4>Exports ({slice.exports.length})</h4>
                <ul className="symbol-list mono">
                  {slice.exports.slice(0, 2000).map((name) => (
                    <li key={name}>{name}</li>
                  ))}
                </ul>
              </div>
            </div>
          </SectionCard>
        ))}
      </div>
    );
  }

  return <NotApplicable title="No import/export table" reason="This format does not provide import or export information." />;
}

function SymbolList({
  title,
  items,
  query,
  onQuery,
}: {
  title: string;
  items: string[];
  query: string;
  onQuery: (value: string) => void;
}) {
  const q = query.toLowerCase();
  const filtered = items.filter((item) => item.toLowerCase().includes(q));
  return (
    <SectionCard title={title} extra={<SearchInput value={query} onChange={onQuery} placeholder="Filter symbol…" />}>
      {filtered.length === 0 ? (
        <p className="muted">No matching symbols.</p>
      ) : (
        <ul className="symbol-list mono scroll-y-small">
          {filtered.slice(0, 5000).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}



const STRINGS_PAGE = 200;

export function StringsTab({ report, onNotify }: { report: Report; onNotify: Notify }) {
  const [query, setQuery] = useState("");
  const [encoding, setEncoding] = useState<"all" | "ascii" | "utf8" | "utf16_le">("all");
  const [classFilter, setClassFilter] = useState("all");
  const [page, setPage] = useState(0);
  const strings = report.strings;

  useEffect(() => {
    setPage(0);
  }, [query, encoding, classFilter]);

  const classKinds = useMemo(() => {
    const kinds = new Set<string>();
    for (const item of strings?.items ?? []) {
      for (const classification of item.classifications) {
        kinds.add(classification.kind);
      }
    }
    return [...kinds].sort();
  }, [strings]);

  const filtered = useMemo(() => {
    if (!strings) return [] as ExtractedString[];
    const q = query.trim().toLowerCase();
    return strings.items.filter((item) => {
      if (encoding !== "all" && item.encoding !== encoding) return false;
      if (
        classFilter !== "all" &&
        !item.classifications.some((classification) => classification.kind === classFilter)
      ) {
        return false;
      }
      if (!q) return true;
      return (
        item.value.toLowerCase().includes(q) ||
        item.offset.toString(16).includes(q) ||
        (item.section ?? "").toLowerCase().includes(q) ||
        item.classifications.some((classification) =>
          classification.kind.replace(/_/g, " ").includes(q),
        )
      );
    });
  }, [strings, query, encoding, classFilter]);

  if (!strings) {
    return (
      <NotApplicable
        title="Strings not extracted"
        reason="String extraction was disabled for this analysis or stopped before completion."
      />
    );
  }

  const pageCount = Math.max(1, Math.ceil(filtered.length / STRINGS_PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const slice = filtered.slice(safePage * STRINGS_PAGE, safePage * STRINGS_PAGE + STRINGS_PAGE);

  const doExport = async (format: "csv" | "json") => {
    try {
      const target = await save({
        title: `Export ${format.toUpperCase()} strings`,
        defaultPath: `${report.file.name}.strings.${format}`,
        filters: [{ name: format === "csv" ? "CSV" : "JSON", extensions: [format] }],
      });
      if (typeof target !== "string") return;
      await exportStrings(target, format, filtered);
      onNotify(`Exported ${fmtNum(filtered.length)} strings to ${target.split(/[\\/]/).pop()}`);
    } catch (err) {
      onNotify(`Export failed: ${String(err)}`);
    }
  };

  return (
    <div className="tab-stack">
      <SectionCard
        title="String extraction"
        extra={
          <div className="toolbar">
            <select
              value={encoding}
              onChange={(event) => setEncoding(event.target.value as typeof encoding)}
              aria-label="Encoding filter"
            >
              <option value="all">All encodings</option>
              <option value="ascii">ASCII</option>
              <option value="utf8">UTF-8</option>
              <option value="utf16_le">utf-16le</option>
            </select>
            <select
              value={classFilter}
              onChange={(event) => setClassFilter(event.target.value)}
              aria-label="Classification filter"
            >
              <option value="all">All classifications</option>
              {classKinds.map((kind) => (
                <option key={kind} value={kind}>
                  {kind.replace(/_/g, " ")}
                </option>
              ))}
            </select>
            <SearchInput value={query} onChange={setQuery} placeholder="Search strings, offsets or sections." />
          </div>
        }
      >
        <div className="stats-row">
          <span><strong>{fmtNum(strings.summary.total)}</strong> strings</span>
          <span><strong>{fmtNum(strings.summary.ascii)}</strong> ASCII</span>
          <span><strong>{fmtNum(strings.summary.utf8)}</strong> UTF-8</span>
          <span><strong>{fmtNum(strings.summary.utf16le)}</strong> utf-16le</span>
          <span>min length <strong>{strings.summary.minLen}</strong></span>
          <span>{fmtBytes(strings.summary.bytesScanned)} scanned</span>
          <span>{strings.summary.elapsedMs} ms</span>
          {strings.summary.truncated && <Badge tone="warn">truncated at limit</Badge>}
        </div>
        <p className="muted small">
          Multi-byte UTF-8 is scanned when the file is fully buffered (within the parse limit); streamed
          files report ASCII and UTF-16LE. UTF-16LE covers Latin-range text (high byte zero). String and
          memory limits bound every pass.
        </p>
        <div className="toolbar">
          <span className="muted small">{fmtNum(filtered.length)} matching</span>
          <button type="button" className="ghost" onClick={() => void doExport("csv")} disabled={filtered.length === 0}>
            Export CSV
          </button>
          <button type="button" className="ghost" onClick={() => void doExport("json")} disabled={filtered.length === 0}>
            Export JSON
          </button>
          <button
            type="button"
            className="ghost"
            disabled={filtered.length === 0}
            onClick={() => {
              const text = filtered
                .slice(0, 5000)
                .map((item) => `${fmtHex(item.offset, 8)}\t${item.encoding}\t${item.value}`)
                .join("\n");
              navigator.clipboard
                .writeText(text)
                .then(() => onNotify(`Copied ${Math.min(filtered.length, 5000)} strings`))
                .catch(() => onNotify("Could not access the clipboard"));
            }}
          >
            Copy filtered (max 5,000)
          </button>
        </div>
        <div className="table-wrap scroll-y">
          <table>
            <thead>
              <tr>
                <th>Offset</th>
                <th>Enc</th>
                <th>Section</th>
                <th>Classification</th>
                <th>String</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {slice.map((item, index) => (
                <tr key={`${item.offset}-${item.encoding}-${index}`}>
                  <td className="mono offset-cell">{fmtHex(item.offset, 8)}</td>
                  <td>
                    <Badge tone={item.encoding === "ascii" ? "neutral" : "info"}>
                      {item.encoding === "ascii" ? "ASCII" : item.encoding === "utf8" ? "UTF-8" : "UTF-16LE"}
                    </Badge>
                  </td>
                  <td className="mono">{item.section ?? "-"}</td>
                  <td>
                    {item.classifications.length === 0 ? (
                      <span className="muted">-</span>
                    ) : (
                      <div className="chips">
                        {item.classifications.map((classification) => (
                          <Badge
                            key={classification.kind}
                            tone={classification.confidence >= 80 ? "info" : "neutral"}
                            title={`${classification.confidence}% confidence${classification.note ? `: ${classification.note}` : ""}`}
                          >
                            {classification.kind.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="mono string-cell" title={item.value}>
                    {item.value}
                    {item.truncated && <span className="muted"> ... [truncated]</span>}
                  </td>
                  <td><CopyButton value={item.value} label="copy" onCopied={onNotify} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager page={safePage} pageCount={pageCount} total={filtered.length} onChange={setPage} />
      </SectionCard>
    </div>
  );
}



const CATEGORIES = [
  "all",
  "compiler",
  "linker",
  "packer",
  "protector",
  "runtime",
  "framework",
  "installer",
  "language",
  "library",
  "format",
  "tool",
  "other",
] as const;

export function SignaturesTab({ report }: { report: Report }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<(typeof CATEGORIES)[number]>("all");

  const filtered = report.detections.filter((detection) => {
    if (category !== "all" && detection.category !== category) return false;
    const q = query.toLowerCase();
    if (!q) return true;
    return (
      detection.name.toLowerCase().includes(q) ||
      detection.description.toLowerCase().includes(q) ||
      detection.id.toLowerCase().includes(q) ||
      detection.evidence.some((ev) => ev.description.toLowerCase().includes(q))
    );
  });

  return (
    <div className="tab-stack">
      <SectionCard
        title="Signature detections"
        extra={
          <div className="toolbar">
            <select value={category} onChange={(event) => setCategory(event.target.value as typeof category)}>
              {CATEGORIES.map((value) => (
                <option key={value} value={value}>
                  {value === "all" ? "All categories" : value[0].toUpperCase() + value.slice(1)}
                </option>
              ))}
            </select>
            <SearchInput value={query} onChange={setQuery} placeholder="Search detections or evidence…" />
          </div>
        }
      >
        {!report.signatures.enabled ? (
          <p className="muted">Signature detection was disabled for this analysis.</p>
        ) : filtered.length === 0 ? (
          <p className="muted">No matching signature detection.</p>
        ) : (
          <div className="detection-grid">
            {filtered.map((detection) => (
              <DetectionCard key={detection.id} detection={detection} />
            ))}
          </div>
        )}
        {report.signatures.errors.length > 0 && (
          <div className="error-box">
            {report.signatures.errors.map((error, index) => (
              <div key={`${error}-${index}`}>{error}</div>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard
        title="Signature databases"
        extra={<span className="muted small">{fmtNum(report.signatures.totalSignatures)} signatures</span>}
      >
        {report.signatures.die && (
          <div className="database-status">
            <div className="database-title">
              <strong>Detect It Easy</strong>
              <Badge tone={report.signatures.die.errors.length > 0 ? "warn" : "info"}>
                {report.signatures.die.version}
              </Badge>
            </div>
            <div className="stats-row">
              <span><strong>{fmtNum(report.signatures.die.files)}</strong> signature files</span>
              <span><strong>{fmtNum(report.signatures.die.compatible)}</strong> compatible</span>
              <span><strong>{fmtNum(report.signatures.die.incompatible)}</strong> incompatible</span>
              <span><strong>{fmtNum(report.signatures.die.withMetadata)}</strong> with metadata</span>
            </div>
            <p className="muted small mono">{report.signatures.die.path}</p>
            {report.signatures.die.reasons.length > 0 && (
              <details>
                <summary>Incompatibility reasons</summary>
                <ul className="plain-list">
                  {report.signatures.die.reasons.map((reason) => (
                    <li key={reason.reason}>
                      {reason.count} × {reason.reason}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            {report.signatures.die.errors.length > 0 && (
              <div className="error-box">{report.signatures.die.errors.join("\n")}</div>
            )}
            <p className="muted small">
              BinScope does not embed DiE-JS. Only single entry-point byte signatures without
              loops, includes, negations or other PE APIs are executed; all other signatures are
              listed as incompatible, never approximated.
            </p>
          </div>
        )}
        {report.signatures.pebear && (
          <div className="database-status">
            <div className="database-title">
              <strong>PE-bear SIG.txt</strong>
              <Badge tone="neutral">{report.signatures.pebear.license}</Badge>
            </div>
            <div className="stats-row">
              <span><strong>{fmtNum(report.signatures.pebear.loaded)}</strong> loaded</span>
              <span><strong>{fmtNum(report.signatures.pebear.totalBlocks)}</strong> blocks</span>
              <span><strong>{fmtNum(report.signatures.pebear.skipped)}</strong> skipped</span>
            </div>
            <p className="muted small mono">{report.signatures.pebear.path}</p>
            <p className="muted small">
              Historical PEiD-derived signatures: byte matches are evidence, not definitive
              attribution, and may be outdated.
            </p>
          </div>
        )}
        {report.signatures.databases.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Version</th>
                  <th>Source</th>
                  <th>Signatures</th>
                </tr>
              </thead>
              <tbody>
                {report.signatures.databases.map((db) => (
                  <tr key={`${db.name}-${db.version}`}>
                    <td>{db.name}</td>
                    <td className="mono">{db.version}</td>
                    <td>{db.source}</td>
                    <td className="mono">{fmtNum(db.signatures)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small">
          DIE full compatibility is not claimed. See the compatibility document for the tested
          subset and limitations.
        </p>
      </SectionCard>
    </div>
  );
}

function detectionEngineLabel(engine: Detection["engine"]): string {
  switch (engine) {
    case "detect_it_easy":
      return "DIE";
    case "pebear":
      return "PE-bear";
    case "structural_heuristic":
      return "structural heuristic";
    case "die_heuristic":
      return "DIE heuristic";
    default:
      return "internal signature";
  }
}

function detectionCertaintyLabel(certainty: Detection["certainty"]): string {
  switch (certainty) {
    case "exact":
      return "exact match";
    case "strong_heuristic":
      return "strong heuristic";
    case "possible":
      return "possible";
    default:
      return "unknown certainty";
  }
}

function DetectionCard({ detection }: { detection: Detection }) {
  return (
    <article className="detection-card">
      <header>
        <div>
          <h4>{detection.name}</h4>
          <div className="muted small">{detection.id}</div>
        </div>
        <div className="detection-badges">
          <Badge tone={categoryTone(detection.category)}>{detection.category}</Badge>
          <Badge tone={detection.confidence >= 90 ? "ok" : detection.confidence >= 75 ? "info" : "warn"}>
            {detection.confidence}% confidence
          </Badge>
          <Badge tone="neutral">{detectionEngineLabel(detection.engine)}</Badge>
          <Badge
            tone={
              detection.certainty === "exact"
                ? "ok"
                : detection.certainty === "strong_heuristic"
                  ? "info"
                  : "warn"
            }
          >
            {detectionCertaintyLabel(detection.certainty)}
          </Badge>
        </div>
      </header>
      {detection.vendor && <div className="detection-version">vendor: {detection.vendor}</div>}
      {detection.version && <div className="detection-version mono">version {detection.version}</div>}
      {detection.options.length > 0 && (
        <div className="detection-version">options: {detection.options.join(", ")}</div>
      )}
      {detection.description && <p>{detection.description}</p>}
      {detection.compatibility && (
        <p className="compatibility-note">{detection.compatibility}</p>
      )}
      <div className="muted small mono">ID: {detection.id}</div>
      <ul className="evidence-list">
        {detection.evidence.map((evidence, index) => (
          <li key={`${evidence.condition}-${index}`}>
            {evidence.description}
            {evidence.offset !== null && <span className="muted mono"> @ {fmtHex(evidence.offset)}</span>}
          </li>
        ))}
      </ul>
      <footer className="muted small">Source: {detection.source}</footer>
    </article>
  );
}



export function YaraTab({ report }: { report: Report }) {
  const [query, setQuery] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const yara = report.yara;
  const matches = yara.matches.filter((match) => {
    const q = query.toLowerCase();
    if (!q) return true;
    return (
      match.rule.toLowerCase().includes(q) ||
      (match.description ?? "").toLowerCase().includes(q) ||
      match.tags.some((tag) => tag.toLowerCase().includes(q))
    );
  });

  const selected =
    matches.find((match) => `${match.namespace}:${match.rule}` === selectedKey) ?? null;
  const selectedSource = selected
    ? yara.sources.find((source) => source.origin === selected.origin) ?? null
    : null;
  const selectedCompileError = selected
    ? yara.compile?.errors.filter((error) => error.source === selected.origin) ?? []
    : [];

  if (!yara.enabled) {
    return <NotApplicable title="YARA disabled" reason="Enable YARA rules in Settings to scan samples locally with YARA-X." />;
  }

  return (
    <div className="tab-stack">
      <SectionCard
        title={`YARA-X matches (${yara.matches.length})`}
        extra={<SearchInput value={query} onChange={setQuery} placeholder="Filter rule or tag…" />}
      >
        <div className="stats-row">
          <span><strong>{fmtNum(yara.ruleCount)}</strong> rules compiled</span>
          <span>YARA-X {yara.engineVersion}</span>
          <span>{yara.elapsedMs} ms</span>
          {yara.compile && <span>{yara.compile.files} files</span>}
          <span>{fmtNum(yara.internalMatches)} internal / {fmtNum(yara.externalMatches)} external matches</span>
          <span>{fmtNum(yara.internalSources)} internal / {fmtNum(yara.externalSources)} external sources</span>
          <span className="mono" title={yara.revision}>
            rev {yara.revision ? yara.revision.slice(0, 12) : "unavailable"}
          </span>
          {yara.compile && yara.compile.errors.length > 0 && (
            <Badge tone="warn">{yara.compile.errors.length} compile errors</Badge>
          )}
        </div>
        {matches.length === 0 ? (
          <p className="muted">{yara.matches.length === 0 ? "No YARA rule matched this file." : "No match matches the filter."}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Tags</th>
                  <th>Description</th>
                  <th>Author</th>
                  <th>Reference</th>
                  <th>Origin</th>
                </tr>
              </thead>
              <tbody>
                {matches.map((match, index) => {
                  const key = `${match.namespace}:${match.rule}`;
                  return (
                  <tr
                    key={`${match.namespace}-${match.rule}-${index}`}
                    className={`selectable-row ${selectedKey === key ? "row-selected" : ""}`}
                    tabIndex={0}
                    onClick={() => setSelectedKey(selectedKey === key ? null : key)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedKey(selectedKey === key ? null : key);
                      }
                    }}
                    aria-selected={selectedKey === key}
                  >
                    <td className="mono">{match.rule}</td>
                    <td>
                      <div className="chips">
                        {match.tags.length === 0 ? <span className="muted">none</span> : match.tags.map((tag) => <Badge key={tag}>{tag}</Badge>)}
                      </div>
                    </td>
                    <td>{match.description ?? "—"}</td>
                    <td>{match.author ?? "—"}</td>
                    <td className="mono small">{match.reference ?? "—"}</td>
                    <td className="mono small" title={match.origin}>
                      <Badge tone={match.scope === "external" ? "info" : "neutral"}>
                        {match.scope || "unknown"}
                      </Badge>{" "}
                      {match.origin.split(/[\\/]/).slice(-2).join("/")}
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {selected && (
          <div className="yara-detail">
            <div className="yara-detail-head">
              <strong className="mono">{selected.rule}</strong>
              <span className="mono muted">{selected.namespace}</span>
              <Badge tone={selected.strings.length > 0 ? "info" : "neutral"}>
                {selected.strings.length} pattern matches
              </Badge>
            </div>
            <div className="yara-detail-grid">
              <div>
                <span className="meta-label">Source file</span>
                <code className="mono" title={selected.origin}>{selected.origin}</code>
              </div>
              <div>
                <span className="meta-label">Source type</span>
                <span>
                  {selected.scope || "unknown"}
                  {selected.sourceId ? ` · ${selected.sourceId}` : ""}
                </span>
              </div>
              <div>
                <span className="meta-label">Tags</span>
                <span>{selected.tags.length > 0 ? selected.tags.join(", ") : "none"}</span>
              </div>
              <div>
                <span className="meta-label">Description</span>
                <span>{selected.description ?? "No description"}</span>
              </div>
              <div>
                <span className="meta-label">Namespace</span>
                <span className="mono">{selected.namespace}</span>
              </div>
              <div>
                <span className="meta-label">Rule-set revision</span>
                <span className="mono" title={yara.revision}>{yara.revision ? yara.revision.slice(0, 16) : "unavailable"}</span>
              </div>
              <div>
                <span className="meta-label">Compilation</span>
                <span>
                  {selectedCompileError.length === 0 ? "compiled" : "rejected"}
                  {" · "}YARA-X {yara.engineVersion}
                </span>
              </div>
            </div>
            <h4>Match evidence</h4>
            {selected.strings.length === 0 ? (
              <p className="muted small">
                YARA-X did not report pattern evidence for this rule. The condition may not depend on
                string matches; this is not a missing detection.
              </p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Pattern</th>
                      <th>Offset</th>
                      <th>Length</th>
                      <th>Bytes</th>
                      <th>Data</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.strings.map((evidence, index) => (
                      <tr key={`${evidence.identifier}-${evidence.offset}-${index}`}>
                        <td className="mono">{evidence.identifier}</td>
                        <td className="mono">{fmtHex(evidence.offset, 8)}</td>
                        <td className="mono">{evidence.length}</td>
                        <td className="mono small">{evidence.hex}</td>
                        <td className="mono">{evidence.data}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <details>
              <summary>Rule metadata</summary>
              <pre className="code-block">{JSON.stringify(selected.metadata, null, 2)}</pre>
            </details>
            <details>
              <summary>Original rule source</summary>
              {selectedSource?.text ? (
                <>
                  {selectedSource.truncated && (
                    <p className="muted small">
                      Source display is truncated at 256 KiB; the SHA-256 covers the full file.
                    </p>
                  )}
                  <pre className="code-block rule-source">{selectedSource.text}</pre>
                  <p className="muted small mono">SHA-256 {selectedSource.sha256}</p>
                </>
              ) : (
                <p className="muted small">
                  Source text is unavailable for this rule. The file may have changed after the
                  inventory was built, or the compiled source exceeded the display limit.
                </p>
              )}
            </details>
            {selectedCompileError.length > 0 && (
              <div className="error-box">
                {selectedCompileError.map((error, index) => (
                  <div key={`${error.message}-${index}`}>{error.message}</div>
                ))}
              </div>
            )}
          </div>
        )}
        {yara.errors.length > 0 && (
          <div className="error-box">
            {yara.errors.map((error, index) => (
              <div key={`${error}-${index}`}>{error}</div>
            ))}
          </div>
        )}
        {yara.compile && yara.compile.errors.length > 0 && (
          <details>
            <summary>YARA compile diagnostics</summary>
            <ul className="plain-list">
              {yara.compile.errors.map((error, index) => (
                <li key={`${error.source}-${index}`}>
                  <span className="mono">{error.source}</span>: {error.message}
                </li>
              ))}
            </ul>
          </details>
        )}
      </SectionCard>
    </div>
  );
}



export function VirusTotalTab({
  report,
  settings,
  keyConfigured,
  onOpenSettings,
  onNotify,
}: {
  report: Report;
  settings: AppSettings | null;
  keyConfigured: boolean;
  onOpenSettings: () => void;
  onNotify: Notify;
}) {
  const [result, setResult] = useState<VtFileReport | null>(null);
  const [lookupState, setLookupState] = useState<"idle" | "loading" | "done" | "missing">("idle");
  const [error, setError] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<VtUploadReceipt | null>(null);
  const [uploading, setUploading] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [engineQuery, setEngineQuery] = useState("");
  const [engineCategory, setEngineCategory] = useState("all");

  const enabled = settings?.virustotalEnabled ?? false;
  const uploadTooLarge = report.file.size > 32 * 1024 * 1024;

  const lookup = async () => {
    setError(null);
    setLookupState("loading");
    try {
      const data = await vtLookup(report.file.sha256);
      if (data) {
        setResult(data);
        setLookupState("done");
      } else {
        setResult(null);
        setLookupState("missing");
      }
    } catch (err) {
      setLookupState("idle");
      setError(String(err));
    }
  };

  const upload = async () => {
    setConfirmOpen(false);
    setUploading(true);
    setError(null);
    try {
      const data = await vtUpload(report.file.path, true);
      setReceipt(data);
      onNotify("File submitted to VirusTotal. Analysis may take a few minutes.");
    } catch (err) {
      setError(String(err));
    } finally {
      setUploading(false);
    }
  };

  const refreshAnalysis = async () => {
    if (!receipt) return;
    setError(null);
    try {
      const data = await vtAnalysis(receipt.analysisId);
      setReceipt(data);
      if (data.status === "completed") {
        await lookup();
      }
    } catch (err) {
      setError(String(err));
    }
  };

  if (!enabled) {
    return (
      <NotApplicable title="VirusTotal integration is disabled" reason="The local analyzer works fully offline. Enable VirusTotal in Settings if you want to query or upload samples.">
        <button type="button" onClick={onOpenSettings}>Open settings</button>
      </NotApplicable>
    );
  }

  if (!keyConfigured) {
    return (
      <NotApplicable title="No VirusTotal API key" reason="Store an API key in the Windows Credential Manager through Settings. Keys are never written to the report or source code.">
        <button type="button" onClick={onOpenSettings}>Configure API key</button>
      </NotApplicable>
    );
  }

  const categories = Array.from(new Set(result?.engines.map((engine) => engine.category) ?? [])).sort();
  const q = engineQuery.toLowerCase();
  const engines = (result?.engines ?? []).filter((engine) => {
    if (engineCategory !== "all" && engine.category !== engineCategory) return false;
    if (!q) return true;
    return (
      engine.engine.toLowerCase().includes(q) ||
      (engine.result ?? "").toLowerCase().includes(q) ||
      engine.category.toLowerCase().includes(q)
    );
  });

  return (
    <div className="tab-stack">
      <SectionCard
        title="VirusTotal lookup"
        extra={
          <button type="button" onClick={lookup} disabled={lookupState === "loading"}>
            {lookupState === "loading" ? "Querying…" : "Check existing report"}
          </button>
        }
      >
        <p className="muted small">
          Only the SHA-256 hash is sent for lookups. No file content leaves this device unless you explicitly upload
          it below. Requests respect API quotas and timeouts.
        </p>
        <Field label="SHA-256" value={report.file.sha256} copy={report.file.sha256} onCopied={onNotify} mono />
        {lookupState === "missing" && (
          <p className="warn-text">VirusTotal has no existing analysis for this hash. You may upload the file explicitly.</p>
        )}
        {error && <div className="error-box">{error}</div>}
        {result && (
          <>
            <div className="vt-stats">
              <div className="vt-stat vt-malicious">
                <span>{result.stats.malicious}</span>
                <label>malicious</label>
              </div>
              <div className="vt-stat vt-suspicious">
                <span>{result.stats.suspicious}</span>
                <label>suspicious</label>
              </div>
              <div className="vt-stat vt-harmless">
                <span>{result.stats.harmless}</span>
                <label>harmless</label>
              </div>
              <div className="vt-stat">
                <span>{result.stats.undetected}</span>
                <label>undetected</label>
              </div>
              <div className="vt-stat">
                <span>{result.stats.timeout + result.stats.failure + result.stats.typeUnsupported}</span>
                <label>other</label>
              </div>
            </div>
            <div className="field-grid">
              <Field label="Name" value={result.meaningfulName} />
              <Field label="Type" value={result.typeDescription} />
              <Field label="Reputation" value={result.reputation} />
              <Field label="Times submitted" value={result.timesSubmitted} />
              <Field label="Last analysis" value={fmtTimestamp(result.lastAnalysisDate)} />
              <Field label="First submission" value={fmtTimestamp(result.firstSubmissionDate)} />
            </div>
            <div className="chips">
              {result.tags.map((tag) => (
                <Badge key={tag}>{tag}</Badge>
              ))}
            </div>
            <div className="toolbar">
              <span className="muted small mono">{result.permalink}</span>
              <CopyButton value={result.permalink} label="copy link" onCopied={onNotify} />
            </div>
            <div className="toolbar">
              <select value={engineCategory} onChange={(event) => setEngineCategory(event.target.value)}>
                <option value="all">All verdicts</option>
                {categories.map((category) => (
                  <option key={category} value={category}>
                    {category}
                  </option>
                ))}
              </select>
              <SearchInput value={engineQuery} onChange={setEngineQuery} placeholder="Filter engine or result…" />
            </div>
            <div className="table-wrap scroll-y">
              <table>
                <thead>
                  <tr>
                    <th>Engine</th>
                    <th>Verdict</th>
                    <th>Result</th>
                    <th>Method</th>
                    <th>Engine version</th>
                    <th>Definitions</th>
                  </tr>
                </thead>
                <tbody>
                  {engines.map((engine) => (
                    <tr key={engine.engine}>
                      <td>{engine.engine}</td>
                      <td>
                        <Badge tone={engine.category === "malicious" ? "danger" : engine.category === "suspicious" ? "warn" : "neutral"}>
                          {engine.category}
                        </Badge>
                      </td>
                      <td className="mono">{engine.result ?? "—"}</td>
                      <td>{engine.method ?? "—"}</td>
                      <td className="mono">{engine.engineVersion ?? "—"}</td>
                      <td className="mono">{engine.engineUpdate ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="muted small">{fmtNum(vtTotal(result.stats))} engines reported a verdict.</p>
          </>
        )}
      </SectionCard>

      <SectionCard title="Upload sample">
        <div className="warning-box">
          <strong>Uploading shares file content with VirusTotal.</strong>
          <p>
            The file may contain confidential or personal data. VirusTotal is an external service and may share
            samples with security partners. BinScope never uploads automatically; the file is only sent after you
            confirm.
          </p>
          <p className="mono small">{report.file.path}</p>
          <p className="small">
            Size {report.file.sizeHuman}, Standard API limit 32 MiB
            {uploadTooLarge ? ", this file exceeds the standard upload limit" : ""}
          </p>
        </div>
        <div className="toolbar">
          <button
            type="button"
            className="danger"
            disabled={uploading || uploadTooLarge}
            onClick={() => setConfirmOpen(true)}
          >
            {uploading ? "Uploading…" : "Upload to VirusTotal…"}
          </button>
          {uploadTooLarge && <span className="warn-text">Upload disabled: file exceeds 32 MiB.</span>}
        </div>
        {receipt && (
          <div className="notice-box">
            <div>
              Analysis ID <code>{receipt.analysisId}</code>, status <strong>{receipt.status ?? "unknown"}</strong>
            </div>
            <div className="toolbar">
              <button type="button" className="ghost" onClick={refreshAnalysis}>
                Check analysis status
              </button>
              <span className="muted small">
                VirusTotal may need a few minutes. Polling is manual to avoid consuming quota.
              </span>
            </div>
          </div>
        )}
      </SectionCard>

      {confirmOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal small-modal">
            <h2>Confirm upload</h2>
            <p>
              You are about to upload <strong>{report.file.name}</strong> ({report.file.sizeHuman}) to VirusTotal, an
              external third-party service.
            </p>
            <ul className="plain-list">
              <li>The file content will leave this device.</li>
              <li>It may contain confidential, personal or licensed material.</li>
              <li>VirusTotal may retain and share submitted samples.</li>
              <li>Uploading consumes API quota and is subject to VirusTotal’s terms.</li>
            </ul>
            <div className="modal-actions">
              <button type="button" className="ghost" onClick={() => setConfirmOpen(false)}>
                Cancel
              </button>
              <button type="button" className="danger" onClick={upload}>
                I understand, upload
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}



function vtTotal(stats: VtStats): number {
  return (
    stats.harmless +
    stats.malicious +
    stats.suspicious +
    stats.undetected +
    stats.timeout +
    stats.failure +
    stats.typeUnsupported +
    stats.confirmedTimeout
  );
}

export function dateCell(value: number | null | undefined): string {
  return fmtDate(value);
}

export function shortText(value: string | null | undefined, max = 120): string {
  return value ? shorten(value, max) : "—";
}
