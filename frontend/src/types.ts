export type FormatKind =
  | "pe"
  | "dos_mz"
  | "ne"
  | "le"
  | "elf"
  | "mach_o"
  | "mach_o_fat"
  | "zip"
  | "seven_zip"
  | "rar"
  | "gzip"
  | "pdf"
  | "ole"
  | "script"
  | "unknown";

export type AnalysisStatus = "complete" | "partial" | "failed" | "cancelled";
export type IssueLevel = "info" | "warning" | "error";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type StringEncoding = "ascii" | "utf8" | "utf16_le";
export type DetectionCategory =
  | "packer"
  | "protector"
  | "compiler"
  | "linker"
  | "runtime"
  | "framework"
  | "installer"
  | "tool"
  | "signer"
  | "format"
  | "language"
  | "library"
  | "other";

export interface ToolInfo {
  name: string;
  version: string;
  engine: string;
}

export interface FileInfo {
  name: string;
  path: string;
  size: number;
  sizeHuman: string;
  sha256: string;
  sha1: string;
  md5: string;
  modifiedUtc: string | null;
}

export interface FormatInfo {
  kind: FormatKind;
  label: string;
  description: string;
  confidence: number;
  evidence: string[];
  supported: boolean;
  executable: boolean;
  architecture: string;
  bits: number;
  operatingSystem: string;
  fileType: string;
  isDotnet: boolean;
  managedness: string;
}

export interface AnalysisIssue {
  stage: string;
  level: IssueLevel;
  message: string;
}

export interface AnalysisMeta {
  startedUtc: string;
  finishedUtc: string;
  durationMs: number;
  status: AnalysisStatus;
  issues: AnalysisIssue[];
  timeBudgetMs: number;
  parseLimitBytes: number;
}

export interface DetectionSummary {
  compilers: string[];
  linkers: string[];
  packers: string[];
  protectors: string[];
  runtimes: string[];
  frameworks: string[];
  installers: string[];
  tools: string[];
  languages: string[];
  libraries: string[];
  formats: string[];
  other: string[];
}

export interface Evidence {
  condition: string;
  description: string;
  offset: number | null;
  value: string | null;
}

export interface Detection {
  id: string;
  name: string;
  category: DetectionCategory;
  description: string;
  confidence: number;
  version: string | null;
  options: string[];
  evidence: Evidence[];
  source: string;
  vendor: string | null;
  certainty: "exact" | "strong_heuristic" | "possible" | "unknown";
  engine:
    | "internal_signatures"
    | "detect_it_easy"
    | "pebear"
    | "structural_heuristic"
    | "die_heuristic";
  compatibility: string | null;
}

export interface SignatureDatabaseInfo {
  name: string;
  version: string;
  source: string;
  signatures: number;
}

export interface SignatureSummary {
  enabled: boolean;
  databases: SignatureDatabaseInfo[];
  totalSignatures: number;
  errors: string[];
  die: DieSummary | null;
  pebear: PebearSummary | null;
}

export interface DieReason {
  reason: string;
  count: number;
}

export interface DieSummary {
  version: string;
  path: string;
  files: number;
  withMetadata: number;
  compatible: number;
  incompatible: number;
  reasons: DieReason[];
  errors: string[];
}

export interface PebearSummary {
  path: string;
  totalBlocks: number;
  loaded: number;
  skipped: number;
  reasons: DieReason[];
  errors: string[];
  license: string;
}

export interface YaraDiagnostic {
  source: string;
  message: string;
}

export interface YaraCompileReport {
  files: number;
  errors: YaraDiagnostic[];
  warnings: YaraDiagnostic[];
}

export interface YaraStringMatch {
  identifier: string;
  offset: number;
  length: number;
  data: string;
  hex: string;
}

export interface YaraSourceFile {
  origin: string;
  sourceId: string;
  scope: string;
  sha256: string;
  bytes: number;
  text: string | null;
  truncated: boolean;
}

export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string[];
  description: string | null;
  author: string | null;
  reference: string | null;
  metadata: unknown;
  source: string;
  origin: string;
  sourceId: string;
  scope: string;
  strings: YaraStringMatch[];
}

export interface YaraReport {
  enabled: boolean;
  engineVersion: string;
  matches: YaraMatch[];
  ruleCount: number;
  compile: YaraCompileReport | null;
  revision: string;
  sources: YaraSourceFile[];
  externalMatches: number;
  internalMatches: number;
  externalSources: number;
  internalSources: number;
  errors: string[];
  elapsedMs: number;
}

export interface StringsSummary {
  total: number;
  ascii: number;
  utf8: number;
  utf16le: number;
  truncated: boolean;
  totalFound: number;
  bytesScanned: number;
  elapsedMs: number;
  minLen: number;
}

export interface StringClassification {
  kind: string;
  confidence: number;
  note: string | null;
}

export interface ExtractedString {
  offset: number;
  encoding: StringEncoding;
  value: string;
  truncated: boolean;
  section: string | null;
  classifications: StringClassification[];
}

export interface StringsSection {
  summary: StringsSummary;
  items: ExtractedString[];
}

export interface SectionInfo {
  index: number;
  name: string;
  nameIsIrregular: boolean;
  virtualAddress: number;
  virtualSize: number;
  rawOffset: number;
  rawSize: number;
  characteristics: number;
  permissions: string;
  flags: string[];
  entropy: number;
  executable: boolean;
  writable: boolean;
  readable: boolean;
  isBss: boolean;
}

export interface DataDirectoryInfo {
  index: number;
  name: string;
  rva: number;
  size: number;
  fileOffset: number | null;
  present: boolean;
  note: string | null;
}

export interface ImportFunction {
  name: string | null;
  ordinal: number | null;
  hint: number | null;
}

export interface ImportLibrary {
  name: string;
  descriptorRva: number;
  functions: ImportFunction[];
  nameIsIrregular: boolean;
}

export interface ExportInfo {
  name: string | null;
  ordinal: number;
  rva: number;
  fileOffset: number | null;
  forwarder: string | null;
}

export interface ResourceEntry {
  typeId: number | null;
  typeName: string;
  nameId: number | null;
  name: string;
  language: number;
  codepage: number;
  rva: number;
  size: number;
  fileOffset: number | null;
}

export interface KeyValue {
  key: string;
  value: string;
}

export interface VersionInfo {
  fixedFileVersion: string | null;
  fixedProductVersion: string | null;
  companyName: string | null;
  productName: string | null;
  fileDescription: string | null;
  fileVersion: string | null;
  productVersion: string | null;
  internalName: string | null;
  originalFilename: string | null;
  legalCopyright: string | null;
  comments: string | null;
  entries: KeyValue[];
}

export interface PdbInfo {
  path: string;
  guid: string | null;
  age: number | null;
  signature: string;
  debugDirectoryRva: number;
  dataFileOffset: number | null;
}

export interface DebugEntryInfo {
  index: number;
  debugType: number;
  typeName: string;
  timestamp: number;
  timestampUtc: string | null;
  majorVersion: number;
  minorVersion: number;
  sizeOfData: number;
  addressRva: number;
  fileOffset: number | null;
  status: string;
}

export interface RichEntry {
  productId: number;
  buildNumber: number;
  count: number;
}

export interface RichHeaderInfo {
  offset: number;
  key: number;
  entries: RichEntry[];
  productIds: number[];
}

export interface ClrDirectory {
  headerSize: number;
  runtimeVersion: string;
  metadataRva: number;
  metadataSize: number;
  metadataFileOffset: number | null;
  flags: number;
  flagNames: string[];
  entryPointToken: number;
  entryPointKind: string;
  resourcesRva: number;
  resourcesSize: number;
  strongNameRva: number;
  strongNameSize: number;
  strongNameSigned: boolean;
  metadataVersion: string | null;
}

export interface CertificateEntry {
  offset: number;
  length: number;
  revision: number;
  revisionName: string;
  certificateType: number;
  certificateTypeName: string;
  containsNestedSignatureOid: boolean;
  dataOffset: number;
  dataLength: number;
  inBounds: boolean;
}

export interface CertificateInfo {
  present: boolean;
  directoryOffset: number;
  directorySize: number;
  entries: CertificateEntry[];
  note: string;
}

export interface OverlayInfo {
  offset: number;
  size: number;
  entropy: number | null;
  sha256: string | null;
}

export type AnomalyCategory = "malformed" | "suspicious" | "informational";
export type AnomalyConfidence = "high" | "medium" | "low";
export type EvidenceKind =
  | "section_header"
  | "file_range"
  | "rva"
  | "data_directory"
  | "header_field"
  | "overlay"
  | "certificate_table"
  | "debug_directory"
  | "entropy"
  | "checksum";

export interface AnomalyEvidence {
  kind: EvidenceKind;
  label: string;
  value: string;
  fileOffset: number | null;
  rva: number | null;
  section: string | null;
}

export interface Anomaly {
  ruleId: string;
  code: string;
  severity: Severity;
  title: string;
  message: string;
  explanation: string;
  category: AnomalyCategory | null;
  confidence: AnomalyConfidence | null;
  evidence: AnomalyEvidence[];
  fileOffset: number | null;
  rva: number | null;
  sections: string[];
  expected: string | null;
  observed: string | null;
  falsePositiveNotes: string;
}

export type SignaturePresence = "none" | "malformed" | "present";
export type SignatureValidity = "valid" | "invalid" | "not_verified" | "unavailable";
export type ChainTrust = "trusted" | "untrusted" | "not_checked" | "unknown" | "unavailable";
export type CertificateTimeStatus = "valid" | "expired" | "not_yet_valid" | "unknown" | "not_checked";
export type RevocationStatus = "good" | "revoked" | "unavailable" | "unknown" | "not_checked";
export type VerificationBackend = "windows_crypto_api" | "unavailable";

export interface SignatureCheck {
  entryIndex: number;
  certificateType: string;
  digestAlgorithm: string | null;
  signedDigest: string | null;
  computedDigest: string | null;
  digestMatches: boolean | null;
  status: string;
  note: string;
}

export interface AuthenticodeReport {
  presence: SignaturePresence;
  signature: SignatureValidity;
  chain: ChainTrust;
  certificateTime: CertificateTimeStatus;
  revocation: RevocationStatus;
  backend: VerificationBackend;
  digestAlgorithm: string | null;
  signedDigest: string | null;
  computedDigest: string | null;
  digestMatches: boolean | null;
  signer: { subject: string | null } | null;
  signatures: SignatureCheck[];
  winverifyStatus: string | null;
  winverifyStatusText: string | null;
  counterSignatures: number;
  platformSupported: boolean;
  notes: string[];
}

export interface CodeViewRecord {
  debugIndex: number;
  signature: string;
  pdbPath: string | null;
  guid: string | null;
  age: number | null;
  timestamp: number | null;
  timestampUtc: string | null;
  dataOffset: number | null;
  dataSize: number;
  status: string;
  primary: boolean;
  source: string;
}

export interface PeInfo {
  peKind: string;
  is64: boolean;
  machine: number;
  machineName: string;
  architecture: string;
  bits: number;
  numberOfSections: number;
  timeDateStamp: number;
  timeDateStampUtc: string | null;
  characteristics: number;
  characteristicNames: string[];
  dllCharacteristics: number;
  dllCharacteristicNames: string[];
  imageBase: number;
  entryPointRva: number;
  entryPointFileOffset: number | null;
  sizeOfImage: number;
  sizeOfHeaders: number;
  optionalHeaderOffset: number;
  sectionTableOffset: number;
  sectionAlignment: number;
  fileAlignment: number;
  subsystem: number;
  subsystemName: string;
  isDll: boolean;
  isDriver: boolean;
  linkerVersion: string;
  osVersion: string;
  imageVersion: string;
  subsystemVersion: string;
  checksum: number;
  computedChecksum: number;
  checksumValid: boolean;
  numberOfRvaAndSizes: number;
  dataDirectories: DataDirectoryInfo[];
  sections: SectionInfo[];
  exportsDllName: string | null;
  exports: ExportInfo[];
  imports: ImportLibrary[];
  delayImports: ImportLibrary[];
  resources: ResourceEntry[];
  versionInfo: VersionInfo | null;
  manifest: string | null;
  pdb: PdbInfo | null;
  codeviewRecords: CodeViewRecord[];
  debugEntries: DebugEntryInfo[];
  pdbPathWarning: string | null;
  richHeader: RichHeaderInfo | null;
  clr: ClrDirectory | null;
  certificate: CertificateInfo;
  tlsCallbacks: number[];
  overlay: OverlayInfo | null;
  anomalies: Anomaly[];
  parseNotes: string[];
}

export interface DotNetAssembly {
  name: string;
  version: string;
  culture: string | null;
  publicKeySize: number;
  flags: number;
}

export interface AssemblyReference {
  name: string;
  version: string;
}

export interface TableRowCount {
  table: string;
  rows: number;
}

export interface MetadataStream {
  name: string;
  offset: number;
  size: number;
}

export interface DotNetInfo {
  runtimeVersion: string;
  metadataVersion: string | null;
  streams: MetadataStream[];
  flags: number;
  flagNames: string[];
  entryPointToken: number;
  entryPointKind: string;
  strongNameSigned: boolean;
  kind: string;
  assembly: DotNetAssembly | null;
  moduleName: string | null;
  assemblyReferences: AssemblyReference[];
  tableRowCounts: TableRowCount[];
  typeDefinitionCount: number;
  methodDefinitionCount: number;
}

export interface ElfProgramHeader {
  index: number;
  typeName: string;
  flags: string;
  offset: number;
  virtualAddress: number;
  physicalAddress: number;
  fileSize: number;
  memorySize: number;
  align: number;
}

export interface ElfSection {
  index: number;
  name: string;
  typeName: string;
  flags: string[];
  address: number;
  offset: number;
  size: number;
  align: number;
  entropy: number;
  executable: boolean;
  writable: boolean;
}

export interface ElfInfo {
  class: string;
  is64: boolean;
  endianness: string;
  osAbi: string;
  abiVersion: number;
  objectType: number;
  objectTypeName: string;
  machine: number;
  machineName: string;
  architecture: string;
  bits: number;
  entryPoint: number;
  loadBase: number;
  flags: number;
  isPie: boolean;
  isSharedObject: boolean;
  interpreter: string | null;
  soname: string | null;
  neededLibraries: string[];
  rpaths: string[];
  runpaths: string[];
  programHeaders: ElfProgramHeader[];
  sections: ElfSection[];
  imports: string[];
  exports: string[];
  buildId: string | null;
  notes: string[];
}

export interface MachSegment {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  fileOffset: number;
  fileSize: number;
  protections: string;
}

export interface MachSliceInfo {
  architecture: string;
  bits: number;
  cpuType: number;
  cpuSubtype: number;
  fileType: number;
  fileTypeName: string;
  entryPoint: number;
  is64: boolean;
  segments: MachSegment[];
  imports: string[];
  exports: string[];
  libraries: string[];
  rpaths: string[];
  installName: string | null;
}

export interface MachOInfo {
  isFat: boolean;
  sliceCount: number;
  slices: MachSliceInfo[];
  notes: string[];
}

export interface DetectionConfig {
  profile: string | null;
  yaraEnabled: boolean;
  signaturesEnabled: boolean;
  disabledYaraCategories: string[];
  disabledYaraRules: string[];
  disabledSignatureCategories: string[];
  disabledSignatures: string[];
}

export interface Report {
  schemaVersion: number;
  tool: ToolInfo;
  analysis: AnalysisMeta;
  file: FileInfo;
  format: FormatInfo;
  summary: DetectionSummary;
  pe: PeInfo | null;
  elf: ElfInfo | null;
  macho: MachOInfo | null;
  dotnet: DotNetInfo | null;
  detections: Detection[];
  signatures: SignatureSummary;
  yara: YaraReport;
  authenticode: AuthenticodeReport | null;
  detectionConfig: DetectionConfig;
  strings: StringsSection | null;
  notes: string[];
}

export interface AnalysisProgress {
  analysisId?: string;
  stage: string;
  percent: number;
  message: string;
}

export interface AppSettings {
  includeStrings: boolean;
  minStringLen: number;
  maxStrings: number;
  signaturesEnabled: boolean;
  builtinSignatures: boolean;
  signatureDirs: string[];
  dieEnabled: boolean;
  dieSignatureDir: string | null;
  pebearEnabled: boolean;
  pebearSigPath: string | null;
  yaraEnabled: boolean;
  yaraRuleDirs: string[];
  virustotalEnabled: boolean;
  theme: string;
  retainHistory: boolean;
}

export type ContextMenuState =
  | "unavailable"
  | "disabled"
  | "enabled"
  | "stale"
  | "partial"
  | "failed"
  | "foreign";

export interface ContextMenuRegistration {
  key: string;
  installed: boolean;
  current: boolean;
  commandOk: boolean;
  executableExists: boolean;
  executable: string | null;
}

export interface ContextMenuStatus {
  supported: boolean;
  installed: boolean;
  foreignEntry: boolean;
  canWrite: boolean;
  requiresAdmin: boolean;
  preferenceEnabled: boolean;
  state: ContextMenuState;
  partial: boolean;
  executable: string | null;
  registeredExecutable: string | null;
  executableExists: boolean;
  stale: boolean;
  registrations: ContextMenuRegistration[];
  missingTargets: string[];
  staleTargets: string[];
  conflicts: string[];
  diagnostics: string[];
  registryKey: string;
  detail: string;
}

export interface ContextMenuFailure {
  kind:
    | "unsupported"
    | "permission_denied"
    | "conflict"
    | "executable_unavailable"
    | "development_build"
    | "partial"
    | "busy"
    | "registry"
    | "not_enabled";
  message: string;
  remaining?: string[];
}

export interface AppInfo {
  version: string;
  bundledDieDir: string | null;
  bundledYaraDir: string | null;
  bundledSignatureDir: string | null;
  dataDir: string;
  virusTotalKeyConfigured: boolean;
  yaraEngineVersion: string;
  portable: boolean;
}

export interface UpdateRecord {
  source: string;
  version: string;
  updatedAt: string;
  archiveSha256: string | null;
  files: number;
  added: number;
  removed: number;
  modified: number;
  excluded: number;
  status: string;
  message: string | null;
}

export interface UpdateState {
  die: UpdateRecord | null;
  pebear: UpdateRecord | null;
  yara: UpdateRecord | null;
}

export interface VtStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
  failure: number;
  typeUnsupported: number;
  confirmedTimeout: number;
}

export interface VtEngineResult {
  engine: string;
  category: string;
  result: string | null;
  method: string | null;
  engineVersion: string | null;
  engineUpdate: string | null;
}

export interface VtFileReport {
  sha256: string;
  sha1: string | null;
  md5: string | null;
  meaningfulName: string | null;
  typeDescription: string | null;
  size: number | null;
  reputation: number | null;
  timesSubmitted: number | null;
  uniqueSources: number | null;
  tags: string[];
  lastAnalysisDate: number | null;
  firstSubmissionDate: number | null;
  lastSubmissionDate: number | null;
  stats: VtStats;
  engines: VtEngineResult[];
  permalink: string;
}

export interface VtUploadReceipt {
  analysisId: string;
  status: string | null;
}




export type RuleStatus =
  | "compatible"
  | "invalid"
  | "incompatible"
  | "pending"
  | "quarantined"
  | "duplicate"
  | "license_blocked"
  | "obsolete";

export type MatchKind = "exact" | "probable" | "heuristic";

export interface YaraRuleEntry {
  id: string;
  name: string;
  description: string;
  categories: string[];
  tags: string[];
  sourceId: string;
  source: string;
  path: string;
  author: string | null;
  license: string | null;
  hash: string;
  added: string | null;
  modified: string | null;
  status: RuleStatus;
  enabled: boolean;
  namespace: string;
  revision: string;
  version: string | null;
  severity: string | null;
  confidence: number | null;
  dependencies: string[];
  errors: string[];
}

export interface SignatureEntry {
  id: string;
  name: string;
  description: string;
  category: string;
  format: string | null;
  version: string | null;
  sourceId: string;
  source: string;
  license: string | null;
  status: RuleStatus;
  enabled: boolean;
  confidence: number;
  kind: MatchKind;
  pattern: string | null;
  offsets: string | null;
  product: string | null;
  evidence: string[];
  compatibility: string | null;
}

export interface CategoryInfo {
  id: string;
  label: string;
  description: string;
  total: number;
  enabled: number;
  invalid: number;
}

export interface InventoryStats {
  yaraInstalled: number;
  yaraEnabled: number;
  yaraDisabled: number;
  yaraInvalid: number;
  signaturesInstalled: number;
  signaturesEnabled: number;
  signaturesDisabled: number;
  signaturesInvalid: number;
  sourcesEnabled: number;
  sourcesTotal: number;
  pendingUpdates: number;
}

export interface SourceDefinition {
  id: string;
  name: string;
  url: string;
  kind: string;
  method: string;
  repo: string | null;
  branch: string | null;
  asset: string | null;
  includePrefixes: string[];
  license: string | null;
  licenseUrl: string | null;
  defaultEnabled: boolean;
  implemented: boolean;
  notes: string;
}

export interface SourceStatus {
  id: string;
  name: string;
  url: string;
  kind: string;
  method: string;
  repo: string | null;
  branch: string | null;
  asset: string | null;
  includePrefixes: string[];
  license: string | null;
  licenseUrl: string | null;
  defaultEnabled: boolean;
  implemented: boolean;
  notes: string;
  enabled: boolean;
  lastCheck: string | null;
  lastSuccess: string | null;
  version: string | null;
  commit: string | null;
  artifactSha256: string | null;
  imported: number;
  accepted: number;
  rejected: number;
  duplicates: number;
  compatibility: string;
  errors: string[];
  warnings: string[];
  pending: boolean;
}

export interface SignatureSourceInfo {
  id: string;
  name: string;
  license: string | null;
  version: string | null;
  installed: number;
  compatible: number;
  incompatible: number;
  lastUpdate: string | null;
  notes: string;
}

export interface RuleInventory {
  generatedAt: string;
  revision: string;
  yaraRules: YaraRuleEntry[];
  signatures: SignatureEntry[];
  yaraCategories: CategoryInfo[];
  signatureCategories: CategoryInfo[];
  sources: SourceStatus[];
  signatureSources: SignatureSourceInfo[];
  sourceErrors: string[];
  stats: InventoryStats;
}

export interface UpdatePreferences {
  autoCheck: boolean;
  intervalHours: number;
  lastCheck: string | null;
  lastUpdate: string | null;
}

export interface FalsePositive {
  ruleId: string;
  sha256: string | null;
  name: string;
  markedAt: string;
}

export interface RuleProfile {
  id: string;
  name: string;
  description: string;
  yaraCategories: string[];
  signatureCategories: string[];
  builtin: boolean;
}

export interface RulePreferences {
  schema: number;
  yaraEnabled: boolean;
  signaturesEnabled: boolean;
  disabledYaraCategories: string[];
  disabledYaraRules: string[];
  disabledSignatureCategories: string[];
  disabledSignatures: string[];
  enabledSources: string[];
  update: UpdatePreferences;
  profile: string;
  customProfiles: RuleProfile[];
  falsePositives: FalsePositive[];
}

export interface ChangelogEntry {
  at: string;
  sourceId: string;
  sourceName: string;
  fromVersion: string | null;
  version: string;
  added: number;
  removed: number;
  modified: number;
  invalid: number;
  status: string;
  message: string;
}

export interface UpdateLogEntry {
  at: string;
  sourceId: string;
  level: string;
  message: string;
}

export interface SourceUpdateResult {
  sourceId: string;
  status: string;
  version: string | null;
  accepted: number;
  rejected: number;
  message: string;
}

export interface ScheduledUpdateResult {
  checked: number;
  updated: number;
  unchanged: number;
  errors: number;
  records: SourceUpdateResult[];
}

export interface RuleImportResult {
  accepted: number;
  rejected: number;
  files: string[];
  errors: string[];
}

export interface SourceConfigInput {
  name: string;
  repoUrl: string;
  branch: string;
  license: string | null;
  includePrefixes: string[];
}

export interface HistoryEntry {
  id: string;
  analyzedAt: string;
  name: string;
  path: string;
  sha256: string;
  size: number;
  sizeHuman: string;
  format: string;
  status: string;
  detections: number;
  durationMs: number;
}
export type BatchJobState = "queued" | "running" | "completed" | "failed" | "cancelled";
export type BatchFileState =
  | "queued"
  | "hashing"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "reused";

export interface BatchLimits {
  maxFiles: number;
  maxDepth: number;
  maxScanEntries: number;
  concurrency: number;
}

export interface BatchFileView {
  index: number;
  path: string;
  name: string;
  size: number | null;
  state: BatchFileState;
  sha256: string | null;
  reusedFrom: number | null;
  error: string | null;
  hasReport: boolean;
  anomalies: number;
  yara: number;
  signatures: number;
  debug: string | null;
  format: string | null;
  architecture: string | null;
  durationMs: number;
}

export interface BatchJobView {
  id: string;
  state: BatchJobState;
  createdUtc: string;
  startedUtc: string | null;
  finishedUtc: string | null;
  concurrency: number;
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
  reused: number;
  errors: string[];
  files: BatchFileView[];
}

export interface BatchClearResult {
  removed: number;
  remaining: number;
}

export interface BatchExportRow {
  file: string;
  path: string;
  sha256: string;
  format: string;
  architecture: string;
  size: number;
  anomalies: number;
  yara: number;
  signatures: number;
  debug: string;
  status: string;
  reusedFrom: string | null;
}

export interface DirectoryListing {
  files: string[];
  errors: string[];
}
