import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { RuleInventory, RulePreferences, YaraRuleEntry } from "../types";

const api = vi.hoisted(() => ({
  addRuleSource: vi.fn(),
  applyRuleProfile: vi.fn(),
  getDetectionInventory: vi.fn(),
  getRuleChangelog: vi.fn(),
  getRuleLogs: vi.fn(),
  getRulePreferences: vi.fn(),
  getRuleSources: vi.fn(),
  getYaraRuleSource: vi.fn(),
  importCustomYaraRules: vi.fn(),
  importRulePreferencesFile: vi.fn(),
  exportRulePreferencesFile: vi.fn(),
  markFalsePositive: vi.fn(),
  removeRuleSource: vi.fn(),
  restoreRuleDefaults: vi.fn(),
  runScheduledRuleUpdates: vi.fn(),
  saveRulePreferences: vi.fn(),
  saveRuleProfile: vi.fn(),
  setRuleSourceEnabled: vi.fn(),
  updateRuleSource: vi.fn(),
}));

vi.mock("../api", () => api);
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn().mockResolvedValue(() => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

import { DetectionRulesView } from "../rules";

const rule: YaraRuleEntry = {
  id: "yara:bundled:binscope_dotnet_metadata",
  name: "binscope_dotnet_metadata",
  description: "Detects .NET metadata",
  categories: ["dotnet"],
  tags: ["dotnet", "managed"],
  sourceId: "bundled",
  source: "Bundled rules",
  path: "C:\\rules\\yara\\dotnet.yar",
  author: "BinScope",
  license: "MIT",
  hash: "ab".repeat(32),
  added: "2026-01-01T00:00:00Z",
  modified: "2026-01-01T00:00:00Z",
  status: "compatible",
  enabled: true,
  namespace: "default",
  revision: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  version: null,
  severity: null,
  confidence: 80,
  dependencies: [],
  errors: [],
};

const inventory: RuleInventory = {
  generatedAt: "2026-10-31T12:00:00Z",
  revision: rule.revision,
  yaraRules: [rule],
  signatures: [],
  yaraCategories: [
    { id: "dotnet", label: ".NET", description: ".NET rules", total: 1, enabled: 1, invalid: 0 },
  ],
  signatureCategories: [],
  sources: [],
  signatureSources: [],
  sourceErrors: [],
  stats: {
    yaraInstalled: 1,
    yaraEnabled: 1,
    yaraDisabled: 0,
    yaraInvalid: 0,
    signaturesInstalled: 0,
    signaturesEnabled: 0,
    signaturesDisabled: 0,
    signaturesInvalid: 0,
    sourcesEnabled: 0,
    sourcesTotal: 0,
    pendingUpdates: 0,
  },
};

const prefs: RulePreferences = {
  schema: 1,
  yaraEnabled: true,
  signaturesEnabled: true,
  disabledYaraCategories: [],
  disabledYaraRules: [],
  disabledSignatureCategories: [],
  disabledSignatures: [],
  enabledSources: [],
  update: { autoCheck: false, intervalHours: 24, lastCheck: null, lastUpdate: null },
  profile: "balanced",
  customProfiles: [],
  falsePositives: [],
};

describe("Detection rule inspector", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getDetectionInventory.mockResolvedValue(inventory);
    api.getRulePreferences.mockResolvedValue(prefs);
    api.getRuleSources.mockResolvedValue([]);
    api.getRuleChangelog.mockResolvedValue([]);
    api.getRuleLogs.mockResolvedValue([]);
    api.getYaraRuleSource.mockResolvedValue(
      'rule binscope_dotnet_metadata {\n  condition:\n    true\n}\n',
    );
  });

  it("opens the exact source and revision for the selected rule", async () => {
    render(<DetectionRulesView section="yara" onNotify={vi.fn()} />);

    expect(await screen.findByText("binscope_dotnet_metadata")).toBeTruthy();
    expect(screen.getByText(/Rule-set revision/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Inspect" }));

    expect(await screen.findByText(/Original source/)).toBeTruthy();
    expect(screen.getByText(/rule binscope_dotnet_metadata/)).toBeTruthy();
    expect(api.getYaraRuleSource).toHaveBeenCalledWith(rule.path, rule.hash);
    expect(screen.getByText(/YARA-X compatible/)).toBeTruthy();
  });

  it("shows a clear message when the source cannot be read", async () => {
    api.getYaraRuleSource.mockRejectedValue("the rule file changed since the inventory was built");
    render(<DetectionRulesView section="yara" onNotify={vi.fn()} />);
    await screen.findByText("binscope_dotnet_metadata");
    fireEvent.click(screen.getByRole("button", { name: "Inspect" }));
    expect(
      await screen.findByText(/the rule file changed since the inventory was built/),
    ).toBeTruthy();
  });
});
