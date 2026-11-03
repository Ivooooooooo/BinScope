import { useCallback, useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  addRuleSource,
  applyRuleProfile,
  getDetectionInventory,
  getRuleChangelog,
  getRuleLogs,
  getRulePreferences,
  getRuleSources,
  getYaraRuleSource,
  importCustomYaraRules,
  importRulePreferencesFile,
  exportRulePreferencesFile,
  markFalsePositive,
  removeRuleSource,
  restoreRuleDefaults,
  runScheduledRuleUpdates,
  saveRulePreferences,
  saveRuleProfile,
  setRuleSourceEnabled,
  updateRuleSource,
} from "./api";
import type {
  ChangelogEntry,
  RuleInventory,
  RulePreferences,
  RuleStatus,
  SignatureEntry,
  SignatureSourceInfo,
  SourceStatus,
  UpdateLogEntry,
  YaraRuleEntry,
} from "./types";
import { fmtNum } from "./format";

type MainTab = "yara" | "signatures" | "sources";
type ActivityTab = "sources" | "changelog" | "logs";

type RulesProgress = {
  sourceId: string;
  percent: number;
  message: string;
};

const STATUS_TONE: Record<RuleStatus, "ok" | "warn" | "danger" | "info" | "neutral"> = {
  compatible: "ok",
  invalid: "danger",
  incompatible: "danger",
  pending: "warn",
  quarantined: "warn",
  duplicate: "warn",
  license_blocked: "warn",
  obsolete: "neutral",
};

function includesText(values: Array<string | null | undefined>, query: string): boolean {
  if (!query) return true;
  const haystack = values.filter(Boolean).join(" ").toLowerCase();
  return haystack.includes(query);
}

export function DetectionRulesView({
  section,
  onNotify,
}: {
  section: MainTab;
  onNotify: (message: string) => void;
}) {
  const [inventory, setInventory] = useState<RuleInventory | null>(null);
  const [prefs, setPrefs] = useState<RulePreferences | null>(null);
  const [sources, setSources] = useState<SourceStatus[]>([]);
  const [changelog, setChangelog] = useState<ChangelogEntry[]>([]);
  const [logs, setLogs] = useState<UpdateLogEntry[]>([]);
  const [tab, setTab] = useState<MainTab>(section);
  const [activityTab, setActivityTab] = useState<ActivityTab>("sources");
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState("all");
  const [formatFilter, setFormatFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [profile, setProfile] = useState("balanced");
  const [profileName, setProfileName] = useState("");
  const [limit, setLimit] = useState(150);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<YaraRuleEntry | null>(null);
  const [ruleSource, setRuleSource] = useState<string | null>(null);
  const [ruleSourceError, setRuleSourceError] = useState<string | null>(null);
  const [ruleSourceLoading, setRuleSourceLoading] = useState(false);
  const [progress, setProgress] = useState<RulesProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [newSource, setNewSource] = useState({
    name: "",
    repoUrl: "",
    branch: "main",
    license: "",
    prefixes: "",
  });

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextInventory, nextPrefs, nextSources, nextChangelog, nextLogs] =
        await Promise.all([
          getDetectionInventory(),
          getRulePreferences(),
          getRuleSources(),
          getRuleChangelog(),
          getRuleLogs(),
        ]);
      if (nextInventory) setInventory(nextInventory);
      if (nextPrefs) {
        setPrefs(nextPrefs);
        setProfile(nextPrefs.profile);
      }
      setSources(nextSources);
      setChangelog(nextChangelog);
      setLogs(nextLogs);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let disposed = false;
    try {
      listen<RulesProgress>("rules://progress", (event) => setProgress(event.payload))
        .then((fn) => {
          if (disposed) fn();
          else unlisten = fn;
        })
        .catch(() => {});
    } catch {
      

    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    setTab(section);
  }, [section]);

  const persist = useCallback(
    async (next: RulePreferences, message = "Detection preferences saved") => {
      setPrefs(next);
      try {
        const saved = await saveRulePreferences(next);
        setPrefs(saved);
        setNotice(message);
        onNotify(message);
      } catch (err) {
        setError(String(err));
      }
    },
    [onNotify],
  );

  const refreshSources = useCallback(async () => {
    const [nextSources, nextChangelog, nextLogs] = await Promise.all([
      getRuleSources(),
      getRuleChangelog(),
      getRuleLogs(),
    ]);
    setSources(nextSources);
    setChangelog(nextChangelog);
    setLogs(nextLogs);
  }, []);

  const yaraRuleEnabled = (rule: YaraRuleEntry): boolean => {
    if (!prefs?.yaraEnabled || rule.status !== "compatible") return false;
    if (prefs.disabledYaraRules.includes(rule.name)) return false;
    if (prefs.falsePositives.some((fp) => fp.ruleId === rule.name)) return false;
    return !rule.categories.some((value) => prefs.disabledYaraCategories.includes(value));
  };

  const signatureEnabled = (signature: SignatureEntry): boolean => {
    if (!prefs?.signaturesEnabled || signature.status !== "compatible") return false;
    if (prefs.disabledSignatures.includes(signature.id)) return false;
    if (prefs.falsePositives.some((fp) => fp.ruleId === signature.id)) return false;
    return !prefs.disabledSignatureCategories.includes(signature.category);
  };

  const toggleYaraCategory = (id: string) => {
    if (!prefs) return;
    const disabled = new Set(prefs.disabledYaraCategories);
    if (disabled.has(id)) disabled.delete(id);
    else disabled.add(id);
    void persist({ ...prefs, disabledYaraCategories: [...disabled] });
  };

  const toggleSignatureCategory = (id: string) => {
    if (!prefs) return;
    const disabled = new Set(prefs.disabledSignatureCategories);
    if (disabled.has(id)) disabled.delete(id);
    else disabled.add(id);
    void persist({ ...prefs, disabledSignatureCategories: [...disabled] });
  };

  const toggleYaraRule = (rule: YaraRuleEntry) => {
    if (!prefs) return;
    const disabled = new Set(prefs.disabledYaraRules);
    if (disabled.has(rule.name)) disabled.delete(rule.name);
    else disabled.add(rule.name);
    void persist({ ...prefs, disabledYaraRules: [...disabled] });
  };

  const toggleSignature = (signature: SignatureEntry) => {
    if (!prefs) return;
    const disabled = new Set(prefs.disabledSignatures);
    if (disabled.has(signature.id)) disabled.delete(signature.id);
    else disabled.add(signature.id);
    void persist({ ...prefs, disabledSignatures: [...disabled] });
  };

  const setSection = (kind: "yara" | "signatures", enabled: boolean) => {
    if (!prefs) return;
    void persist(
      kind === "yara"
        ? { ...prefs, yaraEnabled: enabled }
        : { ...prefs, signaturesEnabled: enabled },
      kind === "yara" ? "YARA-X section updated" : "Signature section updated",
    );
  };

  const setAllCategories = (kind: "yara" | "signatures", enabled: boolean) => {
    if (!prefs || !inventory) return;
    if (kind === "yara") {
      const ids = inventory.yaraCategories.map((item) => item.id);
      void persist({
        ...prefs,
        disabledYaraCategories: enabled ? [] : ids,
      });
    } else {
      const ids = inventory.signatureCategories.map((item) => item.id);
      void persist({
        ...prefs,
        disabledSignatureCategories: enabled ? [] : ids,
      });
    }
  };

  const setAllRules = (kind: "yara" | "signatures", enabled: boolean) => {
    if (!prefs || !inventory) return;
    if (kind === "yara") {
      const currentIds = filteredYara.map((rule) => rule.name);
      const disabled = new Set(prefs.disabledYaraRules);
      for (const id of currentIds) {
        if (enabled) disabled.delete(id);
        else disabled.add(id);
      }
      void persist({ ...prefs, disabledYaraRules: [...disabled] });
    } else {
      const currentIds = filteredSignatures.map((signature) => signature.id);
      const disabled = new Set(prefs.disabledSignatures);
      for (const id of currentIds) {
        if (enabled) disabled.delete(id);
        else disabled.add(id);
      }
      void persist({ ...prefs, disabledSignatures: [...disabled] });
    }
  };

  const applyProfile = async (id: string) => {
    setProfile(id);
    try {
      const next = await applyRuleProfile(id);
      setPrefs(next);
      setNotice(`Profile "${id}" applied`);
    } catch (err) {
      setError(String(err));
    }
  };

  const saveProfile = async () => {
    if (!prefs || !profileName.trim()) return;
    try {
      const next = await saveRuleProfile(
        profileName.trim(),
        "Custom profile saved from Detection Rules.",
        prefs,
      );
      setPrefs(next);
      setProfile(next.profile);
      setProfileName("");
      setNotice("Custom profile saved");
    } catch (err) {
      setError(String(err));
    }
  };

  const markRuleFalsePositive = async (ruleId: string, name: string) => {
    if (
      !window.confirm(
        `Mark ${name} as a false positive and disable it locally? You can re-enable it from the rule list.`,
      )
    ) {
      return;
    }
    try {
      const next = await markFalsePositive(ruleId, name, null);
      setPrefs(next);
      setNotice(`Marked ${name} as a false positive`);
    } catch (err) {
      setError(String(err));
    }
  };

  const runUpdate = async (source?: string) => {
    setBusy(source ?? "all");
    setError(null);
    setProgress(null);
    try {
      if (source) {
        const result = await updateRuleSource(source, true);
        setNotice(`${result.sourceId}: ${result.message}`);
      } else {
        const result = await runScheduledRuleUpdates(true);
        setNotice(
          `Checked ${result.checked}; updated ${result.updated}; unchanged ${result.unchanged}; errors ${result.errors}`,
        );
      }
      await loadAll();
      await refreshSources();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
      setProgress(null);
    }
  };

  const toggleSource = async (source: SourceStatus) => {
    setBusy(source.id);
    try {
      const next = await setRuleSourceEnabled(source.id, !source.enabled);
      setSources(next);
      const nextPrefs = await getRulePreferences();
      setPrefs(nextPrefs);
      const inv = await getDetectionInventory();
      setInventory(inv);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const addRepository = async () => {
    if (!newSource.repoUrl.trim()) {
      setError("Enter a GitHub repository URL");
      return;
    }
    setBusy("add-source");
    try {
      const next = await addRuleSource({
        name: newSource.name.trim(),
        repoUrl: newSource.repoUrl.trim(),
        branch: newSource.branch.trim() || "main",
        license: newSource.license.trim() || null,
        includePrefixes: newSource.prefixes
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
      });
      setSources(next);
      setNewSource({ name: "", repoUrl: "", branch: "main", license: "", prefixes: "" });
      setNotice("Repository added disabled; review its licence, then enable and update it");
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const removeRepository = async (source: SourceStatus) => {
    if (!window.confirm(`Remove source "${source.name}" and its downloaded rules?`)) return;
    setBusy(source.id);
    try {
      const next = await removeRuleSource(source.id);
      setSources(next);
      await loadAll();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const importRules = async () => {
    try {
      const paths = await open({
        multiple: true,
        filters: [{ name: "YARA rules", extensions: ["yar", "yara"] }],
      });
      if (!paths) return;
      setBusy("import");
      const selected = Array.isArray(paths) ? paths : [paths];
      const result = await importCustomYaraRules(selected);
      setNotice(`Imported ${result.accepted}; rejected ${result.rejected}`);
      if (result.errors.length) setError(result.errors.join("\n"));
      await loadAll();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const exportPrefs = async () => {
    try {
      const path = await save({
        defaultPath: "binscope-detection-preferences.json",
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!path) return;
      await exportRulePreferencesFile(path);
      setNotice("Preferences exported");
    } catch (err) {
      setError(String(err));
    }
  };

  const importPrefs = async () => {
    try {
      const path = await open({
        multiple: false,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!path || Array.isArray(path)) return;
      const next = await importRulePreferencesFile(path);
      setPrefs(next);
      setProfile(next.profile);
      await loadAll();
      setNotice("Preferences imported");
    } catch (err) {
      setError(String(err));
    }
  };

  const restoreDefaults = async () => {
    if (!window.confirm("Restore all detection category and rule preferences to their defaults?")) return;
    try {
      const next = await restoreRuleDefaults();
      setPrefs(next);
      setProfile(next.profile);
      await loadAll();
      setNotice("Default preferences restored");
    } catch (err) {
      setError(String(err));
    }
  };

  const inspectRule = async (rule: YaraRuleEntry) => {
    setSelectedRule(rule);
    setRuleSource(null);
    setRuleSourceError(null);
    setRuleSourceLoading(true);
    try {
      setRuleSource(await getYaraRuleSource(rule.path, rule.hash));
    } catch (err) {
      setRuleSourceError(String(err));
    } finally {
      setRuleSourceLoading(false);
    }
  };

  const visibleYara = useMemo(() => {
    if (!inventory) return [];
    const query = search.trim().toLowerCase();
    return inventory.yaraRules
      .filter((rule) => category === "all" || rule.categories.includes(category))
      .filter((rule) => statusFilter === "all" || rule.status === statusFilter)
      .filter((rule) => sourceFilter === "all" || rule.sourceId === sourceFilter)
      .filter((rule) => severityFilter === "all" || rule.severity === severityFilter)
      .filter((rule) =>
        includesText(
          [
            rule.name,
            rule.description,
            rule.author,
            rule.source,
            rule.tags.join(" "),
            rule.categories.join(" "),
          ],
          query,
        ),
      )
      .sort(
        (a, b) =>
          Number(a.status === "compatible") - Number(b.status === "compatible") ||
          a.name.localeCompare(b.name),
      );
  }, [inventory, category, statusFilter, sourceFilter, severityFilter, search]);

  const visibleSignatures = useMemo(() => {
    if (!inventory) return [];
    const query = search.trim().toLowerCase();
    return inventory.signatures
      .filter((signature) => category === "all" || signature.category === category)
      .filter((signature) => statusFilter === "all" || signature.status === statusFilter)
      .filter((signature) => sourceFilter === "all" || signature.sourceId === sourceFilter)
      .filter((signature) => formatFilter === "all" || signature.format === formatFilter)
      .filter((signature) => confidenceFilter === "all" || signature.confidence >= Number(confidenceFilter))
      .filter((signature) =>
        includesText(
          [
            signature.name,
            signature.description,
            signature.product,
            signature.source,
            signature.version,
            signature.category,
          ],
          query,
        ),
      )
      .sort(
        (a, b) =>
          Number(a.status === "compatible") - Number(b.status === "compatible") ||
          a.name.localeCompare(b.name),
      );
  }, [inventory, category, statusFilter, sourceFilter, formatFilter, confidenceFilter, search]);

  const filteredYara = visibleYara;
  const filteredSignatures = visibleSignatures;

  const yaraCounts = useMemo(() => {
    if (!inventory) return { installed: 0, enabled: 0, invalid: 0 };
    const invalid = inventory.yaraRules.filter((rule) => rule.status !== "compatible").length;
    const enabled = inventory.yaraRules.filter((rule) => yaraRuleEnabled(rule)).length;
    return { installed: inventory.yaraRules.length, enabled, invalid };
  }, [inventory, prefs]);

  const signatureCounts = useMemo(() => {
    if (!inventory) return { installed: 0, enabled: 0, invalid: 0 };
    const invalid = inventory.signatures.filter(
      (signature) => signature.status !== "compatible",
    ).length;
    const enabled = inventory.signatures.filter((signature) => signatureEnabled(signature)).length;
    return { installed: inventory.signatures.length, enabled, invalid };
  }, [inventory, prefs]);

  const categories = tab === "yara" ? inventory?.yaraCategories ?? [] : inventory?.signatureCategories ?? [];
  const selectedSource = sourceFilter;

  const sourceOptions = useMemo(
    () =>
      tab === "yara"
        ? [...new Map((inventory?.yaraRules ?? []).map((rule) => [rule.sourceId, rule.source])).entries()]
        : [...new Map((inventory?.signatures ?? []).map((sig) => [sig.sourceId, sig.source])).entries()],
    [inventory, tab],
  );

  const formatOptions = useMemo(
    () =>
      [...new Set((inventory?.signatures ?? []).map((signature) => signature.format).filter(Boolean))] as string[],
    [inventory],
  );

  const setTabAndReset = (next: MainTab) => {
    setTab(next);
    setCategory("all");
    setStatusFilter("all");
    setSourceFilter("all");
    setConfidenceFilter("all");
    setFormatFilter("all");
    setSeverityFilter("all");
    setSearch("");
    setLimit(150);
  };

  if (loading) {
    return (
      <div className="rules-view">
        <div className="rules-loading">
          <span className="rules-spinner" />
          <div>
            <strong>Building the rule inventory</strong>
            <span className="mono">Discover · validate · compile with YARA-X</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="rules-view">
      <div className="rules-head">
        <div>
          <h2>Detection Rules</h2>
          <p className="muted small">
            Independent control of YARA-X matches and binary signatures. Preferences are stored locally.
          </p>
        </div>
        <div className="rules-actions">
          <button type="button" className="ghost" onClick={restoreDefaults}>
            Restore defaults
          </button>
          <button type="button" className="ghost" onClick={() => void exportPrefs()}>
            Export prefs
          </button>
          <button type="button" className="ghost" onClick={() => void importPrefs()}>
            Import prefs
          </button>
          <button type="button" className="ghost" onClick={() => void importRules()}>
            Import rules
          </button>
          <button type="button" className="ghost" onClick={() => void loadAll()}>
            Refresh
          </button>
        </div>
      </div>

      <div className="rules-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "yara"}
          className={`rules-tab ${tab === "yara" ? "active" : ""}`}
          onClick={() => setTabAndReset("yara")}
        >
          YARA-X Rules
          <span className="rules-tab-count">{fmtNum(yaraCounts.enabled)}/{fmtNum(yaraCounts.installed)}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "signatures"}
          className={`rules-tab ${tab === "signatures" ? "active" : ""}`}
          onClick={() => setTabAndReset("signatures")}
        >
          Binary Signatures
          <span className="rules-tab-count">{fmtNum(signatureCounts.enabled)}/{fmtNum(signatureCounts.installed)}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "sources"}
          className={`rules-tab ${tab === "sources" ? "active" : ""}`}
          onClick={() => setTab("sources")}
        >
          Sources & Updates
          {sources.some((source) => source.pending) && <span className="rules-dot" />}
        </button>
      </div>

      {tab !== "sources" && inventory?.revision && (
        <p className="muted small rules-revision" title={inventory.revision}>
          Rule-set revision <span className="mono">{inventory.revision.slice(0, 16)}</span> · derived
          from normalized source paths and file SHA-256 values
        </p>
      )}

      {progress && (
        <div className="rules-progress">
          <div className="rules-progress-label">
            <span>{progress.message}</span>
            <span>{progress.percent}%</span>
          </div>
          <div className="rules-progress-track">
            <div style={{ width: "100%", transform: `scaleX(${Math.min(progress.percent, 100) / 100})` }} />
          </div>
        </div>
      )}
      {error && (
        <div className="rules-message error-box">
          <span>{error}</span>
          <button type="button" className="ghost small-button" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}
      {notice && !error && (
        <div className="rules-message notice-box">
          <span>{notice}</span>
          <button type="button" className="ghost small-button" onClick={() => setNotice(null)}>
            Dismiss
          </button>
        </div>
      )}

      {tab === "sources" ? (
        <SourcesPanel
          sources={sources}
          changelog={changelog}
          logs={logs}
          activityTab={activityTab}
          setActivityTab={setActivityTab}
          busy={busy}
          onUpdate={(id) => void runUpdate(id)}
          onUpdateAll={() => void runUpdate()}
          onToggle={(source) => void toggleSource(source)}
          onRemove={(source) => void removeRepository(source)}
          newSource={newSource}
          setNewSource={setNewSource}
          onAdd={() => void addRepository()}
          prefs={prefs}
          signatureSources={inventory?.signatureSources ?? []}
          onPrefs={(next) => void persist(next, "Update policy saved")}
        />
      ) : (
        <div className="rules-layout">
          <aside className="rules-sidebar">
            <div className="rules-section-toggle">
              <label className="rules-check">
                <input
                  type="checkbox"
                  checked={tab === "yara" ? prefs?.yaraEnabled ?? false : prefs?.signaturesEnabled ?? false}
                  onChange={(event) => setSection(tab, event.target.checked)}
                />
                <span>{tab === "yara" ? "YARA-X scanning" : "Binary signatures"}</span>
              </label>
              <button
                type="button"
                className="ghost rules-mini"
                onClick={() => setAllCategories(tab, true)}
              >
                All on
              </button>
              <button
                type="button"
                className="ghost rules-mini"
                onClick={() => setAllCategories(tab, false)}
              >
                All off
              </button>
            </div>
            <button
              type="button"
              className={`rules-category ${category === "all" ? "active" : ""}`}
              onClick={() => setCategory("all")}
            >
              <span className="rules-check-spacer" />
              <span>All rules</span>
              <span className="rules-count">
                {fmtNum(tab === "yara" ? yaraCounts.enabled : signatureCounts.enabled)}/
                {fmtNum(tab === "yara" ? yaraCounts.installed : signatureCounts.installed)}
              </span>
            </button>
            {categories.map((item) => {
              const enabledCount =
                tab === "yara"
                  ? inventory?.yaraRules.filter(
                      (rule) => rule.categories.includes(item.id) && yaraRuleEnabled(rule),
                    ).length ?? 0
                  : inventory?.signatures.filter(
                      (signature) =>
                        signature.category === item.id && signatureEnabled(signature),
                    ).length ?? 0;
              const total =
                tab === "yara"
                  ? inventory?.yaraRules.filter((rule) => rule.categories.includes(item.id)).length ?? 0
                  : inventory?.signatures.filter((signature) => signature.category === item.id).length ?? 0;
              const disabled =
                tab === "yara"
                  ? prefs?.disabledYaraCategories.includes(item.id) ?? false
                  : prefs?.disabledSignatureCategories.includes(item.id) ?? false;
              return (
                <button
                  type="button"
                  key={item.id}
                  className={`rules-category ${category === item.id ? "active" : ""} ${
                    disabled ? "is-off" : ""
                  }`}
                  onClick={() => setCategory(item.id)}
                  title={item.description}
                >
                  <input
                    type="checkbox"
                    checked={!disabled}
                    onClick={(event) => event.stopPropagation()}
                    onChange={() =>
                      tab === "yara" ? toggleYaraCategory(item.id) : toggleSignatureCategory(item.id)
                    }
                  />
                  <span>{item.label}</span>
                  <span className="rules-count">
                    {fmtNum(enabledCount)}/{fmtNum(total)}
                  </span>
                </button>
              );
            })}
            <div className="rules-profile">
              <label className="rules-label">
                Profile
                <select value={profile} onChange={(event) => void applyProfile(event.target.value)}>
                  {[
                    ["balanced", "Balanced"],
                    ["deep", "Deep Scan"],
                    ["malware-research", "Malware Research"],
                    ["networking", "Networking"],
                    ["custom", "Custom"],
                  ].map(([id, label]) => (
                    <option key={id} value={id}>
                      {label}
                    </option>
                  ))}
                  {prefs?.customProfiles.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
              <div className="rules-save-profile">
                <input
                  type="text"
                  value={profileName}
                  placeholder="New profile name"
                  onChange={(event) => setProfileName(event.target.value)}
                />
                <button type="button" className="ghost rules-mini" onClick={() => void saveProfile()}>
                  Save
                </button>
              </div>
            </div>
          </aside>

          <section className="rules-main">
            <div className="rules-stats">
              <div>
                <span>Installed</span>
                <strong>{fmtNum(tab === "yara" ? yaraCounts.installed : signatureCounts.installed)}</strong>
              </div>
              <div>
                <span>Enabled</span>
                <strong>{fmtNum(tab === "yara" ? yaraCounts.enabled : signatureCounts.enabled)}</strong>
              </div>
              <div>
                <span>Invalid</span>
                <strong>{fmtNum(tab === "yara" ? yaraCounts.invalid : signatureCounts.invalid)}</strong>
              </div>
              <div>
                <span>Disabled</span>
                <strong>
                  {fmtNum(
                    tab === "yara"
                      ? yaraCounts.installed - yaraCounts.enabled
                      : signatureCounts.installed - signatureCounts.enabled,
                  )}
                </strong>
              </div>
              <div>
                <span>Pending updates</span>
                <strong>{fmtNum(sources.filter((source) => source.enabled && source.pending).length)}</strong>
              </div>
            </div>
            <div className="rules-toolbar">
              <input
                type="search"
                className="rules-search"
                value={search}
                placeholder="Search name, family, tag, description, author or source"
                onChange={(event) => {
                  setSearch(event.target.value);
                  setLimit(150);
                }}
              />
              <select
                value={statusFilter}
                onChange={(event) => {
                  setStatusFilter(event.target.value);
                  setLimit(150);
                }}
              >
                <option value="all">All states</option>
                <option value="compatible">Compatible</option>
                <option value="invalid">Invalid</option>
                <option value="incompatible">Incompatible</option>
                <option value="pending">Pending</option>
                <option value="quarantined">Quarantined</option>
                <option value="duplicate">Duplicate</option>
                <option value="license_blocked">License blocked</option>
              </select>
              <select
                value={selectedSource}
                onChange={(event) => {
                  setSourceFilter(event.target.value);
                  setLimit(150);
                }}
              >
                <option value="all">All sources</option>
                {sourceOptions.map(([id, name]) => (
                  <option key={id} value={id}>
                    {name}
                  </option>
                ))}
              </select>
              {tab === "signatures" ? (
                <>
                  <select
                    value={formatFilter}
                    onChange={(event) => {
                      setFormatFilter(event.target.value);
                      setLimit(150);
                    }}
                  >
                    <option value="all">All formats</option>
                    {formatOptions.map((format) => (
                      <option key={format} value={format}>
                        {format}
                      </option>
                    ))}
                  </select>
                  <select
                    value={confidenceFilter}
                    onChange={(event) => {
                      setConfidenceFilter(event.target.value);
                      setLimit(150);
                    }}
                  >
                    <option value="all">Any confidence</option>
                    <option value="50">50% and above</option>
                    <option value="70">70% and above</option>
                    <option value="90">90% and above</option>
                  </select>
                </>
              ) : (
                <select
                  value={severityFilter}
                  onChange={(event) => {
                    setSeverityFilter(event.target.value);
                    setLimit(150);
                  }}
                >
                  <option value="all">Any severity</option>
                  <option value="info">info</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                </select>
              )}
              <button type="button" className="ghost rules-mini" onClick={() => setAllRules(tab, true)}>
                Enable visible
              </button>
              <button type="button" className="ghost rules-mini" onClick={() => setAllRules(tab, false)}>
                Disable visible
              </button>
            </div>

            {inventory?.sourceErrors.length ? (
              <details className="rules-errors">
                <summary>{inventory.sourceErrors.length} load/validation messages</summary>
                <ul>
                  {inventory.sourceErrors.slice(0, 50).map((item, index) => (
                    <li key={`${item}-${index}`}>{item}</li>
                  ))}
                </ul>
              </details>
            ) : null}

            {tab === "yara" ? (
              <div className="rules-table" role="table">
                <div className="rules-row rules-row-head" role="row">
                  <span role="columnheader" />
                  <span role="columnheader">Rule</span>
                  <span role="columnheader">Category</span>
                  <span role="columnheader">Source</span>
                  <span role="columnheader" title="Compiled rules are unmarked; only exceptions show a state">
                    Exceptions
                  </span>
                  <span role="columnheader" />
                </div>
                {visibleYara.slice(0, limit).map((rule, index) => (
                  <div
                    className={`rules-row ${yaraRuleEnabled(rule) ? "" : "is-off"}`}
                    key={`${rule.id}-${index}`}
                    role="row"
                  >
                    <div role="cell" className="rules-check-cell">
                      <input
                        type="checkbox"
                        checked={yaraRuleEnabled(rule)}
                        disabled={rule.status !== "compatible"}
                        onChange={() => toggleYaraRule(rule)}
                        aria-label={`Toggle ${rule.name}`}
                      />
                    </div>
                    <div className="rules-name" role="cell">
                      <strong>{rule.name}</strong>
                      <span>{rule.description || "No description in metadata"}</span>
                      <small className="mono">
                        {rule.id}
                        {rule.version ? ` · ${rule.version}` : ""}
                      </small>
                    </div>
                    <div className="rules-tags" role="cell">
                      {rule.categories.map((item) => (
                        <span key={item} className="rules-tag">
                          {item}
                        </span>
                      ))}
                      {rule.tags.slice(0, 3).map((item) => (
                        <span key={item} className="rules-tag muted">
                          {item}
                        </span>
                      ))}
                    </div>
                    <div className="rules-source" role="cell">
                      <span>{rule.source}</span>
                      <small>{rule.author ? `by ${rule.author}` : rule.license ?? "unknown author"}</small>
                    </div>
                    <div role="cell" className="rules-state">
                      {rule.status !== "compatible" && <StatusBadge status={rule.status} />}
                      {rule.errors.length > 0 && (
                        <small className="warn-text" title={rule.errors.join("\n")}>
                          {rule.errors[0]}
                        </small>
                      )}
                    </div>
                    <div className="rules-row-actions" role="cell">
                      <button
                        type="button"
                        className="ghost rules-mini"
                        onClick={() => void inspectRule(rule)}
                        title="Show source, revision, metadata and compatibility"
                      >
                        Inspect
                      </button>
                      <button
                        type="button"
                        className="ghost rules-mini"
                        onClick={() => void markRuleFalsePositive(rule.id, rule.name)}
                        title="Disable this rule locally and record a false positive"
                        aria-label={`Mark ${rule.name} as a false positive`}
                      >
                        FP
                      </button>
                    </div>
                  </div>
                ))}
                {visibleYara.length === 0 && <div className="rules-empty">No YARA rules match these filters.</div>}
              </div>
            ) : (
              <div className="rules-table" role="table">
                <div className="rules-row rules-row-head" role="row">
                  <span role="columnheader" />
                  <span role="columnheader">Signature</span>
                  <span role="columnheader">Category</span>
                  <span role="columnheader">Source</span>
                  <span role="columnheader" title="Compiled rules are unmarked; only exceptions show a state">
                    Exceptions
                  </span>
                  <span role="columnheader" />
                </div>
                {visibleSignatures.slice(0, limit).map((signature, index) => (
                  <div
                    className={`rules-row ${signatureEnabled(signature) ? "" : "is-off"}`}
                    key={`${signature.id}-${index}`}
                    role="row"
                  >
                    <div role="cell" className="rules-check-cell">
                      <input
                        type="checkbox"
                        checked={signatureEnabled(signature)}
                        disabled={signature.status !== "compatible"}
                        onChange={() => toggleSignature(signature)}
                        aria-label={`Toggle ${signature.name}`}
                      />
                    </div>
                    <div className="rules-name" role="cell">
                      <strong>{signature.name}</strong>
                      <span>{signature.description || "No description"}</span>
                      <small className="mono">
                        {signature.id}
                        {signature.version ? ` · ${signature.version}` : ""}
                        {` · ${signature.kind} · ${signature.confidence}%`}
                      </small>
                    </div>
                    <div className="rules-tags" role="cell">
                      <span className="rules-tag">{signature.category}</span>
                      {signature.format && <span className="rules-tag muted">{signature.format}</span>}
                    </div>
                    <div className="rules-source" role="cell">
                      <span>{signature.source}</span>
                      <small>{signature.license ?? "unknown licence"}</small>
                    </div>
                    <div role="cell" className="rules-state">
                      {signature.status !== "compatible" && <StatusBadge status={signature.status} />}
                      {signature.compatibility && (
                        <small className="muted" title={signature.compatibility}>
                          {signature.compatibility}
                        </small>
                      )}
                    </div>
                    <div className="rules-row-actions" role="cell">
                      <button
                        type="button"
                        className="ghost rules-mini"
                        onClick={() => void markRuleFalsePositive(signature.id, signature.name)}
                        title="Disable this signature locally and record a false positive"
                        aria-label={`Mark ${signature.name} as a false positive`}
                      >
                        FP
                      </button>
                    </div>
                  </div>
                ))}
                {visibleSignatures.length === 0 && (
                  <div className="rules-empty">No signatures match these filters.</div>
                )}
              </div>
            )}
            {tab === "yara" && selectedRule && (
              <div className="rule-detail">
                <div className="rule-detail-head">
                  <div>
                    <strong className="mono">{selectedRule.name}</strong>
                    <span className="muted small">
                      {" · "}
                      {selectedRule.namespace}
                      {" · "}
                      {selectedRule.revision ? selectedRule.revision.slice(0, 16) : "revision unavailable"}
                    </span>
                  </div>
                  <div className="rule-detail-actions">
                    <StatusBadge status={selectedRule.status} />
                    <button
                      type="button"
                      className="ghost rules-mini"
                      onClick={() => setSelectedRule(null)}
                    >
                      Close
                    </button>
                  </div>
                </div>
                <div className="rule-detail-grid">
                  <div>
                    <span className="meta-label">Source file</span>
                    <code className="mono" title={selectedRule.path}>{selectedRule.path || "unavailable"}</code>
                  </div>
                  <div>
                    <span className="meta-label">Tags</span>
                    <span>{selectedRule.tags.length > 0 ? selectedRule.tags.join(", ") : "none"}</span>
                  </div>
                  <div>
                    <span className="meta-label">Categories</span>
                    <span>{selectedRule.categories.length > 0 ? selectedRule.categories.join(", ") : "none"}</span>
                  </div>
                  <div>
                    <span className="meta-label">Author / licence</span>
                    <span>{selectedRule.author ?? "unknown"} · {selectedRule.license ?? "unknown"}</span>
                  </div>
                  <div>
                    <span className="meta-label">Compatibility</span>
                    <span>
                      {selectedRule.status === "compatible"
                        ? "YARA-X compatible"
                        : selectedRule.errors[0] ?? selectedRule.status}
                    </span>
                  </div>
                  <div>
                    <span className="meta-label">Content SHA-256</span>
                    <span className="mono small"> {selectedRule.hash}</span>
                  </div>
                  <div>
                    <span className="meta-label">Added / modified</span>
                    <span>{selectedRule.added ?? "-"} · {selectedRule.modified ?? "-"}</span>
                  </div>
                </div>
                {selectedRule.dependencies.length > 0 && (
                  <p className="muted small">Requires: {selectedRule.dependencies.join(", ")}</p>
                )}
                <h4>Original source</h4>
                {ruleSourceLoading ? (
                  <p className="muted small">Loading source...</p>
                ) : ruleSource ? (
                  <>
                    <pre className="code-block rule-source">{ruleSource}</pre>
                    <p className="muted small">
                      Read-only source from the exact file and revision compiled for this inventory.
                      Text is rendered as text, never interpreted as HTML.
                    </p>
                  </>
                ) : (
                  <p className="muted small">
                    {ruleSourceError ?? "Source text is unavailable for this rule."}
                  </p>
                )}
              </div>
            )}
            {(tab === "yara" ? visibleYara.length : visibleSignatures.length) > limit && (
              <button type="button" className="ghost rules-load-more" onClick={() => setLimit(limit + 200)}>
                Show more ({fmtNum((tab === "yara" ? visibleYara.length : visibleSignatures.length) - limit)} remaining)
              </button>
            )}
          </section>
        </div>
      )}
    </div>
  );
}



function StatusBadge({ status }: { status: RuleStatus }) {
  return <span className={`badge badge-${STATUS_TONE[status]}`}>{status.replace("_", " ")}</span>;
}

function SourcesPanel({
  sources,
  changelog,
  logs,
  activityTab,
  setActivityTab,
  busy,
  onUpdate,
  onUpdateAll,
  onToggle,
  onRemove,
  newSource,
  setNewSource,
  onAdd,
  prefs,
  signatureSources,
  onPrefs,
}: {
  sources: SourceStatus[];
  changelog: ChangelogEntry[];
  logs: UpdateLogEntry[];
  activityTab: ActivityTab;
  setActivityTab: (tab: ActivityTab) => void;
  busy: string | null;
  onUpdate: (id: string) => void;
  onUpdateAll: () => void;
  onToggle: (source: SourceStatus) => void;
  onRemove: (source: SourceStatus) => void;
  newSource: { name: string; repoUrl: string; branch: string; license: string; prefixes: string };
  setNewSource: (value: { name: string; repoUrl: string; branch: string; license: string; prefixes: string }) => void;
  onAdd: () => void;
  prefs: RulePreferences | null;
  signatureSources: SignatureSourceInfo[];
  onPrefs: (prefs: RulePreferences) => void;
}) {
  return (
    <div className="rules-sources-layout">
      <div className="rules-sources-main">
        <div className="rules-sources-toolbar">
          <div>
            <h3>Rule sources</h3>
            <p className="muted small">
              Downloads are pinned to commits or release tags, size-limited and compiled before activation.
            </p>
          </div>
          <div className="rules-actions">
            <button type="button" onClick={onUpdateAll} disabled={busy !== null}>
              {busy === "all" ? "Checking sources…" : "Check all sources"}
            </button>
          </div>
        </div>
        <div className="rules-update-policy">
          <label className="rules-check">
            <input
              type="checkbox"
              checked={prefs?.update.autoCheck ?? true}
              onChange={(event) =>
                prefs &&
                onPrefs({
                  ...prefs,
                  update: { ...prefs.update, autoCheck: event.target.checked },
                })
              }
            />
            <span>Check for updates automatically</span>
          </label>
          <label className="rules-label">
            Frequency
            <select
              value={prefs?.update.intervalHours ?? 24}
              onChange={(event) =>
                prefs &&
                onPrefs({
                  ...prefs,
                  update: { ...prefs.update, intervalHours: Number(event.target.value) },
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
            Last check: {prefs?.update.lastCheck ?? "never"} · last install:{" "}
            {prefs?.update.lastUpdate ?? "never"}
          </span>
        </div>
        <div className="rules-source-list">
          {sources.map((source) => (
            <article className="rules-source-card" key={source.id}>
              <div className="rules-source-title">
                <label className="rules-check">
                  <input
                    type="checkbox"
                    checked={source.enabled}
                    onChange={() => onToggle(source)}
                    disabled={busy !== null}
                  />
                  <strong>{source.name}</strong>
                </label>
                <div className="rules-tags">
                  {source.license && <span className="rules-tag">{source.license}</span>}
                  {source.compatibility !== "compatible" && (
                    <span className="rules-tag">{source.compatibility}</span>
                  )}
                  {!source.implemented && <span className="rules-tag">manual</span>}
                  {source.pending && <span className="rules-tag warn-text">pending</span>}
                </div>
              </div>
              <p>{source.notes}</p>
              <div className="rules-source-facts">
                <span className="mono">{source.version ?? "not downloaded"}</span>
                <span>checked {source.lastCheck ?? "never"}</span>
                <span>updated {source.lastSuccess ?? "never"}</span>
                <span>
                  {fmtNum(source.accepted)} accepted / {fmtNum(source.rejected)} rejected
                </span>
              </div>
              {source.commit && <small className="mono">commit {source.commit}</small>}
              {source.errors.length > 0 && <div className="error-box">{source.errors.join("\n")}</div>}
              <div className="rules-source-actions">
                <button
                  type="button"
                  className="ghost rules-mini"
                  disabled={busy !== null || !source.implemented}
                  onClick={() => onUpdate(source.id)}
                >
                  {busy === source.id ? "Updating…" : "Update"}
                </button>
                <a href={source.url} target="_blank" rel="noreferrer">
                  Open source
                </a>
                {source.id.startsWith("custom-") && (
                  <button type="button" className="ghost rules-mini danger" onClick={() => onRemove(source)}>
                    Remove
                  </button>
                )}
              </div>
            </article>
          ))}
        </div>
        <section className="rules-add-source">
          <h3>Add GitHub repository</h3>
          <p className="muted small">
            The repository is validated as HTTPS/GitHub, disabled by default, and only .yar/.yara files are fetched.
          </p>
          <div className="rules-source-form">
            <input
              type="text"
              placeholder="Name (optional)"
              value={newSource.name}
              onChange={(event) => setNewSource({ ...newSource, name: event.target.value })}
            />
            <input
              type="text"
              placeholder="https://github.com/owner/repo"
              value={newSource.repoUrl}
              onChange={(event) => setNewSource({ ...newSource, repoUrl: event.target.value })}
            />
            <input
              type="text"
              placeholder="Branch or tag"
              value={newSource.branch}
              onChange={(event) => setNewSource({ ...newSource, branch: event.target.value })}
            />
            <input
              type="text"
              placeholder="Licence (optional)"
              value={newSource.license}
              onChange={(event) => setNewSource({ ...newSource, license: event.target.value })}
            />
            <input
              type="text"
              placeholder="Include prefixes, comma separated"
              value={newSource.prefixes}
              onChange={(event) => setNewSource({ ...newSource, prefixes: event.target.value })}
            />
            <button type="button" onClick={onAdd} disabled={busy !== null}>
              Add source
            </button>
          </div>
        </section>
      </div>
      <aside className="rules-activity">
        <div className="rules-activity-tabs">
          {(["sources", "changelog", "logs"] as ActivityTab[]).map((id) => (
            <button
              type="button"
              key={id}
              className={`rules-tab ${activityTab === id ? "active" : ""}`}
              onClick={() => setActivityTab(id)}
            >
              {id === "sources" ? "Databases" : id === "changelog" ? "Changelog" : "Logs"}
            </button>
          ))}
        </div>
        {activityTab === "sources" && (
          <div className="rules-signature-sources">
            <h4>Signature databases</h4>
            <p className="muted small">
              These are installed with BinScope or downloaded explicitly; they are managed separately from YARA sources.
            </p>
            {signatureSources.length === 0 ? (
              <p className="muted small">No signature database information available.</p>
            ) : (
              signatureSources.map((source) => (
                <article key={source.id}>
                  <strong>{source.name}</strong>
                  <span className="mono">{source.version ?? "unknown version"}</span>
                  <small>
                    {source.license ?? "unknown licence"} · {fmtNum(source.compatible)} compatible
                    {source.incompatible > 0 ? ` · ${fmtNum(source.incompatible)} incompatible` : ""}
                  </small>
                  <p>{source.notes}</p>
                </article>
              ))
            )}
          </div>
        )}
        {activityTab === "changelog" && (
          <div className="rules-log-list">
            {changelog.length === 0 ? (
              <p className="muted small">No source updates recorded yet.</p>
            ) : (
              changelog.map((entry) => (
                <article key={`${entry.at}-${entry.sourceId}`}>
                  <strong>{entry.sourceName}</strong>
                  <span className="mono">{entry.version}</span>
                  <small>
                    {entry.at} · +{entry.added} ~{entry.modified} -{entry.removed} · invalid {entry.invalid}
                  </small>
                  <p>{entry.message}</p>
                </article>
              ))
            )}
          </div>
        )}
        {activityTab === "logs" && (
          <div className="rules-log-list">
            {logs.length === 0 ? (
              <p className="muted small">No technical update logs yet.</p>
            ) : (
              logs.map((entry) => (
                <article key={`${entry.at}-${entry.sourceId}-${entry.message}`}>
                  <span className={`badge badge-${entry.level === "error" ? "danger" : "neutral"}`}>
                    {entry.level}
                  </span>
                  <strong>{entry.sourceId}</strong>
                  <small>{entry.at}</small>
                  <p className="mono">{entry.message}</p>
                </article>
              ))
            )}
          </div>
        )}
      </aside>
    </div>
  );
}
