use crate::classify::{self, SIGNATURE_CATEGORIES, YARA_CATEGORIES};
use crate::manager::{now_utc, RuleManager};
use crate::model::{
    CategoryInfo, InventoryStats, MatchKind, RuleInventory, RulePreferences, RuleStatus,
    SignatureEntry, SignatureSourceInfo, YaraRuleEntry,
};
use binscope_signatures::die::load_die_directory;
use binscope_signatures::pebear::{self, parse_pebear};
use binscope_signatures::{Category as SignatureCategory, Condition, SignatureDatabase};
use binscope_yara::YaraRuleSet;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const MAX_RULE_FILES: usize = 2048;
const MAX_RULE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct YaraRoot {
    pub source_id: String,
    pub source_name: String,
    pub license: Option<String>,
    pub path: PathBuf,
}

pub fn collect_yara_roots(manager: &RuleManager, bundled: &[PathBuf]) -> Vec<YaraRoot> {
    let prefs = manager.load_preferences();
    let sources = manager.load_sources();
    let mut roots = Vec::new();
    let legacy_root = manager.data_dir.join("yara");
    for path in bundled {
        if path.as_path() == legacy_root.as_path() {
            continue;
        }
        roots.push(YaraRoot {
            source_id: "bundled".into(),
            source_name: "BinScope bundled".into(),
            license: Some("MIT".into()),
            path: path.clone(),
        });
    }
    let custom = manager.custom_yara_dir();
    if custom.is_dir() {
        roots.push(YaraRoot {
            source_id: "custom".into(),
            source_name: "Custom imported rules".into(),
            license: None,
            path: custom,
        });
    }
    for source in &sources {
        let id = &source.definition.id;
        let enabled = if prefs.enabled_sources.is_empty() {
            source.enabled
        } else {
            prefs.enabled_sources.iter().any(|item| item == id)
        };
        if !enabled {
            continue;
        }
        let path = manager.source_dir(id);
        if path.is_dir() {
            roots.push(YaraRoot {
                source_id: id.clone(),
                source_name: source.definition.name.clone(),
                license: source.definition.license.clone(),
                path,
            });
        }
    }
    let legacy = manager.legacy_yara_dir();
    if legacy.is_dir() {
        roots.push(YaraRoot {
            source_id: "legacy".into(),
            source_name: "Legacy YARA install".into(),
            license: None,
            path: legacy,
        });
    }
    roots.sort_by(|a, b| a.source_id.cmp(&b.source_id).then(a.path.cmp(&b.path)));
    roots.dedup_by(|a, b| a.path == b.path);
    roots
}

pub fn build_inventory(
    manager: &RuleManager,
    bundled: &[PathBuf],
    die_dir: Option<&Path>,
    pebear_path: Option<&Path>,
    signature_dirs: &[PathBuf],
) -> RuleInventory {
    let prefs = manager.load_preferences();
    let mut inventory = RuleInventory {
        generated_at: now_utc(),
        ..Default::default()
    };
    let mut errors = Vec::new();
    let roots = collect_yara_roots(manager, bundled);
    let root_paths: Vec<PathBuf> = roots.iter().map(|root| root.path.clone()).collect();
    let (compile, revision) = {
        let (map, failed, revision) = compile_errors(&root_paths, &mut errors);
        ((map, failed), revision)
    };
    inventory.revision = revision.clone();
    let mut all_rules = Vec::new();
    for root in &roots {
        all_rules.extend(scan_root(root, &prefs, &compile.0, compile.1, &revision));
    }
    dedupe_rule_names(&mut all_rules, &prefs);
    inventory.yara_rules = all_rules;
    inventory.yara_categories = category_counts_yara(&inventory.yara_rules);
    inventory.source_errors.extend(errors);

    let (signatures, signature_sources, signature_errors) =
        build_signatures(manager, &prefs, die_dir, pebear_path, signature_dirs);
    inventory.signatures = signatures;
    inventory.signature_sources = signature_sources;
    inventory.source_errors.extend(signature_errors);
    inventory.signature_categories = category_counts_signatures(&inventory.signatures);
    inventory.sources = manager.load_sources();
    inventory.stats = inventory_stats(&inventory);
    inventory
}

fn compile_errors(
    roots: &[PathBuf],
    errors: &mut Vec<String>,
) -> (HashMap<String, Vec<String>>, bool, String) {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if roots.is_empty() {
        return (map, false, String::new());
    }
    match YaraRuleSet::compile_dirs(roots) {
        Ok(rules) => {
            for error in &rules.report.errors {
                map.entry(normalize_path(&error.source))
                    .or_default()
                    .push(error.message.clone());
                errors.push(format!("{}: {}", error.source, error.message));
            }
            for warning in &rules.report.warnings {
                errors.push(format!("warning: {}: {}", warning.source, warning.message));
            }
            (map, false, rules.revision.clone())
        }
        Err(error) => {
            errors.push(format!("YARA compilation failed: {error}"));
            (map, true, String::new())
        }
    }
}

fn scan_root(
    root: &YaraRoot,
    prefs: &RulePreferences,
    compile_errors: &HashMap<String, Vec<String>>,
    all_failed: bool,
    revision: &str,
) -> Vec<YaraRuleEntry> {
    let mut files = Vec::new();
    collect_files(&root.path, &mut files);
    files.sort();
    let mut out = Vec::new();
    for file in files {
        if out.len() >= MAX_RULE_FILES {
            break;
        }
        let Ok(metadata) = std::fs::metadata(&file) else {
            continue;
        };
        if metadata.len() > MAX_RULE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let hash = sha256(text.as_bytes());
        let modified = metadata
            .modified()
            .ok()
            .map(DateTime::<Utc>::from)
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        let errors = if all_failed {
            vec![
                "YARA-X rejected every rule in this load; inspect the source and compilation log"
                    .into(),
            ]
        } else {
            compile_errors
                .get(&normalize_path(&file.to_string_lossy()))
                .cloned()
                .unwrap_or_default()
        };
        for parsed in parse_yara_rules(&text) {
            let mut tags = parsed.tags.clone();
            if let Some(family) = parsed.metadata_map.get("family") {
                if !tags.iter().any(|tag| tag == family) {
                    tags.push(family.clone());
                }
            }
            let categories = classify::classify_yara_rule(
                &parsed.name,
                &tags,
                &parsed.metadata,
                &file.to_string_lossy(),
            );
            let status = if errors.is_empty() {
                RuleStatus::Compatible
            } else {
                RuleStatus::Invalid
            };
            let disabled = prefs
                .disabled_yara_rules
                .iter()
                .any(|id| id == &parsed.name)
                || prefs
                    .false_positives
                    .iter()
                    .any(|fp| fp.rule_id == parsed.name)
                || categories.iter().any(|category| {
                    prefs
                        .disabled_yara_categories
                        .iter()
                        .any(|disabled| disabled == category)
                });
            let hash_id = format!("yara:{}:{}", root.source_id, parsed.name);
            out.push(YaraRuleEntry {
                id: hash_id,
                name: parsed.name,
                description: parsed
                    .metadata_map
                    .get("description")
                    .cloned()
                    .unwrap_or_default(),
                categories,
                tags,
                source_id: root.source_id.clone(),
                source: root.source_name.clone(),
                path: file.to_string_lossy().to_string(),
                author: parsed.metadata_map.get("author").cloned(),
                license: parsed
                    .metadata_map
                    .get("license")
                    .cloned()
                    .or_else(|| root.license.clone()),
                hash: hash.clone(),
                added: modified.clone(),
                modified: modified.clone(),
                status,
                enabled: prefs.yara_enabled && status == RuleStatus::Compatible && !disabled,
                namespace: "default".into(),
                revision: revision.to_string(),
                severity: parsed.metadata_map.get("severity").cloned(),
                confidence: parsed
                    .metadata_map
                    .get("confidence")
                    .and_then(|value| value.parse::<u8>().ok()),
                dependencies: parsed
                    .metadata_map
                    .get("requires")
                    .or_else(|| parsed.metadata_map.get("depends_on"))
                    .map(|value| {
                        value
                            .split([',', ';'])
                            .map(|item| item.trim().to_string())
                            .filter(|item| !item.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
                errors: errors.clone(),
            });
        }
    }
    out
}

fn dedupe_rule_names(rules: &mut [YaraRuleEntry], prefs: &RulePreferences) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for rule in rules.iter_mut() {
        let count = seen.entry(rule.name.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            rule.status = RuleStatus::Duplicate;
            rule.enabled = false;
            rule.errors
                .push("duplicate rule name across the active rule set".into());
        } else if rule.status == RuleStatus::Compatible {
            rule.enabled = prefs.yara_enabled
                && !prefs.disabled_yara_rules.iter().any(|id| id == &rule.name)
                && !prefs
                    .false_positives
                    .iter()
                    .any(|fp| fp.rule_id == rule.name);
        }
    }
}

fn category_counts_yara(rules: &[YaraRuleEntry]) -> Vec<CategoryInfo> {
    category_counts(
        YARA_CATEGORIES,
        rules.iter().map(|rule| {
            (
                rule.categories.clone(),
                rule.enabled,
                rule.status != RuleStatus::Compatible,
            )
        }),
    )
}

fn category_counts_signatures(signatures: &[SignatureEntry]) -> Vec<CategoryInfo> {
    category_counts(
        SIGNATURE_CATEGORIES,
        signatures.iter().map(|signature| {
            (
                vec![signature.category.clone()],
                signature.enabled,
                signature.status != RuleStatus::Compatible,
            )
        }),
    )
}

fn category_counts(
    catalog: &[(&str, &str, &str)],
    entries: impl Iterator<Item = (Vec<String>, bool, bool)>,
) -> Vec<CategoryInfo> {
    let mut counts: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for (categories, enabled, invalid) in entries {
        for category in categories {
            let entry = counts.entry(category).or_default();
            entry.0 += 1;
            if enabled {
                entry.1 += 1;
            }
            if invalid {
                entry.2 += 1;
            }
        }
    }
    catalog
        .iter()
        .map(|(id, label, description)| {
            let (total, enabled, invalid) = counts.get(*id).copied().unwrap_or((0, 0, 0));
            CategoryInfo {
                id: (*id).to_string(),
                label: (*label).to_string(),
                description: (*description).to_string(),
                total,
                enabled,
                invalid,
            }
        })
        .collect()
}

fn build_signatures(
    manager: &RuleManager,
    prefs: &RulePreferences,
    die_dir: Option<&Path>,
    pebear_path: Option<&Path>,
    signature_dirs: &[PathBuf],
) -> (Vec<SignatureEntry>, Vec<SignatureSourceInfo>, Vec<String>) {
    let mut entries = Vec::new();
    let mut sources = Vec::new();
    let mut errors = Vec::new();
    let updates = read_update_state(manager);

    if let Ok(db) = SignatureDatabase::builtin() {
        let mut count = 0;
        for signature in &db.signatures {
            let category = classify::signature_category_for(signature.category).to_string();
            entries.push(SignatureEntry {
                id: signature.id.clone(),
                name: signature.name.clone(),
                description: signature.description.clone(),
                category: category.clone(),
                format: None,
                version: signature.version.clone(),
                source_id: "builtin".into(),
                source: "BinScope built-in".into(),
                license: db.license.clone(),
                status: RuleStatus::Compatible,
                enabled: signature_enabled(prefs, &signature.id, &category),
                confidence: signature.confidence,
                kind: MatchKind::Exact,
                pattern: None,
                offsets: None,
                product: None,
                evidence: condition_summary(signature),
                compatibility: None,
            });
            count += 1;
        }
        sources.push(SignatureSourceInfo {
            id: "builtin".into(),
            name: "BinScope built-in signatures".into(),
            license: db.license.clone(),
            version: Some(db.version.clone()),
            installed: count,
            compatible: count,
            incompatible: 0,
            last_update: None,
            notes: "Shipped with BinScope; MIT.".into(),
        });
    } else {
        errors.push("built-in signature database could not be parsed".into());
    }

    if let Some(dir) = die_dir {
        let pe_dir = if dir.join("PE").is_dir() {
            dir.join("PE")
        } else {
            dir.to_path_buf()
        };
        let db = load_die_directory(&pe_dir, &die_version(manager));
        for signature in &db.signatures {
            let category = classify::signature_category_for(signature.category).to_string();
            entries.push(SignatureEntry {
                id: signature.id.clone(),
                name: signature.name.clone(),
                description: format!("Detect It Easy signature {}", signature.file),
                category: category.clone(),
                format: Some("PE".into()),
                version: signature.version.clone(),
                source_id: "die".into(),
                source: "Detect It Easy".into(),
                license: Some("MIT".into()),
                status: RuleStatus::Compatible,
                enabled: signature_enabled(prefs, &signature.id, &category),
                confidence: 70,
                kind: MatchKind::Exact,
                pattern: Some(signature.pattern_text()),
                offsets: Some(format!(
                    "entry point, {} fixed bytes",
                    signature.fixed_bytes
                )),
                product: Some(signature.name.clone()),
                evidence: vec![signature.compatibility.clone()],
                compatibility: Some(signature.compatibility.clone()),
            });
        }
        sources.push(SignatureSourceInfo {
            id: "die".into(),
            name: "Detect It Easy (PE subset)".into(),
            license: Some("MIT".into()),
            version: Some(db.version.clone()),
            installed: db.stats.files,
            compatible: db.stats.compatible,
            incompatible: db.stats.incompatible,
            last_update: updates.get("die").cloned(),
            notes: format!(
                "{} files loaded; {} compatible with the compareEP adapter, {} incompatible.",
                db.stats.files, db.stats.compatible, db.stats.incompatible
            ),
        });
    } else {
        errors.push("DIE database is not configured".into());
    }

    if let Some(path) = pebear_path {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let db = parse_pebear(&text);
                let mut count = 0;
                for signature in &db.signatures {
                    let pebear_category = pebear::category_for(&signature.name);
                    let category = if pebear_category == SignatureCategory::Other {
                        "packers".to_string()
                    } else {
                        classify::signature_category_for(pebear_category).to_string()
                    };
                    entries.push(SignatureEntry {
                        id: format!("pebear:{}", signature.name),
                        name: signature.name.clone(),
                        description: "PE-bear SIG.txt historical signature".into(),
                        category: category.clone(),
                        format: Some("PE".into()),
                        version: None,
                        source_id: "pebear".into(),
                        source: "PE-bear SIG.txt".into(),
                        license: Some("GPLv2".into()),
                        status: RuleStatus::Compatible,
                        enabled: signature_enabled(
                            prefs,
                            &format!("pebear:{}", signature.name),
                            &category,
                        ),
                        confidence: if signature.pattern.iter().flatten().count() >= 24 {
                            60
                        } else {
                            45
                        },
                        kind: MatchKind::Probable,
                        pattern: Some(hex_pattern(&signature.pattern)),
                        offsets: None,
                        product: Some(signature.name.clone()),
                        evidence: vec!["historical PEiD UserDB byte pattern".into()],
                        compatibility: Some(
                            "Historical signature; byte matches are evidence, not definitive attribution."
                                .into(),
                        ),
                    });
                    count += 1;
                }
                sources.push(SignatureSourceInfo {
                    id: "pebear".into(),
                    name: "PE-bear SIG.txt".into(),
                    license: Some("GPLv2".into()),
                    version: Some("PEiD UserDB".into()),
                    installed: db.total_blocks,
                    compatible: count,
                    incompatible: db.skipped,
                    last_update: updates.get("pebear").cloned(),
                    notes: format!(
                        "{} blocks parsed; {} signatures active; {} skipped.",
                        db.total_blocks, count, db.skipped
                    ),
                });
            }
            Err(error) => errors.push(format!("PE-bear SIG.txt: {error}")),
        }
    }

    if !signature_dirs.is_empty() {
        match binscope_signatures::load_databases(signature_dirs) {
            Ok(databases) => {
                let mut count = 0;
                for db in databases {
                    for signature in &db.signatures {
                        let category =
                            classify::signature_category_for(signature.category).to_string();
                        entries.push(SignatureEntry {
                            id: signature.id.clone(),
                            name: signature.name.clone(),
                            description: signature.description.clone(),
                            category: category.clone(),
                            format: None,
                            version: signature.version.clone(),
                            source_id: "custom".into(),
                            source: format!("{} {}", db.name, db.version),
                            license: db.license.clone(),
                            status: RuleStatus::Compatible,
                            enabled: signature_enabled(prefs, &signature.id, &category),
                            confidence: signature.confidence,
                            kind: MatchKind::Exact,
                            pattern: None,
                            offsets: None,
                            product: None,
                            evidence: condition_summary(signature),
                            compatibility: None,
                        });
                        count += 1;
                    }
                }
                sources.push(SignatureSourceInfo {
                    id: "custom".into(),
                    name: "Custom JSON signatures".into(),
                    license: None,
                    version: None,
                    installed: count,
                    compatible: count,
                    incompatible: 0,
                    last_update: None,
                    notes: "User-configured signature directories.".into(),
                });
            }
            Err(error) => errors.push(format!("custom signature database: {error}")),
        }
    }

    (entries, sources, errors)
}

fn signature_enabled(prefs: &RulePreferences, id: &str, category: &str) -> bool {
    prefs.signatures_enabled
        && !prefs
            .disabled_signatures
            .iter()
            .any(|disabled| disabled == id)
        && !prefs
            .false_positives
            .iter()
            .any(|false_positive| false_positive.rule_id == id)
        && !prefs
            .disabled_signature_categories
            .iter()
            .any(|disabled| disabled == category)
}

fn inventory_stats(inventory: &RuleInventory) -> InventoryStats {
    let yara_enabled = inventory
        .yara_rules
        .iter()
        .filter(|rule| rule.enabled)
        .count();
    let yara_invalid = inventory
        .yara_rules
        .iter()
        .filter(|rule| rule.status != RuleStatus::Compatible)
        .count();
    let signatures_enabled = inventory
        .signatures
        .iter()
        .filter(|signature| signature.enabled)
        .count();
    let signatures_invalid = inventory
        .signature_sources
        .iter()
        .map(|source| source.incompatible)
        .sum::<usize>()
        + inventory
            .signatures
            .iter()
            .filter(|signature| signature.status != RuleStatus::Compatible)
            .count();
    InventoryStats {
        yara_installed: inventory.yara_rules.len(),
        yara_enabled,
        yara_disabled: inventory.yara_rules.len().saturating_sub(yara_enabled),
        yara_invalid,
        signatures_installed: inventory.signatures.len(),
        signatures_enabled,
        signatures_disabled: inventory
            .signatures
            .len()
            .saturating_sub(signatures_enabled),
        signatures_invalid,
        sources_enabled: inventory
            .sources
            .iter()
            .filter(|source| source.enabled)
            .count(),
        sources_total: inventory.sources.len(),
        pending_updates: inventory
            .sources
            .iter()
            .filter(|source| source.enabled && source.pending)
            .count(),
    }
}

fn parse_yara_rules(text: &str) -> Vec<ParsedRule> {
    let code = strip_comments(text);
    let lines: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let trimmed = trimmed
            .strip_prefix("private ")
            .or_else(|| trimmed.strip_prefix("global "))
            .unwrap_or(trimmed)
            .trim_start();
        let Some(rest) = trimmed.strip_prefix("rule ") else {
            continue;
        };
        let header = rest.trim();
        let mut name_end = 0;
        for (position, character) in header.char_indices() {
            if character.is_ascii_alphanumeric() || character == '_' {
                name_end = position + character.len_utf8();
            } else {
                break;
            }
        }
        if name_end == 0 {
            continue;
        }
        let name = header[..name_end].to_string();
        let tags = header[name_end..]
            .split_once(':')
            .map(|(_, tags)| {
                tags.split(|c: char| c.is_whitespace() || c == '{')
                    .filter(|tag| !tag.is_empty())
                    .map(|tag| tag.to_string())
                    .collect()
            })
            .unwrap_or_default();
        let mut metadata_map = BTreeMap::new();
        let mut in_meta = false;
        for line in lines.iter().skip(index + 1).take(240) {
            let trimmed = line.trim();
            if trimmed.starts_with("strings:") || trimmed.starts_with("condition:") {
                break;
            }
            if trimmed == "meta:" {
                in_meta = true;
                continue;
            }
            if in_meta {
                if let Some((key, value)) = trimmed.split_once('=') {
                    let key = key.trim().trim_end_matches(':').trim();
                    let value = value.trim().trim_end_matches(',').trim();
                    if !key.is_empty() && !value.is_empty() {
                        metadata_map.insert(key.to_string(), unquote(value));
                    }
                }
            }
        }
        let metadata: Vec<(String, String)> = metadata_map
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        out.push(ParsedRule {
            name,
            tags,
            metadata,
            metadata_map,
        });
    }
    out
}

struct ParsedRule {
    name: String,
    tags: Vec<String>,
    metadata: Vec<(String, String)>,
    metadata_map: BTreeMap<String, String>,
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].replace("\\\"", "\"")
    } else {
        value.to_string()
    }
}

fn strip_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(character) = chars.next() {
        if let Some(active) = quote {
            out.push(character);
            if character == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else if character == active {
                quote = None;
            }
            continue;
        }
        if character == '"' || character == '\'' {
            quote = Some(character);
            out.push(character);
        } else if character == '/' && chars.peek() == Some(&'/') {
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(next) = chars.next() {
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else {
            out.push(character);
        }
    }
    out
}

fn condition_summary(signature: &binscope_signatures::Signature) -> Vec<String> {
    let mut out = Vec::new();
    for condition in signature
        .all
        .iter()
        .chain(&signature.any)
        .chain(&signature.none)
    {
        out.push(condition_text(condition));
        if out.len() >= 6 {
            break;
        }
    }
    out
}

fn condition_text(condition: &Condition) -> String {
    let text = format!("{condition:?}");
    if text.len() > 180 {
        format!("{}…", &text[..179])
    } else {
        text
    }
}

fn read_update_state(manager: &RuleManager) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(manager.data_dir.join("updates.json")) else {
        return out;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return out;
    };
    for key in ["die", "pebear", "yara"] {
        if let Some(date) = value
            .get(key)
            .and_then(|item| item.get("updatedAt"))
            .and_then(|item| item.as_str())
        {
            out.insert(key.to_string(), date.to_string());
        }
    }
    out
}

fn die_version(manager: &RuleManager) -> String {
    let path = manager.data_dir.join("die").join("manifest.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return "installed".into();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return "installed".into();
    };
    let tag = value
        .get("releaseTag")
        .and_then(|item| item.as_str())
        .unwrap_or("db");
    let date = value
        .get("releasedAt")
        .and_then(|item| item.as_str())
        .unwrap_or("unknown");
    format!("{tag} @ {date}")
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) {
    if out.len() >= MAX_RULE_FILES {
        return;
    }
    if path.is_file() {
        if is_rule_file(path) {
            out.push(path.to_path_buf());
        }
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        if out.len() >= MAX_RULE_FILES {
            break;
        }
        if path.is_dir() {
            if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                if metadata.file_type().is_symlink() {
                    continue;
                }
            }
            collect_files(&path, out);
        } else if is_rule_file(&path) {
            out.push(path);
        }
    }
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yar") || extension.eq_ignore_ascii_case("yara")
        })
}

fn hex_pattern(pattern: &[Option<u8>]) -> String {
    pattern
        .iter()
        .map(|byte| byte.map_or_else(|| "??".into(), |value| format!("{value:02X}")))
        .collect::<Vec<_>>()
        .join(" ")
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn normalize_path(value: &str) -> String {
    value.replace('/', "\\").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yara_metadata_tags_and_multiple_rules() {
        let rules = parse_yara_rules(
            r#"
rule first : malware ransomware {
  meta:
    description = "first rule"
    author = "tester"
    category = "malware"
  strings:
    $a = "x"
  condition:
    $a
}
private rule second {
  meta:
    description = "second"
  condition:
    true
}
"#,
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "first");
        assert_eq!(rules[0].tags, vec!["malware", "ransomware"]);
        assert_eq!(rules[0].metadata_map.get("author").unwrap(), "tester");
        assert_eq!(rules[1].name, "second");
    }

    #[test]
    fn ignores_rule_words_inside_comments() {
        let rules = parse_yara_rules(
            "// rule fake { condition: true }\nrule real { condition: uint16(0) == 0x5A4D }\n",
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "real");
    }

    #[test]
    fn categories_are_counted_per_rule() {
        let entries = vec![YaraRuleEntry {
            id: "yara:test:one".into(),
            name: "one".into(),
            description: String::new(),
            categories: vec!["malware".into(), "forensics".into()],
            tags: vec![],
            source_id: "test".into(),
            source: "test".into(),
            path: String::new(),
            author: None,
            license: None,
            hash: String::new(),
            added: None,
            modified: None,
            status: RuleStatus::Compatible,
            enabled: true,
            namespace: "default".into(),
            revision: String::new(),
            severity: None,
            confidence: None,
            dependencies: vec![],
            errors: vec![],
        }];
        let counts = category_counts_yara(&entries);
        assert_eq!(counts.iter().find(|c| c.id == "malware").unwrap().total, 1);
        assert_eq!(
            counts.iter().find(|c| c.id == "forensics").unwrap().total,
            1
        );
    }
}
