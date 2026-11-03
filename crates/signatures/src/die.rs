use crate::{Category, Detection, DetectionCertainty, DetectionEngine, Evidence, SignatureContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DieStats {
    pub files: usize,
    pub with_metadata: usize,
    pub compatible: usize,
    pub incompatible: usize,
    pub errors: usize,
    pub reasons: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DieDatabase {
    pub version: String,
    pub source: String,
    pub signatures: Vec<DieSignature>,
    pub stats: DieStats,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DieSignature {
    pub id: String,
    pub file: String,
    pub name: String,
    pub category: Category,
    pub pattern: Vec<Option<u8>>,
    pub version: Option<String>,
    pub options: Vec<String>,
    pub fixed_bytes: usize,
    pub compatibility: String,
}

impl DieSignature {
    pub fn pattern_text(&self) -> String {
        self.pattern
            .iter()
            .map(|b| b.map_or_else(|| "??".to_string(), |v| format!("{v:02X}")))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn load_die_directory(dir: &Path, version: &str) -> DieDatabase {
    let mut db = DieDatabase {
        version: version.to_string(),
        source: "Detect It Easy database (MIT)".to_string(),
        signatures: Vec::new(),
        stats: DieStats::default(),
        errors: Vec::new(),
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            db.errors
                .push(format!("cannot read {}: {e}", dir.display()));
            return db;
        }
    };
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("sg")))
        .collect();
    paths.sort();
    for path in paths {
        db.stats.files += 1;
        match std::fs::read_to_string(&path) {
            Ok(text) => match parse_die_signature(&path, &text) {
                Ok(sig) => db.signatures.push(sig),
                Err(reason) => {
                    db.stats.incompatible += 1;
                    *db.stats.reasons.entry(reason.to_string()).or_insert(0) += 1;
                }
            },
            Err(e) => {
                db.stats.errors += 1;
                db.errors.push(format!("{}: {e}", path.display()));
            }
        }
    }
    let missing_meta = db
        .stats
        .reasons
        .get("missing meta() declaration")
        .copied()
        .unwrap_or(0);
    db.stats.with_metadata = db.stats.files.saturating_sub(missing_meta);

    let mut seen: HashMap<Vec<Option<u8>>, usize> = HashMap::new();
    for sig in &db.signatures {
        *seen.entry(sig.pattern.clone()).or_insert(0) += 1;
    }
    let mut kept = Vec::new();
    for sig in db.signatures {
        if seen.get(&sig.pattern).copied().unwrap_or(0) > 1 {
            db.stats.incompatible += 1;
            *db.stats
                .reasons
                .entry("entry-point pattern shared by other DiE signatures".into())
                .or_insert(0) += 1;
        } else {
            kept.push(sig);
        }
    }
    db.stats.compatible = kept.len();
    db.signatures = kept;
    db
}

fn parse_die_signature(path: &Path, text: &str) -> Result<DieSignature, &'static str> {
    if text.len() > 512 * 1024 {
        return Err("signature file too large");
    }
    let code = strip_comments(text);
    let meta = parse_meta(&code).ok_or("missing meta() declaration")?;

    if let Some(reason) = unsupported_reason(&code) {
        return Err(reason);
    }

    let compare_calls = extract_calls(&code, "compareEP");
    let all_pe_calls = extract_pe_calls(&code);
    if compare_calls.len() != 1 || all_pe_calls.len() != 1 {
        return Err("not a single entry-point byte signature");
    }
    let raw_pattern = compare_calls.first().ok_or("missing pattern")?;
    let pattern = parse_die_pattern(raw_pattern).ok_or("unsupported DiE byte-pattern syntax")?;
    let fixed = pattern.iter().filter(|b| b.is_some()).count();
    if pattern.len() < 12 || fixed < 8 {
        return Err("pattern too short or too many wildcards");
    }

    let version = extract_assignment(&code, "sVersion");
    let options = extract_assignment(&code, "sOptions")
        .into_iter()
        .collect::<Vec<_>>();
    let name = meta.name;
    let category = map_die_category(&meta.kind);
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown.sg".into());
    let id = format!("die:PE/{file}");
    let compatibility = "DIE subset: single compareEP pattern; DiE-JS control flow was not executed, but the signature has no loops, includes, negations or other PE API calls.".to_string();

    Ok(DieSignature {
        id,
        file,
        name,
        category,
        pattern,
        version,
        options,
        fixed_bytes: fixed,
        compatibility,
    })
}
struct Meta {
    kind: String,
    name: String,
}

fn parse_meta(code: &str) -> Option<Meta> {
    let start = code.find("meta(")?;
    let args = &code[start + 5..];
    let end = args.find(')')?;
    let args = &args[..end];
    let mut values = Vec::new();
    let mut chars = args.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c == '"' || c == '\'' {
            let quote = c;
            let mut value = String::new();
            let mut escaped = false;
            for (_, ch) in chars.by_ref() {
                if escaped {
                    value.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == quote {
                    break;
                } else {
                    value.push(ch);
                }
            }
            values.push(value);
        }
    }
    if values.len() < 2 {
        return None;
    }
    Some(Meta {
        kind: values[0].clone(),
        name: values[1].clone(),
    })
}

fn unsupported_reason(code: &str) -> Option<&'static str> {
    for (needle, reason) in [
        ("includeScript", "uses includeScript framework helpers"),
        ("while (", "contains loops (not executed by the adapter)"),
        ("while(", "contains loops (not executed by the adapter)"),
        ("for (", "contains loops (not executed by the adapter)"),
        ("for(", "contains loops (not executed by the adapter)"),
        ("do {", "contains loops (not executed by the adapter)"),
        ("eval(", "uses eval"),
        ("Function(", "uses dynamic Function"),
        ("PE.section", "uses PE.section API"),
        ("PE.resource", "uses PE.resource API"),
        ("_isResultPresent", "uses result-state APIs"),
        ("_setResult", "uses result-state APIs"),
        ("!PE.", "uses negated PE checks"),
    ] {
        if code.contains(needle) {
            return Some(reason);
        }
    }
    if code.contains("PE.compare(") && !code.contains("compareEP") {
        return Some("uses PE.compare with dynamic offsets");
    }
    None
}

fn extract_pe_calls(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(pos) = rest.find("PE.") {
        let tail = &rest[pos + 3..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        if end > 0 {
            out.push(tail[..end].to_string());
        }
        rest = &tail[end..];
    }
    out
}

fn extract_calls(code: &str, method: &str) -> Vec<String> {
    let needle = format!("PE.{method}(");
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(pos) = rest.find(&needle) {
        let after = &rest[pos + needle.len()..];
        if let Some(value) = parse_quoted(after) {
            out.push(value);
        }
        rest = after;
    }
    out
}

fn parse_quoted(input: &str) -> Option<String> {
    let start = input.find(['"', '\''])?;
    let quote = input.as_bytes()[start] as char;
    let mut value = String::new();
    let mut escaped = false;
    for ch in input[start + 1..].chars() {
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn extract_assignment(code: &str, variable: &str) -> Option<String> {
    let mut values = Vec::new();
    let mut rest = code;
    while let Some(pos) = rest.find(variable) {
        let after = &rest[pos + variable.len()..];
        let trimmed = after.trim_start();
        if let Some(rest) = trimmed.strip_prefix('=') {
            if let Some(value) = parse_quoted(rest) {
                values.push(value);
            }
        }
        rest = &after[1.min(after.len())..];
    }
    values.sort();
    values.dedup();
    if values.len() == 1 {
        values.pop()
    } else {
        None
    }
}

fn parse_die_pattern(raw: &str) -> Option<Vec<Option<u8>>> {
    let mut out = Vec::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '\'' {
            for ch in chars.by_ref() {
                if ch == '\'' {
                    break;
                }
                out.push(Some(ch as u8));
            }
            continue;
        }
        let next = chars.next()?;
        let pair = [c, next];
        match pair {
            ['?', '?'] | ['.', '.'] | ['$', '$'] | ['#', '#'] | ['*', '*'] => out.push(None),
            [a, b] if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => {
                let hex = format!("{a}{b}");
                out.push(Some(u8::from_str_radix(&hex, 16).ok()?));
            }
            _ => return None,
        }
    }
    Some(out)
}

fn strip_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            out.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if c == '"' || c == '\'' {
            quote = Some(c);
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            for n in chars.by_ref() {
                if n == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(n) = chars.next() {
                if n == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn map_die_category(kind: &str) -> Category {
    match kind.to_ascii_lowercase().as_str() {
        "compiler" => Category::Compiler,
        "linker" => Category::Linker,
        "packer" => Category::Packer,
        "protector" | "protection" | "cryptor" => Category::Protector,
        "runtime" | "emulator" => Category::Runtime,
        "framework" | "game engine" => Category::Framework,
        "installer" => Category::Installer,
        "format" => Category::Format,
        "language" => Category::Language,
        "library" => Category::Library,
        _ => Category::Other,
    }
}

pub fn evaluate_die(db: &DieDatabase, ctx: &SignatureContext<'_>) -> Vec<Detection> {
    let Some(pe) = ctx.pe else {
        return Vec::new();
    };
    let Some(offset) = pe.entry_point_file_offset else {
        return Vec::new();
    };
    let start = offset as usize;
    let mut out = Vec::new();
    for sig in &db.signatures {
        let Some(available) = ctx.file_bytes.get(start..) else {
            continue;
        };
        if available.len() < sig.pattern.len() {
            continue;
        }
        if sig
            .pattern
            .iter()
            .enumerate()
            .all(|(i, p)| p.is_none_or(|b| available[i] == b))
        {
            let options = if sig.options.is_empty() {
                Vec::new()
            } else {
                sig.options.clone()
            };
            out.push(Detection {
                id: sig.id.clone(),
                name: sig.name.clone(),
                category: sig.category,
                description: format!("Detect It Easy signature {}", sig.file),
                confidence: 70,
                version: sig.version.clone(),
                evidence: vec![Evidence {
                    condition: "die_compare_ep".into(),
                    description: format!(
                        "DIE entry-point signature {} matched at file offset {offset:#x} ({} fixed bytes)",
                        sig.pattern_text(),
                        sig.fixed_bytes
                    ),
                    offset: Some(offset),
                    value: Some(sig.id.clone()),
                }],
                source: format!("DIE {} ({})", db.version, db.source),
                vendor: None,
                certainty: DetectionCertainty::Exact,
                engine: DetectionEngine::DetectItEasy,
                options,
                compatibility: Some(sig.compatibility.clone()),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_style_die_signature() {
        let text = r#"
// comment
meta("packer", "32LiTe");
function detect() {
    if (PE.compareEP("6006FC1E07BE........6A0468........68")) {
        sVersion = "0.03a";
        bDetected = true;
    }
    return result();
}
"#;
        let sig = parse_die_signature(Path::new("packer_32LiTe.2.sg"), text).expect("parse");
        assert_eq!(sig.name, "32LiTe");
        assert_eq!(sig.category, Category::Packer);
        assert_eq!(sig.version.as_deref(), Some("0.03a"));
        assert_eq!(sig.fixed_bytes, 10);
    }

    #[test]
    fn rejects_signatures_with_loops_or_framework() {
        let text =
            r#"meta("packer", "X"); function detect(){ for(var i=0;i<10;i++){} return result(); }"#;
        let result = parse_die_signature(Path::new("x.sg"), text);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "contains loops (not executed by the adapter)"
        );
    }

    #[test]
    fn pattern_parser_supports_wildcards_and_text() {
        let p = parse_die_pattern("60E8$$$$??..'AB'").unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p[0], Some(0x60));
        assert!(p[2].is_none());
        assert_eq!(p[6], Some(b'A'));
    }

    #[test]
    fn comments_do_not_create_false_calls() {
        let code = strip_comments("// PE.compareEP(\"AA\")\nmeta(\"packer\",\"X\");");
        assert!(!code.contains("compareEP"));
    }
}
