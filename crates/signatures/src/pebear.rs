use crate::{Category, Detection, DetectionCertainty, DetectionEngine, Evidence, SignatureContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PebearSignature {
    pub name: String,
    pub pattern: Vec<Option<u8>>,
    pub anchor_index: usize,
    pub anchor: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PebearDatabase {
    pub signatures: Vec<PebearSignature>,
    pub total_blocks: usize,
    pub skipped: usize,
    pub skip_reasons: BTreeMap<String, usize>,
    pub source: String,
}

pub fn parse_pebear(text: &str) -> PebearDatabase {
    let mut db = PebearDatabase {
        source: "PE-bear SIG.txt (PEiD UserDB, GPLv2)".into(),
        ..Default::default()
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    let mut seen: HashMap<Vec<Option<u8>>, usize> = HashMap::new();
    while index < lines.len() {
        while index < lines.len() && lines[index].trim().is_empty() {
            index += 1;
        }
        if index >= lines.len() {
            break;
        }
        let name = lines[index].trim().to_string();
        index += 1;
        while index < lines.len() && lines[index].trim().is_empty() {
            index += 1;
        }
        if index >= lines.len() {
            break;
        }
        let length: usize = match lines[index].trim().parse() {
            Ok(v) => v,
            Err(_) => {
                db.skipped += 1;
                *db.skip_reasons
                    .entry("invalid length line".into())
                    .or_insert(0) += 1;
                index += 1;
                continue;
            }
        };
        index += 1;
        let mut tokens = Vec::new();
        while index < lines.len() && !lines[index].trim().is_empty() {
            tokens.extend(
                lines[index]
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
            );
            index += 1;
        }
        db.total_blocks += 1;
        if name.is_empty() || length == 0 {
            db.skipped += 1;
            *db.skip_reasons
                .entry("empty name or length".into())
                .or_insert(0) += 1;
            continue;
        }
        if tokens.len() != length {
            db.skipped += 1;
            *db.skip_reasons
                .entry("length does not match pattern".into())
                .or_insert(0) += 1;
            continue;
        }
        let mut pattern = Vec::with_capacity(length);
        let mut valid = true;
        for token in &tokens {
            if token == "??" || token == "?" {
                pattern.push(None);
            } else if token.len() == 2 {
                match u8::from_str_radix(token, 16) {
                    Ok(v) => pattern.push(Some(v)),
                    Err(_) => {
                        valid = false;
                        break;
                    }
                }
            } else {
                valid = false;
                break;
            }
        }
        if !valid {
            db.skipped += 1;
            *db.skip_reasons
                .entry("invalid hex token".into())
                .or_insert(0) += 1;
            continue;
        }
        let fixed = pattern.iter().filter(|b| b.is_some()).count();
        if pattern.len() < 12 || fixed < 8 {
            db.skipped += 1;
            *db.skip_reasons
                .entry("pattern too short or too many wildcards".into())
                .or_insert(0) += 1;
            continue;
        }
        let unique_fixed: std::collections::BTreeSet<u8> =
            pattern.iter().flatten().copied().collect();
        if unique_fixed.len() < 3 {
            db.skipped += 1;
            *db.skip_reasons
                .entry("repetitive/low-information pattern".into())
                .or_insert(0) += 1;
            continue;
        }
        let Some((anchor_index, anchor)) = find_anchor(&pattern) else {
            db.skipped += 1;
            *db.skip_reasons
                .entry("no 4-byte fixed anchor".into())
                .or_insert(0) += 1;
            continue;
        };
        let count = seen.entry(pattern.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            db.skipped += 1;
            *db.skip_reasons
                .entry("duplicate pattern".into())
                .or_insert(0) += 1;
            continue;
        }
        db.signatures.push(PebearSignature {
            name,
            pattern,
            anchor_index,
            anchor,
        });
    }
    db
}

fn find_anchor(pattern: &[Option<u8>]) -> Option<(usize, u32)> {
    for i in 0..pattern.len().saturating_sub(3) {
        if let [Some(a), Some(b), Some(c), Some(d)] = &pattern[i..i + 4] {
            return Some((i, u32::from_le_bytes([*a, *b, *c, *d])));
        }
    }
    None
}

fn matches_at(data: &[u8], start: usize, pattern: &[Option<u8>]) -> bool {
    let Some(slice) = data.get(start..start.saturating_add(pattern.len())) else {
        return false;
    };
    pattern
        .iter()
        .zip(slice)
        .all(|(p, b)| p.is_none_or(|v| v == *b))
}

pub fn scan_bytes(db: &PebearDatabase, data: &[u8], limit: usize) -> Vec<(usize, usize)> {
    let mut index: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, sig) in db.signatures.iter().enumerate() {
        index.entry(sig.anchor).or_default().push(i);
    }
    let mut hits = Vec::new();
    if data.len() < 4 {
        return hits;
    }
    for offset in 0..=data.len() - 4 {
        let value = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let Some(candidates) = index.get(&value) else {
            continue;
        };
        for &sig_index in candidates {
            let sig = &db.signatures[sig_index];
            let Some(start) = offset.checked_sub(sig.anchor_index) else {
                continue;
            };
            if matches_at(data, start, &sig.pattern) {
                hits.push((sig_index, start));
                if hits.len() >= limit {
                    return hits;
                }
            }
        }
    }
    hits
}

pub fn evaluate_pebear(db: &PebearDatabase, ctx: &SignatureContext<'_>) -> Vec<Detection> {
    if ctx.pe.is_none() {
        return Vec::new();
    }
    let hits = scan_bytes(db, ctx.file_bytes, 500);
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (sig_index, offset) in hits {
        let sig = &db.signatures[sig_index];
        if !seen.insert(sig.name.clone()) {
            continue;
        }
        let category = category_for(&sig.name);
        out.push(Detection {
            id: format!("pebear:{}", sig.name),
            name: sig.name.clone(),
            category,
            description: "PE-bear SIG.txt historical signature match".into(),
            confidence: if sig.pattern.iter().flatten().count() >= 24 {
                60
            } else {
                45
            },
            version: None,
            options: Vec::new(),
            evidence: vec![Evidence {
                condition: "pebear_pattern".into(),
                description: format!(
                    "PE-bear signature '{}' matched at file offset {offset:#x}",
                    sig.name
                ),
                offset: Some(offset as u64),
                value: Some(hex_pattern(&sig.pattern)),
            }],
            source: db.source.clone(),
            vendor: None,
            certainty: DetectionCertainty::Exact,
            engine: DetectionEngine::Pebear,
            compatibility: Some(
                "Historical PEiD/PE-bear signature: byte match only; may be outdated and may produce false positives."
                    .into(),
            ),
        });
    }
    out
}

fn hex_pattern(pattern: &[Option<u8>]) -> String {
    pattern
        .iter()
        .map(|b| b.map_or_else(|| "??".into(), |v| format!("{v:02X}")))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn category_for(name: &str) -> Category {
    let n = name.to_ascii_lowercase();
    if n.contains("protect")
        || n.contains("virtualizer")
        || n.contains("themida")
        || n.contains("vmprotect")
        || n.contains("obsidium")
        || n.contains("armadillo")
        || n.contains("cryptor")
        || n.contains("enigma")
    {
        Category::Protector
    } else if n.contains("compiler") || n.contains("delphi") || n.contains("borland") {
        Category::Compiler
    } else if n.contains("installer") || n.contains("setup") {
        Category::Installer
    } else if n.contains("pack")
        || n.contains("upx")
        || n.contains("aspack")
        || n.contains("mpress")
        || n.contains("pecompact")
        || n.contains("petite")
        || n.contains("fsg")
        || n.contains("nspack")
        || n.contains("rlpack")
        || n.contains("telock")
        || n.contains("expressor")
    {
        Category::Packer
    } else {
        Category::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "ASPack 1.00b\n13\n60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 00\n\nDemo Protector 1.0\n16\nDE AD BE EF 01 02 03 04 05 06 07 08 09 0A 0B 0C\n\nBad\n5\nZZ ZZ\n";

    #[test]
    fn parses_and_skips_malformed_blocks() {
        let db = parse_pebear(SAMPLE);
        assert_eq!(db.signatures.len(), 2);
        assert_eq!(db.signatures[0].name, "ASPack 1.00b");
        assert_eq!(db.signatures[0].pattern[2], None);
        assert_eq!(db.signatures[1].name, "Demo Protector 1.0");
        assert_eq!(db.skipped, 1);
        assert!(db.skip_reasons.keys().any(|r| r.contains("length")));
    }

    #[test]
    fn scans_positive_and_negative_bytes() {
        let db = parse_pebear(SAMPLE);
        let mut positive = [0u8; 32];

        positive[7..7 + 13].copy_from_slice(&[
            0x60, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x5D, 0x81, 0xED, 0x92, 0x1A, 0x44, 0x00,
        ]);
        let hits = scan_bytes(&db, &positive, 20);
        assert!(hits
            .iter()
            .any(|(i, off)| db.signatures[*i].name == "ASPack 1.00b" && *off == 7));
        let negative = [0u8; 32];
        assert!(scan_bytes(&db, &negative, 20).is_empty());
    }

    #[test]
    fn low_information_repeating_patterns_are_rejected() {
        let text = "PENinja\n16\n90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90\n";
        let db = parse_pebear(text);
        assert!(db.signatures.is_empty());
        assert!(db
            .skip_reasons
            .keys()
            .any(|r| r.contains("low-information")));
    }

    #[test]
    fn categories_are_conservative() {
        assert_eq!(category_for("ASPack 1.00b"), Category::Packer);
        assert_eq!(category_for("VMProtect 2.0"), Category::Protector);
        assert_eq!(category_for("Some Installer"), Category::Installer);
        assert_eq!(category_for("Unknown Tool"), Category::Other);
    }
}
