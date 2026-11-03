use crate::{Category, Detection, DetectionCertainty, DetectionEngine, Evidence};
use binscope_pe::{PeInfo, SectionInfo};

const DIRECT_CONFIDENCE: u8 = 60;
const COLLISION_CONFIDENCE: u8 = 50;
const STRUCTURAL_CONFIDENCE: u8 = 50;

const NON_VMP_PREFIXES: &[&str] = &[
    "upx", "mpress", "aspack", "adata", "pec", "fsg", "nspack", "rlpack", "packed", "petite",
    "telock", "themida", "winlice", "enigma", "obsidium", "reacto", "alien", "asmg", "asguard",
    "be", "y0da", "yp", "obfh", "shell", "prdata", "dingboy", "sign", "xcomp", "xvlk", "sec",
    "text", "rdata", "data", "pdata", "rsrc", "reloc", "bss", "idata", "edata", "tls", "debug",
];

const THEMIDA_SOURCE: &str = "DIE heuristic (protector_Themida.2.sg)";
const THEMIDA_VENDOR: &str = "Oreans Technologies";

pub fn evaluate_themida(pe: &PeInfo, file_bytes: &[u8]) -> Option<Detection> {
    if let Some(detection) = themida_entry_pattern(pe, file_bytes) {
        return Some(detection);
    }
    if let Some(detection) = themida_section_name(pe) {
        return Some(detection);
    }
    if pe.clr.is_none() {
        if let Some(detection) = themida_structure(pe) {
            return Some(detection);
        }
    }
    None
}

fn themida_entry_pattern(pe: &PeInfo, file_bytes: &[u8]) -> Option<Detection> {
    let offset = pe.entry_point_file_offset? as usize;
    let available = file_bytes.get(offset..)?;

    struct Pattern {
        bytes: &'static str,
        is_64: bool,
        version: Option<&'static str>,
        option: Option<&'static str>,
        confidence: u8,
    }

    let patterns = [
        Pattern {
            bytes: "4883EC085053E801000000CC584889C348FFC0482D........482D........4805........803BCC75..C60300",
            is_64: true,
            version: Some("2.X"),
            option: None,
            confidence: 86,
        },
        Pattern {
            bytes: "558BEC83C4D860E8000000005A81EA........8BDAC745D8000000008B45D8408945D8817DD880000000",
            is_64: false,
            version: Some("1.0.X.X-1.8.X.X"),
            option: Some("NoCompression"),
            confidence: 84,
        },
        Pattern {
            bytes: "8BC58BD460E8000000005D81ED........8995........89B5........8985........83BD",
            is_64: false,
            version: Some("1.X"),
            option: Some("NoCompression SecureEngine"),
            confidence: 84,
        },
        Pattern {
            bytes: "83EC045053E801000000CC588BD840",
            is_64: false,
            version: Some("2.0.1.0-2.1.8.0"),
            option: None,
            confidence: 82,
        },
        Pattern {
            bytes: "51b9........85c974$$59e9$$$$$$$$83ec..5053............5889c3402d........2d........05........803b..75..c603..bb........68........68........5350",
            is_64: false,
            version: Some("2.0.1.0-2.1.8.0"),
            option: None,
            confidence: 82,
        },
        Pattern {
            bytes: "83EC045053E801000000CC5889C3402D........2D........05........803BCC75..C60300",
            is_64: false,
            version: Some("2.X"),
            option: None,
            confidence: 86,
        },
        Pattern {
            bytes: "E9$$$$$$$$8bc58bd460e8",
            is_64: false,
            version: Some("1.1.X-1.2.X"),
            option: None,
            confidence: 78,
        },
        Pattern {
            bytes: "eb$$e9$$$$$$$$e9$$$$$$$$565053e8$$$$$$$$5889c3402d",
            is_64: false,
            version: None,
            option: None,
            confidence: 74,
        },
    ];

    for pattern in patterns {
        if pattern.is_64 != pe.is_64 {
            continue;
        }
        let Some(mask) = parse_themida_pattern(pattern.bytes) else {
            continue;
        };
        if !mask_matches(available, &mask) {
            continue;
        }
        let evidence = vec![Evidence {
            condition: "die_themida_compare_ep".into(),
            description: format!(
                "DIE Themida entry-point pattern matched at file offset {offset:#x}: {}",
                pattern.bytes
            ),
            offset: Some(offset as u64),
            value: Some(pattern.bytes.to_string()),
        }];
        return Some(themida_detection(
            pattern.version.map(str::to_string),
            pattern.confidence,
            DetectionCertainty::Exact,
            pattern
                .option
                .iter()
                .map(|value| value.to_string())
                .collect(),
            evidence,
            "Themida/Winlicense entry-point byte signature from DIE's protector_Themida.2.sg.",
        ));
    }

    let compressed = "B8........600BC074..E8000000005805..0000008038E975";
    if !pe.is_64 {
        if let Some(mask) = parse_themida_pattern(compressed) {
            if mask_matches(available, &mask) {
                let marker = available.get(9).copied();
                let version = match marker {
                    Some(0x58) => Some("1.0.X.X-1.8.0.0".to_string()),
                    Some(0x68) => Some("1.8.X-1.9.X".to_string()),
                    _ => None,
                };
                return Some(themida_detection(
                    version,
                    84,
                    DetectionCertainty::Exact,
                    vec!["Compressed".to_string()],
                    vec![Evidence {
                        condition: "die_themida_compare_ep".into(),
                        description: format!(
                            "DIE Themida compressed entry-point pattern matched at file offset {offset:#x}; byte at EP+9 is {}",
                            marker.map_or_else(|| "unavailable".to_string(), |b| format!("{b:#04x}"))
                        ),
                        offset: Some(offset as u64),
                        value: Some(compressed.to_string()),
                    }],
                    "Themida/Winlicense compressed entry-point signature from DIE's protector_Themida.2.sg.",
                ));
            }
        }
    }
    None
}

fn themida_section_name(pe: &PeInfo) -> Option<Detection> {
    for (index, section) in pe.sections.iter().enumerate() {
        let lower = section.name.trim().to_ascii_lowercase();
        let (version, label) = if lower == ".themida" {
            ("3.XX".to_string(), "Themida")
        } else if lower == ".winlice" {
            ("3.XX, WinLicense".to_string(), "Themida/WinLicense")
        } else {
            continue;
        };
        let offset = pe
            .section_table_offset
            .checked_add((index as u64).saturating_mul(40));
        return Some(themida_detection(
            Some(version),
            70,
            DetectionCertainty::StrongHeuristic,
            Vec::new(),
            vec![Evidence {
                condition: "die_themida_section_name".into(),
                description: format!(
                    "DIE Themida rule checks for the section name '{}'; section {index} has that name.",
                    section.name
                ),
                offset,
                value: Some(section.name.clone()),
            }],
            &format!(
                "{label} section name observed. Section names can be renamed or imitated; this is a strong indicator, not a byte-level signature."
            ),
        ));
    }
    None
}

fn themida_structure(pe: &PeInfo) -> Option<Detection> {
    if pe.sections.len() < 4 {
        return None;
    }
    let resource = directory_section(pe, 2);
    let import = directory_section(pe, 1);
    if resource != Some(1) || import != Some(2) {
        return None;
    }
    let entry = entry_section(pe, pe.entry_point_rva)?;
    let section = pe.sections.get(entry)?;
    if pe.entry_point_rva != section.virtual_address {
        return None;
    }
    let first = pe.sections.first()?;
    if first.entropy < 7.5 {
        return None;
    }
    let version = if entry == 3 {
        "1.X".to_string()
    } else if entry > 3 {
        "2.X".to_string()
    } else {
        return None;
    };
    let header_offset = pe
        .section_table_offset
        .checked_add((entry as u64).saturating_mul(40));
    Some(themida_detection(
        Some(version),
        62,
        DetectionCertainty::StrongHeuristic,
        Vec::new(),
        vec![
            Evidence {
                condition: "die_themida_resource_section".into(),
                description: "The resource directory maps to section 1, as required by DIE's detectThemida().".into(),
                offset: pe
                    .data_directories
                    .iter()
                    .find(|dir| dir.index == 2)
                    .and_then(|dir| dir.file_offset),
                value: Some("section 1".into()),
            },
            Evidence {
                condition: "die_themida_import_section".into(),
                description: "The import directory maps to section 2, as required by DIE's detectThemida().".into(),
                offset: pe
                    .data_directories
                    .iter()
                    .find(|dir| dir.index == 1)
                    .and_then(|dir| dir.file_offset),
                value: Some("section 2".into()),
            },
            Evidence {
                condition: "die_themida_entry_at_section_start".into(),
                description: format!(
                    "Entry point RVA {:#x} equals the virtual address of section {entry} ('{}').",
                    pe.entry_point_rva, section.name
                ),
                offset: pe.entry_point_file_offset,
                value: Some(format!("{:#x}", pe.entry_point_rva)),
            },
            Evidence {
                condition: "die_themida_first_section_entropy".into(),
                description: format!(
                    "Section 0 ('{}') has entropy {:.2} bits/byte (DIE requires >= 7.5).",
                    first.name, first.entropy
                ),
                offset: header_offset,
                value: Some(format!("{:.2}", first.entropy)),
            },
        ],
        "DIE detectThemida() structural conditions matched: section layout, entry point at the start of a later section, and high-entropy first section.",
    ))
}

fn themida_detection(
    version: Option<String>,
    confidence: u8,
    certainty: DetectionCertainty,
    options: Vec<String>,
    evidence: Vec<Evidence>,
    description: &str,
) -> Detection {
    Detection {
        id: "die-heuristic.themida".into(),
        name: "Themida/Winlicense (heuristic)".into(),
        category: Category::Protector,
        description: format!(
            "{description} This is not proof of malware; protectors are used by both benign and malicious software."
        ),
        confidence,
        version,
        options,
        evidence,
        source: THEMIDA_SOURCE.into(),
        vendor: Some(THEMIDA_VENDOR.into()),
        certainty,
        engine: DetectionEngine::DieHeuristic,
        compatibility: Some(
            "DIE heuristic port (protector_Themida.2.sg): DIE executes a DiE-JS program with PE.section/import-hash branches that BinScope does not execute. Entry-point patterns are exact masked byte matches; section names and the structural branch are heuristics and can produce false positives."
                .into(),
        ),
    }
}

fn parse_themida_pattern(pattern: &str) -> Option<Vec<Option<u8>>> {
    let mut out = Vec::new();
    let mut chars = pattern.chars().filter(|c| !c.is_whitespace());
    while let Some(first) = chars.next() {
        let second = chars.next()?;
        match [first, second] {
            ['?', '?'] | ['.', '.'] | ['$', '$'] | ['#', '#'] | ['*', '*'] => out.push(None),
            [a, b] if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => {
                out.push(Some(u8::from_str_radix(&format!("{a}{b}"), 16).ok()?));
            }
            _ => return None,
        }
    }
    Some(out)
}

fn mask_matches(available: &[u8], mask: &[Option<u8>]) -> bool {
    available.len() >= mask.len()
        && mask
            .iter()
            .enumerate()
            .all(|(index, expected)| expected.is_none_or(|byte| available[index] == byte))
}

pub fn evaluate_vmprotect(pe: &PeInfo, file_bytes: &[u8]) -> Option<Detection> {
    if pe.clr.is_some() {
        return None;
    }

    let resource = directory_section(pe, 2);
    let reloc = directory_section(pe, 5);

    let named = (|| -> Option<Detection> {
        for index in (0..pe.sections.len()).rev() {
            if Some(index) == resource || Some(index) == reloc {
                continue;
            }
            let section = &pe.sections[index];
            if section.name.is_empty() {
                return None;
            }

            if index > 0 && section.name == ".vmp0" {
                return Some(vmprotect_detection(
                    pe,
                    section,
                    DIRECT_CONFIDENCE,
                    format!(
                        "DIE heuristic: last non-resource section is the VMProtect section '{}'.",
                        section.name
                    ),
                    "direct VMProtect section name",
                ));
            }

            let (suffix, required) = if index > 3 && section.name.ends_with('3') {
                ("3", 3)
            } else if index > 2 && section.name.ends_with('2') {
                ("2", 2)
            } else if index > 1 && section.name.ends_with('1') {
                ("1", 1)
            } else {
                return None;
            };

            let (left, right, needed) = match suffix {
                "1" => ("0", "1", vec!["0", "1"]),
                "2" => ("1", "2", vec!["0", "1", "2"]),
                _ => ("2", "3", vec!["0", "1", "2", "3"]),
            };
            let prefix = section_collision(pe, left, right)?;
            if !numbered_siblings_present(pe, &prefix, &needed) {
                return None;
            }
            if is_known_non_vmp_prefix(&prefix) {
                return None;
            }
            if required > 1 && !prefix.starts_with('.') {
                return None;
            }

            return Some(vmprotect_detection(
                pe,
                section,
                COLLISION_CONFIDENCE,
                format!(
                    "DIE heuristic: section '{}' belongs to the numbered family '{}0'..='{}{}' and uses the same suffix-collision rule as DIE's VMProtect script.",
                    section.name, prefix, prefix, suffix
                ),
                "section-name collision",
            ));
        }
        None
    })();

    named.or_else(|| detect_vmp2(pe, file_bytes))
}

fn vmprotect_detection(
    pe: &PeInfo,
    section: &SectionInfo,
    confidence: u8,
    description: String,
    evidence_condition: &str,
) -> Detection {
    let mut options = Vec::new();
    if section.name.ends_with('0') {
        options.push("min protection".to_string());
    }
    let version = if pe.is_64 {
        Some("2.XX-3.XX".to_string())
    } else {
        None
    };
    Detection {
        id: "die-heuristic.vmprotect".into(),
        name: "VMProtect (heuristic)".into(),
        category: Category::Protector,
        description: format!(
            "{description} This is not proof of VMProtect: section names can be renamed or imitated by other protectors."
        ),
        confidence,
        version,
        options,
        evidence: vec![Evidence {
            condition: evidence_condition.into(),
            description,
            offset: (section.raw_offset > 0).then_some(u64::from(section.raw_offset)),
            value: Some(section.name.clone()),
        }],
        source: "DIE heuristic (VMProtect section rules)".into(),
        vendor: Some("VMProtect Software".into()),
        certainty: DetectionCertainty::Possible,
        engine: DetectionEngine::DieHeuristic,
        compatibility: Some(
            "DIE heuristic port (protector_VMProtect.2.sg): section names and structural clues are attacker-controlled and can produce false positives. Low confidence; this is not definitive and not full DiE-JS execution."
                .into(),
        ),
    }
}

fn detect_vmp2(pe: &PeInfo, file_bytes: &[u8]) -> Option<Detection> {
    if pe.sections.len() <= 7 {
        return None;
    }
    let len = pe.sections.len();
    let resource = directory_section(pe, 2);
    let reloc = directory_section(pe, 5);
    let mut count = 5usize;
    if resource.is_some_and(|index| index > len.saturating_sub(count)) {
        count += 1;
    }
    if reloc.is_some_and(|index| index > len.saturating_sub(count)) {
        count += 1;
    }
    let start = len.saturating_sub(count);
    let mut virtual_only = 0usize;
    let mut last_non_empty = None;
    for (index, section) in pe.sections.iter().enumerate().skip(start) {
        if Some(index) == resource || Some(index) == reloc {
            continue;
        }
        if section.raw_size == 0 && section.raw_offset == 0 {
            virtual_only += 1;
        } else if section.raw_size != 0 && section.raw_offset != 0 {
            last_non_empty = Some(index);
        }
    }
    if virtual_only < 3 {
        return None;
    }
    let last = last_non_empty?;
    if entry_section(pe, pe.entry_point_rva) != Some(last) {
        return None;
    }
    let section = &pe.sections[last];
    let matched = if section.characteristics == 0xE000_0060 {
        section.entropy > 7.6
    } else if section.characteristics & 0x2000_0000 != 0 {
        let raw = file_bytes
            .get(
                section.raw_offset as usize
                    ..section.raw_offset as usize + section.raw_size as usize,
            )
            .unwrap_or(&[]);
        raw.windows(3).filter(|w| *w == [0x9C, 0x8D, 0x64]).count() >= 2
    } else {
        false
    };
    if !matched {
        return None;
    }
    Some(Detection {
        id: "die-heuristic.vmprotect".into(),
        name: "VMProtect (heuristic)".into(),
        category: Category::Protector,
        description: "DIE's detectVmp2 structural heuristic matched: several trailing sections are virtual-only and the entry point is in the last populated section with VMProtect-like flags/entropy. This is not proof of VMProtect."
            .into(),
        confidence: STRUCTURAL_CONFIDENCE,
        version: Some("2.X".into()),
        options: Vec::new(),
        evidence: vec![
            Evidence {
                condition: "die_detect_vmp2".into(),
                description: format!(
                    "{virtual_only} trailing sections are virtual-only (no raw data)"
                ),
                offset: None,
                value: Some(virtual_only.to_string()),
            },
            Evidence {
                condition: "entry_section".into(),
                description: format!(
                    "Entry point is in the last populated section '{}' (flags {:#x}, entropy {:.2})",
                    section.name, section.characteristics, section.entropy
                ),
                offset: pe.entry_point_file_offset,
                value: Some(section.name.clone()),
            },
        ],
        source: "DIE heuristic (VMProtect detectVmp2)".into(),
        vendor: Some("VMProtect Software".into()),
        certainty: DetectionCertainty::Possible,
        engine: DetectionEngine::DieHeuristic,
        compatibility: Some(
            "DIE detectVmp2 structural heuristic: virtual-only sections, section flags and entropy can also occur in other protectors. Low confidence; not definitive."
                .into(),
        ),
    })
}

fn directory_section(pe: &PeInfo, directory_index: usize) -> Option<usize> {
    let dir = pe
        .data_directories
        .iter()
        .find(|d| d.index == directory_index)?;
    if dir.rva == 0 {
        return None;
    }
    entry_section(pe, dir.rva)
}

fn entry_section(pe: &PeInfo, rva: u32) -> Option<usize> {
    pe.sections.iter().position(|section| {
        let start = u64::from(section.virtual_address);
        let size = u64::from(section.virtual_size.max(section.raw_size));
        u64::from(rva) >= start && u64::from(rva) < start.saturating_add(size)
    })
}

fn section_collision(pe: &PeInfo, suffix_a: &str, suffix_b: &str) -> Option<String> {
    for first in &pe.sections {
        let Some(prefix_a) = first.name.strip_suffix(suffix_a) else {
            continue;
        };
        if prefix_a.is_empty() {
            continue;
        }
        if pe
            .sections
            .iter()
            .any(|second| second.name.strip_suffix(suffix_b) == Some(prefix_a))
        {
            return Some(prefix_a.to_string());
        }
    }
    None
}

fn numbered_siblings_present(pe: &PeInfo, prefix: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().all(|suffix| {
        pe.sections
            .iter()
            .any(|s| s.name == format!("{prefix}{suffix}"))
    })
}

fn is_known_non_vmp_prefix(prefix: &str) -> bool {
    let lower = prefix.to_ascii_lowercase();
    NON_VMP_PREFIXES.iter().any(|known| {
        lower == *known
            || lower == format!(".{known}")
            || lower.strip_prefix('.').is_some_and(|v| v == *known)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use binscope_pe::{parse_default, PeBuilder};

    fn parse(bytes: &[u8]) -> PeInfo {
        parse_default(bytes).expect("PE")
    }

    fn high_entropy_bytes(size: usize) -> Vec<u8> {
        (0..size).map(|index| (index % 256) as u8).collect()
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn pe_offset(data: &[u8]) -> usize {
        u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize
    }

    fn optional_header(data: &[u8]) -> usize {
        pe_offset(data) + 4 + 20
    }

    fn section_table(data: &[u8]) -> usize {
        let pe = pe_offset(data);
        let size = u16::from_le_bytes(data[pe + 20..pe + 22].try_into().unwrap()) as usize;
        optional_header(data) + size
    }

    fn section_va(data: &[u8], index: usize) -> u32 {
        let table = section_table(data);
        u32::from_le_bytes(
            data[table + index * 40 + 12..table + index * 40 + 16]
                .try_into()
                .unwrap(),
        )
    }

    fn structural_fixture(extra_sections: &str) -> Vec<u8> {
        let mut builder = PeBuilder::pe32();
        builder.text_bytes = high_entropy_bytes(0x800);
        let mut data = builder
            .with_section(extra_sections, vec![0x90; 0x200], 0xE000_0020)
            .build();
        if extra_sections == "second" {
            let mut builder = PeBuilder::pe32();
            builder.text_bytes = high_entropy_bytes(0x800);
            data = builder
                .with_section("code0", vec![0x90; 0x200], 0xE000_0020)
                .with_section("code1", vec![0x90; 0x200], 0xE000_0020)
                .build();
        }
        let opt = optional_header(&data);
        let dirs = opt + 96;
        let resource_va = section_va(&data, 1);
        let import_va = section_va(&data, 2);
        write_u32(&mut data, dirs + 16, resource_va);
        write_u32(&mut data, dirs + 20, 0x20);
        write_u32(&mut data, dirs + 8, import_va);
        write_u32(&mut data, dirs + 12, 0x20);
        let entry_index = if extra_sections == "second" { 4 } else { 3 };
        let entry_va = section_va(&data, entry_index);
        write_u32(&mut data, opt + 16, entry_va);
        data
    }

    #[test]
    fn detects_themida_structural_1x_and_2x() {
        for (label, expected) in [("1.X", "1.X"), ("2.X", "2.X")] {
            let data = if label == "1.X" {
                structural_fixture("code0")
            } else {
                structural_fixture("second")
            };
            let pe = parse(&data);
            let detection = evaluate_themida(&pe, &data).expect("Themida structural");
            assert_eq!(detection.name, "Themida/Winlicense (heuristic)");
            assert_eq!(detection.category, Category::Protector);
            assert_eq!(detection.version.as_deref(), Some(expected));
            assert_eq!(detection.confidence, 62);
            assert_eq!(detection.vendor.as_deref(), Some("Oreans Technologies"));
            assert_eq!(detection.certainty, DetectionCertainty::StrongHeuristic);
            assert_eq!(detection.engine, DetectionEngine::DieHeuristic);
            assert!(detection.evidence.len() >= 4);
            assert!(detection
                .compatibility
                .as_deref()
                .unwrap()
                .contains("heuristic"));
        }
    }

    #[test]
    fn clean_and_other_packers_are_not_themida() {
        let clean = PeBuilder::pe64().build();
        let pe = parse(&clean);
        assert!(evaluate_themida(&pe, &clean).is_none());

        let upx = PeBuilder::pe64()
            .with_section("UPX0", vec![0x90; 16], 0xE000_0020)
            .with_section("UPX1", vec![0x90; 16], 0xE000_0020)
            .build();
        let pe = parse(&upx);
        assert!(evaluate_themida(&pe, &upx).is_none());

        let mut low = structural_fixture("code0");
        let text_offset = {
            let table = section_table(&low);
            u32::from_le_bytes(low[table + 20..table + 24].try_into().unwrap()) as usize
        };
        for byte in &mut low[text_offset..text_offset + 0x800] {
            *byte = 0;
        }
        let pe = parse(&low);
        assert!(evaluate_themida(&pe, &low).is_none());
    }

    #[test]
    fn themida_section_names_are_strong_heuristics() {
        for (name, expected) in [(".themida", "3.XX"), (".winlice", "3.XX, WinLicense")] {
            let bytes = PeBuilder::pe64()
                .with_section(name, vec![0x90; 16], 0xE000_0020)
                .build();
            let pe = parse(&bytes);
            let detection = evaluate_themida(&pe, &bytes).expect("section name heuristic");
            assert_eq!(detection.version.as_deref(), Some(expected));
            assert_eq!(detection.certainty, DetectionCertainty::StrongHeuristic);
            assert!(detection.evidence[0].description.contains(name));
        }
    }

    #[test]
    fn exact_themida_ep_patterns_are_matched_but_not_generic_entropy() {
        let pattern = "4883EC085053E801000000CC584889C348FFC0482D00000000482D00000000480500000000803BCC7500C60300";
        let hex: Vec<u8> = (0..pattern.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&pattern[i..i + 2], 16).unwrap())
            .collect();
        let mut builder = PeBuilder::pe64();
        builder.text_bytes = hex;
        let bytes = builder.build();
        let pe = parse(&bytes);
        let detection = evaluate_themida(&pe, &bytes).expect("Themida EP pattern");
        assert_eq!(detection.version.as_deref(), Some("2.X"));
        assert_eq!(detection.certainty, DetectionCertainty::Exact);
        assert_eq!(detection.confidence, 86);

        let clean = PeBuilder::pe64().build();
        let pe = parse(&clean);
        assert!(evaluate_themida(&pe, &clean).is_none());
    }
    #[test]
    fn detects_die_numbered_section_family_with_warning() {
        let bytes = PeBuilder::pe64()
            .with_section(".ofme0", vec![0x90; 16], 0x6000_0020)
            .with_section(".ofme1", vec![0x90; 16], 0xE000_0020)
            .with_section(".ofme2", vec![0x90; 16], 0x6800_0060)
            .build();
        let pe = parse(&bytes);
        let detection = evaluate_vmprotect(&pe, &bytes).expect("VMProtect heuristic");
        assert_eq!(detection.name, "VMProtect (heuristic)");
        assert_eq!(detection.category, Category::Protector);
        assert_eq!(detection.version.as_deref(), Some("2.XX-3.XX"));
        assert_eq!(detection.confidence, 50);
        assert!(detection
            .compatibility
            .as_deref()
            .unwrap()
            .contains("not definitive"));
        assert!(detection.description.contains("not proof"));
    }

    #[test]
    fn direct_vmp_section_is_lower_risk_but_still_heuristic() {
        let bytes = PeBuilder::pe64()
            .with_section(".vmp0", vec![0x90; 16], 0xE000_0020)
            .build();
        let pe = parse(&bytes);
        let detection = evaluate_vmprotect(&pe, &bytes).expect("direct VMProtect section");
        assert_eq!(detection.confidence, 60);
        assert_eq!(detection.options, vec!["min protection"]);
        assert!(detection.compatibility.is_some());
    }

    #[test]
    fn upx_and_standard_numbered_names_are_not_vmprotect() {
        let bytes = PeBuilder::pe64()
            .with_section("UPX0", vec![0x90; 16], 0xE000_0020)
            .with_section("UPX1", vec![0x90; 16], 0xE000_0020)
            .build();
        let pe = parse(&bytes);
        assert!(evaluate_vmprotect(&pe, &bytes).is_none());

        let bytes = PeBuilder::pe64()
            .with_section(".data0", vec![0x90; 16], 0xC000_0040)
            .with_section(".data1", vec![0x90; 16], 0xC000_0040)
            .build();
        let pe = parse(&bytes);
        assert!(evaluate_vmprotect(&pe, &bytes).is_none());
    }
}
