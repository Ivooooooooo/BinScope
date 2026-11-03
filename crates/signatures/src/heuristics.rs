use crate::{Category, Detection, DetectionCertainty, DetectionEngine, Evidence, SignatureContext};

#[derive(Clone, Debug)]
pub struct PackingSignals<'a> {
    pub entry_section_name: &'a str,
    pub entry_section_entropy: f64,
    pub entry_section_executable: bool,
    pub entry_rva: u32,
    pub entry_offset: Option<u64>,
    pub import_functions: usize,
    pub import_libraries: usize,
    pub virtual_only_sections: usize,
}

const MIN_ENTRY_ENTROPY: f64 = 7.2;

const MAX_IMPORT_FUNCTIONS: usize = 24;

const MIN_VIRTUAL_ONLY_SECTIONS: usize = 2;

pub fn evaluate_packing(signals: &PackingSignals<'_>) -> Option<Detection> {
    if !signals.entry_section_executable
        || signals.entry_section_entropy < MIN_ENTRY_ENTROPY
        || signals.import_functions > MAX_IMPORT_FUNCTIONS
        || signals.virtual_only_sections < MIN_VIRTUAL_ONLY_SECTIONS
    {
        return None;
    }

    let mut confidence = 55u8;
    if signals.entry_section_entropy >= 7.5 {
        confidence += 5;
    }
    if signals.import_functions <= 8 {
        confidence += 5;
    }
    if signals.virtual_only_sections >= 3 {
        confidence += 5;
    }

    let options = vec![
        format!(
            "entry point in high-entropy section {} ({:.2} bits/byte)",
            signals.entry_section_name, signals.entry_section_entropy
        ),
        format!("only {} imported functions", signals.import_functions),
        format!(
            "{} sections are virtual-only (no raw data)",
            signals.virtual_only_sections
        ),
    ];

    Some(Detection {
        id: "heuristic.structural_packer".into(),
        name: "Generic packed/protected PE".into(),
        category: Category::Packer,
        description: "The entry point is inside a high-entropy executable section, most original \
                      sections have no raw data and the import table is unusually small. These \
                      combined facts are consistent with packing or runtime protection; the \
                      specific packer is not identified."
            .into(),
        confidence,
        version: None,
        options,
        evidence: vec![
            Evidence {
                condition: "entry_section_entropy".into(),
                description: format!(
                    "Entry point section '{}' is executable with entropy {:.2} bits/byte",
                    signals.entry_section_name, signals.entry_section_entropy
                ),
                offset: signals.entry_offset,
                value: Some(format!("{:.2}", signals.entry_section_entropy)),
            },
            Evidence {
                condition: "stub_import_table".into(),
                description: format!(
                    "Only {} imported functions across {} libraries",
                    signals.import_functions, signals.import_libraries
                ),
                offset: None,
                value: Some(signals.import_functions.to_string()),
            },
            Evidence {
                condition: "virtual_only_sections".into(),
                description: format!(
                    "{} sections have a virtual size but no raw data",
                    signals.virtual_only_sections
                ),
                offset: None,
                value: Some(signals.virtual_only_sections.to_string()),
            },
            Evidence {
                condition: "entry_point".into(),
                description: format!(
                    "Entry point RVA {:#x} maps to file offset {:#x}",
                    signals.entry_rva,
                    signals.entry_offset.unwrap_or(0)
                ),
                offset: signals.entry_offset,
                value: Some(format!("{:#x}", signals.entry_rva)),
            },
        ],
        source: "BinScope structural heuristic".into(),
        vendor: None,
        certainty: DetectionCertainty::Possible,
        engine: DetectionEngine::StructuralHeuristic,
        compatibility: Some(
            "Structural heuristic: it does not identify a specific packer and does not rely on \
             section names or entropy alone."
                .into(),
        ),
    })
}

pub fn evaluate_structural(ctx: &SignatureContext<'_>) -> Vec<Detection> {
    let Some(pe) = ctx.pe else {
        return Vec::new();
    };
    if ctx.dotnet_present || pe.clr.is_some() {
        return Vec::new();
    }
    let entry_rva = pe.entry_point_rva;
    let Some(section) = pe.sections.iter().find(|section| {
        let start = u64::from(section.virtual_address);
        let size = u64::from(section.virtual_size.max(section.raw_size));
        u64::from(entry_rva) >= start && u64::from(entry_rva) < start.saturating_add(size)
    }) else {
        return Vec::new();
    };
    let import_functions = pe.imports.iter().map(|lib| lib.functions.len()).sum();
    let virtual_only_sections = pe
        .sections
        .iter()
        .filter(|section| section.virtual_size > 0 && section.raw_size == 0)
        .count();
    let signals = PackingSignals {
        entry_section_name: &section.name,
        entry_section_entropy: section.entropy,
        entry_section_executable: section.executable,
        entry_rva,
        entry_offset: pe.entry_point_file_offset,
        import_functions,
        import_libraries: pe.imports.len(),
        virtual_only_sections,
    };
    evaluate_packing(&signals).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PackingSignals<'static> {
        PackingSignals {
            entry_section_name: ".ofme2",
            entry_section_entropy: 7.68,
            entry_section_executable: true,
            entry_rva: 0x13c1d65,
            entry_offset: Some(0xa2c365),
            import_functions: 6,
            import_libraries: 6,
            virtual_only_sections: 6,
        }
    }

    #[test]
    fn matches_packed_structural_profile() {
        let detection = evaluate_packing(&sample()).expect("packed profile");
        assert_eq!(detection.category, Category::Packer);
        assert_eq!(detection.confidence, 70);
        assert_eq!(detection.evidence.len(), 4);
        assert!(detection.evidence[0].description.contains(".ofme2"));
        assert!(detection.compatibility.is_some());
    }

    #[test]
    fn rejects_entropy_alone_and_normal_imports() {
        let mut only_entropy = sample();
        only_entropy.virtual_only_sections = 0;
        assert!(evaluate_packing(&only_entropy).is_none());

        let mut many_imports = sample();
        many_imports.import_functions = 500;
        assert!(evaluate_packing(&many_imports).is_none());

        let mut not_executable = sample();
        not_executable.entry_section_executable = false;
        assert!(evaluate_packing(&not_executable).is_none());
    }
}
