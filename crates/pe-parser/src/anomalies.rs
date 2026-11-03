use crate::types::{
    Anomaly, AnomalyCategory, AnomalyEvidence, Confidence, EvidenceKind, PeInfo, Severity,
};
use chrono::Utc;

const MAX_DEBUG_FINDINGS: usize = 8;

pub fn collect(info: &PeInfo, data: &[u8], headers: &crate::headers::Headers) -> Vec<Anomaly> {
    let mut out = Vec::new();
    let file_len = data.len() as u64;

    if info.sections.is_empty() {
        out.push(
            Anomaly::build(
                "no_sections",
                Severity::High,
                "The PE file declares no sections.",
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-001", "No sections declared")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The COFF header reports NumberOfSections = 0. Without a section table the loader cannot map code or data, so the image is structurally incomplete or deliberately malformed.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "NumberOfSections",
                "0",
            ))
            .with_expected("at least 1 section")
            .with_observed("0 sections")
            .with_false_positive_notes(
                "Object files and some unusual linker outputs can omit sections; BinScope only analyzes images here, so this remains a structural defect.",
            ),
        );
    }

    if info.number_of_sections as usize > 16 {
        out.push(
            Anomaly::build(
                "many_sections",
                Severity::Low,
                format!(
                    "{} sections are declared; this is legal but unusual for compiler-produced binaries.",
                    info.number_of_sections
                ),
                AnomalyCategory::Suspicious,
            )
            .with_rule("BS-PE-002", "Unusually high section count")
            .with_confidence(Confidence::Medium)
            .with_explanation(
                "The section table contains more entries than typical compiler output. Packers and protectors often create many small sections, but large legitimate applications can as well.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "NumberOfSections",
                info.number_of_sections.to_string(),
            ))
            .with_expected("typically 1-16 sections")
            .with_observed(format!("{} sections", info.number_of_sections))
            .with_false_positive_notes(
                "Large native applications, game engines and bundled installers legitimately use many sections. This finding is not evidence of malware.",
            ),
        );
    }

    if info.entry_point_rva == 0 {
        if !info.is_dll {
            out.push(
                Anomaly::build(
                    "entry_point_zero",
                    Severity::Medium,
                    "AddressOfEntryPoint is zero for a non-DLL image.",
                    AnomalyCategory::Malformed,
                )
                .with_rule("BS-PE-003", "Entry point is zero")
                .with_confidence(Confidence::High)
                .with_explanation(
                    "A native executable normally has a non-zero entry point. Zero is valid for DLLs, where DllMain is optional, but for an EXE it usually means the header was modified or the image is not directly runnable.",
                )
                .with_rva(0)
                .with_evidence(AnomalyEvidence::new(
                    EvidenceKind::Rva,
                    "AddressOfEntryPoint",
                    "0x00000000",
                ))
                .with_expected("non-zero RVA inside an executable section")
                .with_observed("0x0")
                .with_false_positive_notes(
                    "Some drivers and resource-only images use a zero entry point. BinScope records the observation without changing the verdict.",
                ),
            );
        }
    } else if let Some(section) = info.section_for_rva(info.entry_point_rva) {
        if !section.executable {
            out.push(
                Anomaly::build(
                    "entry_point_not_executable",
                    Severity::High,
                    format!(
                        "Entry point RVA {:#x} lies in section '{}' which is not marked executable.",
                        info.entry_point_rva, section.name
                    ),
                    AnomalyCategory::Suspicious,
                )
                .with_rule("BS-PE-004", "Entry point outside executable section")
                .with_confidence(Confidence::High)
                .with_explanation(
                    "The entry point resolves to a section without IMAGE_SCN_MEM_EXECUTE. Windows normally refuses to execute from such a section; this can indicate a modified entry point or an unusual loader.",
                )
                .with_rva(info.entry_point_rva)
                .with_section(section.name.clone())
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::Rva,
                        "AddressOfEntryPoint",
                        format!("{:#x}", info.entry_point_rva),
                    )
                    .at_rva(info.entry_point_rva),
                )
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::SectionHeader,
                        format!("Section '{}' characteristics", section.name),
                        format!("{} ({:#010x})", section.permissions, section.characteristics),
                    )
                    .in_section(section.name.clone()),
                )
                .with_expected("entry point inside a section with execute permission")
                .with_observed(format!("section '{}' has {}", section.name, section.permissions))
                .with_false_positive_notes(
                    "A relocated or obfuscated entry point can still be benign. BinScope does not disassemble the target and does not treat this as malware.",
                ),
            );
        }
    } else {
        out.push(
            Anomaly::build(
                "entry_point_outside_sections",
                Severity::High,
                format!(
                    "Entry point RVA {:#x} does not fall inside any declared section.",
                    info.entry_point_rva
                ),
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-005", "Entry point outside every section")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The RVA cannot be mapped through the section table, so the loader cannot resolve the first instruction. This is a structural defect or a deliberately inconsistent header.",
            )
            .with_rva(info.entry_point_rva)
            .with_evidence(
                AnomalyEvidence::new(
                    EvidenceKind::Rva,
                    "AddressOfEntryPoint",
                    format!("{:#x}", info.entry_point_rva),
                )
                .at_rva(info.entry_point_rva),
            )
            .with_expected("RVA inside a declared section")
            .with_observed("no matching section")
            .with_false_positive_notes(
                "Sections with a zero raw size but a virtual size can still map the RVA at load time; BinScope checks both virtual and raw sizes before reporting this.",
            ),
        );
    }

    for s in &info.sections {
        let section_header = section_header_offset(info, s.index);
        if s.raw_size > 0 {
            let end = s.raw_offset as u64 + s.raw_size as u64;
            if end > file_len {
                out.push(
                    Anomaly::build(
                        "section_beyond_eof",
                        Severity::High,
                        format!(
                            "Section '{}' raw data ends at {end:#x}, beyond the file size {file_len:#x}.",
                            s.name
                        ),
                        AnomalyCategory::Malformed,
                    )
                    .with_rule("BS-PE-006", "Section raw data extends beyond EOF")
                    .with_confidence(Confidence::High)
                    .with_explanation(
                        "PointerToRawData plus SizeOfRawData exceeds the bytes actually present in the file. The missing range cannot be mapped without reading outside the buffer.",
                    )
                    .with_section(s.name.clone())
                    .with_evidence(
                        AnomalyEvidence::new(
                            EvidenceKind::FileRange,
                            format!("Section '{}' raw range", s.name),
                            format!("{:#x}..{:#x}", s.raw_offset, end),
                        )
                        .at_offset(s.raw_offset as u64)
                        .in_section(s.name.clone()),
                    )
                    .with_evidence(AnomalyEvidence::new(
                        EvidenceKind::HeaderField,
                        "SizeOfRawData",
                        s.raw_size.to_string(),
                    ))
                    .with_expected(format!("range ends at or before {file_len:#x}"))
                    .with_observed(format!("range ends at {end:#x}"))
                    .with_false_positive_notes(
                        "Truncated downloads and sparse files produce the same observation. The parser reports it instead of reading out of bounds.",
                    ),
                );
            }
            if (s.raw_offset as u64) < info.size_of_headers as u64 {
                out.push(
                    Anomaly::build(
                        "section_overlaps_headers",
                        Severity::Medium,
                        format!(
                            "Section '{}' raw data starts at {:#x}, inside the PE headers (SizeOfHeaders {:#x}).",
                            s.name, s.raw_offset, info.size_of_headers
                        ),
                        AnomalyCategory::Malformed,
                    )
                    .with_rule("BS-PE-007", "Section raw data overlaps headers")
                    .with_confidence(Confidence::High)
                    .with_explanation(
                        "SizeOfHeaders describes the region reserved for DOS/NT headers and the section table. A section that starts inside it aliases header bytes as section content.",
                    )
                    .with_section(s.name.clone())
                    .with_evidence(
                        AnomalyEvidence::new(
                            EvidenceKind::FileRange,
                            format!("Section '{}' PointerToRawData", s.name),
                            format!("{:#x}", s.raw_offset),
                        )
                        .at_offset(s.raw_offset as u64)
                        .in_section(s.name.clone()),
                    )
                    .with_expected(format!("start >= SizeOfHeaders ({:#x})", info.size_of_headers))
                    .with_observed(format!("start {:#x}", s.raw_offset))
                    .with_false_positive_notes(
                        "Some minimal linkers place data immediately after the headers. A correct SizeOfHeaders usually prevents this finding.",
                    ),
                );
            }
        }

        if s.executable && s.writable {
            out.push(
                Anomaly::build(
                    "writable_executable_section",
                    Severity::Medium,
                    format!(
                        "Section '{}' is both writable and executable ({}).",
                        s.name, s.permissions
                    ),
                    AnomalyCategory::Suspicious,
                )
                .with_rule("BS-PE-008", "Writable and executable section")
                .with_confidence(Confidence::Medium)
                .with_explanation(
                    "IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are both set. This permits code to be modified at runtime and then executed, which weakens W^X protections. JIT engines and some protectors do this legitimately.",
                )
                .with_section(s.name.clone())
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::SectionHeader,
                        format!("Section '{}' characteristics", s.name),
                        format!(
                            "{} (W={}, X={}, raw {:#010x})",
                            s.permissions, s.writable, s.executable, s.characteristics
                        ),
                    )
                    .maybe_at_offset(section_header)
                    .in_section(s.name.clone()),
                )
                .with_expected("writable or executable, not both")
                .with_observed(format!("{} section", s.permissions))
                .with_false_positive_notes(
                    "JIT runtimes, emulators, packers and some game engines legitimately use RWX sections. This is an indicator, not a verdict.",
                ),
            );
        }

        if s.name_is_irregular {
            out.push(
                Anomaly::build(
                    "irregular_section_name",
                    Severity::Medium,
                    format!(
                        "Section {} has a name that is not printable ASCII.",
                        s.index
                    ),
                    AnomalyCategory::Suspicious,
                )
                .with_rule("BS-PE-009", "Irregular section name")
                .with_confidence(Confidence::Medium)
                .with_explanation(
                    "The eight-byte name contains bytes outside printable ASCII. Compiler-generated names normally use letters, digits, dots and dollar signs.",
                )
                .with_section(s.name.clone())
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::SectionHeader,
                        "Name",
                        format!("{:?}", s.name),
                    )
                    .maybe_at_offset(section_header)
                    .in_section(s.name.clone()),
                )
                .with_expected("printable ASCII name")
                .with_observed("non-printable bytes")
                .with_false_positive_notes(
                    "Obfuscators and protectors commonly randomize section names, but unusual names alone do not imply malicious behavior.",
                ),
            );
        }

        if s.entropy >= 7.2 && s.raw_size >= 1024 {
            out.push(
                Anomaly::build(
                    "high_entropy_section",
                    Severity::Info,
                    format!(
                        "Section '{}' has entropy {:.3} bits/byte. High entropy can indicate compression or encryption, but is not by itself evidence of packing.",
                        s.name, s.entropy
                    ),
                    AnomalyCategory::Informational,
                )
                .with_rule("BS-PE-010", "Unusually high section entropy")
                .with_confidence(Confidence::Low)
                .with_explanation(
                    "Shannon entropy measures byte distribution, not intent. Compressed resources, encrypted payloads and random padding all raise it; many benign installers and .NET assemblies contain high-entropy sections.",
                )
                .with_section(s.name.clone())
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::Entropy,
                        format!("Section '{}' entropy", s.name),
                        format!("{:.3} bits/byte over {} raw bytes", s.entropy, s.raw_size),
                    )
                    .maybe_at_offset(section_header)
                    .in_section(s.name.clone()),
                )
                .with_expected("entropy below 7.2 bits/byte")
                .with_observed(format!("{:.3} bits/byte", s.entropy))
                .with_false_positive_notes(
                    "High entropy is never classified as malware. Compressed and encrypted data is common in legitimate software.",
                ),
            );
        }

        if s.virtual_size == 0 && s.raw_size > 0 {
            out.push(
                Anomaly::build(
                    "zero_virtual_size",
                    Severity::Low,
                    format!(
                        "Section '{}' has VirtualSize 0 but {} bytes of raw data.",
                        s.name, s.raw_size
                    ),
                    AnomalyCategory::Malformed,
                )
                .with_rule("BS-PE-011", "Zero virtual size with raw data")
                .with_confidence(Confidence::Medium)
                .with_explanation(
                    "VirtualSize zero contradicts a non-empty raw range. Windows generally falls back to SizeOfRawData, but the header is inconsistent.",
                )
                .with_section(s.name.clone())
                .with_evidence(AnomalyEvidence::new(
                    EvidenceKind::HeaderField,
                    "VirtualSize",
                    "0",
                ))
                .with_expected("VirtualSize > 0")
                .with_observed(format!("0 (raw size {})", s.raw_size))
                .with_false_positive_notes(
                    "Some linkers emit VirtualSize 0 for sections that are never mapped. The observation is structural, not behavioral.",
                ),
            );
        }
    }

    let mut ranges: Vec<(u64, u64, &str)> = info
        .sections
        .iter()
        .filter(|s| s.raw_size > 0)
        .map(|s| {
            (
                s.raw_offset as u64,
                s.raw_offset as u64 + s.raw_size as u64,
                s.name.as_str(),
            )
        })
        .collect();
    ranges.sort_by_key(|r| r.0);
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 && pair[0].2 != pair[1].2 {
            out.push(
                Anomaly::build(
                    "overlapping_sections",
                    Severity::Medium,
                    format!(
                        "Sections '{}' and '{}' have overlapping raw data ranges.",
                        pair[0].2, pair[1].2
                    ),
                    AnomalyCategory::Suspicious,
                )
                .with_rule("BS-PE-012", "Overlapping section raw ranges")
                .with_confidence(Confidence::High)
                .with_explanation(
                    "Two sections claim the same file bytes. One section's content can be changed by writes intended for the other, and tools may disagree about which bytes belong to which section.",
                )
                .with_section(pair[0].2.to_string())
                .with_section(pair[1].2.to_string())
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::FileRange,
                        format!("Section '{}' raw range", pair[0].2),
                        format!("{:#x}..{:#x}", pair[0].0, pair[0].1),
                    )
                    .at_offset(pair[0].0)
                    .in_section(pair[0].2.to_string()),
                )
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::FileRange,
                        format!("Section '{}' raw range", pair[1].2),
                        format!("{:#x}..{:#x}", pair[1].0, pair[1].1),
                    )
                    .at_offset(pair[1].0)
                    .in_section(pair[1].2.to_string()),
                )
                .with_expected("disjoint raw ranges")
                .with_observed(format!(
                    "sections overlap at {:#x}",
                    pair[1].0.max(pair[0].0)
                ))
                .with_false_positive_notes(
                    "Deliberately aliased sections are used by a few packers. BinScope reports the overlap without assuming intent.",
                ),
            );
        }
    }

    if info.file_alignment == 0 || !info.file_alignment.is_power_of_two() {
        out.push(
            Anomaly::build(
                "invalid_file_alignment",
                Severity::Medium,
                format!(
                    "FileAlignment {} is not a non-zero power of two.",
                    info.file_alignment
                ),
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-013", "Invalid FileAlignment")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The PE specification requires FileAlignment to be a power of two. A different value makes raw offsets ambiguous and is rejected by stricter loaders.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "FileAlignment",
                info.file_alignment.to_string(),
            ))
            .with_expected("non-zero power of two, typically 0x200 or 0x1000")
            .with_observed(info.file_alignment.to_string())
            .with_false_positive_notes(
                "ROM images and some embedded toolchains use non-standard alignment. The header is still inconsistent with the standard PE format.",
            ),
        );
    }
    if info.section_alignment == 0 || !info.section_alignment.is_power_of_two() {
        out.push(
            Anomaly::build(
                "invalid_section_alignment",
                Severity::Medium,
                format!(
                    "SectionAlignment {} is not a non-zero power of two.",
                    info.section_alignment
                ),
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-014", "Invalid SectionAlignment")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The PE specification requires SectionAlignment to be a power of two. Non-power-of-two values break RVA-to-offset conversion and are rejected by the Windows loader.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "SectionAlignment",
                info.section_alignment.to_string(),
            ))
            .with_expected("non-zero power of two")
            .with_observed(info.section_alignment.to_string())
            .with_false_positive_notes(
                "A malformed alignment is a structural fact; it does not by itself indicate malicious intent.",
            ),
        );
    }
    if info.section_alignment != 0
        && info.file_alignment != 0
        && info.section_alignment < info.file_alignment
    {
        out.push(
            Anomaly::build(
                "alignment_order",
                Severity::Low,
                "SectionAlignment is smaller than FileAlignment.",
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-015", "SectionAlignment below FileAlignment")
            .with_confidence(Confidence::Medium)
            .with_explanation(
                "The specification expects SectionAlignment >= FileAlignment. The inverted order makes section mapping and padding calculations inconsistent.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "SectionAlignment / FileAlignment",
                format!("{} / {}", info.section_alignment, info.file_alignment),
            ))
            .with_expected("SectionAlignment >= FileAlignment")
            .with_observed(format!(
                "{} < {}",
                info.section_alignment, info.file_alignment
            ))
            .with_false_positive_notes(
                "Some compact packers intentionally use a small SectionAlignment. The finding describes header ordering only.",
            ),
        );
    }

    if info.number_of_rva_and_sizes < 16 && info.number_of_rva_and_sizes > 0 {
        out.push(
            Anomaly::build(
                "short_data_directory_list",
                Severity::Low,
                format!(
                    "NumberOfRvaAndSizes is {} instead of the usual 16.",
                    info.number_of_rva_and_sizes
                ),
                AnomalyCategory::Suspicious,
            )
            .with_rule("BS-PE-016", "Short data directory list")
            .with_confidence(Confidence::Medium)
            .with_explanation(
                "Fewer than 16 data directories are declared. Directories beyond the count are absent by definition, which can hide or remove security-relevant tables.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "NumberOfRvaAndSizes",
                info.number_of_rva_and_sizes.to_string(),
            ))
            .with_expected("16")
            .with_observed(info.number_of_rva_and_sizes.to_string())
            .with_false_positive_notes(
                "Older or minimal toolchains sometimes emit fewer directories. Absence of a directory is not evidence of tampering.",
            ),
        );
    }

    if info.time_date_stamp == 0 {
        out.push(
            Anomaly::build(
                "zero_timestamp",
                Severity::Info,
                "COFF TimeDateStamp is zero.",
                AnomalyCategory::Informational,
            )
            .with_rule("BS-PE-017", "Zero COFF timestamp")
            .with_confidence(Confidence::High)
            .with_explanation(
                "A zero COFF timestamp is common in reproducible builds and some linkers. It removes one source of build-time information.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "TimeDateStamp",
                "0",
            ))
            .with_expected("non-zero build timestamp")
            .with_observed("0")
            .with_false_positive_notes(
                "Reproducible builds deliberately zero timestamps. This is informational only.",
            ),
        );
    } else {
        let ts = info.time_date_stamp as i64;
        let now = Utc::now().timestamp();
        if ts > now + 86_400 {
            out.push(
                Anomaly::build(
                    "future_timestamp",
                    Severity::Low,
                    format!("COFF TimeDateStamp is in the future ({ts}).",),
                    AnomalyCategory::Suspicious,
                )
                .with_rule("BS-PE-018", "COFF timestamp in the future")
                .with_confidence(Confidence::Medium)
                .with_explanation(
                    "The stored timestamp is more than one day ahead of the analyzing system's clock. This can be caused by clock skew or a modified header.",
                )
                .with_evidence(AnomalyEvidence::new(
                    EvidenceKind::HeaderField,
                    "TimeDateStamp",
                    format!("{ts} ({})", info.time_date_stamp_utc.as_deref().unwrap_or("unrendered")),
                ))
                .with_expected("timestamp not in the future")
                .with_observed(format!("{ts}"))
                .with_false_positive_notes(
                    "Machines with incorrect clocks and reproducible-build tooling can produce future timestamps. Timestamps are not proof of compilation time.",
                ),
            );
        }
    }

    if info.checksum != 0 && !info.checksum_valid {
        out.push(
            Anomaly::build(
                "checksum_mismatch",
                Severity::Low,
                format!(
                    "Stored PE checksum {:#010x} does not match the computed checksum {:#010x}.",
                    info.checksum, info.computed_checksum
                ),
                AnomalyCategory::Suspicious,
            )
            .with_rule("BS-PE-019", "PE checksum mismatch")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The optional-header checksum does not match the value computed over the file with the checksum field treated as zero. Modifying the file without updating the checksum produces this result.",
            )
            .with_evidence(
                AnomalyEvidence::new(
                    EvidenceKind::Checksum,
                    "Stored checksum",
                    format!("{:#010x}", info.checksum),
                )
                .at_offset(info.optional_header_offset + 64),
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::Checksum,
                "Computed checksum",
                format!("{:#010x}", info.computed_checksum),
            ))
            .with_expected(format!("{:#010x}", info.computed_checksum))
            .with_observed(format!("{:#010x}", info.checksum))
            .with_false_positive_notes(
                "Many legitimate tools and some linkers do not refresh the checksum. Windows does not require it for normal execution.",
            ),
        );
    }

    if !info.is_dll && info.imports.is_empty() && info.clr.is_none() {
        out.push(
            Anomaly::build(
                "no_imports",
                Severity::Info,
                "The executable declares no imported functions and has no CLR runtime header.",
                AnomalyCategory::Informational,
            )
            .with_rule("BS-PE-020", "No imports and no CLR header")
            .with_confidence(Confidence::Medium)
            .with_explanation(
                "Native executables normally import at least the C runtime or kernel32. A missing import table can indicate a dynamically resolved API set, a stripped binary, or a malformed image.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::DataDirectory,
                "Import directory",
                "absent or empty",
            ))
            .with_expected("at least one imported library")
            .with_observed("no imports")
            .with_false_positive_notes(
                "Shellcode-style binaries and statically linked freestanding programs legitimately have no imports. Informational only.",
            ),
        );
    }

    for dir in &info.data_directories {
        if let Some(note) = &dir.note {
            out.push(
                Anomaly::build(
                    "directory_inconsistent",
                    Severity::Medium,
                    format!(
                        "Data directory '{}' (index {}): {note}.",
                        dir.name, dir.index
                    ),
                    AnomalyCategory::Malformed,
                )
                .with_rule("BS-PE-021", "Inconsistent data directory")
                .with_confidence(Confidence::High)
                .with_explanation(
                    "The directory's RVA, size or file mapping is not consistent with the section table. Consumers of this directory cannot read it safely.",
                )
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::DataDirectory,
                        format!("{} directory", dir.name),
                        format!("RVA {:#x}, size {:#x}", dir.rva, dir.size),
                    )
                    .at_rva(dir.rva)
                    .extend_offset(dir.file_offset),
                )
                .with_expected("mapped RVA and valid size")
                .with_observed(note.clone())
                .with_false_positive_notes(
                    "Directories that are intentionally absent may still carry stale header values. BinScope reports the inconsistency, not intent.",
                ),
            );
        }
    }

    if let Some(clr) = &info.clr {
        if clr.metadata_file_offset.is_none() {
            out.push(
                Anomaly::build(
                    "clr_metadata_unmapped",
                    Severity::Medium,
                    "The CLR metadata RVA is not backed by raw section data.",
                    AnomalyCategory::Malformed,
                )
                .with_rule("BS-PE-022", "CLR metadata cannot be mapped")
                .with_confidence(Confidence::High)
                .with_explanation(
                    "The CLR header points at metadata that does not resolve to file bytes. The .NET metadata parser cannot read it.",
                )
                .with_rva(clr.metadata_rva)
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::Rva,
                        "MetaData RVA",
                        format!("{:#x}", clr.metadata_rva),
                    )
                    .at_rva(clr.metadata_rva),
                )
                .with_expected("metadata RVA backed by section data")
                .with_observed("not mapped")
                .with_false_positive_notes(
                    "A trimmed or obfuscated managed image can remove metadata. This is a structural observation.",
                ),
            );
        }
        if !clr.flag_names.iter().any(|f| f == "ILONLY")
            && info.imports.iter().any(|i| {
                i.name.to_ascii_lowercase().contains("mscoree")
                    || i.name.to_ascii_lowercase().contains("clr")
            })
        {
            out.push(
                Anomaly::build(
                    "clr_mixed_mode_candidate",
                    Severity::Info,
                    "CLR header is present without ILONLY and the image imports native runtime libraries; this may be a mixed-mode assembly.",
                    AnomalyCategory::Informational,
                )
                .with_rule("BS-PE-023", "Mixed-mode CLR candidate")
                .with_confidence(Confidence::Low)
                .with_explanation(
                    "ILONLY is clear and the import table references the CLR runtime. This combination is consistent with mixed-mode assemblies that contain both IL and native code.",
                )
                .with_evidence(AnomalyEvidence::new(
                    EvidenceKind::HeaderField,
                    "CLR flags",
                    clr.flag_names.join(" | "),
                ))
                .with_expected("ILONLY for pure managed assemblies")
                .with_observed("ILONLY absent")
                .with_false_positive_notes(
                    "Mixed-mode assemblies are a normal .NET deployment option, including many C++/CLI applications.",
                ),
            );
        }
    }

    if info.certificate.present && info.certificate.entries.is_empty() {
        out.push(
            Anomaly::build(
                "empty_certificate_table",
                Severity::Low,
                "The certificate directory is present but contains no parseable WIN_CERTIFICATE entry.",
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-024", "Empty certificate table")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The Security data directory is non-zero, but no valid WIN_CERTIFICATE header could be read. The table may be truncated, padded, or point at non-certificate data.",
            )
            .with_evidence(
                AnomalyEvidence::new(
                    EvidenceKind::CertificateTable,
                    "Security directory",
                    format!(
                        "offset {:#x}, size {:#x}",
                        info.certificate.directory_offset, info.certificate.directory_size
                    ),
                )
                .at_offset(info.certificate.directory_offset as u64),
            )
            .with_expected("at least one WIN_CERTIFICATE entry")
            .with_observed("0 parseable entries")
            .with_false_positive_notes(
                "A certificate table can be stripped by tools that rewrite the PE. Stripping removes signature evidence but is not itself malicious.",
            ),
        );
    }

    if let Some(overlay) = &info.overlay {
        if overlay.size > 0 {
            let ratio = overlay.size as f64 / file_len.max(1) as f64;
            out.push(
                Anomaly::build(
                    "overlay_data",
                    Severity::Info,
                    format!(
                        "{} bytes of data follow the last section ({:.1}% of the file). Overlay data is used by installers and signed binaries as well as by packers.",
                        overlay.size,
                        ratio * 100.0
                    ),
                    AnomalyCategory::Informational,
                )
                .with_rule("BS-PE-025", "Data after the last section")
                .with_confidence(Confidence::High)
                .with_explanation(
                    "Bytes beyond the maximum section raw end are not mapped by the loader. They can contain installer payloads, signatures, debug data or appended archives.",
                )
                .with_evidence(
                    AnomalyEvidence::new(
                        EvidenceKind::Overlay,
                        "Overlay",
                        format!(
                            "{} bytes at {:#x} ({:.1}% of the file)",
                            overlay.size,
                            overlay.offset,
                            ratio * 100.0
                        ),
                    )
                    .at_offset(overlay.offset),
                )
                .with_expected("no bytes after the last section")
                .with_observed(format!("{} bytes", overlay.size))
                .with_false_positive_notes(
                    "Overlay data alone is never classified as malicious. Signed binaries store their certificate table there and installers append archives.",
                ),
            );
            if overlay.size >= 4096 && overlay.entropy.is_some_and(|value| value >= 7.2) {
                let entropy = overlay.entropy.unwrap_or(0.0);
                out.push(
                    Anomaly::build(
                        "high_entropy_overlay",
                        Severity::Info,
                        format!(
                            "Overlay data has entropy {entropy:.3} bits/byte over {} bytes.",
                            overlay.size
                        ),
                        AnomalyCategory::Informational,
                    )
                    .with_rule("BS-PE-026", "High-entropy overlay")
                    .with_confidence(Confidence::Low)
                    .with_explanation(
                        "The appended region is large and close to uniformly distributed. Compressed installers, encrypted containers and packed payloads all produce this pattern.",
                    )
                    .with_evidence(
                        AnomalyEvidence::new(
                            EvidenceKind::Entropy,
                            "Overlay entropy",
                            format!("{entropy:.3} bits/byte over {} bytes", overlay.size),
                        )
                        .at_offset(overlay.offset),
                    )
                    .with_expected("entropy below 7.2 bits/byte")
                    .with_observed(format!("{entropy:.3} bits/byte"))
                    .with_false_positive_notes(
                        "Compressed installers and signed files routinely have high-entropy overlays. Informational only.",
                    ),
                );
            }
        }
    }

    if info.size_of_headers as u64 > file_len {
        out.push(
            Anomaly::build(
                "headers_beyond_eof",
                Severity::High,
                format!(
                    "SizeOfHeaders {} exceeds the file size {file_len}.",
                    info.size_of_headers
                ),
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-027", "Headers extend beyond EOF")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The header region declared in the optional header is larger than the entire file, so the section table cannot be fully present.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "SizeOfHeaders",
                info.size_of_headers.to_string(),
            ))
            .with_expected(format!("at most {file_len}"))
            .with_observed(info.size_of_headers.to_string())
            .with_false_positive_notes(
                "This is a structural defect. It cannot be explained by legitimate build configuration on its own.",
            ),
        );
    }

    if headers.number_of_sections as usize != info.sections.len() {
        out.push(
            Anomaly::build(
                "section_count_mismatch",
                Severity::Medium,
                "The number of parsed sections does not match the COFF header.",
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-028", "Section count mismatch")
            .with_confidence(Confidence::High)
            .with_explanation(
                "The section table was truncated or contains entries the parser refused. Consumers see fewer sections than the header declares.",
            )
            .with_evidence(AnomalyEvidence::new(
                EvidenceKind::HeaderField,
                "NumberOfSections",
                headers.number_of_sections.to_string(),
            ))
            .with_expected(headers.number_of_sections.to_string())
            .with_observed(format!("{} parsed", info.sections.len()))
            .with_false_positive_notes(
                "The parser caps the section table at a configured maximum and reports truncation; this finding reflects that limit or a damaged table.",
            ),
        );
    }

    collect_certificate_boundary_findings(info, file_len, &mut out);
    collect_debug_findings(info, file_len, &mut out);

    out
}

fn collect_certificate_boundary_findings(info: &PeInfo, file_len: u64, out: &mut Vec<Anomaly>) {
    let cert = &info.certificate;
    if !cert.present {
        return;
    }
    let offset = cert.directory_offset as u64;
    let size = cert.directory_size as u64;
    let end = offset.saturating_add(size);
    let misaligned = offset % 8 != 0;
    let inside_headers = offset < info.size_of_headers as u64;
    let beyond_eof = end > file_len;

    if misaligned || inside_headers || beyond_eof {
        let mut reasons = Vec::new();
        if misaligned {
            reasons.push("offset is not 8-byte aligned");
        }
        if inside_headers {
            reasons.push("table starts inside the PE headers");
        }
        if beyond_eof {
            reasons.push("table extends beyond the end of the file");
        }
        out.push(
            Anomaly::build(
                "certificate_table_bounds",
                Severity::Medium,
                format!(
                    "Certificate table boundaries are inconsistent: {}.",
                    reasons.join(", ")
                ),
                AnomalyCategory::Malformed,
            )
            .with_rule("BS-PE-029", "Inconsistent certificate table boundaries")
            .with_confidence(Confidence::High)
            .with_explanation(
                "WIN_CERTIFICATE tables must be 8-byte aligned, located outside the header region and fully contained in the file. These constraints are required to read entries without crossing buffer boundaries.",
            )
            .with_evidence(
                AnomalyEvidence::new(
                    EvidenceKind::CertificateTable,
                    "Security directory",
                    format!("{offset:#x}..{end:#x}"),
                )
                .at_offset(offset),
            )
            .with_expected(format!("aligned range inside 0..{file_len:#x}"))
            .with_observed(reasons.join("; "))
            .with_false_positive_notes(
                "PE rewriting tools can leave stale directory values. The table is reported as malformed; BinScope does not trust any entry it cannot bound.",
            ),
        );
    }

    if !cert.entries.is_empty() {
        for section in &info.sections {
            if section.raw_size == 0 {
                continue;
            }
            let section_start = section.raw_offset as u64;
            let section_end = section_start.saturating_add(section.raw_size as u64);
            if offset < section_end && end > section_start {
                out.push(
                    Anomaly::build(
                        "certificate_overlaps_section",
                        Severity::Medium,
                        format!(
                            "Certificate table overlaps raw data of section '{}'.",
                            section.name
                        ),
                        AnomalyCategory::Suspicious,
                    )
                    .with_rule("BS-PE-030", "Certificate table overlaps section data")
                    .with_confidence(Confidence::Medium)
                    .with_explanation(
                        "The certificate table shares file bytes with section raw data. Modifying either region changes the other, which can invalidate the signature or alter code.",
                    )
                    .with_section(section.name.clone())
                    .with_evidence(
                        AnomalyEvidence::new(
                            EvidenceKind::CertificateTable,
                            "Certificate table",
                            format!("{offset:#x}..{end:#x}"),
                        )
                        .at_offset(offset),
                    )
                    .with_evidence(
                        AnomalyEvidence::new(
                            EvidenceKind::FileRange,
                            format!("Section '{}' raw range", section.name),
                            format!("{section_start:#x}..{section_end:#x}"),
                        )
                        .at_offset(section_start)
                        .in_section(section.name.clone()),
                    )
                    .with_expected("certificate table outside section data")
                    .with_observed("ranges overlap")
                    .with_false_positive_notes(
                        "A few non-standard signers append the table in unusual places. BinScope reports the overlap without asserting intent.",
                    ),
                );
            }
        }
    }
}

fn collect_debug_findings(info: &PeInfo, file_len: u64, out: &mut Vec<Anomaly>) {
    let mut reported = 0usize;
    for entry in &info.debug_entries {
        if entry.status == "ok" {
            continue;
        }
        if reported >= MAX_DEBUG_FINDINGS {
            break;
        }
        reported += 1;
        let offset = entry.file_offset;
        let end = offset.and_then(|value| value.checked_add(entry.size_of_data as u64));
        let mut finding = Anomaly::build(
            "debug_entry_invalid",
            Severity::Medium,
            format!(
                "Debug directory entry {} points at data that cannot be read ({}).",
                entry.index, entry.status
            ),
            AnomalyCategory::Malformed,
        )
        .with_rule("BS-PE-031", "Debug directory points outside valid file ranges")
        .with_confidence(Confidence::High)
        .with_explanation(
            "IMAGE_DEBUG_DIRECTORY entry data is resolved through AddressOfRawData or PointerToRawData. The reported range is not fully backed by the file, so the debug payload cannot be consumed safely.",
        )
        .with_evidence(
            AnomalyEvidence::new(
                EvidenceKind::DebugDirectory,
                format!("Debug entry {} ({})", entry.index, entry.type_name),
                format!(
                    "RVA {:#x}, offset {}, size {}",
                    entry.address_rva,
                    offset.map(|value| format!("{value:#x}")).unwrap_or_else(|| "none".into()),
                    entry.size_of_data
                ),
            )
            .extend_offset(offset),
        )
        .with_expected(format!("range inside 0..{file_len:#x}"))
        .with_observed(entry.status.clone())
        .with_false_positive_notes(
            "Debug data can be stripped while the directory entries remain. Stripping is common in release builds and is not malicious by itself.",
        );
        if let Some(end) = end {
            finding = finding.with_evidence(AnomalyEvidence::new(
                EvidenceKind::FileRange,
                "Debug payload range",
                format!(
                    "{}..{end:#x}",
                    offset
                        .map(|value| format!("{value:#x}"))
                        .unwrap_or_else(|| "unmapped".into())
                ),
            ));
        }
        out.push(finding);
    }
}

fn section_header_offset(info: &PeInfo, index: usize) -> Option<u64> {
    info.section_table_offset
        .checked_add((index as u64).checked_mul(40)?)
}

trait EvidenceExt {
    fn extend_offset(self, offset: Option<u64>) -> Self;
}

impl EvidenceExt for AnomalyEvidence {
    fn extend_offset(mut self, offset: Option<u64>) -> Self {
        if let Some(value) = offset {
            self.file_offset = Some(value);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_default, PeBuilder};

    fn codes(info: &PeInfo) -> Vec<&str> {
        info.anomalies.iter().map(|a| a.code.as_str()).collect()
    }

    fn find<'a>(info: &'a PeInfo, code: &str) -> &'a Anomaly {
        info.anomalies
            .iter()
            .find(|a| a.code == code)
            .unwrap_or_else(|| panic!("missing {code}: {:?}", codes(info)))
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
        optional_header(data)
            + u16::from_le_bytes(
                data[pe_offset(data) + 20..pe_offset(data) + 22]
                    .try_into()
                    .unwrap(),
            ) as usize
    }

    #[test]
    fn clean_fixture_has_no_high_severity_findings() {
        let info = parse_default(&PeBuilder::pe32().build()).expect("parse");
        assert!(
            info.anomalies.iter().all(|a| a.severity < Severity::High),
            "unexpected findings: {:?}",
            codes(&info)
        );
        assert!(info.anomalies.iter().all(|a| !a.rule_id.is_empty()));
    }

    #[test]
    fn every_finding_has_typed_evidence_and_explanation() {
        let mut data = PeBuilder::pe32()
            .with_section("rwx", vec![0u8; 0x600], 0xE000_0020)
            .build();

        let opt = optional_header(&data);
        write_u32(&mut data, opt + 16, 0x99999);
        let info = parse_default(&data).expect("parse");
        assert!(!info.anomalies.is_empty());
        for anomaly in &info.anomalies {
            assert!(!anomaly.rule_id.is_empty());
            assert!(!anomaly.title.is_empty());
            assert!(!anomaly.explanation.is_empty());
            assert!(!anomaly.false_positive_notes.is_empty());
            assert!(anomaly.category.is_some());
            assert!(anomaly.confidence.is_some());
            assert!(
                !anomaly.evidence.is_empty(),
                "{} has no evidence",
                anomaly.rule_id
            );
            for evidence in &anomaly.evidence {
                assert!(!evidence.label.is_empty());
                assert!(!evidence.value.is_empty());
            }
        }
    }

    #[test]
    fn writable_executable_section_reports_permissions_and_header_offset() {
        let info = parse_default(
            &PeBuilder::pe32()
                .with_section("rwx", vec![0x90; 0x200], 0xE000_0020)
                .build(),
        )
        .expect("parse");
        let finding = find(&info, "writable_executable_section");
        assert_eq!(finding.rule_id, "BS-PE-008");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.category, Some(AnomalyCategory::Suspicious));
        assert!(finding.message.contains("writable and executable"));
        assert!(finding.sections.iter().any(|name| name == "rwx"));
        let header = finding
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::SectionHeader)
            .expect("section header evidence");
        assert!(header.file_offset.is_some_and(|offset| offset >= 0x100));
    }

    #[test]
    fn entry_point_outside_sections_is_high_severity_malformed() {
        let mut data = PeBuilder::pe32().build();
        let opt = optional_header(&data);
        write_u32(&mut data, opt + 16, 0x7FFF_0000);
        let info = parse_default(&data).expect("parse");
        let finding = find(&info, "entry_point_outside_sections");
        assert_eq!(finding.rule_id, "BS-PE-005");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.category, Some(AnomalyCategory::Malformed));
        assert_eq!(finding.rva, Some(0x7FFF_0000));
        assert_eq!(finding.file_offset, None);
    }

    #[test]
    fn entry_point_in_non_executable_section_is_reported() {
        let mut data = PeBuilder::pe32()
            .with_section("data2", vec![0x41; 0x200], 0)
            .build();
        let table = section_table(&data);
        let extra_index = 3;
        let extra_rva = u32::from_le_bytes(
            data[table + extra_index * 40 + 12..table + extra_index * 40 + 16]
                .try_into()
                .unwrap(),
        );
        let opt = optional_header(&data);
        write_u32(&mut data, opt + 16, extra_rva);
        let info = parse_default(&data).expect("parse");
        let finding = find(&info, "entry_point_not_executable");
        assert_eq!(finding.rule_id, "BS-PE-004");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.rva, Some(extra_rva));
        assert!(finding.sections.iter().any(|name| name == "data2"));
    }

    #[test]
    fn invalid_alignment_is_malformed_and_has_observed_value() {
        let mut data = PeBuilder::pe32().build();
        let opt = optional_header(&data);
        write_u32(&mut data, opt + 32, 0x1234);
        write_u32(&mut data, opt + 36, 0x1001);
        let info = parse_default(&data).expect("parse");
        let section = find(&info, "invalid_section_alignment");
        assert_eq!(section.rule_id, "BS-PE-014");
        assert_eq!(section.observed.as_deref(), Some("4660"));
        assert!(section.evidence.iter().any(|e| e.value == "4660"));
        let file = find(&info, "invalid_file_alignment");
        assert_eq!(file.rule_id, "BS-PE-013");
        assert_eq!(file.severity, Severity::Medium);
    }

    #[test]
    fn truncated_file_reports_section_beyond_eof() {
        let mut data = PeBuilder::pe32().build();
        data.truncate(data.len() - 0x100);
        let info = parse_default(&data).expect("parse");
        let finding = find(&info, "section_beyond_eof");
        assert_eq!(finding.rule_id, "BS-PE-006");
        assert_eq!(finding.severity, Severity::High);
        let range = finding
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::FileRange)
            .expect("range evidence");
        assert!(range.file_offset.is_some());
    }

    #[test]
    fn overlay_is_informational_and_never_malicious() {
        let info = parse_default(&PeBuilder::pe32().with_overlay(vec![0xAA; 8192]).build())
            .expect("parse");
        let finding = find(&info, "overlay_data");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.category, Some(AnomalyCategory::Informational));
        assert!(finding
            .false_positive_notes
            .contains("never classified as malicious"));
        assert!(!info
            .anomalies
            .iter()
            .any(|a| a.code == "high_entropy_overlay" && a.severity >= Severity::Medium));
    }

    #[test]
    fn high_entropy_is_informational_even_for_rwx_data() {
        let mut bytes = Vec::new();
        for value in 0..=255u16 {
            for _ in 0..8 {
                bytes.push(value as u8);
            }
        }
        let info = parse_default(
            &PeBuilder::pe32()
                .with_section("packed", bytes, 0xE000_0020)
                .build(),
        )
        .expect("parse");
        let entropy = find(&info, "high_entropy_section");
        assert_eq!(entropy.severity, Severity::Info);
        assert_eq!(entropy.rule_id, "BS-PE-010");
        assert!(entropy
            .false_positive_notes
            .contains("never classified as malware"));
    }

    #[test]
    fn overlapping_raw_ranges_report_both_sections() {
        let mut data = PeBuilder::pe32()
            .with_section("one", vec![0x11; 0x200], 0)
            .with_section("two", vec![0x22; 0x200], 0)
            .build();
        let table = section_table(&data);
        let first_raw = u32::from_le_bytes(
            data[table + 3 * 40 + 20..table + 3 * 40 + 24]
                .try_into()
                .unwrap(),
        );

        write_u32(&mut data, table + 4 * 40 + 20, first_raw);
        let info = parse_default(&data).expect("parse");
        let finding = find(&info, "overlapping_sections");
        assert_eq!(finding.rule_id, "BS-PE-012");
        assert_eq!(finding.sections.len(), 2);
        assert!(finding.expected.is_some());
        assert!(finding.observed.is_some());
    }

    #[test]
    fn certificate_boundaries_are_validated() {
        let mut builder = PeBuilder::pe32();
        builder.certificate = true;
        let mut data = builder.build();
        let dirs = optional_header(&data) + 96;
        let bad_offset = (data.len() as u32).saturating_sub(4);
        write_u32(&mut data, dirs + 32, bad_offset);
        write_u32(&mut data, dirs + 36, 0x100);
        let info = parse_default(&data).expect("parse");
        let finding = find(&info, "certificate_table_bounds");
        assert_eq!(finding.rule_id, "BS-PE-029");
        assert_eq!(finding.category, Some(AnomalyCategory::Malformed));
        assert!(finding.observed.as_deref().unwrap_or("").contains("beyond"));
    }

    #[test]
    fn debug_entry_outside_file_is_reported_without_inventing_offsets() {
        let mut data = PeBuilder::pe32().with_pdb(r"C:\build\demo.pdb").build();
        let dirs = optional_header(&data) + 96;
        let debug_rva = u32::from_le_bytes(data[dirs + 48..dirs + 52].try_into().unwrap());
        let table = section_table(&data);
        let mut debug_offset = None;
        for index in 0..3 {
            let va = u32::from_le_bytes(
                data[table + index * 40 + 12..table + index * 40 + 16]
                    .try_into()
                    .unwrap(),
            );
            let raw = u32::from_le_bytes(
                data[table + index * 40 + 20..table + index * 40 + 24]
                    .try_into()
                    .unwrap(),
            );
            let vsize = u32::from_le_bytes(
                data[table + index * 40 + 8..table + index * 40 + 12]
                    .try_into()
                    .unwrap(),
            );
            if debug_rva >= va && debug_rva < va + vsize.max(0x200) {
                debug_offset = Some(raw as usize + (debug_rva - va) as usize);
            }
        }
        let entry = debug_offset.expect("debug entry");
        write_u32(&mut data, entry + 20, 0xFFFF_FFF0);
        write_u32(&mut data, entry + 24, 0xFFFF_FFF0);
        let info = parse_default(&data).expect("parse");
        let finding = find(&info, "debug_entry_invalid");
        assert_eq!(finding.rule_id, "BS-PE-031");
        assert_eq!(finding.category, Some(AnomalyCategory::Malformed));
        assert_eq!(finding.file_offset, None);
    }

    #[test]
    fn issue_counts_are_deterministic() {
        let data = PeBuilder::pe32()
            .with_section("rwx", vec![0x90; 0x200], 0xE000_0020)
            .build();
        let first = parse_default(&data).expect("parse");
        let second = parse_default(&data).expect("parse");
        assert_eq!(codes(&first), codes(&second));
        assert_eq!(first.anomalies, second.anomalies);
    }

    #[test]
    fn header_and_section_field_rules_have_positive_fixtures() {
        let base = PeBuilder::pe32().build();

        let mut zero_entry = base.clone();
        let opt = optional_header(&zero_entry);
        write_u32(&mut zero_entry, opt + 16, 0);
        let info = parse_default(&zero_entry).expect("parse");
        assert_eq!(find(&info, "entry_point_zero").severity, Severity::Medium);

        let mut zero_ts = base.clone();
        let coff_ts = pe_offset(&zero_ts) + 8;
        write_u32(&mut zero_ts, coff_ts, 0);
        let info = parse_default(&zero_ts).expect("parse");
        assert_eq!(find(&info, "zero_timestamp").severity, Severity::Info);

        let mut bad_checksum = base.clone();
        let opt = optional_header(&bad_checksum);
        write_u32(&mut bad_checksum, opt + 64, 0xDEAD_BEEF);
        let info = parse_default(&bad_checksum).expect("parse");
        assert_eq!(find(&info, "checksum_mismatch").severity, Severity::Low);

        let mut short_dirs = base.clone();
        let opt = optional_header(&short_dirs);
        write_u32(&mut short_dirs, opt + 92, 4);
        let info = parse_default(&short_dirs).expect("parse");
        assert_eq!(
            find(&info, "short_data_directory_list").severity,
            Severity::Low
        );

        let mut headers = base.clone();
        let opt = optional_header(&headers);
        write_u32(&mut headers, opt + 60, 0x1000);
        let info = parse_default(&headers).expect("parse");
        assert_eq!(find(&info, "headers_beyond_eof").severity, Severity::High);

        let mut overlap = base.clone();
        let table = section_table(&overlap);
        write_u32(&mut overlap, table + 20, 0x100);
        let info = parse_default(&overlap).expect("parse");
        assert_eq!(
            find(&info, "section_overlaps_headers").severity,
            Severity::Medium
        );

        let mut zero_vsize = base.clone();
        let table = section_table(&zero_vsize);
        write_u32(&mut zero_vsize, table + 8, 0);
        let info = parse_default(&zero_vsize).expect("parse");
        assert_eq!(find(&info, "zero_virtual_size").severity, Severity::Low);
    }

    #[test]
    fn additional_rule_paths_have_positive_fixtures() {
        let mut no_sections = PeBuilder::pe32().build();
        let pe = pe_offset(&no_sections);
        no_sections[pe + 6..pe + 8].copy_from_slice(&0u16.to_le_bytes());
        let info = parse_default(&no_sections).expect("parse");
        assert_eq!(find(&info, "no_sections").rule_id, "BS-PE-001");

        let mut many = PeBuilder::pe32();
        for index in 0..18 {
            many = many.with_section(&format!("s{index}"), vec![0x90; 0x20], 0x6000_0020);
        }
        let info = parse_default(&many.build()).expect("parse");
        assert_eq!(find(&info, "many_sections").rule_id, "BS-PE-002");

        let info = parse_default(
            &PeBuilder::pe32()
                .with_section("bad\u{1}", vec![0x90; 0x20], 0x6000_0020)
                .build(),
        )
        .expect("parse");
        assert_eq!(find(&info, "irregular_section_name").rule_id, "BS-PE-009");

        let mut order = PeBuilder::pe32().build();
        let opt = optional_header(&order);
        write_u32(&mut order, opt + 32, 0x100);
        write_u32(&mut order, opt + 36, 0x200);
        let info = parse_default(&order).expect("parse");
        assert_eq!(find(&info, "alignment_order").rule_id, "BS-PE-015");

        let mut future = PeBuilder::pe32().build();
        let pe = pe_offset(&future);
        write_u32(&mut future, pe + 8, 0x7FFF_FFFF);
        let info = parse_default(&future).expect("parse");
        assert_eq!(find(&info, "future_timestamp").rule_id, "BS-PE-018");

        let mut no_imports = PeBuilder::pe32();
        no_imports.imports.clear();
        let info = parse_default(&no_imports.build()).expect("parse");
        assert_eq!(find(&info, "no_imports").rule_id, "BS-PE-020");

        let info = parse_default(
            &PeBuilder::pe32()
                .with_clr(0)
                .with_import("mscoree.dll", "_CorExeMain")
                .build(),
        )
        .expect("parse");
        assert_eq!(find(&info, "clr_mixed_mode_candidate").rule_id, "BS-PE-023");

        let mut bytes = Vec::new();
        for value in 0..=255u8 {
            for _ in 0..32 {
                bytes.push(value);
            }
        }
        let info = parse_default(&PeBuilder::pe32().with_overlay(bytes).build()).expect("parse");
        assert_eq!(find(&info, "high_entropy_overlay").rule_id, "BS-PE-026");

        let mut certificate = PeBuilder::pe32();
        certificate.certificate = true;
        let mut data = certificate.build();
        let dirs = optional_header(&data) + 96;
        let cert_offset = u32::from_le_bytes(data[dirs + 32..dirs + 36].try_into().unwrap());
        let table = section_table(&data);
        write_u32(&mut data, table + 20, cert_offset);
        write_u32(&mut data, table + 16, 0x40);
        let info = parse_default(&data).expect("parse");
        assert_eq!(
            find(&info, "certificate_overlaps_section").rule_id,
            "BS-PE-030"
        );

        let mut empty_cert = PeBuilder::pe32().build();
        let dirs = optional_header(&empty_cert) + 96;
        write_u32(&mut empty_cert, dirs + 32, 0x1000);
        write_u32(&mut empty_cert, dirs + 36, 0x40);
        let info = parse_default(&empty_cert).expect("parse");
        assert_eq!(find(&info, "empty_certificate_table").rule_id, "BS-PE-024");

        let mut clr = PeBuilder::pe32().with_clr(1).build();
        let dirs = optional_header(&clr) + 96;
        let clr_rva = u32::from_le_bytes(clr[dirs + 14 * 8..dirs + 14 * 8 + 4].try_into().unwrap());
        let clr_offset = rva_to_offset(&clr, clr_rva).expect("clr offset");
        write_u32(&mut clr, clr_offset + 8, 0x7FFF_0000);
        let info = parse_default(&clr).expect("parse");
        assert_eq!(find(&info, "clr_metadata_unmapped").rule_id, "BS-PE-022");
    }

    #[test]
    fn section_count_mismatch_is_reported_from_header_state() {
        let data = PeBuilder::pe32().build();
        let info = parse_default(&data).expect("parse");
        let mut headers = crate::headers::parse_headers(&data, 65_536).expect("headers");
        headers.number_of_sections = 9;
        let findings = collect(&info, &data, &headers);
        assert!(findings
            .iter()
            .any(|anomaly| anomaly.rule_id == "BS-PE-028"));
    }

    fn rva_to_offset(data: &[u8], rva: u32) -> Option<usize> {
        let table = section_table(data);
        let count = u16::from_le_bytes(
            data[pe_offset(data) + 6..pe_offset(data) + 8]
                .try_into()
                .unwrap(),
        );
        for index in 0..count as usize {
            let base = table + index * 40;
            let va = u32::from_le_bytes(data[base + 12..base + 16].try_into().unwrap());
            let vsize = u32::from_le_bytes(data[base + 8..base + 12].try_into().unwrap());
            let raw = u32::from_le_bytes(data[base + 20..base + 24].try_into().unwrap());
            if rva >= va && rva < va + vsize.max(0x200) {
                return Some(raw as usize + (rva - va) as usize);
            }
        }
        None
    }

    #[test]
    fn rule_identifiers_are_unique_and_stable() {
        let info = parse_default(
            &PeBuilder::pe32()
                .with_section("rwx", vec![0u8; 0x800], 0xE000_0020)
                .with_overlay(vec![0xCC; 8192])
                .build(),
        )
        .expect("parse");
        let ids: Vec<&str> = info
            .anomalies
            .iter()
            .map(|anomaly| anomaly.rule_id.as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
        for id in ids {
            assert!(id.starts_with("BS-PE-"), "unexpected rule id {id}");
            assert_eq!(id.len(), 9);
        }
    }
}
