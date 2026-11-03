use binscope_common::Reader;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatKind {
    Pe,

    DosMz,

    Ne,

    Le,
    Elf,
    MachO,
    MachOFat,
    Zip,
    SevenZip,
    Rar,
    Gzip,
    Pdf,
    Ole,
    Script,
    Unknown,
}

impl FormatKind {
    pub fn label(self) -> &'static str {
        match self {
            FormatKind::Pe => "PE",
            FormatKind::DosMz => "DOS MZ",
            FormatKind::Ne => "NE",
            FormatKind::Le => "LE/LX",
            FormatKind::Elf => "ELF",
            FormatKind::MachO => "Mach-O",
            FormatKind::MachOFat => "Mach-O (fat/universal)",
            FormatKind::Zip => "ZIP",
            FormatKind::SevenZip => "7-Zip",
            FormatKind::Rar => "RAR",
            FormatKind::Gzip => "GZip",
            FormatKind::Pdf => "PDF",
            FormatKind::Ole => "OLE/CFB",
            FormatKind::Script => "Script",
            FormatKind::Unknown => "Unknown",
        }
    }

    pub fn is_supported(self) -> bool {
        matches!(
            self,
            FormatKind::Pe | FormatKind::Elf | FormatKind::MachO | FormatKind::MachOFat
        )
    }

    pub fn is_executable_container(self) -> bool {
        matches!(
            self,
            FormatKind::Pe
                | FormatKind::DosMz
                | FormatKind::Ne
                | FormatKind::Le
                | FormatKind::Elf
                | FormatKind::MachO
                | FormatKind::MachOFat
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatDetection {
    pub kind: FormatKind,
    pub label: String,
    pub description: String,

    pub confidence: u8,
    pub evidence: Vec<String>,
    pub supported: bool,
}

impl FormatDetection {
    fn new(
        kind: FormatKind,
        description: impl Into<String>,
        confidence: u8,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            kind,
            label: kind.label().to_string(),
            description: description.into(),
            confidence,
            evidence,
            supported: kind.is_supported(),
        }
    }
}

pub fn detect(data: &[u8]) -> FormatDetection {
    if data.is_empty() {
        return FormatDetection::new(
            FormatKind::Unknown,
            "Empty file (0 bytes)",
            100,
            vec!["File size is zero".into()],
        );
    }

    if data.starts_with(b"MZ") {
        return detect_dos_or_pe(data);
    }
    if data.starts_with(b"\x7fELF") {
        return detect_elf(data);
    }
    if let Some(macho) = detect_mach_o(data) {
        return macho;
    }
    if data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
    {
        return FormatDetection::new(
            FormatKind::Zip,
            "ZIP archive (also used by JAR, APK, DOCX, XLSX, NuGet, ...)",
            95,
            vec!["ZIP local file header signature".into()],
        );
    }
    if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return FormatDetection::new(
            FormatKind::SevenZip,
            "7-Zip archive",
            100,
            vec!["7-Zip signature 37 7A BC AF 27 1C".into()],
        );
    }
    if data.starts_with(b"Rar!\x1a\x07") {
        return FormatDetection::new(
            FormatKind::Rar,
            "RAR archive",
            100,
            vec!["RAR signature".into()],
        );
    }
    if data.starts_with(b"\x1f\x8b") {
        return FormatDetection::new(
            FormatKind::Gzip,
            "GZip compressed stream",
            100,
            vec!["GZip magic 1F 8B".into()],
        );
    }
    if data.starts_with(b"%PDF-") {
        return FormatDetection::new(
            FormatKind::Pdf,
            "PDF document",
            100,
            vec!["PDF header".into()],
        );
    }
    if data.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return FormatDetection::new(
            FormatKind::Ole,
            "OLE compound file (legacy Office, MSI, ...)",
            100,
            vec!["OLE/CFB signature D0 CF 11 E0 A1 B1 1A E1".into()],
        );
    }
    if let Some(script) = detect_script(data) {
        return script;
    }

    FormatDetection::new(
        FormatKind::Unknown,
        "Unknown or unsupported format",
        20,
        vec!["No known magic signature matched".into()],
    )
}

fn detect_dos_or_pe(data: &[u8]) -> FormatDetection {
    let mut evidence = vec!["DOS header signature 'MZ'".to_string()];
    let reader = Reader::new(data);
    let e_lfanew = match reader.u32(0x3c, "DOS e_lfanew") {
        Ok(v) => v as u64,
        Err(_) => {
            return FormatDetection::new(
                FormatKind::DosMz,
                "DOS MZ executable truncated before e_lfanew",
                60,
                evidence,
            )
        }
    };
    if e_lfanew >= data.len() as u64 {
        evidence.push(format!(
            "e_lfanew {e_lfanew:#x} points beyond the buffered data (file may be truncated)"
        ));
        return FormatDetection::new(
            FormatKind::DosMz,
            "DOS MZ executable (PE header unavailable or beyond EOF)",
            55,
            evidence,
        );
    }
    match reader.bytes(e_lfanew, 4, "NT signature") {
        Ok(b"PE\0\0") => {
            evidence.push(format!("PE signature at file offset {e_lfanew:#x}"));
            FormatDetection::new(
                FormatKind::Pe,
                "Windows Portable Executable (PE)",
                100,
                evidence,
            )
        }
        Ok(b"NE\0\0") => {
            evidence.push(format!("NE signature at file offset {e_lfanew:#x}"));
            FormatDetection::new(FormatKind::Ne, "16-bit New Executable (NE)", 95, evidence)
        }
        Ok(b"LE\0\0") | Ok(b"LX\0\0") => {
            evidence.push(format!("LE/LX signature at file offset {e_lfanew:#x}"));
            FormatDetection::new(FormatKind::Le, "Linear Executable (LE/LX)", 95, evidence)
        }
        Ok(other) => {
            evidence.push(format!(
                "Bytes at e_lfanew are {:02X} {:02X} {:02X} {:02X}, not a PE signature",
                other[0], other[1], other[2], other[3]
            ));
            FormatDetection::new(
                FormatKind::DosMz,
                "DOS MZ executable with unrecognized header",
                65,
                evidence,
            )
        }
        Err(_) => {
            evidence.push("File ends before the NT signature".into());
            FormatDetection::new(
                FormatKind::DosMz,
                "Truncated DOS MZ executable",
                55,
                evidence,
            )
        }
    }
}

fn detect_elf(data: &[u8]) -> FormatDetection {
    let mut evidence = vec!["ELF magic 7F 45 4C 46".to_string()];
    let (bits, class) = match data.get(4) {
        Some(1) => (32, "ELF32"),
        Some(2) => (64, "ELF64"),
        _ => (0, "unknown ELF class"),
    };
    let endian = match data.get(5) {
        Some(1) => "little-endian",
        Some(2) => "big-endian",
        _ => "unknown endianness",
    };
    if !class.starts_with("unknown") {
        evidence.push(format!("{class}, {endian}, {bits}-bit"));
    }
    FormatDetection::new(
        FormatKind::Elf,
        format!("ELF executable ({class}, {endian}, {bits}-bit)"),
        100,
        evidence,
    )
}

fn detect_mach_o(data: &[u8]) -> Option<FormatDetection> {
    let magic = data.get(..4)?;
    match magic {
        [0xfe, 0xed, 0xfa, 0xce] => Some(FormatDetection::new(
            FormatKind::MachO,
            "Mach-O 32-bit (big-endian magic)",
            100,
            vec!["Mach-O magic FE ED FA CE".into()],
        )),
        [0xce, 0xfa, 0xed, 0xfe] => Some(FormatDetection::new(
            FormatKind::MachO,
            "Mach-O 32-bit (little-endian)",
            100,
            vec!["Mach-O magic CE FA ED FE".into()],
        )),
        [0xfe, 0xed, 0xfa, 0xcf] => Some(FormatDetection::new(
            FormatKind::MachO,
            "Mach-O 64-bit (big-endian magic)",
            100,
            vec!["Mach-O magic FE ED FA CF".into()],
        )),
        [0xcf, 0xfa, 0xed, 0xfe] => Some(FormatDetection::new(
            FormatKind::MachO,
            "Mach-O 64-bit (little-endian)",
            100,
            vec!["Mach-O magic CF FA ED FE".into()],
        )),
        [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] => {
            let be = magic == [0xca, 0xfe, 0xba, 0xbe];
            let read_u32 = |off: usize| -> Option<u32> {
                let b = data.get(off..off + 4)?;
                Some(if be {
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
                } else {
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                })
            };
            let nfat = read_u32(4)?;

            let cputype = read_u32(8)?;
            let known_cputype = matches!(
                cputype,
                7 | 12 | 18 | 0x0100_0007 | 0x0100_000C | 0x0100_0012 | 0x0200_000C
            );
            if (1..=32).contains(&nfat) && known_cputype {
                Some(FormatDetection::new(
                    FormatKind::MachOFat,
                    format!("Mach-O universal binary with {nfat} architectures"),
                    95,
                    vec![format!(
                        "Fat Mach-O magic, nfat_arch={nfat}, first cputype={cputype:#x}"
                    )],
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn detect_script(data: &[u8]) -> Option<FormatDetection> {
    let head = &data[..data.len().min(512)];
    let text = String::from_utf8_lossy(head);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    let (desc, sig) = if trimmed.starts_with("#!") {
        ("Unix shebang script", "#! interpreter line")
    } else if trimmed.starts_with("<!DOCTYPE")
        || trimmed.starts_with("<html")
        || trimmed.starts_with("<HTML")
    {
        ("HTML document", "HTML doctype/tag")
    } else if trimmed.starts_with("<?xml") {
        ("XML document", "XML declaration")
    } else if trimmed.starts_with("powershell")
        || trimmed.to_ascii_lowercase().contains("write-host")
    {
        ("Possible PowerShell script", "PowerShell keywords")
    } else {
        return None;
    };
    Some(FormatDetection::new(
        FormatKind::Script,
        desc,
        60,
        vec![sig.into()],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data
    }

    #[test]
    fn detects_pe() {
        let d = detect(&minimal_pe());
        assert_eq!(d.kind, FormatKind::Pe);
        assert_eq!(d.confidence, 100);
        assert!(d.supported);
    }

    #[test]
    fn detects_truncated_pe_as_dos() {
        let d = detect(b"MZ\x90\x00");
        assert_eq!(d.kind, FormatKind::DosMz);
        assert!(d.confidence < 100);
    }

    #[test]
    fn detects_elf32_and_elf64() {
        let d = detect(b"\x7fELF\x01\x01\x01");
        assert_eq!(d.kind, FormatKind::Elf);
        assert_eq!(d.confidence, 100);
        assert!(d.description.contains("32-bit"));
        let d = detect(b"\x7fELF\x02\x01\x01");
        assert!(d.description.contains("64-bit"));
    }

    #[test]
    fn detects_mach_o_variants() {
        assert_eq!(
            detect(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).kind,
            FormatKind::MachO
        );
        let mut fat = vec![0xca, 0xfe, 0xba, 0xbe];
        fat.extend(2u32.to_be_bytes());
        fat.extend(0x0100_0007u32.to_be_bytes());
        assert_eq!(detect(&fat).kind, FormatKind::MachOFat);

        let mut class = vec![0xca, 0xfe, 0xba, 0xbe];
        class.extend(0u16.to_be_bytes());
        class.extend(52u16.to_be_bytes());
        assert_eq!(detect(&class).kind, FormatKind::Unknown);
    }

    #[test]
    fn detects_other_containers() {
        assert_eq!(detect(b"PK\x03\x04rest").kind, FormatKind::Zip);
        assert_eq!(detect(b"7z\xbc\xaf\x27\x1crest").kind, FormatKind::SevenZip);
        assert_eq!(detect(b"%PDF-1.7").kind, FormatKind::Pdf);
        assert_eq!(detect(b"#!/bin/sh\necho hi").kind, FormatKind::Script);
        assert_eq!(detect(b"").kind, FormatKind::Unknown);
    }

    #[test]
    fn ne_signature_is_not_reported_as_pe() {
        let mut data = vec![0u8; 0x100];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        data[0x40..0x42].copy_from_slice(b"NE");
        let d = detect(&data);
        assert_eq!(d.kind, FormatKind::Ne);
        assert!(!d.supported);
    }
}
