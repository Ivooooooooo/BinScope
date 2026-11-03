use binscope_common::{entropy, hex, Reader};
use goblin::elf::Elf;
use goblin::mach::MachO;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BinaryError {
    #[error("ELF parsing failed: {0}")]
    Elf(String),
    #[error("Mach-O parsing failed: {0}")]
    MachO(String),
    #[error("fat Mach-O container is malformed: {0}")]
    Fat(String),
    #[error("unsupported or truncated file")]
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfProgramHeader {
    pub index: usize,
    pub type_name: String,
    pub flags: String,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfSection {
    pub index: usize,
    pub name: String,
    pub type_name: String,
    pub flags: Vec<String>,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub align: u64,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfInfo {
    pub class: String,
    pub is_64: bool,
    pub endianness: String,
    pub os_abi: String,
    pub abi_version: u8,
    pub object_type: u16,
    pub object_type_name: String,
    pub machine: u16,
    pub machine_name: String,
    pub architecture: String,
    pub bits: u8,
    pub entry_point: u64,
    pub load_base: u64,
    pub flags: u32,
    pub is_pie: bool,
    pub is_shared_object: bool,
    pub interpreter: Option<String>,
    pub soname: Option<String>,
    pub needed_libraries: Vec<String>,
    pub rpaths: Vec<String>,
    pub runpaths: Vec<String>,
    pub program_headers: Vec<ElfProgramHeader>,
    pub sections: Vec<ElfSection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub build_id: Option<String>,
    pub notes: Vec<String>,
}

pub fn parse_elf(data: &[u8]) -> Result<ElfInfo, BinaryError> {
    let elf = Elf::parse(data).map_err(|e| BinaryError::Elf(e.to_string()))?;
    let header = elf.header;
    let (arch, bits) = elf_machine(header.e_machine);
    let load_base = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|p| p.p_vaddr)
        .min()
        .unwrap_or(0);

    let program_headers = elf
        .program_headers
        .iter()
        .enumerate()
        .map(|(index, p)| ElfProgramHeader {
            index,
            type_name: elf_program_type(p.p_type).to_string(),
            flags: elf_program_flags(p.p_flags),
            offset: p.p_offset,
            virtual_address: p.p_vaddr,
            physical_address: p.p_paddr,
            file_size: p.p_filesz,
            memory_size: p.p_memsz,
            align: p.p_align,
        })
        .collect();

    let mut notes = Vec::new();
    let mut sections = Vec::new();
    for (index, sh) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let start = sh.sh_offset as usize;
        let end = start.saturating_add(sh.sh_size as usize);
        let raw = data.get(start..end).unwrap_or(&[]);
        let executable = sh.sh_flags & 0x4 != 0;
        let writable = sh.sh_flags & 0x1 != 0;
        let alloc = sh.sh_flags & 0x2 != 0;
        let mut flags = Vec::new();
        if writable {
            flags.push("WRITE".to_string());
        }
        if alloc {
            flags.push("ALLOC".to_string());
        }
        if executable {
            flags.push("EXECINSTR".to_string());
        }
        if sh.sh_flags & 0x10 != 0 {
            flags.push("MERGE".to_string());
        }
        if sh.sh_flags & 0x20 != 0 {
            flags.push("STRINGS".to_string());
        }
        if sh.sh_flags & 0x200 != 0 {
            flags.push("TLS".to_string());
        }
        sections.push(ElfSection {
            index,
            name,
            type_name: elf_section_type(sh.sh_type).to_string(),
            flags,
            address: sh.sh_addr,
            offset: sh.sh_offset,
            size: sh.sh_size,
            align: sh.sh_addralign,
            entropy: round3(entropy(raw)),
            executable,
            writable,
        });
    }

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for sym in elf.dynsyms.iter() {
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if sym.is_import() {
            imports.push(name.to_string());
        } else if sym.st_value != 0 && sym.st_shndx != 0 {
            exports.push(name.to_string());
        }
        if imports.len() + exports.len() > 100_000 {
            notes.push("dynamic symbol limit reached".into());
            break;
        }
    }
    imports.sort_unstable();
    imports.dedup();
    exports.sort_unstable();
    exports.dedup();

    let build_id = find_gnu_build_id(data, &sections);
    let object_type_name = elf_object_type(header.e_type).to_string();
    let is_shared_object = header.e_type == 3;
    let is_pie = is_shared_object && elf.interpreter.is_some();

    Ok(ElfInfo {
        class: if elf.is_64 { "ELF64" } else { "ELF32" }.to_string(),
        is_64: elf.is_64,
        endianness: if elf.little_endian {
            "little-endian".to_string()
        } else {
            "big-endian".to_string()
        },
        os_abi: elf_os_abi(header.e_ident[7]).to_string(),
        abi_version: header.e_ident[8],
        object_type: header.e_type,
        object_type_name,
        machine: header.e_machine,
        machine_name: format!("{:#06x}", header.e_machine),
        architecture: arch.to_string(),
        bits,
        entry_point: elf.entry,
        load_base,
        flags: header.e_flags,
        is_pie,
        is_shared_object,
        interpreter: elf.interpreter.map(|s| s.to_string()),
        soname: elf.soname.map(|s| s.to_string()),
        needed_libraries: elf.libraries.iter().map(|s| s.to_string()).collect(),
        rpaths: elf.rpaths.iter().map(|s| s.to_string()).collect(),
        runpaths: elf.runpaths.iter().map(|s| s.to_string()).collect(),
        program_headers,
        sections,
        imports,
        exports,
        build_id,
        notes,
    })
}

fn elf_machine(machine: u16) -> (&'static str, u8) {
    match machine {
        0x03 => ("x86", 32),
        0x3e => ("x86-64", 64),
        0x28 => ("ARM", 32),
        0xb7 => ("ARM64", 64),
        0x08 => ("MIPS", 32),
        0x14 => ("PowerPC", 32),
        0x15 => ("PowerPC64", 64),
        0x16 => ("S390", 32),
        0x2b => ("SPARC64", 64),
        0xf3 => ("RISC-V", 64),
        _ => ("unknown", 0),
    }
}

fn elf_object_type(t: u16) -> &'static str {
    match t {
        0 => "ET_NONE",
        1 => "ET_REL (relocatable object)",
        2 => "ET_EXEC (executable)",
        3 => "ET_DYN (shared object / PIE)",
        4 => "ET_CORE (core dump)",
        _ => "Unknown ELF type",
    }
}

fn elf_os_abi(abi: u8) -> &'static str {
    match abi {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        7 => "AIX",
        8 => "IRIX",
        9 => "FreeBSD",
        12 => "OpenBSD",
        64 => "ARM EABI",
        97 => "ARM",
        _ => "Unknown ABI",
    }
}

fn elf_program_type(t: u32) -> &'static str {
    use goblin::elf::program_header::*;
    match t {
        PT_NULL => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        PT_DYNAMIC => "PT_DYNAMIC",
        PT_INTERP => "PT_INTERP",
        PT_NOTE => "PT_NOTE",
        PT_SHLIB => "PT_SHLIB",
        PT_PHDR => "PT_PHDR",
        PT_TLS => "PT_TLS",
        PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
        PT_GNU_STACK => "PT_GNU_STACK",
        PT_GNU_RELRO => "PT_GNU_RELRO",
        _ => "PT_UNKNOWN",
    }
}

fn elf_program_flags(flags: u32) -> String {
    format!(
        "{}{}{}",
        if flags & 4 != 0 { 'R' } else { '-' },
        if flags & 2 != 0 { 'W' } else { '-' },
        if flags & 1 != 0 { 'X' } else { '-' }
    )
}

fn elf_section_type(t: u32) -> &'static str {
    use goblin::elf::section_header::*;
    match t {
        SHT_NULL => "SHT_NULL",
        SHT_PROGBITS => "SHT_PROGBITS",
        SHT_SYMTAB => "SHT_SYMTAB",
        SHT_STRTAB => "SHT_STRTAB",
        SHT_RELA => "SHT_RELA",
        SHT_HASH => "SHT_HASH",
        SHT_DYNAMIC => "SHT_DYNAMIC",
        SHT_NOTE => "SHT_NOTE",
        SHT_NOBITS => "SHT_NOBITS",
        SHT_REL => "SHT_REL",
        SHT_SHLIB => "SHT_SHLIB",
        SHT_DYNSYM => "SHT_DYNSYM",
        SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
        SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
        SHT_GNU_HASH => "SHT_GNU_HASH",
        SHT_GNU_VERDEF => "SHT_GNU_verdef",
        SHT_GNU_VERNEED => "SHT_GNU_verneed",
        _ => "SHT_UNKNOWN",
    }
}

fn find_gnu_build_id(data: &[u8], sections: &[ElfSection]) -> Option<String> {
    let section = sections.iter().find(|s| s.name == ".note.gnu.build-id")?;
    let start = section.offset as usize;
    let end = start.checked_add(section.size as usize)?;
    let bytes = data.get(start..end)?;
    let r = Reader::new(bytes);
    let namesz = r.u32(0, "build-id namesz").ok()? as usize;
    let descsz = r.u32(4, "build-id descsz").ok()? as usize;
    let note_type = r.u32(8, "build-id type").ok()?;
    if note_type != 3 || namesz > 64 || descsz > 64 {
        return None;
    }
    let name_start = 12usize;
    let name = bytes.get(name_start..name_start + namesz)?;
    if !name.starts_with(b"GNU") {
        return None;
    }
    let desc_start = name_start + ((namesz + 3) & !3);
    let desc = bytes.get(desc_start..desc_start + descsz)?;
    Some(hex(desc))
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachSegment {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protections: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachSliceInfo {
    pub architecture: String,
    pub bits: u8,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub file_type_name: String,
    pub entry_point: u64,
    pub is_64: bool,
    pub segments: Vec<MachSegment>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub libraries: Vec<String>,
    pub rpaths: Vec<String>,
    pub install_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOInfo {
    pub is_fat: bool,
    pub slice_count: usize,
    pub slices: Vec<MachSliceInfo>,
    pub notes: Vec<String>,
}

pub fn parse_macho(data: &[u8]) -> Result<MachOInfo, BinaryError> {
    let magic = data.get(..4).ok_or(BinaryError::Unsupported)?;
    let fat = matches!(
        magic,
        [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    );
    let mut notes = Vec::new();
    let mut slices = Vec::new();
    if fat {
        let is_big = magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xca, 0xfe, 0xba, 0xbf];
        let is_64_fat = magic == [0xca, 0xfe, 0xba, 0xbf] || magic == [0xbf, 0xba, 0xfe, 0xca];
        let read_u32 = |off: usize| -> Option<u32> {
            let b = data.get(off..off + 4)?;
            Some(if is_big {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            })
        };
        let read_u64 = |off: usize| -> Option<u64> {
            let b = data.get(off..off + 8)?;
            Some(if is_big {
                u64::from_be_bytes(b.try_into().ok()?)
            } else {
                u64::from_le_bytes(b.try_into().ok()?)
            })
        };
        let nfat = read_u32(4).ok_or_else(|| BinaryError::Fat("missing nfat_arch".into()))?;
        if nfat == 0 || nfat > 64 {
            return Err(BinaryError::Fat(format!(
                "implausible architecture count {nfat}"
            )));
        }
        let entry_size = if is_64_fat { 32 } else { 20 };
        for i in 0..nfat as usize {
            let base = 8 + i * entry_size;
            let (cputype, _cpusubtype, offset, size) = if is_64_fat {
                (
                    read_u32(base).unwrap_or(0),
                    read_u32(base + 4).unwrap_or(0),
                    read_u64(base + 8).unwrap_or(0),
                    read_u64(base + 16).unwrap_or(0),
                )
            } else {
                (
                    read_u32(base).unwrap_or(0),
                    read_u32(base + 4).unwrap_or(0),
                    read_u32(base + 8).unwrap_or(0) as u64,
                    read_u32(base + 12).unwrap_or(0) as u64,
                )
            };
            if size == 0 || offset.saturating_add(size) > data.len() as u64 {
                notes.push(format!(
                    "fat architecture {i} (cputype {cputype:#x}) points outside the file"
                ));
                continue;
            }
            let slice = &data[offset as usize..(offset + size) as usize];
            match MachO::parse(data, offset as usize) {
                Ok(binary) => slices.push(mach_slice(&binary)),
                Err(e) => {
                    let _ = slice;
                    notes.push(format!("fat architecture {i} could not be parsed: {e}"));
                }
            }
        }
        if slices.is_empty() {
            return Err(BinaryError::Fat("no architecture could be parsed".into()));
        }
    } else {
        let binary = MachO::parse(data, 0).map_err(|e| BinaryError::MachO(e.to_string()))?;
        slices.push(mach_slice(&binary));
    }
    Ok(MachOInfo {
        is_fat: fat,
        slice_count: slices.len(),
        slices,
        notes,
    })
}

fn mach_slice(binary: &MachO<'_>) -> MachSliceInfo {
    let header = binary.header;
    let (arch, bits) = macho_cpu(header.cputype);
    let segments = binary
        .segments
        .iter()
        .map(|seg| MachSegment {
            name: cstr16(&seg.segname),
            virtual_address: seg.vmaddr,
            virtual_size: seg.vmsize,
            file_offset: seg.fileoff,
            file_size: seg.filesize,
            protections: format!(
                "{}{}{}",
                if seg.initprot & 1 != 0 { 'R' } else { '-' },
                if seg.initprot & 2 != 0 { 'W' } else { '-' },
                if seg.initprot & 4 != 0 { 'X' } else { '-' }
            ),
        })
        .collect();
    let mut imports: Vec<String> = binary
        .imports()
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    let mut exports: Vec<String> = binary
        .exports()
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    imports.sort_unstable();
    imports.dedup();
    exports.sort_unstable();
    exports.dedup();
    MachSliceInfo {
        architecture: arch.to_string(),
        bits,
        cpu_type: header.cputype,
        cpu_subtype: header.cpusubtype,
        file_type: header.filetype,
        file_type_name: macho_file_type(header.filetype).to_string(),
        entry_point: binary.entry,
        is_64: binary.is_64,
        segments,
        imports,
        exports,
        libraries: binary.libs.iter().map(|s| s.to_string()).collect(),
        rpaths: binary.rpaths.iter().map(|s| s.to_string()).collect(),
        install_name: binary.name.map(|s| s.to_string()),
    }
}

fn cstr16(bytes: &[u8; 16]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn macho_cpu(cpu: u32) -> (&'static str, u8) {
    match cpu {
        7 => ("x86", 32),
        0x0100_0007 => ("x86-64", 64),
        12 => ("ARM", 32),
        0x0100_000C => ("ARM64", 64),
        18 => ("PowerPC", 32),
        0x0100_0012 => ("PowerPC64", 64),
        _ => ("unknown", 0),
    }
}

fn macho_file_type(t: u32) -> &'static str {
    match t {
        1 => "MH_OBJECT",
        2 => "MH_EXECUTE",
        3 => "MH_FVMLIB",
        4 => "MH_CORE",
        5 => "MH_PRELOAD",
        6 => "MH_DYLIB",
        7 => "MH_DYLINKER",
        8 => "MH_BUNDLE",
        9 => "MH_DYLIB_STUB",
        10 => "MH_DSYM",
        11 => "MH_KEXT_BUNDLE",
        _ => "Unknown Mach-O type",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf64() -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;

        data[5] = 1;

        data[6] = 1;

        data[7] = 3;

        data[16..18].copy_from_slice(&2u16.to_le_bytes());

        data[18..20].copy_from_slice(&0x3eu16.to_le_bytes());

        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes());
        data[58..60].copy_from_slice(&64u16.to_le_bytes());
        data
    }

    #[test]
    fn parses_minimal_elf64() {
        let info = parse_elf(&minimal_elf64()).expect("ELF");
        assert_eq!(info.class, "ELF64");
        assert_eq!(info.architecture, "x86-64");
        assert_eq!(info.bits, 64);
        assert_eq!(info.entry_point, 0x401000);
        assert_eq!(info.os_abi, "Linux");
        assert!(info.object_type_name.contains("ET_EXEC"));
        assert!(info.sections.is_empty());
    }

    #[test]
    fn rejects_truncated_elf() {
        assert!(parse_elf(b"\x7fELF").is_err());
        assert!(parse_elf(b"MZ").is_err());
    }

    fn minimal_macho64() -> Vec<u8> {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        data[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());

        data[8..12].copy_from_slice(&3u32.to_le_bytes());

        data[12..16].copy_from_slice(&2u32.to_le_bytes());

        data[16..20].copy_from_slice(&0u32.to_le_bytes());

        data[20..24].copy_from_slice(&0u32.to_le_bytes());

        data[24..28].copy_from_slice(&0u32.to_le_bytes());

        data
    }

    #[test]
    fn parses_thin_macho() {
        let info = parse_macho(&minimal_macho64()).expect("Mach-O");
        assert!(!info.is_fat);
        assert_eq!(info.slices.len(), 1);
        assert_eq!(info.slices[0].architecture, "x86-64");
        assert_eq!(info.slices[0].file_type_name, "MH_EXECUTE");
    }

    #[test]
    fn parses_fat_macho_with_two_slices() {
        let thin = minimal_macho64();
        let mut fat = vec![0u8; 0x200];
        fat[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        for (i, offset) in [0x100usize, 0x180usize].iter().enumerate() {
            let base = 8 + i * 20;
            fat[base..base + 4].copy_from_slice(&0x0100_0007u32.to_be_bytes());
            fat[base + 4..base + 8].copy_from_slice(&3u32.to_be_bytes());
            fat[base + 8..base + 12].copy_from_slice(&(*offset as u32).to_be_bytes());
            fat[base + 12..base + 16].copy_from_slice(&(thin.len() as u32).to_be_bytes());
            fat[base + 16..base + 20].copy_from_slice(&0u32.to_be_bytes());
            fat[*offset..*offset + thin.len()].copy_from_slice(&thin);
        }
        let info = parse_macho(&fat).expect("fat Mach-O");
        assert!(info.is_fat);
        assert_eq!(info.slices.len(), 2);
        assert!(info.slices.iter().all(|s| s.architecture == "x86-64"));
    }

    #[test]
    fn rejects_invalid_fat_header() {
        let mut fat = vec![0u8; 32];
        fat[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        fat[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse_macho(&fat).is_err());
    }
}
