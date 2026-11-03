use crate::types::{
    machine_info, DataDirectoryInfo, ParseError, SectionInfo, DATA_DIRECTORY_NAMES,
};
use binscope_common::{entropy, Reader};

#[derive(Clone, Debug)]
pub struct RawSection {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug)]
pub struct Headers {
    pub pe_offset: u64,
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
    pub is_64: bool,
    pub magic: u16,
    pub linker_major: u8,
    pub linker_minor: u8,
    pub entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub os_major: u16,
    pub os_minor: u16,
    pub image_major: u16,
    pub image_minor: u16,
    pub subsystem_major: u16,
    pub subsystem_minor: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub number_of_rva_and_sizes: u32,
    pub directories: Vec<(usize, u32, u32)>,
    pub sections: Vec<RawSection>,
    pub section_table_offset: u64,
    pub optional_header_offset: u64,
    pub notes: Vec<String>,
}

pub fn parse_headers(data: &[u8], max_entries: usize) -> Result<Headers, ParseError> {
    let r = Reader::new(data);
    if data.len() < 0x40 {
        return Err(ParseError::TooSmall);
    }
    if r.u16(0, "DOS header").map_err(|_| ParseError::TooSmall)? != 0x5a4d {
        return Err(ParseError::InvalidDosHeader);
    }
    let pe_offset = r
        .u32(0x3c, "DOS e_lfanew")
        .map_err(|_| ParseError::InvalidDosHeader)? as u64;
    let sig = r
        .bytes(pe_offset, 4, "NT signature")
        .map_err(|_| ParseError::InvalidPeHeader)?;
    if sig != b"PE\0\0" {
        return Err(ParseError::InvalidPeHeader);
    }
    let file_header = pe_offset + 4;
    let machine = r
        .u16(file_header, "COFF machine")
        .map_err(|_| ParseError::InvalidPeHeader)?;
    let number_of_sections = r
        .u16(file_header + 2, "COFF section count")
        .map_err(|_| ParseError::InvalidPeHeader)?;
    let time_date_stamp = r
        .u32(file_header + 4, "COFF timestamp")
        .map_err(|_| ParseError::InvalidPeHeader)?;
    let pointer_to_symbol_table = r.u32(file_header + 8, "COFF symbol table").unwrap_or(0);
    let number_of_symbols = r.u32(file_header + 12, "COFF symbol count").unwrap_or(0);
    let size_of_optional_header = r
        .u16(file_header + 16, "COFF optional header size")
        .map_err(|_| ParseError::InvalidPeHeader)?;
    let characteristics = r
        .u16(file_header + 18, "COFF characteristics")
        .map_err(|_| ParseError::InvalidPeHeader)?;

    if number_of_sections as usize > max_entries || number_of_sections as usize > 96 {
        return Err(ParseError::TooManySections);
    }

    let optional_header_offset = file_header + 20;
    let magic = r
        .u16(optional_header_offset, "optional header magic")
        .map_err(|_| ParseError::InvalidOptionalHeader)?;
    let (is_64, min_optional_size) = match magic {
        0x10b => (false, 96usize),
        0x20b => (true, 112usize),
        0x107 => (false, 96usize),

        _ => return Err(ParseError::InvalidOptionalHeader),
    };
    if (size_of_optional_header as usize) < min_optional_size {
        return Err(ParseError::InvalidOptionalHeader);
    }

    let opt = optional_header_offset;
    let linker_major = r
        .u8(opt + 2, "linker version")
        .map_err(|_| ParseError::InvalidOptionalHeader)?;
    let linker_minor = r
        .u8(opt + 3, "linker version")
        .map_err(|_| ParseError::InvalidOptionalHeader)?;
    let entry_point = r
        .u32(opt + 16, "entry point")
        .map_err(|_| ParseError::InvalidOptionalHeader)?;
    let (image_base, dirs_offset) = if is_64 {
        (
            r.u64(opt + 24, "image base")
                .map_err(|_| ParseError::InvalidOptionalHeader)?,
            opt + 112,
        )
    } else {
        (
            r.u32(opt + 28, "image base")
                .map_err(|_| ParseError::InvalidOptionalHeader)? as u64,
            opt + 96,
        )
    };
    let section_alignment = r
        .u32(opt + 32, "section alignment")
        .map_err(|_| ParseError::InvalidOptionalHeader)?;
    let file_alignment = r
        .u32(opt + 36, "file alignment")
        .map_err(|_| ParseError::InvalidOptionalHeader)?;
    let os_major = r.u16(opt + 40, "OS version").unwrap_or(0);
    let os_minor = r.u16(opt + 42, "OS version").unwrap_or(0);
    let image_major = r.u16(opt + 44, "image version").unwrap_or(0);
    let image_minor = r.u16(opt + 46, "image version").unwrap_or(0);
    let subsystem_major = r.u16(opt + 48, "subsystem version").unwrap_or(0);
    let subsystem_minor = r.u16(opt + 50, "subsystem version").unwrap_or(0);
    let size_of_image = r.u32(opt + 56, "size of image").unwrap_or(0);
    let size_of_headers = r.u32(opt + 60, "size of headers").unwrap_or(0);
    let checksum = r.u32(opt + 64, "checksum").unwrap_or(0);
    let subsystem = r.u16(opt + 68, "subsystem").unwrap_or(0);
    let dll_characteristics = r.u16(opt + 70, "DLL characteristics").unwrap_or(0);
    let number_of_rva_and_sizes = if is_64 {
        r.u32(opt + 108, "RVA count").unwrap_or(0)
    } else {
        r.u32(opt + 92, "RVA count").unwrap_or(0)
    };

    let mut notes = Vec::new();
    let declared_dirs = number_of_rva_and_sizes.min(16);
    if number_of_rva_and_sizes > 16 {
        notes.push(format!(
            "NumberOfRvaAndSizes is {number_of_rva_and_sizes}; only the 16 specified directories are read"
        ));
    }
    let available = size_of_optional_header as usize - min_optional_size;
    let readable_dirs = (available / 8).min(declared_dirs as usize);
    if (declared_dirs as usize) > readable_dirs {
        notes.push(format!(
            "Optional header declares {declared_dirs} data directories but only {readable_dirs} fit in SizeOfOptionalHeader"
        ));
    }
    let mut directories = Vec::new();
    for i in 0..readable_dirs {
        let off = dirs_offset + (i as u64) * 8;
        let rva = r
            .u32(off, "data directory RVA")
            .map_err(|_| ParseError::InvalidOptionalHeader)?;
        let size = r
            .u32(off + 4, "data directory size")
            .map_err(|_| ParseError::InvalidOptionalHeader)?;
        directories.push((i, rva, size));
    }

    let section_table_offset = optional_header_offset + size_of_optional_header as u64;
    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections as usize {
        let off = section_table_offset + (i as u64) * 40;
        let name_slice = r
            .bytes(off, 8, "section name")
            .map_err(|_| ParseError::InvalidPeHeader)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(name_slice);
        sections.push(RawSection {
            name,
            virtual_size: r
                .u32(off + 8, "section virtual size")
                .map_err(|_| ParseError::InvalidPeHeader)?,
            virtual_address: r
                .u32(off + 12, "section RVA")
                .map_err(|_| ParseError::InvalidPeHeader)?,
            raw_size: r
                .u32(off + 16, "section raw size")
                .map_err(|_| ParseError::InvalidPeHeader)?,
            raw_offset: r
                .u32(off + 20, "section raw offset")
                .map_err(|_| ParseError::InvalidPeHeader)?,
            characteristics: r
                .u32(off + 36, "section characteristics")
                .map_err(|_| ParseError::InvalidPeHeader)?,
        });
    }

    Ok(Headers {
        pe_offset,
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
        is_64,
        magic,
        linker_major,
        linker_minor,
        entry_point,
        image_base,
        section_alignment,
        file_alignment,
        os_major,
        os_minor,
        image_major,
        image_minor,
        subsystem_major,
        subsystem_minor,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
        number_of_rva_and_sizes,
        directories,
        sections,
        section_table_offset,
        optional_header_offset,
        notes,
    })
}

pub fn build_sections(headers: &Headers, data: &[u8]) -> Vec<SectionInfo> {
    headers
        .sections
        .iter()
        .enumerate()
        .map(|(index, s)| {
            let name_end = s.name.iter().position(|&b| b == 0).unwrap_or(8);
            let name_bytes = &s.name[..name_end];
            let name_is_irregular = !name_bytes.iter().all(|b| (0x20..=0x7e).contains(b));
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            let raw_start = s.raw_offset as usize;
            let raw_end = raw_start.saturating_add(s.raw_size as usize);
            let raw = data.get(raw_start..raw_end).unwrap_or(&[]);
            let executable = s.characteristics & 0x2000_0000 != 0;
            let readable = s.characteristics & 0x4000_0000 != 0;
            let writable = s.characteristics & 0x8000_0000 != 0;

            let permissions = format!(
                "{}{}{}",
                if readable { 'R' } else { '-' },
                if writable { 'W' } else { '-' },
                if executable { 'X' } else { '-' }
            );
            SectionInfo {
                index,
                name,
                name_is_irregular,
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_offset: s.raw_offset,
                raw_size: s.raw_size,
                characteristics: s.characteristics,
                permissions,
                flags: section_flag_names(s.characteristics),
                entropy: round3(entropy(raw)),
                executable,
                writable,
                readable,
                is_bss: s.raw_size == 0 && s.virtual_size > 0,
            }
        })
        .collect()
}

pub fn data_directories(
    data: &[u8],
    headers: &Headers,
    sections: &[SectionInfo],
    size_of_headers: u32,
) -> Vec<DataDirectoryInfo> {
    headers
        .directories
        .iter()
        .map(|&(index, rva, size)| {
            let name = DATA_DIRECTORY_NAMES
                .get(index)
                .copied()
                .unwrap_or("Unknown")
                .to_string();
            let present = rva != 0 && size != 0;
            let file_offset = if !present {
                None
            } else if index == crate::types::DIR_SECURITY {
                Some(rva as u64)
            } else {
                rva_to_offset_in(sections, size_of_headers, rva)
            };
            let mut note = None;
            if present {
                if let Some(off) = file_offset {
                    if off >= data.len() as u64 {
                        note = Some(format!(
                            "directory points beyond EOF (file offset {off:#x})"
                        ));
                    }
                } else if index != crate::types::DIR_SECURITY {
                    note = Some("RVA is not backed by raw section data".to_string());
                }
                if size > data.len() as u32 {
                    note = Some(match note {
                        Some(n) => format!("{n}; size {size:#x} exceeds file size"),
                        None => format!("size {size:#x} exceeds file size"),
                    });
                }
            }
            DataDirectoryInfo {
                index,
                name,
                rva,
                size,
                file_offset,
                present,
                note,
            }
        })
        .collect()
}

pub fn rva_to_offset_in(sections: &[SectionInfo], size_of_headers: u32, rva: u32) -> Option<u64> {
    if rva < size_of_headers {
        return Some(rva as u64);
    }
    for s in sections {
        let size = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && (rva as u64) < s.virtual_address as u64 + size as u64 {
            let delta = rva - s.virtual_address;
            if delta >= s.raw_size {
                return None;
            }
            return Some(s.raw_offset as u64 + delta as u64);
        }
    }
    None
}

pub fn characteristic_names(flags: u16) -> Vec<String> {
    const NAMES: &[(u16, &str)] = &[
        (0x0001, "RELOCS_STRIPPED"),
        (0x0002, "EXECUTABLE_IMAGE"),
        (0x0004, "LINE_NUMS_STRIPPED"),
        (0x0008, "LOCAL_SYMS_STRIPPED"),
        (0x0010, "AGGRESSIVE_WS_TRIM"),
        (0x0020, "LARGE_ADDRESS_AWARE"),
        (0x0080, "BYTES_REVERSED_LO"),
        (0x0100, "32BIT_MACHINE"),
        (0x0200, "DEBUG_STRIPPED"),
        (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
        (0x0800, "NET_RUN_FROM_SWAP"),
        (0x1000, "SYSTEM"),
        (0x2000, "DLL"),
        (0x4000, "UP_SYSTEM_ONLY"),
        (0x8000, "BYTES_REVERSED_HI"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

pub fn dll_characteristic_names(flags: u16) -> Vec<String> {
    const NAMES: &[(u16, &str)] = &[
        (0x0020, "HIGH_ENTROPY_VA"),
        (0x0040, "DYNAMIC_BASE"),
        (0x0080, "FORCE_INTEGRITY"),
        (0x0100, "NX_COMPAT"),
        (0x0200, "NO_ISOLATION"),
        (0x0400, "NO_SEH"),
        (0x0800, "NO_BIND"),
        (0x1000, "APPCONTAINER"),
        (0x2000, "WDM_DRIVER"),
        (0x4000, "GUARD_CF"),
        (0x8000, "TERMINAL_SERVER_AWARE"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

pub fn section_flag_names(flags: u32) -> Vec<String> {
    const NAMES: &[(u32, &str)] = &[
        (0x0000_0008, "TYPE_NO_PAD"),
        (0x0000_0020, "CNT_CODE"),
        (0x0000_0040, "CNT_INITIALIZED_DATA"),
        (0x0000_0080, "CNT_UNINITIALIZED_DATA"),
        (0x0000_0100, "LNK_OTHER"),
        (0x0000_0200, "LNK_INFO"),
        (0x0000_0800, "LNK_REMOVE"),
        (0x0000_1000, "LNK_COMDAT"),
        (0x0000_8000, "GPREL"),
        (0x0001_0000, "MEM_PURGEABLE"),
        (0x0002_0000, "MEM_LOCKED"),
        (0x0004_0000, "MEM_PRELOAD"),
        (0x0010_0000, "ALIGN_1BYTES"),
        (0x0020_0000, "ALIGN_2BYTES"),
        (0x0030_0000, "ALIGN_4BYTES"),
        (0x0040_0000, "ALIGN_8BYTES"),
        (0x0050_0000, "ALIGN_16BYTES"),
        (0x0060_0000, "ALIGN_32BYTES"),
        (0x0070_0000, "ALIGN_64BYTES"),
        (0x0080_0000, "ALIGN_128BYTES"),
        (0x0090_0000, "ALIGN_256BYTES"),
        (0x00A0_0000, "ALIGN_512BYTES"),
        (0x00B0_0000, "ALIGN_1024BYTES"),
        (0x00C0_0000, "ALIGN_2048BYTES"),
        (0x00D0_0000, "ALIGN_4096BYTES"),
        (0x00E0_0000, "ALIGN_8192BYTES"),
        (0x0100_0000, "LNK_NRELOC_OVFL"),
        (0x0200_0000, "MEM_DISCARDABLE"),
        (0x0400_0000, "MEM_NOT_CACHED"),
        (0x0800_0000, "MEM_NOT_PAGED"),
        (0x1000_0000, "MEM_SHARED"),
        (0x2000_0000, "MEM_EXECUTE"),
        (0x4000_0000, "MEM_READ"),
        (0x8000_0000, "MEM_WRITE"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

pub fn compute_checksum(data: &[u8], checksum_offset: u64) -> u32 {
    let mut sum: u64 = 0;
    let mut offset = 0usize;
    while offset + 1 < data.len() {
        let in_checksum_field = (offset as u64) >= checksum_offset
            && (offset as u64) < checksum_offset.saturating_add(4);
        let word = if in_checksum_field {
            0
        } else {
            u16::from_le_bytes([data[offset], data[offset + 1]]) as u64
        };
        sum = sum.wrapping_add(word);
        sum = (sum & 0xffff) + (sum >> 16);
        offset += 2;
    }
    if offset < data.len() {
        sum += data[offset] as u64;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = (sum & 0xffff) + (sum >> 16);
    let folded = ((folded & 0xffff) + (folded >> 16)) as u32;
    folded.wrapping_add(data.len() as u32)
}

pub fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

pub fn machine_name(machine: u16) -> String {
    machine_info(machine).0.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_reference_algorithm_on_zeroed_field() {
        let mut data: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 256) as u8).collect();
        let offset = 0x40usize;
        data[offset..offset + 4].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        let got = compute_checksum(&data, offset as u64);

        let mut zeroed = data.clone();
        zeroed[offset..offset + 4].fill(0);
        let mut sum: u64 = 0;
        for chunk in zeroed.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_le_bytes([chunk[0], chunk[1]]) as u64
            } else {
                chunk[0] as u64
            };
            sum += word;
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let folded = (sum & 0xffff) + (sum >> 16);
        let expected =
            (((folded & 0xffff) + (folded >> 16)) as u32).wrapping_add(zeroed.len() as u32);
        assert_eq!(got, expected);
    }

    #[test]
    fn rejects_missing_signature() {
        let data = vec![0u8; 0x100];
        assert_eq!(
            parse_headers(&data, 1000).unwrap_err(),
            ParseError::InvalidDosHeader
        );
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3c] = 0x40;
        assert_eq!(
            parse_headers(&data, 1000).unwrap_err(),
            ParseError::InvalidPeHeader
        );
    }
}
