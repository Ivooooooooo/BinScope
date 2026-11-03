use crate::headers::rva_to_offset_in;
use crate::types::{ImportFunction, ImportLibrary, SectionInfo};
use binscope_common::Reader;

const MAX_LIBRARIES: usize = 4096;
const MAX_NAME_LEN: usize = 512;

#[derive(Default)]
pub struct ImportOutcome {
    pub libraries: Vec<ImportLibrary>,
    pub notes: Vec<String>,
}

pub fn parse_imports(
    data: &[u8],
    sections: &[SectionInfo],
    size_of_headers: u32,
    is_64: bool,
    dir_rva: u32,
    max_entries: usize,
) -> ImportOutcome {
    let mut out = ImportOutcome::default();
    if dir_rva == 0 {
        return out;
    }
    let Some(mut offset) = rva_to_offset_in(sections, size_of_headers, dir_rva) else {
        out.notes
            .push("import directory RVA is not backed by file data".into());
        return out;
    };
    let r = Reader::new(data);
    let descriptor_size = 20u64;
    let mut total_functions = 0usize;
    for descriptor_index in 0..MAX_LIBRARIES as u64 {
        let name_rva = match r.u32(offset + 12, "import name RVA") {
            Ok(v) => v,
            Err(_) => {
                out.notes
                    .push("import descriptor table is truncated".into());
                break;
            }
        };
        let first_thunk = r.u32(offset + 16, "import first thunk").unwrap_or(0);
        let original_thunk = r.u32(offset, "import original first thunk").unwrap_or(0);
        if name_rva == 0 && first_thunk == 0 && original_thunk == 0 {
            break;
        }
        let name = r
            .u32(offset + 12, "import name RVA")
            .ok()
            .and_then(|rva| rva_to_offset_in(sections, size_of_headers, rva))
            .and_then(|off| r.cstr(off, MAX_NAME_LEN, "import library name").ok())
            .unwrap_or_else(|| "<unreadable>".to_string());
        let name_is_irregular =
            name.is_empty() || name == "<unreadable>" || name.chars().any(|c| c.is_control());

        let mut functions = Vec::new();
        let thunk_rva = if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        };
        if let Some(mut thunk_off) = rva_to_offset_in(sections, size_of_headers, thunk_rva) {
            let width = if is_64 { 8usize } else { 4 };
            let limit = max_entries.min(16_384);
            for _ in 0..limit {
                let value = if is_64 {
                    match r.u64(thunk_off, "import thunk") {
                        Ok(v) => v,
                        Err(_) => break,
                    }
                } else {
                    match r.u32(thunk_off, "import thunk") {
                        Ok(v) => v as u64,
                        Err(_) => break,
                    }
                };
                if value == 0 {
                    break;
                }
                let ordinal_flag = if is_64 { 1u64 << 63 } else { 1u64 << 31 };
                if value & ordinal_flag != 0 {
                    functions.push(ImportFunction {
                        name: None,
                        ordinal: Some((value & 0xffff) as u16),
                        hint: None,
                    });
                } else {
                    let name_rva = (value & 0x7fff_ffff) as u32;
                    if let Some(off) = rva_to_offset_in(sections, size_of_headers, name_rva) {
                        let hint = r.u16(off, "import hint").ok();
                        let fname = r
                            .cstr(off + 2, MAX_NAME_LEN, "import function name")
                            .unwrap_or_else(|_| "<unreadable>".to_string());
                        functions.push(ImportFunction {
                            name: Some(fname),
                            ordinal: None,
                            hint,
                        });
                    } else {
                        out.notes.push(format!(
                            "import name RVA {name_rva:#x} in {name} is not backed by file data"
                        ));
                    }
                }
                thunk_off += width as u64;
                total_functions += 1;
                if total_functions >= max_entries {
                    out.notes.push(
                        "import function limit reached; remaining imports were ignored".into(),
                    );
                    break;
                }
            }
        }
        out.libraries.push(ImportLibrary {
            name,
            descriptor_rva: dir_rva.wrapping_add((descriptor_index * descriptor_size) as u32),
            functions,
            name_is_irregular,
        });
        offset += descriptor_size;
        if total_functions >= max_entries {
            break;
        }
    }
    out
}

pub fn parse_delay_imports(
    data: &[u8],
    sections: &[SectionInfo],
    size_of_headers: u32,
    is_64: bool,
    dir_rva: u32,
    max_entries: usize,
) -> ImportOutcome {
    let mut out = ImportOutcome::default();
    if dir_rva == 0 {
        return out;
    }
    let Some(mut offset) = rva_to_offset_in(sections, size_of_headers, dir_rva) else {
        out.notes
            .push("delay import directory RVA is not backed by file data".into());
        return out;
    };
    let r = Reader::new(data);
    for _ in 0..1024 {
        let name_rva = r.u32(offset + 4, "delay import name RVA").unwrap_or(0);
        let int_rva = r.u32(offset + 16, "delay import INT").unwrap_or(0);
        let iat_rva = r.u32(offset + 12, "delay import IAT").unwrap_or(0);
        if name_rva == 0 && int_rva == 0 && iat_rva == 0 {
            break;
        }
        let name = rva_to_offset_in(sections, size_of_headers, name_rva)
            .and_then(|off| r.cstr(off, MAX_NAME_LEN, "delay import name").ok())
            .unwrap_or_else(|| "<unreadable>".to_string());
        let mut functions = Vec::new();
        let thunk_rva = if int_rva != 0 { int_rva } else { iat_rva };
        if let Some(mut thunk_off) = rva_to_offset_in(sections, size_of_headers, thunk_rva) {
            let width = if is_64 { 8usize } else { 4 };
            for _ in 0..max_entries.min(16_384) {
                let value = if is_64 {
                    r.u64(thunk_off, "delay thunk").unwrap_or(0)
                } else {
                    r.u32(thunk_off, "delay thunk").unwrap_or(0) as u64
                };
                if value == 0 {
                    break;
                }
                let ordinal_flag = if is_64 { 1u64 << 63 } else { 1u64 << 31 };
                if value & ordinal_flag != 0 {
                    functions.push(ImportFunction {
                        name: None,
                        ordinal: Some((value & 0xffff) as u16),
                        hint: None,
                    });
                } else if let Some(off) =
                    rva_to_offset_in(sections, size_of_headers, (value & 0x7fff_ffff) as u32)
                {
                    let hint = r.u16(off, "delay import hint").ok();
                    let fname = r.cstr(off + 2, MAX_NAME_LEN, "delay import name").ok();
                    functions.push(ImportFunction {
                        name: fname,
                        ordinal: None,
                        hint,
                    });
                }
                thunk_off += width as u64;
            }
        }
        let index = out.libraries.len() as u64;
        out.libraries.push(ImportLibrary {
            name,
            descriptor_rva: dir_rva.wrapping_add((index * 32) as u32),
            functions,
            name_is_irregular: false,
        });
        offset += 32;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::rva_to_offset_in;

    fn section() -> SectionInfo {
        SectionInfo {
            index: 0,
            name: ".rdata".into(),
            name_is_irregular: false,
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_offset: 0x200,
            raw_size: 0x1000,
            characteristics: 0x4000_0040,
            permissions: "R--".into(),
            flags: vec![],
            entropy: 0.0,
            executable: false,
            writable: false,
            readable: true,
            is_bss: false,
        }
    }

    #[test]
    fn rva_mapping_handles_headers_and_sections() {
        let s = [section()];
        assert_eq!(rva_to_offset_in(&s, 0x200, 0x10), Some(0x10));
        assert_eq!(rva_to_offset_in(&s, 0x200, 0x1000), Some(0x200));
        assert_eq!(rva_to_offset_in(&s, 0x200, 0x1fff), Some(0x11ff));
        assert_eq!(rva_to_offset_in(&s, 0x200, 0x2000), None);
    }
}
