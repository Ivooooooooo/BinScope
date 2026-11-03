use crate::headers::rva_to_offset_in;
use crate::types::{ExportInfo, SectionInfo};
use binscope_common::Reader;
use std::collections::HashMap;

pub struct ExportOutcome {
    pub dll_name: Option<String>,
    pub exports: Vec<ExportInfo>,
    pub notes: Vec<String>,
}

pub fn parse_exports(
    data: &[u8],
    sections: &[SectionInfo],
    size_of_headers: u32,
    dir_rva: u32,
    dir_size: u32,
    max_entries: usize,
) -> ExportOutcome {
    let mut out = ExportOutcome {
        dll_name: None,
        exports: Vec::new(),
        notes: Vec::new(),
    };
    if dir_rva == 0 {
        return out;
    }
    let Some(dir_off) = rva_to_offset_in(sections, size_of_headers, dir_rva) else {
        out.notes
            .push("export directory RVA is not backed by file data".into());
        return out;
    };
    let r = Reader::new(data);
    let name_rva = match r.u32(dir_off + 12, "export DLL name") {
        Ok(v) => v,
        Err(_) => {
            out.notes.push("export directory is truncated".into());
            return out;
        }
    };
    let base = r.u32(dir_off + 16, "export base").unwrap_or(0);
    let number_of_functions = r.u32(dir_off + 20, "export function count").unwrap_or(0);
    let number_of_names = r.u32(dir_off + 24, "export name count").unwrap_or(0);
    let functions_rva = r.u32(dir_off + 28, "export function array").unwrap_or(0);
    let names_rva = r.u32(dir_off + 32, "export name array").unwrap_or(0);
    let ordinals_rva = r.u32(dir_off + 36, "export ordinal array").unwrap_or(0);

    if (number_of_functions as usize) > max_entries || (number_of_names as usize) > max_entries {
        out.notes.push(format!(
            "export counts (functions={number_of_functions}, names={number_of_names}) exceed the configured limit; only the first {max_entries} are read"
        ));
    }
    let func_count = (number_of_functions as usize).min(max_entries);
    let name_count = (number_of_names as usize).min(max_entries);

    out.dll_name = rva_to_offset_in(sections, size_of_headers, name_rva)
        .and_then(|off| r.cstr(off, 512, "export DLL name").ok())
        .filter(|s| !s.is_empty());

    let function_array = rva_to_offset_in(sections, size_of_headers, functions_rva);
    let name_array = rva_to_offset_in(sections, size_of_headers, names_rva);
    let ordinal_array = rva_to_offset_in(sections, size_of_headers, ordinals_rva);

    let mut by_index: HashMap<usize, (Option<String>, u32)> = HashMap::new();
    if let (Some(names_off), Some(ordinals_off)) = (name_array, ordinal_array) {
        for i in 0..name_count {
            let name_entry_rva = match r.u32(names_off + (i as u64) * 4, "export name RVA") {
                Ok(v) => v,
                Err(_) => break,
            };
            let ordinal_index = match r.u16(ordinals_off + (i as u64) * 2, "export ordinal") {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            let name = rva_to_offset_in(sections, size_of_headers, name_entry_rva)
                .and_then(|off| r.cstr(off, 512, "export name").ok());
            let func_rva = function_array
                .and_then(|off| {
                    r.u32(off + (ordinal_index as u64) * 4, "export function RVA")
                        .ok()
                })
                .unwrap_or(0);
            by_index.insert(ordinal_index, (name, func_rva));
        }
    }

    for index in 0..func_count {
        let func_rva = function_array
            .and_then(|off| r.u32(off + (index as u64) * 4, "export function RVA").ok())
            .unwrap_or(0);
        if func_rva == 0 {
            continue;
        }
        let (name, named_rva) = match by_index.remove(&index) {
            Some((n, v)) => (n, v),
            None => (None, func_rva),
        };
        let rva = if named_rva != 0 { named_rva } else { func_rva };
        let forwarder = if rva >= dir_rva && (rva as u64) < dir_rva as u64 + dir_size.max(1) as u64
        {
            rva_to_offset_in(sections, size_of_headers, rva)
                .and_then(|off| r.cstr(off, 512, "export forwarder").ok())
        } else {
            None
        };
        out.exports.push(ExportInfo {
            name,
            ordinal: base.saturating_add(index as u32),
            rva,
            file_offset: rva_to_offset_in(sections, size_of_headers, rva)
                .and_then(|o| u32::try_from(o).ok()),
            forwarder,
        });
    }

    out
}
