use crate::headers::rva_to_offset_in;
use crate::types::{ResourceEntry, SectionInfo};
use binscope_common::Reader;
use std::collections::HashSet;

const MAX_DEPTH: usize = 4;

pub struct ResourceOutcome {
    pub entries: Vec<ResourceEntry>,
    pub notes: Vec<String>,
}

pub fn resource_type_label(id: u32) -> &'static str {
    match id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => "RT_UNKNOWN",
    }
}

struct Walker<'a> {
    r: Reader<'a>,
    sections: &'a [SectionInfo],
    size_of_headers: u32,
    base_offset: u64,
    max_entries: usize,
    visited: HashSet<u64>,
    entries: Vec<ResourceEntry>,
    notes: Vec<String>,
}

pub fn parse_resources(
    data: &[u8],
    sections: &[SectionInfo],
    size_of_headers: u32,
    dir_rva: u32,
    max_entries: usize,
) -> ResourceOutcome {
    let mut walker = Walker {
        r: Reader::new(data),
        sections,
        size_of_headers,
        base_offset: 0,
        max_entries,
        visited: HashSet::new(),
        entries: Vec::new(),
        notes: Vec::new(),
    };
    if dir_rva == 0 {
        return ResourceOutcome {
            entries: vec![],
            notes: walker.notes,
        };
    }
    let Some(base) = rva_to_offset_in(sections, size_of_headers, dir_rva) else {
        walker
            .notes
            .push("resource directory RVA is not backed by file data".into());
        return ResourceOutcome {
            entries: vec![],
            notes: walker.notes,
        };
    };
    walker.base_offset = base;
    let mut path = Vec::new();
    if walker.walk(base, 0, &mut path).is_err() {
        walker
            .notes
            .push("resource tree is truncated or malformed".into());
    }
    ResourceOutcome {
        entries: walker.entries,
        notes: walker.notes,
    }
}

impl<'a> Walker<'a> {
    fn walk(
        &mut self,
        dir_offset: u64,
        depth: usize,
        path: &mut Vec<(Option<u32>, String)>,
    ) -> Result<(), ()> {
        if depth > MAX_DEPTH || self.entries.len() >= self.max_entries {
            return Ok(());
        }
        if !self.visited.insert(dir_offset) {
            self.notes.push(format!(
                "resource directory cycle at file offset {dir_offset:#x}"
            ));
            return Ok(());
        }
        let named = self
            .r
            .u16(dir_offset + 12, "resource entry count")
            .map_err(|_| ())?;
        let id_count = self
            .r
            .u16(dir_offset + 14, "resource entry count")
            .map_err(|_| ())?;
        let total = named as usize + id_count as usize;
        if total > 8192 {
            self.notes
                .push("resource directory entry count is implausibly large".into());
            return Ok(());
        }
        for i in 0..total {
            let entry_off = dir_offset + 16 + (i as u64) * 8;
            let name_field = self
                .r
                .u32(entry_off, "resource name field")
                .map_err(|_| ())?;
            let data_field = self
                .r
                .u32(entry_off + 4, "resource data field")
                .map_err(|_| ())?;
            let (name_id, entry_name) = if name_field & 0x8000_0000 != 0 {
                let string_off = self.base_offset + (name_field & 0x7fff_ffff) as u64;
                let len = self.r.u16(string_off, "resource name length").unwrap_or(0) as usize;
                let byte_len = len.saturating_mul(2).min(1024);
                let name = self
                    .r
                    .bytes(string_off + 2, byte_len, "resource name")
                    .map(|b| decode_utf16le(b).trim_end_matches('\0').to_string())
                    .unwrap_or_else(|_| "<unreadable>".to_string());
                (None, name)
            } else {
                let id = name_field & 0xffff;
                (Some(id), format!("#{id}"))
            };

            let type_id = if depth == 0 {
                name_id
            } else {
                path.first().and_then(|p| p.0)
            };
            let type_name = match type_id {
                Some(id) => resource_type_label(id).to_string(),
                None => path
                    .first()
                    .map(|p| p.1.clone())
                    .unwrap_or_else(|| entry_name.clone()),
            };

            if data_field & 0x8000_0000 != 0 {
                path.push((name_id, entry_name));
                let sub = self.base_offset + (data_field & 0x7fff_ffff) as u64;
                self.walk(sub, depth + 1, path)?;
                path.pop();
            } else {
                let entry_rva = data_field & 0x7fff_ffff;
                let data_off = self.base_offset + entry_rva as u64;
                let size = self.r.u32(data_off + 4, "resource size").unwrap_or(0);
                let codepage = self.r.u32(data_off + 8, "resource codepage").unwrap_or(0);
                let rva = self.r.u32(data_off, "resource data RVA").unwrap_or(0);
                let language = name_id.unwrap_or_default();
                let (res_name_id, res_name) = path
                    .get(1)
                    .map(|p| (p.0, p.1.clone()))
                    .unwrap_or((None, name_id.map(|id| format!("#{id}")).unwrap_or_default()));
                self.entries.push(ResourceEntry {
                    type_id,
                    type_name,
                    name_id: res_name_id,
                    name: res_name,
                    language,
                    codepage,
                    rva,
                    size,
                    file_offset: rva_to_offset_in(self.sections, self.size_of_headers, rva),
                });
                if self.entries.len() >= self.max_entries {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn resource_bytes<'a>(
    data: &'a [u8],
    entries: &[ResourceEntry],
    type_id: u32,
) -> Option<&'a [u8]> {
    let entry = entries.iter().find(|e| e.type_id == Some(type_id))?;
    let off = entry.file_offset? as usize;
    let end = off.checked_add(entry.size as usize)?;
    data.get(off..end)
}

pub fn decode_manifest(bytes: &[u8]) -> String {
    const MAX_MANIFEST: usize = 256 * 1024;
    let bytes = &bytes[..bytes.len().min(MAX_MANIFEST)];
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        decode_utf16le(&bytes[2..])
    } else if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        String::from_utf8_lossy(&bytes[3..]).into_owned()
    } else if bytes.len() > 4 && bytes[1] == 0 && bytes[3] == 0 {
        decode_utf16le(bytes)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    text.trim_end_matches('\0').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_type_names_are_stable() {
        assert_eq!(resource_type_label(16), "RT_VERSION");
        assert_eq!(resource_type_label(24), "RT_MANIFEST");
        assert_eq!(resource_type_label(9999), "RT_UNKNOWN");
    }

    #[test]
    fn manifest_decoding_handles_utf16_and_utf8() {
        let utf8 = b"\xef\xbb\xbf<assembly/>";
        assert_eq!(decode_manifest(utf8), "<assembly/>");
        let mut wide = vec![0xff, 0xfe];
        wide.extend("<assembly/>".encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert_eq!(decode_manifest(&wide), "<assembly/>");
        assert_eq!(decode_manifest(b"<assembly/>\0"), "<assembly/>");
    }
}
