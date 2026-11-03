use crate::headers::rva_to_offset_in;
use crate::types::{CodeViewRecord, DebugEntryInfo, PdbInfo, SectionInfo};
use binscope_common::Reader;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, Default)]
pub struct DebugParseResult {
    pub pdb: Option<PdbInfo>,

    pub codeview_records: Vec<CodeViewRecord>,
    pub entries: Vec<DebugEntryInfo>,
    pub notes: Vec<String>,

    pub path_warning: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ParsedCodeView {
    pub signature: String,
    pub path: Option<String>,
    pub guid: Option<String>,
    pub age: Option<u32>,
    pub timestamp: Option<u32>,

    pub known: bool,
}

pub fn parse_debug_directory(
    data: &[u8],
    sections: &[SectionInfo],
    size_of_headers: u32,
    dir_rva: u32,
    dir_size: u32,
) -> DebugParseResult {
    let mut result = DebugParseResult::default();
    if dir_rva == 0 || dir_size == 0 {
        return result;
    }
    let Some(base) = rva_to_offset_in(sections, size_of_headers, dir_rva) else {
        result
            .notes
            .push("debug directory RVA is not backed by file data".into());
        return result;
    };
    let reader = Reader::new(data);
    let count = (dir_size as usize / 28).min(64);
    if dir_size as usize % 28 != 0 {
        result.notes.push(format!(
            "debug directory size {dir_size} is not a multiple of 28"
        ));
    }
    for index in 0..count {
        let entry = base + (index as u64) * 28;
        let Ok(_characteristics) = reader.u32(entry, "debug characteristics") else {
            result.notes.push(format!(
                "debug directory entry {index} is truncated in the header"
            ));
            break;
        };
        let timestamp = reader.u32(entry + 4, "debug timestamp").unwrap_or(0);
        let major = reader.u16(entry + 8, "debug major version").unwrap_or(0);
        let minor = reader.u16(entry + 10, "debug minor version").unwrap_or(0);
        let debug_type = reader.u32(entry + 12, "debug type").unwrap_or(0);
        let size_of_data = reader.u32(entry + 16, "debug data size").unwrap_or(0);
        let address_rva = reader.u32(entry + 20, "debug data RVA").unwrap_or(0);
        let pointer = reader.u32(entry + 24, "debug data offset").unwrap_or(0);
        let file_offset = if address_rva != 0 {
            rva_to_offset_in(sections, size_of_headers, address_rva)
        } else if pointer != 0 {
            Some(pointer as u64)
        } else {
            None
        };
        let mut status = "ok".to_string();
        let data_in_bounds = file_offset
            .map(|offset| {
                offset
                    .checked_add(size_of_data as u64)
                    .is_some_and(|end| end <= data.len() as u64)
            })
            .unwrap_or(false);
        if file_offset.is_none() {
            status = "data not backed by file".into();
        } else if !data_in_bounds {
            status = "data out of bounds".into();
        }

        result.entries.push(DebugEntryInfo {
            index,
            debug_type,
            type_name: debug_type_name(debug_type).to_string(),
            timestamp,
            timestamp_utc: format_timestamp(timestamp),
            major_version: major,
            minor_version: minor,
            size_of_data,
            address_rva,
            file_offset,
            status: status.clone(),
        });

        if debug_type != 2 {
            if debug_type != 0 {
                result.notes.push(format!(
                    "debug directory entry {index} has type {debug_type} ({}), not CodeView",
                    debug_type_name(debug_type)
                ));
            }
            continue;
        }

        let source = format!("IMAGE_DEBUG_DIRECTORY[{index}]");
        let Some(offset) = file_offset else {
            result.codeview_records.push(CodeViewRecord {
                debug_index: index,
                signature: "unknown".into(),
                pdb_path: None,
                guid: None,
                age: None,
                timestamp: Some(timestamp).filter(|value| *value != 0),
                timestamp_utc: format_timestamp(timestamp),
                data_offset: None,
                data_size: size_of_data,
                status: "not backed by file".into(),
                primary: false,
                source,
            });
            result
                .notes
                .push("CodeView debug data is not backed by file data".into());
            continue;
        };

        let available = data.len().saturating_sub(offset as usize);
        let size = (size_of_data as usize).min(available).min(4096);
        let end = (offset as usize).saturating_add(size);
        let blob = data.get(offset as usize..end).unwrap_or(&[]);
        let truncated = !data_in_bounds;
        if blob.is_empty() {
            result.codeview_records.push(CodeViewRecord {
                debug_index: index,
                signature: "unknown".into(),
                pdb_path: None,
                guid: None,
                age: None,
                timestamp: Some(timestamp).filter(|value| *value != 0),
                timestamp_utc: format_timestamp(timestamp),
                data_offset: Some(offset),
                data_size: size_of_data,
                status: "truncated".into(),
                primary: false,
                source,
            });
            result.notes.push("CodeView debug data is truncated".into());
            continue;
        }

        let parsed = parse_codeview_blob(blob);
        let status = if truncated {
            "truncated"
        } else if parsed.known {
            "parsed"
        } else {
            "unknown signature"
        };
        let record = CodeViewRecord {
            debug_index: index,
            signature: parsed.signature.clone(),
            pdb_path: parsed.path.clone(),
            guid: parsed.guid.clone(),
            age: parsed.age,
            timestamp: parsed
                .timestamp
                .or(Some(timestamp).filter(|value| *value != 0)),
            timestamp_utc: format_timestamp(parsed.timestamp.unwrap_or(timestamp)),
            data_offset: Some(offset),
            data_size: size_of_data,
            status: status.into(),
            primary: false,
            source,
        };
        let is_primary = parsed.known && parsed.path.is_some() && result.pdb.is_none();
        if is_primary {
            if let Some(warning) = parsed.path.as_deref().and_then(pdb_path_warning) {
                result.path_warning = Some(warning);
            }
            result.pdb = Some(PdbInfo {
                path: parsed.path.clone().unwrap_or_default(),
                guid: parsed.guid.clone(),
                age: parsed.age,
                signature: parsed.signature.clone(),
                debug_directory_rva: dir_rva,
                data_file_offset: Some(offset),
            });
        } else if parsed.known && parsed.path.is_some() {
            result.notes.push(format!(
                "additional CodeView record at {offset:#x} is preserved separately"
            ));
        }
        result.codeview_records.push(CodeViewRecord {
            primary: is_primary,
            ..record
        });
        if !parsed.known {
            result
                .notes
                .push("CodeView record has an unsupported signature".into());
        } else if truncated {
            result.notes.push("CodeView debug data is truncated".into());
        }
    }
    result
}

pub fn parse_codeview(blob: &[u8]) -> Option<PdbInfo> {
    let parsed = parse_codeview_blob(blob);
    if !parsed.known {
        return None;
    }
    Some(PdbInfo {
        path: parsed.path?,
        guid: parsed.guid,
        age: parsed.age,
        signature: parsed.signature,
        debug_directory_rva: 0,
        data_file_offset: None,
    })
}

pub fn parse_codeview_blob(blob: &[u8]) -> ParsedCodeView {
    if blob.len() < 4 {
        return ParsedCodeView {
            signature: "unknown".into(),
            ..Default::default()
        };
    }
    let signature = signature_string(&blob[0..4]);
    match &blob[0..4] {
        b"RSDS" => {
            if blob.len() < 25 {
                return ParsedCodeView {
                    signature,
                    ..Default::default()
                };
            }
            ParsedCodeView {
                signature,
                path: Some(cstr_bytes(&blob[24..])),
                guid: Some(format_guid(&blob[4..20])),
                age: Some(u32::from_le_bytes([blob[20], blob[21], blob[22], blob[23]])),
                timestamp: None,
                known: true,
            }
        }
        b"NB10" => {
            if blob.len() < 17 {
                return ParsedCodeView {
                    signature,
                    ..Default::default()
                };
            }
            ParsedCodeView {
                signature,
                path: Some(cstr_bytes(&blob[16..])),
                guid: None,
                age: Some(u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]])),
                timestamp: Some(u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]])),
                known: true,
            }
        }
        _ => ParsedCodeView {
            signature,
            ..Default::default()
        },
    }
}

fn signature_string(bytes: &[u8]) -> String {
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join("")
    }
}

pub fn pdb_path_warning(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let user_profile = lower.contains("\\users\\")
        || lower.contains("/users/")
        || lower.contains("\\documents and settings\\");
    let unc = path.starts_with("\\\\");
    let build_root = lower.contains("\\build\\")
        || lower.contains("/build/")
        || lower.contains("\\jenkins\\")
        || lower.contains("\\gitlab-runner\\");
    if user_profile {
        return Some(
            "The PDB path contains a user profile directory. This can disclose a local username or project path; it is not evidence of malware."
                .into(),
        );
    }
    if unc {
        return Some(
            "The PDB path is a UNC network location. This can disclose an internal build share; it is not evidence of malware."
                .into(),
        );
    }
    if build_root {
        return Some(
            "The PDB path contains a build or CI directory. This can disclose internal build infrastructure; it is not evidence of malware."
                .into(),
        );
    }
    None
}

fn debug_type_name(value: u32) -> &'static str {
    match value {
        0 => "Unknown",
        1 => "COFF",
        2 => "CodeView",
        3 => "FPO",
        4 => "Misc",
        5 => "Exception",
        6 => "Fixup",
        7 => "OmapToSrc",
        8 => "OmapFromSrc",
        9 => "Borland",
        11 => "CLSID",
        12 => "VCFeature",
        13 => "POGO",
        14 => "ILTCG",
        15 => "MPX",
        16 => "Repro",
        17 => "EmbeddedPortablePdb",
        19 => "PdbChecksum",
        20 => "ExDllCharacteristics",
        _ => "Other",
    }
}

fn format_timestamp(value: u32) -> Option<String> {
    if value == 0 {
        return None;
    }
    let seconds = i64::from(value);
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|date| date.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn cstr_bytes(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(bytes.len().min(260));
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rsds(path: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"RSDS");
        blob.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        blob.extend_from_slice(&7u32.to_le_bytes());
        blob.extend_from_slice(path.as_bytes());
        blob.push(0);
        blob
    }

    #[test]
    fn guid_is_formatted_canonically() {
        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        assert_eq!(format_guid(&guid), "04030201-0605-0807-090A-0B0C0D0E0F10");
    }

    #[test]
    fn rsds_is_decoded_with_guid_age_and_path() {
        let pdb = parse_codeview(&rsds(r"C:\build\demo.pdb")).expect("RSDS");
        assert_eq!(pdb.signature, "RSDS");
        assert_eq!(pdb.path, r"C:\build\demo.pdb");
        assert_eq!(pdb.age, Some(7));
        assert_eq!(
            pdb.guid.as_deref(),
            Some("04030201-0605-0807-090A-0B0C0D0E0F10")
        );
    }

    #[test]
    fn nb10_is_decoded() {
        let mut blob = b"NB10".to_vec();
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&1234u32.to_le_bytes());
        blob.extend_from_slice(&9u32.to_le_bytes());
        blob.extend_from_slice(b"legacy.pdb\0");
        let pdb = parse_codeview(&blob).expect("NB10");
        assert_eq!(pdb.signature, "NB10");
        assert_eq!(pdb.path, "legacy.pdb");
        assert_eq!(pdb.age, Some(9));
        assert!(pdb.guid.is_none());
    }

    #[test]
    fn truncated_and_unknown_records_are_rejected() {
        assert!(parse_codeview(b"RSDS\x00\x01").is_none());
        assert!(parse_codeview(b"NB10\x00").is_none());
        assert!(parse_codeview(b"XXXX").is_none());
        assert!(parse_codeview(&[]).is_none());
    }

    #[test]
    fn pdb_paths_flag_user_and_build_locations() {
        assert!(pdb_path_warning(r"C:\Users\analyst\proj\app.pdb").is_some());
        assert!(pdb_path_warning(r"\\build-server\symbols\app.pdb").is_some());
        assert!(pdb_path_warning(r"D:\jenkins\workspace\app.pdb").is_some());
        assert!(pdb_path_warning(r"C:\src\app.pdb").is_none());
    }

    #[test]
    fn unterminated_paths_are_bounded() {
        let mut blob = rsds("A");
        blob.pop();

        let pdb = parse_codeview(&blob).expect("RSDS");
        assert_eq!(pdb.path, "A");
    }

    fn section() -> SectionInfo {
        SectionInfo {
            index: 1,
            name: ".rdata".into(),
            name_is_irregular: false,
            virtual_address: 0x1000,
            virtual_size: 0x600,
            raw_offset: 0x200,
            raw_size: 0x600,
            characteristics: 0x4000_0040,
            permissions: "R".into(),
            flags: Vec::new(),
            entropy: 0.0,
            executable: false,
            writable: false,
            readable: true,
            is_bss: false,
        }
    }

    fn nb10(path: &str, timestamp: u32) -> Vec<u8> {
        let mut blob = b"NB10".to_vec();
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&timestamp.to_le_bytes());
        blob.extend_from_slice(&9u32.to_le_bytes());
        blob.extend_from_slice(path.as_bytes());
        blob.push(0);
        blob
    }

    fn write_debug_entry(data: &mut [u8], entry: usize, size: u32, rva: u32, offset: u32) {
        data[entry + 12..entry + 16].copy_from_slice(&2u32.to_le_bytes());
        data[entry + 16..entry + 20].copy_from_slice(&size.to_le_bytes());
        data[entry + 20..entry + 24].copy_from_slice(&rva.to_le_bytes());
        data[entry + 24..entry + 28].copy_from_slice(&offset.to_le_bytes());
    }

    #[test]
    fn every_codeview_record_is_preserved() {
        let mut data = vec![0u8; 0x800];
        let blobs = [
            rsds(r"C:\a\first.pdb"),
            nb10(r"C:\b\second.pdb", 0x6500_0000),
            b"XXXXunknown payload".to_vec(),
        ];
        for (index, blob) in blobs.iter().enumerate() {
            let offset = 0x300 + index * 0x60;
            data[offset..offset + blob.len()].copy_from_slice(blob);
            let entry = 0x200 + index * 28;
            write_debug_entry(
                &mut data,
                entry,
                blob.len() as u32,
                0x1000 + (offset as u32 - 0x200),
                offset as u32,
            );
        }
        let parsed = parse_debug_directory(&data, &[section()], 0x200, 0x1000, 3 * 28);
        assert_eq!(parsed.codeview_records.len(), 3);
        assert_eq!(parsed.pdb.as_ref().unwrap().path, r"C:\a\first.pdb");
        let primary: Vec<_> = parsed
            .codeview_records
            .iter()
            .filter(|record| record.primary)
            .collect();
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].debug_index, 0);
        assert_eq!(parsed.codeview_records[1].signature, "NB10");
        assert_eq!(
            parsed.codeview_records[1].pdb_path.as_deref(),
            Some(r"C:\b\second.pdb")
        );
        assert_eq!(parsed.codeview_records[1].timestamp, Some(0x6500_0000));
        assert_eq!(parsed.codeview_records[2].signature, "XXXX");
        assert_eq!(parsed.codeview_records[2].status, "unknown signature");
        assert_eq!(parsed.codeview_records[2].data_offset, Some(0x3c0));
        assert!(parsed
            .codeview_records
            .iter()
            .all(|record| record.source.contains("IMAGE_DEBUG_DIRECTORY")));
    }

    #[test]
    fn truncated_codeview_record_is_kept_with_status() {
        let mut data = vec![0u8; 0x340];
        let blob = rsds(r"C:\x\truncated.pdb");
        data[0x300..0x300 + blob.len()].copy_from_slice(&blob);
        write_debug_entry(&mut data, 0x200, 0x200, 0x1000 + 0x100, 0x300);
        let parsed = parse_debug_directory(&data, &[section()], 0x200, 0x1000, 28);
        assert_eq!(parsed.codeview_records.len(), 1);
        assert_eq!(parsed.codeview_records[0].status, "truncated");
        assert_eq!(parsed.codeview_records[0].data_offset, Some(0x300));
        assert_eq!(parsed.codeview_records[0].data_size, 0x200);
    }
}
