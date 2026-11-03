use crate::types::{CertificateEntry, CertificateInfo};
use binscope_common::Reader;

const MAX_CERT_ENTRIES: usize = 64;

pub fn parse_certificate_table(
    data: &[u8],
    directory_offset: u32,
    directory_size: u32,
) -> CertificateInfo {
    let mut info = CertificateInfo {
        present: directory_offset != 0 && directory_size != 0,
        directory_offset,
        directory_size,
        entries: Vec::new(),
        note: String::new(),
    };
    if !info.present {
        info.note = "No Authenticode certificate table is present.".to_string();
        return info;
    }
    let r = Reader::new(data);
    let start = directory_offset as u64;
    let end = start.saturating_add(directory_size as u64);
    if end > data.len() as u64 {
        info.note =
            "Certificate table extends beyond the end of the file; it is truncated or corrupt."
                .to_string();
    }
    let mut offset = start;
    let mut count = 0;
    while offset + 8 <= end.min(data.len() as u64) && count < MAX_CERT_ENTRIES {
        let length = match r.u32(offset, "WIN_CERTIFICATE length") {
            Ok(v) => v,
            Err(_) => break,
        };
        if length < 8 {
            info.note =
                format!("Invalid WIN_CERTIFICATE length {length} at file offset {offset:#x}.");
            break;
        }
        let revision = r.u16(offset + 4, "WIN_CERTIFICATE revision").unwrap_or(0);
        let cert_type = r.u16(offset + 6, "WIN_CERTIFICATE type").unwrap_or(0);
        let entry_end = offset.saturating_add(length as u64);
        let available_end = entry_end.min(data.len() as u64).min(end);
        let blob_start = (offset + 8) as usize;
        let blob_end = available_end as usize;
        let in_bounds = entry_end <= data.len() as u64 && entry_end <= end;
        let data_length = blob_end.saturating_sub(blob_start) as u32;
        let contains_nested = if blob_start < blob_end {
            contains_oid(&data[blob_start..blob_end])
        } else {
            false
        };
        info.entries.push(CertificateEntry {
            offset,
            length,
            revision,
            revision_name: revision_name(revision).to_string(),
            certificate_type: cert_type,
            certificate_type_name: certificate_type_name(cert_type).to_string(),
            contains_nested_signature_oid: contains_nested,
            data_offset: blob_start as u64,
            data_length,
            in_bounds,
        });
        count += 1;

        let next = (entry_end + 7) & !7;
        if !in_bounds || next <= offset {
            break;
        }
        offset = next;
    }
    if info.entries.is_empty() {
        info.note = "Certificate table is present but no valid entry could be parsed.".to_string();
    } else {
        info.note =
            "Signature presence and encoding only; cryptographic verification was not performed."
                .to_string();
    }
    info
}

fn revision_name(revision: u16) -> &'static str {
    match revision {
        0x0100 => "WIN_CERT_REVISION_1_0",
        0x0200 => "WIN_CERT_REVISION_2_0",
        _ => "Unknown revision",
    }
}

fn certificate_type_name(cert_type: u16) -> &'static str {
    match cert_type {
        0x0001 => "X509",
        0x0002 => "PKCS_SIGNED_DATA",
        0x0003 => "TS_STACK_SIGNED",
        0x0004 => "PKCS1_SIGN",
        0x0009 => "TS_STACK_UNSIGNED",
        _ => "Unknown certificate type",
    }
}

fn contains_oid(blob: &[u8]) -> bool {
    const OID: [u8; 12] = [
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01,
    ];
    blob.windows(OID.len()).any(|w| w == OID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pkcs7_entry() {
        let mut data = vec![0u8; 0x300];
        let offset = 0x100u32;
        let length = 0x40u32;
        data[offset as usize..offset as usize + 4].copy_from_slice(&length.to_le_bytes());
        data[offset as usize + 4..offset as usize + 6].copy_from_slice(&0x0200u16.to_le_bytes());
        data[offset as usize + 6..offset as usize + 8].copy_from_slice(&0x0002u16.to_le_bytes());
        let nested = [
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01,
        ];
        data[offset as usize + 8..offset as usize + 8 + nested.len()].copy_from_slice(&nested);
        let info = parse_certificate_table(&data, offset, length);
        assert!(info.present);
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].revision_name, "WIN_CERT_REVISION_2_0");
        assert_eq!(info.entries[0].certificate_type_name, "PKCS_SIGNED_DATA");
        assert!(info.entries[0].contains_nested_signature_oid);
    }

    #[test]
    fn rejects_zero_length_entry() {
        let data = vec![0u8; 64];
        let info = parse_certificate_table(&data, 0, 0);
        assert!(!info.present);
        assert!(info.entries.is_empty());
    }
}
