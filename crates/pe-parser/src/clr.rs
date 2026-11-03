use crate::headers::rva_to_offset_in;
use crate::types::{ClrDirectory, SectionInfo};
use binscope_common::Reader;

pub fn parse_clr_directory(
    data: &[u8],
    sections: &[SectionInfo],
    size_of_headers: u32,
    dir_rva: u32,
    dir_size: u32,
) -> Option<ClrDirectory> {
    if dir_rva == 0 {
        return None;
    }
    let offset = rva_to_offset_in(sections, size_of_headers, dir_rva)?;
    let r = Reader::new(data);
    let header_size = r.u32(offset, "CLR header size").ok()?;
    if header_size < 72 {
        return None;
    }
    let major = r.u16(offset + 4, "CLR major version").ok()?;
    let minor = r.u16(offset + 6, "CLR minor version").ok()?;
    let metadata_rva = r.u32(offset + 8, "CLR metadata RVA").ok()?;
    let metadata_size = r.u32(offset + 12, "CLR metadata size").ok()?;
    let flags = r.u32(offset + 16, "CLR flags").ok()?;
    let entry_point_token = r.u32(offset + 20, "CLR entry point").ok()?;
    let resources_rva = r.u32(offset + 24, "CLR resources RVA").unwrap_or(0);
    let resources_size = r.u32(offset + 28, "CLR resources size").unwrap_or(0);
    let strong_name_rva = r.u32(offset + 32, "CLR strong name RVA").unwrap_or(0);
    let strong_name_size = r.u32(offset + 36, "CLR strong name size").unwrap_or(0);

    let metadata_file_offset = if metadata_rva != 0 {
        rva_to_offset_in(sections, size_of_headers, metadata_rva)
    } else {
        None
    };
    let metadata_version = metadata_file_offset.and_then(|off| read_metadata_version(data, off));

    let mut flag_names = Vec::new();
    const FLAGS: &[(u32, &str)] = &[
        (0x0000_0001, "ILONLY"),
        (0x0000_0002, "32BITREQUIRED"),
        (0x0000_0004, "IL_LIBRARY"),
        (0x0000_0008, "STRONGNAMESIGNED"),
        (0x0000_0010, "NATIVE_ENTRYPOINT"),
        (0x0001_0000, "TRACKDEBUGDATA"),
        (0x0002_0000, "32BITPREFERRED"),
    ];
    for (bit, name) in FLAGS {
        if flags & bit != 0 {
            flag_names.push((*name).to_string());
        }
    }

    let entry_point_kind = if entry_point_token == 0 {
        "none".to_string()
    } else if flags & 0x10 != 0 {
        format!("native entry point RVA {entry_point_token:#x}")
    } else {
        let table = (entry_point_token >> 24) & 0xff;
        let row = entry_point_token & 0x00ff_ffff;
        match table {
            0x06 => format!("MethodDef token 0x{entry_point_token:08X} (row {row})"),
            0x0A => format!("MemberRef token 0x{entry_point_token:08X} (row {row})"),
            other => format!("token 0x{entry_point_token:08X} (table {other:#x}, row {row})"),
        }
    };

    if dir_size != 0 && dir_size < header_size {
        let _ = dir_size;
    }

    Some(ClrDirectory {
        header_size,
        runtime_version: format!("v{major}.{minor}"),
        metadata_rva,
        metadata_size,
        metadata_file_offset,
        flags,
        flag_names,
        entry_point_token,
        entry_point_kind,
        resources_rva,
        resources_size,
        strong_name_rva,
        strong_name_size,
        strong_name_signed: strong_name_size > 0,
        metadata_version,
    })
}

pub fn read_metadata_version(data: &[u8], offset: u64) -> Option<String> {
    let r = Reader::new(data);
    if r.u32(offset, "metadata signature").ok()? != 0x424A_5342 {
        return None;
    }
    let length = r.u32(offset + 12, "metadata version length").ok()? as usize;
    let capped = length.min(256);
    let bytes = r
        .bytes(offset + 16, capped, "metadata version string")
        .ok()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bsjb_version_string() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0x424A_5342u32.to_le_bytes());
        data[12..16].copy_from_slice(&12u32.to_le_bytes());
        data[16..28].copy_from_slice(b"v4.0.30319\0\0");
        assert_eq!(
            read_metadata_version(&data, 0).as_deref(),
            Some("v4.0.30319")
        );
        data[0] = 0;
        assert!(read_metadata_version(&data, 0).is_none());
    }
}
