pub mod anomalies;
pub mod clr;
pub mod debug;
pub mod exports;
mod fixture;
pub mod headers;
pub mod imports;
pub mod resources;
pub mod rich;
pub mod security;
pub mod types;
pub mod version;

pub use types::*;

use binscope_common::Reader;
use chrono::{DateTime, Utc};

pub fn parse(data: &[u8], max_entries: usize) -> Result<PeInfo, ParseError> {
    let max_entries = max_entries.max(1);
    let h = headers::parse_headers(data, max_entries)?;
    let sections = headers::build_sections(&h, data);
    let dirs = headers::data_directories(data, &h, &sections, h.size_of_headers);

    let mut notes = h.notes.clone();
    let dir_value = |index: usize| -> (u32, u32) {
        h.directories
            .iter()
            .find(|(i, _, _)| *i == index)
            .map(|(_, rva, size)| (*rva, *size))
            .unwrap_or((0, 0))
    };

    let (import_rva, import_size) = dir_value(DIR_IMPORT);
    let import_out = imports::parse_imports(
        data,
        &sections,
        h.size_of_headers,
        h.is_64,
        import_rva,
        max_entries,
    );
    notes.extend(import_out.notes);
    let _ = import_size;

    let (delay_rva, _) = dir_value(DIR_DELAY_IMPORT);
    let delay_out = imports::parse_delay_imports(
        data,
        &sections,
        h.size_of_headers,
        h.is_64,
        delay_rva,
        max_entries,
    );
    notes.extend(delay_out.notes);

    let (export_rva, export_size) = dir_value(DIR_EXPORT);
    let export_out = exports::parse_exports(
        data,
        &sections,
        h.size_of_headers,
        export_rva,
        export_size,
        max_entries,
    );
    notes.extend(export_out.notes);

    let (resource_rva, _) = dir_value(DIR_RESOURCE);
    let resource_out = resources::parse_resources(
        data,
        &sections,
        h.size_of_headers,
        resource_rva,
        max_entries,
    );
    notes.extend(resource_out.notes);

    let version_info = resources::resource_bytes(data, &resource_out.entries, 16)
        .and_then(version::parse_version_info);
    let manifest = resources::resource_bytes(data, &resource_out.entries, 24)
        .map(resources::decode_manifest)
        .filter(|m| !m.trim().is_empty());

    let (debug_rva, debug_size) = dir_value(DIR_DEBUG);
    let debug_info =
        debug::parse_debug_directory(data, &sections, h.size_of_headers, debug_rva, debug_size);
    notes.extend(debug_info.notes);
    let pdb = debug_info.pdb;
    let codeview_records = debug_info.codeview_records;
    let debug_entries = debug_info.entries;
    let pdb_path_warning = debug_info.path_warning;

    let rich_header = rich::parse_rich_header(data, h.pe_offset);

    let (clr_rva, clr_size) = dir_value(DIR_CLR);
    let clr = clr::parse_clr_directory(data, &sections, h.size_of_headers, clr_rva, clr_size);

    let (security_offset, security_size) = dir_value(DIR_SECURITY);
    let certificate = security::parse_certificate_table(data, security_offset, security_size);

    let (tls_rva, _) = dir_value(DIR_TLS);
    let (tls_callbacks, tls_notes) = parse_tls_callbacks(
        data,
        &sections,
        h.size_of_headers,
        h.image_base,
        h.is_64,
        tls_rva,
    );
    notes.extend(tls_notes);

    let machine = machine_info(h.machine);
    let computed_checksum = headers::compute_checksum(data, h.optional_header_offset + 64);
    let entry_point_file_offset =
        headers::rva_to_offset_in(&sections, h.size_of_headers, h.entry_point);
    let is_dll = h.characteristics & 0x2000 != 0;
    let is_driver = h.subsystem == 1 || h.characteristics & 0x1000 != 0;
    let pe_kind = match h.magic {
        0x20b => "PE32+",
        0x10b => "PE32",
        0x107 => "PE32 ROM",
        _ => "PE",
    }
    .to_string();

    let timestamp = if h.time_date_stamp == 0 {
        None
    } else {
        DateTime::<Utc>::from_timestamp(h.time_date_stamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    };

    let raw_end = sections
        .iter()
        .filter(|s| s.raw_size > 0)
        .map(|s| s.raw_offset as u64 + s.raw_size as u64)
        .chain(std::iter::once(h.size_of_headers as u64))
        .max()
        .unwrap_or(0);
    let overlay = if (data.len() as u64) > raw_end {
        let size = data.len() as u64 - raw_end;
        let bytes = data.get(raw_end as usize..).unwrap_or(&[]);
        Some(OverlayInfo {
            offset: raw_end,
            size,
            entropy: Some(binscope_common::entropy(bytes)),
            sha256: data.get(raw_end as usize..).map(sha256_hex),
        })
    } else {
        None
    };
    if certificate.present && overlay.is_some() {
        notes.push("Overlay data includes the Authenticode certificate table.".to_string());
    }

    let mut info = PeInfo {
        pe_kind,
        is_64: h.is_64,
        machine: h.machine,
        machine_name: machine.0.to_string(),
        architecture: machine.1.to_string(),
        bits: machine.2,
        number_of_sections: h.number_of_sections,
        time_date_stamp: h.time_date_stamp,
        time_date_stamp_utc: timestamp,
        characteristics: h.characteristics,
        characteristic_names: headers::characteristic_names(h.characteristics),
        dll_characteristics: h.dll_characteristics,
        dll_characteristic_names: headers::dll_characteristic_names(h.dll_characteristics),
        image_base: h.image_base,
        entry_point_rva: h.entry_point,
        entry_point_file_offset,
        size_of_image: h.size_of_image,
        size_of_headers: h.size_of_headers,
        optional_header_offset: h.optional_header_offset,
        section_table_offset: h.section_table_offset,
        section_alignment: h.section_alignment,
        file_alignment: h.file_alignment,
        subsystem: h.subsystem,
        subsystem_name: types::subsystem_name(h.subsystem).to_string(),
        is_dll,
        is_driver,
        linker_version: format!("{}.{}", h.linker_major, h.linker_minor),
        os_version: format!("{}.{}", h.os_major, h.os_minor),
        image_version: format!("{}.{}", h.image_major, h.image_minor),
        subsystem_version: format!("{}.{}", h.subsystem_major, h.subsystem_minor),
        checksum: h.checksum,
        computed_checksum,
        checksum_valid: h.checksum != 0 && h.checksum == computed_checksum,
        number_of_rva_and_sizes: h.number_of_rva_and_sizes,
        data_directories: dirs,
        sections,
        exports_dll_name: export_out.dll_name,
        exports: export_out.exports,
        imports: import_out.libraries,
        delay_imports: delay_out.libraries,
        resources: resource_out.entries,
        version_info,
        manifest,
        pdb,
        codeview_records,
        debug_entries,
        pdb_path_warning,
        rich_header,
        clr,
        certificate,
        tls_callbacks,
        overlay,
        anomalies: Vec::new(),
        parse_notes: notes,
    };

    info.anomalies = anomalies::collect(&info, data, &h);
    Ok(info)
}

pub fn parse_default(data: &[u8]) -> Result<PeInfo, ParseError> {
    parse(data, 65_536)
}

fn parse_tls_callbacks(
    data: &[u8],
    sections: &[SectionInfo],
    size_of_headers: u32,
    image_base: u64,
    is_64: bool,
    tls_rva: u32,
) -> (Vec<u64>, Vec<String>) {
    let mut notes = Vec::new();
    let mut callbacks = Vec::new();
    if tls_rva == 0 {
        return (callbacks, notes);
    }
    let Some(base) = headers::rva_to_offset_in(sections, size_of_headers, tls_rva) else {
        notes.push("TLS directory RVA is not backed by file data".into());
        return (callbacks, notes);
    };
    let r = Reader::new(data);
    let callbacks_va = if is_64 {
        r.u64(base + 24, "TLS callbacks VA").unwrap_or(0)
    } else {
        r.u32(base + 12, "TLS callbacks VA").unwrap_or(0) as u64
    };
    if callbacks_va == 0 {
        return (callbacks, notes);
    }
    let Some(rva) = callbacks_va
        .checked_sub(image_base)
        .and_then(|v| u32::try_from(v).ok())
    else {
        notes.push("TLS callback array VA does not map into the image".into());
        return (callbacks, notes);
    };
    let Some(mut offset) = headers::rva_to_offset_in(sections, size_of_headers, rva) else {
        notes.push("TLS callback array RVA is not backed by file data".into());
        return (callbacks, notes);
    };
    let width = if is_64 { 8u64 } else { 4 };
    for _ in 0..64 {
        let va = if is_64 {
            r.u64(offset, "TLS callback").unwrap_or(0)
        } else {
            r.u32(offset, "TLS callback").unwrap_or(0) as u64
        };
        if va == 0 {
            break;
        }
        callbacks.push(va);
        offset += width;
    }
    if !callbacks.is_empty() {
        notes.push(format!(
            "{} TLS callback(s) are registered; their code is not executed or analyzed.",
            callbacks.len()
        ));
    }
    (callbacks, notes)
}

pub use fixture::PeBuilder;

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
