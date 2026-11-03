use binscope_common::{Reader, Result};
use binscope_pe::ClrDirectory;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DotNetError {
    #[error("CLR directory does not reference file-backed metadata")]
    UnmappedMetadata,
    #[error("metadata root signature is not BSJB")]
    InvalidMetadataSignature,
    #[error("metadata is truncated or malformed: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Common(#[from] binscope_common::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataStream {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssemblyIdentity {
    pub name: String,
    pub version: String,
    pub culture: Option<String>,
    pub public_key_size: u32,
    pub flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssemblyReference {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableRowCount {
    pub table: String,
    pub rows: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DotNetInfo {
    pub runtime_version: String,
    pub metadata_version: Option<String>,
    pub streams: Vec<MetadataStream>,
    pub flags: u32,
    pub flag_names: Vec<String>,
    pub entry_point_token: u32,
    pub entry_point_kind: String,
    pub strong_name_signed: bool,

    pub kind: String,
    pub assembly: Option<AssemblyIdentity>,
    pub module_name: Option<String>,
    pub assembly_references: Vec<AssemblyReference>,
    pub table_row_counts: Vec<TableRowCount>,
    pub type_definition_count: u32,
    pub method_definition_count: u32,
}

pub fn parse(data: &[u8], clr: &ClrDirectory) -> std::result::Result<DotNetInfo, DotNetError> {
    let meta_offset = clr
        .metadata_file_offset
        .ok_or(DotNetError::UnmappedMetadata)?;
    let r = Reader::new(data);
    if r.u32(meta_offset, "metadata signature")
        .map_err(DotNetError::Common)?
        != 0x424A_5342
    {
        return Err(DotNetError::InvalidMetadataSignature);
    }
    let version_len = r
        .u32(meta_offset + 12, "metadata version length")
        .map_err(DotNetError::Common)? as usize;
    if version_len > 1024 {
        return Err(DotNetError::Malformed(
            "metadata version string is too long",
        ));
    }
    let version_bytes = r
        .bytes(meta_offset + 16, version_len.min(256), "metadata version")
        .map_err(DotNetError::Common)?;
    let metadata_version = Some(
        String::from_utf8_lossy(version_bytes)
            .trim_end_matches('\0')
            .to_string(),
    );
    let version_padded = align4(version_len);
    let flags_off = meta_offset + 16 + version_padded as u64;
    let _metadata_flags = r.u16(flags_off, "metadata flags").unwrap_or(0);
    let stream_count = r
        .u16(flags_off + 2, "metadata stream count")
        .map_err(DotNetError::Common)?;
    if stream_count > 64 {
        return Err(DotNetError::Malformed("implausible metadata stream count"));
    }
    let mut streams = Vec::new();
    let mut cursor = flags_off + 4;
    for _ in 0..stream_count {
        let offset = r
            .u32(cursor, "stream offset")
            .map_err(DotNetError::Common)?;
        let size = r
            .u32(cursor + 4, "stream size")
            .map_err(DotNetError::Common)?;

        let name_bytes = r
            .bytes(cursor + 8, 32, "stream name")
            .map_err(DotNetError::Common)?;
        let end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        streams.push(MetadataStream { name, offset, size });
        cursor += 8 + align4(end + 1) as u64;
    }

    let mut table_stream = None;
    let mut strings = StreamSlice::default();
    let mut blobs = StreamSlice::default();
    for stream in &streams {
        let start = meta_offset + stream.offset as u64;
        let end = start.saturating_add(stream.size as u64);
        if end > data.len() as u64 {
            continue;
        }
        let slice = StreamSlice {
            start: start as usize,
            end: end as usize,
        };
        match stream.name.as_str() {
            "#~" | "#-" => table_stream = Some(slice),
            "#Strings" => strings = slice,
            "#Blob" => blobs = slice,
            _ => {}
        }
    }

    let tables = table_stream
        .and_then(|s| parse_tables(data, s))
        .ok_or(DotNetError::Malformed(
            "metadata table stream is missing or invalid",
        ))?;

    let mut table_row_counts = Vec::new();
    for (id, rows) in tables.row_counts.iter().enumerate() {
        if *rows > 0 && id < TABLE_NAMES.len() {
            table_row_counts.push(TableRowCount {
                table: TABLE_NAMES[id].to_string(),
                rows: *rows,
            });
        }
    }

    let type_definition_count = *tables.row_counts.get(2).unwrap_or(&0);
    let method_definition_count = *tables.row_counts.get(6).unwrap_or(&0);

    let assembly = read_assembly(data, &tables, strings, blobs);
    let module_name = read_module_name(data, &tables, strings);
    let assembly_references = read_assembly_refs(data, &tables, strings);

    let mut flag_names = Vec::new();
    const CLR_FLAGS: &[(u32, &str)] = &[
        (0x0000_0001, "ILONLY"),
        (0x0000_0002, "32BITREQUIRED"),
        (0x0000_0004, "IL_LIBRARY"),
        (0x0000_0008, "STRONGNAMESIGNED"),
        (0x0000_0010, "NATIVE_ENTRYPOINT"),
        (0x0001_0000, "TRACKDEBUGDATA"),
        (0x0002_0000, "32BITPREFERRED"),
    ];
    for (bit, name) in CLR_FLAGS {
        if clr.flags & bit != 0 {
            flag_names.push((*name).to_string());
        }
    }

    let kind = if clr.flags & 0x10 != 0 {
        "native_entry_point".to_string()
    } else if clr.flags & 0x1 != 0 {
        "managed".to_string()
    } else {
        "mixed_mode".to_string()
    };

    Ok(DotNetInfo {
        runtime_version: clr.runtime_version.clone(),
        metadata_version,
        streams,
        flags: clr.flags,
        flag_names,
        entry_point_token: clr.entry_point_token,
        entry_point_kind: clr.entry_point_kind.clone(),
        strong_name_signed: clr.strong_name_signed,
        kind,
        assembly,
        module_name,
        assembly_references,
        table_row_counts,
        type_definition_count,
        method_definition_count,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct StreamSlice {
    start: usize,
    end: usize,
}

impl StreamSlice {
    fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

struct Tables {
    row_counts: Vec<u32>,

    layout: Vec<(usize, usize, usize)>,
    heap_sizes: u8,
}

fn parse_tables(data: &[u8], stream: StreamSlice) -> Option<Tables> {
    if stream.end < stream.start + 24 {
        return None;
    }
    let bytes = &data[stream.start..stream.end];
    let r = Reader::new(bytes);
    let heap_sizes = r.u8(6, "heap sizes").ok()?;
    let valid = r.u64(8, "valid tables").ok()?;
    let mut row_counts = vec![0u32; 64];
    let mut cursor = 24usize;
    for (id, rows) in row_counts.iter_mut().enumerate() {
        if valid & (1u64 << id) != 0 {
            *rows = r.u32(cursor as u64, "row count").ok()?;
            cursor += 4;
        }
    }

    let mut layout = Vec::new();
    for id in 0..64 {
        if row_counts[id] == 0 {
            continue;
        }
        let size = row_size(&row_counts, heap_sizes, id)?;
        let absolute = stream.start + cursor;
        let total = size.checked_mul(row_counts[id] as usize)?;
        if cursor.checked_add(total)? > bytes.len() {
            return None;
        }
        layout.push((id, absolute, size));
        cursor += total;
    }
    Some(Tables {
        row_counts,
        layout,
        heap_sizes,
    })
}

fn table_rows(tables: &Tables, id: usize) -> Option<(usize, usize, u32)> {
    let (_, offset, size) = tables.layout.iter().find(|(t, _, _)| *t == id)?;
    Some((*offset, *size, tables.row_counts[id]))
}

fn string_index_size(heap_sizes: u8) -> usize {
    if heap_sizes & 0x01 != 0 {
        4
    } else {
        2
    }
}
fn guid_index_size(heap_sizes: u8) -> usize {
    if heap_sizes & 0x02 != 0 {
        4
    } else {
        2
    }
}
fn blob_index_size(heap_sizes: u8) -> usize {
    if heap_sizes & 0x04 != 0 {
        4
    } else {
        2
    }
}
fn simple_index_size(row_counts: &[u32], table: usize) -> usize {
    if *row_counts.get(table).unwrap_or(&0) >= 0x1_0000 {
        4
    } else {
        2
    }
}

fn coded_index_size(row_counts: &[u32], tables: &[usize], bits: u32) -> usize {
    let max = tables
        .iter()
        .filter_map(|t| row_counts.get(*t))
        .copied()
        .max()
        .unwrap_or(0) as usize;
    if max >= (1usize << (16 - bits)) {
        4
    } else {
        2
    }
}

#[derive(Clone, Copy)]
enum Col {
    U8,
    U16,
    U32,
    String,
    Guid,
    Blob,
    Table(usize),
    Coded(CodedSet),
}

#[derive(Clone, Copy)]
enum CodedSet {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

impl CodedSet {
    fn tables(self) -> &'static [usize] {
        match self {
            CodedSet::TypeDefOrRef => &[2, 1, 0x1b],
            CodedSet::HasConstant => &[4, 8, 0x17],
            CodedSet::HasCustomAttribute => &[
                6, 4, 1, 2, 8, 9, 0x0a, 0, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26,
                0x27, 0x28, 0x2a, 0x2c, 0x2b,
            ],
            CodedSet::HasFieldMarshal => &[4, 8],
            CodedSet::HasDeclSecurity => &[2, 6, 0x20],
            CodedSet::MemberRefParent => &[2, 1, 0x1a, 6, 0x1b],
            CodedSet::HasSemantics => &[0x14, 0x17],
            CodedSet::MethodDefOrRef => &[6, 0x0a],
            CodedSet::MemberForwarded => &[4, 6],
            CodedSet::Implementation => &[0x26, 0x23, 0x27],
            CodedSet::CustomAttributeType => &[6, 0x0a],
            CodedSet::ResolutionScope => &[0, 0x1a, 0x23, 1],
            CodedSet::TypeOrMethodDef => &[2, 6],
        }
    }

    fn bits(self) -> u32 {
        match self {
            CodedSet::TypeDefOrRef => 2,
            CodedSet::HasConstant => 2,
            CodedSet::HasCustomAttribute => 5,
            CodedSet::HasFieldMarshal => 1,
            CodedSet::HasDeclSecurity => 2,
            CodedSet::MemberRefParent => 3,
            CodedSet::HasSemantics => 1,
            CodedSet::MethodDefOrRef => 1,
            CodedSet::MemberForwarded => 1,
            CodedSet::Implementation => 2,
            CodedSet::CustomAttributeType => 3,
            CodedSet::ResolutionScope => 2,
            CodedSet::TypeOrMethodDef => 1,
        }
    }
}

fn row_size(row_counts: &[u32], heap_sizes: u8, id: usize) -> Option<usize> {
    use CodedSet::*;
    use Col::*;
    let schema: Vec<Col> = match id {
        0x00 => vec![U16, String, Guid, Guid, Guid],
        0x01 => vec![Coded(ResolutionScope), String, String],
        0x02 => vec![U32, String, String, Coded(TypeDefOrRef), Table(4), Table(6)],
        0x03 => vec![Table(4)],
        0x04 => vec![U16, String, Blob],
        0x05 => vec![Table(6)],
        0x06 => vec![U32, U16, U16, String, Blob, Table(8)],
        0x07 => vec![Table(8)],
        0x08 => vec![U16, U16, String],
        0x09 => vec![Table(2), Coded(TypeDefOrRef)],
        0x0a => vec![Coded(MemberRefParent), String, Blob],
        0x0b => vec![U8, U8, Coded(HasConstant), Blob],
        0x0c => vec![Coded(HasCustomAttribute), Coded(CustomAttributeType), Blob],
        0x0d => vec![Coded(HasFieldMarshal), Blob],
        0x0e => vec![U16, Coded(HasDeclSecurity), Blob],
        0x0f => vec![U16, U32, Table(2)],
        0x10 => vec![U32, Table(4)],
        0x11 => vec![Blob],
        0x12 => vec![Table(2), Table(0x14)],
        0x13 => vec![Table(0x14)],
        0x14 => vec![U16, String, Coded(TypeDefOrRef)],
        0x15 => vec![Table(2), Table(0x17)],
        0x16 => vec![Table(0x17)],
        0x17 => vec![U16, String, Blob],
        0x18 => vec![U16, Table(6), Coded(HasSemantics)],
        0x19 => vec![Table(2), Coded(MethodDefOrRef), Coded(MethodDefOrRef)],
        0x1a => vec![String],
        0x1b => vec![Blob],
        0x1c => vec![U16, Coded(MemberForwarded), String, Table(0x1a)],
        0x1d => vec![U32, Table(4)],
        0x1e => vec![U32, U32],
        0x1f => vec![U32],
        0x20 => vec![U32, U16, U16, U16, U16, U32, Blob, String, String],
        0x21 => vec![U32],
        0x22 => vec![U32, U32, U32],
        0x23 => vec![U16, U16, U16, U16, U32, Blob, String, String, Blob],
        0x24 => vec![U32, Table(0x23)],
        0x25 => vec![U32, U32, U32, Table(0x23)],
        0x26 => vec![U32, String, Blob],
        0x27 => vec![U32, U32, String, String, Coded(Implementation)],
        0x28 => vec![U32, U32, String, Coded(Implementation)],
        0x29 => vec![Table(2), Table(2)],
        0x2a => vec![U16, U16, Coded(TypeOrMethodDef), String],
        0x2b => vec![Coded(MethodDefOrRef), Blob],
        0x2c => vec![Table(0x2a), Coded(TypeDefOrRef)],
        _ => return None,
    };
    let mut size = 0usize;
    for col in schema {
        size += match col {
            U8 => 1,
            U16 => 2,
            U32 => 4,
            String => string_index_size(heap_sizes),
            Guid => guid_index_size(heap_sizes),
            Blob => blob_index_size(heap_sizes),
            Table(t) => simple_index_size(row_counts, t),
            Coded(set) => coded_index_size(row_counts, set.tables(), set.bits()),
        };
    }
    Some(size)
}

fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn index(data: &[u8], offset: usize, size: usize) -> Option<u32> {
    match size {
        2 => read_u16_at(data, offset).map(|v| v as u32),
        4 => read_u32_at(data, offset),
        _ => None,
    }
}

fn read_string(data: &[u8], heap: StreamSlice, index: u32, heap_sizes: u8) -> Option<String> {
    if heap.is_empty() {
        return None;
    }
    let start = heap.start + index as usize;
    if start >= heap.end {
        return None;
    }
    let _ = heap_sizes;
    let end = data[start..heap.end]
        .iter()
        .position(|&b| b == 0)
        .map(|n| start + n)
        .unwrap_or(heap.end);
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fn read_blob_len(data: &[u8], heap: StreamSlice, index: u32) -> Option<u32> {
    if heap.is_empty() {
        return None;
    }
    let start = heap.start + index as usize;
    if start >= heap.end {
        return None;
    }
    let first = data[start];
    if first & 0x80 == 0 {
        Some((first & 0x7f) as u32)
    } else if first & 0xc0 == 0x80 {
        let second = *data.get(start + 1)?;
        Some((((first & 0x3f) as u32) << 8) | second as u32)
    } else {
        let b = data.get(start + 1..start + 4)?;
        Some(
            (((first & 0x1f) as u32) << 24)
                | ((b[0] as u32) << 16)
                | ((b[1] as u32) << 8)
                | b[2] as u32,
        )
    }
}

fn read_assembly(
    data: &[u8],
    tables: &Tables,
    strings: StreamSlice,
    blobs: StreamSlice,
) -> Option<AssemblyIdentity> {
    let (offset, size, rows) = table_rows(tables, 0x20)?;
    if rows == 0 {
        return None;
    }
    let s = string_index_size(tables.heap_sizes);
    let b = blob_index_size(tables.heap_sizes);
    let name_index = read_u16_at(data, offset + 4 + 8 + 4 + b)? as u32;
    let _ = size;
    let _ = tables.heap_sizes;
    let culture_index = read_u16_at(data, offset + 4 + 8 + 4 + b + s)? as u32;
    let public_key_index = index(data, offset + 4 + 8 + 4, b)?;
    let flags = read_u32_at(data, offset + 4 + 8)?;
    let major = read_u16_at(data, offset + 4)?;
    let minor = read_u16_at(data, offset + 6)?;
    let build = read_u16_at(data, offset + 8)?;
    let revision = read_u16_at(data, offset + 10)?;
    let name = read_string(data, strings, name_index, tables.heap_sizes)
        .unwrap_or_else(|| "<unreadable>".to_string());
    let culture = if culture_index == 0 {
        None
    } else {
        read_string(data, strings, culture_index, tables.heap_sizes)
    };
    let public_key_size = read_blob_len(data, blobs, public_key_index).unwrap_or(0);
    Some(AssemblyIdentity {
        name,
        version: format!("{major}.{minor}.{build}.{revision}"),
        culture,
        public_key_size,
        flags,
    })
}

fn read_module_name(data: &[u8], tables: &Tables, strings: StreamSlice) -> Option<String> {
    let (offset, _, rows) = table_rows(tables, 0x00)?;
    if rows == 0 {
        return None;
    }
    let s = string_index_size(tables.heap_sizes);
    let name_index = if s == 2 {
        read_u16_at(data, offset + 2).map(|v| v as u32)
    } else {
        read_u32_at(data, offset + 2)
    };
    name_index.and_then(|idx| read_string(data, strings, idx, tables.heap_sizes))
}

fn read_assembly_refs(
    data: &[u8],
    tables: &Tables,
    strings: StreamSlice,
) -> Vec<AssemblyReference> {
    let Some((offset, size, rows)) = table_rows(tables, 0x23) else {
        return Vec::new();
    };
    let s = string_index_size(tables.heap_sizes);
    let b = blob_index_size(tables.heap_sizes);
    let mut out = Vec::new();
    for i in 0..rows.min(256) as usize {
        let row = offset + i * size;
        let major = read_u16_at(data, row).unwrap_or(0);
        let minor = read_u16_at(data, row + 2).unwrap_or(0);
        let build = read_u16_at(data, row + 4).unwrap_or(0);
        let revision = read_u16_at(data, row + 6).unwrap_or(0);
        let name_index = index(data, row + 12 + b, s).unwrap_or(0);
        let name = read_string(data, strings, name_index, tables.heap_sizes)
            .unwrap_or_else(|| "<unreadable>".to_string());
        out.push(AssemblyReference {
            name,
            version: format!("{major}.{minor}.{build}.{revision}"),
        });
    }
    out
}

fn align4(v: usize) -> usize {
    (v + 3) & !3
}

const TABLE_NAMES: [&str; 45] = [
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRVA",
    "EncLog",
    "EncMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
];

#[allow(dead_code)]
fn unused_result(_: Result<()>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use binscope_pe::{parse_default, PeBuilder};

    fn analyze(builder: PeBuilder) -> DotNetInfo {
        let data = builder.build();
        let pe = parse_default(&data).expect("PE");
        let clr = pe.clr.expect("CLR");
        parse(&data, &clr).expect("dotnet")
    }

    #[test]
    fn managed_assembly_metadata_is_parsed() {
        let info = analyze(PeBuilder::pe32().with_clr(0x1 | 0x8));
        assert_eq!(info.kind, "managed");
        assert_eq!(info.runtime_version, "v2.5");
        assert_eq!(info.metadata_version.as_deref(), Some("v4.0.30319"));
        assert_eq!(info.assembly.as_ref().unwrap().name, "FixtureAssembly");
        assert_eq!(info.assembly.as_ref().unwrap().version, "1.0.0.0");
        assert_eq!(info.module_name.as_deref(), Some("FixtureModule"));
        assert!(info.streams.iter().any(|s| s.name == "#~"));
        assert!(info.streams.iter().any(|s| s.name == "#Strings"));
        assert!(info.strong_name_signed);
        assert_eq!(info.entry_point_kind, "MethodDef token 0x06000001 (row 1)");
    }

    #[test]
    fn native_entrypoint_is_classified() {
        let info = analyze(PeBuilder::pe32().with_clr(0x10));
        assert_eq!(info.kind, "native_entry_point");
    }

    #[test]
    fn missing_metadata_is_an_error() {
        let mut clr = binscope_pe::ClrDirectory {
            header_size: 72,
            runtime_version: "v4.0".into(),
            metadata_rva: 0,
            metadata_size: 0,
            metadata_file_offset: None,
            flags: 1,
            flag_names: vec![],
            entry_point_token: 0,
            entry_point_kind: "none".into(),
            resources_rva: 0,
            resources_size: 0,
            strong_name_rva: 0,
            strong_name_size: 0,
            strong_name_signed: false,
            metadata_version: None,
        };
        assert!(matches!(
            parse(&[0u8; 16], &clr),
            Err(DotNetError::UnmappedMetadata)
        ));
        clr.metadata_file_offset = Some(0);
        assert!(matches!(
            parse(&[0u8; 16], &clr),
            Err(DotNetError::Common(_)) | Err(DotNetError::InvalidMetadataSignature)
        ));
    }
}
