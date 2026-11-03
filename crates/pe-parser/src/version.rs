use crate::types::{KeyValue, VersionInfo};
use binscope_common::Reader;

const MAX_NODES: usize = 512;
const MAX_DEPTH: usize = 4;

struct Node {
    key: String,
    value_offset: usize,
    value_len_bytes: usize,
    w_type: u16,
    end: usize,
    children_offset: usize,
}

fn align4(v: usize) -> usize {
    (v + 3) & !3
}

fn parse_node(data: &[u8], offset: usize, hard_end: usize) -> Option<Node> {
    if offset + 6 > hard_end || offset + 6 > data.len() {
        return None;
    }
    let r = Reader::new(data);
    let length = r.u16(offset as u64, "version node length").ok()? as usize;
    let value_length = r.u16(offset as u64 + 2, "version value length").ok()? as usize;
    let w_type = r.u16(offset as u64 + 4, "version value type").ok()?;
    if length < 6 {
        return None;
    }
    let end = offset.saturating_add(length).min(hard_end).min(data.len());
    if end <= offset {
        return None;
    }

    let key_start = offset + 6;
    let mut p = key_start;
    let mut key_units = Vec::new();
    while p + 2 <= end {
        let u = u16::from_le_bytes([data[p], data[p + 1]]);
        if u == 0 {
            p += 2;
            break;
        }
        if key_units.len() >= 256 {
            return None;
        }
        key_units.push(u);
        p += 2;
    }
    if p + 2 > end && key_units.is_empty() {
        return None;
    }
    let key = String::from_utf16_lossy(&key_units);

    let value_offset = align4(p);
    let value_len_bytes = if w_type == 1 {
        value_length.saturating_mul(2)
    } else {
        value_length
    };
    let value_end = value_offset.saturating_add(value_len_bytes).min(end);
    let children_offset = align4(value_end).min(end);

    Some(Node {
        key,
        value_offset,
        value_len_bytes: value_end.saturating_sub(value_offset),
        w_type,
        end,
        children_offset,
    })
}

fn child_nodes(data: &[u8], node: &Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut offset = node.children_offset;
    let mut count = 0;
    while offset + 6 <= node.end && count < MAX_NODES {
        let Some(child) = parse_node(data, offset, node.end) else {
            break;
        };
        if child.end <= offset {
            break;
        }
        offset = align4(child.end);
        out.push(child);
        count += 1;
        if offset >= node.end {
            break;
        }
    }
    out
}

fn decode_key_string(data: &[u8], node: &Node) -> Option<String> {
    if node.w_type != 1 {
        return None;
    }
    let bytes = data.get(node.value_offset..node.value_offset + node.value_len_bytes)?;
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    Some(String::from_utf16_lossy(&units))
}

fn fixed_version(ms: u32, ls: u32) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
}

pub fn parse_version_info(data: &[u8]) -> Option<VersionInfo> {
    let root = parse_node(data, 0, data.len())?;
    if !root.key.eq_ignore_ascii_case("VS_VERSION_INFO") {
        return None;
    }
    let r = Reader::new(data);
    let mut info = VersionInfo::default();

    if root.value_len_bytes >= 52 {
        let sig = r.u32(root.value_offset as u64, "VS_FIXEDFILEINFO").ok()?;
        if sig == 0xFEEF_04BD {
            let fms = r
                .u32(root.value_offset as u64 + 8, "file version MS")
                .ok()?;
            let fls = r
                .u32(root.value_offset as u64 + 12, "file version LS")
                .ok()?;
            let pms = r
                .u32(root.value_offset as u64 + 16, "product version MS")
                .ok()?;
            let pls = r
                .u32(root.value_offset as u64 + 20, "product version LS")
                .ok()?;
            info.fixed_file_version = Some(fixed_version(fms, fls));
            info.fixed_product_version = Some(fixed_version(pms, pls));
        }
    }

    let mut stack: Vec<(Node, usize)> = child_nodes(data, &root)
        .into_iter()
        .map(|n| (n, 1))
        .collect();
    let mut visited = 0usize;
    while let Some((node, depth)) = stack.pop() {
        visited += 1;
        if visited > MAX_NODES {
            break;
        }
        let children = if depth < MAX_DEPTH {
            child_nodes(data, &node)
        } else {
            Vec::new()
        };
        if node.key.eq_ignore_ascii_case("StringFileInfo")
            || node.key.eq_ignore_ascii_case("VarFileInfo")
        {
            for child in children {
                stack.push((child, depth + 1));
            }
            continue;
        }
        if node.w_type == 1 && !children.is_empty() {
            for child in children {
                stack.push((child, depth + 1));
            }
            continue;
        }
        if node.w_type == 1 {
            if let Some(value) = decode_key_string(data, &node) {
                if node.key.is_empty() || value.is_empty() {
                    continue;
                }
                let exists = info
                    .entries
                    .iter()
                    .any(|kv| kv.key.eq_ignore_ascii_case(&node.key));
                if !exists {
                    info.entries.push(KeyValue {
                        key: node.key.clone(),
                        value: value.clone(),
                    });
                    let key_lower = node.key.to_ascii_lowercase();
                    match key_lower.as_str() {
                        "companyname" => info.company_name = Some(value),
                        "productname" => info.product_name = Some(value),
                        "filedescription" => info.file_description = Some(value),
                        "fileversion" => info.file_version = Some(value),
                        "productversion" => info.product_version = Some(value),
                        "internalname" => info.internal_name = Some(value),
                        "originalfilename" => info.original_filename = Some(value),
                        "legalcopyright" => info.legal_copyright = Some(value),
                        "comments" => info.comments = Some(value),
                        _ => {}
                    }
                }
            }
            continue;
        }
        for child in children {
            stack.push((child, depth + 1));
        }
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend([0, 0]);
        v
    }

    fn node(key: &str, w_type: u16, value_bytes: Vec<u8>, children: Vec<u8>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(wide(key));
        while (6 + body.len()) % 4 != 0 {
            body.push(0);
        }
        body.extend(&value_bytes);
        while (6 + body.len()) % 4 != 0 {
            body.push(0);
        }
        body.extend(&children);
        let mut out = Vec::new();
        let total = 6 + body.len();
        out.extend((total as u16).to_le_bytes());
        let value_len = if w_type == 1 {
            (value_bytes.len() / 2) as u16
        } else {
            value_bytes.len() as u16
        };
        out.extend(value_len.to_le_bytes());
        out.extend(w_type.to_le_bytes());
        out.extend(body);
        while out.len() % 4 != 0 {
            out.push(0);
        }

        let total = out.len() as u16;
        out[0..2].copy_from_slice(&total.to_le_bytes());
        out
    }

    #[test]
    fn parses_string_file_info_and_fixed_version() {
        let mut fixed = vec![0u8; 52];
        fixed[0..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
        fixed[8..12].copy_from_slice(&0x0001_0002u32.to_le_bytes());
        fixed[12..16].copy_from_slice(&0x0003_0004u32.to_le_bytes());
        fixed[16..20].copy_from_slice(&0x0005_0006u32.to_le_bytes());
        fixed[20..24].copy_from_slice(&0x0007_0008u32.to_le_bytes());

        let company = node("CompanyName", 1, wide("BinScope Labs"), vec![]);
        let desc = node("FileDescription", 1, wide("Test binary"), vec![]);
        let mut strings = Vec::new();
        strings.extend(company);
        strings.extend(desc);
        let table = node("040904B0", 1, Vec::new(), strings);
        let sfi = node("StringFileInfo", 1, Vec::new(), table);
        let root = node("VS_VERSION_INFO", 0, fixed, sfi);

        let info = parse_version_info(&root).expect("version info");
        assert_eq!(info.fixed_file_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(info.fixed_product_version.as_deref(), Some("5.6.7.8"));
        assert_eq!(info.company_name.as_deref(), Some("BinScope Labs"));
        assert_eq!(info.file_description.as_deref(), Some("Test binary"));
        assert_eq!(info.entries.len(), 2);
    }

    #[test]
    fn rejects_random_data() {
        assert!(parse_version_info(&[0u8; 64]).is_none());
        assert!(parse_version_info(b"not a version resource").is_none());
    }
}
