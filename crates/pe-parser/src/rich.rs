use crate::types::{RichEntry, RichHeaderInfo};
use binscope_common::Reader;

const MAX_ENTRIES: usize = 512;

pub fn parse_rich_header(data: &[u8], pe_offset: u64) -> Option<RichHeaderInfo> {
    let limit = (pe_offset as usize).min(data.len());
    if limit < 0x40 {
        return None;
    }
    let hay = &data[..limit];
    let rich_pos = hay.windows(4).rposition(|w| w == b"Rich")?;
    if rich_pos + 8 > hay.len() {
        return None;
    }
    let key = u32::from_le_bytes([
        hay[rich_pos + 4],
        hay[rich_pos + 5],
        hay[rich_pos + 6],
        hay[rich_pos + 7],
    ]);

    let dans = hay.windows(4).position(|w| {
        let decoded = [
            w[0] ^ (key & 0xff) as u8,
            w[1] ^ ((key >> 8) & 0xff) as u8,
            w[2] ^ ((key >> 16) & 0xff) as u8,
            w[3] ^ ((key >> 24) & 0xff) as u8,
        ];
        &decoded == b"DanS"
    })?;
    if dans + 16 > rich_pos {
        return None;
    }
    let r = Reader::new(data);
    let mut entries = Vec::new();
    let mut offset = (dans + 16) as u64;
    while offset + 8 <= rich_pos as u64 && entries.len() < MAX_ENTRIES {
        let comp_id = match r.u32(offset, "rich entry") {
            Ok(v) => v ^ key,
            Err(_) => break,
        };
        let count = match r.u32(offset + 4, "rich entry count") {
            Ok(v) => v ^ key,
            Err(_) => break,
        };
        entries.push(RichEntry {
            product_id: (comp_id >> 16) as u16,
            build_number: (comp_id & 0xffff) as u16,
            count,
        });
        offset += 8;
    }
    let mut product_ids: Vec<u16> = entries.iter().map(|e| e.product_id).collect();
    product_ids.sort_unstable();
    product_ids.dedup();

    Some(RichHeaderInfo {
        offset: dans as u64,
        key,
        entries,
        product_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_synthetic_rich_header() {
        let key: u32 = 0x1a2b3c4d;
        let mut data = vec![0u8; 0x40];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x200u32.to_le_bytes());

        for i in 0..4 {
            let word = if i == 0 {
                u32::from_le_bytes(*b"DanS")
            } else {
                0
            };
            data.extend((word ^ key).to_le_bytes());
        }

        let e1 = (0x00C9u32 << 16) | 30319;
        let e2 = (0x00FFu32 << 16) | 1234;
        data.extend((e1 ^ key).to_le_bytes());
        data.extend((3u32 ^ key).to_le_bytes());
        data.extend((e2 ^ key).to_le_bytes());
        data.extend((5u32 ^ key).to_le_bytes());
        data.extend(b"Rich");
        data.extend(key.to_le_bytes());

        let rich = parse_rich_header(&data, 0x200).expect("rich header");
        assert_eq!(rich.key, key);
        assert_eq!(rich.entries.len(), 2);
        assert_eq!(rich.entries[0].product_id, 0x00C9);
        assert_eq!(rich.entries[0].build_number, 30319);
        assert_eq!(rich.entries[0].count, 3);
        assert_eq!(rich.product_ids, vec![0x00C9, 0x00FF]);
    }

    #[test]
    fn absent_rich_header_is_none() {
        assert!(parse_rich_header(&[0u8; 512], 0x200).is_none());
    }
}
