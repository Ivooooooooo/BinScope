pub mod classify;

use binscope_common::{CancelToken, Deadline, Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

pub const MAX_STRING_LEN: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
}

impl StringEncoding {
    pub fn label(self) -> &'static str {
        match self {
            StringEncoding::Ascii => "ASCII",
            StringEncoding::Utf8 => "UTF-8",
            StringEncoding::Utf16Le => "UTF-16LE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: StringEncoding,
    pub value: String,

    pub truncated: bool,

    #[serde(default)]
    pub section: Option<String>,

    #[serde(default)]
    pub classifications: Vec<classify::StringClassification>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StringOptions {
    pub min_len: usize,
    pub max_strings: usize,
    pub max_bytes: usize,
    pub include_ascii: bool,
    pub include_utf16le: bool,
    pub chunk_size: usize,
}

impl Default for StringOptions {
    fn default() -> Self {
        Self {
            min_len: 4,
            max_strings: 200_000,
            max_bytes: 32 * 1024 * 1024,
            include_ascii: true,
            include_utf16le: true,
            chunk_size: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StringsResult {
    pub items: Vec<ExtractedString>,

    pub total_found: u64,

    pub truncated: bool,
    pub bytes_scanned: u64,
    pub elapsed_ms: u64,
    pub min_len: usize,
}

impl StringsResult {
    pub fn count_by_encoding(&self) -> (usize, usize, usize) {
        let ascii = self
            .items
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .count();
        let utf8 = self
            .items
            .iter()
            .filter(|s| s.encoding == StringEncoding::Utf8)
            .count();
        (ascii, utf8, self.items.len() - ascii - utf8)
    }
}

fn is_ascii_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

fn is_utf16_printable(u: u16) -> bool {
    matches!(u, 0x0020..=0x007E | 0x00A0..=0x00FF)
}

struct Collector<'o> {
    opts: &'o StringOptions,
    items: Vec<ExtractedString>,
    bytes: usize,
    total_found: u64,
    truncated: bool,
}

impl<'o> Collector<'o> {
    fn new(opts: &'o StringOptions) -> Self {
        Self {
            opts,
            items: Vec::new(),
            bytes: 0,
            total_found: 0,
            truncated: false,
        }
    }

    fn full(&self) -> bool {
        self.items.len() >= self.opts.max_strings || self.bytes >= self.opts.max_bytes
    }

    fn push(&mut self, encoding: StringEncoding, offset: u64, bytes: &[u8], truncated: bool) {
        self.total_found += 1;
        if self.full() {
            self.truncated = true;
            return;
        }

        let value = String::from_utf8_lossy(bytes).into_owned();
        self.bytes = self.bytes.saturating_add(value.len());
        self.items.push(ExtractedString {
            offset,
            encoding,
            value,
            truncated,
            section: None,
            classifications: Vec::new(),
        });
        if self.full() {
            self.truncated = true;
        }
    }

    fn push_decoded(
        &mut self,
        encoding: StringEncoding,
        offset: u64,
        value: String,
        truncated: bool,
    ) {
        self.total_found += 1;
        if self.full() {
            self.truncated = true;
            return;
        }
        self.bytes = self.bytes.saturating_add(value.len());
        self.items.push(ExtractedString {
            offset,
            encoding,
            value,
            truncated,
            section: None,
            classifications: Vec::new(),
        });
        if self.full() {
            self.truncated = true;
        }
    }
}

#[derive(Default)]
struct AsciiState {
    run: Vec<u8>,
    start: u64,
    active: bool,
    truncated: bool,
}

impl AsciiState {
    fn flush(&mut self, out: &mut Collector<'_>, min_len: usize) {
        if self.active {
            if self.run.len() >= min_len {
                out.push(StringEncoding::Ascii, self.start, &self.run, self.truncated);
            }
            self.run.clear();
            self.active = false;
            self.truncated = false;
        }
    }
}

#[derive(Default)]
struct Utf16State {
    run: Vec<u8>,
    start: u64,
    active: bool,
    truncated: bool,

    pending: Option<(u8, u64)>,
}

impl Utf16State {
    fn flush(&mut self, out: &mut Collector<'_>, min_len: usize) {
        if self.active {
            let units = self.run.len() / 2;
            if units >= min_len {
                let mut value = String::with_capacity(units);
                for chunk in self.run.chunks_exact(2) {
                    let u = u16::from_le_bytes([chunk[0], chunk[1]]);
                    value.push(char::from_u32(u as u32).unwrap_or('\u{FFFD}'));
                }
                out.push_decoded(StringEncoding::Utf16Le, self.start, value, self.truncated);
            }
            self.run.clear();
            self.active = false;
            self.truncated = false;
        }
    }
}

pub fn extract_file(
    path: &Path,
    opts: &StringOptions,
    cancel: &CancelToken,
    deadline: Option<&Deadline>,
) -> Result<StringsResult> {
    let file = File::open(path).map_err(Error::Io)?;
    extract_reader(file, opts, cancel, deadline)
}

pub fn extract_reader<R: Read>(
    mut reader: R,
    opts: &StringOptions,
    cancel: &CancelToken,
    deadline: Option<&Deadline>,
) -> Result<StringsResult> {
    let started = Instant::now();
    if opts.chunk_size == 0 {
        return Err(Error::Invalid("chunk size must be > 0".into()));
    }
    if opts.min_len == 0 || opts.min_len > MAX_STRING_LEN {
        return Err(Error::Invalid(format!(
            "min string length must be between 1 and {MAX_STRING_LEN}"
        )));
    }

    let chunk_size = opts.chunk_size;
    let mut buf = vec![0u8; chunk_size];
    let mut collector = Collector::new(opts);
    let mut ascii = AsciiState::default();
    let mut wide = Utf16State::default();
    let mut base_offset: u64 = 0;

    'read: loop {
        cancel.check()?;
        if let Some(d) = deadline {
            d.check()?;
        }
        let n = reader.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];

        if opts.include_ascii {
            for (i, &b) in chunk.iter().enumerate() {
                if is_ascii_printable(b) {
                    if !ascii.active {
                        ascii.active = true;
                        ascii.start = base_offset + i as u64;
                    }
                    if ascii.run.len() < MAX_STRING_LEN {
                        ascii.run.push(b);
                    } else {
                        ascii.truncated = true;
                    }
                } else {
                    ascii.flush(&mut collector, opts.min_len);
                    if collector.truncated && collector.full() {
                        break 'read;
                    }
                }
            }
        }

        if opts.include_utf16le {
            let mut i = 0usize;
            if let Some((lo, off)) = wide.pending.take() {
                if n > 0 {
                    let u = u16::from_le_bytes([lo, chunk[0]]);
                    process_utf16_unit(u, off, &mut wide, &mut collector, opts.min_len);
                    i = 1;
                } else {
                    wide.pending = Some((lo, off));
                }
            }
            while i + 1 < n {
                let u = u16::from_le_bytes([chunk[i], chunk[i + 1]]);
                process_utf16_unit(
                    u,
                    base_offset + i as u64,
                    &mut wide,
                    &mut collector,
                    opts.min_len,
                );
                i += 2;
            }
            if i < n {
                wide.pending = Some((chunk[i], base_offset + i as u64));
            }
        }

        base_offset = base_offset.saturating_add(n as u64);
        if collector.full() {
            break;
        }
    }

    if opts.include_ascii {
        ascii.flush(&mut collector, opts.min_len);
    }
    if opts.include_utf16le {
        wide.flush(&mut collector, opts.min_len);
        wide.pending = None;
    }

    let mut items = collector.items;
    items.sort_by_key(|s| (s.offset, s.encoding as u8));

    Ok(StringsResult {
        items,
        total_found: collector.total_found,
        truncated: collector.truncated,
        bytes_scanned: base_offset,
        elapsed_ms: started.elapsed().as_millis() as u64,
        min_len: opts.min_len,
    })
}

fn process_utf16_unit(
    u: u16,
    offset: u64,
    wide: &mut Utf16State,
    collector: &mut Collector<'_>,
    min_len: usize,
) {
    if is_utf16_printable(u) {
        if !wide.active {
            wide.active = true;
            wide.start = offset;
        }
        if wide.run.len() < MAX_STRING_LEN {
            wide.run.extend_from_slice(&u.to_le_bytes());
        } else {
            wide.truncated = true;
        }
    } else {
        wide.flush(collector, min_len);
    }
}

pub fn filter_strings<'a>(items: &'a [ExtractedString], needle: &str) -> Vec<&'a ExtractedString> {
    let needle = needle.to_ascii_lowercase();
    items
        .iter()
        .filter(|s| s.value.to_ascii_lowercase().contains(&needle))
        .collect()
}

pub fn extract_utf8_bytes(data: &[u8], min_len: usize, max_len: usize) -> Vec<ExtractedString> {
    const MAX_UTF8_ITEMS: usize = 20_000;
    let max_len = max_len.clamp(4, MAX_STRING_LEN);
    let mut items = Vec::new();
    let mut index = 0usize;
    while index < data.len() && items.len() < MAX_UTF8_ITEMS {
        let start = index;
        let mut end = index;
        let mut chars = 0usize;
        let mut has_multibyte = false;
        while index < data.len() && end - start < max_len {
            match decode_utf8_char(&data[index..]) {
                Some((character, width)) if !character.is_control() && character != '\u{FFFD}' => {
                    has_multibyte |= width > 1;
                    index += width;
                    chars += 1;
                    end = index;
                }
                _ => break,
            }
        }
        if end > start && has_multibyte && chars >= min_len {
            let value = String::from_utf8_lossy(&data[start..end]).into_owned();
            items.push(ExtractedString {
                offset: start as u64,
                encoding: StringEncoding::Utf8,
                value,
                truncated: end - start >= max_len,
                section: None,
                classifications: Vec::new(),
            });
        }
        if index == start {
            index += 1;
        }
    }
    items
}

pub fn classify_items(items: &mut [ExtractedString]) {
    for item in items {
        item.classifications = classify::classify(&item.value);
    }
}

fn decode_utf8_char(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    let width = if first < 0x80 {
        1
    } else if first & 0xE0 == 0xC0 {
        2
    } else if first & 0xF0 == 0xE0 {
        3
    } else if first & 0xF8 == 0xF0 {
        4
    } else {
        return None;
    };
    if bytes.len() < width {
        return None;
    }
    let text = std::str::from_utf8(&bytes[..width]).ok()?;
    text.chars().next().map(|character| (character, width))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn extract(data: &[u8], chunk: usize, min_len: usize) -> StringsResult {
        let opts = StringOptions {
            min_len,
            chunk_size: chunk,
            ..Default::default()
        };
        extract_reader(Cursor::new(data), &opts, &CancelToken::new(), None).unwrap()
    }

    fn values(r: &StringsResult) -> Vec<&str> {
        r.items.iter().map(|s| s.value.as_str()).collect()
    }

    #[test]
    fn ascii_strings_are_found_with_offsets() {
        let data = b"\x00\x01Hello, world!\x00abc\x00toolongstring";
        let r = extract(data, 4, 3);
        let items: Vec<_> = r
            .items
            .iter()
            .map(|s| (s.offset, s.value.as_str()))
            .collect();
        assert_eq!(
            items,
            vec![(2, "Hello, world!"), (16, "abc"), (20, "toolongstring")]
        );
    }

    #[test]
    fn short_strings_are_filtered() {
        let r = extract(b"abc\x00abcd\x00", 8, 4);
        assert_eq!(values(&r), vec!["abcd"]);
    }

    #[test]
    fn utf16le_strings_are_found() {
        let mut data = vec![0u8, 0u8];
        data.extend("Hello".encode_utf16().flat_map(|u| u.to_le_bytes()));
        data.extend([0u8, 0]);
        data.extend("Café".encode_utf16().flat_map(|u| u.to_le_bytes()));
        data.extend([0u8, 0]);
        let r = extract(&data, 3, 4);
        assert_eq!(values(&r), vec!["Hello", "Café"]);
        assert_eq!(r.items[0].offset, 2);
        assert_eq!(r.items[1].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn strings_split_across_chunks_are_reported_once() {
        let data = b"prefix\x00cross-boundary-string\x00end";
        for chunk in [1usize, 2, 3, 7, 8, 13, 64] {
            let r = extract(data, chunk, 3);
            assert_eq!(
                values(&r),
                vec!["prefix", "cross-boundary-string", "end"],
                "chunk size {chunk}"
            );
        }
    }

    #[test]
    fn utf16_strings_split_across_chunks_are_reported_once() {
        let mut data = b"xx".to_vec();
        data.extend("BoundaryWide".encode_utf16().flat_map(|u| u.to_le_bytes()));
        data.extend([0u8, 0]);
        for chunk in [1usize, 2, 3, 5, 7] {
            let r = extract(&data, chunk, 4);
            let wide: Vec<_> = r
                .items
                .iter()
                .filter(|s| s.encoding == StringEncoding::Utf16Le)
                .map(|s| s.value.as_str())
                .collect();
            assert_eq!(wide, vec!["BoundaryWide"], "chunk size {chunk}");
        }
    }

    #[test]
    fn limits_are_enforced() {
        let opts = StringOptions {
            min_len: 4,
            max_strings: 2,
            chunk_size: 8,
            ..Default::default()
        };
        let data = b"aaaa\x00bbbb\x00cccc\x00dddd\x00";
        let r = extract_reader(Cursor::new(data), &opts, &CancelToken::new(), None).unwrap();
        assert_eq!(r.items.len(), 2);
        assert!(r.truncated);
        assert!(r.total_found >= 2);
    }

    #[test]
    fn cancellation_is_honoured() {
        let cancel = CancelToken::new();
        cancel.cancel();
        let err = extract_reader(
            Cursor::new(vec![b'A'; 4096]),
            &StringOptions::default(),
            &cancel,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Cancelled));
    }

    #[test]
    fn binary_noise_does_not_produce_long_utf16_runs() {
        let data: Vec<u8> = (0..64 * 1024u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let r = extract(&data, 4096, 4);
        let wide = r
            .items
            .iter()
            .filter(|s| s.encoding == StringEncoding::Utf16Le)
            .count();
        assert!(wide < 100, "unexpected {wide} UTF-16 matches in noise");
    }

    #[test]
    fn huge_printable_run_is_truncated_not_allocated_fully() {
        let data = vec![b'A'; 100_000];
        let r = extract(&data, 4096, 4);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].value.len(), MAX_STRING_LEN);
        assert!(r.items[0].truncated);
    }

    #[test]
    fn utf8_multibyte_runs_are_extracted_at_exact_offsets() {
        let data = b"MZ\x00Caf\xc3\xa9 au lait\x00yy";
        let items = extract_utf8_bytes(data, 4, 8192);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].offset, 3);
        assert_eq!(items[0].value, "Café au lait");
        assert_eq!(items[0].encoding, StringEncoding::Utf8);
        assert!(items[0].classifications.is_empty());
    }

    #[test]
    fn utf8_ignores_ascii_only_runs_and_invalid_sequences() {
        assert!(extract_utf8_bytes(b"plain ascii text here", 4, 8192).is_empty());

        assert!(extract_utf8_bytes(b"abc\xff\xfe def", 4, 8192).is_empty());
    }

    #[test]
    fn utf8_stops_at_control_characters() {
        let items = extract_utf8_bytes(b"Caf\xc3\xa9\nau lait", 4, 8192);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "Café");
    }

    #[test]
    fn classification_is_applied_separately_from_extraction() {
        let mut items = extract_utf8_bytes(b"https://example.com/caf\xc3\xa9", 4, 8192);
        assert!(items[0].classifications.is_empty());
        classify_items(&mut items);
        assert!(items[0]
            .classifications
            .iter()
            .any(|c| c.kind == classify::StringClass::Url));
    }
}
