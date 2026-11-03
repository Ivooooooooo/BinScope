use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Clone, Debug, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnalysisLimits {
    pub max_parse_bytes: u64,

    pub max_stream_bytes: u64,

    pub min_string_len: usize,

    pub max_strings: usize,

    pub max_string_bytes: usize,

    pub time_budget: Duration,

    pub max_entries: usize,

    pub chunk_size: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_parse_bytes: 512 * 1024 * 1024,
            max_stream_bytes: 2 * 1024 * 1024 * 1024,
            min_string_len: 4,
            max_strings: 200_000,
            max_string_bytes: 32 * 1024 * 1024,
            time_budget: Duration::from_secs(180),
            max_entries: 65_536,
            chunk_size: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Deadline {
    end: Instant,
}

impl Deadline {
    pub fn after(budget: Duration) -> Self {
        Self {
            end: Instant::now() + budget,
        }
    }

    pub fn check(&self) -> Result<()> {
        if Instant::now() >= self.end {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }

    pub fn remaining(&self) -> Duration {
        self.end.saturating_duration_since(Instant::now())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("operation cancelled")]
    Cancelled,
    #[error("analysis time budget exceeded")]
    Timeout,
    #[error("unexpected end of data while reading {context} at offset {offset:#x}")]
    OutOfBounds { context: &'static str, offset: u64 },
    #[error("invalid structure: {0}")]
    Invalid(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    fn slice(&self, offset: u64, len: usize, context: &'static str) -> Result<&'a [u8]> {
        let start = usize::try_from(offset).map_err(|_| Error::OutOfBounds { context, offset })?;
        let end = start
            .checked_add(len)
            .ok_or(Error::OutOfBounds { context, offset })?;
        self.data
            .get(start..end)
            .ok_or(Error::OutOfBounds { context, offset })
    }

    pub fn bytes(&self, offset: u64, len: usize, context: &'static str) -> Result<&'a [u8]> {
        self.slice(offset, len, context)
    }

    pub fn u8(&self, offset: u64, context: &'static str) -> Result<u8> {
        Ok(self.slice(offset, 1, context)?[0])
    }

    pub fn u16(&self, offset: u64, context: &'static str) -> Result<u16> {
        let b = self.slice(offset, 2, context)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&self, offset: u64, context: &'static str) -> Result<u32> {
        let b = self.slice(offset, 4, context)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&self, offset: u64, context: &'static str) -> Result<u64> {
        let b = self.slice(offset, 8, context)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn cstr(&self, offset: u64, max_len: usize, context: &'static str) -> Result<String> {
        let start = usize::try_from(offset).map_err(|_| Error::OutOfBounds { context, offset })?;
        let tail = self
            .data
            .get(start..)
            .ok_or(Error::OutOfBounds { context, offset })?;
        let end = tail
            .iter()
            .take(max_len)
            .position(|&b| b == 0)
            .unwrap_or_else(|| tail.len().min(max_len));
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    pub fn utf16z(&self, offset: u64, max_bytes: usize, context: &'static str) -> Result<String> {
        let start = usize::try_from(offset).map_err(|_| Error::OutOfBounds { context, offset })?;
        let tail = self
            .data
            .get(start..)
            .ok_or(Error::OutOfBounds { context, offset })?;
        let units = tail.len().min(max_bytes) / 2;
        let mut out = String::new();
        for i in 0..units {
            let u = u16::from_le_bytes([tail[i * 2], tail[i * 2 + 1]]);
            if u == 0 {
                return Ok(out);
            }
            out.push(char::from_u32(u as u32).unwrap_or('\u{FFFD}'));
        }
        Ok(out)
    }
}

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn parse_hex_pattern(pattern: &str) -> Option<Vec<Option<u8>>> {
    let mut out = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            out.push(None);
            continue;
        }
        if token.len() != 2 {
            return None;
        }
        let byte = u8::from_str_radix(token, 16).ok()?;
        out.push(Some(byte));
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn find_pattern(haystack: &[u8], pattern: &[Option<u8>], limit: usize) -> Vec<usize> {
    let mut hits = Vec::new();
    if pattern.is_empty() || haystack.len() < pattern.len() || limit == 0 {
        return hits;
    }
    let first_fixed = pattern.iter().position(|p| p.is_some());
    let max_start = haystack.len() - pattern.len();
    let mut i = 0usize;
    while i <= max_start {
        if let Some(idx) = first_fixed {
            let Some(needle) = pattern[idx] else {
                i += 1;
                continue;
            };
            match haystack[i + idx..=max_start + idx]
                .iter()
                .position(|&b| b == needle)
            {
                Some(delta) => i += delta,
                None => break,
            }
        }
        let matched = pattern
            .iter()
            .enumerate()
            .all(|(k, p)| p.is_none_or(|b| haystack[i + k] == b));
        if matched {
            hits.push(i);
            if hits.len() >= limit {
                break;
            }
            i += pattern.len().max(1);
        } else {
            i += 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_rejects_out_of_bounds() {
        let data = [1u8, 2, 3];
        let r = Reader::new(&data);
        assert_eq!(r.u16(0, "test").unwrap(), 0x0201);
        assert!(matches!(
            r.u32(0, "test"),
            Err(Error::OutOfBounds { offset: 0, .. })
        ));
        assert!(r.u16(u64::MAX, "test").is_err());
    }

    #[test]
    fn entropy_of_uniform_buffer_is_eight_bits() {
        let data: Vec<u8> = (0..=255).collect();
        let e = entropy(&data);
        assert!((e - 8.0).abs() < 1e-9, "entropy was {e}");
        assert_eq!(entropy(&[0; 1024]), 0.0);
    }

    #[test]
    fn hex_pattern_matching_respects_wildcards() {
        let pat = parse_hex_pattern("4D 5A ?? 00").unwrap();
        assert_eq!(find_pattern(b"xxMZ\x90\x00yy", &pat, 10), vec![2]);
        assert_eq!(find_pattern(b"MZ", &pat, 10), Vec::<usize>::new());
        assert!(parse_hex_pattern("4D 5").is_none());
    }

    #[test]
    fn size_formatting_is_binary() {
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.00 MiB");
    }

    #[test]
    fn cancel_token_is_shared() {
        let token = CancelToken::new();
        let clone = token.clone();
        clone.cancel();
        assert!(token.is_cancelled());
        assert!(matches!(token.check(), Err(Error::Cancelled)));
    }

    #[test]
    fn cstr_and_utf16z_are_bounded() {
        let data = b"abc\0def".to_vec();
        let r = Reader::new(&data);
        assert_eq!(r.cstr(0, 100, "t").unwrap(), "abc");
        let wide: Vec<u8> = "Hola\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let r2 = Reader::new(&wide);
        assert_eq!(r2.utf16z(0, 100, "t").unwrap(), "Hola");
        assert_eq!(r2.utf16z(0, 4, "t").unwrap(), "Ho");
    }
}
