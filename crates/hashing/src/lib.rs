use binscope_common::{CancelToken, Deadline, Error, Result};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

impl FileHashes {
    pub fn as_pairs(&self) -> [(&'static str, &str); 3] {
        [
            ("SHA-256", &self.sha256),
            ("SHA-1", &self.sha1),
            ("MD5", &self.md5),
        ]
    }
}

pub fn hash_bytes(data: &[u8]) -> FileHashes {
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();

    sha256.update(data);
    sha1.update(data);
    md5.update(data);
    FileHashes {
        sha256: format!("{:x}", sha256.finalize()),
        sha1: format!("{:x}", sha1.finalize()),
        md5: format!("{:x}", md5.finalize()),
    }
}

pub fn hash_file(
    path: &Path,
    cancel: &CancelToken,
    deadline: Option<&Deadline>,
) -> Result<FileHashes> {
    let file = File::open(path).map_err(Error::Io)?;

    hash_reader(file, 1024 * 1024, cancel, deadline)
}

pub fn hash_reader<R: Read>(
    mut reader: R,
    chunk_size: usize,
    cancel: &CancelToken,
    deadline: Option<&Deadline>,
) -> Result<FileHashes> {
    if chunk_size == 0 {
        return Err(Error::Invalid("hash chunk size must be > 0".into()));
    }
    let mut buf = vec![0u8; chunk_size];
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    loop {
        cancel.check()?;
        if let Some(d) = deadline {
            d.check()?;
        }
        let n = reader.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        sha256.update(chunk);
        sha1.update(chunk);
        md5.update(chunk);
    }
    Ok(FileHashes {
        sha256: format!("{:x}", sha256.finalize()),
        sha1: format!("{:x}", sha1.finalize()),
        md5: format!("{:x}", md5.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn hashes(data: &[u8]) -> FileHashes {
        hash_reader(Cursor::new(data), 3, &CancelToken::new(), None).unwrap()
    }

    #[test]
    fn known_vectors_empty_input() {
        let h = hashes(b"");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn known_vectors_abc() {
        let h = hashes(b"abc");
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn streaming_matches_single_pass_across_chunk_boundaries() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 31 % 251) as u8).collect();
        assert_eq!(hashes(&data), hash_bytes(&data));
    }

    #[test]
    fn cancellation_is_honoured() {
        let cancel = CancelToken::new();
        cancel.cancel();
        let err = hash_reader(Cursor::new(vec![0u8; 16]), 4, &cancel, None).unwrap_err();
        assert!(matches!(err, Error::Cancelled));
    }

    #[test]
    fn hashes_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, b"BinScope").unwrap();
        let h = hash_file(&path, &CancelToken::new(), None).unwrap();
        assert_eq!(h, hash_bytes(b"BinScope"));
    }
}
