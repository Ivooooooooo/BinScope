use binscope_pe::CertificateInfo;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::path::Path;

const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_VALIDITYPERIODNESTING: u32 = 0x800B_0102;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const CERT_E_REVOCATION_FAILURE: u32 = 0x800B_010E;
const CERT_E_WRONG_USAGE: u32 = 0x800B_0108;
const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePresence {
    None,

    Malformed,

    Present,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureValidity {
    Valid,
    Invalid,
    NotVerified,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainTrust {
    Trusted,
    Untrusted,
    NotChecked,
    Unknown,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateTimeStatus {
    Valid,
    Expired,
    NotYetValid,
    Unknown,
    NotChecked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Good,
    Revoked,

    Unavailable,
    Unknown,
    NotChecked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationBackend {
    WindowsCryptoApi,
    Unavailable,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerInfo {
    pub subject: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureCheck {
    pub entry_index: usize,
    pub certificate_type: String,
    pub digest_algorithm: Option<String>,
    pub signed_digest: Option<String>,
    pub computed_digest: Option<String>,
    pub digest_matches: Option<bool>,

    pub status: String,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticodeReport {
    pub presence: SignaturePresence,
    pub signature: SignatureValidity,
    pub chain: ChainTrust,
    pub certificate_time: CertificateTimeStatus,
    pub revocation: RevocationStatus,
    pub backend: VerificationBackend,
    pub digest_algorithm: Option<String>,
    pub signed_digest: Option<String>,
    pub computed_digest: Option<String>,
    pub digest_matches: Option<bool>,
    pub signer: Option<SignerInfo>,

    pub signatures: Vec<SignatureCheck>,
    pub winverify_status: Option<String>,
    pub winverify_status_text: Option<String>,
    pub counter_signatures: usize,
    pub platform_supported: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct PeHashLayout {
    pub optional_header_offset: u64,
    pub is_64: bool,
    pub certificate_offset: u64,
    pub certificate_size: u64,
}

impl PeHashLayout {
    fn checksum_offset(&self) -> Option<u64> {
        self.optional_header_offset.checked_add(64)
    }

    fn certificate_directory_entry_offset(&self) -> Option<u64> {
        let data_directories = if self.is_64 { 112 } else { 96 };
        self.optional_header_offset
            .checked_add(data_directories)?
            .checked_add(4 * 8)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticodeError {
    #[error("file is smaller than the authenticated header region")]
    Truncated,
    #[error("invalid Authenticode offset layout")]
    InvalidLayout,
    #[error("certificate table is out of bounds")]
    CertificateOutOfBounds,
    #[error("signed digest could not be decoded: {0}")]
    DigestDecode(String),
    #[error("unsupported digest algorithm {0}")]
    UnsupportedAlgorithm(String),
}

pub fn verify(
    path: Option<&Path>,
    data: &[u8],
    certificate: &CertificateInfo,
    layout: PeHashLayout,
) -> AuthenticodeReport {
    let mut report = AuthenticodeReport {
        presence: if !certificate.present {
            SignaturePresence::None
        } else if certificate.entries.is_empty() {
            SignaturePresence::Malformed
        } else {
            SignaturePresence::Present
        },
        signature: SignatureValidity::NotVerified,
        chain: ChainTrust::NotChecked,
        certificate_time: CertificateTimeStatus::NotChecked,
        revocation: RevocationStatus::NotChecked,
        backend: VerificationBackend::Unavailable,
        digest_algorithm: None,
        signed_digest: None,
        computed_digest: None,
        digest_matches: None,
        signer: None,
        signatures: Vec::new(),
        winverify_status: None,
        winverify_status_text: None,
        counter_signatures: 0,
        platform_supported: cfg!(windows),
        notes: Vec::new(),
    };

    if !certificate.present {
        report
            .notes
            .push("No Authenticode certificate table is present.".into());
        return report;
    }
    if certificate.entries.is_empty() {
        report.notes.push(
            "The Security directory is present but contains no readable WIN_CERTIFICATE entry."
                .into(),
        );
        return report;
    }

    let mut any_signed_data = false;
    let mut first_digest: Option<SpcDigest> = None;
    for (index, entry) in certificate.entries.iter().enumerate() {
        if !entry.in_bounds {
            report.notes.push(format!(
                "WIN_CERTIFICATE entry {index} at {:#x} crosses the file or table boundary.",
                entry.offset
            ));
            report.signatures.push(SignatureCheck {
                entry_index: index,
                certificate_type: entry.certificate_type_name.clone(),
                digest_algorithm: None,
                signed_digest: None,
                computed_digest: None,
                digest_matches: None,
                status: "not_verified".into(),
                note: "entry is out of bounds".into(),
            });
            continue;
        }
        if entry.certificate_type != 0x0002 {
            report.signatures.push(SignatureCheck {
                entry_index: index,
                certificate_type: entry.certificate_type_name.clone(),
                digest_algorithm: None,
                signed_digest: None,
                computed_digest: None,
                digest_matches: None,
                status: "not_signed_data".into(),
                note: "only PKCS#7 signed data entries carry an Authenticode digest".into(),
            });
            continue;
        }
        any_signed_data = true;
        let start = entry.data_offset as usize;
        let end = start.saturating_add(entry.data_length as usize);
        let blob = data.get(start..end).unwrap_or(&[]);
        match extract_signed_content(blob).and_then(|content| parse_spc_content(&content)) {
            Ok(digest) => {
                if first_digest.is_none() {
                    first_digest = Some(digest.clone());
                }
                let computed = compute_authenticode_digest(data, layout, &digest.algorithm_oid);
                let (matches, computed_hex) = match &computed {
                    Ok(bytes) => (
                        Some(bytes.as_slice() == digest.digest.as_slice()),
                        Some(hex(bytes)),
                    ),
                    Err(error) => {
                        report.notes.push(format!(
                            "Entry {index}: digest could not be computed: {error}"
                        ));
                        (None, None)
                    }
                };
                let status = match matches {
                    Some(true) => "valid",
                    Some(false) => "invalid",
                    None => "not_verified",
                };
                report.signatures.push(SignatureCheck {
                    entry_index: index,
                    certificate_type: entry.certificate_type_name.clone(),
                    digest_algorithm: Some(digest.algorithm_name.clone()),
                    signed_digest: Some(hex(&digest.digest)),
                    computed_digest: computed_hex,
                    digest_matches: matches,
                    status: status.into(),
                    note: if matches == Some(true) {
                        "signed digest matches the PE digest computed by BinScope".into()
                    } else if matches == Some(false) {
                        "signed digest does not match the PE digest computed by BinScope".into()
                    } else {
                        "the PE digest could not be computed".into()
                    },
                });
            }
            Err(error) => {
                report.notes.push(format!(
                    "Entry {index}: PKCS#7 content could not be decoded: {error}"
                ));
                report.signatures.push(SignatureCheck {
                    entry_index: index,
                    certificate_type: entry.certificate_type_name.clone(),
                    digest_algorithm: None,
                    signed_digest: None,
                    computed_digest: None,
                    digest_matches: None,
                    status: "not_verified".into(),
                    note: error,
                });
            }
        }
    }

    if !any_signed_data {
        report.presence = SignaturePresence::Malformed;
        report
            .notes
            .push("No PKCS#7 signed-data entry could be decoded.".into());
        return report;
    }
    if let Some(digest) = &first_digest {
        report.digest_algorithm = Some(digest.algorithm_name.clone());
        report.signed_digest = Some(hex(&digest.digest));
        report.computed_digest = compute_authenticode_digest(data, layout, &digest.algorithm_oid)
            .ok()
            .map(|bytes| hex(&bytes));
        report.digest_matches = report
            .computed_digest
            .as_ref()
            .map(|computed| computed.eq_ignore_ascii_case(&hex(&digest.digest)));
    } else {
        report.presence = SignaturePresence::Malformed;
    }

    if report.digest_matches == Some(false) {
        report.signature = SignatureValidity::Invalid;
        report.notes.push(
            "The PE digest computed by BinScope does not match the signed digest; the file was modified after signing or the signature is invalid."
                .into(),
        );
    }

    verify_platform(path, &mut report);
    report
}

#[cfg(windows)]
fn verify_platform(path: Option<&Path>, report: &mut AuthenticodeReport) {
    report.backend = VerificationBackend::WindowsCryptoApi;
    let Some(path) = path else {
        report.signature = SignatureValidity::NotVerified;
        report
            .notes
            .push("No file path was available for the Windows trust call.".into());
        return;
    };
    let (status, subject) = win::verify_file(path, false);
    report.winverify_status = Some(format!("{status:#010x}"));
    report.winverify_status_text = Some(win::status_text(status));
    report.signer = subject.map(|subject| SignerInfo {
        subject: Some(subject),
    });

    let trust_only = matches!(
        status,
        CERT_E_UNTRUSTEDROOT
            | CERT_E_CHAINING
            | CERT_E_EXPIRED
            | CERT_E_VALIDITYPERIODNESTING
            | CERT_E_REVOKED
            | CERT_E_REVOCATION_FAILURE
            | CERT_E_WRONG_USAGE
            | TRUST_E_EXPLICIT_DISTRUST
    );

    if status == 0 {
        report.signature = SignatureValidity::Valid;
        report.chain = ChainTrust::Trusted;
        report.certificate_time = CertificateTimeStatus::Valid;
    } else if status == TRUST_E_BAD_DIGEST {
        report.signature = SignatureValidity::Invalid;
        report.chain = ChainTrust::NotChecked;
    } else if trust_only {
        if report.digest_matches != Some(false) {
            report.signature = SignatureValidity::Valid;
        }
        report.chain = ChainTrust::Untrusted;
        report.certificate_time = match status {
            CERT_E_EXPIRED => CertificateTimeStatus::Expired,
            CERT_E_VALIDITYPERIODNESTING => CertificateTimeStatus::Unknown,
            _ => CertificateTimeStatus::Unknown,
        };
    } else if matches!(status, TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN) {
        report.signature = SignatureValidity::NotVerified;
        report.chain = ChainTrust::NotChecked;
        report
            .notes
            .push("Windows did not find a usable signature in the certificate table.".into());
    } else {
        report.signature = SignatureValidity::NotVerified;
        report.chain = ChainTrust::Unknown;
        report.notes.push(format!(
            "Windows returned {status:#010x}; BinScope does not infer trust from this code."
        ));
    }

    if report.signature == SignatureValidity::Valid
        || report.signature == SignatureValidity::NotVerified
    {
        let (revocation, _) = win::verify_file(path, true);
        report.revocation = match revocation {
            0 => RevocationStatus::Good,
            CERT_E_REVOKED => RevocationStatus::Revoked,
            CRYPT_E_REVOCATION_OFFLINE | CERT_E_REVOCATION_FAILURE => RevocationStatus::Unavailable,

            CERT_E_UNTRUSTEDROOT | CERT_E_CHAINING | CERT_E_EXPIRED => RevocationStatus::Unknown,
            _ => RevocationStatus::Unknown,
        };
        if report.revocation == RevocationStatus::Unavailable {
            report.notes.push(
                "Revocation could not be checked from the local cache; the certificate is not reported as invalid because of this."
                    .into(),
            );
        }
        if report.revocation == RevocationStatus::Revoked {
            report.chain = ChainTrust::Untrusted;
            report
                .notes
                .push("Windows reported that a certificate in the chain is revoked.".into());
        }
    }
    if report.counter_signatures == 0 {
        report.notes.push(
            "Counter-signature and timestamp verification is delegated to Windows and not asserted separately."
                .into(),
        );
    }
}

#[cfg(not(windows))]
fn verify_platform(_path: Option<&Path>, report: &mut AuthenticodeReport) {
    report.backend = VerificationBackend::Unavailable;
    report.signature = SignatureValidity::Unavailable;
    report.chain = ChainTrust::Unavailable;
    report.certificate_time = CertificateTimeStatus::Unknown;
    report.revocation = RevocationStatus::Unavailable;
    report.notes.push(
        "Cryptographic trust verification requires the Windows CryptoAPI. Structure and digest are still reported, but no trust decision is made on this platform."
            .into(),
    );
}

#[derive(Clone, Debug)]
struct SpcDigest {
    algorithm_oid: String,
    algorithm_name: String,
    digest: Vec<u8>,
}

fn parse_spc_content(content: &[u8]) -> Result<SpcDigest, String> {
    if content.is_empty() {
        return Err("empty SpcIndirectDataContent".into());
    }
    let reader = Der::new(content);
    let (tag, content) = reader.element(0)?;
    if tag != 0x30 {
        return Err(format!("expected SignedData SEQUENCE, found tag {tag:#x}"));
    }
    let outer = Der::new(content);
    let mut cursor = 0usize;

    let (tag, value, next) = outer.element_at(cursor)?;
    if tag != 0x30 {
        return Err("SpcIndirectDataContent is not a SEQUENCE".into());
    }
    let _ = value;
    cursor = next;
    let (tag, digest_info_outer, next) = outer.element_at(cursor)?;
    if tag != 0x30 {
        return Err("DigestInfo is not a SEQUENCE".into());
    }
    cursor = next;
    let _ = cursor;
    let inner = Der::new(digest_info_outer);
    let (tag, algorithm, next) = inner.element_at(0)?;
    if tag != 0x30 {
        return Err("DigestInfo algorithm is not a SEQUENCE".into());
    }
    let (oid_tag, oid_bytes, _) = Der::new(algorithm).element_at(0)?;
    if oid_tag != 0x06 {
        return Err("digest algorithm OID is missing".into());
    }
    let oid = decode_oid(oid_bytes)?;
    let (digest_tag, digest, _) = inner.element_at(next)?;
    if digest_tag != 0x04 {
        return Err("DigestInfo digest is not an OCTET STRING".into());
    }
    if digest.len() > 128 {
        return Err("digest is unreasonably long".into());
    }
    Ok(SpcDigest {
        algorithm_name: algorithm_name(&oid),
        algorithm_oid: oid,
        digest: digest.to_vec(),
    })
}

struct Der<'a> {
    bytes: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn element(&self, offset: usize) -> Result<(u8, &'a [u8]), String> {
        let (tag, value, _) = self.element_at(offset)?;
        Ok((tag, value))
    }

    fn element_at(&self, offset: usize) -> Result<(u8, &'a [u8], usize), String> {
        let tag = *self
            .bytes
            .get(offset)
            .ok_or_else(|| "truncated DER tag".to_string())?;
        let mut cursor = offset + 1;
        let first = *self
            .bytes
            .get(cursor)
            .ok_or_else(|| "truncated DER length".to_string())?;
        cursor += 1;
        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7F) as usize;
            if count == 0 || count > 4 {
                return Err("unsupported DER length".into());
            }
            let mut value = 0usize;
            for _ in 0..count {
                let byte = *self
                    .bytes
                    .get(cursor)
                    .ok_or_else(|| "truncated DER length".to_string())?;
                value = value
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(byte as usize))
                    .ok_or_else(|| "DER length overflow".to_string())?;
                cursor += 1;
            }
            value
        };
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| "DER length overflow".to_string())?;
        let content = self
            .bytes
            .get(cursor..end)
            .ok_or_else(|| "truncated DER content".to_string())?;
        Ok((tag, content, end))
    }
}

fn decode_oid(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("empty OID".into());
    }
    let mut parts = Vec::new();
    let first = bytes[0] as u32;
    parts.push(first / 40);
    parts.push(first % 40);
    let mut value = 0u32;
    for byte in &bytes[1..] {
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add((byte & 0x7F) as u32))
            .ok_or_else(|| "OID component overflow".to_string())?;
        if byte & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    if value != 0 {
        return Err("truncated OID component".into());
    }
    Ok(parts
        .iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

fn algorithm_name(oid: &str) -> String {
    match oid {
        "1.3.14.3.2.26" => "SHA-1".into(),
        "2.16.840.1.101.3.4.2.1" => "SHA-256".into(),
        "2.16.840.1.101.3.4.2.2" => "SHA-384".into(),
        "2.16.840.1.101.3.4.2.3" => "SHA-512".into(),
        "1.2.840.113549.1.1.4" => "MD5".into(),
        other => other.to_string(),
    }
}

pub fn compute_authenticode_digest(
    data: &[u8],
    layout: PeHashLayout,
    algorithm_oid: &str,
) -> Result<Vec<u8>, AuthenticodeError> {
    let len = data.len() as u64;
    let checksum = layout
        .checksum_offset()
        .ok_or(AuthenticodeError::InvalidLayout)?;
    let cert_entry = layout
        .certificate_directory_entry_offset()
        .ok_or(AuthenticodeError::InvalidLayout)?;
    if checksum.checked_add(4).is_none_or(|value| value > len)
        || cert_entry.checked_add(8).is_none_or(|value| value > len)
    {
        return Err(AuthenticodeError::Truncated);
    }
    let cert_start = layout.certificate_offset;
    let cert_end = cert_start
        .checked_add(layout.certificate_size)
        .ok_or(AuthenticodeError::CertificateOutOfBounds)?;
    let has_certificate = layout.certificate_offset != 0 && layout.certificate_size != 0;
    if has_certificate && (cert_start < cert_entry + 8 || cert_end > len) {
        return Err(AuthenticodeError::CertificateOutOfBounds);
    }

    let mut hasher: Box<dyn DigestWriter> = match algorithm_oid {
        "1.3.14.3.2.26" => Box::new(Sha1::new()),
        "2.16.840.1.101.3.4.2.1" => Box::new(Sha256::new()),
        "2.16.840.1.101.3.4.2.2" => Box::new(Sha384::new()),
        "2.16.840.1.101.3.4.2.3" => Box::new(Sha512::new()),
        other => return Err(AuthenticodeError::UnsupportedAlgorithm(other.to_string())),
    };

    hasher.update_range(data, 0, checksum)?;
    hasher.update_range(data, checksum + 4, cert_entry)?;
    if has_certificate {
        hasher.update_range(data, cert_entry + 8, cert_start)?;
        hasher.update_range(data, cert_end, len)?;
    } else {
        hasher.update_range(data, cert_entry + 8, len)?;
    }
    Ok(hasher.finish_boxed())
}

trait DigestWriter {
    fn update_range(&mut self, data: &[u8], start: u64, end: u64) -> Result<(), AuthenticodeError>;
    fn finish_boxed(self: Box<Self>) -> Vec<u8>;
}

macro_rules! impl_digest_writer {
    ($ty:ty) => {
        impl DigestWriter for $ty {
            fn update_range(
                &mut self,
                data: &[u8],
                start: u64,
                end: u64,
            ) -> Result<(), AuthenticodeError> {
                if start > end || end > data.len() as u64 {
                    return Err(AuthenticodeError::InvalidLayout);
                }
                let slice = data
                    .get(start as usize..end as usize)
                    .ok_or(AuthenticodeError::InvalidLayout)?;
                Digest::update(self, slice);
                Ok(())
            }

            fn finish_boxed(self: Box<Self>) -> Vec<u8> {
                Digest::finalize(*self).to_vec()
            }
        }
    };
}

impl_digest_writer!(Sha1);
impl_digest_writer!(Sha256);
impl_digest_writer!(Sha384);
impl_digest_writer!(Sha512);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn extract_signed_content(blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.is_empty() {
        return Err("empty PKCS#7 blob".into());
    }
    #[cfg(windows)]
    {
        win::pkcs7_content(blob)
    }
    #[cfg(not(windows))]
    {
        let _ = blob;
        Err("PKCS#7 decoding requires the Windows CryptoAPI".into())
    }
}

#[cfg(windows)]
mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_BLOB, CMSG_CONTENT_PARAM,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, CRYPT_PROVIDER_DATA, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
        WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    pub fn verify_file(path: &Path, check_revocation: bool) -> (u32, Option<String>) {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = if check_revocation {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        };
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 {
            pFile: &mut file_info,
        };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut::<std::ffi::c_void>() as HWND,
                &mut action,
                &mut data as *mut WINTRUST_DATA as *mut std::ffi::c_void,
            )
        } as u32;

        let subject = signer_subject(&data);

        let saved = data.hWVTStateData;
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut::<std::ffi::c_void>() as HWND,
                &mut action,
                &mut data as *mut WINTRUST_DATA as *mut std::ffi::c_void,
            )
        };
        let _ = saved;
        (status, subject)
    }

    fn signer_subject(data: &WINTRUST_DATA) -> Option<String> {
        use windows_sys::Win32::Security::WinTrust::{
            WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
            WTHelperProvDataFromStateData,
        };
        if data.hWVTStateData.is_null() {
            return None;
        }
        unsafe {
            let provider: *mut CRYPT_PROVIDER_DATA =
                WTHelperProvDataFromStateData(data.hWVTStateData);
            if provider.is_null() {
                return None;
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
            if signer.is_null() {
                return None;
            }
            let cert = WTHelperGetProvCertFromChain(signer, 0);
            if cert.is_null() || (*cert).pCert.is_null() {
                return None;
            }
            let context = (*cert).pCert;
            let len = CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );
            if len <= 1 {
                return None;
            }
            let mut buffer = vec![0u16; len as usize];
            let written = CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                len,
            );
            if written <= 1 {
                return None;
            }
            Some(String::from_utf16_lossy(&buffer[..written as usize - 1]))
        }
    }

    pub fn pkcs7_content(blob: &[u8]) -> Result<Vec<u8>, String> {
        #[repr(C)]
        struct CertBlob {
            cb_data: u32,
            pb_data: *mut u8,
        }
        if blob.len() > u32::MAX as usize {
            return Err("PKCS#7 blob is too large".into());
        }
        let mut cert_blob = CertBlob {
            cb_data: blob.len() as u32,
            pb_data: blob.as_ptr() as *mut u8,
        };
        let mut encoding = 0u32;
        let mut content_type = 0u32;
        let mut format = 0u32;
        let mut store = std::ptr::null_mut();
        let mut message: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut context: *mut std::ffi::c_void = std::ptr::null_mut();
        let ok = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_BLOB,
                &mut cert_blob as *mut CertBlob as *const std::ffi::c_void,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &mut encoding,
                &mut content_type,
                &mut format,
                &mut store,
                &mut message,
                &mut context,
            )
        };
        if ok == 0 || message.is_null() {
            if !store.is_null() {
                unsafe {
                    CertCloseStore(store, 0);
                }
            }
            return Err("CryptQueryObject could not decode the PKCS#7 signature".into());
        }
        let result = (|| {
            let mut length = 0u32;
            let ok = unsafe {
                CryptMsgGetParam(
                    message,
                    CMSG_CONTENT_PARAM,
                    0,
                    std::ptr::null_mut(),
                    &mut length,
                )
            };
            if ok == 0 || length == 0 || length > 16 * 1024 * 1024 {
                return Err("PKCS#7 content length is unavailable or unreasonable".into());
            }
            let mut buffer = vec![0u8; length as usize];
            let ok = unsafe {
                CryptMsgGetParam(
                    message,
                    CMSG_CONTENT_PARAM,
                    0,
                    buffer.as_mut_ptr() as *mut std::ffi::c_void,
                    &mut length,
                )
            };
            if ok == 0 {
                return Err("PKCS#7 content could not be read".into());
            }
            buffer.truncate(length as usize);
            Ok(buffer)
        })();
        unsafe {
            CryptMsgClose(message);
            if !store.is_null() {
                CertCloseStore(store, 0);
            }
        }
        result
    }

    pub fn status_text(status: u32) -> String {
        match status {
            0 => "trusted".into(),
            0x800B_0100 => "no signature".into(),
            0x8009_6010 => "bad digest or signature".into(),
            0x800B_0109 => "untrusted root".into(),
            0x800B_010A => "certificate chain could not be built".into(),
            0x800B_0101 => "certificate expired".into(),
            0x800B_010C => "certificate revoked".into(),
            0x800B_010E | 0x8009_2013 => "revocation status unavailable".into(),
            0x800B_0111 => "explicitly distrusted".into(),
            0x800B_0108 => "certificate has the wrong usage".into(),
            0x800B_0003 => "subject form unknown".into(),
            0x800B_0001 => "trust provider unknown".into(),
            other => format!("Windows status {other:#010x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binscope_pe::CertificateInfo;

    fn layout() -> PeHashLayout {
        PeHashLayout {
            optional_header_offset: 0x98,
            is_64: false,
            certificate_offset: 0,
            certificate_size: 0,
        }
    }

    #[test]
    fn unsigned_image_is_not_an_error() {
        let data = vec![0u8; 0x400];
        let report = verify(None, &data, &CertificateInfo::default(), layout());
        assert_eq!(report.presence, SignaturePresence::None);
        assert!(report.signatures.is_empty());
        assert_eq!(report.chain, ChainTrust::NotChecked);
    }

    #[test]
    fn malformed_table_is_reported_separately() {
        let data = vec![0u8; 0x400];
        let certificate = CertificateInfo {
            present: true,
            directory_offset: 0x200,
            directory_size: 4,
            entries: Vec::new(),
            note: String::new(),
        };
        let report = verify(None, &data, &certificate, layout());
        assert_eq!(report.presence, SignaturePresence::Malformed);
        assert_eq!(report.signature, SignatureValidity::NotVerified);
    }

    #[test]
    fn digest_skips_checksum_security_entry_and_certificate_table() {
        let mut data = vec![0u8; 0x200];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut layout = layout();
        layout.certificate_offset = 0x180;
        layout.certificate_size = 0x40;
        let full = compute_authenticode_digest(&data, layout, "2.16.840.1.101.3.4.2.1").unwrap();

        data[0x98 + 64] ^= 0xFF;
        data[0x98 + 96 + 32] ^= 0xFF;
        data[0x180 + 4] ^= 0xFF;
        let modified =
            compute_authenticode_digest(&data, layout, "2.16.840.1.101.3.4.2.1").unwrap();
        assert_eq!(full, modified);

        data[0x10] ^= 0xFF;
        let changed = compute_authenticode_digest(&data, layout, "2.16.840.1.101.3.4.2.1").unwrap();
        assert_ne!(full, changed);
    }

    #[test]
    fn unsigned_layout_hashes_through_to_eof() {
        let data = vec![0x11u8; 0x200];
        let digest =
            compute_authenticode_digest(&data, layout(), "2.16.840.1.101.3.4.2.1").expect("digest");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn out_of_bounds_certificate_range_is_rejected() {
        let data = vec![0u8; 0x200];
        let mut layout = layout();
        layout.certificate_offset = 0x1F0;
        layout.certificate_size = 0x40;
        assert!(matches!(
            compute_authenticode_digest(&data, layout, "2.16.840.1.101.3.4.2.1"),
            Err(AuthenticodeError::CertificateOutOfBounds)
        ));
    }

    #[test]
    fn unsupported_digest_algorithm_is_rejected() {
        let data = vec![0u8; 0x200];
        assert!(matches!(
            compute_authenticode_digest(&data, layout(), "1.2.3.4"),
            Err(AuthenticodeError::UnsupportedAlgorithm(_))
        ));
    }

    fn spc(oid: &[u8], digest: &[u8]) -> Vec<u8> {
        let attribute = [0x30, 0x03, 0x06, 0x01, 0x00];
        let mut algorithm = vec![0x30, (2 + oid.len()) as u8, 0x06, oid.len() as u8];
        algorithm.extend_from_slice(oid);
        let mut digest_info = vec![0x30];
        let inner_len = algorithm.len() + 2 + digest.len();
        digest_info.push(inner_len as u8);
        digest_info.extend_from_slice(&algorithm);
        digest_info.push(0x04);
        digest_info.push(digest.len() as u8);
        digest_info.extend_from_slice(digest);
        let mut outer = vec![0x30];
        outer.push((attribute.len() + digest_info.len()) as u8);
        outer.extend_from_slice(&attribute);
        outer.extend_from_slice(&digest_info);
        outer
    }

    #[test]
    fn spc_indirect_data_is_decoded() {
        let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let content = spc(&oid, &[0xAB; 32]);
        let parsed = parse_spc_content(&content).expect("parse");
        assert_eq!(parsed.algorithm_name, "SHA-256");
        assert_eq!(parsed.digest, vec![0xAB; 32]);
    }

    #[test]
    fn malformed_der_does_not_panic() {
        for length in 0..64usize {
            let mut blob = vec![0x30; length];
            for (index, byte) in blob.iter_mut().enumerate() {
                *byte = (index * 7) as u8;
            }
            let _ = parse_spc_content(&blob);
        }
        assert!(parse_spc_content(&[]).is_err());
        assert!(parse_spc_content(&[0x30, 0xFF]).is_err());
    }
}
