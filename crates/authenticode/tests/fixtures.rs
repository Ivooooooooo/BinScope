use binscope_authenticode::{
    verify, ChainTrust, PeHashLayout, RevocationStatus, SignaturePresence, SignatureValidity,
};
use binscope_pe::parse_default;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn verify_file(path: &Path) -> binscope_authenticode::AuthenticodeReport {
    let data = std::fs::read(path).expect("read fixture");
    let pe = parse_default(&data).expect("parse PE");
    verify(
        Some(path),
        &data,
        &pe.certificate,
        PeHashLayout {
            optional_header_offset: pe.optional_header_offset,
            is_64: pe.is_64,
            certificate_offset: pe.certificate.directory_offset as u64,
            certificate_size: pe.certificate.directory_size as u64,
        },
    )
}

#[test]
fn unsigned_image_reports_no_signature() {
    let report = verify_file(&fixture("pe32-x86.exe"));
    assert_eq!(report.presence, SignaturePresence::None);
    assert_eq!(report.signature, SignatureValidity::NotVerified);
    assert_eq!(report.chain, ChainTrust::NotChecked);
}

#[test]
fn self_signed_fixture_has_valid_digest_but_untrusted_chain() {
    let report = verify_file(&fixture("authenticode/self-signed.exe"));
    assert_eq!(report.presence, SignaturePresence::Present);
    assert_eq!(
        report.digest_matches,
        Some(true),
        "digest notes: {:?}",
        report.notes
    );
    assert_eq!(report.digest_algorithm.as_deref(), Some("SHA-256"));
    assert_eq!(report.signature, SignatureValidity::Valid);
    assert_eq!(report.chain, ChainTrust::Untrusted);
    assert_eq!(
        report.backend,
        binscope_authenticode::VerificationBackend::WindowsCryptoApi
    );
    assert!(report
        .signer
        .as_ref()
        .and_then(|s| s.subject.as_deref())
        .is_some());
    assert_ne!(report.revocation, RevocationStatus::Revoked);
    assert!(!report.signatures.is_empty());
    assert!(report
        .signatures
        .iter()
        .any(|check| check.status == "valid"));
}

#[test]
fn tampered_signed_file_has_invalid_digest() {
    let report = verify_file(&fixture("authenticode/tampered.exe"));
    assert_eq!(report.presence, SignaturePresence::Present);
    assert_eq!(report.digest_matches, Some(false));
    assert_eq!(report.signature, SignatureValidity::Invalid);
    assert!(report
        .notes
        .iter()
        .any(|note| note.contains("does not match the signed digest")));
}

#[test]
fn malformed_certificate_table_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = binscope_pe::PeBuilder::pe64();
    builder.certificate = true;
    let path = dir.path().join("fake-cert.exe");
    std::fs::write(&path, builder.build()).unwrap();
    let report = verify_file(&path);
    assert_eq!(report.presence, SignaturePresence::Malformed);
    assert_eq!(report.signature, SignatureValidity::NotVerified);
}

#[test]
fn truncated_certificate_table_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = binscope_pe::PeBuilder::pe32();
    builder.certificate = true;
    let mut data = builder.build();

    data.truncate(data.len() - 0x40);
    let path = dir.path().join("truncated-cert.exe");
    std::fs::write(&path, &data).unwrap();
    let pe = parse_default(&data).expect("parse");
    let report = verify(
        Some(&path),
        &data,
        &pe.certificate,
        PeHashLayout {
            optional_header_offset: pe.optional_header_offset,
            is_64: pe.is_64,
            certificate_offset: pe.certificate.directory_offset as u64,
            certificate_size: pe.certificate.directory_size as u64,
        },
    );
    assert_eq!(report.presence, SignaturePresence::Malformed);
    assert_ne!(report.signature, SignatureValidity::Valid);
    assert!(
        !report.notes.is_empty(),
        "a malformed table must explain itself"
    );
}
