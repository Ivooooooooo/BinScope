














use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlRejection {
    Malformed,
    NotHttps,
    Credentials,
    Port,
    QueryOrFragment,
    WrongHost,
    WrongPath,
    NotSha256,
}

impl UrlRejection {
    pub fn reason(self) -> &'static str {
        match self {
            UrlRejection::Malformed => "the report URL is malformed",
            UrlRejection::NotHttps => "the report URL is not HTTPS",
            UrlRejection::Credentials => "the report URL embeds credentials",
            UrlRejection::Port => "the report URL uses a non-standard port",
            UrlRejection::QueryOrFragment => "the report URL carries a query or fragment",
            UrlRejection::WrongHost => "the report URL host is not the provider's official host",
            UrlRejection::WrongPath => "the report URL path does not match the provider report layout",
            UrlRejection::NotSha256 => "the value is not a SHA-256 hash",
        }
    }
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}



pub fn validate_report_url(provider_id: &str, raw: &str) -> Result<String, UrlRejection> {
    if raw.trim() != raw {
        return Err(UrlRejection::Malformed);
    }
    let url = Url::parse(raw).map_err(|_| UrlRejection::Malformed)?;
    if url.scheme() != "https" {
        return Err(UrlRejection::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlRejection::Credentials);
    }
    if url.port().is_some_and(|port| port != 443) {
        return Err(UrlRejection::Port);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(UrlRejection::QueryOrFragment);
    }
    let host = url
        .host_str()
        .ok_or(UrlRejection::WrongHost)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let segments = path_segments(&url);

    match provider_id {
        "virustotal" => {
            expect_host(&host, &["www.virustotal.com"])?;
            match segments.as_slice() {
                ["gui", "file", hash] if is_sha256(hash) => {}
                _ => return Err(UrlRejection::WrongPath),
            }
        }
        "malwarebazaar" => {
            expect_host(&host, &["bazaar.abuse.ch"])?;
            match segments.as_slice() {
                ["sample", hash] if is_sha256(hash) => {}
                _ => return Err(UrlRejection::WrongPath),
            }
        }
        "urlhaus" => {
            expect_host(&host, &["urlhaus.abuse.ch"])?;
            match segments.as_slice() {
                ["url", id] if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) => {}
                _ => return Err(UrlRejection::WrongPath),
            }
        }
        "hybrid-analysis" => {
            expect_host(&host, &["www.hybrid-analysis.com"])?;
            match segments.as_slice() {
                ["sample", hash] if is_sha256(hash) => {}
                _ => return Err(UrlRejection::WrongPath),
            }
        }
        "triage" => {
            expect_host(&host, &["tria.ge"])?;
            match segments.as_slice() {
                [id] if is_triage_id(id) => {}
                _ => return Err(UrlRejection::WrongPath),
            }
        }
        

        _ => return Err(UrlRejection::WrongPath),
    }
    Ok(url.to_string())
}



pub fn virustotal_report_url(sha256: &str) -> Option<String> {
    if !is_sha256(sha256) {
        return None;
    }
    validate_report_url(
        "virustotal",
        &format!("https://www.virustotal.com/gui/file/{sha256}"),
    )
    .ok()
}

pub fn malwarebazaar_report_url(sha256: &str) -> Option<String> {
    if !is_sha256(sha256) {
        return None;
    }
    validate_report_url(
        "malwarebazaar",
        &format!("https://bazaar.abuse.ch/sample/{sha256}/"),
    )
    .ok()
}

pub fn hybrid_analysis_report_url(sha256: &str) -> Option<String> {
    if !is_sha256(sha256) {
        return None;
    }
    validate_report_url(
        "hybrid-analysis",
        &format!("https://www.hybrid-analysis.com/sample/{sha256}"),
    )
    .ok()
}

pub fn triage_report_url(id: &str) -> Option<String> {
    if !is_triage_id(id) {
        return None;
    }
    validate_report_url("triage", &format!("https://tria.ge/{id}")).ok()
}

fn is_triage_id(value: &str) -> bool {
    (1..=80).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && value != "."
        && value != ".."
}

fn path_segments(url: &Url) -> Vec<String> {
    let mut segments: Vec<String> = url
        .path_segments()
        .map(|segments| segments.map(str::to_string).collect())
        .unwrap_or_default();
    if segments.last().is_some_and(|last| last.is_empty()) {
        segments.pop();
    }
    segments
}

fn expect_host(host: &str, allowed: &[&str]) -> Result<(), UrlRejection> {
    if allowed.contains(&host) {
        Ok(())
    } else {
        Err(UrlRejection::WrongHost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    #[test]
    fn accepts_the_documented_layouts() {
        assert!(validate_report_url(
            "virustotal",
            &format!("https://www.virustotal.com/gui/file/{SHA}")
        )
        .is_ok());
        assert!(validate_report_url(
            "malwarebazaar",
            &format!("https://bazaar.abuse.ch/sample/{SHA}/")
        )
        .is_ok());
        assert!(validate_report_url("urlhaus", "https://urlhaus.abuse.ch/url/1234567/").is_ok());
        assert!(validate_report_url(
            "hybrid-analysis",
            &format!("https://www.hybrid-analysis.com/sample/{SHA}")
        )
        .is_ok());
        assert!(validate_report_url("triage", "https://tria.ge/210809-abc123xyz").is_ok());
    }

    #[test]
    fn rejects_insecure_and_deceptive_urls() {
        assert_eq!(
            validate_report_url("virustotal", &format!("http://www.virustotal.com/gui/file/{SHA}")),
            Err(UrlRejection::NotHttps)
        );
        assert_eq!(
            validate_report_url(
                "virustotal",
                &format!("https://www.virustotal.com.evil.example/gui/file/{SHA}")
            ),
            Err(UrlRejection::WrongHost)
        );
        assert_eq!(
            validate_report_url(
                "virustotal",
                &format!("https://user:pass@www.virustotal.com/gui/file/{SHA}")
            ),
            Err(UrlRejection::Credentials)
        );
        assert_eq!(
            validate_report_url(
                "virustotal",
                &format!("https://www.virustotal.com:8443/gui/file/{SHA}")
            ),
            Err(UrlRejection::Port)
        );
        assert_eq!(
            validate_report_url(
                "virustotal",
                &format!("https://www.virustotal.com/gui/file/{SHA}?x=1")
            ),
            Err(UrlRejection::QueryOrFragment)
        );
        assert_eq!(
            validate_report_url("virustotal", "javascript:alert(1)"),
            Err(UrlRejection::NotHttps)
        );
        assert_eq!(
            validate_report_url("virustotal", "not a url"),
            Err(UrlRejection::Malformed)
        );
    }

    #[test]
    fn rejects_wrong_paths_and_non_matching_hashes() {
        assert_eq!(
            validate_report_url("virustotal", "https://www.virustotal.com/gui/file/notahash"),
            Err(UrlRejection::WrongPath)
        );
        assert_eq!(
            validate_report_url("malwarebazaar", &format!("https://bazaar.abuse.ch/browse/{SHA}/")),
            Err(UrlRejection::WrongPath)
        );
        assert_eq!(
            validate_report_url("triage", "https://tria.ge/../../etc/passwd"),
            Err(UrlRejection::WrongPath)
        );
        assert_eq!(
            validate_report_url("urlhaus", "https://urlhaus.abuse.ch/url/abc/"),
            Err(UrlRejection::WrongPath)
        );
    }

    #[test]
    fn providers_without_a_report_page_reject_every_url() {
        assert_eq!(
            validate_report_url("threatfox", "https://threatfox.abuse.ch/ioc/123/"),
            Err(UrlRejection::WrongPath)
        );
        assert_eq!(
            validate_report_url("metadefender", "https://metadefender.opswat.com/results"),
            Err(UrlRejection::WrongPath)
        );
    }

    #[test]
    fn hash_validation_is_strict() {
        assert!(is_sha256(SHA));
        assert!(is_sha256(&SHA.to_ascii_uppercase()));
        assert!(!is_sha256(&SHA[..63]));
        assert!(!is_sha256(&format!("{}g", &SHA[..63])));
        assert!(!is_sha256(""));
    }

    #[test]
    fn constructed_urls_are_validated() {
        assert!(virustotal_report_url(SHA).is_some());
        assert!(malwarebazaar_report_url(SHA).is_some());
        assert!(hybrid_analysis_report_url(SHA).is_some());
        assert!(triage_report_url("210809-abc123").is_some());
        assert!(triage_report_url("not a valid id").is_none());
        assert!(virustotal_report_url("short").is_none());
    }
}
