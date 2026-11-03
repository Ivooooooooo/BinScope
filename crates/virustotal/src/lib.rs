use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

pub const DEFAULT_BASE_URL: &str = "https://www.virustotal.com/api/v3";

pub const STANDARD_UPLOAD_LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum VtError {
    #[error("no VirusTotal API key is configured")]
    MissingApiKey,
    #[error("VirusTotal rejected the API key (HTTP 401)")]
    Unauthorized,
    #[error("the API key is not permitted to perform this request (HTTP 403)")]
    Forbidden,
    #[error("VirusTotal rate limit reached{}", .retry_after.map(|s| format!("; retry after {s}s")).unwrap_or_default())]
    RateLimited { retry_after: Option<u64> },
    #[error("VirusTotal quota exceeded for this API key")]
    QuotaExceeded,
    #[error("file is {size} bytes; the standard VirusTotal upload limit is {limit} bytes")]
    TooLarge { size: u64, limit: u64 },
    #[error("network error: {0}")]
    Network(String),
    #[error("VirusTotal API error (HTTP {status}{code}): {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("invalid or unexpected VirusTotal response: {0}")]
    InvalidResponse(String),
    #[error("invalid SHA-256 value: {0}")]
    InvalidHash(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VtStats {
    pub harmless: u32,
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub timeout: u32,
    pub failure: u32,
    pub type_unsupported: u32,
    pub confirmed_timeout: u32,
}

impl VtStats {
    pub fn total(&self) -> u32 {
        self.harmless
            + self.malicious
            + self.suspicious
            + self.undetected
            + self.timeout
            + self.failure
            + self.type_unsupported
            + self.confirmed_timeout
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VtEngineResult {
    pub engine: String,
    pub category: String,
    pub result: Option<String>,
    pub method: Option<String>,
    pub engine_version: Option<String>,
    pub engine_update: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VtFileReport {
    pub sha256: String,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub meaningful_name: Option<String>,
    pub type_description: Option<String>,
    pub size: Option<u64>,
    pub reputation: Option<i64>,
    pub times_submitted: Option<u64>,
    pub unique_sources: Option<u64>,
    pub tags: Vec<String>,
    pub last_analysis_date: Option<u64>,
    pub first_submission_date: Option<u64>,
    pub last_submission_date: Option<u64>,
    pub stats: VtStats,
    pub engines: Vec<VtEngineResult>,
    pub permalink: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VtUploadReceipt {
    pub analysis_id: String,
    pub status: Option<String>,
}

pub struct VirusTotalClient {
    api_key: String,
    base_url: String,
    http: reqwest::Client,
    max_upload_bytes: u64,
}

impl fmt::Debug for VirusTotalClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirusTotalClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("max_upload_bytes", &self.max_upload_bytes)
            .finish()
    }
}

impl VirusTotalClient {
    pub fn new(api_key: impl Into<String>) -> Result<Self, VtError> {
        let api_key = api_key.into();
        if api_key.trim().is_empty() {
            return Err(VtError::MissingApiKey);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(15))
            .user_agent(concat!("BinScope/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| VtError::Network(e.to_string()))?;
        Ok(Self {
            api_key: api_key.trim().to_string(),
            base_url: DEFAULT_BASE_URL.to_string(),
            http,
            max_upload_bytes: STANDARD_UPLOAD_LIMIT,
        })
    }

    pub fn with_base_url(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self, VtError> {
        let mut client = Self::new(api_key)?;
        client.base_url = base_url.into().trim_end_matches('/').to_string();
        Ok(client)
    }

    pub fn set_max_upload_bytes(&mut self, limit: u64) {
        self.max_upload_bytes = limit;
    }

    pub async fn lookup(&self, sha256: &str) -> Result<Option<VtFileReport>, VtError> {
        let hash = sha256.trim().to_ascii_lowercase();
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VtError::InvalidHash(sha256.to_string()));
        }
        let url = format!("{}/files/{}", self.base_url, hash);
        let response = self
            .http
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        let headers = response.headers().clone();
        let body = response.text().await.map_err(network_error)?;
        let value = check_response(status.as_u16(), &headers, &body)?;
        parse_file_response(&value).map(Some)
    }

    pub async fn upload(&self, path: &Path) -> Result<VtUploadReceipt, VtError> {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > self.max_upload_bytes {
            return Err(VtError::TooLarge {
                size: metadata.len(),
                limit: self.max_upload_bytes,
            });
        }
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "sample.bin".to_string());
        let bytes = tokio::fs::read(path).await?;
        let part = reqwest::multipart::Part::bytes(bytes).file_name(file_name);
        let form = reqwest::multipart::Form::new().part("file", part);
        let url = format!("{}/files", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("x-apikey", &self.api_key)
            .multipart(form)
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.map_err(network_error)?;
        let value = check_response(status.as_u16(), &headers, &body)?;
        parse_upload_response(&value)
    }

    pub async fn analysis(&self, analysis_id: &str) -> Result<VtUploadReceipt, VtError> {
        if analysis_id.is_empty() || analysis_id.len() > 256 {
            return Err(VtError::InvalidResponse("invalid analysis id".into()));
        }
        let url = format!("{}/analyses/{}", self.base_url, analysis_id);
        let response = self
            .http
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.map_err(network_error)?;
        let value = check_response(status.as_u16(), &headers, &body)?;
        parse_upload_response(&value)
    }
}

fn network_error(e: reqwest::Error) -> VtError {
    if e.is_timeout() {
        VtError::Network("request timed out".into())
    } else {
        VtError::Network(e.to_string())
    }
}

fn check_response(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Result<serde_json::Value, VtError> {
    if status == 200 || status == 201 {
        return serde_json::from_str(body).map_err(|e| {
            VtError::InvalidResponse(format!("{e} (body starts with {:?})", truncate(body, 120)))
        });
    }
    let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/code"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let message = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/message"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| truncate(body, 300));
    match status {
        401 => Err(VtError::Unauthorized),
        403 => Err(VtError::Forbidden),
        413 => Err(VtError::Api {
            status,
            code: if code.is_empty() {
                "TooLarge".into()
            } else {
                code
            },
            message: if message.is_empty() {
                "VirusTotal rejected the upload because the file is too large".into()
            } else {
                message
            },
        }),
        429 => {
            if code.eq_ignore_ascii_case("QuotaExceeded")
                || message.to_lowercase().contains("quota")
            {
                Err(VtError::QuotaExceeded)
            } else {
                let retry_after = headers
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok());
                Err(VtError::RateLimited { retry_after })
            }
        }
        _ => Err(VtError::Api {
            status,
            code,
            message,
        }),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let cleaned: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

pub fn parse_file_response(value: &serde_json::Value) -> Result<VtFileReport, VtError> {
    let data = value
        .get("data")
        .ok_or_else(|| VtError::InvalidResponse("missing data object".into()))?;
    let attributes = data
        .get("attributes")
        .ok_or_else(|| VtError::InvalidResponse("missing data.attributes".into()))?;
    let sha256 = data
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| attributes.get("sha256").and_then(|v| v.as_str()))
        .ok_or_else(|| VtError::InvalidResponse("missing file id".into()))?
        .to_string();

    let stats = parse_stats(attributes.get("last_analysis_stats"));
    let mut engines = Vec::new();
    if let Some(results) = attributes
        .get("last_analysis_results")
        .and_then(|v| v.as_object())
    {
        for (name, result) in results {
            let get = |key: &str| {
                result
                    .get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };
            engines.push(VtEngineResult {
                engine: get("engine_name").unwrap_or_else(|| name.clone()),
                category: get("category").unwrap_or_else(|| "unknown".into()),
                result: get("result"),
                method: get("method"),
                engine_version: get("engine_version"),
                engine_update: get("engine_update"),
            });
        }
    }
    engines.sort_by(|a, b| {
        severity(&b.category)
            .cmp(&severity(&a.category))
            .then(a.engine.cmp(&b.engine))
    });
    let tags = attributes
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(VtFileReport {
        permalink: format!("https://www.virustotal.com/gui/file/{sha256}"),
        sha256,
        sha1: attributes
            .get("sha1")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        md5: attributes
            .get("md5")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        meaningful_name: attributes
            .get("meaningful_name")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        type_description: attributes
            .get("type_description")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        size: attributes.get("size").and_then(|v| v.as_u64()),
        reputation: attributes.get("reputation").and_then(|v| v.as_i64()),
        times_submitted: attributes.get("times_submitted").and_then(|v| v.as_u64()),
        unique_sources: attributes.get("unique_sources").and_then(|v| v.as_u64()),
        tags,
        last_analysis_date: attributes
            .get("last_analysis_date")
            .and_then(|v| v.as_u64()),
        first_submission_date: attributes
            .get("first_submission_date")
            .and_then(|v| v.as_u64()),
        last_submission_date: attributes
            .get("last_submission_date")
            .and_then(|v| v.as_u64()),
        stats,
        engines,
    })
}

fn severity(category: &str) -> u8 {
    match category {
        "malicious" => 4,
        "suspicious" => 3,
        "undetected" => 2,
        "harmless" => 1,
        _ => 0,
    }
}

fn parse_stats(value: Option<&serde_json::Value>) -> VtStats {
    let Some(obj) = value.and_then(|v| v.as_object()) else {
        return VtStats::default();
    };
    let get = |key: &str| {
        obj.get(key)
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32
    };
    VtStats {
        harmless: get("harmless"),
        malicious: get("malicious"),
        suspicious: get("suspicious"),
        undetected: get("undetected"),
        timeout: get("timeout"),
        failure: get("failure"),
        type_unsupported: get("type-unsupported"),
        confirmed_timeout: get("confirmed-timeout"),
    }
}

pub fn parse_upload_response(value: &serde_json::Value) -> Result<VtUploadReceipt, VtError> {
    let data = value
        .get("data")
        .ok_or_else(|| VtError::InvalidResponse("missing data object".into()))?;
    let analysis_id = data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VtError::InvalidResponse("missing analysis id".into()))?
        .to_string();
    let status = data
        .pointer("/attributes/status")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok(VtUploadReceipt {
        analysis_id,
        status,
    })
}

pub fn verdict_counts(stats: &VtStats) -> BTreeMap<&'static str, u32> {
    let mut map = BTreeMap::new();
    map.insert("malicious", stats.malicious);
    map.insert("suspicious", stats.suspicious);
    map.insert("harmless", stats.harmless);
    map.insert("undetected", stats.undetected);
    map.insert("timeout", stats.timeout);
    map.insert("failure", stats.failure);
    map.insert("type-unsupported", stats.type_unsupported);
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "type": "file",
                "id": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                "attributes": {
                    "sha1": "1111111111111111111111111111111111111111",
                    "md5": "22222222222222222222222222222222",
                    "meaningful_name": "sample.exe",
                    "type_description": "Win32 EXE",
                    "size": 123456,
                    "reputation": -12,
                    "times_submitted": 42,
                    "unique_sources": 7,
                    "tags": ["peexe", "upx"],
                    "last_analysis_date": 1700000000u64,
                    "first_submission_date": 1600000000u64,
                    "last_submission_date": 1700000001u64,
                    "last_analysis_stats": {
                        "harmless": 10,
                        "malicious": 3,
                        "suspicious": 1,
                        "undetected": 50,
                        "timeout": 0,
                        "failure": 1,
                        "type-unsupported": 2,
                        "confirmed-timeout": 0
                    },
                    "last_analysis_results": {
                        "EngineB": {"engine_name":"EngineB","category":"harmless","result":null,"method":"blacklist","engine_version":"1.0","engine_update":"20260101"},
                        "EngineA": {"engine_name":"EngineA","category":"malicious","result":"Trojan.Test","method":"signature","engine_version":"2.0","engine_update":"20260102"}
                    }
                }
            }
        })
    }

    #[test]
    fn parses_full_file_response() {
        let report = parse_file_response(&sample_response()).unwrap();
        assert_eq!(report.meaningful_name.as_deref(), Some("sample.exe"));
        assert_eq!(report.stats.malicious, 3);
        assert_eq!(report.stats.total(), 67);
        assert_eq!(report.tags, vec!["peexe", "upx"]);
        assert_eq!(report.engines[0].engine, "EngineA");
        assert_eq!(report.engines[0].result.as_deref(), Some("Trojan.Test"));
        assert!(report.permalink.ends_with(&report.sha256));
    }

    #[test]
    fn parses_minimal_response_without_optional_fields() {
        let value = serde_json::json!({
            "data": {"id": "abc", "attributes": {}}
        });
        let report = parse_file_response(&value).unwrap();
        assert_eq!(report.sha256, "abc");
        assert_eq!(report.stats.malicious, 0);
        assert!(report.engines.is_empty());
    }

    #[test]
    fn missing_id_is_an_error() {
        let value = serde_json::json!({"data": {"attributes": {}}});
        assert!(matches!(
            parse_file_response(&value),
            Err(VtError::InvalidResponse(_))
        ));
    }

    #[test]
    fn status_mapping_is_actionable() {
        let headers = reqwest::header::HeaderMap::new();
        assert!(matches!(
            check_response(401, &headers, "{}"),
            Err(VtError::Unauthorized)
        ));
        assert!(matches!(
            check_response(403, &headers, "{}"),
            Err(VtError::Forbidden)
        ));
        let quota = r#"{"error":{"code":"QuotaExceeded","message":"Quota exceeded"}}"#;
        assert!(matches!(
            check_response(429, &headers, quota),
            Err(VtError::QuotaExceeded)
        ));
        let rate = r#"{"error":{"code":"TooManyRequests","message":"Slow down"}}"#;
        assert!(matches!(
            check_response(429, &headers, rate),
            Err(VtError::RateLimited { retry_after: None })
        ));
        let api = r#"{"error":{"code":"NotFoundError","message":"Not found"}}"#;
        match check_response(400, &headers, api) {
            Err(VtError::Api { status, code, .. }) => {
                assert_eq!(status, 400);
                assert_eq!(code, "NotFoundError");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn upload_response_is_parsed() {
        let value = serde_json::json!({
            "data": {"type": "analysis", "id": "analysis-id", "attributes": {"status": "queued"}}
        });
        let receipt = parse_upload_response(&value).unwrap();
        assert_eq!(receipt.analysis_id, "analysis-id");
        assert_eq!(receipt.status.as_deref(), Some("queued"));
    }

    #[test]
    fn api_key_is_never_debug_printed() {
        let client = VirusTotalClient::new("super-secret-key").unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains("super-secret-key"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn empty_key_and_invalid_hash_are_rejected() {
        assert!(matches!(
            VirusTotalClient::new("   "),
            Err(VtError::MissingApiKey)
        ));
        let client = VirusTotalClient::new("key").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(matches!(
                client.lookup("not-a-hash").await,
                Err(VtError::InvalidHash(_))
            ));
        });
    }

    #[test]
    fn too_large_upload_is_refused_before_network_io() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        std::fs::write(&path, vec![0u8; 2048]).unwrap();
        let mut client = VirusTotalClient::new("key").unwrap();
        client.set_max_upload_bytes(1024);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(matches!(
                client.upload(&path).await,
                Err(VtError::TooLarge { .. })
            ));
        });
    }

    #[test]
    fn quota_variants_are_distinguished() {
        let headers = reqwest::header::HeaderMap::new();
        let msg = r#"{"error":{"code":"QuotaExceeded","message":"You have exceeded your quota"}}"#;
        assert!(matches!(
            check_response(429, &headers, msg),
            Err(VtError::QuotaExceeded)
        ));
    }

    #[test]
    fn verdict_counts_are_stable() {
        let stats = VtStats {
            malicious: 2,
            suspicious: 1,
            harmless: 5,
            undetected: 10,
            ..Default::default()
        };
        let counts = verdict_counts(&stats);
        assert_eq!(counts.get("malicious"), Some(&2));
        assert_eq!(counts.get("undetected"), Some(&10));
    }
}
