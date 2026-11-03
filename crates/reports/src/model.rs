


use serde::{Deserialize, Serialize};



#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    pub id: &'static str,
    pub name: &'static str,
    

    pub homepage: &'static str,
    

    pub docs_url: &'static str,
    

    pub requires_auth: bool,
    

    pub credential_label: &'static str,
    

    pub implemented: bool,
    

    pub integration: &'static str,
    

    pub notes: &'static str,
}



#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderStatus {
    #[serde(flatten)]
    pub info: ProviderInfo,
    

    pub configured: bool,
    

    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupStatus {
    

    ReportFound,
    

    NotFound,
    

    Unsupported,
    

    AuthenticationRequired,
    

    RateLimited,
    

    Unavailable,
    

    LookupFailed,
}

impl LookupStatus {
    pub fn label(self) -> &'static str {
        match self {
            LookupStatus::ReportFound => "Report found",
            LookupStatus::NotFound => "No report found",
            LookupStatus::Unsupported => "Unsupported",
            LookupStatus::AuthenticationRequired => "Authentication required",
            LookupStatus::RateLimited => "Rate limited",
            LookupStatus::Unavailable => "Unavailable",
            LookupStatus::LookupFailed => "Lookup failed",
        }
    }

    pub fn is_failure(self) -> bool {
        matches!(
            self,
            LookupStatus::RateLimited | LookupStatus::Unavailable | LookupStatus::LookupFailed
        )
    }
}





#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResult {
    pub provider_id: String,
    pub provider_name: String,
    pub sha256: String,
    pub status: LookupStatus,
    pub report_url: Option<String>,
    pub message: Option<String>,
    pub checked_at: String,
    pub requires_auth: bool,
    pub error_code: Option<String>,
    

    pub http_status: Option<u16>,
    pub elapsed_ms: u64,
}

impl ProviderResult {
    pub fn new(info: &ProviderInfo, sha256: &str, status: LookupStatus) -> Self {
        Self {
            provider_id: info.id.to_string(),
            provider_name: info.name.to_string(),
            sha256: sha256.to_string(),
            status,
            report_url: None,
            message: None,
            checked_at: crate::now_utc(),
            requires_auth: info.requires_auth,
            error_code: None,
            http_status: None,
            elapsed_ms: 0,
        }
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn report_url(mut self, url: impl Into<String>) -> Self {
        self.report_url = Some(url.into());
        self
    }

    pub fn error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    pub fn http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    pub fn elapsed(mut self, elapsed_ms: u64) -> Self {
        self.elapsed_ms = elapsed_ms;
        self
    }
}



#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupSummary {
    pub lookup_id: String,
    pub sha256: String,
    pub results: Vec<ProviderResult>,
    pub checked: usize,
    pub found: usize,
    pub cancelled: bool,
    pub started_at: String,
    pub finished_at: String,
}





#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashInfo {
    pub sha256: String,
    pub size: u64,
    pub source: HashSource,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashSource {
    

    

    AnalysisCache,
    

    #[default]
    Calculated,
}



#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("the selected file does not exist or is not a regular file")]
    NotFound,
    #[error("the file could not be read: {0}")]
    Io(String),
    #[error("the file changed while it was being hashed; select it again")]
    FileChanged,
    #[error("the file no longer matches the analysed hash; run the analysis again")]
    HashMismatch,
    #[error("the provided SHA-256 value is malformed")]
    InvalidHash,
    #[error("the lookup was cancelled")]
    Cancelled,
}

impl From<HashError> for String {
    fn from(error: HashError) -> Self {
        error.to_string()
    }
}



pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_labels_are_explicit() {
        assert_eq!(LookupStatus::ReportFound.label(), "Report found");
        assert_eq!(LookupStatus::NotFound.label(), "No report found");
        assert_eq!(
            LookupStatus::AuthenticationRequired.label(),
            "Authentication required"
        );
        assert!(LookupStatus::RateLimited.is_failure());
        assert!(!LookupStatus::NotFound.is_failure());
    }

    #[test]
    fn human_size_is_stable() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(9 * 1024 * 1024 + 153_600), "9.1 MiB");
    }
}
