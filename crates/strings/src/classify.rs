use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringClass {
    Url,
    Domain,
    Ipv4,
    Ipv6,
    FilePath,
    RegistryPath,
    CommandLine,
    PowerShell,
    Mutex,
    Email,
    ExecutableName,
    Base64,
    Hexadecimal,
    Configuration,
}

impl StringClass {
    pub fn label(self) -> &'static str {
        match self {
            StringClass::Url => "URL",
            StringClass::Domain => "Domain",
            StringClass::Ipv4 => "IPv4",
            StringClass::Ipv6 => "IPv6",
            StringClass::FilePath => "File path",
            StringClass::RegistryPath => "Registry path",
            StringClass::CommandLine => "Command line",
            StringClass::PowerShell => "PowerShell",
            StringClass::Mutex => "Mutex",
            StringClass::Email => "Email",
            StringClass::ExecutableName => "Executable name",
            StringClass::Base64 => "Base64-like",
            StringClass::Hexadecimal => "Hex-encoded",
            StringClass::Configuration => "Configuration",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StringClassification {
    pub kind: StringClass,

    pub confidence: u8,

    pub note: Option<String>,
}

impl StringClassification {
    fn new(kind: StringClass, confidence: u8) -> Self {
        Self {
            kind,
            confidence,
            note: None,
        }
    }

    fn with_note(mut self, note: &str) -> Self {
        self.note = Some(note.to_string());
        self
    }
}

pub fn classify(value: &str) -> Vec<StringClassification> {
    let text = value.trim().trim_end_matches('\u{0}');
    if text.len() < 4 {
        return Vec::new();
    }
    let mut out = Vec::new();

    if is_url(text) {
        out.push(StringClassification::new(StringClass::Url, 92));
        return out;
    }
    if is_ipv4(text) {
        out.push(StringClassification::new(StringClass::Ipv4, 88));
        return out;
    }
    if is_ipv6(text) {
        out.push(StringClassification::new(StringClass::Ipv6, 88));
        return out;
    }
    if is_registry_path(text) {
        out.push(StringClassification::new(StringClass::RegistryPath, 86));
    }
    if is_email(text) {
        out.push(StringClassification::new(StringClass::Email, 84));
    }
    let executable = is_executable_name(text);
    let file_path = is_file_path(text);
    if file_path {
        out.push(StringClassification::new(StringClass::FilePath, 82));
    }
    if executable {
        out.push(StringClassification::new(StringClass::ExecutableName, 78));
    }
    if !executable && !file_path && is_domain(text) {
        out.push(StringClassification::new(StringClass::Domain, 72));
    }
    if is_powershell(text) {
        out.push(StringClassification::new(StringClass::PowerShell, 80));
    } else if is_command_line(text) {
        out.push(StringClassification::new(StringClass::CommandLine, 62));
    }
    if is_mutex(text) {
        out.push(StringClassification::new(StringClass::Mutex, 64));
    }
    if is_configuration(text) {
        out.push(StringClassification::new(StringClass::Configuration, 66));
    }
    if is_hex(text) {
        out.push(
            StringClassification::new(StringClass::Hexadecimal, 48)
                .with_note("Even-length hexadecimal candidate; not decoded automatically."),
        );
    } else if is_base64(text) {
        out.push(
            StringClassification::new(StringClass::Base64, 45)
                .with_note("Shaped like base64; not decoded automatically."),
        );
    }
    out
}

fn is_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if !(lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://"))
    {
        return false;
    }
    let Ok(url) = url::Url::parse(text) else {
        return false;
    };
    url.host_str().is_some() && !text.chars().any(char::is_whitespace)
}

fn is_ipv4(text: &str) -> bool {
    !text.contains(':') && Ipv4Addr::from_str(text).is_ok()
}

fn is_ipv6(text: &str) -> bool {
    text.contains(':') && text.matches(':').count() >= 2 && Ipv6Addr::from_str(text).is_ok()
}

fn is_domain(text: &str) -> bool {
    if text.len() > 253 || !text.contains('.') || text.contains(['/', '\\', ' ', '@', ':']) {
        return false;
    }
    let labels: Vec<&str> = text.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    let tld = labels.last().copied().unwrap_or_default();
    (2..=24).contains(&tld.len()) && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_file_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    let windows_drive = bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    let unc = text.starts_with("\\\\");
    let unix = text.starts_with('/') && text.matches('/').count() >= 2 && !text.contains(' ');
    windows_drive || unc || unix
}

fn is_registry_path(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("\\registry\\") {
        return true;
    }
    let root = lower.split('\\').next().unwrap_or_default();
    matches!(
        root,
        "hkey_local_machine"
            | "hkey_current_user"
            | "hkey_classes_root"
            | "hkey_users"
            | "hkey_current_config"
            | "hklm"
            | "hkcu"
            | "hkcr"
            | "hku"
            | "hkcc"
    ) && lower.contains('\\')
}

fn is_email(text: &str) -> bool {
    if text.matches('@').count() != 1 || text.contains(char::is_whitespace) {
        return false;
    }
    let (local, domain) = text.split_once('@').unwrap_or_default();
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
    {
        return false;
    }
    is_domain(domain)
}

fn is_executable_name(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const EXTENSIONS: [&str; 8] = [
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".drv",
    ];
    EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) && lower.len() <= 260
}

fn is_powershell(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const TOKENS: [&str; 10] = [
        "powershell",
        "pwsh",
        "invoke-expression",
        "invoke-webrequest",
        "frombase64string",
        "-windowstyle hidden",
        "-executionpolicy bypass",
        "downloadstring",
        "iex(",
        "iex ",
    ];
    TOKENS.iter().any(|token| lower.contains(token))
}

fn is_command_line(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if text.contains(char::is_whitespace)
        && (lower.contains(" -") || lower.contains(" /") || lower.contains(" --"))
        && (lower.contains(".exe") || lower.starts_with("cmd") || lower.starts_with("rundll32"))
    {
        return true;
    }
    false
}

fn is_mutex(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ((lower.starts_with("global\\") || lower.starts_with("local\\"))
        && text.len() > 8
        && !text.contains(' '))
        || (lower.contains("mutex") && !text.contains(char::is_whitespace) && text.contains('\\'))
}

fn is_configuration(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const KEYS: [&str; 8] = [
        "password=",
        "passwd=",
        "token=",
        "secret=",
        "api_key=",
        "apikey=",
        "authorization: bearer ",
        "-----begin ",
    ];
    KEYS.iter().any(|key| lower.contains(key))
}

fn is_base64(text: &str) -> bool {
    if text.len() < 24 || text.len() % 4 != 0 {
        return false;
    }
    let trimmed = text.trim_end_matches('=');
    if trimmed.len() < 20 {
        return false;
    }
    let padding = text.len() - trimmed.len();
    padding <= 2
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        && !text.starts_with('=')
}

fn is_hex(text: &str) -> bool {
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    body.len() >= 16 && body.len() % 2 == 0 && body.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(value: &str) -> Vec<StringClass> {
        classify(value).into_iter().map(|c| c.kind).collect()
    }

    #[test]
    fn urls_are_parsed_not_guessed() {
        assert_eq!(kinds("https://example.com/a?b=1"), vec![StringClass::Url]);
        assert!(kinds("https://").is_empty());
        assert!(kinds("http://exa mple.com").is_empty());
        assert_eq!(kinds("example.com"), vec![StringClass::Domain]);
    }

    #[test]
    fn addresses_use_proper_parsers() {
        assert_eq!(kinds("192.168.1.10"), vec![StringClass::Ipv4]);
        assert_eq!(kinds("2001:db8::1"), vec![StringClass::Ipv6]);
        assert!(kinds("999.1.1.1").is_empty());
        assert!(kinds("1.2.3").is_empty());
    }

    #[test]
    fn paths_and_registry_are_distinguished() {
        assert!(kinds(r"C:\Windows\System32\cmd.exe").contains(&StringClass::FilePath));
        assert!(kinds(r"HKEY_LOCAL_MACHINE\Software\Run").contains(&StringClass::RegistryPath));
        assert!(kinds(r"HKCU\Software\Microsoft").contains(&StringClass::RegistryPath));
        assert!(kinds("/etc/passwd").contains(&StringClass::FilePath));
        assert!(!kinds("one.2").contains(&StringClass::Domain));
    }

    #[test]
    fn executable_names_and_emails() {
        assert_eq!(kinds("kernel32.dll"), vec![StringClass::ExecutableName]);
        assert_eq!(kinds("analyst@example.org"), vec![StringClass::Email]);
        assert!(!kinds("not-an-email@").contains(&StringClass::Email));
    }

    #[test]
    fn powershell_and_command_lines_are_classified() {
        assert!(kinds("powershell -enc SQBFAFgA").contains(&StringClass::PowerShell));
        assert!(kinds("cmd.exe /c whoami").contains(&StringClass::CommandLine));
        assert!(!kinds("just a sentence with spaces").contains(&StringClass::CommandLine));
    }

    #[test]
    fn mutex_and_configuration_strings() {
        assert!(kinds(r"Global\MyMutexName").contains(&StringClass::Mutex));
        assert!(kinds("password=hunter2").contains(&StringClass::Configuration));
    }

    #[test]
    fn encoded_candidates_are_marked_not_decoded() {
        let b64 = classify("SGVsbG8gd29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==");
        assert_eq!(b64[0].kind, StringClass::Base64);
        assert!(b64[0].note.is_some());
        let hex = classify("4d5a90000300000004000000ffff0000");
        assert_eq!(hex[0].kind, StringClass::Hexadecimal);
    }

    #[test]
    fn plain_text_has_no_classification() {
        assert!(kinds("The quick brown fox").is_empty());
        assert!(kinds("").is_empty());
    }
}
