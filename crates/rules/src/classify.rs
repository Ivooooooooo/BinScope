use binscope_signatures::Category as SignatureCategory;
use binscope_yara::YaraMatch;
use std::collections::BTreeSet;

pub const YARA_CATEGORIES: &[(&str, &str, &str)] = &[
    (
        "malware",
        "Malware",
        "Malware families and behaviours backed by rule metadata or tags.",
    ),
    (
        "anti-analysis",
        "Anti-Analysis",
        "Anti-debugging, anti-VM, evasion, obfuscation and packing indicators.",
    ),
    (
        "networking",
        "Networking",
        "C2, suspicious URLs/domains, protocols and tunnelling indicators.",
    ),
    (
        "exploits",
        "Exploits",
        "Known exploits, CVE payloads and documents carrying exploit code.",
    ),
    (
        "documents",
        "Documents",
        "PDF, Office, macro and archive-borne document threats.",
    ),
    (
        "scripts",
        "Scripts",
        "PowerShell, JavaScript, VBScript, Python, shell and other scripts.",
    ),
    (
        "offensive-tools",
        "Offensive Tools",
        "Red-team frameworks, post-exploitation tools and webshells.",
    ),
    (
        "persistence",
        "Persistence",
        "Windows, Linux and macOS persistence artefacts.",
    ),
    (
        "credential-theft",
        "Credential Theft",
        "Credential, cookie, session and token theft, keyloggers.",
    ),
    (
        "drivers-kernel",
        "Drivers & Kernel",
        "Suspicious and vulnerable drivers, kernel/rootkit artefacts.",
    ),
    (
        "crypto-obfuscation",
        "Crypto & Obfuscation",
        "Cryptographic patterns, encoded strings and encrypted payloads.",
    ),
    (
        "file-formats",
        "File Formats",
        "PE/DLL, ELF, Mach-O, .NET, installers and special formats.",
    ),
    (
        "forensics",
        "Forensics & Indicators",
        "Forensic artefacts and published indicators.",
    ),
    (
        "custom",
        "Custom Rules",
        "Rules imported by the user or not classifiable from metadata.",
    ),
];

pub const SIGNATURE_CATEGORIES: &[(&str, &str, &str)] = &[
    (
        "packers",
        "Packers",
        "Executable packers and compression wrappers.",
    ),
    (
        "protectors",
        "Protectors",
        "Runtime protectors, virtualizers and commercial shields.",
    ),
    (
        "compilers",
        "Compilers",
        "Compiler and language toolchains.",
    ),
    ("linkers", "Linkers", "Linker and build-tool signatures."),
    (
        "executable-formats",
        "Executable Formats",
        "PE, ELF, Mach-O and container formats.",
    ),
    (
        "dotnet-tools",
        ".NET Tools",
        "Managed runtimes, obfuscators and .NET build tools.",
    ),
    (
        "installers",
        "Installers",
        "Installer and self-extracting archive builders.",
    ),
    (
        "obfuscators",
        "Obfuscators",
        "Obfuscation and code-mutation tools.",
    ),
    (
        "anti-debug",
        "Anti-Debugging Markers",
        "Markers associated with anti-debugging.",
    ),
    (
        "anti-vm",
        "Anti-VM Markers",
        "Markers associated with VM and sandbox checks.",
    ),
    (
        "crypto-libs",
        "Cryptographic Libraries",
        "Embedded cryptographic libraries.",
    ),
    (
        "runtime-libs",
        "Runtime Libraries",
        "Language and application runtime libraries.",
    ),
    (
        "custom",
        "Custom Signatures",
        "Signatures imported by the user.",
    ),
];

pub fn yara_category_label(id: &str) -> &str {
    YARA_CATEGORIES
        .iter()
        .find(|(category, _, _)| *category == id)
        .map(|(_, label, _)| *label)
        .unwrap_or("Custom Rules")
}

pub fn signature_category_label(id: &str) -> &str {
    SIGNATURE_CATEGORIES
        .iter()
        .find(|(category, _, _)| *category == id)
        .map(|(_, label, _)| *label)
        .unwrap_or("Custom Signatures")
}

pub fn signature_category_for(category: SignatureCategory) -> &'static str {
    match category {
        SignatureCategory::Packer => "packers",
        SignatureCategory::Protector => "protectors",
        SignatureCategory::Compiler => "compilers",
        SignatureCategory::Linker => "linkers",
        SignatureCategory::Runtime => "runtime-libs",
        SignatureCategory::Framework => "runtime-libs",
        SignatureCategory::Installer => "installers",
        SignatureCategory::Tool => "custom",
        SignatureCategory::Signer => "executable-formats",
        SignatureCategory::Format => "executable-formats",
        SignatureCategory::Language => "compilers",
        SignatureCategory::Library => "runtime-libs",
        SignatureCategory::Other => "custom",
    }
}

pub fn classify_yara_match(matched: &YaraMatch) -> Vec<String> {
    let tags = matched.tags.clone();
    let mut metadata = Vec::new();
    if let Some(array) = matched.metadata.as_array() {
        for pair in array {
            let key = pair.get(0).and_then(|v| v.as_str()).unwrap_or_default();
            let value = pair.get(1).and_then(|v| v.as_str()).unwrap_or_default();
            if matches!(
                key.to_ascii_lowercase().as_str(),
                "category" | "categories" | "family" | "malware_type" | "type" | "severity"
            ) {
                metadata.push(value.to_string());
            }
        }
    }
    classify_yara_components(&matched.rule, &tags, &metadata, &matched.origin)
}

pub fn classify_yara_rule(
    name: &str,
    tags: &[String],
    metadata: &[(String, String)],
    source_path: &str,
) -> Vec<String> {
    let metadata: Vec<String> = metadata
        .iter()
        .filter(|(key, _)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "category" | "categories" | "family" | "malware_type" | "type" | "severity"
            )
        })
        .map(|(_, value)| value.clone())
        .collect();
    classify_yara_components(name, tags, &metadata, source_path)
}

fn classify_yara_components(
    name: &str,
    tags: &[String],
    metadata: &[String],
    source_path: &str,
) -> Vec<String> {
    let mut result = BTreeSet::new();
    let mut tokens: Vec<String> = Vec::new();
    tokens.extend(tags.iter().map(|t| t.to_ascii_lowercase()));
    for value in metadata {
        tokens.extend(
            value
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .filter(|t| t.len() >= 3)
                .map(|t| t.to_ascii_lowercase()),
        );
    }
    let path = source_path.to_ascii_lowercase();
    for token in &tokens {
        add_token_category(&mut result, token);
    }
    for token in name
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .filter(|token| token.len() >= 3)
    {
        add_token_category(&mut result, &token.to_ascii_lowercase());
    }
    for token in path
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .filter(|token| token.len() >= 3)
    {
        add_token_category(&mut result, token);
    }
    if path.contains("\\eset-ioc\\") || path.contains("/eset-ioc/") {
        result.insert("malware".into());
    }
    if path.contains("\\gcti\\") || path.contains("/gcti/") {
        result.insert("offensive-tools".into());
    }
    if path.contains("\\mandiant-rtc\\") || path.contains("/mandiant-rtc/") {
        result.insert("offensive-tools".into());
    }
    if result.is_empty() {
        let lower_name = name.to_ascii_lowercase();
        if lower_name.starts_with("binscope_packer")
            || lower_name.starts_with("binscope_protector")
            || lower_name.contains("packer")
            || lower_name.contains("protector")
        {
            result.insert("anti-analysis".into());
        }
        if lower_name.starts_with("binscope_compiler")
            || lower_name.starts_with("binscope_toolchain")
            || lower_name.starts_with("binscope_pe_")
            || lower_name.starts_with("binscope_dotnet")
        {
            result.insert("file-formats".into());
        }
        if lower_name.contains("mimikatz") || lower_name.contains("credential") {
            result.insert("credential-theft".into());
        }
        if lower_name.contains("cobaltstrike") || lower_name.contains("webshell") {
            result.insert("offensive-tools".into());
        }
        if path.contains("/malware/") || path.contains("\\malware\\") {
            result.insert("malware".into());
        }
        if path.contains("/anti") || path.contains("\\anti") || path.contains("/packer") {
            result.insert("anti-analysis".into());
        }
    }
    if result.is_empty() {
        result.insert("custom".into());
    }
    result.into_iter().collect()
}

fn add_token_category(result: &mut BTreeSet<String>, token: &str) {
    let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
    match token {
        "malware" | "ransomware" | "ransom" | "stealer" | "infostealer" | "rat" | "backdoor"
        | "loader" | "dropper" | "banker" | "banking" | "miner" | "cryptominer" | "worm"
        | "rootkit" | "apt" | "trojan" | "botnet" => {
            result.insert("malware".into());
        }
        "anti-debug" | "antidebug" | "anti-vm" | "antivm" | "anti-sandbox" | "anti-analysis"
        | "evasion" | "obfuscation" | "obfuscated" | "packer" | "packed" | "protector"
        | "virtualizer" => {
            result.insert("anti-analysis".into());
        }
        "c2"
        | "command-and-control"
        | "networking"
        | "network"
        | "tunnel"
        | "tunneling"
        | "dns"
        | "http"
        | "https"
        | "url"
        | "domain" => {
            result.insert("networking".into());
        }
        "exploit" | "exploits" | "cve" | "payload" => {
            result.insert("exploits".into());
        }
        "pdf" | "office" | "word" | "excel" | "macro" | "document" | "archive" => {
            result.insert("documents".into());
        }
        "powershell" | "javascript" | "js" | "vbscript" | "python" | "shell" | "script"
        | "scripts" => {
            result.insert("scripts".into());
        }
        "red-team" | "redteam" | "offensive-tools" | "offensive" | "hacktool" | "hacktools"
        | "cobaltstrike" | "mimikatz" | "webshell" | "post-exploitation" | "remote-access" => {
            result.insert("offensive-tools".into());
        }
        "persistence" | "startup" | "run-key" | "autorun" => {
            result.insert("persistence".into());
        }
        "credential" | "credentials" | "credential-theft" | "credtheft" | "keylogger"
        | "cookie" | "cookies" | "token" | "tokens" | "lsass" => {
            result.insert("credential-theft".into());
        }
        "driver" | "drivers" | "kernel" => {
            result.insert("drivers-kernel".into());
        }
        "crypto" | "cryptographic" | "encoded" | "encrypted" | "encryption" => {
            result.insert("crypto-obfuscation".into());
        }
        "pe" | "elf" | "macho" | "dotnet" | "installer" | "format" | "formats" | "file-formats"
        | "pe32" | "pe64" => {
            result.insert("file-formats".into());
        }
        "forensics" | "forensic" | "indicator" | "indicators" | "ioc" | "cert" | "certs"
        | "certificate" | "certificates" | "blocklist" => {
            result.insert("forensics".into());
        }
        "custom" => {
            result.insert("custom".into());
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn metadata_beats_a_url_in_a_rule_body() {
        let categories = classify_yara_rule(
            "binscope_note_example",
            &tags(&["forensics"]),
            &[("description".into(), "https://example.invalid".into())],
            "rules/general/example.yar",
        );
        assert_eq!(categories, vec!["forensics"]);
    }

    #[test]
    fn explicit_tags_add_multiple_categories_without_duplicates() {
        let categories = classify_yara_rule(
            "sample",
            &tags(&["malware", "ransomware", "credential-theft"]),
            &[],
            "rules/malware/sample.yar",
        );
        assert!(categories.contains(&"malware".to_string()));
        assert!(categories.contains(&"credential-theft".to_string()));
        assert_eq!(categories.iter().filter(|c| *c == "malware").count(), 1);
    }

    #[test]
    fn signature_categories_are_controlled() {
        assert_eq!(signature_category_for(SignatureCategory::Packer), "packers");
        assert_eq!(
            signature_category_for(SignatureCategory::Protector),
            "protectors"
        );
        assert_eq!(
            signature_category_for(SignatureCategory::Format),
            "executable-formats"
        );
    }

    #[test]
    fn source_paths_and_certificate_names_add_conservative_categories() {
        let cert = classify_yara_rule(
            "cert_blocklist_deadbeef",
            &[],
            &[],
            "sources/reversinglabs/yara/certificate/blocklist.yara",
        );
        assert!(cert.contains(&"forensics".to_string()));
        let eset = classify_yara_rule(
            "ramFS",
            &[],
            &[],
            "sources/eset-ioc/animalfarm/animalfarm.yar",
        );
        assert!(eset.contains(&"malware".to_string()));
    }
}
