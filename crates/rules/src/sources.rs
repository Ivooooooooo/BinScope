use crate::model::{Profile, SourceDefinition, SourceStatus};

fn source(
    id: &str,
    name: &str,
    repo: &str,
    branch: &str,
    license: &str,
    enabled: bool,
    notes: &str,
) -> SourceDefinition {
    SourceDefinition {
        id: id.into(),
        name: name.into(),
        url: format!("https://github.com/{repo}"),
        kind: "yara".into(),
        method: "github_archive".into(),
        repo: Some(repo.into()),
        branch: Some(branch.into()),
        asset: None,
        include_prefixes: Vec::new(),
        license: Some(license.into()),
        license_url: Some(format!("https://github.com/{repo}/blob/{branch}/LICENSE")),
        default_enabled: enabled,
        implemented: true,
        notes: notes.into(),
    }
}

pub fn default_sources() -> Vec<SourceStatus> {
    let mut out = vec![
        source(
            "reversinglabs",
            "ReversingLabs YARA Rules",
            "reversinglabs/reversinglabs-yara-rules",
            "develop",
            "MIT",
            true,
            "Maintained family rules under yara/. Downloaded as a pinned GitHub archive.",
        ),
        source(
            "mandiant-rtc",
            "Mandiant Red Team Tool Countermeasures",
            "mandiant/red_team_tool_countermeasures",
            "master",
            "BSD-2-Clause",
            true,
            "Red-team tool rules. Scope is offensive tooling, not general malware.",
        ),
        source(
            "eset-ioc",
            "ESET Malware IOC",
            "eset/malware-ioc",
            "master",
            "BSD-2-Clause",
            true,
            "Family IOC rules organised by campaign; updated when the upstream repository changes.",
        ),
        source(
            "gcti",
            "Google Cloud Threat Intelligence",
            "chronicle/GCTI",
            "main",
            "Apache-2.0",
            true,
            "Cobalt Strike and targeted-threat YARA rules.",
        ),
        source(
            "ditekshen",
            "ditekSHen Detection",
            "ditekshen/detection",
            "master",
            "NOASSERTION",
            false,
            "Useful indicators, but the repository has no SPDX licence. Enable only after checking the upstream terms.",
        ),
        source(
            "yara-rules",
            "YARA-Rules Community",
            "Yara-Rules/rules",
            "master",
            "GPL-2.0",
            false,
            "Large historical collection; GPL-2.0 and less maintained. Not enabled by default.",
        ),
        source(
            "signature-base",
            "Neo23x0 signature-base",
            "Neo23x0/signature-base",
            "master",
            "NOASSERTION",
            false,
            "Mixed-licence rule set; repository does not declare a single SPDX licence. Disabled by default.",
        ),
        source(
            "elastic",
            "Elastic Protections Artifacts",
            "elastic/protections-artifacts",
            "main",
            "NOASSERTION",
            false,
            "Detection content is not a standalone YARA-only package. Disabled pending a licence review.",
        ),
        source(
            "inquest",
            "InQuest YARA Rules",
            "InQuest/yara-rules",
            "master",
            "MIT",
            false,
            "MIT-licensed but last updated in 2022; optional historical coverage.",
        ),
        source(
            "cape",
            "CAPE Sandbox",
            "kevoreilly/CAPEv2",
            "master",
            "NOASSERTION",
            false,
            "Not an automatic rule package: a large sandbox repository with engine code and no single licence. Enable only for manual review.",
        ),
    ];

    let mut yara_forge = source(
        "yara-forge-core",
        "YARA Forge Core",
        "YARAHQ/yara-forge",
        "master",
        "GPL-3.0",
        false,
        "Aggregated core release (one ~7.8 MB rule file). Validated before activation; GPL-3.0 terms apply.",
    );
    yara_forge.method = "github_release_zip".into();
    yara_forge.asset = Some("yara-forge-rules-core.zip".into());
    yara_forge.url = "https://github.com/YARAHQ/yara-forge/releases".into();
    yara_forge.license_url =
        Some("https://github.com/YARAHQ/yara-forge/blob/master/LICENSE".into());
    out.insert(0, yara_forge);
    if let Some(source) = out.iter_mut().find(|source| source.id == "cape") {
        source.implemented = false;
        source.method = "manual".into();
    }

    for (id, prefixes) in [
        ("mandiant-rtc", vec!["rules/".to_string()]),
        ("gcti", vec!["YARA/".to_string()]),
        ("reversinglabs", vec!["yara/".to_string()]),
    ] {
        if let Some(source) = out.iter_mut().find(|source| source.id == id) {
            source.include_prefixes = prefixes;
        }
    }

    out.into_iter().map(SourceStatus::from_definition).collect()
}

pub fn default_profiles() -> Vec<Profile> {
    let all_yara = crate::classify::YARA_CATEGORIES
        .iter()
        .map(|(id, _, _)| (*id).to_string())
        .collect::<Vec<_>>();
    let all_signatures = crate::classify::SIGNATURE_CATEGORIES
        .iter()
        .map(|(id, _, _)| (*id).to_string())
        .collect::<Vec<_>>();
    vec![
        Profile {
            id: "balanced".into(),
            name: "Balanced".into(),
            description: "General coverage with precision and performance first.".into(),
            yara_categories: vec![
                "malware".into(),
                "anti-analysis".into(),
                "file-formats".into(),
                "forensics".into(),
                "custom".into(),
            ],
            signature_categories: all_signatures.clone(),
            builtin: true,
        },
        Profile {
            id: "deep".into(),
            name: "Deep Scan".into(),
            description: "All YARA and signature categories, including documents, scripts and exploits.".into(),
            yara_categories: all_yara.clone(),
            signature_categories: all_signatures.clone(),
            builtin: true,
        },
        Profile {
            id: "malware-research".into(),
            name: "Malware Research".into(),
            description: "Malware, anti-analysis, offensive tooling, persistence, credentials and indicators.".into(),
            yara_categories: vec![
                "malware".into(),
                "anti-analysis".into(),
                "offensive-tools".into(),
                "persistence".into(),
                "credential-theft".into(),
                "drivers-kernel".into(),
                "crypto-obfuscation".into(),
                "forensics".into(),
                "custom".into(),
            ],
            signature_categories: vec![
                "packers".into(),
                "protectors".into(),
                "compilers".into(),
                "linkers".into(),
                "obfuscators".into(),
                "anti-debug".into(),
                "anti-vm".into(),
                "crypto-libs".into(),
                "runtime-libs".into(),
                "custom".into(),
            ],
            builtin: true,
        },
        Profile {
            id: "networking".into(),
            name: "Networking".into(),
            description: "C2, protocol, URL, domain and tunnelling indicators plus file formats.".into(),
            yara_categories: vec![
                "networking".into(),
                "malware".into(),
                "file-formats".into(),
                "forensics".into(),
                "custom".into(),
            ],
            signature_categories: all_signatures.clone(),
            builtin: true,
        },
        Profile {
            id: "custom".into(),
            name: "Custom".into(),
            description: "The user's current category and rule selection.".into(),
            yara_categories: all_yara,
            signature_categories: all_signatures,
            builtin: true,
        },
    ]
}
