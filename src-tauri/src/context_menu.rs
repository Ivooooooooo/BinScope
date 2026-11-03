use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const DISPLAY_NAME: &str = "Analyze with BinScope";
pub const VERB_NAME: &str = "BinScope.Analyze";
pub const SHELL_KEY: &str = r"Software\Classes\*\shell";
pub const VERB_KEY: &str = r"Software\Classes\*\shell\BinScope.Analyze";

#[allow(dead_code)]
pub const COMMAND_KEY: &str = r"Software\Classes\*\shell\BinScope.Analyze\command";
pub const SYSTEM_FILE_ASSOCIATIONS: &str = r"Software\Classes\SystemFileAssociations";

pub const PREFERENCE_KEY: &str = r"Software\BinScope\ContextMenu";
const PROBE_KEY: &str = r"Software\Classes";
const OWNER_VALUE: &str = "BinScopeOwner";
const OWNER_ID: &str = "BinScope";
const SCHEMA_VALUE: &str = "BinScopeSchema";
const SCHEMA_ID: &str = "2";
const EXE_VALUE: &str = "BinScopeExePath";
const PREF_ENABLED: &str = "Enabled";
const PREF_SCHEMA: &str = "Schema";
const PREF_RESULT: &str = "LastResult";
const PREF_UPDATED: &str = "UpdatedUtc";
const FILE_PLACEHOLDER: &str = "\"%1\"";
const MANAGED_VALUES: [&str; 6] = [
    "MUIVerb",
    "Icon",
    "MultiSelectModel",
    OWNER_VALUE,
    SCHEMA_VALUE,
    EXE_VALUE,
];
const MAX_OWNED_KEYS: usize = 512;

pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "scr", "cpl", "ocx", "efi", "bin", "elf", "so", "dylib", "pyd", "node",
    "ax", "acm", "drv", "mui",
];

const BUSY_MESSAGE: &str =
    "A Windows integration operation is already running; wait for it to finish.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildProfile {
    Development,
    Release,
}

impl BuildProfile {
    pub fn current() -> Self {
        if cfg!(debug_assertions) {
            BuildProfile::Development
        } else {
            BuildProfile::Release
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    PermissionDenied,
    NotFound,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryFault {
    pub kind: FaultKind,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Unsupported,
    PermissionDenied,
    Conflict,
    ExecutableUnavailable,
    DevelopmentBuild,
    Partial,
    Busy,
    Registry,
    NotEnabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMenuFailure {
    pub kind: FailureKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<String>,
}

impl ContextMenuFailure {
    pub fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            remaining: Vec::new(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::new(FailureKind::Conflict, message)
    }

    pub fn busy() -> Self {
        Self::new(FailureKind::Busy, BUSY_MESSAGE)
    }

    fn from_fault(fault: &RegistryFault, action: &str) -> Self {
        let kind = if fault.kind == FaultKind::PermissionDenied {
            FailureKind::PermissionDenied
        } else {
            FailureKind::Registry
        };
        let message = if kind == FailureKind::PermissionDenied {
            format!(
                "Windows denied access while trying to {action} HKEY_CURRENT_USER\\{VERB_KEY}. \
                 BinScope registers the entry for the current user only; sign in as the user who \
                 owns this profile and retry. ({})",
                fault.message
            )
        } else {
            format!(
                "Could not {action} HKEY_CURRENT_USER\\{VERB_KEY}: {}",
                fault.message
            )
        };
        Self::new(kind, message)
    }
}

impl std::fmt::Display for ContextMenuFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ContextMenuFailure {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMenuState {
    Unavailable,
    #[default]
    Disabled,
    Enabled,
    Stale,
    Partial,
    Failed,
    Foreign,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationInfo {
    pub key: String,
    pub installed: bool,
    pub current: bool,
    pub command_ok: bool,
    pub executable_exists: bool,
    pub executable: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMenuStatus {
    pub supported: bool,

    pub installed: bool,
    pub foreign_entry: bool,
    pub can_write: bool,
    pub requires_admin: bool,

    pub preference_enabled: bool,
    pub state: ContextMenuState,

    pub partial: bool,
    pub executable: Option<String>,
    pub registered_executable: Option<String>,
    pub executable_exists: bool,
    pub stale: bool,
    pub registrations: Vec<RegistrationInfo>,
    pub missing_targets: Vec<String>,
    pub stale_targets: Vec<String>,
    pub conflicts: Vec<String>,
    pub diagnostics: Vec<String>,
    pub registry_key: String,
    pub detail: String,
}

pub trait Registry {
    fn key_exists(&self, path: &str) -> Result<bool, RegistryFault>;
    fn read_string(&self, path: &str, name: &str) -> Result<Option<String>, RegistryFault>;
    fn set_string(&self, path: &str, name: &str, value: &str) -> Result<(), RegistryFault>;
    fn delete_value(&self, path: &str, name: &str) -> Result<(), RegistryFault>;
    fn delete_tree(&self, path: &str) -> Result<(), RegistryFault>;
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegistryFault>;
    fn is_writable(&self, path: &str) -> Result<bool, RegistryFault>;
}

#[cfg(windows)]
pub fn registry() -> Box<dyn Registry> {
    Box::new(WindowsRegistry)
}

#[cfg(not(windows))]
pub fn registry() -> Box<dyn Registry> {
    Box::new(UnsupportedRegistry)
}

#[cfg(windows)]
struct WindowsRegistry;

#[cfg(windows)]
impl WindowsRegistry {
    fn current_user() -> winreg::RegKey {
        winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
    }
}

#[cfg(windows)]
fn fault_from_io(error: &std::io::Error) -> RegistryFault {
    let kind = match error.kind() {
        std::io::ErrorKind::PermissionDenied => FaultKind::PermissionDenied,
        std::io::ErrorKind::NotFound => FaultKind::NotFound,
        _ => match error.raw_os_error() {
            Some(5) => FaultKind::PermissionDenied,
            Some(2) => FaultKind::NotFound,
            _ => FaultKind::Other,
        },
    };
    RegistryFault {
        kind,
        message: error.to_string(),
    }
}

#[cfg(windows)]
impl Registry for WindowsRegistry {
    fn key_exists(&self, path: &str) -> Result<bool, RegistryFault> {
        match Self::current_user().open_subkey(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(fault_from_io(&error)),
        }
    }

    fn read_string(&self, path: &str, name: &str) -> Result<Option<String>, RegistryFault> {
        let key = match Self::current_user().open_subkey(path) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(fault_from_io(&error)),
        };
        match key.get_value::<String, _>(name) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(fault_from_io(&error)),
        }
    }

    fn set_string(&self, path: &str, name: &str, value: &str) -> Result<(), RegistryFault> {
        let (key, _) = Self::current_user()
            .create_subkey(path)
            .map_err(|error| fault_from_io(&error))?;
        key.set_value(name, &value)
            .map_err(|error| fault_from_io(&error))
    }

    fn delete_value(&self, path: &str, name: &str) -> Result<(), RegistryFault> {
        let key = match Self::current_user()
            .open_subkey_with_flags(path, winreg::enums::KEY_READ | winreg::enums::KEY_WRITE)
        {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(fault_from_io(&error)),
        };
        match key.delete_value(name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(fault_from_io(&error)),
        }
    }

    fn delete_tree(&self, path: &str) -> Result<(), RegistryFault> {
        if !self.key_exists(path)? {
            return Ok(());
        }
        Self::current_user()
            .delete_subkey_all(path)
            .map_err(|error| fault_from_io(&error))
    }

    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegistryFault> {
        let key = match Self::current_user().open_subkey(path) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(fault_from_io(&error)),
        };
        key.enum_keys()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| fault_from_io(&error))
    }

    fn is_writable(&self, path: &str) -> Result<bool, RegistryFault> {
        match Self::current_user()
            .open_subkey_with_flags(path, winreg::enums::KEY_READ | winreg::enums::KEY_WRITE)
        {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(not(windows))]
struct UnsupportedRegistry;

#[cfg(not(windows))]
impl Registry for UnsupportedRegistry {
    fn key_exists(&self, _path: &str) -> Result<bool, RegistryFault> {
        Ok(false)
    }
    fn read_string(&self, _path: &str, _name: &str) -> Result<Option<String>, RegistryFault> {
        Ok(None)
    }
    fn set_string(&self, _path: &str, _name: &str, _value: &str) -> Result<(), RegistryFault> {
        Err(RegistryFault {
            kind: FaultKind::Other,
            message: "the Windows registry is unavailable on this platform".into(),
        })
    }
    fn delete_value(&self, _path: &str, _name: &str) -> Result<(), RegistryFault> {
        Ok(())
    }
    fn delete_tree(&self, _path: &str) -> Result<(), RegistryFault> {
        Ok(())
    }
    fn subkeys(&self, _path: &str) -> Result<Vec<String>, RegistryFault> {
        Ok(Vec::new())
    }
    fn is_writable(&self, _path: &str) -> Result<bool, RegistryFault> {
        Ok(false)
    }
}

pub fn target_keys() -> Vec<String> {
    let mut keys = Vec::with_capacity(SUPPORTED_EXTENSIONS.len() + 1);
    keys.push(VERB_KEY.to_string());
    for extension in SUPPORTED_EXTENSIONS {
        keys.push(format!(
            r"{SYSTEM_FILE_ASSOCIATIONS}\.{extension}\shell\{VERB_NAME}"
        ));
    }
    keys
}

fn command_key(verb_key: &str) -> String {
    format!("{verb_key}\\command")
}

fn read_preference(registry: &dyn Registry) -> Result<Option<bool>, RegistryFault> {
    if !registry.key_exists(PREFERENCE_KEY)? {
        return Ok(None);
    }
    match registry.read_string(PREFERENCE_KEY, PREF_ENABLED)? {
        Some(value) if value == "1" => Ok(Some(true)),
        Some(value) if value == "0" => Ok(Some(false)),
        _ => Ok(None),
    }
}

fn write_preference(
    registry: &dyn Registry,
    enabled: bool,
    result: &str,
) -> Result<(), RegistryFault> {
    registry.set_string(PREFERENCE_KEY, PREF_SCHEMA, SCHEMA_ID)?;
    registry.set_string(
        PREFERENCE_KEY,
        PREF_ENABLED,
        if enabled { "1" } else { "0" },
    )?;
    registry.set_string(PREFERENCE_KEY, PREF_RESULT, result)?;
    registry.set_string(
        PREFERENCE_KEY,
        PREF_UPDATED,
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )?;
    Ok(())
}

fn inspect_registration(
    registry: &dyn Registry,
    key: &str,
    current_exe: Option<&Path>,
) -> RegistrationInfo {
    let mut info = RegistrationInfo {
        key: key.to_string(),
        ..Default::default()
    };
    let Ok(exists) = registry.key_exists(key) else {
        return info;
    };
    if !exists {
        return info;
    }
    let owner = registry.read_string(key, OWNER_VALUE).ok().flatten();
    info.installed = owner.as_deref() == Some(OWNER_ID);
    info.executable = registry.read_string(key, EXE_VALUE).ok().flatten();
    info.executable_exists = info
        .executable
        .as_deref()
        .map(|path| Path::new(path).is_file())
        .unwrap_or(false);
    info.current = match (info.executable.as_deref(), current_exe) {
        (Some(registered), Some(current)) => same_path(registered, current),
        (Some(_), None) => true,
        _ => false,
    };
    let expected = info
        .executable
        .as_deref()
        .map(command_value)
        .unwrap_or_default();
    info.command_ok = registry
        .read_string(&command_key(key), "")
        .ok()
        .flatten()
        .is_some_and(|command| command == expected);
    info
}

fn owned_registrations(registry: &dyn Registry) -> Result<Vec<String>, RegistryFault> {
    let mut keys = BTreeSet::new();
    for key in registry.subkeys(SHELL_KEY)? {
        let path = format!("{SHELL_KEY}\\{key}");
        if registry.read_string(&path, OWNER_VALUE)?.as_deref() == Some(OWNER_ID) {
            keys.insert(path);
        }
        if keys.len() >= MAX_OWNED_KEYS {
            return Ok(keys.into_iter().collect());
        }
    }
    for extension in registry.subkeys(SYSTEM_FILE_ASSOCIATIONS)? {
        let shell = format!("{SYSTEM_FILE_ASSOCIATIONS}\\{extension}\\shell");
        for key in registry.subkeys(&shell)? {
            let path = format!("{shell}\\{key}");
            if registry.read_string(&path, OWNER_VALUE)?.as_deref() == Some(OWNER_ID) {
                keys.insert(path);
            }
            if keys.len() >= MAX_OWNED_KEYS {
                return Ok(keys.into_iter().collect());
            }
        }
    }
    Ok(keys.into_iter().collect())
}

pub fn status(registry: &dyn Registry, current_exe: Option<&Path>) -> ContextMenuStatus {
    let mut out = ContextMenuStatus {
        supported: cfg!(windows),
        executable: current_exe.map(display_path),
        registry_key: VERB_KEY.to_string(),
        state: ContextMenuState::Disabled,
        ..Default::default()
    };
    if !out.supported {
        out.state = ContextMenuState::Unavailable;
        out.detail = "Explorer integration is only available on Windows.".into();
        return out;
    }

    out.can_write = registry.is_writable(PROBE_KEY).unwrap_or(false);
    out.requires_admin = !out.can_write;

    let preference = read_preference(registry);
    out.preference_enabled = preference.clone().ok().flatten().unwrap_or(false);
    let owned = owned_registrations(registry).unwrap_or_default();
    let desired = target_keys();

    let primary_exists = registry.key_exists(VERB_KEY).unwrap_or(false);
    let primary_owner = registry.read_string(VERB_KEY, OWNER_VALUE).ok().flatten();
    if primary_exists && primary_owner.as_deref() != Some(OWNER_ID) {
        out.foreign_entry = true;
        out.state = ContextMenuState::Foreign;
        out.detail =
            format!("{VERB_KEY} already exists but is not owned by BinScope. It was not modified.");
        out.conflicts = sibling_conflicts(registry);
        out.diagnostics = diagnostics(registry, &preference, &desired, &owned, None, current_exe);
        return out;
    }

    for key in &desired {
        out.registrations
            .push(inspect_registration(registry, key, current_exe));
    }
    let primary = out.registrations.first().cloned().unwrap_or_default();
    out.installed = primary.installed;
    out.registered_executable = primary.executable.clone().or_else(|| {
        out.registrations
            .iter()
            .find_map(|item| item.executable.clone())
    });
    out.executable_exists = out
        .registered_executable
        .as_deref()
        .map(|path| Path::new(path).is_file())
        .unwrap_or(false);
    out.stale = out
        .registrations
        .iter()
        .filter(|item| item.installed)
        .any(|item| !item.current);
    out.missing_targets = out
        .registrations
        .iter()
        .filter(|item| !item.installed)
        .map(|item| item.key.clone())
        .collect();
    out.stale_targets = out
        .registrations
        .iter()
        .filter(|item| item.installed && !item.current)
        .map(|item| item.key.clone())
        .collect();
    out.partial = preference == Ok(Some(true))
        && (out
            .registrations
            .iter()
            .any(|item| !item.installed || !item.command_ok)
            || owned.iter().any(|key| !desired.contains(key)));

    out.state = match (&preference, owned.is_empty()) {
        (Err(_), _) => ContextMenuState::Failed,
        (_, _) if out.foreign_entry => ContextMenuState::Foreign,
        (Ok(Some(true)), _) if out.partial => ContextMenuState::Partial,
        (Ok(Some(true)), _) if out.stale => ContextMenuState::Stale,
        (Ok(Some(true)), false) if out.installed => ContextMenuState::Enabled,
        (Ok(Some(true)), _) => ContextMenuState::Partial,
        (Ok(Some(false)), false) => ContextMenuState::Partial,
        (Ok(Some(false)), true) => ContextMenuState::Disabled,
        (Ok(None), false) => ContextMenuState::Partial,
        (Ok(None), true) => ContextMenuState::Disabled,
    };

    out.detail = match out.state {
        ContextMenuState::Enabled => {
            "Enabled for the current Windows user and registered for the running executable.".into()
        }
        ContextMenuState::Disabled => {
            "Disabled. BinScope will not add an Explorer entry until you enable it.".into()
        }
        ContextMenuState::Stale => format!(
            "Enabled, but the registration is stale. It points at {}. BinScope repairs it on the \
             next launch.",
            out.registered_executable
                .as_deref()
                .unwrap_or("an unknown executable")
        ),
        ContextMenuState::Partial => {
            if preference.is_err() {
                "Enabled, but the preference or registration could not be read reliably.".into()
            } else if !owned.is_empty() && preference != Ok(Some(true)) {
                "BinScope-owned Explorer entries exist without an enabled preference. Disable the \
                 integration to remove them, or enable it to repair them."
                    .into()
            } else {
                "Enabled, but the registration is incomplete. Use Repair registration.".into()
            }
        }
        ContextMenuState::Foreign => {
            "A conflicting registration exists that BinScope does not own.".into()
        }
        ContextMenuState::Failed => {
            "Could not read the Windows integration state from the registry.".into()
        }
        ContextMenuState::Unavailable => {
            "Explorer integration is only available on Windows.".into()
        }
    };

    out.conflicts = sibling_conflicts(registry);
    out.diagnostics = diagnostics(
        registry,
        &preference,
        &desired,
        &owned,
        Some(&out.registrations),
        current_exe,
    );
    if !out.can_write {
        out.detail.push_str(
            " The current user cannot write to HKEY_CURRENT_USER; administrator privileges may be required.",
        );
    }
    out
}

fn diagnostics(
    registry: &dyn Registry,
    preference: &Result<Option<bool>, RegistryFault>,
    desired: &[String],
    owned: &[String],
    registrations: Option<&[RegistrationInfo]>,
    current_exe: Option<&Path>,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(match preference {
        Ok(Some(true)) => format!(
            "Stored preference: enabled (HKEY_CURRENT_USER\\{PREFERENCE_KEY}\\{PREF_ENABLED}=1)"
        ),
        Ok(Some(false)) => format!(
            "Stored preference: disabled (HKEY_CURRENT_USER\\{PREFERENCE_KEY}\\{PREF_ENABLED}=0)"
        ),
        Ok(None) => "Stored preference: not set".into(),
        Err(error) => format!("Stored preference could not be read: {}", error.message),
    });
    if let Ok(Some(result)) = registry.read_string(PREFERENCE_KEY, PREF_RESULT) {
        lines.push(format!("Last operation: {result}"));
    }
    lines.push(format!(
        "Registry targets: {} expected, {} BinScope-owned key(s) present",
        desired.len(),
        owned.len()
    ));
    if let Some(registrations) = registrations {
        let valid = registrations
            .iter()
            .filter(|item| item.installed && item.current && item.command_ok)
            .count();
        lines.push(format!(
            "Registration check: {valid}/{} target(s) installed and current",
            registrations.len()
        ));
        for item in registrations.iter().filter(|item| !item.installed) {
            lines.push(format!("Missing target: {}", item.key));
        }
        for item in registrations
            .iter()
            .filter(|item| item.installed && (!item.current || !item.command_ok))
        {
            let reason = if !item.current {
                "path differs from the running executable"
            } else {
                "shell command is missing or malformed"
            };
            lines.push(format!("Stale target: {} ({reason})", item.key));
        }
    }
    if let Some(exe) = current_exe {
        lines.push(format!("Current executable: {}", display_path(exe)));
    }
    let legacy: Vec<&String> = owned
        .iter()
        .filter(|key| !desired.iter().any(|desired| desired == *key))
        .collect();
    for key in legacy {
        lines.push(format!("Legacy BinScope entry will be removed: {key}"));
    }
    lines
}

fn sibling_conflicts(registry: &dyn Registry) -> Vec<String> {
    let mut out = Vec::new();
    let mut inspect = |root: &str| {
        let Ok(keys) = registry.subkeys(root) else {
            return;
        };
        for key in keys {
            let path = format!("{root}\\{key}");
            if path.eq_ignore_ascii_case(VERB_KEY)
                || path.to_ascii_lowercase().contains("\\binscope.analyze")
            {
                continue;
            }
            let label = registry
                .read_string(&path, "MUIVerb")
                .ok()
                .flatten()
                .or_else(|| registry.read_string(&path, "").ok().flatten());
            if label.as_deref() == Some(DISPLAY_NAME) {
                out.push(format!(
                    "{path} also uses the label \"{DISPLAY_NAME}\". It belongs to another program \
                     and was left untouched."
                ));
            }
        }
    };
    inspect(SHELL_KEY);
    if let Ok(extensions) = registry.subkeys(SYSTEM_FILE_ASSOCIATIONS) {
        for extension in extensions {
            inspect(&format!("{SYSTEM_FILE_ASSOCIATIONS}\\{extension}\\shell"));
        }
    }
    out
}

pub fn install(
    registry: &dyn Registry,
    exe: &Path,
    profile: BuildProfile,
) -> Result<ContextMenuStatus, ContextMenuFailure> {
    install_checking(registry, exe, profile, |path| path.is_file())
}

fn install_checking(
    registry: &dyn Registry,
    exe: &Path,
    profile: BuildProfile,
    exists: impl Fn(&Path) -> bool,
) -> Result<ContextMenuStatus, ContextMenuFailure> {
    if !cfg!(windows) {
        return Err(ContextMenuFailure::new(
            FailureKind::Unsupported,
            "Explorer integration is only available on Windows.",
        ));
    }
    validate_layout(exe, profile, &std::env::temp_dir())?;
    if !exists(exe) {
        return Err(executable_unavailable(exe));
    }
    let exe_text = display_path(exe);
    let desired = target_keys();
    let owned = owned_registrations(registry)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "inspect"))?;

    for key in &desired {
        if registry
            .key_exists(key)
            .map_err(|error| ContextMenuFailure::from_fault(&error, "inspect"))?
        {
            let owner = registry
                .read_string(key, OWNER_VALUE)
                .map_err(|error| ContextMenuFailure::from_fault(&error, "inspect"))?;
            if owner.as_deref() != Some(OWNER_ID) {
                return Err(ContextMenuFailure::conflict(format!(
                    "HKEY_CURRENT_USER\\{key} already exists but was not created by BinScope. \
                     It was left untouched. Remove or rename that entry manually if it is stale."
                )));
            }
        }
    }

    let mut snapshot_keys: BTreeSet<String> = desired.iter().cloned().collect();
    snapshot_keys.extend(owned.iter().cloned());
    let snapshot = snapshot_targets(registry, &snapshot_keys).map_err(|error| {
        ContextMenuFailure::from_fault(&error, "read the current registration from")
    })?;

    let written = write_all(registry, &desired, &exe_text)
        .and_then(|()| verify_all(registry, &desired, &exe_text));
    if let Err(error) = written {
        return Err(rollback_failure(registry, &snapshot, error, "install"));
    }

    let mut cleanup_error = None;
    for key in owned.iter().filter(|key| !desired.contains(key)) {
        if let Err(error) = registry.delete_tree(key) {
            cleanup_error = Some(error);
            break;
        }
    }
    if let Some(error) = cleanup_error {
        return Err(ContextMenuFailure {
            kind: FailureKind::Partial,
            message: format!(
                "The current registration is installed, but an obsolete BinScope entry could not \
                 be removed: {}. Retry Repair registration. The existing registration was kept.",
                error.message
            ),
            remaining: owned
                .into_iter()
                .filter(|key| !desired.contains(key))
                .collect(),
        });
    }

    if let Err(error) = write_preference(registry, true, "enabled") {
        return Err(rollback_failure(
            registry,
            &snapshot,
            ContextMenuFailure::from_fault(&error, "save the integration preference under"),
            "install",
        ));
    }

    Ok(status(registry, Some(exe)))
}

fn rollback_failure(
    registry: &dyn Registry,
    snapshot: &[(String, Snapshot)],
    error: ContextMenuFailure,
    action: &str,
) -> ContextMenuFailure {
    match restore_targets(registry, snapshot) {
        Ok(()) => error,
        Err(rollback_error) => ContextMenuFailure {
            kind: FailureKind::Partial,
            message: format!(
                "{} The previous registration could not be fully restored after the failed {action}: \
                 {rollback_error}",
                error.message
            ),
            remaining: snapshot
                .iter()
                .map(|(key, _)| key.clone())
                .collect(),
        },
    }
}

fn write_all(
    registry: &dyn Registry,
    keys: &[String],
    exe: &str,
) -> Result<(), ContextMenuFailure> {
    for key in keys {
        write_registration(registry, key, exe)?;
    }
    Ok(())
}

fn write_registration(
    registry: &dyn Registry,
    key: &str,
    exe: &str,
) -> Result<(), ContextMenuFailure> {
    registry
        .set_string(key, OWNER_VALUE, OWNER_ID)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "write"))?;
    registry
        .set_string(key, SCHEMA_VALUE, SCHEMA_ID)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "write"))?;
    registry
        .set_string(key, "MUIVerb", DISPLAY_NAME)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "write"))?;
    registry
        .set_string(key, "Icon", exe)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "write"))?;
    registry
        .set_string(key, "MultiSelectModel", "Single")
        .map_err(|error| ContextMenuFailure::from_fault(&error, "write"))?;
    registry
        .set_string(key, EXE_VALUE, exe)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "write"))?;
    registry
        .set_string(&command_key(key), "", &command_value(exe))
        .map_err(|error| ContextMenuFailure::from_fault(&error, "write"))
}

fn verify_all(
    registry: &dyn Registry,
    keys: &[String],
    exe: &str,
) -> Result<(), ContextMenuFailure> {
    for key in keys {
        verify_registration(registry, key, exe)?;
    }
    Ok(())
}

fn verify_registration(
    registry: &dyn Registry,
    key: &str,
    exe: &str,
) -> Result<(), ContextMenuFailure> {
    let owner = registry
        .read_string(key, OWNER_VALUE)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "verify"))?;
    if owner.as_deref() != Some(OWNER_ID) {
        return Err(ContextMenuFailure::new(
            FailureKind::Partial,
            format!("HKEY_CURRENT_USER\\{key} was written but the ownership marker is missing."),
        ));
    }
    let registered = registry
        .read_string(key, EXE_VALUE)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "verify"))?;
    if registered.as_deref() != Some(exe) {
        return Err(ContextMenuFailure::new(
            FailureKind::Partial,
            format!("HKEY_CURRENT_USER\\{key} was written but the executable path does not match."),
        ));
    }
    let command = registry
        .read_string(&command_key(key), "")
        .map_err(|error| ContextMenuFailure::from_fault(&error, "verify"))?;
    let expected = command_value(exe);
    match command {
        Some(command) if command == expected => Ok(()),
        Some(command) if command.contains(FILE_PLACEHOLDER) => Err(ContextMenuFailure::new(
            FailureKind::Partial,
            format!("HKEY_CURRENT_USER\\{key} contains an unexpected shell command: {command}"),
        )),
        _ => Err(ContextMenuFailure::new(
            FailureKind::Partial,
            format!(
                "HKEY_CURRENT_USER\\{key} was written but the shell command is missing the \
                 \"%1\" file argument."
            ),
        )),
    }
}

pub fn remove(registry: &dyn Registry) -> Result<ContextMenuStatus, ContextMenuFailure> {
    if !cfg!(windows) {
        return Err(ContextMenuFailure::new(
            FailureKind::Unsupported,
            "Explorer integration is only available on Windows.",
        ));
    }
    let primary_exists = registry
        .key_exists(VERB_KEY)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "inspect"))?;
    if primary_exists {
        let owner = registry
            .read_string(VERB_KEY, OWNER_VALUE)
            .map_err(|error| ContextMenuFailure::from_fault(&error, "inspect"))?;
        if owner.as_deref() != Some(OWNER_ID) {
            return Err(ContextMenuFailure::conflict(format!(
                "HKEY_CURRENT_USER\\{VERB_KEY} was not created by BinScope, so it was not removed. \
                 Delete it manually if it is stale."
            )));
        }
    }

    let previous = read_preference(registry)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "read the preference from"))?;
    let mut owned = owned_registrations(registry)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "inspect"))?;
    let desired = target_keys();
    for key in &desired {
        if registry.key_exists(key).unwrap_or(false) {
            let owner = registry.read_string(key, OWNER_VALUE).ok().flatten();
            if owner.as_deref() == Some(OWNER_ID) && !owned.contains(key) {
                owned.push(key.clone());
            }
        }
    }

    if let Err(error) = write_preference(registry, false, "disabling") {
        return Err(ContextMenuFailure::from_fault(
            &error,
            "write the preference to",
        ));
    }

    let snapshot = snapshot_targets(registry, &owned.iter().cloned().collect())
        .map_err(|error| ContextMenuFailure::from_fault(&error, "read the registration from"))?;

    let mut first_error = None;
    for key in &owned {
        if let Err(error) = registry.delete_tree(key) {
            first_error = first_error.or(Some(error));
            break;
        }
    }

    let remaining: Vec<String> = owned
        .iter()
        .filter(|key| registry.key_exists(key).unwrap_or(true))
        .cloned()
        .collect();
    if !remaining.is_empty() {
        let _ = restore_targets(registry, &snapshot);
        let _ = write_preference(registry, previous.unwrap_or(true), "disable-failed");
        let detail = first_error
            .map(|error| format!(" ({})", error.message))
            .unwrap_or_default();
        return Err(ContextMenuFailure {
            kind: FailureKind::Partial,
            message: format!(
                "Removal of the BinScope Explorer entry did not complete{detail}. The previous \
                 registration was restored; retry to finish removing it."
            ),
            remaining,
        });
    }

    if let Err(error) = write_preference(registry, false, "disabled") {
        return Err(ContextMenuFailure::from_fault(
            &error,
            "write the preference to",
        ));
    }

    Ok(status(registry, None))
}

pub fn repair(
    registry: &dyn Registry,
    exe: &Path,
    profile: BuildProfile,
) -> Result<ContextMenuStatus, ContextMenuFailure> {
    let preference = read_preference(registry)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "read the preference from"))?;
    let owned = owned_registrations(registry)
        .map_err(|error| ContextMenuFailure::from_fault(&error, "inspect"))?;
    if preference == Some(false) {
        return Err(ContextMenuFailure::new(
            FailureKind::NotEnabled,
            "The Explorer integration is disabled. Enable it first to register the current \
             executable.",
        ));
    }
    if preference.is_none() && owned.is_empty() {
        return Err(ContextMenuFailure::new(
            FailureKind::NotEnabled,
            "The Explorer integration has never been enabled. Enable it first.",
        ));
    }
    install(registry, exe, profile)
}

pub fn startup(registry: &dyn Registry, exe: &Path, profile: BuildProfile) -> Option<String> {
    startup_checking(registry, exe, profile, |path| path.is_file())
}

fn startup_checking(
    registry: &dyn Registry,
    exe: &Path,
    profile: BuildProfile,
    exists: impl Fn(&Path) -> bool,
) -> Option<String> {
    let preference = match read_preference(registry) {
        Ok(value) => value,
        Err(error) => {
            return Some(format!(
                "could not read the Explorer integration preference: {}",
                error.message
            ))
        }
    };
    if preference == Some(false) {
        return None;
    }
    let owned = owned_registrations(registry).unwrap_or_default();
    if preference.is_none() && owned.is_empty() {
        return None;
    }
    let current = status(registry, Some(exe));
    if current.state == ContextMenuState::Enabled {
        return None;
    }
    match install_checking(registry, exe, profile, exists) {
        Ok(status) => Some(format!(
            "repaired the Explorer integration for {} ({} targets, state {:?})",
            display_path(exe),
            status
                .registrations
                .iter()
                .filter(|item| item.installed && item.current && item.command_ok)
                .count(),
            status.state
        )),
        Err(error) => {
            let _ = write_preference(registry, true, &format!("repair-failed: {}", error.message));
            Some(format!(
                "the Explorer integration is enabled but could not be repaired: {}",
                error.message
            ))
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Snapshot {
    existed: bool,
    had_command: bool,
    values: BTreeMap<String, String>,
    command: Option<String>,
}

fn snapshot_targets(
    registry: &dyn Registry,
    keys: &BTreeSet<String>,
) -> Result<Vec<(String, Snapshot)>, RegistryFault> {
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let existed = registry.key_exists(key)?;
        if !existed {
            out.push((key.clone(), Snapshot::default()));
            continue;
        }
        let mut values = BTreeMap::new();
        for name in MANAGED_VALUES {
            if let Some(value) = registry.read_string(key, name)? {
                values.insert(name.to_string(), value);
            }
        }
        let command_path = command_key(key);
        let had_command = registry.key_exists(&command_path)?;
        let command = registry.read_string(&command_path, "")?;
        out.push((
            key.clone(),
            Snapshot {
                existed,
                had_command,
                values,
                command,
            },
        ));
    }
    Ok(out)
}

fn restore_targets(registry: &dyn Registry, snapshot: &[(String, Snapshot)]) -> Result<(), String> {
    for (key, snapshot) in snapshot {
        if !snapshot.existed {
            registry.delete_tree(key).map_err(|error| error.message)?;
            continue;
        }
        for (name, value) in &snapshot.values {
            registry
                .set_string(key, name, value)
                .map_err(|error| error.message)?;
        }
        for name in MANAGED_VALUES {
            if !snapshot.values.contains_key(name) {
                let _ = registry.delete_value(key, name);
            }
        }
        let command_path = command_key(key);
        match &snapshot.command {
            Some(command) => registry
                .set_string(&command_path, "", command)
                .map_err(|error| error.message)?,
            None if !snapshot.had_command => {
                let _ = registry.delete_tree(&command_path);
            }
            None => {}
        }
    }
    Ok(())
}

pub fn command_value(exe: &str) -> String {
    format!("{} {FILE_PLACEHOLDER}", quote_windows_arg(exe))
}

pub fn quote_windows_arg(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                out.push('\\');
                out.push('"');
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                out.push(character);
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

pub fn extract_file_argument<I, S>(args: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = S>,
    S: Into<PathBuf>,
{
    for argument in args.into_iter().skip(1) {
        let path: PathBuf = argument.into();
        let text = path.to_string_lossy();
        if text.starts_with('-') || text.trim().is_empty() {
            continue;
        }
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn executable_unavailable(exe: &Path) -> ContextMenuFailure {
    ContextMenuFailure::new(
        FailureKind::ExecutableUnavailable,
        format!(
            "BinScope cannot register a context menu for {}: the file does not exist. \
             Run BinScope from its extracted folder.",
            display_path(exe)
        ),
    )
}

pub fn validate_layout(
    exe: &Path,
    profile: BuildProfile,
    temp_dir: &Path,
) -> Result<(), ContextMenuFailure> {
    if profile == BuildProfile::Development {
        return Err(ContextMenuFailure::new(
            FailureKind::DevelopmentBuild,
            "The Explorer entry can only be registered from a packaged release build. \
             Build with `tauri build` and run the released BinScope.exe.",
        ));
    }
    if !exe.is_absolute() {
        return Err(ContextMenuFailure::new(
            FailureKind::ExecutableUnavailable,
            "The BinScope executable path must be absolute to be registered.",
        ));
    }
    let text = display_path(exe);
    let normalized = text.replace('/', "\\").to_ascii_lowercase();
    if normalized.contains("\\target\\debug\\") || normalized.contains("\\target\\release\\") {
        return Err(ContextMenuFailure::new(
            FailureKind::DevelopmentBuild,
            format!(
                "{text} is a Cargo build output. Run the packaged executable from the release or \
                 portable folder."
            ),
        ));
    }
    if inside_dir(&normalized, temp_dir) {
        return Err(ContextMenuFailure::new(
            FailureKind::ExecutableUnavailable,
            format!(
                "{text} is inside the temporary directory. Extract BinScope to a permanent folder \
                 before registering the Explorer entry."
            ),
        ));
    }
    Ok(())
}

fn inside_dir(normalized_path: &str, dir: &Path) -> bool {
    let mut dir = display_path(dir).replace('/', "\\").to_ascii_lowercase();
    if dir.is_empty() {
        return false;
    }
    if !dir.ends_with('\\') {
        dir.push('\\');
    }
    normalized_path.starts_with(&dir)
}

fn same_path(a: &str, b: &Path) -> bool {
    let left = Path::new(a);
    if left == b {
        return true;
    }
    match (left.canonicalize(), b.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => display_path(left).eq_ignore_ascii_case(&display_path(b)),
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub struct MemoryRegistry {
    keys: std::cell::RefCell<BTreeMap<String, BTreeMap<String, String>>>,
    writable: bool,
    fail_writes: Vec<String>,
    fail_once_writes: std::cell::RefCell<Vec<String>>,
    fail_deletes: Vec<String>,
}

#[cfg(test)]
impl MemoryRegistry {
    pub fn new() -> Self {
        Self {
            keys: std::cell::RefCell::new(BTreeMap::new()),
            writable: true,
            fail_writes: Vec::new(),
            fail_once_writes: std::cell::RefCell::new(Vec::new()),
            fail_deletes: Vec::new(),
        }
    }

    pub fn read_only() -> Self {
        Self {
            writable: false,
            ..Self::new()
        }
    }

    pub fn fail_writes_on(mut self, path: &str) -> Self {
        self.fail_writes.push(path.to_string());
        self
    }

    pub fn fail_deletes_on(mut self, path: &str) -> Self {
        self.fail_deletes.push(path.to_string());
        self
    }

    pub fn fail_next_write_on(self, path: &str) -> Self {
        self.fail_once_writes.borrow_mut().push(path.to_string());
        self
    }

    pub fn preload(mut self, path: &str, name: &str, value: &str) -> Self {
        self.ensure_parents(path);
        self.keys
            .get_mut()
            .entry(path.to_string())
            .or_default()
            .insert(name.to_string(), value.to_string());
        self
    }

    pub fn remove_key(&self, path: &str) {
        let prefix = format!("{path}\\");
        self.keys
            .borrow_mut()
            .retain(|key, _| key != path && !key.starts_with(&prefix));
    }

    pub fn remove_failures(mut self) -> Self {
        self.fail_writes.clear();
        self.fail_once_writes.borrow_mut().clear();
        self.fail_deletes.clear();
        self
    }

    pub fn value(&self, path: &str, name: &str) -> Option<String> {
        self.keys
            .borrow()
            .get(path)
            .and_then(|values| values.get(name))
            .cloned()
    }

    pub fn key_paths(&self) -> Vec<String> {
        self.keys.borrow().keys().cloned().collect()
    }

    fn ensure_parents(&self, path: &str) {
        let mut keys = self.keys.borrow_mut();
        let mut current = String::new();
        for part in path.split('\\') {
            if !current.is_empty() {
                current.push('\\');
            }
            current.push_str(part);
            keys.entry(current.clone()).or_default();
        }
    }
}

#[cfg(test)]
impl Registry for MemoryRegistry {
    fn key_exists(&self, path: &str) -> Result<bool, RegistryFault> {
        Ok(self.keys.borrow().contains_key(path))
    }

    fn read_string(&self, path: &str, name: &str) -> Result<Option<String>, RegistryFault> {
        Ok(self.value(path, name))
    }

    fn set_string(&self, path: &str, name: &str, value: &str) -> Result<(), RegistryFault> {
        if !self.writable {
            return Err(RegistryFault {
                kind: FaultKind::PermissionDenied,
                message: "access denied (simulated)".into(),
            });
        }
        let fail_once = {
            let mut pending = self.fail_once_writes.borrow_mut();
            match pending.iter().position(|item| item == path) {
                Some(index) => {
                    pending.remove(index);
                    true
                }
                None => false,
            }
        };
        if fail_once || self.fail_writes.iter().any(|item| item == path) {
            return Err(RegistryFault {
                kind: FaultKind::PermissionDenied,
                message: format!("access denied for {path} (simulated)"),
            });
        }
        self.ensure_parents(path);
        self.keys
            .borrow_mut()
            .entry(path.to_string())
            .or_default()
            .insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn delete_value(&self, path: &str, name: &str) -> Result<(), RegistryFault> {
        if self.fail_deletes.iter().any(|item| item == path) {
            return Err(RegistryFault {
                kind: FaultKind::PermissionDenied,
                message: format!("access denied for {path} (simulated)"),
            });
        }
        if let Some(values) = self.keys.borrow_mut().get_mut(path) {
            values.remove(name);
        }
        Ok(())
    }

    fn delete_tree(&self, path: &str) -> Result<(), RegistryFault> {
        if self.fail_deletes.iter().any(|item| item == path) {
            return Err(RegistryFault {
                kind: FaultKind::PermissionDenied,
                message: format!("access denied for {path} (simulated)"),
            });
        }
        let prefix = format!("{path}\\");
        self.keys
            .borrow_mut()
            .retain(|key, _| key != path && !key.starts_with(&prefix));
        Ok(())
    }

    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegistryFault> {
        let prefix = format!("{path}\\");
        let keys = self.keys.borrow();
        let mut out: Vec<String> = Vec::new();
        for key in keys.keys() {
            if let Some(rest) = key.strip_prefix(&prefix) {
                let name = rest.split('\\').next().unwrap_or(rest);
                if !name.is_empty() && !out.iter().any(|item| item == name) {
                    out.push(name.to_string());
                }
            }
        }
        Ok(out)
    }

    fn is_writable(&self, _path: &str) -> Result<bool, RegistryFault> {
        Ok(self.writable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const EXE: &str = r"C:\Program Files\BinScope\binscope-app.exe";
    const MOVED: &str = r"D:\Tools\BinScope Portable\BinScope.exe";

    fn enabled(registry: &MemoryRegistry) -> ContextMenuStatus {
        install_checking(registry, Path::new(EXE), BuildProfile::Release, |_| true)
            .expect("installation should succeed")
    }

    #[test]
    fn initial_state_is_disabled_and_not_installed() {
        let registry = MemoryRegistry::new();
        let status = status(&registry, Some(Path::new(EXE)));
        assert!(!status.installed);
        assert!(!status.preference_enabled);
        assert_eq!(status.state, ContextMenuState::Disabled);
        assert!(!status.foreign_entry);
        assert!(status.can_write);
        assert!(!status.requires_admin);
        assert!(status.conflicts.is_empty());
        assert_eq!(status.registry_key, VERB_KEY);
    }

    #[test]
    fn enabling_writes_the_documented_layout_and_all_targets() {
        let registry = MemoryRegistry::new();
        let status = enabled(&registry);

        assert!(status.installed);
        assert!(status.preference_enabled);
        assert_eq!(status.state, ContextMenuState::Enabled);
        assert!(!status.foreign_entry);
        assert_eq!(status.registered_executable.as_deref(), Some(EXE));
        assert!(!status.stale);
        assert_eq!(
            registry.value(VERB_KEY, "MUIVerb").as_deref(),
            Some(DISPLAY_NAME)
        );
        assert_eq!(
            registry.value(VERB_KEY, OWNER_VALUE).as_deref(),
            Some(OWNER_ID)
        );
        assert_eq!(
            registry.value(VERB_KEY, "MultiSelectModel").as_deref(),
            Some("Single")
        );
        assert_eq!(registry.value(VERB_KEY, "Icon").as_deref(), Some(EXE));
        assert_eq!(
            registry.value(COMMAND_KEY, "").as_deref(),
            Some(format!("\"{EXE}\" \"%1\"").as_str())
        );
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("1")
        );
        assert!(registry
            .key_exists(r"Software\Classes\SystemFileAssociations\.exe\shell\BinScope.Analyze")
            .unwrap());
        assert!(registry
            .key_exists(r"Software\Classes\SystemFileAssociations\.dll\shell\BinScope.Analyze")
            .unwrap());
    }

    #[test]
    fn preference_is_stored_separately_from_registration() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("1")
        );
        remove(&registry).unwrap();
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("0")
        );
        assert!(!status(&registry, Some(Path::new(EXE))).preference_enabled);
    }

    #[test]
    fn state_is_detected_by_a_fresh_read_after_a_restart() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        let status = status(&registry, Some(Path::new(EXE)));
        assert!(status.installed);
        assert_eq!(status.state, ContextMenuState::Enabled);
        assert!(status
            .diagnostics
            .iter()
            .any(|line| line.contains("Stored preference: enabled")));
    }

    #[test]
    fn disabling_removes_only_binscope_entries_and_records_intent() {
        let registry = MemoryRegistry::new()
            .preload(
                r"Software\Classes\*\shell\OpenWithSomething",
                "MUIVerb",
                "Open with something",
            )
            .preload(
                r"Software\Classes\*\shell\OpenWithSomething\command",
                "",
                r#""C:\Other\other.exe" "%1""#,
            );
        enabled(&registry);
        let status = remove(&registry).expect("removal should succeed");

        assert!(!status.installed);
        assert!(!status.preference_enabled);
        for key in target_keys() {
            assert!(!registry.key_exists(&key).unwrap(), "{key} still exists");
        }
        assert!(registry
            .key_exists(r"Software\Classes\*\shell\OpenWithSomething")
            .unwrap());
        assert!(registry
            .key_exists(r"Software\Classes\*\shell\OpenWithSomething\command")
            .unwrap());
        assert!(registry.key_exists(SHELL_KEY).unwrap());
        assert!(registry.key_exists(r"Software\Classes\*").unwrap());
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("0")
        );
    }

    #[test]
    fn removing_when_absent_is_a_success_and_sets_disabled() {
        let registry = MemoryRegistry::new();
        let status = remove(&registry).expect("absent entry is not an error");
        assert!(!status.installed);
        assert_eq!(status.state, ContextMenuState::Disabled);
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("0")
        );
    }

    #[test]
    fn repeated_enable_and_disable_are_idempotent() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        let first = registry.key_paths();
        enabled(&registry);
        assert_eq!(
            first,
            registry.key_paths(),
            "enable must not duplicate keys"
        );

        remove(&registry).unwrap();
        remove(&registry).unwrap();
        assert!(!registry.key_exists(VERB_KEY).unwrap());
        assert!(registry
            .key_paths()
            .iter()
            .all(|key| !key.contains("BinScope.Analyze")));
    }

    #[test]
    fn stale_registration_is_detected_and_repaired() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        let moved = Path::new(MOVED);
        let detected = status(&registry, Some(moved));
        assert!(detected.installed);
        assert!(detected.stale);
        assert_eq!(detected.state, ContextMenuState::Stale);
        assert_eq!(detected.registered_executable.as_deref(), Some(EXE));

        install_checking(&registry, moved, BuildProfile::Release, |_| true).unwrap();
        assert_eq!(registry.value(VERB_KEY, EXE_VALUE).as_deref(), Some(MOVED));
        assert!(!status(&registry, Some(moved)).stale);
        for key in target_keys() {
            assert_eq!(registry.value(&key, EXE_VALUE).as_deref(), Some(MOVED));
        }
    }

    #[test]
    fn startup_repairs_a_stale_path_and_preserves_the_preference() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        let log = startup_checking(&registry, Path::new(MOVED), BuildProfile::Release, |_| true)
            .expect("startup should repair the stale path");
        assert!(log.contains("repaired"));
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("1")
        );
        assert_eq!(registry.value(VERB_KEY, EXE_VALUE).as_deref(), Some(MOVED));
        assert_eq!(
            status(&registry, Some(Path::new(MOVED))).state,
            ContextMenuState::Enabled
        );
        let before = registry.key_paths();
        assert!(
            startup_checking(&registry, Path::new(MOVED), BuildProfile::Release, |_| true)
                .is_none()
        );
        assert_eq!(
            before,
            registry.key_paths(),
            "no writes when everything is current"
        );
    }

    #[test]
    fn startup_repairs_a_manually_removed_registration() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        for key in target_keys() {
            registry.remove_key(&key);
        }
        let partial = status(&registry, Some(Path::new(EXE)));
        assert!(partial.preference_enabled);
        assert_eq!(partial.state, ContextMenuState::Partial);
        assert!(!partial.installed);

        let log = startup_checking(&registry, Path::new(EXE), BuildProfile::Release, |_| true)
            .expect("repair");
        assert!(log.contains("repaired"));
        assert_eq!(
            status(&registry, Some(Path::new(EXE))).state,
            ContextMenuState::Enabled
        );
    }

    #[test]
    fn startup_never_reinstalls_after_the_user_disabled_it() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        remove(&registry).unwrap();
        assert!(
            startup_checking(&registry, Path::new(EXE), BuildProfile::Release, |_| true).is_none()
        );
        for key in target_keys() {
            assert!(!registry.key_exists(&key).unwrap());
        }
    }

    #[test]
    fn legacy_binscope_owned_entries_are_removed_on_repair() {
        let registry = MemoryRegistry::new();
        let legacy = r"Software\Classes\*\shell\BinScope.Legacy";
        let registry = registry
            .preload(legacy, OWNER_VALUE, OWNER_ID)
            .preload(legacy, "MUIVerb", DISPLAY_NAME)
            .preload(
                &format!("{legacy}\\command"),
                "",
                r#""C:\Old\BinScope.exe" "%1""#,
            );
        enabled(&registry);
        assert!(!registry.key_exists(legacy).unwrap());
    }

    #[test]
    fn a_foreign_key_is_never_overwritten_or_deleted() {
        let registry = MemoryRegistry::new()
            .preload(VERB_KEY, OWNER_VALUE, "SomeOtherProgram")
            .preload(VERB_KEY, "MUIVerb", "Analyze with SomeOtherProgram");

        let status = status(&registry, Some(Path::new(EXE)));
        assert!(!status.installed);
        assert!(status.foreign_entry);
        assert_eq!(status.state, ContextMenuState::Foreign);

        let install_error =
            install_checking(&registry, Path::new(EXE), BuildProfile::Release, |_| true)
                .unwrap_err();
        assert_eq!(install_error.kind, FailureKind::Conflict);
        assert_eq!(
            registry.value(VERB_KEY, "MUIVerb").as_deref(),
            Some("Analyze with SomeOtherProgram")
        );

        let remove_error = remove(&registry).unwrap_err();
        assert_eq!(remove_error.kind, FailureKind::Conflict);
        assert_eq!(
            registry.value(VERB_KEY, OWNER_VALUE).as_deref(),
            Some("SomeOtherProgram")
        );
    }

    #[test]
    fn a_sibling_using_the_same_label_is_reported_but_preserved() {
        let registry = MemoryRegistry::new().preload(
            r"Software\Classes\*\shell\SomeOtherAnalyzer",
            "MUIVerb",
            DISPLAY_NAME,
        );
        let status = enabled(&registry);
        assert_eq!(status.conflicts.len(), 1);
        assert!(status.conflicts[0].contains("SomeOtherAnalyzer"));

        remove(&registry).unwrap();
        assert!(registry
            .key_exists(r"Software\Classes\*\shell\SomeOtherAnalyzer")
            .unwrap());
    }

    #[test]
    fn a_partial_registration_is_detected_and_repaired() {
        let registry = MemoryRegistry::new()
            .preload(VERB_KEY, OWNER_VALUE, OWNER_ID)
            .preload(VERB_KEY, "MUIVerb", DISPLAY_NAME);
        let registry = registry.preload(PREFERENCE_KEY, PREF_ENABLED, "1");
        let partial = status(&registry, Some(Path::new(EXE)));
        assert_eq!(partial.state, ContextMenuState::Partial);
        assert!(partial.partial);

        let status = enabled(&registry);
        assert!(status.installed);
        assert_eq!(status.state, ContextMenuState::Enabled);
        assert_eq!(
            registry.value(COMMAND_KEY, "").as_deref(),
            Some(format!("\"{EXE}\" \"%1\"").as_str())
        );
    }

    #[test]
    fn a_failed_install_rolls_back_a_new_key_and_the_preference() {
        let registry = MemoryRegistry::new().fail_writes_on(COMMAND_KEY);
        let error = install_checking(&registry, Path::new(EXE), BuildProfile::Release, |_| true)
            .unwrap_err();
        assert_eq!(error.kind, FailureKind::PermissionDenied);
        assert!(
            !registry.key_exists(VERB_KEY).unwrap(),
            "a failed first install must not leave a half-written verb"
        );
        assert_eq!(registry.value(PREFERENCE_KEY, PREF_ENABLED), None);
    }

    #[test]
    fn a_failed_repair_restores_the_previous_registration() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        let original = registry.value(COMMAND_KEY, "").unwrap();

        let moved = Path::new(MOVED);
        let failing = MemoryRegistry::new()
            .preload(VERB_KEY, OWNER_VALUE, OWNER_ID)
            .preload(VERB_KEY, EXE_VALUE, EXE)
            .preload(COMMAND_KEY, "", &original)
            .preload(PREFERENCE_KEY, PREF_ENABLED, "1")
            .fail_next_write_on(COMMAND_KEY);
        let error = install_checking(&failing, moved, BuildProfile::Release, |_| true).unwrap_err();
        assert_eq!(error.kind, FailureKind::PermissionDenied);
        assert_eq!(failing.value(VERB_KEY, EXE_VALUE).as_deref(), Some(EXE));
        assert_eq!(
            failing.value(COMMAND_KEY, "").as_deref(),
            Some(original.as_str())
        );
    }

    #[test]
    fn a_partially_failed_removal_reports_the_key_and_can_be_retried() {
        let mut registry = MemoryRegistry::new().fail_deletes_on(VERB_KEY);
        enabled(&registry);
        let error = remove(&registry).unwrap_err();
        assert_eq!(error.kind, FailureKind::Partial);
        assert!(error.remaining.contains(&VERB_KEY.to_string()));
        assert!(registry.value(COMMAND_KEY, "").is_some());
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("1")
        );

        registry = registry.remove_failures();
        remove(&registry).unwrap();
        for key in target_keys() {
            assert!(!registry.key_exists(&key).unwrap());
        }
        assert_eq!(
            registry.value(PREFERENCE_KEY, PREF_ENABLED).as_deref(),
            Some("0")
        );
    }

    #[test]
    fn permission_errors_are_actionable_and_marked_as_admin_required() {
        let registry = MemoryRegistry::read_only();
        let status = status(&registry, Some(Path::new(EXE)));
        assert!(!status.can_write);
        assert!(status.requires_admin);
        assert!(status.detail.contains("administrator"));

        let error = install_checking(&registry, Path::new(EXE), BuildProfile::Release, |_| true)
            .unwrap_err();
        assert_eq!(error.kind, FailureKind::PermissionDenied);
        assert!(error.message.contains("HKEY_CURRENT_USER"));
        assert!(error.message.contains("current user"));
    }

    #[test]
    fn paths_with_spaces_and_unicode_are_quoted() {
        let unicode = "C:\\Users\\Jos\u{e9}\\Programas BinScope\\BinScope.exe";
        assert_eq!(command_value(unicode), format!("\"{unicode}\" \"%1\""));
        let registry = MemoryRegistry::new();
        install_checking(&registry, Path::new(unicode), BuildProfile::Release, |_| {
            true
        })
        .unwrap();
        assert_eq!(
            registry.value(COMMAND_KEY, "").unwrap(),
            command_value(unicode)
        );
        assert_eq!(
            registry
                .value(COMMAND_KEY, "")
                .unwrap()
                .matches("\"%1\"")
                .count(),
            1
        );
    }

    #[test]
    fn command_quoting_follows_windows_rules() {
        assert_eq!(quote_windows_arg(r"C:\a\b.exe"), r#""C:\a\b.exe""#);
        assert_eq!(quote_windows_arg(r"C:\a b\c.exe"), r#""C:\a b\c.exe""#);
        assert_eq!(quote_windows_arg(r"C:\a b\"), r#""C:\a b\\""#);
        assert_eq!(quote_windows_arg(r#"C:\a"b\c.exe"#), r#""C:\a\"b\c.exe""#);
        assert_eq!(quote_windows_arg(""), r#""""#);
        assert_eq!(
            command_value(r"C:\x y\BinScope.exe"),
            r#""C:\x y\BinScope.exe" "%1""#
        );
    }

    #[test]
    fn file_arguments_are_taken_from_argv_without_a_shell() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sample with spaces \u{f1}.exe");
        std::fs::write(&file, b"MZ").unwrap();

        let args = vec![
            r"C:\Apps\BinScope\BinScope.exe".to_string(),
            "--unrelated-flag".to_string(),
            file.to_string_lossy().into_owned(),
        ];
        assert_eq!(extract_file_argument(args), Some(file.clone()));

        assert_eq!(
            extract_file_argument(vec![r"C:\Apps\BinScope.exe".to_string()]),
            None
        );
        assert_eq!(
            extract_file_argument(vec![
                r"C:\Apps\BinScope.exe".to_string(),
                r"C:\missing\file.exe".to_string()
            ]),
            None
        );
        assert_eq!(
            extract_file_argument(vec![
                r"C:\Apps\BinScope.exe".to_string(),
                format!("-{}", file.display())
            ]),
            None
        );
    }

    #[test]
    fn development_and_build_paths_are_rejected() {
        let temp = Path::new(r"C:\Temp");
        let dev = Path::new(r"C:\src\binscope\target\debug\BinScope.exe");
        assert_eq!(
            validate_layout(dev, BuildProfile::Release, temp)
                .unwrap_err()
                .kind,
            FailureKind::DevelopmentBuild
        );
        assert_eq!(
            validate_layout(dev, BuildProfile::Development, temp)
                .unwrap_err()
                .kind,
            FailureKind::DevelopmentBuild
        );
        let portable = Path::new(r"C:\Tools\BinScope\BinScope.exe");
        assert_eq!(
            validate_layout(portable, BuildProfile::Development, temp)
                .unwrap_err()
                .kind,
            FailureKind::DevelopmentBuild
        );
        assert!(validate_layout(portable, BuildProfile::Release, temp).is_ok());
        assert_eq!(
            validate_layout(
                Path::new(r"C:\Temp\binscope\BinScope.exe"),
                BuildProfile::Release,
                temp
            )
            .unwrap_err()
            .kind,
            FailureKind::ExecutableUnavailable
        );
        assert_eq!(
            validate_layout(Path::new(r"BinScope.exe"), BuildProfile::Release, temp)
                .unwrap_err()
                .kind,
            FailureKind::ExecutableUnavailable
        );
    }

    #[test]
    fn repair_requires_an_enabled_preference() {
        let registry = MemoryRegistry::new();
        let error = repair(&registry, Path::new(EXE), BuildProfile::Release).unwrap_err();
        assert_eq!(error.kind, FailureKind::NotEnabled);

        enabled(&registry);
        remove(&registry).unwrap();
        let error = repair(&registry, Path::new(EXE), BuildProfile::Release).unwrap_err();
        assert_eq!(error.kind, FailureKind::NotEnabled);
    }

    #[test]
    fn status_without_a_current_executable_does_not_invent_staleness() {
        let registry = MemoryRegistry::new();
        enabled(&registry);
        let status = status(&registry, None);
        assert!(!status.stale);
        assert!(status.installed);
    }
}
