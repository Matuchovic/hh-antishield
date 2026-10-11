//! Cíle rychlé a úplné kontroly: běžící procesy, položky spouštěné po
//! přihlášení a typické složky uživatele. Výčet jen čte; zásahy (ukončení
//! procesu, vypnutí položky) jsou samostatné funkce volané po potvrzení.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::EngineError;
use crate::types::{FindingOrigin, ScanRequest};

const MAX_STARTUP_ITEMS: usize = 1_000;
const MAX_PLIST_BYTES: u64 = 1024 * 1024;

/// Běžící proces se známou cestou ke spustitelnému souboru.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: PathBuf,
}

/// Položka spouštěná po přihlášení nebo startu systému.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupItem {
    /// Soubor (plist, zástupce) nebo klíč registru, který položku definuje.
    pub location: String,
    pub label: String,
    /// Spouštěný program, pokud ho jde zjistit.
    pub program: Option<PathBuf>,
}

/// Domovská složka uživatele.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let var = "USERPROFILE";
    #[cfg(not(windows))]
    let var = "HOME";
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Složky, které hlídání a rychlá kontrola sledují ve výchozím stavu.
pub fn default_watch_folders() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    ["Downloads", "Desktop", "Documents"]
        .iter()
        .map(|name| home.join(name))
        .collect()
}

/// Běžící procesy s cestou k programu (bez jader a systémových úloh bez cesty).
pub fn running_processes() -> Vec<ProcessInfo> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    let mut list: Vec<ProcessInfo> = system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let exe = process.exe()?.to_path_buf();
            exe.is_absolute().then(|| ProcessInfo {
                pid: pid.as_u32(),
                name: process.name().to_string_lossy().chars().take(200).collect(),
                exe,
            })
        })
        .collect();
    list.sort_by_key(|p| p.pid);
    list
}

/// Ukončí proces, jen pokud pořád běží ze stejného programu (ochrana proti
/// opětovnému použití PID). Vrací `false`, když proces už neběží.
pub fn terminate_process(pid: u32, expected_exe: &Path) -> Result<bool, EngineError> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let Some(process) = system.process(pid) else {
        return Ok(false);
    };
    if process.exe() != Some(expected_exe) {
        return Err(EngineError::InvalidRequest(
            "the process no longer runs the detected program".into(),
        ));
    }
    if process.kill() {
        Ok(true)
    } else {
        Err(EngineError::InvalidRequest(
            "the process could not be terminated (missing permission?)".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn startup_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
    ];
    if let Some(home) = home_dir() {
        dirs.insert(0, home.join("Library/LaunchAgents"));
    }
    dirs
}

#[cfg(windows)]
fn startup_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(appdata) = std::env::var_os("APPDATA") {
        dirs.push(PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if let Some(programdata) = std::env::var_os("PROGRAMDATA") {
        dirs.push(
            PathBuf::from(programdata).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        );
    }
    dirs
}

#[cfg(not(any(target_os = "macos", windows)))]
fn startup_dirs() -> Vec<PathBuf> {
    home_dir()
        .map(|home| vec![home.join(".config/autostart")])
        .unwrap_or_default()
}

/// Leží soubor přímo ve složce položek po spuštění? (jen takové smí vypnout)
pub fn is_startup_location(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    startup_dirs().iter().any(|dir| dir == parent)
}

fn program_from_plist(path: &Path) -> Option<(String, Option<PathBuf>)> {
    if fs::symlink_metadata(path).ok()?.len() > MAX_PLIST_BYTES {
        return None;
    }
    let value = plist::Value::from_file(path).ok()?;
    let dict = value.as_dictionary()?;
    let label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect();
    let program = dict
        .get("Program")
        .and_then(|v| v.as_string())
        .or_else(|| {
            dict.get("ProgramArguments")
                .and_then(|v| v.as_array())
                .and_then(|args| args.first())
                .and_then(|v| v.as_string())
        })
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    Some((label, program))
}

fn program_from_desktop_entry(path: &Path) -> Option<(String, Option<PathBuf>)> {
    let text = fs::read_to_string(path).ok()?;
    let mut label = String::new();
    let mut program = None;
    for line in text.lines().take(200) {
        if let Some(name) = line.strip_prefix("Name=") {
            label = name.chars().take(200).collect();
        } else if let Some(exec) = line.strip_prefix("Exec=") {
            program = exec
                .split_whitespace()
                .next()
                .map(PathBuf::from)
                .filter(|p| p.is_absolute());
        }
    }
    Some((label, program))
}

/// Vytáhne cestu k programu z příkazové řádky (registr Run).
#[cfg_attr(not(windows), allow(dead_code))]
fn program_from_command(command: &str) -> Option<PathBuf> {
    let command = command.trim();
    let path = if let Some(rest) = command.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        let lower = command.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(end) => command[..end + 4].to_string(),
            None => command.split_whitespace().next()?.to_string(),
        }
    };
    let path = PathBuf::from(path);
    path.is_absolute().then_some(path)
}

#[cfg(windows)]
fn registry_items(items: &mut Vec<StartupItem>) {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    for (root, prefix) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
        let Ok(key) = RegKey::predef(root).open_subkey_with_flags(RUN, KEY_READ) else {
            continue;
        };
        for (name, value) in key.enum_values().flatten().take(MAX_STARTUP_ITEMS) {
            let command = value.to_string();
            items.push(StartupItem {
                location: format!(r"{prefix}\{RUN}\{name}"),
                label: name.chars().take(200).collect(),
                program: program_from_command(&command),
            });
        }
    }
}

/// Položky spouštěné po přihlášení (LaunchAgents/Daemons, Startup, Run, autostart).
pub fn startup_items() -> Vec<StartupItem> {
    let mut items = Vec::new();
    for dir in startup_dirs() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_STARTUP_ITEMS) {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let extension = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase());
            let parsed = match extension.as_deref() {
                Some("plist") => program_from_plist(&path),
                Some("desktop") => program_from_desktop_entry(&path),
                _ => Some((
                    path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    // Zástupce (.lnk) se nerozbaluje; spustitelný soubor ve složce je program.
                    None,
                )),
            };
            if let Some((label, program)) = parsed {
                items.push(StartupItem {
                    location: path.display().to_string(),
                    label,
                    program,
                });
            }
        }
    }
    #[cfg(windows)]
    registry_items(&mut items);
    items.truncate(MAX_STARTUP_ITEMS);
    items
}

/// Vypne položku po spuštění v registru (jen HKCU). Soubory řeší karanténa.
#[cfg(windows)]
pub fn remove_registry_startup(location: &str) -> Result<(), EngineError> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let name = location
        .strip_prefix(&format!(r"HKCU\{RUN}\"))
        .ok_or_else(|| {
            EngineError::InvalidRequest("only current-user startup entries can be removed".into())
        })?;
    let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN, KEY_SET_VALUE)?;
    key.delete_value(name)?;
    Ok(())
}

fn canonical(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok()
}

/// Přidá do požadavku programy procesů a položek po spuštění i s jejich původem.
fn add_system_targets(request: &mut ScanRequest) {
    let mut origins: HashMap<PathBuf, crate::types::FindingOrigin> = HashMap::new();
    for process in running_processes() {
        if let Some(path) = canonical(&process.exe) {
            origins.entry(path).or_insert(FindingOrigin::Process {
                pid: process.pid,
                name: process.name,
            });
        }
    }
    for item in startup_items() {
        let origin = FindingOrigin::StartupItem {
            location: item.location.clone(),
            label: item.label.clone(),
        };
        if let Some(path) = item.program.as_deref().and_then(canonical) {
            origins.entry(path).or_insert_with(|| origin.clone());
        }
        let location = Path::new(&item.location);
        if location.is_absolute()
            && let Some(path) = canonical(location)
        {
            origins.entry(path).or_insert(origin);
        }
    }
    for path in origins.keys() {
        request.roots.push(path.clone());
    }
    request.origins.extend(origins);
}

/// Rychlá kontrola: procesy, položky po spuštění, Stažené soubory a Plocha.
pub fn quick_scan_request() -> ScanRequest {
    let mut request = ScanRequest::new(Vec::new());
    if let Some(home) = home_dir() {
        for name in ["Downloads", "Desktop"] {
            let dir = home.join(name);
            if dir.is_dir() {
                request.roots.push(dir);
            }
        }
    }
    add_system_targets(&mut request);
    request.roots.truncate(256);
    request
}

/// Úplná kontrola: celá domovská složka a aplikace, plus procesy a položky po spuštění.
pub fn full_scan_request() -> ScanRequest {
    let mut request = ScanRequest::new(Vec::new());
    if let Some(home) = home_dir() {
        request.roots.push(home);
    }
    #[cfg(target_os = "macos")]
    request.roots.push(PathBuf::from("/Applications"));
    #[cfg(windows)]
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(dir) = std::env::var_os(var) {
            request.roots.push(PathBuf::from(dir));
        }
    }
    add_system_targets(&mut request);
    request.roots.retain(|root| root.exists());
    request.roots.truncate(256);
    request
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_yield_programs() {
        #[cfg(windows)]
        let (quoted, plain) = (
            r#""C:\Program Files\App\app.exe" --background"#,
            r"C:\Tools\tool.exe /quiet",
        );
        #[cfg(not(windows))]
        let (quoted, plain) = (r#""/opt/app/app" --background"#, "/usr/bin/tool --quiet");
        assert!(program_from_command(quoted).is_some());
        assert!(program_from_command(plain).is_some());
        assert_eq!(program_from_command("relative.exe"), None);
    }

    #[test]
    fn processes_include_this_test() {
        let me = std::env::current_exe().unwrap();
        let me = canonical(&me).unwrap();
        assert!(
            running_processes()
                .iter()
                .any(|p| canonical(&p.exe).as_deref() == Some(me.as_path()))
        );
    }
}
