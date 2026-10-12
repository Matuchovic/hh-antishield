//! Cíle rychlé a úplné kontroly: běžící procesy, položky spouštěné po
//! přihlášení a typické složky uživatele. Výčet jen čte; zásahy (ukončení
//! procesu, vypnutí položky) jsou samostatné funkce volané po potvrzení.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::error::EngineError;
use crate::types::{FindingOrigin, ScanRequest};

const MAX_STARTUP_ITEMS: usize = 1_000;
/// Kolik zkontrolovaných programů si hlídání procesů pamatuje.
const MAX_CHECKED_PROGRAMS: usize = 20_000;
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

/// Článek řetězu spuštění: proces a kdy začal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessLink {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub started_at_ms: Option<u64>,
}

/// Proces a ti, kdo ho spustili (rodiče), od něj ke kořeni; nejvýš `depth`
/// článků. Proces, který už neběží, vrátí prázdný řetěz.
pub fn process_chain(pid: u32, depth: usize) -> Vec<ProcessLink> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    let mut chain = Vec::new();
    let mut current = Some(Pid::from_u32(pid));
    while let Some(pid) = current
        && chain.len() < depth
    {
        let Some(process) = system.process(pid) else {
            break;
        };
        chain.push(ProcessLink {
            pid: pid.as_u32(),
            name: process.name().to_string_lossy().chars().take(200).collect(),
            path: process.exe().map(|exe| exe.to_string_lossy().into_owned()),
            started_at_ms: process.start_time().checked_mul(1000),
        });
        // Smyčka v rodičích (nemělo by nastat) řetěz ukončí.
        current = process
            .parent()
            .filter(|parent| *parent != pid && !chain.iter().any(|l| l.pid == parent.as_u32()));
    }
    chain
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

/// Program v části disku, kterou chrání systém (macOS SIP, složka Windows).
/// Hlídání spuštěných programů ho přeskakuje: nejde ho změnit ani izolovat.
pub fn is_system_program(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    const PREFIXES: &[&str] = &[
        "/System/",
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/usr/lib/",
        "/usr/share/",
        "/Library/Apple/",
        "/private/var/db/",
    ];
    #[cfg(not(any(target_os = "macos", windows)))]
    const PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"];
    #[cfg(windows)]
    {
        let windir = std::env::var_os("SystemRoot")
            .map(|v| v.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|| r"c:\windows".into());
        let text = path.to_string_lossy().to_ascii_lowercase();
        let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
        text.starts_with(&format!(r"{}\", windir.trim_end_matches('\\')))
    }
    #[cfg(not(windows))]
    {
        let text = path.to_string_lossy();
        PREFIXES.iter().any(|prefix| text.starts_with(prefix))
    }
}

/// Hlídání spuštěných programů: `poll` vrátí procesy, jejichž program se
/// ještě nekontroloval (nebo se od kontroly změnil). Každý program jen
/// jednou, bez systémových programů a bez vlastní aplikace. Spuštění tím
/// nejde předem zablokovat; škodlivý proces se ukončí až po startu.
pub struct ProcessMonitor {
    system: sysinfo::System,
    checked: HashMap<PathBuf, (u64, Option<SystemTime>)>,
    own_exe: Option<PathBuf>,
}

impl std::fmt::Debug for ProcessMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessMonitor")
            .field("checked", &self.checked.len())
            .finish()
    }
}

impl Default for ProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            system: sysinfo::System::new(),
            checked: HashMap::new(),
            own_exe: std::env::current_exe().ok(),
        }
    }

    /// Procesy s programy, které je potřeba zkontrolovat (seřazené podle PID).
    pub fn poll(&mut self) -> Vec<ProcessInfo> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
        );
        let mut seen_now = HashSet::new();
        let mut fresh = Vec::new();
        for (pid, process) in self.system.processes() {
            let Some(exe) = process.exe().filter(|exe| exe.is_absolute()) else {
                continue;
            };
            if is_system_program(exe)
                || self.own_exe.as_deref() == Some(exe)
                || !seen_now.insert(exe.to_path_buf())
            {
                continue;
            }
            let Ok(meta) = fs::metadata(exe) else {
                continue;
            };
            let stamp = (meta.len(), meta.modified().ok());
            if self.checked.get(exe) == Some(&stamp) {
                continue;
            }
            if self.checked.len() >= MAX_CHECKED_PROGRAMS {
                self.checked.clear();
            }
            self.checked.insert(exe.to_path_buf(), stamp);
            fresh.push(ProcessInfo {
                pid: pid.as_u32(),
                name: process.name().to_string_lossy().chars().take(200).collect(),
                exe: exe.to_path_buf(),
            });
        }
        fresh.sort_by_key(|p| p.pid);
        fresh
    }
}

/// Složky s položkami spouštěnými po přihlášení nebo startu systému.
#[cfg(target_os = "macos")]
pub fn startup_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
    ];
    if let Some(home) = home_dir() {
        dirs.insert(0, home.join("Library/LaunchAgents"));
    }
    dirs
}

/// Složky s položkami spouštěnými po přihlášení.
#[cfg(windows)]
pub fn startup_dirs() -> Vec<PathBuf> {
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

/// Složky s položkami spouštěnými po přihlášení.
#[cfg(not(any(target_os = "macos", windows)))]
pub fn startup_dirs() -> Vec<PathBuf> {
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

/// Aplikace (balíček `.app`) podle jejího Info.plist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppBundle {
    pub path: PathBuf,
    pub id: String,
    pub name: String,
}

/// Jen bezpečné znaky (identifikátor může jít do příkazu AppleScriptu).
pub(crate) fn valid_bundle_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Načte identifikátor a jméno balíčku `.app`.
pub fn read_app_bundle(app: &Path) -> Option<AppBundle> {
    let info = app.join("Contents/Info.plist");
    if fs::metadata(&info).ok()?.len() > MAX_PLIST_BYTES {
        return None;
    }
    let value = plist::Value::from_file(&info).ok()?;
    let dict = value.as_dictionary()?;
    let id = dict.get("CFBundleIdentifier")?.as_string()?.to_string();
    if !valid_bundle_id(&id) {
        return None;
    }
    let name = ["CFBundleDisplayName", "CFBundleName"]
        .iter()
        .find_map(|key| dict.get(key).and_then(|v| v.as_string()))
        .map(str::to_string)
        .filter(|n| !n.trim().is_empty())
        .or_else(|| app.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_default()
        .chars()
        .take(120)
        .collect();
    Some(AppBundle {
        path: app.to_path_buf(),
        id,
        name,
    })
}

/// Balíčky `.app`, ve kterých program leží, od vnějšího (hlavní aplikace)
/// k vnitřním (pomocníci).
pub fn app_bundle_paths(exe: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = exe
        .ancestors()
        .filter(|a| a.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
        .collect();
    found.reverse();
    found
}

/// Identifikátory běžících aplikací včetně jejich pomocníků (jen macOS).
pub fn running_app_ids() -> HashSet<String> {
    let mut ids = HashSet::new();
    if !cfg!(target_os = "macos") {
        return ids;
    }
    let mut seen = HashSet::new();
    for process in running_processes() {
        for bundle in app_bundle_paths(&process.exe) {
            if seen.insert(bundle.clone())
                && let Some(app) = read_app_bundle(&bundle)
            {
                ids.insert(app.id);
            }
        }
    }
    ids
}

/// Identifikátory nainstalovaných aplikací: Aplikace, systémové aplikace
/// a ~/Aplikace, i o jednu složku hlouběji (např. sady Office). Jen macOS.
pub fn installed_app_ids(home: &Path) -> HashSet<String> {
    let mut ids = HashSet::new();
    if !cfg!(target_os = "macos") {
        return ids;
    }
    let roots = [
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
        home.join("Applications"),
    ];
    let is_app = |p: &Path| p.extension().is_some_and(|e| e == "app");
    for root in roots {
        let Ok(read) = fs::read_dir(&root) else {
            continue;
        };
        for path in read.filter_map(|e| e.ok().map(|e| e.path())).take(5_000) {
            if is_app(&path) {
                ids.extend(read_app_bundle(&path).map(|a| a.id));
            } else if path.is_dir()
                && let Ok(inner) = fs::read_dir(&path)
            {
                for app in inner
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| is_app(p))
                    .take(500)
                {
                    ids.extend(read_app_bundle(&app).map(|a| a.id));
                }
            }
        }
    }
    ids
}

pub(crate) fn program_from_plist(path: &Path) -> Option<(String, Option<PathBuf>)> {
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

/// Položka po spuštění definovaná souborem ve složce položek po spuštění
/// (plist, .desktop, zástupce); jinde nebo pro nečitelný soubor `None`.
pub fn startup_item_at(path: &Path) -> Option<StartupItem> {
    if !is_startup_location(path) || !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    let (label, program) = match extension.as_deref() {
        Some("plist") => program_from_plist(path)?,
        Some("desktop") => program_from_desktop_entry(path)?,
        _ => (
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            // Zástupce (.lnk) se nerozbaluje; spustitelný soubor ve složce je program.
            None,
        ),
    };
    Some(StartupItem {
        location: path.display().to_string(),
        label,
        program,
    })
}

/// Položky spouštěné po přihlášení (LaunchAgents/Daemons, Startup, Run, autostart).
pub fn startup_items() -> Vec<StartupItem> {
    let mut items = Vec::new();
    for dir in startup_dirs() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_STARTUP_ITEMS) {
            if let Some(item) = startup_item_at(&entry.path()) {
                items.push(item);
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

/// Složky rozšíření prohlížečů (Chrome, Edge, Brave, Firefox) ve všech profilech.
pub fn browser_extension_dirs() -> Vec<PathBuf> {
    const MAX_PROFILES: usize = 20;
    #[cfg_attr(not(any(target_os = "macos", windows)), allow(unused_mut))]
    let mut bases: Vec<(PathBuf, &str)> = Vec::new();
    #[cfg(target_os = "macos")]
    if let Some(home) = home_dir() {
        let support = home.join("Library/Application Support");
        bases.push((support.join("Google/Chrome"), "Extensions"));
        bases.push((support.join("Microsoft Edge"), "Extensions"));
        bases.push((support.join("BraveSoftware/Brave-Browser"), "Extensions"));
        bases.push((support.join("Firefox/Profiles"), "extensions"));
    }
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            bases.push((local.join(r"Google\Chrome\User Data"), "Extensions"));
            bases.push((local.join(r"Microsoft\Edge\User Data"), "Extensions"));
            bases.push((
                local.join(r"BraveSoftware\Brave-Browser\User Data"),
                "Extensions",
            ));
        }
        if let Some(roaming) = std::env::var_os("APPDATA").map(PathBuf::from) {
            bases.push((roaming.join(r"Mozilla\Firefox\Profiles"), "extensions"));
        }
    }
    let mut dirs = Vec::new();
    for (base, leaf) in bases {
        let Ok(profiles) = fs::read_dir(&base) else {
            continue;
        };
        for profile in profiles.flatten().take(MAX_PROFILES) {
            let dir = profile.path().join(leaf);
            if dir.is_dir() {
                dirs.push(dir);
            }
        }
    }
    dirs
}

/// Složky Apple Mail s přílohami (přístup vyžaduje plný přístup k disku).
pub fn mail_folders() -> Vec<PathBuf> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    [
        home.join("Library/Mail"),
        home.join("Library/Containers/com.apple.mail/Data/Library/Mail Downloads"),
    ]
    .into_iter()
    .filter(|dir| dir.is_dir())
    .collect()
}

/// Soubor ve složkách Mailu, který je přílohou (ne zpráva ani index pošty).
pub fn is_mail_store_file(path: &Path) -> bool {
    let Some(home) = home_dir() else {
        return false;
    };
    path.starts_with(home.join("Library/Mail"))
        && !path.components().any(|c| c.as_os_str() == "Attachments")
}

/// Rychlá kontrola: procesy, položky po spuštění, Stažené soubory, Plocha
/// a rozšíření prohlížečů.
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
    request.roots.extend(browser_extension_dirs());
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
    fn the_launch_chain_starts_with_the_process_itself() {
        let me = std::process::id();
        let chain = process_chain(me, 4);
        assert_eq!(chain.first().map(|link| link.pid), Some(me));
        assert!(
            chain.len() >= 2,
            "a test process always has a parent: {chain:?}"
        );
        assert!(chain.len() <= 4);
        assert!(process_chain(u32::MAX - 7, 4).is_empty());
    }

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

    #[test]
    fn system_programs_are_recognized() {
        #[cfg(target_os = "macos")]
        {
            assert!(is_system_program(Path::new("/usr/bin/curl")));
            assert!(is_system_program(Path::new(
                "/System/Applications/Mail.app/Contents/MacOS/Mail"
            )));
            assert!(!is_system_program(Path::new("/usr/local/bin/tool")));
            assert!(!is_system_program(Path::new(
                "/Applications/App.app/Contents/MacOS/App"
            )));
        }
        #[cfg(windows)]
        {
            assert!(is_system_program(Path::new(r"C:\Windows\System32\cmd.exe")));
            assert!(!is_system_program(Path::new(
                r"C:\Users\eva\Downloads\a.exe"
            )));
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            assert!(is_system_program(Path::new("/usr/bin/curl")));
            assert!(!is_system_program(Path::new("/home/eva/Downloads/a")));
        }
    }

    /// Nově spuštěný program se nahlásí jednou; další kontrola ho už nevrátí.
    #[cfg(unix)]
    #[test]
    fn new_programs_are_reported_once() {
        let tmp = tempfile::tempdir().unwrap();
        let program = tmp.path().join("hh-test-sleeper");
        std::fs::copy("/bin/sleep", &program).unwrap();
        let mut monitor = ProcessMonitor::new();
        let mut child = std::process::Command::new(&program)
            .arg("30")
            .spawn()
            .unwrap();
        let canonical_program = canonical(&program).unwrap();
        let is_ours =
            |p: &ProcessInfo| canonical(&p.exe).as_deref() == Some(canonical_program.as_path());
        let mut first = Vec::new();
        for _ in 0..20 {
            first = monitor.poll();
            if first.iter().any(is_ours) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let second = monitor.poll();
        let _ = child.kill();
        let _ = child.wait();
        assert!(first.iter().any(is_ours), "{first:?}");
        assert!(!second.iter().any(is_ours));
        assert!(first.iter().all(|p| !is_system_program(&p.exe)));
    }

    #[test]
    fn mail_messages_are_skipped_but_attachments_are_not() {
        let Some(home) = home_dir() else {
            return;
        };
        let mail = home.join("Library/Mail/V10/acc/INBOX.mbox");
        assert!(is_mail_store_file(&mail.join("Data/Messages/1.emlx")));
        assert!(!is_mail_store_file(
            &mail.join("Data/Attachments/1/2/invoice.pdf")
        ));
        assert!(!is_mail_store_file(&home.join("Downloads/invoice.pdf")));
    }
}
