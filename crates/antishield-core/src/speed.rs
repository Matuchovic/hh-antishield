//! Zrychlení: co počítač skutečně brzdí, změřené, ne odhadnuté.
//!
//! Měří volné místo, tlak na paměť, vytížení procesoru a dobu běhu, najde
//! náročné programy a položky spouštěné po přihlášení. Nabízí jen vratné nebo
//! šetrné kroky: aplikaci požádá o ukončení (s dotazem na uložení práce),
//! položku po přihlášení odloží do vlastní složky (jde vrátit). „Čištění RAM“
//! ani zásahy do systému nedělá: počítač by tím nezrychlil.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::EngineError;
use crate::system::{is_system_program, program_from_plist};

/// Kolik náročných procesů ukázat.
const MAX_HEAVY: usize = 8;
/// Náročný proces: aspoň tento podíl celého procesoru, nebo tolik paměti.
const HEAVY_CPU_SHARE: f32 = 8.0;
const HEAVY_MEMORY: u64 = 1536 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub total: u64,
    pub free: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MemoryPressure {
    Normal,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryInfo {
    pub total: u64,
    pub used: u64,
    /// Paměť odložená na disk: když roste, počítač zpomaluje.
    pub swap_used: u64,
    /// Tlak na paměť podle systému (jen macOS); ukazuje skutečný nedostatek.
    pub pressure: Option<MemoryPressure>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeavyProcess {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    /// Podíl celého procesoru (všech jader) v procentech.
    pub cpu: f32,
    pub memory: u64,
    /// Aplikace (balíček .app): ukončí se šetrně, s dotazem na uložení.
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    pub id: String,
    pub label: String,
    pub plist: String,
    pub program: Option<String>,
    /// Položka pro celý systém: vypnout ji jde jen v Nastavení systému.
    pub system: bool,
    pub enabled: bool,
    pub pid: Option<u32>,
    pub cpu: f32,
    pub memory: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedReport {
    pub disk: Option<DiskInfo>,
    pub memory: MemoryInfo,
    /// Vytížení celého procesoru v procentech.
    pub cpu: f32,
    pub cores: usize,
    pub uptime_secs: u64,
    pub heavy: Vec<HeavyProcess>,
    pub startup: Vec<StartupEntry>,
    pub measured_at_ms: u64,
}

fn entry_id(path: &Path) -> String {
    hex::encode(&Sha256::digest(path.to_string_lossy().as_bytes())[..8])
}

/// Balíček `.app`, ve kterém program leží, a jeho identifikátor.
fn bundle_of(exe: &Path) -> Option<(PathBuf, String)> {
    let bundle = exe
        .ancestors()
        .find(|a| a.extension().is_some_and(|e| e == "app"))?
        .to_path_buf();
    let info = plist::Value::from_file(bundle.join("Contents/Info.plist")).ok()?;
    let id = info
        .as_dictionary()?
        .get("CFBundleIdentifier")?
        .as_string()?
        .to_string();
    valid_bundle_id(&id).then_some((bundle, id))
}

/// Jen bezpečné znaky (identifikátor jde do příkazu AppleScriptu).
fn valid_bundle_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

#[cfg(target_os = "macos")]
fn memory_pressure() -> Option<MemoryPressure> {
    let out = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.memorystatus_vm_pressure_level"])
        .output()
        .ok()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "1" => Some(MemoryPressure::Normal),
        "2" => Some(MemoryPressure::Warning),
        "4" => Some(MemoryPressure::Critical),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
fn memory_pressure() -> Option<MemoryPressure> {
    None
}

fn disk_for(home: &Path) -> Option<DiskInfo> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|d| home.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| DiskInfo {
            total: d.total_space(),
            free: d.available_space(),
        })
}

/// PID běžících uživatelských agentů podle `launchctl list` (PID, stav, jméno).
#[cfg(target_os = "macos")]
fn agent_pids() -> std::collections::HashMap<String, u32> {
    let Ok(out) = Command::new("/bin/launchctl").arg("list").output() else {
        return Default::default();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut cols = line.split('\t');
            let pid = cols.next()?.trim().parse::<u32>().ok()?;
            let label = cols.nth(1)?.trim().to_string();
            Some((label, pid))
        })
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn agent_pids() -> std::collections::HashMap<String, u32> {
    Default::default()
}

/// Složka uživatelských položek po přihlášení, které jde vypnout.
pub fn user_startup_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/LaunchAgents")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map_or_else(
            || home.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
            |a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
        )
    } else {
        home.join(".config/autostart")
    }
}

fn startup_entries(
    home: &Path,
    disabled_dir: &Path,
    own_label: &str,
    system: &sysinfo::System,
) -> Vec<StartupEntry> {
    let pids = agent_pids();
    let mut dirs: Vec<(PathBuf, bool, bool)> = vec![
        (user_startup_dir(home), false, true),
        (disabled_dir.to_path_buf(), false, false),
    ];
    if cfg!(target_os = "macos") {
        dirs.push((PathBuf::from("/Library/LaunchAgents"), true, true));
        dirs.push((PathBuf::from("/Library/LaunchDaemons"), true, true));
    }
    let mut entries = Vec::new();
    for (dir, is_system, enabled) in dirs {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for path in read.filter_map(|e| e.ok().map(|e| e.path())).take(500) {
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let is_plist = path.extension().is_some_and(|e| e == "plist");
            let (label, program) = if is_plist {
                match program_from_plist(&path) {
                    Some(found) => found,
                    None => continue,
                }
            } else {
                (
                    path.file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    None,
                )
            };
            if label == own_label {
                continue;
            }
            let pid = enabled.then(|| pids.get(&label).copied()).flatten();
            let (cpu, memory) = pid
                .and_then(|p| system.process(sysinfo::Pid::from_u32(p)))
                .map_or((0.0, 0), |p| (p.cpu_usage() / cores(system), p.memory()));
            entries.push(StartupEntry {
                id: entry_id(&path),
                label,
                plist: path.to_string_lossy().into_owned(),
                program: program.map(|p| p.to_string_lossy().into_owned()),
                system: is_system,
                enabled,
                pid,
                cpu,
                memory,
            });
        }
    }
    entries.sort_by(|a, b| {
        a.system
            .cmp(&b.system)
            .then(b.cpu.total_cmp(&a.cpu))
            .then(a.label.cmp(&b.label))
    });
    entries
}

fn cores(system: &sysinfo::System) -> f32 {
    system.cpus().len().max(1) as f32
}

/// Změří stav počítače. Trvá asi sekundu (vytížení procesoru se měří mezi dvěma vzorky).
pub fn measure(home: &Path, disabled_dir: &Path, own_label: &str, own_pid: u32) -> SpeedReport {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};
    let kind = ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_exe(UpdateKind::OnlyIfNotSet);
    let mut system = System::new_with_specifics(RefreshKind::nothing());
    system.refresh_memory();
    system.refresh_cpu_usage();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    std::thread::sleep(Duration::from_millis(1000).max(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL));
    system.refresh_cpu_usage();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);

    let share = cores(&system);
    let mut heavy: Vec<HeavyProcess> = system
        .processes()
        .iter()
        .filter(|(pid, _)| pid.as_u32() != own_pid)
        .filter_map(|(pid, p)| {
            let exe = p.exe().map(Path::to_path_buf);
            if exe.as_deref().is_some_and(is_system_program) {
                return None;
            }
            let cpu = p.cpu_usage() / share;
            (cpu >= HEAVY_CPU_SHARE || p.memory() >= HEAVY_MEMORY).then(|| HeavyProcess {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().chars().take(120).collect(),
                path: exe.as_ref().map(|e| e.to_string_lossy().into_owned()),
                cpu,
                memory: p.memory(),
                bundle_id: exe.as_deref().and_then(bundle_of).map(|(_, id)| id),
            })
        })
        .collect();
    heavy.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.memory.cmp(&a.memory)));
    heavy.truncate(MAX_HEAVY);

    SpeedReport {
        disk: disk_for(home),
        memory: MemoryInfo {
            total: system.total_memory(),
            used: system.used_memory(),
            swap_used: system.used_swap(),
            pressure: memory_pressure(),
        },
        cpu: system.global_cpu_usage(),
        cores: system.cpus().len(),
        uptime_secs: System::uptime(),
        heavy,
        startup: startup_entries(home, disabled_dir, own_label, &system),
        measured_at_ms: crate::now_ms(),
    }
}

/// Požádá proces o ukončení. Aplikace dostane běžný požadavek na ukončení
/// (zeptá se na uložení práce); ostatní procesy signál SIGTERM. Ověří, že PID
/// pořád patří stejnému programu, a systémové programy neukončuje.
pub fn quit_process(pid: u32, expected_exe: &Path, own_pid: u32) -> Result<(), EngineError> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System, UpdateKind};
    if pid == own_pid || is_system_program(expected_exe) {
        return Err(EngineError::InvalidRequest(
            "this process cannot be quit".into(),
        ));
    }
    let mut system = System::new();
    let target = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let process = system
        .process(target)
        .ok_or_else(|| EngineError::InvalidRequest("the process is no longer running".into()))?;
    if process.exe() != Some(expected_exe) {
        return Err(EngineError::InvalidRequest(
            "the process no longer runs the same program".into(),
        ));
    }
    if cfg!(target_os = "macos")
        && let Some((_, id)) = bundle_of(expected_exe)
    {
        let script = format!("tell application id \"{id}\" to quit");
        let status = Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .status()
            .map_err(|e| EngineError::InvalidRequest(e.to_string()))?;
        return if status.success() {
            Ok(())
        } else {
            Err(EngineError::InvalidRequest("the app did not quit".into()))
        };
    }
    match process.kill_with(Signal::Term) {
        Some(true) => Ok(()),
        _ => Err(EngineError::InvalidRequest(
            "the process could not be quit".into(),
        )),
    }
}

#[cfg(target_os = "macos")]
fn launchctl(args: &[&str]) {
    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|u| !u.is_empty() && u.chars().all(|c| c.is_ascii_digit()));
    let Some(uid) = uid else { return };
    let domain = format!("gui/{uid}");
    let mut full: Vec<&str> = vec![args[0], &domain];
    full.extend(&args[1..]);
    let _ = Command::new("/bin/launchctl").args(&full).output();
}

/// Přímý obsah složky bez odkazu (jen takovou položku smí vypnout/zapnout).
fn direct_child(path: &Path, dir: &Path) -> Result<(), EngineError> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| EngineError::InvalidRequest("the item no longer exists".into()))?;
    if path.parent() != Some(dir) || !meta.is_file() {
        return Err(EngineError::InvalidRequest("not a startup item".into()));
    }
    Ok(())
}

/// Vypne uživatelskou položku po přihlášení: zastaví ji a odloží do `disabled_dir`
/// (jde vrátit přes [`enable_startup`]). Vlastního agenta AntiShieldu nevypne.
pub fn disable_startup(
    plist: &Path,
    home: &Path,
    disabled_dir: &Path,
    own_label: &str,
) -> Result<PathBuf, EngineError> {
    let dir = user_startup_dir(home);
    direct_child(plist, &dir)?;
    if plist.extension().is_some_and(|e| e == "plist")
        && program_from_plist(plist).is_some_and(|(label, _)| label == own_label)
    {
        return Err(EngineError::InvalidRequest(
            "AntiShield cannot be disabled here".into(),
        ));
    }
    std::fs::create_dir_all(disabled_dir)?;
    let name = plist
        .file_name()
        .ok_or_else(|| EngineError::InvalidRequest("invalid name".into()))?;
    let target = disabled_dir.join(name);
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(EngineError::InvalidRequest("already disabled".into()));
    }
    #[cfg(target_os = "macos")]
    {
        let path = plist.to_string_lossy();
        launchctl(&["bootout", path.as_ref()]);
    }
    std::fs::rename(plist, &target)?;
    Ok(target)
}

/// Vrátí položku odloženou přes [`disable_startup`] a znovu ji spustí.
pub fn enable_startup(
    stored: &Path,
    home: &Path,
    disabled_dir: &Path,
) -> Result<PathBuf, EngineError> {
    direct_child(stored, disabled_dir)?;
    let name = stored
        .file_name()
        .ok_or_else(|| EngineError::InvalidRequest("invalid name".into()))?;
    let target = user_startup_dir(home).join(name);
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(EngineError::InvalidRequest(
            "an item with this name already exists".into(),
        ));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(stored, &target)?;
    #[cfg(target_os = "macos")]
    {
        let path = target.to_string_lossy();
        launchctl(&["bootstrap", path.as_ref()]);
    }
    Ok(target)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn measuring_finds_memory_cpu_and_uptime() {
        let tmp = tempfile::tempdir().unwrap();
        let report = measure(tmp.path(), &tmp.path().join("off"), "x", std::process::id());
        assert!(report.memory.total > 0);
        assert!(report.cores > 0);
        assert!(report.cpu >= 0.0);
        assert!(report.heavy.iter().all(|p| p.pid != std::process::id()));
    }

    #[test]
    fn startup_items_are_disabled_reversibly_but_never_antishield() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let dir = user_startup_dir(home);
        std::fs::create_dir_all(&dir).unwrap();
        let off = home.join("disabled");
        let item = dir.join("com.vendor.updater.plist");
        std::fs::write(&item, b"<plist version=\"1.0\"><dict><key>Label</key><string>com.vendor.updater</string></dict></plist>").unwrap();
        let ours = dir.join("cz.hh.antishield.agent.plist");
        std::fs::write(&ours, b"<plist version=\"1.0\"><dict><key>Label</key><string>cz.hh.antishield.agent</string></dict></plist>").unwrap();

        let stored = disable_startup(&item, home, &off, "cz.hh.antishield.agent").unwrap();
        assert!(!item.exists() && stored.exists());
        assert!(disable_startup(&ours, home, &off, "cz.hh.antishield.agent").is_err());
        assert!(ours.exists());
        // Jen přímý obsah složky, nic odjinud.
        assert!(disable_startup(&home.join("elsewhere.plist"), home, &off, "x").is_err());

        let restored = enable_startup(&stored, home, &off).unwrap();
        assert_eq!(restored, item);
        assert!(item.exists());
        assert!(
            enable_startup(&item, home, &off).is_err(),
            "only from the disabled folder"
        );
    }

    #[test]
    fn system_programs_and_self_are_never_quit() {
        let me = std::process::id();
        let exe = std::env::current_exe().unwrap();
        assert!(quit_process(me, &exe, me).is_err());
        #[cfg(unix)]
        assert!(quit_process(1, Path::new("/sbin/launchd"), me).is_err());
        assert!(valid_bundle_id("com.google.Chrome"));
        assert!(!valid_bundle_id("x\" to do shell script \"rm"));
    }
}
