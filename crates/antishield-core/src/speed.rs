//! Zrychlení: co počítač skutečně brzdí, změřené, ne odhadnuté.
//!
//! Měří volné místo, tlak na paměť, odkládání paměti na disk, vytížení
//! procesoru a dobu běhu, najde náročné aplikace a položky spouštěné po
//! přihlášení. Nabízí jen šetrné nebo vratné kroky: aplikaci požádá
//! o ukončení (sama se zeptá na uložení práce), položku po přihlášení odloží
//! do vlastní složky (jde vrátit). „Čištění RAM“ ani zásahy do systému nedělá:
//! počítač by tím nezrychlil.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::EngineError;
use crate::system::{
    AppBundle, app_bundle_paths, is_system_program, program_from_plist, read_app_bundle,
};

/// Kolik náročných aplikací ukázat.
const MAX_HEAVY: usize = 8;
/// Náročná aplikace: aspoň tento podíl celého procesoru, nebo tolik paměti.
const HEAVY_CPU_SHARE: f32 = 8.0;
const HEAVY_MEMORY: u64 = 1536 * 1024 * 1024;
/// Jak dlouho se po požadavku čeká, jestli program skončil.
const QUIT_WAIT: Duration = Duration::from_secs(6);

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

/// Aplikace (se všemi pomocnými procesy) nebo program, který zatěžuje počítač.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeavyProcess {
    /// Hlavní proces (u aplikace ten, který běží z balíčku přímo).
    pub pid: u32,
    pub name: String,
    /// Program hlavního procesu.
    pub path: Option<String>,
    /// Podíl celého procesoru (všech jader) v procentech, součet procesů.
    pub cpu: f32,
    /// Paměť procesů dohromady (sdílené části se počítají vícekrát, je to horní odhad).
    pub memory: u64,
    pub processes: u32,
    /// Aplikace: ukončí se běžným požadavkem (zeptá se na uložení práce).
    pub bundle_id: Option<String>,
    pub app_path: Option<String>,
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

/// Jak dopadl požadavek na ukončení.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum QuitOutcome {
    /// Program skončil.
    Quit,
    /// Požadavek odešel, program ještě běží (např. se ptá na uložení práce).
    Pending,
}

fn entry_id(path: &Path) -> String {
    hex::encode(&Sha256::digest(path.to_string_lossy().as_bytes())[..8])
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
fn agent_pids() -> HashMap<String, u32> {
    let Ok(out) = Command::new("/bin/launchctl").arg("list").output() else {
        return HashMap::new();
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
fn agent_pids() -> HashMap<String, u32> {
    HashMap::new()
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
    // (složka, pro celý systém, zapnutá)
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

/// Aplikace s pomocníky nebo jeden program, jak se sčítá do přehledu.
struct Group {
    name: String,
    bundle: Option<AppBundle>,
    cpu: f32,
    memory: u64,
    processes: u32,
    /// (PID, program, začátek běhu, běží přímo z balíčku)
    main: Option<(u32, Option<PathBuf>, u64, bool)>,
}

/// Seskupí procesy: aplikaci macOS s pomocníky podle vnějšího balíčku `.app`,
/// na Windows procesy stejného programu, jinak každý proces zvlášť.
fn heavy_processes(system: &sysinfo::System, own_pid: u32) -> Vec<HeavyProcess> {
    let share = cores(system);
    let own_exe = std::env::current_exe().ok();
    let own_bundle = own_exe
        .as_deref()
        .and_then(|e| app_bundle_paths(e).into_iter().next());
    let mut bundles: HashMap<PathBuf, Option<AppBundle>> = HashMap::new();
    let mut groups: HashMap<String, Group> = HashMap::new();
    for (pid, process) in system.processes() {
        let pid = pid.as_u32();
        let exe = process.exe().map(Path::to_path_buf);
        if pid == own_pid
            || exe.as_deref().is_some_and(is_system_program)
            || (exe.is_some() && exe == own_exe)
        {
            continue;
        }
        let outer = exe
            .as_deref()
            .and_then(|e| app_bundle_paths(e).into_iter().next());
        if outer.is_some() && outer == own_bundle {
            continue;
        }
        let bundle = outer.as_ref().and_then(|path| {
            bundles
                .entry(path.clone())
                .or_insert_with(|| read_app_bundle(path))
                .clone()
        });
        let key = match (&bundle, &exe) {
            (Some(b), _) => format!("app:{}", b.path.display()),
            (None, Some(e)) if cfg!(windows) => format!("exe:{}", e.display()),
            _ => format!("pid:{pid}"),
        };
        let name: String = process.name().to_string_lossy().chars().take(120).collect();
        let group = groups.entry(key).or_insert_with(|| Group {
            name: bundle.as_ref().map_or(name, |b| b.name.clone()),
            bundle: bundle.clone(),
            cpu: 0.0,
            memory: 0,
            processes: 0,
            main: None,
        });
        group.cpu += process.cpu_usage() / share;
        group.memory = group.memory.saturating_add(process.memory());
        group.processes += 1;
        // Hlavní proces aplikace běží přímo z Contents/MacOS; jinak nejstarší.
        let direct = match (&bundle, &exe) {
            (Some(b), Some(e)) => e.parent() == Some(b.path.join("Contents/MacOS").as_path()),
            _ => true,
        };
        let start = process.start_time();
        let better = group
            .main
            .as_ref()
            .is_none_or(|(_, _, old_start, old_direct)| {
                (direct && !old_direct) || (direct == *old_direct && start < *old_start)
            });
        if better {
            group.main = Some((pid, exe.clone(), start, direct));
        }
    }
    let mut heavy: Vec<HeavyProcess> = groups
        .into_values()
        .filter(|g| g.cpu >= HEAVY_CPU_SHARE || g.memory >= HEAVY_MEMORY)
        .filter_map(|g| {
            let (pid, exe, _, _) = g.main?;
            Some(HeavyProcess {
                pid,
                name: g.name,
                path: exe.map(|e| e.to_string_lossy().into_owned()),
                cpu: g.cpu,
                memory: g.memory,
                processes: g.processes,
                bundle_id: g.bundle.as_ref().map(|b| b.id.clone()),
                app_path: g
                    .bundle
                    .as_ref()
                    .map(|b| b.path.to_string_lossy().into_owned()),
            })
        })
        .collect();
    heavy.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.memory.cmp(&a.memory)));
    heavy.truncate(MAX_HEAVY);
    heavy
}

/// Disk, paměť a doba běhu bez měření procesoru a procesů (rychlé, pro zprávy
/// o stavu, které Mac posílá pravidelně).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vitals {
    pub disk: Option<DiskInfo>,
    pub memory: MemoryInfo,
    pub uptime_secs: u64,
}

pub fn vitals(home: &Path) -> Vitals {
    use sysinfo::{RefreshKind, System};
    let mut system = System::new_with_specifics(RefreshKind::nothing());
    system.refresh_memory();
    Vitals {
        disk: disk_for(home),
        memory: MemoryInfo {
            total: system.total_memory(),
            used: system.used_memory(),
            swap_used: system.used_swap(),
            pressure: memory_pressure(),
        },
        uptime_secs: System::uptime(),
    }
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
        heavy: heavy_processes(&system, own_pid),
        startup: startup_entries(home, disabled_dir, own_label, &system),
        measured_at_ms: crate::now_ms(),
    }
}

/// Běží proces pořád stejný program? (ochrana proti opětovnému použití PID)
fn still_running(pid: u32, exe: &Path) -> bool {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let target = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    system.process(target).and_then(|p| p.exe()) == Some(exe)
}

fn wait_for_exit(pid: u32, exe: &Path) -> QuitOutcome {
    let deadline = Instant::now() + QUIT_WAIT;
    while Instant::now() < deadline {
        if !still_running(pid, exe) {
            return QuitOutcome::Quit;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    QuitOutcome::Pending
}

/// Požádá aplikaci nebo program o běžné ukončení. Aplikace dostane stejný
/// požadavek jako po ⌘Q (zeptá se na uložení práce); program signál SIGTERM,
/// na Windows zavření oken. Nic neukončuje násilím, systémové programy ani
/// AntiShield neukončí a ověří, že PID pořád patří stejnému programu.
pub fn quit_process(target: &HeavyProcess, own_pid: u32) -> Result<QuitOutcome, EngineError> {
    let refuse = |reason: &str| Err(EngineError::InvalidRequest(reason.into()));
    let Some(exe) = target.path.as_deref().map(Path::new) else {
        return refuse("the program is unknown");
    };
    if target.pid == own_pid || is_system_program(exe) {
        return refuse("this program cannot be quit");
    }
    if !still_running(target.pid, exe) {
        return Ok(QuitOutcome::Quit);
    }
    if cfg!(target_os = "macos")
        && let Some(id) = target.bundle_id.as_deref()
    {
        if !crate::system::valid_bundle_id(id) {
            return refuse("invalid app identifier");
        }
        // Bez čekání na odpověď: aplikace se může ptát na uložení práce.
        let script = format!("tell application id \"{id}\" to quit");
        let out = Command::new("/usr/bin/osascript")
            .args([
                "-e",
                "ignoring application responses",
                "-e",
                script.as_str(),
                "-e",
                "end ignoring",
            ])
            .output()
            .map_err(|e| EngineError::InvalidRequest(e.to_string()))?;
        if !out.status.success() {
            let detail = String::from_utf8_lossy(&out.stderr);
            return if detail.contains("-1743") {
                refuse("automation not allowed")
            } else {
                refuse("the app did not accept the request")
            };
        }
        return Ok(wait_for_exit(target.pid, exe));
    }
    #[cfg(windows)]
    {
        // Bez /F: program dostane požadavek na zavření oken (může se ptát na uložení).
        let windir = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let taskkill = PathBuf::from(windir).join(r"System32\taskkill.exe");
        let status = Command::new(taskkill)
            .args(["/PID", &target.pid.to_string()])
            .output()
            .map_err(|e| EngineError::InvalidRequest(e.to_string()))?
            .status;
        if !status.success() {
            return refuse("the program has no window to close");
        }
        Ok(wait_for_exit(target.pid, exe))
    }
    #[cfg(not(windows))]
    {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System};
        let pid = Pid::from_u32(target.pid);
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing(),
        );
        match system.process(pid).and_then(|p| p.kill_with(Signal::Term)) {
            Some(true) => Ok(wait_for_exit(target.pid, exe)),
            _ => refuse("the program could not be asked to quit"),
        }
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
    let mut full: Vec<&str> = vec![args[0], domain.as_str()];
    full.extend_from_slice(&args[1..]);
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
        assert!(report.heavy.iter().all(|p| p.processes >= 1));
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

    fn target(pid: u32, path: &Path, bundle_id: Option<&str>) -> HeavyProcess {
        HeavyProcess {
            pid,
            name: "x".into(),
            path: Some(path.to_string_lossy().into_owned()),
            cpu: 50.0,
            memory: 0,
            processes: 1,
            bundle_id: bundle_id.map(str::to_string),
            app_path: None,
        }
    }

    #[test]
    fn system_programs_self_and_unknown_programs_are_never_quit() {
        let me = std::process::id();
        let exe = std::env::current_exe().unwrap();
        assert!(quit_process(&target(me, &exe, None), me).is_err());
        #[cfg(unix)]
        assert!(quit_process(&target(1, Path::new("/sbin/launchd"), None), me).is_err());
        let unknown = HeavyProcess {
            path: None,
            ..target(1, &exe, None)
        };
        assert!(quit_process(&unknown, me).is_err());
        // PID, který už patří jinému programu, se nijak nedotkne.
        assert_eq!(
            quit_process(&target(me, Path::new("/nonexistent/app"), None), u32::MAX).unwrap(),
            QuitOutcome::Quit
        );
        assert!(crate::system::valid_bundle_id("com.google.Chrome"));
        assert!(!crate::system::valid_bundle_id(
            "x\" to do shell script \"rm"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_program_is_asked_to_quit_and_its_exit_is_confirmed() {
        // Systémový `sleep` zůstane netknutý.
        let mut system_sleep = Command::new("sleep").arg("30").spawn().unwrap();
        let exe = exe_of(system_sleep.id());
        assert!(is_system_program(&exe), "{exe:?}");
        assert!(quit_process(&target(system_sleep.id(), &exe, None), std::process::id()).is_err());
        system_sleep.kill().unwrap();
        let _ = system_sleep.wait();

        // Kopie mimo systém (jako program uživatele) dostane SIGTERM a skončí.
        let tmp = tempfile::tempdir().unwrap();
        let copy = tmp.path().join("busy-tool");
        std::fs::copy(&exe, &copy).unwrap();
        // Souběžný test může po fork chvíli držet kopii otevřenou pro zápis
        // (Linux pak hlásí ETXTBSY); spuštění se zopakuje.
        let mut child = (0..100)
            .find_map(|_| match Command::new(&copy).arg("30").spawn() {
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(50));
                    None
                }
                other => Some(other),
            })
            .unwrap()
            .unwrap();
        let exe = exe_of(child.id());
        let outcome = quit_process(&target(child.id(), &exe, None), std::process::id());
        let status = child.wait().unwrap();
        assert_eq!(outcome.unwrap(), QuitOutcome::Quit);
        assert!(!status.success(), "ended by the request, not by itself");
    }

    #[cfg(unix)]
    fn exe_of(pid: u32) -> PathBuf {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
        let mut system = System::new();
        let target = Pid::from_u32(pid);
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[target]),
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
        );
        system.process(target).unwrap().exe().unwrap().to_path_buf()
    }
}
