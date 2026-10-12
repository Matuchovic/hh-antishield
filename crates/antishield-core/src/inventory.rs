//! Podrobnosti o počítači pro firemní správu: hardware a baterie, zabezpečení
//! systému, zálohy a vytížení. Jen čte stav (systémové nástroje s pevnou
//! cestou a časovým limitem), nic nemění. Co z toho jde správci, určují
//! zásady, se kterými uživatel souhlasil.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fleet::{
    AppUsage, BackupReport, BatteryReport, HardwareReport, LoginItemReport, MAX_REPORT_APPS,
    MAX_REPORT_LOGIN_ITEMS, MAX_REPORT_OS_UPDATES, OsUpdate, PerformanceReport, SecurityReport,
};
use crate::posture::{self, PostureState};
use crate::speed::SpeedReport;

/// Výstup `ioreg` s baterií bývá velký (desítky kB).
#[cfg(target_os = "macos")]
const IOREG_MAX_OUTPUT: u64 = 1024 * 1024;

/// Text bez řídicích znaků, nejvýš `max` znaků.
fn text(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Najde v plistu (výstup `ioreg -a`) první slovník s daným klíčem.
fn find_dict<'a>(value: &'a plist::Value, key: &str) -> Option<&'a plist::Dictionary> {
    match value {
        plist::Value::Dictionary(dict) => {
            if dict.contains_key(key) {
                return Some(dict);
            }
            dict.values().find_map(|v| find_dict(v, key))
        }
        plist::Value::Array(items) => items.iter().find_map(|v| find_dict(v, key)),
        _ => None,
    }
}

fn int(dict: &plist::Dictionary, key: &str) -> Option<u64> {
    let value = dict.get(key)?;
    value.as_unsigned_integer().or_else(|| {
        value
            .as_signed_integer()
            .and_then(|i| u64::try_from(i).ok())
    })
}

fn flag(dict: &plist::Dictionary, key: &str) -> Option<bool> {
    dict.get(key).and_then(plist::Value::as_boolean)
}

/// Zaokrouhlené procento, nejvýš 100.
fn percent(part: u64, whole: u64) -> Option<u8> {
    if whole == 0 {
        return None;
    }
    let value = part.saturating_mul(100).saturating_add(whole / 2) / whole;
    u8::try_from(value.min(100)).ok()
}

/// Baterie z výstupu `ioreg -a -r -n AppleSmartBattery`. Kapacita proti nové
/// baterii: na Apple Silicon v mAh (`AppleRawMaxCapacity`, novější macOS
/// `NominalChargeCapacity`), na Intelu `MaxCapacity` v mAh.
pub fn parse_battery(value: &plist::Value) -> Option<BatteryReport> {
    let dict = find_dict(value, "CycleCount")?;
    if flag(dict, "BatteryInstalled") == Some(false) {
        return None;
    }
    let cycles = u32::try_from(int(dict, "CycleCount")?).ok()?;
    let design = int(dict, "DesignCapacity");
    let full = int(dict, "NominalChargeCapacity")
        .or_else(|| int(dict, "AppleRawMaxCapacity"))
        .or_else(|| int(dict, "MaxCapacity").filter(|m| *m > 100));
    let health_pct = match (full, design) {
        (Some(full), Some(design)) => percent(full, design),
        _ => None,
    };
    let charge_pct = match (int(dict, "CurrentCapacity"), int(dict, "MaxCapacity")) {
        // Apple Silicon: obě hodnoty v procentech.
        (Some(current), Some(100)) => u8::try_from(current.min(100)).ok(),
        (Some(current), Some(max)) => percent(current, max),
        _ => None,
    };
    let failure = int(dict, "PermanentFailureStatus").is_some_and(|f| f != 0);
    Some(BatteryReport {
        cycles,
        health_pct,
        service: failure || health_pct.is_some_and(|h| h < 80),
        charge_pct,
        charging: flag(dict, "IsCharging").unwrap_or(false),
        on_power: flag(dict, "ExternalConnected").unwrap_or(false),
    })
}

/// Čekající aktualizace z výstupu `softwareupdate --list`. `None`: výstup
/// nejde přečíst (jiný formát, chyba).
pub fn parse_software_updates(output: &str) -> Option<Vec<OsUpdate>> {
    let lower = output.to_ascii_lowercase();
    if lower.contains("no new software available") {
        return Some(Vec::new());
    }
    if !lower.contains("software update found") {
        return None;
    }
    let mut updates = Vec::new();
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("Title:") else {
            continue;
        };
        // Title: macOS Sequoia 15.1.1, Version: 15.1.1, Size: 2948813KiB, Recommended: YES, Action: restart,
        let mut parts = rest.split(", ").map(|p| p.trim().trim_end_matches(','));
        let title = text(parts.next().unwrap_or_default(), 200);
        if title.is_empty() {
            continue;
        }
        let mut update = OsUpdate {
            title,
            version: None,
            restart: false,
            recommended: false,
        };
        for part in parts {
            if let Some(value) = part.strip_prefix("Version:") {
                update.version = Some(text(value, 40)).filter(|v| !v.is_empty());
            } else if let Some(value) = part.strip_prefix("Recommended:") {
                update.recommended = value.trim().eq_ignore_ascii_case("yes");
            } else if let Some(value) = part.strip_prefix("Action:") {
                update.restart = value.trim().eq_ignore_ascii_case("restart");
            }
        }
        updates.push(update);
        if updates.len() == MAX_REPORT_OS_UPDATES {
            break;
        }
    }
    Some(updates)
}

/// Automatické aktualizace z `/Library/Preferences/com.apple.SoftwareUpdate.plist`:
/// hledání a instalace bezpečnostních oprav (chybějící klíč = výchozí „zapnuto“).
pub fn parse_auto_updates(value: &plist::Value) -> Option<bool> {
    let dict = value.as_dictionary()?;
    let on = |key| flag(dict, key).unwrap_or(true);
    Some(on("AutomaticCheckEnabled") && on("CriticalUpdateInstall"))
}

fn epoch_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Time Machine z `/Library/Preferences/com.apple.TimeMachine.plist`.
pub fn parse_time_machine(value: &plist::Value) -> BackupReport {
    let dict = value.as_dictionary();
    let destinations = dict
        .and_then(|d| d.get("Destinations"))
        .and_then(plist::Value::as_array);
    let last_ms = destinations
        .into_iter()
        .flatten()
        .filter_map(plist::Value::as_dictionary)
        .filter_map(|d| d.get("SnapshotDates").and_then(plist::Value::as_array))
        .flatten()
        .filter_map(plist::Value::as_date)
        .filter_map(|date| epoch_ms(date.into()))
        .max();
    BackupReport {
        configured: destinations.is_some_and(|d| !d.is_empty()),
        auto: dict.and_then(|d| flag(d, "AutoBackup")),
        last_ms,
    }
}

/// Stav ochrany z kontrol Bezpečnosti systému (`None`: nejde zjistit).
fn posture_state(checks: &[posture::PostureCheck], id: &str) -> Option<bool> {
    checks
        .iter()
        .find(|c| c.id == id)
        .and_then(|c| match c.state {
            PostureState::Ok => Some(true),
            PostureState::Warning => Some(false),
            PostureState::Unknown => None,
        })
}

#[cfg(target_os = "macos")]
fn sysctl(name: &str) -> Option<String> {
    posture::run("/usr/sbin/sysctl", &["-n", name])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.contains("unknown oid"))
}

#[cfg(target_os = "macos")]
fn ioreg(args: &[&str]) -> Option<plist::Value> {
    let out = posture::run_limited("/usr/sbin/ioreg", args, IOREG_MAX_OUTPUT)?;
    let end = out.rfind("</plist>")? + "</plist>".len();
    plist::Value::from_reader_xml(out[..end].as_bytes()).ok()
}

/// Hardware Macu: čip, jádra, paměť, sériové číslo, baterie.
#[cfg(target_os = "macos")]
pub fn hardware() -> Option<HardwareReport> {
    let number = |name: &str| sysctl(name).and_then(|v| v.parse::<u64>().ok());
    let chip = sysctl("machdep.cpu.brand_string")?;
    let performance = number("hw.perflevel0.physicalcpu").and_then(|n| u32::try_from(n).ok());
    let efficiency = number("hw.perflevel1.physicalcpu").and_then(|n| u32::try_from(n).ok());
    let serial = ioreg(&["-a", "-r", "-d", "1", "-c", "IOPlatformExpertDevice"]).and_then(|v| {
        find_dict(&v, "IOPlatformSerialNumber")?
            .get("IOPlatformSerialNumber")?
            .as_string()
            .map(|s| text(s, 40))
    });
    Some(HardwareReport {
        chip: text(&chip, 120),
        model_id: text(&sysctl("hw.model").unwrap_or_default(), 40),
        serial: serial.filter(|s| !s.is_empty()),
        cores: number("hw.ncpu")
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
        // Jen čipy s dvěma druhy jader (Apple Silicon).
        performance_cores: performance.filter(|_| efficiency.is_some()),
        efficiency_cores: efficiency,
        memory: number("hw.memsize").unwrap_or(0),
        battery: ioreg(&["-a", "-r", "-n", "AppleSmartBattery"]).and_then(|v| parse_battery(&v)),
    })
}

#[cfg(not(target_os = "macos"))]
pub fn hardware() -> Option<HardwareReport> {
    use sysinfo::{CpuRefreshKind, RefreshKind, System};
    let system = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing())
            .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram()),
    );
    let chip = system.cpus().first().map(|c| text(c.brand(), 120))?;
    Some(HardwareReport {
        chip,
        model_id: String::new(),
        serial: None,
        cores: u32::try_from(system.cpus().len()).unwrap_or(0),
        performance_cores: None,
        efficiency_cores: None,
        memory: system.total_memory(),
        battery: None,
    })
}

/// Zabezpečení systému: ochrany macOS, aktualizace, záloha, přístup AntiShieldu.
#[cfg(target_os = "macos")]
pub fn security(full_disk_access: Option<bool>) -> SecurityReport {
    let checks = posture::checks();
    let stealth = posture::run(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getstealthmode"],
    )
    .map(|out| {
        posture::classify(
            Some(out.as_str()),
            &["mode enabled", "mode is on"],
            &["mode disabled", "mode is off"],
        )
    })
    .and_then(|state| match state {
        PostureState::Ok => Some(true),
        PostureState::Warning => Some(false),
        PostureState::Unknown => None,
    });
    let auto_updates =
        plist::Value::from_file("/Library/Preferences/com.apple.SoftwareUpdate.plist")
            .ok()
            .and_then(|v| parse_auto_updates(&v));
    // Bez hledání na serveru: macOS ho dělá sám, tady se jen čte výsledek.
    let os_updates = posture::run("/usr/sbin/softwareupdate", &["--list", "--no-scan"])
        .and_then(|out| parse_software_updates(&out));
    let backup = plist::Value::from_file("/Library/Preferences/com.apple.TimeMachine.plist")
        .ok()
        .map(|v| parse_time_machine(&v));
    SecurityReport {
        filevault: posture_state(&checks, "filevault"),
        firewall: posture_state(&checks, "firewall"),
        stealth,
        sip: posture_state(&checks, "sip"),
        gatekeeper: posture_state(&checks, "gatekeeper"),
        xprotect: posture::xprotect_version().map(|v| text(&v, 40)),
        auto_updates,
        os_updates,
        backup,
        full_disk_access,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn security(full_disk_access: Option<bool>) -> SecurityReport {
    let checks = posture::checks();
    SecurityReport {
        firewall: posture_state(&checks, "firewall"),
        full_disk_access,
        ..SecurityReport::default()
    }
}

/// Podíl procesoru v promile (12,3 % → 123).
fn permille(percent: f32) -> u32 {
    if percent.is_finite() && percent > 0.0 {
        // Hodnota je v mezích 0–100 000, převod je bezpečný.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let value = (percent * 10.0).round().min(100_000.0) as u32;
        value
    } else {
        0
    }
}

/// Vytížení z měření Zrychlení: aplikace podle paměti a položky po přihlášení
/// (jen názvy programů, ne cesty).
pub fn performance(report: &SpeedReport) -> PerformanceReport {
    PerformanceReport {
        measured_at_ms: report.measured_at_ms,
        cpu_permille: permille(report.cpu),
        cores: u32::try_from(report.cores).unwrap_or(u32::MAX),
        swap_used: report.memory.swap_used,
        apps: report
            .apps
            .iter()
            .take(MAX_REPORT_APPS)
            .map(|app| AppUsage {
                name: text(&app.name, 120),
                bundle_id: app.bundle_id.clone().filter(|id| id.len() <= 200),
                cpu_permille: permille(app.cpu),
                memory: app.memory,
                processes: app.processes,
            })
            .collect(),
        login_items: report
            .startup
            .iter()
            .take(MAX_REPORT_LOGIN_ITEMS)
            .map(|entry| LoginItemReport {
                label: text(&entry.label, 200),
                program: entry
                    .program
                    .as_deref()
                    .and_then(|p| Path::new(p).file_name())
                    .map(|n| text(&n.to_string_lossy(), 200)),
                enabled: entry.enabled,
                system: entry.system,
                running: entry.pid.is_some(),
            })
            .collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn xml(text: &str) -> plist::Value {
        plist::Value::from_reader_xml(text.as_bytes()).unwrap()
    }

    #[test]
    fn battery_health_reads_apple_silicon_and_intel() {
        // Apple Silicon: MaxCapacity a CurrentCapacity v procentech, kapacita v mAh zvlášť.
        let silicon = xml(r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array><dict>
  <key>BatteryInstalled</key><true/>
  <key>CycleCount</key><integer>142</integer>
  <key>DesignCapacity</key><integer>4382</integer>
  <key>AppleRawMaxCapacity</key><integer>4120</integer>
  <key>NominalChargeCapacity</key><integer>4205</integer>
  <key>MaxCapacity</key><integer>100</integer>
  <key>CurrentCapacity</key><integer>76</integer>
  <key>IsCharging</key><false/>
  <key>ExternalConnected</key><true/>
  <key>PermanentFailureStatus</key><integer>0</integer>
</dict></array></plist>"#);
        let battery = parse_battery(&silicon).unwrap();
        assert_eq!(battery.cycles, 142);
        assert_eq!(battery.health_pct, Some(96));
        assert_eq!(battery.charge_pct, Some(76));
        assert!(!battery.service && !battery.charging && battery.on_power);

        // Intel: kapacity v mAh, opotřebovaná baterie potřebuje servis.
        let intel = xml(r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>IORegistryEntryChildren</key><array><dict>
  <key>CycleCount</key><integer>1021</integer>
  <key>DesignCapacity</key><integer>6669</integer>
  <key>MaxCapacity</key><integer>4900</integer>
  <key>CurrentCapacity</key><integer>2450</integer>
  <key>IsCharging</key><true/>
  <key>ExternalConnected</key><true/>
</dict></array></dict></plist>"#);
        let battery = parse_battery(&intel).unwrap();
        assert_eq!(battery.health_pct, Some(73));
        assert_eq!(battery.charge_pct, Some(50));
        assert!(battery.service && battery.charging);

        // Stolní Mac bez baterie, porucha baterie.
        let none = xml(r#"<?xml version="1.0"?><plist version="1.0"><array/></plist>"#);
        assert!(parse_battery(&none).is_none());
        let failed = xml(r#"<?xml version="1.0"?><plist version="1.0"><dict>
  <key>CycleCount</key><integer>3</integer><key>PermanentFailureStatus</key><integer>2</integer>
</dict></plist>"#);
        let battery = parse_battery(&failed).unwrap();
        assert!(battery.service);
        assert_eq!(battery.health_pct, None);
    }

    #[test]
    fn software_updates_are_listed_or_reported_unknown() {
        let pending = "Software Update Tool\n\nFinding available software\n\
Software Update found the following new or updated software:\n\
* Label: macOS Sequoia 15.1.1-24B91\n\
\tTitle: macOS Sequoia 15.1.1, Version: 15.1.1, Size: 2948813KiB, Recommended: YES, Action: restart,\n\
* Label: Safari18.2SequoiaAuto-18.2\n\
\tTitle: Safari, Version: 18.2, Size: 197890KiB, Recommended: YES, \n";
        let updates = parse_software_updates(pending).unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].title, "macOS Sequoia 15.1.1");
        assert_eq!(updates[0].version.as_deref(), Some("15.1.1"));
        assert!(updates[0].restart && updates[0].recommended);
        assert_eq!(updates[1].title, "Safari");
        assert!(!updates[1].restart);
        assert_eq!(
            parse_software_updates("Software Update Tool\n\nNo new software available.\n"),
            Some(vec![])
        );
        assert_eq!(parse_software_updates("Error: cannot reach server"), None);
    }

    #[test]
    fn automatic_updates_and_time_machine_settings_are_read() {
        let on = xml(r#"<?xml version="1.0"?><plist version="1.0"><dict>
  <key>AutomaticCheckEnabled</key><true/></dict></plist>"#);
        assert_eq!(parse_auto_updates(&on), Some(true));
        let off = xml(r#"<?xml version="1.0"?><plist version="1.0"><dict>
  <key>AutomaticCheckEnabled</key><true/><key>CriticalUpdateInstall</key><false/></dict></plist>"#);
        assert_eq!(parse_auto_updates(&off), Some(false));

        let tm = xml(r#"<?xml version="1.0"?><plist version="1.0"><dict>
  <key>AutoBackup</key><true/>
  <key>Destinations</key><array><dict>
    <key>SnapshotDates</key><array>
      <date>2026-10-10T08:00:00Z</date><date>2026-10-12T16:30:00Z</date>
    </array>
  </dict></array>
</dict></plist>"#);
        let backup = parse_time_machine(&tm);
        assert!(backup.configured);
        assert_eq!(backup.auto, Some(true));
        assert_eq!(backup.last_ms, Some(1_791_822_600_000));
        let empty = parse_time_machine(&xml(
            r#"<?xml version="1.0"?><plist version="1.0"><dict/></plist>"#,
        ));
        assert!(!empty.configured);
        assert_eq!(empty.last_ms, None);
    }

    #[test]
    fn performance_keeps_names_without_paths() {
        use crate::speed::{HeavyProcess, MemoryInfo, StartupEntry};
        let report = SpeedReport {
            disk: None,
            memory: MemoryInfo {
                total: 16,
                used: 8,
                swap_used: 2,
                pressure: None,
            },
            cpu: 12.34,
            cores: 8,
            uptime_secs: 60,
            heavy: vec![],
            startup: vec![StartupEntry {
                id: "1".into(),
                label: "com.example.agent".into(),
                plist: "/Users/jana/Library/LaunchAgents/com.example.agent.plist".into(),
                program: Some("/Users/jana/Applications/Example.app/Contents/MacOS/agent".into()),
                system: false,
                enabled: true,
                pid: Some(42),
                cpu: 0.0,
                memory: 0,
            }],
            measured_at_ms: 5,
            apps: vec![HeavyProcess {
                pid: 7,
                name: "Google Chrome".into(),
                path: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
                cpu: 3.25,
                memory: 2_000_000_000,
                processes: 14,
                bundle_id: Some("com.google.Chrome".into()),
                app_path: Some("/Applications/Google Chrome.app".into()),
            }],
        };
        let perf = performance(&report);
        assert_eq!(perf.cpu_permille, 123);
        assert_eq!(perf.apps[0].cpu_permille, 33);
        assert_eq!(perf.apps[0].bundle_id.as_deref(), Some("com.google.Chrome"));
        assert_eq!(perf.login_items[0].program.as_deref(), Some("agent"));
        assert!(perf.login_items[0].running);
        let json = serde_json::to_string(&perf).unwrap();
        assert!(!json.contains("/Users/jana"), "no paths leave the Mac");
        assert_eq!(permille(f32::NAN), 0);
        assert_eq!(permille(-1.0), 0);
    }
}
