//! Ochrana na pozadí na macOS. LaunchAgent spustí AntiShield po přihlášení
//! (skrytý v liště) a znovu ho spustí, kdykoli skončí (KeepAlive), takže
//! zavření ani ukončení aplikace ochranu nevypne. Úplné vypnutí z lišty agenta
//! na tuto relaci odhlásí (`launchctl bootout`); znovu naběhne po příštím
//! přihlášení nebo po spuštění a ukončení aplikace. Opakované pády hned po
//! startu agenta zastaví, aby macOS neukazoval hlášení o pádu pořád dokola.

// Mimo macOS se z modulu používá jen `BACKGROUND_ARG` (a testy).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::path::{Path, PathBuf};

/// Označení služby v launchd.
pub const LABEL: &str = "cz.hh.antishield.agent";
/// Argument, se kterým se aplikace spouští skrytá v liště (agent, přihlášení).
pub const BACKGROUND_ARG: &str = "--background";
/// Nejkratší odstup opakovaného spuštění v launchd (sekundy).
const THROTTLE_SECS: i64 = 10;
/// Tolik startů agenta během okna znamená, že hned po spuštění padá.
const CRASH_LOOP_STARTS: usize = 5;
const CRASH_LOOP_WINDOW_MS: u64 = 5 * 60 * 1000;

/// Důvod, proč ochrana na pozadí neběží (anglicky, rozhraní ho přeloží).
pub const NOT_INSTALLED: &str = "app is not installed in Applications";
pub const NOT_BUNDLED: &str = "not running from an app bundle";
pub const CRASH_LOOP: &str = "background protection stopped after repeated crashes";

/// Obsah plistu LaunchAgentu pro danou aplikaci.
pub fn plist_xml(exe: &Path) -> Result<Vec<u8>, String> {
    let mut dict = plist::Dictionary::new();
    dict.insert("Label".into(), LABEL.into());
    dict.insert(
        "ProgramArguments".into(),
        plist::Value::Array(vec![
            exe.to_string_lossy().into_owned().into(),
            BACKGROUND_ARG.into(),
        ]),
    );
    dict.insert("RunAtLoad".into(), true.into());
    dict.insert("KeepAlive".into(), true.into());
    dict.insert("ThrottleInterval".into(), THROTTLE_SECS.into());
    dict.insert("LimitLoadToSessionType".into(), "Aqua".into());
    let mut out = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_xml(&mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Agent smí spouštět jen nainstalovanou aplikaci: ne kopii z DMG ani
/// z dočasného umístění, kam macOS přesouvá nepřesunuté stažené aplikace.
pub fn installed_exe(exe: &Path) -> Result<PathBuf, &'static str> {
    let text = exe.to_string_lossy();
    if text.contains("/AppTranslocation/") || text.starts_with("/Volumes/") {
        return Err(NOT_INSTALLED);
    }
    if !text.contains(".app/Contents/MacOS/") {
        return Err(NOT_BUNDLED);
    }
    Ok(exe.to_path_buf())
}

/// Zaznamená start agenta. `true` znamená, že v posledních minutách startoval
/// tak často, že zřejmě hned padá, a má se na tuto relaci zastavit.
pub fn register_start(starts: &mut Vec<u64>, now: u64) -> bool {
    starts.retain(|&t| t <= now && now - t < CRASH_LOOP_WINDOW_MS);
    starts.push(now);
    starts.len() >= CRASH_LOOP_STARTS
}

#[cfg(target_os = "macos")]
pub mod launchd {
    use super::*;
    use std::process::{Command, Stdio};

    fn home() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }

    /// Data aplikace (stejná složka, jakou používá Tauri pro `cz.hh.antishield`).
    pub fn data_dir() -> Option<PathBuf> {
        Some(home()?.join("Library/Application Support/cz.hh.antishield"))
    }

    fn plist_path() -> Option<PathBuf> {
        Some(
            home()?
                .join("Library/LaunchAgents")
                .join(format!("{LABEL}.plist")),
        )
    }

    fn uid() -> Option<String> {
        let out = Command::new("/usr/bin/id").arg("-u").output().ok()?;
        let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !uid.is_empty()).then_some(uid)
    }

    fn launchctl(args: &[&str]) -> bool {
        Command::new("/bin/launchctl")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn service() -> Option<String> {
        Some(format!("gui/{}/{LABEL}", uid()?))
    }

    /// Zapne nebo vypne agenta (zapíše nebo smaže plist). `is_agent`: volá
    /// sám agent, který se nesmí odhlásit (launchd by ho ukončil).
    pub fn sync(enabled: bool, is_agent: bool) -> Result<(), String> {
        let path = plist_path().ok_or("no home directory")?;
        if !enabled {
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| e.to_string())?;
            }
            if !is_agent {
                stop_for_session();
            }
            return Ok(());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let xml = plist_xml(&installed_exe(&exe).map_err(str::to_string)?)?;
        if std::fs::read(&path).ok().as_deref() == Some(xml.as_slice()) {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("plist.tmp");
        std::fs::write(&tmp, &xml).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        // Načtená stará definice (jiná cesta) se vymění při ukončení aplikace.
        if !is_agent {
            stop_for_session();
        }
        Ok(())
    }

    /// Postará se, aby agent běžel: načte ho, nebo spustí už načteného.
    pub fn ensure_running() {
        let (Some(service), Some(uid), Some(path)) = (service(), uid(), plist_path()) else {
            return;
        };
        if !path.exists() {
            return;
        }
        if launchctl(&["print", &service]) {
            launchctl(&["kickstart", &service]);
        } else {
            launchctl(&["bootstrap", &format!("gui/{uid}"), &path.to_string_lossy()]);
        }
    }

    /// Zastaví agenta do příštího přihlášení nebo spuštění aplikace. Když to
    /// volá sám agent, launchd ho tím ukončí.
    pub fn stop_for_session() {
        if let Some(service) = service() {
            launchctl(&["bootout", &service]);
        }
    }

    /// Kontrola při startu agenta: `Some(důvod)`, když se má hned zastavit.
    pub fn startup_check(data_dir: &Path, enabled: bool) -> Option<&'static str> {
        if !enabled {
            return Some("disabled");
        }
        let file = data_dir.join("agent-starts.json");
        let mut starts: Vec<u64> = std::fs::read(&file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let looping = register_start(&mut starts, antishield_core::now_ms());
        let _ = std::fs::create_dir_all(data_dir);
        if looping {
            let _ = std::fs::remove_file(&file);
            let _ = std::fs::write(data_dir.join("agent-paused"), CRASH_LOOP);
            return Some(CRASH_LOOP);
        }
        if let Ok(bytes) = serde_json::to_vec(&starts) {
            let _ = std::fs::write(&file, bytes);
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn launch_agent_restarts_the_installed_app_in_background() {
        let exe = Path::new("/Applications/H&H AntiShield.app/Contents/MacOS/antishield-app");
        let xml = plist_xml(exe).unwrap();
        let value = plist::Value::from_reader_xml(xml.as_slice()).unwrap();
        let dict = value.as_dictionary().unwrap();
        assert_eq!(dict["Label"].as_string(), Some(LABEL));
        let args: Vec<_> = dict["ProgramArguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_string().unwrap())
            .collect();
        assert_eq!(args, vec![exe.to_str().unwrap(), BACKGROUND_ARG]);
        assert_eq!(dict["KeepAlive"].as_boolean(), Some(true));
        assert_eq!(dict["RunAtLoad"].as_boolean(), Some(true));
    }

    #[test]
    fn only_an_installed_app_can_be_the_agent() {
        let ok = Path::new("/Applications/H&H AntiShield.app/Contents/MacOS/antishield-app");
        assert!(installed_exe(ok).is_ok());
        let dmg =
            Path::new("/Volumes/H&H AntiShield/H&H AntiShield.app/Contents/MacOS/antishield-app");
        assert_eq!(installed_exe(dmg), Err(NOT_INSTALLED));
        let moved = Path::new(
            "/private/var/folders/x/AppTranslocation/1/d/H&H AntiShield.app/Contents/MacOS/antishield-app",
        );
        assert_eq!(installed_exe(moved), Err(NOT_INSTALLED));
        assert_eq!(
            installed_exe(Path::new("/tmp/antishield-app")),
            Err(NOT_BUNDLED)
        );
    }

    #[test]
    fn repeated_quick_starts_stop_the_agent() {
        let mut starts = Vec::new();
        let t0 = 10_000_000;
        for i in 0..4 {
            assert!(!register_start(&mut starts, t0 + i * 11_000));
        }
        assert!(register_start(&mut starts, t0 + 50_000));
        // Starty rozložené v čase (běžné ukončení a obnovení) nevadí.
        let mut spread = Vec::new();
        for i in 0..10 {
            assert!(!register_start(&mut spread, t0 + i * 120_000));
        }
    }
}
