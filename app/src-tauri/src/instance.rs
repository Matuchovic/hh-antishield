//! Jediná běžící instance AntiShieldu (macOS).
//!
//! Agent z launchd a ruční spuštění (nebo obnovení aplikací po přihlášení)
//! můžou naběhnout skoro zároveň a plugin single-instance je v tu chvíli
//! nemusí rozlišit. Pak by běžely dvě ochrany a dva zápisy do auditního logu.
//! Zámek v datech aplikace proto drží vždy jen jedna instance:
//! - agent na uvolnění počká (kdyby skončil, launchd by ho spouštěl dokola
//!   a ochrana proti smyčce pádů by ho zastavila),
//! - ruční spuštění chvíli počká (restart po aktualizaci nebo po povolení
//!   přístupu), pak okno přenechá běžící instanci.

// Mimo macOS se nevolá (tam stačí plugin single-instance); testy běží všude.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const LOCK_FILE: &str = "instance.lock";
/// Ruční spuštění počká, než doběhne předchozí instance (restart).
const HANDOVER_WAIT: Duration = Duration::from_secs(3);

/// Zámek drží proces po celou dobu běhu.
static HELD: OnceLock<File> = OnceLock::new();

#[derive(Debug)]
enum Lock {
    Held(File),
    /// Zámek drží jiná instance.
    Busy,
    /// Zámek nejde vytvořit ani použít (souborový systém bez zámků).
    Unavailable,
}

/// Zamkne `path`. Na pozadí čeká bez omezení, jinak nejvýš `wait`.
fn acquire(path: &Path, background: bool, wait: Duration) -> Lock {
    let Ok(file) = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
    else {
        return Lock::Unavailable;
    };
    if background {
        return match file.lock() {
            Ok(()) => Lock::Held(file),
            Err(_) => Lock::Unavailable,
        };
    }
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Lock::Held(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(TryLockError::WouldBlock) => return Lock::Busy,
            Err(TryLockError::Error(_)) => return Lock::Unavailable,
        }
    }
}

/// `true`: tato instance je jediná a pokračuje. `false`: běží jiná instance
/// (jen u ručního spuštění; agent počká, až skončí). Když zámek nejde
/// použít, pokračuje jako dřív (hlídá jen plugin single-instance).
pub fn claim(data_dir: &Path, background: bool) -> bool {
    let _ = std::fs::create_dir_all(data_dir);
    match acquire(&data_dir.join(LOCK_FILE), background, HANDOVER_WAIT) {
        Lock::Held(file) => {
            let _ = HELD.set(file);
            true
        }
        Lock::Busy => false,
        Lock::Unavailable => true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_manual_start_yields_to_the_running_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LOCK_FILE);
        let running = acquire(&path, false, Duration::ZERO);
        assert!(matches!(running, Lock::Held(_)));
        assert!(matches!(
            acquire(&path, false, Duration::from_millis(200)),
            Lock::Busy
        ));
        drop(running);
        assert!(matches!(
            acquire(&path, false, Duration::ZERO),
            Lock::Held(_)
        ));
    }

    #[test]
    fn the_agent_waits_until_the_running_instance_ends() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LOCK_FILE);
        let running = acquire(&path, false, Duration::ZERO);
        assert!(matches!(running, Lock::Held(_)));
        let waiting_path = path.clone();
        let agent = std::thread::spawn(move || acquire(&waiting_path, true, Duration::ZERO));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!agent.is_finished(), "the agent must wait, not exit");
        drop(running);
        assert!(matches!(agent.join().unwrap(), Lock::Held(_)));
    }

    #[test]
    fn without_a_usable_lock_the_app_starts_as_before() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing-dir").join(LOCK_FILE);
        assert!(matches!(
            acquire(&missing, false, Duration::ZERO),
            Lock::Unavailable
        ));
    }
}
