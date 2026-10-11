//! Hlídání složek: nové a změněné soubory předá ke kontrole, jakmile se
//! přestanou měnit. Detekuje do několika sekund od zápisu; spuštění programu
//! samo o sobě neblokuje (to vyžaduje Endpoint Security / ovladač).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::error::EngineError;

/// Soubor se kontroluje, až se tak dlouho nezměnil (dopisování stahování).
pub const QUIET_PERIOD: Duration = Duration::from_millis(1500);
const TICK: Duration = Duration::from_millis(250);
const MAX_PENDING: usize = 10_000;

/// Přípony rozpracovaných stažení; zkontroluje se až hotový soubor.
const PARTIAL_EXTENSIONS: [&str; 5] = ["crdownload", "part", "partial", "download", "tmp"];

fn is_partial(path: &Path) -> bool {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|e| PARTIAL_EXTENSIONS.contains(&e.as_str()))
}

fn is_hidden_system_file(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy())
        .is_some_and(|n| n == ".DS_Store" || n.starts_with("._") || n.starts_with(".antishield-"))
}

/// Kdy se soubor naposledy změnil nebo přibyl (ms od epochy): nejnovější
/// z času úpravy, vytvoření a (na Unixu) změny záznamu. Přesunutý nebo
/// zkopírovaný soubor si nese starý čas úpravy, ale nový čas změny/vytvoření.
fn changed_at_ms(meta: &std::fs::Metadata) -> u64 {
    let to_ms = |time: std::time::SystemTime| {
        time.duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    };
    let mut latest = meta.modified().map(to_ms).unwrap_or(0);
    if let Ok(created) = meta.created() {
        latest = latest.max(to_ms(created));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(secs) = u64::try_from(meta.ctime()) {
            let nanos = u64::try_from(meta.ctime_nsec()).unwrap_or(0);
            latest = latest.max(secs.saturating_mul(1000) + nanos / 1_000_000);
        }
    }
    latest
}

/// Výsledek dohledání souborů změněných, když ochrana neběžela.
#[derive(Debug, Default)]
pub struct ChangedFiles {
    pub files: Vec<PathBuf>,
    /// `false`, když se procházení zastavilo na limitu.
    pub complete: bool,
}

/// Soubory v hlídaných složkách, které se změnily nebo přibyly od `since_ms`.
/// Po spuštění tak ochrana dožene, co se stalo, když neběžela. Symlinky se
/// nesledují; rozpracovaná stažení, systémové soubory a vyloučené složky se
/// přeskočí. `max_files` omezuje výsledek, `max_visited` délku procházení.
pub fn changed_since(
    folders: &[PathBuf],
    excluded: &[PathBuf],
    since_ms: u64,
    max_files: usize,
    max_visited: usize,
) -> ChangedFiles {
    let mut result = ChangedFiles {
        files: Vec::new(),
        complete: true,
    };
    let mut visited = 0usize;
    for folder in folders {
        let walk = walkdir::WalkDir::new(folder)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| !excluded.iter().any(|dir| entry.path().starts_with(dir)));
        for entry in walk.flatten() {
            visited += 1;
            if visited > max_visited || result.files.len() >= max_files {
                result.complete = false;
                return result;
            }
            let path = entry.path();
            if !entry.file_type().is_file() || is_partial(path) || is_hidden_system_file(path) {
                continue;
            }
            if entry
                .metadata()
                .is_ok_and(|meta| changed_at_ms(&meta) >= since_ms)
            {
                result.files.push(path.to_path_buf());
            }
        }
    }
    result
}

/// Běžící hlídání; zastaví se zahozením.
pub struct FolderWatcher {
    _watcher: RecommendedWatcher,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    watched: Vec<PathBuf>,
}

impl std::fmt::Debug for FolderWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderWatcher")
            .field("watched", &self.watched)
            .finish()
    }
}

impl FolderWatcher {
    /// Začne hlídat existující složky. `excluded` (data enginu, karanténa) se ignorují.
    /// `on_ready` dostává dávky souborů, které jsou připravené ke kontrole.
    pub fn start(
        folders: &[PathBuf],
        excluded: Vec<PathBuf>,
        on_ready: impl Fn(Vec<PathBuf>) + Send + 'static,
    ) -> Result<Self, EngineError> {
        let (tx, rx) = mpsc::channel::<PathBuf>();
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                let Ok(event) = result else {
                    return;
                };
                let relevant = matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any
                );
                if relevant {
                    for path in event.paths {
                        let _ = tx.send(path);
                    }
                }
            })
            .map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;

        let mut watched = Vec::new();
        for folder in folders {
            if folder.is_dir() && watcher.watch(folder, RecursiveMode::Recursive).is_ok() {
                watched.push(folder.clone());
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let thread = std::thread::Builder::new()
            .name("antishield-watch".into())
            .spawn(move || {
                let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
                while !stop_thread.load(Ordering::SeqCst) {
                    match rx.recv_timeout(TICK) {
                        Ok(path) => {
                            if excluded.iter().any(|dir| path.starts_with(dir))
                                || is_partial(&path)
                                || is_hidden_system_file(&path)
                            {
                                continue;
                            }
                            if pending.len() < MAX_PENDING || pending.contains_key(&path) {
                                pending.insert(path, Instant::now());
                            }
                            continue;
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    let ready: Vec<PathBuf> = pending
                        .iter()
                        .filter(|(_, last)| last.elapsed() >= QUIET_PERIOD)
                        .map(|(path, _)| path.clone())
                        .collect();
                    if ready.is_empty() {
                        continue;
                    }
                    for path in &ready {
                        pending.remove(path);
                    }
                    let files: Vec<PathBuf> = ready
                        .into_iter()
                        .filter(|path| {
                            std::fs::symlink_metadata(path)
                                .map(|m| m.is_file())
                                .unwrap_or(false)
                        })
                        .collect();
                    if !files.is_empty() {
                        on_ready(files);
                    }
                }
            })
            .map_err(EngineError::Io)?;

        Ok(Self {
            _watcher: watcher,
            stop,
            thread: Some(thread),
            watched,
        })
    }

    /// Složky, které se opravdu hlídají (existují a systém je dovolil sledovat).
    pub fn watched(&self) -> &[PathBuf] {
        &self.watched
    }
}

impl Drop for FolderWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn files_changed_while_not_watching_are_found() {
        let tmp = tempfile::tempdir().unwrap();
        let watched = tmp.path().join("watched");
        let excluded = watched.join("excluded");
        let nested = watched.join("a").join("b");
        std::fs::create_dir_all(&excluded).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(watched.join("new.exe"), b"x").unwrap();
        std::fs::write(nested.join("deep.zip"), b"x").unwrap();
        std::fs::write(watched.join("film.mp4.part"), b"x").unwrap();
        std::fs::write(watched.join(".DS_Store"), b"x").unwrap();
        std::fs::write(excluded.join("skip.exe"), b"x").unwrap();
        let folders = vec![watched.clone()];
        let excluded = vec![excluded];
        let hour_ago = crate::now_ms() - 3_600_000;

        let mut found = changed_since(&folders, &excluded, hour_ago, 100, 10_000);
        found.files.sort();
        assert!(found.complete);
        assert_eq!(
            found.files,
            vec![nested.join("deep.zip"), watched.join("new.exe")]
        );

        // Nic se nezměnilo od „budoucnosti“.
        let later = crate::now_ms() + 3_600_000;
        assert!(
            changed_since(&folders, &excluded, later, 100, 10_000)
                .files
                .is_empty()
        );

        // Limit výsledku se přizná.
        let capped = changed_since(&folders, &excluded, hour_ago, 1, 10_000);
        assert_eq!(capped.files.len(), 1);
        assert!(!capped.complete);
    }

    #[test]
    fn new_files_are_reported_after_they_settle() {
        let tmp = tempfile::tempdir().unwrap();
        let watched = tmp.path().join("watched");
        let excluded = watched.join("excluded");
        std::fs::create_dir_all(&excluded).unwrap();
        let seen: Arc<Mutex<Vec<PathBuf>>> = Arc::default();
        let sink = seen.clone();
        let watcher = FolderWatcher::start(
            &[watched.clone(), tmp.path().join("missing")],
            vec![excluded.clone()],
            move |files| {
                sink.lock().unwrap().extend(files);
            },
        )
        .unwrap();
        assert_eq!(watcher.watched(), std::slice::from_ref(&watched));

        std::fs::write(watched.join("new.bin"), b"hello").unwrap();
        std::fs::write(watched.join("file.crdownload"), b"partial").unwrap();
        std::fs::write(excluded.join("ignored.bin"), b"x").unwrap();
        std::fs::write(watched.join(".DS_Store"), b"x").unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && seen.lock().unwrap().is_empty() {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(QUIET_PERIOD);
        let seen = seen.lock().unwrap().clone();
        assert!(seen.iter().any(|p| p.ends_with("new.bin")), "{seen:?}");
        assert!(!seen.iter().any(|p| p.ends_with("file.crdownload")));
        assert!(!seen.iter().any(|p| p.starts_with(&excluded)));
        assert!(!seen.iter().any(|p| p.ends_with(".DS_Store")));
    }
}
