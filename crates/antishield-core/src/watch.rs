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
