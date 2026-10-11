//! Čištění: co v domovské složce zbytečně zabírá místo.
//!
//! Bezpečnost:
//! - Mimo domovskou složku nic nehledá a nemaže; systém, fotky, pošta ani
//!   iCloud se neprocházejí.
//! - Smazat se dá jen položka z vlastního skenu (rozhraní posílá identifikátor,
//!   ne cestu) a před zásahem se znovu ověří umístění, typ a že cesta nevede
//!   přes symbolický odkaz.
//! - Přímo se mažou jen věci, které si aplikace samy znovu vytvoří
//!   (mezipaměti, protokoly, vývojářské mezipaměti). Soubory uživatele
//!   (instalátory, velké soubory, zbytky aplikací) jdou do Koše, odkud je jde
//!   vrátit. Vysypání Koše je samostatná, nevratná volba.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Nejvýš tolik položek se při počítání velikosti jedné složky projde.
const MAX_ENTRIES_PER_ITEM: u64 = 400_000;
/// Celkový časový limit skenu.
const SCAN_BUDGET: Duration = Duration::from_secs(90);
const DAY_MS: u64 = 86_400_000;
/// Protokoly a hlášení o pádech starší než tohle jsou k úklidu.
const OLD_LOG_MS: u64 = 7 * DAY_MS;
/// Instalátory ve Stažených starší než tohle (aplikace už je nainstalovaná).
const OLD_INSTALLER_MS: u64 = 14 * DAY_MS;
/// Velký soubor: aspoň 1 GB a půl roku beze změny.
const LARGE_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const STALE_FILE_MS: u64 = 180 * DAY_MS;
/// Kolik velkých souborů nejvýš ukázat.
const MAX_LARGE_FILES: usize = 40;
/// Mezipaměť změněná v posledních minutách se právě používá: nabídne se,
/// ale nepředvybere. Dočasné soubory Windows se nepředvyberou ani den.
const IN_USE_MS: u64 = 15 * 60 * 1000;
const TEMP_IN_USE_MS: u64 = DAY_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CleanCategory {
    AppCaches,
    Logs,
    Developer,
    Installers,
    Leftovers,
    LargeFiles,
    Trash,
}

/// Jak se položka uklidí.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CleanMethod {
    /// Smazat: aplikace si obsah vytvoří znovu.
    Delete,
    /// Přesunout do Koše: jde vrátit.
    MoveToTrash,
    /// Vysypat Koš: nevratné.
    EmptyTrash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanItem {
    pub id: String,
    pub category: CleanCategory,
    pub path: String,
    pub name: String,
    /// Místo na disku (přidělené bloky, ne zdánlivá velikost).
    pub bytes: u64,
    pub files: u64,
    pub modified_ms: Option<u64>,
    /// Předvybrané: bezpečné a obvykle zbytečné.
    pub recommended: bool,
    pub method: CleanMethod,
    /// Proč není předvybrané nebo co se stane (anglicky, rozhraní překládá).
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanScan {
    pub items: Vec<CleanItem>,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    /// `false`: sken narazil na limit nebo ho uživatel zrušil.
    pub complete: bool,
    /// Složky, které nešlo přečíst (např. Koš bez plného přístupu k disku).
    pub unreadable: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanOutcome {
    pub freed_bytes: u64,
    /// Kolik bajtů jde do Koše (uvolní se až po vysypání).
    pub trashed_bytes: u64,
    pub cleaned: Vec<String>,
    pub failed: Vec<CleanFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanFailure {
    pub id: String,
    pub reason: String,
}

/// Okolnosti skenu, které zjišťuje aplikace.
#[derive(Debug, Clone, Default)]
pub struct CleanContext {
    pub home: PathBuf,
    /// Identifikátory běžících aplikací (jejich mezipaměti se nemažou).
    pub running_bundles: HashSet<String>,
    /// Identifikátory nainstalovaných aplikací (pro zbytky po odinstalaci).
    pub installed_bundles: HashSet<String>,
    pub now_ms: u64,
}

fn epoch_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

fn item_id(path: &Path) -> String {
    hex::encode(&Sha256::digest(path.to_string_lossy().as_bytes())[..8])
}

#[cfg(unix)]
fn allocated(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}

/// Velikost, počet souborů a poslední změna souboru (bez odkazů).
fn measure(path: &Path, deadline: Instant) -> (u64, u64, Option<u64>, bool) {
    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut newest: Option<u64> = None;
    let mut complete = true;
    let mut seen = 0u64;
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        seen += 1;
        if seen > MAX_ENTRIES_PER_ITEM || Instant::now() > deadline {
            complete = false;
            break;
        }
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_file() {
            files += 1;
            bytes = bytes.saturating_add(allocated(&meta));
            if let Some(ms) = meta.modified().ok().and_then(epoch_ms) {
                newest = Some(newest.map_or(ms, |n| n.max(ms)));
            }
        }
    }
    (bytes, files, newest, complete)
}

/// Mezipaměti Applu a služeb, které si drží stav, nemažeme.
fn protected_cache(name: &str) -> bool {
    name.starts_with("com.apple.")
        || matches!(
            name,
            "CloudKit" | "FamilyCircle" | "GeoServices" | "cz.hh.antishield" | "Metadata"
        )
}

/// Vypadá jako identifikátor aplikace (cz.hh.antishield, com.google.Chrome)?
fn looks_like_bundle_id(name: &str) -> bool {
    name.split('.').filter(|p| !p.is_empty()).count() >= 3
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Patří identifikátor nainstalované aplikaci (i jejím pomocníkům)?
fn belongs_to_installed(id: &str, ctx: &CleanContext) -> bool {
    let id = id.to_ascii_lowercase();
    ctx.installed_bundles
        .iter()
        .chain(&ctx.running_bundles)
        .any(|b| {
            let b = b.to_ascii_lowercase();
            id == b || id.starts_with(&format!("{b}.")) || b.starts_with(&format!("{id}."))
        })
}

struct Scanner<'a> {
    ctx: &'a CleanContext,
    deadline: Instant,
    cancel: &'a AtomicBool,
    out: CleanScan,
}

impl Scanner<'_> {
    fn stopped(&mut self) -> bool {
        if self.cancel.load(Ordering::Relaxed) || Instant::now() > self.deadline {
            self.out.complete = false;
            return true;
        }
        false
    }

    fn entries(&mut self, dir: &Path) -> Vec<PathBuf> {
        match std::fs::read_dir(dir) {
            Ok(read) => read.filter_map(|e| e.ok().map(|e| e.path())).collect(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => {
                self.out.unreadable.push(dir.to_string_lossy().into_owned());
                Vec::new()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        category: CleanCategory,
        path: &Path,
        name: String,
        method: CleanMethod,
        recommended: bool,
        note: Option<&str>,
        min_bytes: u64,
    ) -> Option<&mut CleanItem> {
        // Odkazy nikdy (ani na položce samé).
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return None;
        }
        let (bytes, files, modified_ms, complete) = measure(path, self.deadline);
        if !complete {
            self.out.complete = false;
        }
        if bytes < min_bytes {
            return None;
        }
        self.out.items.push(CleanItem {
            id: item_id(path),
            category,
            path: path.to_string_lossy().into_owned(),
            name,
            bytes,
            files,
            modified_ms,
            recommended,
            method,
            note: note.map(str::to_string),
        });
        self.out.items.last_mut()
    }

    fn app_caches(&mut self, dir: &Path) {
        for path in self.entries(dir) {
            if self.stopped() {
                return;
            }
            let name = file_name(&path);
            if protected_cache(&name) {
                continue;
            }
            let running = self.ctx.running_bundles.contains(&name);
            let now = self.ctx.now_ms;
            let window = if cfg!(windows) {
                TEMP_IN_USE_MS
            } else {
                IN_USE_MS
            };
            if let Some(item) = self.push(
                CleanCategory::AppCaches,
                &path,
                name,
                CleanMethod::Delete,
                !running,
                running.then_some("app is running"),
                512 * 1024,
            ) && !running
                && item
                    .modified_ms
                    .is_some_and(|ms| now.saturating_sub(ms) < window)
            {
                item.recommended = false;
                item.note = Some("in use".into());
            }
        }
    }

    fn logs(&mut self, dirs: &[PathBuf]) {
        for dir in dirs {
            for path in self.entries(dir) {
                if self.stopped() {
                    return;
                }
                // Hlášení o pádech mají vlastní podsložku, ta se prochází zvlášť.
                if path.file_name().is_some_and(|n| n == "DiagnosticReports") {
                    continue;
                }
                let (_, _, newest, _) = measure(&path, self.deadline);
                if newest.is_some_and(|ms| self.ctx.now_ms.saturating_sub(ms) < OLD_LOG_MS) {
                    continue;
                }
                let name = file_name(&path);
                self.push(
                    CleanCategory::Logs,
                    &path,
                    name,
                    CleanMethod::Delete,
                    true,
                    None,
                    1,
                );
            }
        }
    }

    fn developer(&mut self, home: &Path) {
        // (cesta, předvybrat, poznámka)
        let known: [(&str, bool, Option<&str>); 7] = [
            (
                "Library/Developer/Xcode/DerivedData",
                true,
                Some("rebuilt on next build"),
            ),
            (
                "Library/Developer/Xcode/iOS DeviceSupport",
                true,
                Some("downloaded again when a device connects"),
            ),
            ("Library/Developer/CoreSimulator/Caches", true, None),
            (
                "Library/Developer/Xcode/Archives",
                false,
                Some("app archives you may still need"),
            ),
            (".npm/_cacache", true, Some("downloaded again when needed")),
            (".gradle/caches", true, Some("downloaded again when needed")),
            (
                ".cargo/registry/cache",
                true,
                Some("downloaded again when needed"),
            ),
        ];
        for (relative, recommended, note) in known {
            if self.stopped() {
                return;
            }
            let path = home.join(relative);
            if !path.is_dir() {
                continue;
            }
            let method = if recommended {
                CleanMethod::Delete
            } else {
                CleanMethod::MoveToTrash
            };
            self.push(
                CleanCategory::Developer,
                &path,
                relative.to_string(),
                method,
                recommended,
                note,
                1024 * 1024,
            );
        }
    }

    fn installers(&mut self, downloads: &Path) {
        for path in self.entries(downloads) {
            if self.stopped() {
                return;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_file() || !is_installer(&path) {
                continue;
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(epoch_ms)
                .unwrap_or(self.ctx.now_ms);
            if self.ctx.now_ms.saturating_sub(modified) < OLD_INSTALLER_MS {
                continue;
            }
            let name = file_name(&path);
            self.push(
                CleanCategory::Installers,
                &path,
                name,
                CleanMethod::MoveToTrash,
                true,
                None,
                1,
            );
        }
    }

    fn leftovers(&mut self, home: &Path) {
        let places = [
            ("Library/Saved Application State", ".savedState", true),
            ("Library/Preferences", ".plist", false),
        ];
        for (relative, suffix, recommended) in places {
            for path in self.entries(&home.join(relative)) {
                if self.stopped() {
                    return;
                }
                let name = file_name(&path);
                let Some(id) = name.strip_suffix(suffix) else {
                    continue;
                };
                if !looks_like_bundle_id(id)
                    || id.starts_with("com.apple.")
                    || belongs_to_installed(id, self.ctx)
                {
                    continue;
                }
                self.push(
                    CleanCategory::Leftovers,
                    &path,
                    id.to_string(),
                    CleanMethod::MoveToTrash,
                    recommended,
                    Some("app not found"),
                    1,
                );
            }
        }
    }

    fn large_files(&mut self, home: &Path) {
        let mut found: Vec<(u64, PathBuf, u64)> = Vec::new();
        let walker = walkdir::WalkDir::new(home)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                // Bez skrytých složek, Knihovny, Koše a balíčků (Fotky, aplikace).
                e.depth() == 0
                    || !(name.starts_with('.')
                        || (e.depth() == 1 && name == "Library")
                        || (e.file_type().is_dir() && name.contains('.') && is_package_dir(&name)))
            });
        let mut seen = 0u64;
        for entry in walker {
            seen += 1;
            if seen > MAX_ENTRIES_PER_ITEM * 2 || self.stopped() {
                self.out.complete = false;
                break;
            }
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let bytes = allocated(&meta);
            if bytes < LARGE_FILE_BYTES {
                continue;
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(epoch_ms)
                .unwrap_or(self.ctx.now_ms);
            if self.ctx.now_ms.saturating_sub(modified) < STALE_FILE_MS {
                continue;
            }
            found.push((bytes, entry.into_path(), modified));
        }
        found.sort_by_key(|f| std::cmp::Reverse(f.0));
        for (_, path, _) in found.into_iter().take(MAX_LARGE_FILES) {
            let name = file_name(&path);
            self.push(
                CleanCategory::LargeFiles,
                &path,
                name,
                CleanMethod::MoveToTrash,
                false,
                Some("your file"),
                LARGE_FILE_BYTES,
            );
        }
    }

    fn trash(&mut self, trash: &Path) {
        if std::fs::read_dir(trash).is_err() {
            if trash.exists() {
                self.out
                    .unreadable
                    .push(trash.to_string_lossy().into_owned());
            }
            return;
        }
        self.push(
            CleanCategory::Trash,
            trash,
            "Koš".into(),
            CleanMethod::EmptyTrash,
            false,
            Some("permanent"),
            1,
        );
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn is_installer(path: &Path) -> bool {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if cfg!(windows) {
        matches!(ext.as_str(), "exe" | "msi" | "msix" | "iso")
    } else {
        matches!(ext.as_str(), "dmg" | "pkg" | "mpkg" | "iso" | "xip")
    }
}

/// Balíček (Fotky, Hudba, aplikace) se prochází jen jako celek, ne po souborech.
fn is_package_dir(name: &str) -> bool {
    let ext = name
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "app"
            | "photoslibrary"
            | "musiclibrary"
            | "tvlibrary"
            | "photolibrary"
            | "fcpbundle"
            | "logicx"
            | "band"
            | "sparsebundle"
            | "bundle"
    )
}

/// Kde se v domovské složce hledá (jen macOS má knihovnu; jinde dočasné soubory).
fn layout(home: &Path) -> Layout {
    if cfg!(windows) {
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        Layout {
            caches: local.as_ref().map(|l| l.join("Temp")).into_iter().collect(),
            logs: Vec::new(),
            downloads: home.join("Downloads"),
            trash: None,
            library: false,
        }
    } else if cfg!(target_os = "macos") {
        Layout {
            caches: vec![home.join("Library/Caches")],
            logs: vec![
                home.join("Library/Logs"),
                home.join("Library/Logs/DiagnosticReports"),
            ],
            downloads: home.join("Downloads"),
            trash: Some(home.join(".Trash")),
            library: true,
        }
    } else {
        Layout {
            caches: vec![home.join(".cache")],
            logs: Vec::new(),
            downloads: home.join("Downloads"),
            trash: Some(home.join(".local/share/Trash/files")),
            library: false,
        }
    }
}

struct Layout {
    caches: Vec<PathBuf>,
    logs: Vec<PathBuf>,
    downloads: PathBuf,
    trash: Option<PathBuf>,
    /// Knihovna macOS (zbytky aplikací, vývojářské mezipaměti).
    library: bool,
}

/// Projde domovskou složku. `progress` dostává kategorii, která se právě skenuje.
pub fn scan(
    ctx: &CleanContext,
    cancel: &AtomicBool,
    mut progress: impl FnMut(CleanCategory),
) -> CleanScan {
    let layout = layout(&ctx.home);
    let mut scanner = Scanner {
        ctx,
        deadline: Instant::now() + SCAN_BUDGET,
        cancel,
        out: CleanScan {
            started_at_ms: ctx.now_ms,
            complete: true,
            ..CleanScan::default()
        },
    };
    progress(CleanCategory::AppCaches);
    for dir in &layout.caches {
        scanner.app_caches(dir);
    }
    progress(CleanCategory::Logs);
    scanner.logs(&layout.logs);
    progress(CleanCategory::Developer);
    scanner.developer(&ctx.home);
    progress(CleanCategory::Installers);
    scanner.installers(&layout.downloads);
    if layout.library {
        progress(CleanCategory::Leftovers);
        scanner.leftovers(&ctx.home);
    }
    progress(CleanCategory::LargeFiles);
    scanner.large_files(&ctx.home);
    if let Some(trash) = &layout.trash {
        progress(CleanCategory::Trash);
        scanner.trash(trash);
    }
    let mut out = scanner.out;
    out.items.sort_by_key(|i| std::cmp::Reverse(i.bytes));
    out.finished_at_ms = epoch_ms(SystemTime::now()).unwrap_or(ctx.now_ms);
    out
}

/// Smí se položka uklidit? Ověří umístění podle kategorie a že cesta od domovské
/// složky nevede přes odkaz. Kontroluje se těsně před zásahem.
fn allowed(item: &CleanItem, ctx: &CleanContext) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(&item.path);
    let layout = layout(&ctx.home);
    let relative = path.strip_prefix(&ctx.home).map_err(|_| "outside home")?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err("invalid path");
    }
    // Žádný článek cesty nesmí být odkaz.
    let mut current = ctx.home.clone();
    for part in relative.components() {
        current.push(part);
        let meta = std::fs::symlink_metadata(&current).map_err(|_| "no longer exists")?;
        if meta.file_type().is_symlink() {
            return Err("symbolic link");
        }
    }
    let parent = path.parent().ok_or("invalid path")?;
    let ok = match item.category {
        CleanCategory::AppCaches => {
            layout.caches.iter().any(|c| c == parent)
                && !protected_cache(&file_name(&path))
                && !ctx.running_bundles.contains(&file_name(&path))
        }
        CleanCategory::Logs => layout.logs.iter().any(|l| l == parent),
        CleanCategory::Developer => [
            "Library/Developer/Xcode/DerivedData",
            "Library/Developer/Xcode/iOS DeviceSupport",
            "Library/Developer/CoreSimulator/Caches",
            "Library/Developer/Xcode/Archives",
            ".npm/_cacache",
            ".gradle/caches",
            ".cargo/registry/cache",
        ]
        .iter()
        .any(|known| relative == Path::new(known)),
        CleanCategory::Installers => parent == layout.downloads && is_installer(&path),
        CleanCategory::Leftovers => {
            parent == ctx.home.join("Library/Saved Application State")
                || parent == ctx.home.join("Library/Preferences")
        }
        CleanCategory::LargeFiles => {
            !relative.starts_with("Library")
                && std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file())
        }
        CleanCategory::Trash => layout.trash.as_deref() == Some(path.as_path()),
    };
    if !ok {
        return Err("not allowed here");
    }
    // Metoda musí odpovídat kategorii (rozhraní ji nemůže změnit na mazání).
    let expected = match item.category {
        CleanCategory::Trash => CleanMethod::EmptyTrash,
        CleanCategory::Installers | CleanCategory::Leftovers | CleanCategory::LargeFiles => {
            CleanMethod::MoveToTrash
        }
        CleanCategory::AppCaches | CleanCategory::Logs => CleanMethod::Delete,
        CleanCategory::Developer => item.method,
    };
    if item.method != expected
        || (item.category == CleanCategory::Developer
            && relative == Path::new("Library/Developer/Xcode/Archives")
            && item.method != CleanMethod::MoveToTrash)
    {
        return Err("method not allowed");
    }
    Ok(path)
}

/// Nový název v Koši, který nic nepřepíše.
fn trash_target(trash: &Path, name: &str, now_ms: u64) -> PathBuf {
    let first = trash.join(name);
    if std::fs::symlink_metadata(&first).is_err() {
        return first;
    }
    trash.join(format!("{name} {now_ms}"))
}

fn remove(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        // Bez sledování odkazů (std implementace je odolná vůči záměně za odkaz).
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Vysype Koš: smaže jeho obsah, složku Koše ponechá.
fn empty_trash(trash: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(trash)? {
        remove(&entry?.path())?;
    }
    Ok(())
}

/// Uklidí vybrané položky ze skenu. `move_to_trash` přesouvá do Koše (na macOS
/// to může obstarat Finder, když aplikace nemá do Koše přístup).
pub fn clean(
    ctx: &CleanContext,
    items: &[CleanItem],
    move_to_trash: &dyn Fn(&Path) -> std::io::Result<()>,
) -> CleanOutcome {
    let mut outcome = CleanOutcome::default();
    for item in items {
        let path = match allowed(item, ctx) {
            Ok(path) => path,
            Err(reason) => {
                outcome.failed.push(CleanFailure {
                    id: item.id.clone(),
                    reason: reason.into(),
                });
                continue;
            }
        };
        let result = match item.method {
            CleanMethod::Delete => remove(&path),
            CleanMethod::MoveToTrash => move_to_trash(&path),
            CleanMethod::EmptyTrash => empty_trash(&path),
        };
        match result {
            Ok(()) => {
                if item.method == CleanMethod::MoveToTrash {
                    outcome.trashed_bytes += item.bytes;
                } else {
                    outcome.freed_bytes += item.bytes;
                }
                outcome.cleaned.push(item.id.clone());
            }
            Err(err) => outcome.failed.push(CleanFailure {
                id: item.id.clone(),
                reason: err.to_string(),
            }),
        }
    }
    outcome
}

/// Přesun do Koše přejmenováním (stejný disk). Bez přístupu ke Koši vrátí chybu.
pub fn rename_to_trash(home: &Path, path: &Path, now_ms: u64) -> std::io::Result<()> {
    let trash = layout(home)
        .trash
        .ok_or_else(|| std::io::Error::other("no trash on this system"))?;
    let name = file_name(path);
    std::fs::rename(path, trash_target(&trash, &name, now_ms))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    fn set_old(path: &Path, days: u64) {
        let time = SystemTime::now() - Duration::from_secs(days * 86_400);
        let file = fs::File::options().write(true).open(path).unwrap();
        file.set_modified(time).unwrap();
    }

    fn home() -> (tempfile::TempDir, CleanContext) {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = CleanContext {
            home: tmp.path().to_path_buf(),
            now_ms: epoch_ms(SystemTime::now()).unwrap(),
            ..CleanContext::default()
        };
        (tmp, ctx)
    }

    #[cfg(unix)]
    #[test]
    fn caches_logs_and_old_installers_are_found_and_cleaned_safely() {
        let (tmp, mut ctx) = home();
        let h = tmp.path();
        let paths = layout(h);
        let caches = paths.caches[0].clone();
        for app in [
            "com.vendor.app",
            "com.apple.Safari",
            "com.running.app",
            "com.busy.app",
        ] {
            fs::create_dir_all(caches.join(app)).unwrap();
            fs::write(caches.join(app).join("blob"), vec![1u8; 2 << 20]).unwrap();
            if app != "com.busy.app" {
                set_old(&caches.join(app).join("blob"), 2);
            }
        }
        if let Some(logs) = paths.logs.first() {
            fs::create_dir_all(logs).unwrap();
            fs::write(logs.join("old.log"), b"log").unwrap();
            set_old(&logs.join("old.log"), 30);
            fs::write(logs.join("new.log"), b"log").unwrap();
        }
        fs::create_dir_all(h.join("Downloads")).unwrap();
        fs::write(h.join("Downloads/Setup.dmg"), b"dmg").unwrap();
        set_old(&h.join("Downloads/Setup.dmg"), 30);
        fs::write(h.join("Downloads/report.pdf"), b"pdf").unwrap();
        set_old(&h.join("Downloads/report.pdf"), 30);
        ctx.running_bundles.insert("com.running.app".into());

        let result = scan(&ctx, &AtomicBool::new(false), |_| {});
        let names: Vec<_> = result.items.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"com.vendor.app"));
        assert!(!names.contains(&"com.apple.Safari"), "Apple caches stay");
        if !paths.logs.is_empty() {
            assert!(names.contains(&"old.log") && !names.contains(&"new.log"));
        }
        assert!(names.contains(&"Setup.dmg") && !names.contains(&"report.pdf"));
        let running = result
            .items
            .iter()
            .find(|i| i.name == "com.running.app")
            .unwrap();
        assert!(!running.recommended);
        // Právě zapisovaná mezipaměť se nabídne, ale nepředvybere.
        let busy = result
            .items
            .iter()
            .find(|i| i.name == "com.busy.app")
            .unwrap();
        assert!(!busy.recommended);
        assert_eq!(busy.note.as_deref(), Some("in use"));
        let vendor = result
            .items
            .iter()
            .find(|i| i.name == "com.vendor.app")
            .unwrap();
        assert!(vendor.recommended && vendor.note.is_none());

        let picked: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.recommended)
            .cloned()
            .collect();
        let trash = paths.trash.clone().unwrap();
        fs::create_dir_all(&trash).unwrap();
        let outcome = clean(&ctx, &picked, &|p| rename_to_trash(h, p, 1));
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        assert!(!caches.join("com.vendor.app").exists());
        assert!(
            trash.join("Setup.dmg").exists(),
            "installers go to the Trash"
        );
        assert!(caches.join("com.running.app").exists());
        assert!(caches.join("com.busy.app").exists());
        assert!(outcome.freed_bytes > 0 && outcome.trashed_bytes > 0);
    }

    #[test]
    fn forged_or_moved_items_are_refused() {
        let (tmp, ctx) = home();
        let h = tmp.path();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("precious.txt"), b"x").unwrap();
        let forged = CleanItem {
            id: "x".into(),
            category: CleanCategory::LargeFiles,
            path: outside
                .path()
                .join("precious.txt")
                .to_string_lossy()
                .into_owned(),
            name: "precious.txt".into(),
            bytes: 1,
            files: 1,
            modified_ms: None,
            recommended: true,
            method: CleanMethod::Delete,
            note: None,
        };
        let outcome = clean(&ctx, std::slice::from_ref(&forged), &|_| Ok(()));
        assert_eq!(outcome.failed.len(), 1);
        assert!(outside.path().join("precious.txt").exists());

        // Uvnitř domova, ale metoda mazání u souboru uživatele.
        fs::create_dir_all(h.join("Documents")).unwrap();
        fs::write(h.join("Documents/big.mov"), b"x").unwrap();
        let wrong_method = CleanItem {
            path: h.join("Documents/big.mov").to_string_lossy().into_owned(),
            ..forged
        };
        let outcome = clean(&ctx, &[wrong_method], &|_| Ok(()));
        assert_eq!(outcome.failed[0].reason, "method not allowed");
        assert!(h.join("Documents/big.mov").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_never_followed() {
        let (tmp, ctx) = home();
        let h = tmp.path();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(outside.path().join("data")).unwrap();
        fs::write(outside.path().join("data/keep.txt"), b"x").unwrap();
        let caches = layout(h).caches[0].clone();
        fs::create_dir_all(&caches).unwrap();
        std::os::unix::fs::symlink(outside.path().join("data"), caches.join("com.evil.link"))
            .unwrap();
        let result = scan(&ctx, &AtomicBool::new(false), |_| {});
        assert!(result.items.iter().all(|i| i.name != "com.evil.link"));
        let forged = CleanItem {
            id: "x".into(),
            category: CleanCategory::AppCaches,
            path: caches.join("com.evil.link").to_string_lossy().into_owned(),
            name: "com.evil.link".into(),
            bytes: 1,
            files: 1,
            modified_ms: None,
            recommended: true,
            method: CleanMethod::Delete,
            note: None,
        };
        let outcome = clean(&ctx, &[forged], &|_| Ok(()));
        assert_eq!(outcome.failed[0].reason, "symbolic link");
        assert!(outside.path().join("data/keep.txt").exists());
    }

    #[test]
    fn leftovers_skip_installed_and_apple_apps() {
        let mut ctx = CleanContext::default();
        ctx.installed_bundles.insert("com.google.Chrome".into());
        assert!(belongs_to_installed("com.google.Chrome.helper", &ctx));
        assert!(belongs_to_installed("com.google.chrome", &ctx));
        assert!(!belongs_to_installed("com.gone.app", &ctx));
        assert!(looks_like_bundle_id("com.gone.app"));
        assert!(!looks_like_bundle_id(".GlobalPreferences"));
        assert!(!looks_like_bundle_id("loginwindow"));
    }
}
