//! Čištění a zrychlení: příkazy pro rozhraní.
//!
//! Rozhraní posílá jen identifikátory z posledního skenu nebo měření, které
//! drží backend; cesty ani PID si nevymýšlí. Každý zásah se před provedením
//! znovu ověří v jádru a zapíše do auditu.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use antishield_core::cleanup::{
    self, CleanCategory, CleanContext, CleanMethod, CleanOutcome, CleanScan,
};
use antishield_core::error::ErrorDto;
use antishield_core::speed::{self, QuitOutcome, SpeedReport};
use antishield_core::system;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::state::AppState;

/// Složka, kam se odkládají vypnuté položky po přihlášení (jde je vrátit).
const DISABLED_STARTUP_DIR: &str = "startup-disabled";

#[derive(Default)]
pub struct CareState {
    scan: Mutex<Option<CleanScan>>,
    scanning: AtomicBool,
    cancel: AtomicBool,
    /// Najednou běží jen jeden úklid.
    cleaning: Mutex<()>,
    speed: Mutex<Option<SpeedReport>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn error(code: &str, message: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn home() -> Result<PathBuf, ErrorDto> {
    system::home_dir().ok_or_else(|| error("no_home", "the home folder is unknown"))
}

fn context(home: PathBuf) -> CleanContext {
    CleanContext {
        installed_bundles: system::installed_app_ids(&home),
        running_bundles: system::running_app_ids(),
        home,
        now_ms: antishield_core::now_ms(),
    }
}

/// Přesun do Koše přes systém (na macOS NSFileManager: bez ovládání Finderu).
fn move_to_trash(path: &Path) -> std::io::Result<()> {
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut trash = trash::TrashContext::default();
    #[cfg(target_os = "macos")]
    {
        use trash::macos::{DeleteMethod, TrashContextExtMacos};
        trash.set_delete_method(DeleteMethod::NsFileManager);
    }
    trash
        .delete(path)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Po skončení skenu (i při chybě) uvolní příznak běhu.
struct Running<'a>(&'a AtomicBool);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn audit(app: &AppHandle, kind: &str, data: serde_json::Value) {
    if let Ok(engine) = app.state::<AppState>().engine() {
        engine.record_action(kind, data);
    }
}

// ---------- Čištění ----------

/// Projde domovskou složku a najde, co jde uklidit. Průběh posílá událostí
/// `clean-progress` (právě procházená kategorie).
#[tauri::command]
pub async fn clean_scan(app: AppHandle) -> Result<CleanScan, ErrorDto> {
    let state = app.state::<AppState>();
    if state.care.scanning.swap(true, Ordering::SeqCst) {
        return Err(error("clean_running", "a cleanup scan is already running"));
    }
    state.care.cancel.store(false, Ordering::SeqCst);
    let worker = app.clone();
    let scan = tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<AppState>();
        let _running = Running(&state.care.scanning);
        let ctx = context(home()?);
        let scan = cleanup::scan(&ctx, &state.care.cancel, |category| {
            let _ = worker.emit("clean-progress", category);
        });
        *lock(&state.care.scan) = Some(scan.clone());
        Ok::<_, ErrorDto>(scan)
    })
    .await
    .map_err(|e| error("clean_scan", &e.to_string()))??;
    Ok(scan)
}

#[tauri::command]
pub fn clean_cancel(state: State<'_, AppState>) {
    state.care.cancel.store(true, Ordering::SeqCst);
}

/// Poslední sken (např. po návratu na obrazovku).
#[tauri::command]
pub fn clean_last(state: State<'_, AppState>) -> Option<CleanScan> {
    lock(&state.care.scan).clone()
}

fn run_clean(
    app: &AppHandle,
    pick: impl Fn(&cleanup::CleanItem) -> bool,
) -> Result<CleanOutcome, ErrorDto> {
    let state = app.state::<AppState>();
    let _one_at_a_time = lock(&state.care.cleaning);
    let items: Vec<_> = lock(&state.care.scan)
        .as_ref()
        .map(|scan| scan.items.iter().filter(|i| pick(i)).cloned().collect())
        .unwrap_or_default();
    if items.is_empty() {
        return Err(error("clean_unknown", "nothing from the last scan matches"));
    }
    let ctx = context(home()?);
    let outcome = cleanup::clean(&ctx, &items, &move_to_trash);
    if let Some(scan) = lock(&state.care.scan).as_mut() {
        scan.items.retain(|i| !outcome.cleaned.contains(&i.id));
    }
    let cleaned: Vec<_> = items
        .iter()
        .filter(|i| outcome.cleaned.contains(&i.id))
        .map(|i| json!({ "category": i.category, "path": i.path, "method": i.method, "bytes": i.bytes }))
        .collect();
    let failed: Vec<_> = outcome
        .failed
        .iter()
        .filter_map(|f| {
            let item = items.iter().find(|i| i.id == f.id)?;
            Some(json!({ "path": item.path, "reason": f.reason }))
        })
        .collect();
    audit(
        app,
        "cleanup",
        json!({
            "freedBytes": outcome.freed_bytes,
            "trashedBytes": outcome.trashed_bytes,
            "cleaned": cleaned,
            "failed": failed,
        }),
    );
    Ok(outcome)
}

/// Uklidí vybrané položky z posledního skenu (podle identifikátorů).
/// Koš se tu nevysypává; na to je samostatný příkaz.
#[tauri::command]
pub async fn clean_items(app: AppHandle, ids: Vec<String>) -> Result<CleanOutcome, ErrorDto> {
    tauri::async_runtime::spawn_blocking(move || {
        run_clean(&app, |item| {
            item.method != CleanMethod::EmptyTrash && ids.contains(&item.id)
        })
    })
    .await
    .map_err(|e| error("clean", &e.to_string()))?
}

/// Vysype Koš (nevratné; rozhraní se před tím výslovně zeptá).
#[tauri::command]
pub async fn clean_empty_trash(app: AppHandle) -> Result<CleanOutcome, ErrorDto> {
    tauri::async_runtime::spawn_blocking(move || {
        run_clean(&app, |item| {
            item.category == CleanCategory::Trash && item.method == CleanMethod::EmptyTrash
        })
    })
    .await
    .map_err(|e| error("clean", &e.to_string()))?
}

// ---------- Zrychlení ----------

fn disabled_dir(state: &AppState) -> PathBuf {
    state.data_dir.join(DISABLED_STARTUP_DIR)
}

fn measure(app: &AppHandle) -> Result<SpeedReport, ErrorDto> {
    let state = app.state::<AppState>();
    let report = speed::measure(
        &home()?,
        &disabled_dir(&state),
        crate::agent::LABEL,
        std::process::id(),
    );
    *lock(&state.care.speed) = Some(report.clone());
    Ok(report)
}

/// Změří stav počítače (asi sekundu).
#[tauri::command]
pub async fn speed_report(app: AppHandle) -> Result<SpeedReport, ErrorDto> {
    tauri::async_runtime::spawn_blocking(move || measure(&app))
        .await
        .map_err(|e| error("speed", &e.to_string()))?
}

fn quit_error(err: &antishield_core::EngineError) -> ErrorDto {
    let text = err.to_string();
    let code = if text.contains("automation not allowed") {
        "quit_automation_denied"
    } else if text.contains("no window") {
        "quit_no_window"
    } else if text.contains("cannot be quit") {
        "quit_protected"
    } else {
        "quit_failed"
    };
    error(code, &text)
}

/// Požádá aplikaci z posledního měření o běžné ukončení.
#[tauri::command]
pub async fn speed_quit(app: AppHandle, pid: u32) -> Result<QuitOutcome, ErrorDto> {
    let target = lock(&app.state::<AppState>().care.speed)
        .as_ref()
        .and_then(|report| report.heavy.iter().find(|p| p.pid == pid).cloned())
        .ok_or_else(|| error("speed_unknown", "not in the last measurement"))?;
    tauri::async_runtime::spawn_blocking(move || {
        let result = speed::quit_process(&target, std::process::id());
        audit(
            &app,
            "app_quit_requested",
            json!({
                "name": target.name,
                "path": target.path,
                "bundleId": target.bundle_id,
                "outcome": result.as_ref().ok(),
                "error": result.as_ref().err().map(ToString::to_string),
            }),
        );
        result.map_err(|e| quit_error(&e))
    })
    .await
    .map_err(|e| error("speed", &e.to_string()))?
}

/// Vypne nebo vrátí uživatelskou položku po přihlášení. Vrátí nové měření.
#[tauri::command]
pub async fn speed_startup(
    app: AppHandle,
    id: String,
    enabled: bool,
) -> Result<SpeedReport, ErrorDto> {
    let entry = lock(&app.state::<AppState>().care.speed)
        .as_ref()
        .and_then(|report| report.startup.iter().find(|e| e.id == id).cloned())
        .ok_or_else(|| error("speed_unknown", "not in the last measurement"))?;
    if entry.system {
        return Err(error(
            "startup_system",
            "system items are managed in System Settings",
        ));
    }
    tauri::async_runtime::spawn_blocking(move || {
        if entry.enabled != enabled {
            let state = app.state::<AppState>();
            let home = home()?;
            let disabled = disabled_dir(&state);
            let from = Path::new(&entry.plist);
            let moved = if enabled {
                speed::enable_startup(from, &home, &disabled)
            } else {
                speed::disable_startup(from, &home, &disabled, crate::agent::LABEL)
            }
            .map_err(|e| ErrorDto::from(&e))?;
            audit(
                &app,
                if enabled {
                    "startup_enabled"
                } else {
                    "startup_disabled"
                },
                json!({
                    "label": entry.label,
                    "program": entry.program,
                    "from": entry.plist,
                    "to": moved,
                }),
            );
        }
        measure(&app)
    })
    .await
    .map_err(|e| error("speed", &e.to_string()))?
}
