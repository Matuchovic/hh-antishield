//! Příkazy, které smí volat rozhraní. Každý je povolený jednotlivě
//! v `capabilities/default.json`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use antishield_core::error::ErrorDto;
use antishield_core::posture::PostureCheck;
use antishield_core::status::ProtectionSummary;
use antishield_core::{
    AuditEvent, EngineInfo, QuarantineItem, RemediationReport, RuleUpdateOutcome, ScanRequest,
    ScanSummary, SelfTestReport,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_updater::UpdaterExt;

use crate::services::{self, EmitObserver};
use crate::settings::{PresetScan, Settings};
use crate::state::{AppState, RuntimeInfo};

fn app_error(code: &str, message: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn engine_error(err: &antishield_core::EngineError) -> ErrorDto {
    ErrorDto::from(err)
}

#[tauri::command]
pub fn engine_info(state: State<'_, AppState>) -> Result<EngineInfo, ErrorDto> {
    Ok(state.engine()?.info())
}

#[tauri::command]
pub fn protection_status(state: State<'_, AppState>) -> ProtectionSummary {
    state.protection()
}

#[tauri::command]
pub fn run_self_test(state: State<'_, AppState>) -> Result<SelfTestReport, ErrorDto> {
    Ok(state.engine()?.self_test())
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TargetKind {
    Folders,
    Files,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Selection {
    pub id: String,
    pub paths: Vec<String>,
}

/// Otevře nativní dialog. Vybrané cesty zůstávají v backendu; rozhraní dostane
/// jen ID výběru a cesty k zobrazení.
#[tauri::command]
pub async fn pick_targets(app: AppHandle, kind: TargetKind) -> Result<Option<Selection>, ErrorDto> {
    let dialog = app.dialog().file().set_title(match kind {
        TargetKind::Folders => "Vyberte složky ke kontrole",
        TargetKind::Files => "Vyberte soubory ke kontrole",
    });
    let picked = match kind {
        TargetKind::Folders => dialog.blocking_pick_folders(),
        TargetKind::Files => dialog.blocking_pick_files(),
    };
    let Some(picked) = picked else {
        return Ok(None);
    };
    let paths: Vec<PathBuf> = picked
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .filter(|p| p.is_absolute())
        .collect();
    if paths.is_empty() {
        return Ok(None);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let display = paths.iter().map(|p| p.display().to_string()).collect();
    app.state::<AppState>()
        .remember_selection(id.clone(), paths);
    Ok(Some(Selection { id, paths: display }))
}

#[tauri::command]
pub fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    selection_id: String,
) -> Result<String, ErrorDto> {
    let engine = state.engine()?;
    let roots = state.selection(&selection_id).ok_or_else(|| {
        app_error(
            "unknown_selection",
            "Výběr už neexistuje, vyberte soubory nebo složky znovu.",
        )
    })?;
    let observer = Arc::new(EmitObserver {
        app: app.clone(),
        last_summary: state.last_summary_slot(),
    });
    let handle = engine
        .start_scan(ScanRequest::new(roots), observer)
        .map_err(|err| engine_error(&err))?;
    let scan_id = handle.scan_id().to_string();
    state.set_current_scan(handle);
    Ok(scan_id)
}

/// Rychlá (procesy, položky po spuštění, Stažené, Plocha) nebo úplná kontrola.
#[tauri::command]
pub fn start_preset_scan(app: AppHandle, kind: PresetScan) -> Result<String, ErrorDto> {
    services::start_preset_scan(&app, kind)
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) {
    if let Some(handle) = state.current_scan() {
        handle.cancel();
    }
}

#[tauri::command]
pub fn recent_events(state: State<'_, AppState>, limit: u32) -> Result<Vec<AuditEvent>, ErrorDto> {
    state
        .engine()?
        .recent_audit_events(limit as usize)
        .map_err(|err| engine_error(&err))
}

#[tauri::command]
pub fn last_summary(state: State<'_, AppState>) -> Option<ScanSummary> {
    state.last_summary()
}

// ---------- Vyčištění a karanténa ----------

/// Vyčistí nálezy, které backend sám našel (podle cesty). Cizí cesty ignoruje.
#[tauri::command]
pub async fn remediate(
    app: AppHandle,
    paths: Vec<String>,
) -> Result<Vec<RemediationReport>, ErrorDto> {
    let state = app.state::<AppState>();
    let engine = state.engine()?;
    let findings = state.known_findings(&paths);
    if findings.is_empty() {
        return Err(app_error("unknown_finding", "no matching finding to clean"));
    }
    let reports = tauri::async_runtime::spawn_blocking(move || {
        findings
            .iter()
            .map(|finding| engine.remediate(finding))
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| app_error("remediate", &e.to_string()))?;
    let _ = app.emit("quarantine-changed", ());
    Ok(reports)
}

#[tauri::command]
pub fn quarantine_list(state: State<'_, AppState>) -> Result<Vec<QuarantineItem>, ErrorDto> {
    state
        .engine()?
        .quarantine_items()
        .map_err(|err| engine_error(&err))
}

#[tauri::command]
pub async fn quarantine_restore(app: AppHandle, id: String) -> Result<QuarantineItem, ErrorDto> {
    let engine = app.state::<AppState>().engine()?;
    let item = tauri::async_runtime::spawn_blocking(move || engine.restore_quarantined(&id))
        .await
        .map_err(|e| app_error("quarantine", &e.to_string()))?
        .map_err(|err| engine_error(&err))?;
    let _ = app.emit("quarantine-changed", ());
    Ok(item)
}

#[tauri::command]
pub async fn quarantine_delete(app: AppHandle, id: String) -> Result<QuarantineItem, ErrorDto> {
    let engine = app.state::<AppState>().engine()?;
    let item = tauri::async_runtime::spawn_blocking(move || engine.delete_quarantined(&id))
        .await
        .map_err(|e| app_error("quarantine", &e.to_string()))?
        .map_err(|err| engine_error(&err))?;
    let _ = app.emit("quarantine-changed", ());
    Ok(item)
}

// ---------- Bezpečnost systému, pravidla, běh ochrany ----------

#[tauri::command]
pub async fn posture_checks() -> Result<Vec<PostureCheck>, ErrorDto> {
    tauri::async_runtime::spawn_blocking(antishield_core::posture::checks)
        .await
        .map_err(|e| app_error("posture", &e.to_string()))
}

/// Panel Nastavení systému k danému ochrannému prvku (pevný seznam adres,
/// rozhraní předává jen označení). Jen otevře okno; nic nemění.
#[cfg(target_os = "macos")]
fn system_settings_url(check_id: &str) -> Option<&'static str> {
    match check_id {
        "gatekeeper" => Some("x-apple.systempreferences:com.apple.preference.security?General"),
        "filevault" => Some("x-apple.systempreferences:com.apple.preference.security?FileVault"),
        "firewall" => Some("x-apple.systempreferences:com.apple.preference.security?Firewall"),
        "xprotect" => Some("x-apple.systempreferences:com.apple.preferences.softwareupdate"),
        "fullDisk" => {
            Some("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        }
        "camera" => Some("x-apple.systempreferences:com.apple.preference.security?Privacy_Camera"),
        "microphone" => {
            Some("x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone")
        }
        "screen" => {
            Some("x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture")
        }
        "accessibility" => {
            Some("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
        }
        "input" => {
            Some("x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent")
        }
        _ => None,
    }
}

#[cfg(windows)]
fn system_settings_url(check_id: &str) -> Option<&'static str> {
    match check_id {
        "defender" => Some("windowsdefender:"),
        "firewall" => Some("windowsdefender://network/"),
        _ => None,
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn system_settings_url(_check_id: &str) -> Option<&'static str> {
    None
}

#[tauri::command]
pub fn open_system_settings(check_id: String) -> Result<(), ErrorDto> {
    let url = system_settings_url(&check_id)
        .ok_or_else(|| app_error("unknown_setting", "no settings page for this check"))?;
    #[cfg(target_os = "macos")]
    let program = "/usr/bin/open";
    #[cfg(windows)]
    let program = "explorer.exe";
    #[cfg(not(any(target_os = "macos", windows)))]
    let program = "xdg-open";
    std::process::Command::new(program)
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| app_error("open_settings", &e.to_string()))
}

/// Přehled oprávnění aplikací (čerstvě načtený, jen čtení).
#[tauri::command]
pub async fn privacy_report(
    app: AppHandle,
) -> Result<antishield_core::privacy::PrivacyReport, ErrorDto> {
    tauri::async_runtime::spawn_blocking(move || {
        services::refresh_privacy(&app.state::<AppState>())
    })
    .await
    .map_err(|e| app_error("privacy", &e.to_string()))
}

#[tauri::command]
pub async fn update_rules_now(app: AppHandle) -> Result<RuleUpdateOutcome, ErrorDto> {
    services::update_rules(&app).await
}

#[tauri::command]
pub fn runtime_info(state: State<'_, AppState>) -> RuntimeInfo {
    state.runtime_info()
}

// ---------- Nastavení ----------

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Settings {
    state.settings()
}

#[tauri::command]
pub fn save_settings(app: AppHandle, settings: Settings) -> Result<Settings, ErrorDto> {
    let state = app.state::<AppState>();
    let before = state.settings();
    state.set_settings(settings.clone())?;
    if before.protection_enabled != settings.protection_enabled
        || before.watch_folders != settings.watch_folders
    {
        services::apply_protection(&app);
    }
    if before.launch_at_login != settings.launch_at_login {
        // Problém (např. aplikace mimo Aplikace) se ukáže v rozhraní.
        crate::apply_background_setting(&app, settings.launch_at_login);
    }
    Ok(settings)
}

/// Přidá složku k hlídání přes nativní dialog (rozhraní cesty nezadává).
#[tauri::command]
pub async fn pick_watch_folder(app: AppHandle) -> Result<Option<String>, ErrorDto> {
    let picked = app
        .dialog()
        .file()
        .set_title("Vyberte složku k hlídání")
        .blocking_pick_folder();
    Ok(picked
        .and_then(|p| p.into_path().ok())
        .filter(|p| p.is_absolute())
        .map(|p| p.display().to_string()))
}

// ---------- Aktualizace aplikace ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    pub current_version: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProgress {
    downloaded: u64,
    total: Option<u64>,
}

fn update_error(err: impl std::fmt::Display) -> ErrorDto {
    app_error("update", &err.to_string())
}

/// Zjistí, jestli je na serveru novější verze. Adresu a veřejný klíč určuje
/// tauri.conf.json, rozhraní je změnit nemůže.
#[tauri::command]
pub async fn check_update(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<UpdateInfo>, ErrorDto> {
    let update = app
        .updater()
        .map_err(update_error)?
        .check()
        .await
        .map_err(update_error)?;
    let info = update.as_ref().map(|u| UpdateInfo {
        version: u.version.clone(),
        current_version: u.current_version.clone(),
        notes: u.body.clone(),
    });
    state.set_pending_update(update);
    Ok(info)
}

/// Stáhne aktualizaci, ověří její podpis (Ed25519) a nainstaluje ji.
/// Nepodepsanou nebo poškozenou aktualizaci updater odmítne. Pak restart.
#[tauri::command]
pub async fn install_update(app: AppHandle, state: State<'_, AppState>) -> Result<(), ErrorDto> {
    if state.engine().is_ok_and(|engine| engine.is_scan_running()) {
        return Err(app_error(
            "scan_running",
            "Počkejte na konec kontroly, pak aktualizujte.",
        ));
    }
    // Aplikaci spuštěnou z DMG nebo z dočasného umístění, kam macOS přesouvá
    // nepřesunuté stažené aplikace, nejde nahradit (jen pro čtení).
    #[cfg(target_os = "macos")]
    if let Ok(exe) = std::env::current_exe()
        && crate::agent::installed_exe(&exe).is_err()
    {
        return Err(app_error(
            "update_location",
            "the app does not run from the Applications folder",
        ));
    }
    let update = state
        .take_pending_update()
        .ok_or_else(|| app_error("no_update", "Žádná aktualizace není připravená."))?;
    let progress_app = app.clone();
    let mut downloaded: u64 = 0;
    let mut last_emit: Option<Instant> = None;
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let due = last_emit.is_none_or(|t| t.elapsed() >= Duration::from_millis(100));
                if due || Some(downloaded) == total {
                    last_emit = Some(Instant::now());
                    let _ =
                        progress_app.emit("update-progress", UpdateProgress { downloaded, total });
                }
            },
            || {},
        )
        .await
        .map_err(update_error)?;
    app.restart();
}
