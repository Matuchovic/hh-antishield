//! Příkazy, které smí volat rozhraní. Každý je povolený jednotlivě
//! v `capabilities/default.json`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use antishield_core::error::ErrorDto;
use antishield_core::status::ProtectionSummary;
use antishield_core::{
    AuditEvent, EngineInfo, ScanEvent, ScanObserver, ScanRequest, ScanSummary, SelfTestReport,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::state::AppState;

fn app_error(code: &str, message: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: message.to_string(),
    }
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
/// jen ID výběru a cesty k zobrazení. Na macOS dialog zároveň udělí sandboxu
/// přístup ke čtení vybraných položek.
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

/// Posílá události kontroly do okna a pamatuje si poslední souhrn.
struct EmitObserver {
    app: AppHandle,
    last_summary: Arc<Mutex<Option<ScanSummary>>>,
}

impl ScanObserver for EmitObserver {
    fn on_event(&self, event: ScanEvent) {
        if let ScanEvent::Finished { summary, .. } = &event
            && let Ok(mut last) = self.last_summary.lock()
        {
            *last = Some(summary.clone());
        }
        let _ = self.app.emit("scan-event", &event);
    }
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
        .map_err(|err| ErrorDto::from(&err))?;
    let scan_id = handle.scan_id().to_string();
    state.set_current_scan(handle);
    Ok(scan_id)
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
        .map_err(|err| ErrorDto::from(&err))
}

#[tauri::command]
pub fn last_summary(state: State<'_, AppState>) -> Option<ScanSummary> {
    state.last_summary()
}
