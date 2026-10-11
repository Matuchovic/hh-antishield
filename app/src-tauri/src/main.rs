//! H&H AntiShield – desktopová aplikace (Tauri 2).
//!
//! Backend v Rustu přímo obsahuje engine (`antishield-core`). Rozhraní ve webview
//! smí volat jen příkazy vyjmenované v `build.rs` a povolené v
//! `capabilities/default.json`. Složky ke kontrole vybírá nativní dialog zde
//! v Rustu; rozhraní nikdy neposílá vlastní cesty.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use antishield_core::{Engine, EngineConfig};
use tauri::Manager;

fn main() {
    // `antishield-app --self-test`: ověření enginu bez okna (CI, diagnostika).
    if std::env::args().any(|arg| arg == "--self-test") {
        std::process::exit(state::headless_self_test());
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let engine = Engine::new(EngineConfig::new(data_dir));
            app.manage(state::AppState::new(engine));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::engine_info,
            commands::protection_status,
            commands::run_self_test,
            commands::pick_targets,
            commands::start_scan,
            commands::cancel_scan,
            commands::recent_events,
            commands::last_summary,
            commands::check_update,
            commands::install_update,
        ])
        .run(tauri::generate_context!())
        .expect("H&H AntiShield se nepodařilo spustit");
}
