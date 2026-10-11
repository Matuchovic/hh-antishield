//! H&H AntiShield – desktopová aplikace (Tauri 2).
//!
//! Backend v Rustu přímo obsahuje engine (`antishield-core`). Rozhraní ve webview
//! smí volat jen příkazy vyjmenované v `build.rs` a povolené v
//! `capabilities/default.json`. Engine se spouští na pozadí, aby okno naskočilo
//! hned; ochrana (hlídání složek, aktualizace pravidel, plánované kontroly)
//! běží i se zavřeným oknem, dokud aplikace běží (ikona v liště).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod services;
mod settings;
mod state;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

use crate::settings::PresetScan;
use crate::state::AppState;

/// Spuštění po přihlášení: aplikace startuje skrytá v liště.
const BACKGROUND_ARG: &str = "--background";

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Otevřít H&H AntiShield", true, None::<&str>)?;
    let quick = MenuItem::with_id(app, "quick", "Rychlá kontrola", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Ukončit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quick, &quit])?;
    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("H&H AntiShield")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            "quick" => {
                show_main_window(app);
                if services::start_preset_scan(app, PresetScan::Quick).is_ok() {
                    let _ = app.emit("navigate", "scan");
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn main() {
    // `antishield-app --self-test`: ověření enginu bez okna (CI, diagnostika).
    if std::env::args().any(|arg| arg == "--self-test") {
        std::process::exit(state::headless_self_test());
    }
    // TLS pro stahování pravidel (stejný poskytovatel jako updater).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let start_hidden = std::env::args().any(|arg| arg == BACKGROUND_ARG);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![BACKGROUND_ARG]),
        ))
        .setup(move |app| {
            let data_dir = app.path().app_data_dir()?;
            app.manage(AppState::new(data_dir));
            // Lišta na macOS a Windows. Linux (jen vývoj) ji vynechá: knihovna
            // appindicator tam nemusí být a její načtení končí pádem.
            #[cfg(not(target_os = "linux"))]
            if let Err(err) = build_tray(app.handle()) {
                eprintln!("tray: {err}");
            }
            if !start_hidden {
                show_main_window(app.handle());
            }
            // Spuštění po přihlášení podle nastavení (výchozí: zapnuto).
            let wanted = app.state::<AppState>().settings().launch_at_login;
            let autostart = app.autolaunch();
            if autostart.is_enabled().unwrap_or(false) != wanted {
                let _ = if wanted {
                    autostart.enable()
                } else {
                    autostart.disable()
                };
            }
            // Engine se načítá na pozadí; pak se zapne ochrana.
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("antishield-engine-init".into())
                .spawn(move || {
                    let ready = handle.state::<AppState>().init_engine();
                    let _ = handle.emit("engine-ready", ready);
                    if ready {
                        services::apply_protection(&handle);
                        services::start_rules_updater(handle.clone());
                        services::start_scheduler(handle.clone());
                    }
                })?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let keep = window
                    .app_handle()
                    .state::<AppState>()
                    .settings()
                    .keep_running_in_background;
                if keep {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::engine_info,
            commands::protection_status,
            commands::run_self_test,
            commands::pick_targets,
            commands::start_scan,
            commands::start_preset_scan,
            commands::cancel_scan,
            commands::recent_events,
            commands::last_summary,
            commands::remediate,
            commands::quarantine_list,
            commands::quarantine_restore,
            commands::quarantine_delete,
            commands::posture_checks,
            commands::update_rules_now,
            commands::runtime_info,
            commands::get_settings,
            commands::save_settings,
            commands::pick_watch_folder,
            commands::check_update,
            commands::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("H&H AntiShield se nepodařilo spustit");

    app.run(|app, event| {
        // macOS: klik na ikonu v Docku znovu otevře skryté okno.
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Reopen { .. } = event {
            show_main_window(app);
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (app, event);
    });
}
