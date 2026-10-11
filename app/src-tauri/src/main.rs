//! H&H AntiShield – desktopová aplikace (Tauri 2).
//!
//! Backend v Rustu přímo obsahuje engine (`antishield-core`). Rozhraní ve webview
//! smí volat jen příkazy vyjmenované v `build.rs` a povolené v
//! `capabilities/default.json`. Engine se spouští na pozadí, aby okno naskočilo
//! hned. Ochrana (hlídání složek, aktualizace pravidel, plánované kontroly)
//! běží i se zavřeným oknem; na macOS ji po přihlášení spouští a po ukončení
//! obnovuje LaunchAgent (viz `agent.rs`). Úplně vypnout jde jen z lišty.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent;
mod commands;
mod instance;
mod services;
mod settings;
mod state;

use std::sync::atomic::Ordering;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::agent::BACKGROUND_ARG;
use crate::settings::PresetScan;
use crate::state::AppState;

fn show_main_window(app: &AppHandle) {
    // macOS: s otevřeným oknem má aplikace ikonu v Docku, na pozadí jen v liště.
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}

/// Úplné vypnutí ochrany: jen z lišty a po potvrzení.
fn confirm_quit(app: &AppHandle) {
    let handle = app.clone();
    app.dialog()
        .message(
            "Hlídání složek, aktualizace pravidel ani plánované kontroly nepoběží. \
             Ochrana se znovu zapne po příštím přihlášení nebo po spuštění AntiShieldu.",
        )
        .title("Vypnout ochranu a ukončit AntiShield?")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Vypnout ochranu".into(),
            "Zrušit".into(),
        ))
        .show(move |confirmed| {
            if !confirmed {
                return;
            }
            let state = handle.state::<AppState>();
            state.explicit_quit.store(true, Ordering::SeqCst);
            services::record_heartbeat(&state);
            // Agent se odhlásí, aby ho launchd hned znovu nespustil.
            #[cfg(target_os = "macos")]
            agent::launchd::stop_for_session();
            handle.exit(0);
        });
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Otevřít H&H AntiShield", true, None::<&str>)?;
    let quick = MenuItem::with_id(app, "quick", "Rychlá kontrola", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(
        app,
        "quit",
        "Vypnout ochranu a ukončit…",
        true,
        None::<&str>,
    )?;
    let menu = Menu::with_items(app, &[&open, &quick, &separator, &quit])?;
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
            "quit" => confirm_quit(app),
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

/// Menu aplikace na macOS: ⌘Q okno jen zavře, ochrana běží dál.
#[cfg(target_os = "macos")]
fn build_app_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    use tauri::menu::Submenu;
    let hide_window = MenuItem::with_id(
        app,
        "hide-window",
        "Zavřít AntiShield (ochrana běží dál)",
        true,
        Some("CmdOrCtrl+Q"),
    )?;
    let app_menu = Submenu::with_items(
        app,
        "H&H AntiShield",
        true,
        &[
            &PredefinedMenuItem::about(app, Some("O aplikaci H&H AntiShield"), None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, Some("Skrýt H&H AntiShield"))?,
            &PredefinedMenuItem::hide_others(app, Some("Skrýt ostatní"))?,
            &PredefinedMenuItem::show_all(app, Some("Zobrazit vše"))?,
            &PredefinedMenuItem::separator(app)?,
            &hide_window,
        ],
    )?;
    let edit = Submenu::with_items(
        app,
        "Úpravy",
        true,
        &[
            &PredefinedMenuItem::undo(app, Some("Zpět"))?,
            &PredefinedMenuItem::redo(app, Some("Znovu"))?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, Some("Vyjmout"))?,
            &PredefinedMenuItem::copy(app, Some("Kopírovat"))?,
            &PredefinedMenuItem::paste(app, Some("Vložit"))?,
            &PredefinedMenuItem::select_all(app, Some("Vybrat vše"))?,
        ],
    )?;
    let window = Submenu::with_items(
        app,
        "Okno",
        true,
        &[
            &PredefinedMenuItem::minimize(app, Some("Minimalizovat"))?,
            &PredefinedMenuItem::close_window(app, Some("Zavřít okno"))?,
        ],
    )?;
    Menu::with_items(app, &[&app_menu, &edit, &window])
}

/// Spuštění po přihlášení: na macOS vlastní LaunchAgent (s obnovou po
/// ukončení), jinde plugin autostart (spuštění skryté v liště).
fn sync_background(app: &AppHandle, enabled: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // Starší verze zapisovaly spuštění po přihlášení přes plugin; nahrazuje ho agent.
        let legacy = app.autolaunch();
        if legacy.is_enabled().unwrap_or(false) {
            let _ = legacy.disable();
        }
        let is_agent = app
            .state::<AppState>()
            .background_launch
            .load(Ordering::SeqCst);
        agent::launchd::sync(enabled, is_agent)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let autostart = app.autolaunch();
        if autostart.is_enabled().unwrap_or(false) == enabled {
            return Ok(());
        }
        let result = if enabled {
            autostart.enable()
        } else {
            autostart.disable()
        };
        result.map_err(|e| e.to_string())
    }
}

/// Zapíše výsledek nastavení ochrany na pozadí do stavu pro rozhraní.
pub fn apply_background_setting(app: &AppHandle, enabled: bool) {
    let problem = sync_background(app, enabled).err();
    if let Ok(mut slot) = app.state::<AppState>().background_problem.lock() {
        *slot = problem;
    }
}

fn main() {
    // `antishield-app --self-test`: ověření enginu bez okna (CI, diagnostika).
    if std::env::args().any(|arg| arg == "--self-test") {
        std::process::exit(state::headless_self_test());
    }
    // TLS pro stahování pravidel (stejný poskytovatel jako updater).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let start_hidden = std::env::args().any(|arg| arg == BACKGROUND_ARG);

    #[cfg(target_os = "macos")]
    let duplicate = match agent::launchd::data_dir() {
        Some(data_dir) => {
            // Agent: vypnutý v nastavení, nebo hned po startu opakovaně padá
            // → na tuto relaci se zastaví (launchd ho jinak spouští znovu).
            if start_hidden {
                let enabled =
                    settings::Settings::load(&data_dir.join("settings.json")).launch_at_login;
                if agent::launchd::startup_check(&data_dir, enabled).is_some() {
                    agent::launchd::stop_for_session();
                    return;
                }
            }
            // Jen jedna instance: agent počká, až předchozí skončí; ruční
            // spuštění po chvíli přenechá okno běžící instanci.
            !instance::claim(&data_dir, start_hidden)
        }
        None => false,
    };
    #[cfg(not(target_os = "macos"))]
    let duplicate = false;

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Start agenta na pozadí okno neotevírá; ruční spuštění ano.
            if !args.iter().any(|arg| arg == BACKGROUND_ARG) {
                show_main_window(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![BACKGROUND_ARG]),
        ))
        .setup(move |app| {
            // Druhá instance, kterou plugin nezachytil (souběžný start): skončí
            // dřív, než by spustila druhou ochranu.
            if duplicate {
                std::process::exit(0);
            }
            let data_dir = app.path().app_data_dir()?;
            // Restart z okna (např. po povolení přístupu) okno ukáže i agentovi.
            let show_window = !start_hidden || services::take_window_request(&data_dir);
            let state = AppState::new(data_dir);
            state
                .background_launch
                .store(start_hidden, Ordering::SeqCst);
            app.manage(state);
            #[cfg(target_os = "macos")]
            {
                let menu = build_app_menu(app.handle())?;
                app.set_menu(menu)?;
            }
            // Lišta na macOS a Windows. Linux (jen vývoj) ji vynechá: knihovna
            // appindicator tam nemusí být a její načtení končí pádem.
            #[cfg(not(target_os = "linux"))]
            if let Err(err) = build_tray(app.handle()) {
                eprintln!("tray: {err}");
            }
            if show_window {
                show_main_window(app.handle());
            } else {
                hide_main_window(app.handle());
            }
            // Ochrana na pozadí podle nastavení (výchozí: zapnuto).
            let enabled = app.state::<AppState>().settings().launch_at_login;
            apply_background_setting(app.handle(), enabled);
            #[cfg(target_os = "macos")]
            if show_window {
                // Agent se dřív zastavil po opakovaných pádech: říct to v rozhraní.
                let paused = app.state::<AppState>().data_dir.join("agent-paused");
                if std::fs::remove_file(&paused).is_ok()
                    && let Ok(mut slot) = app.state::<AppState>().background_problem.lock()
                    && slot.is_none()
                {
                    *slot = Some(agent::CRASH_LOOP.to_string());
                }
            }
            // Engine se načítá na pozadí; pak se zapne ochrana a dožene se,
            // co přibylo, když neběžela.
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
                        services::start_process_monitor(handle.clone());
                        services::start_privacy_monitor(handle.clone());
                        services::catch_up(&handle);
                    }
                })?;
            Ok(())
        })
        .on_menu_event(|app, event| {
            if event.id.as_ref() == "hide-window" {
                hide_main_window(app);
            }
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
                    hide_main_window(window.app_handle());
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
            commands::open_system_settings,
            commands::privacy_report,
            commands::update_rules_now,
            commands::runtime_info,
            commands::restart_app,
            commands::get_settings,
            commands::save_settings,
            commands::pick_watch_folder,
            commands::check_update,
            commands::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("H&H AntiShield se nepodařilo spustit");

    app.run(|app, event| match event {
        // macOS: klik na ikonu v Docku znovu otevře skryté okno.
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => show_main_window(app),
        // Ukončení (Dock, ⌘Q z jiných míst, odhlášení): ochrana se nevypíná,
        // agent ji hned obnoví. Jen vědomé vypnutí z lišty ho zastaví.
        tauri::RunEvent::Exit => {
            let state = app.state::<AppState>();
            services::record_heartbeat(&state);
            #[cfg(target_os = "macos")]
            {
                let explicit = state.explicit_quit.load(Ordering::SeqCst);
                if explicit || !state.settings().launch_at_login {
                    agent::launchd::stop_for_session();
                } else {
                    agent::launchd::ensure_running();
                }
            }
        }
        _ => {}
    });
}
