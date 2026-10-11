//! Služby na pozadí: aktualizace pravidel, hlídání složek, plánované kontroly
//! a oznámení. Všechny běží mimo hlavní vlákno, aby okno nesekalo.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use antishield_core::error::ErrorDto;
use antishield_core::watch::FolderWatcher;
use antishield_core::{
    InspectResult, RuleUpdateOutcome, ScanEvent, ScanObserver, ScanRequest, ScanSummary, SkipReason,
};
use chrono::{DateTime, Datelike, Local, TimeZone};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::settings::{PresetScan, Schedule};
use crate::state::{AppState, CatchUp, Detection, DetectionAction, folder_readable, now_ms};

const RULES_BASE: &str = "https://github.com/Matuchovic/hh-antishield/releases/download/rules";
const MAX_SIGNATURE_BYTES: usize = 4 * 1024;
const MAX_PACK_BYTES: usize = 64 * 1024 * 1024;
const RULES_FIRST_CHECK: Duration = Duration::from_secs(15);
const RULES_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const SCHEDULER_TICK: Duration = Duration::from_secs(60);

fn error(code: &str, message: impl Into<String>) -> ErrorDto {
    ErrorDto {
        code: code.into(),
        message: message.into(),
    }
}

/// Posílá události kontroly do okna a pamatuje si poslední souhrn.
pub struct EmitObserver {
    pub app: AppHandle,
    pub last_summary: Arc<Mutex<Option<ScanSummary>>>,
}

impl ScanObserver for EmitObserver {
    fn on_event(&self, event: ScanEvent) {
        if let ScanEvent::Finished { summary, .. } = &event {
            if let Ok(mut last) = self.last_summary.lock() {
                *last = Some(summary.clone());
            }
            let real: Vec<_> = summary.findings.iter().filter(|f| !f.test_only).collect();
            if !real.is_empty() {
                notify(
                    &self.app,
                    "Kontrola našla hrozby",
                    &format!("Nálezů: {}. Otevřete výsledky a vyčistěte je.", real.len()),
                );
            }
        }
        let _ = self.app.emit("scan-event", &event);
    }
}

/// Oznámení systému (jen když je uživatel nevypnul).
pub fn notify(app: &AppHandle, title: &str, body: &str) {
    let enabled = app.state::<AppState>().settings().notifications;
    if enabled {
        let _ = app.notification().builder().title(title).body(body).show();
    }
}

/// Spustí přednastavenou kontrolu (rychlá/úplná).
pub fn start_preset_scan(app: &AppHandle, kind: PresetScan) -> Result<String, ErrorDto> {
    let state = app.state::<AppState>();
    let engine = state.engine()?;
    let request: ScanRequest = match kind {
        PresetScan::Quick => antishield_core::system::quick_scan_request(),
        PresetScan::Full => antishield_core::system::full_scan_request(),
    };
    if request.roots.is_empty() {
        return Err(error("no_targets", "nothing to scan"));
    }
    let observer = Arc::new(EmitObserver {
        app: app.clone(),
        last_summary: state.last_summary_slot(),
    });
    let handle = engine
        .start_scan(request, observer)
        .map_err(|e| ErrorDto::from(&e))?;
    let scan_id = handle.scan_id().to_string();
    state.set_current_scan(handle);
    Ok(scan_id)
}

// ---------- Aktualizace pravidel ----------

async fn fetch(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>, ErrorDto> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| error("rules_download", e.to_string()))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(error(
            "rules_not_published",
            "rule updates are not published yet",
        ));
    }
    if !response.status().is_success() {
        return Err(error(
            "rules_download",
            format!("HTTP {}", response.status()),
        ));
    }
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| error("rules_download", e.to_string()))?
    {
        if data.len() + chunk.len() > limit {
            return Err(error("rules_download", "the download is too large"));
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

/// Stáhne podpis, a jen když se liší od aktivní sady, i sadu; engine ji ověří.
pub async fn update_rules(app: &AppHandle) -> Result<RuleUpdateOutcome, ErrorDto> {
    let state = app.state::<AppState>();
    let engine = state.engine()?;
    {
        let mut status = state
            .rules_status
            .lock()
            .map_err(|_| error("rules", "lock"))?;
        if status.checking {
            return Err(error("rules_busy", "a rule update is already running"));
        }
        status.checking = true;
    }
    let result = async {
        let client = reqwest::Client::builder()
            .user_agent(concat!("HH-AntiShield/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| error("rules_download", e.to_string()))?;
        let signature = fetch(
            &client,
            &format!("{RULES_BASE}/hh-rules.json.sig"),
            MAX_SIGNATURE_BYTES,
        )
        .await?;
        if signature == engine.rules_signature() {
            return Ok(RuleUpdateOutcome::UpToDate {
                rule_pack: engine.rules().info().clone(),
            });
        }
        let pack = fetch(
            &client,
            &format!("{RULES_BASE}/hh-rules.json"),
            MAX_PACK_BYTES,
        )
        .await?;
        let installer = engine.clone();
        tauri::async_runtime::spawn_blocking(move || installer.install_rule_pack(&pack, &signature))
            .await
            .map_err(|e| error("rules", e.to_string()))?
            .map_err(|e| ErrorDto::from(&e))
    }
    .await;

    if let Ok(mut status) = state.rules_status.lock() {
        status.checking = false;
        status.last_check_ms = Some(now_ms());
        match &result {
            Ok(_) => {
                status.last_success_ms = Some(now_ms());
                status.last_error = None;
            }
            Err(err) => status.last_error = Some(err.message.clone()),
        }
    }
    if let Ok(RuleUpdateOutcome::Installed { rule_pack }) = &result {
        let _ = app.emit("rules-updated", rule_pack);
    }
    result
}

pub fn start_rules_updater(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(RULES_FIRST_CHECK).await;
        loop {
            if app.state::<AppState>().settings().rules_auto_update {
                let _ = update_rules(&app).await;
            }
            tokio::time::sleep(RULES_INTERVAL).await;
        }
    });
}

// ---------- Hlídání složek ----------

/// Zapne, vypne nebo přenastaví hlídání podle aktuálního nastavení.
pub fn apply_protection(app: &AppHandle) {
    let state = app.state::<AppState>();
    let settings = state.settings();
    // Starý hlídač se zastaví (a počká na své vlákno) až mimo zámek: jeho
    // vlákno může právě v `on_new_files` čekat na stejný zámek.
    let previous = state
        .protection
        .lock()
        .ok()
        .and_then(|mut runtime| runtime.watcher.take());
    drop(previous);
    let enabled = settings.protection_enabled && state.engine().is_ok();
    // Čtení složky vyvolá dotaz macOS na přístup (Soubory a složky); dělá se
    // mimo zámek, aby stav v okně nečekal na odpověď uživatele. Když přístup
    // odmítne, hlídání se nevydává za funkční.
    let denied = if enabled {
        settings
            .watch_paths()
            .into_iter()
            .find(|folder| folder.is_dir() && !folder_readable(folder))
    } else {
        None
    };
    let Ok(mut runtime) = state.protection.lock() else {
        return;
    };
    runtime.started_at_ms = None;
    runtime.error = None;
    runtime.access_denied = denied;
    if !enabled {
        return;
    }
    let excluded = vec![state.data_dir.clone()];
    let handle = app.clone();
    match FolderWatcher::start(&settings.watch_paths(), excluded, move |files| {
        on_new_files(&handle, files);
    }) {
        Ok(watcher) => {
            runtime.started_at_ms = Some(now_ms());
            runtime.watcher = Some(watcher);
        }
        Err(err) => runtime.error = Some(err.to_string()),
    }
}

/// Kdy naposledy běžela ochrana (soubor v datech aplikace, ms od epochy).
const HEARTBEAT_FILE: &str = "protection-heartbeat";
/// Rezerva: soubory zapsané těsně před ukončením se zkontrolují znovu.
const HEARTBEAT_MARGIN_MS: u64 = 5 * 60 * 1000;
/// Bez záznamu (první spuštění) se kontroluje poslední den.
const FIRST_RUN_LOOKBACK_MS: u64 = 24 * 60 * 60 * 1000;
const CATCH_UP_MAX_FILES: usize = 5_000;
const CATCH_UP_MAX_VISITED: usize = 200_000;

/// Zapíše, že ochrana právě běží (volá se pravidelně a při ukončení).
pub fn record_heartbeat(state: &AppState) {
    if state.settings().protection_enabled {
        let _ = std::fs::write(state.data_dir.join(HEARTBEAT_FILE), now_ms().to_string());
    }
}

/// Od kdy dohnat kontrolu: od posledního běhu ochrany (s rezervou), poprvé den zpět.
fn catch_up_since(heartbeat: Option<u64>, now: u64) -> u64 {
    heartbeat.map_or_else(
        || now.saturating_sub(FIRST_RUN_LOOKBACK_MS),
        |last| last.saturating_sub(HEARTBEAT_MARGIN_MS),
    )
}

/// Po spuštění zkontroluje soubory, které v hlídaných složkách přibyly nebo se
/// změnily, když ochrana neběžela; nálezy se řeší stejně jako při hlídání.
pub fn catch_up(app: &AppHandle) {
    let state = app.state::<AppState>();
    let settings = state.settings();
    if !settings.protection_enabled || state.engine().is_err() {
        return;
    }
    let now = now_ms();
    let heartbeat = std::fs::read_to_string(state.data_dir.join(HEARTBEAT_FILE))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    let since = catch_up_since(heartbeat, now);
    let found = antishield_core::watch::changed_since(
        &settings.watch_paths(),
        std::slice::from_ref(&state.data_dir),
        since,
        CATCH_UP_MAX_FILES,
        CATCH_UP_MAX_VISITED,
    );
    let checked = found.files.len();
    for batch in found.files.chunks(64) {
        on_new_files(app, batch.to_vec());
    }
    if let Ok(mut last) = state.last_catch_up.lock() {
        *last = Some(CatchUp {
            at_ms: now,
            since_ms: since,
            checked,
            complete: found.complete,
        });
    }
    record_heartbeat(&state);
}

fn file_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

fn on_new_files(app: &AppHandle, files: Vec<PathBuf>) {
    let state = app.state::<AppState>();
    let Ok(engine) = state.engine() else {
        return;
    };
    let settings = state.settings();
    for (path, result) in engine.inspect_paths(&files) {
        let findings = match result {
            InspectResult::Scanned { findings, .. } => findings,
            InspectResult::Skipped(SkipReason::PermissionDenied) => {
                // Bez přístupu ke složce hlídání nic nezkontroluje: přiznat to.
                if let Ok(mut runtime) = state.protection.lock() {
                    runtime.access_denied =
                        Some(path.parent().map_or_else(|| path.clone(), PathBuf::from));
                }
                continue;
            }
            InspectResult::Skipped(_) => continue,
        };
        // Jeden zásah na soubor: první nález rozhoduje, zbytek je ve výsledcích.
        let Some(finding) = findings.into_iter().next() else {
            continue;
        };
        let action = if settings.auto_quarantine {
            let report = engine.remediate(&finding);
            match report.quarantined {
                Some(item) => DetectionAction::Quarantined { item_id: item.id },
                None => DetectionAction::Failed {
                    reason: report.problems.join("; "),
                },
            }
        } else {
            DetectionAction::Detected
        };
        let name = file_name(&finding.path);
        let (title, body) = match &action {
            DetectionAction::Quarantined { .. } => (
                "Hrozba zachycena a izolována",
                format!("{name}: {}. Soubor je v karanténě.", finding.rule_name),
            ),
            DetectionAction::Detected => (
                "Zachycena hrozba",
                format!(
                    "{name}: {}. Otevřete aplikaci a vyčistěte ho.",
                    finding.rule_name
                ),
            ),
            DetectionAction::Failed { .. } => (
                "Hrozbu se nepodařilo izolovat",
                format!("{name}: {}. Otevřete aplikaci.", finding.rule_name),
            ),
        };
        notify(app, title, &body);
        let detection = Detection {
            at_ms: now_ms(),
            finding,
            action,
        };
        let _ = app.emit("protection-event", &detection);
        state.add_detection(detection);
    }
}

// ---------- Plánované kontroly ----------

/// Poslední plánovaný okamžik (ms) nejpozději teď, v místním čase.
fn last_due_ms(schedule: Schedule, hour: u8, weekday: u8) -> Option<u64> {
    last_due_at(&Local::now(), schedule, hour, weekday)
}

/// Poslední plánovaný okamžik, který už nastal (nejvýš týden zpět).
/// `weekday`: 1 = pondělí … 7 = neděle.
fn last_due_at<Tz: TimeZone>(
    now: &DateTime<Tz>,
    schedule: Schedule,
    hour: u8,
    weekday: u8,
) -> Option<u64> {
    if schedule == Schedule::Off {
        return None;
    }
    for back in 0..8u64 {
        let date = now.date_naive() - chrono::Days::new(back);
        if schedule == Schedule::Weekly && date.weekday().number_from_monday() != u32::from(weekday)
        {
            continue;
        }
        // Neexistující čas (posun na letní čas) se přeskočí.
        let Some(at) = date
            .and_hms_opt(u32::from(hour), 0, 0)
            .and_then(|naive| now.timezone().from_local_datetime(&naive).earliest())
        else {
            continue;
        };
        if at <= *now {
            return u64::try_from(at.timestamp_millis()).ok();
        }
    }
    None
}

fn schedule_state_path(state: &AppState) -> PathBuf {
    state.data_dir.join("schedule-state.json")
}

pub fn start_scheduler(app: AppHandle) {
    std::thread::Builder::new()
        .name("antishield-schedule".into())
        .spawn(move || {
            let state = app.state::<AppState>();
            let stored = std::fs::read_to_string(schedule_state_path(&state))
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok());
            if let Ok(mut last) = state.last_scheduled_run_ms.lock() {
                *last = stored;
            }
            loop {
                std::thread::sleep(SCHEDULER_TICK);
                record_heartbeat(&state);
                let settings = state.settings();
                let Some(due) = last_due_ms(
                    settings.schedule,
                    settings.schedule_hour,
                    settings.schedule_weekday,
                ) else {
                    continue;
                };
                let last = state.last_scheduled_run_ms.lock().ok().and_then(|g| *g);
                let busy = state.engine().map(|e| e.is_scan_running()).unwrap_or(true);
                if last.is_some_and(|last| last >= due) || busy {
                    continue;
                }
                if start_preset_scan(&app, settings.schedule_scan).is_ok() {
                    let now = now_ms();
                    if let Ok(mut last) = state.last_scheduled_run_ms.lock() {
                        *last = Some(now);
                    }
                    let _ = std::fs::write(schedule_state_path(&state), now.to_string());
                    let _ = app.emit("scheduled-scan", now);
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::{FIRST_RUN_LOOKBACK_MS, HEARTBEAT_MARGIN_MS, catch_up_since, last_due_at};
    use crate::settings::Schedule;
    use chrono::{TimeZone, Utc};

    fn at(d: u32, h: u32) -> chrono::DateTime<Utc> {
        // Říjen 2026: 12. je pondělí, 14. středa.
        Utc.with_ymd_and_hms(2026, 10, d, h, 0, 0)
            .single()
            .expect("valid time")
    }

    fn ms(t: chrono::DateTime<Utc>) -> Option<u64> {
        u64::try_from(t.timestamp_millis()).ok()
    }

    #[test]
    fn daily_schedule_uses_today_once_the_hour_passed() {
        assert_eq!(
            last_due_at(&at(14, 13), Schedule::Daily, 12, 1),
            ms(at(14, 12))
        );
        assert_eq!(
            last_due_at(&at(14, 11), Schedule::Daily, 12, 1),
            ms(at(13, 12))
        );
    }

    #[test]
    fn weekly_schedule_finds_the_last_matching_weekday() {
        assert_eq!(
            last_due_at(&at(14, 13), Schedule::Weekly, 12, 1),
            ms(at(12, 12))
        );
        assert_eq!(
            last_due_at(&at(14, 11), Schedule::Weekly, 12, 3),
            ms(at(7, 12))
        );
        assert_eq!(
            last_due_at(&at(14, 12), Schedule::Weekly, 12, 3),
            ms(at(14, 12))
        );
    }

    #[test]
    fn disabled_schedule_is_never_due() {
        assert_eq!(last_due_at(&at(14, 13), Schedule::Off, 12, 3), None);
    }

    #[test]
    fn catch_up_starts_where_protection_stopped() {
        let now = 1_800_000_000_000;
        let last = now - 3_600_000;
        assert_eq!(catch_up_since(Some(last), now), last - HEARTBEAT_MARGIN_MS);
        assert_eq!(catch_up_since(None, now), now - FIRST_RUN_LOOKBACK_MS);
    }
}
