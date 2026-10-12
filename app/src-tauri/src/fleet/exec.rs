//! Provedení příkazu správce na tomto Macu. Sem se dostane jen příkaz, který
//! prošel ověřením podpisu a zásad (`member::receive`). Úklid, kontrola
//! i karanténa používají stejné cesty a pojistky jako tlačítka v okně.
//! Uživatel dostane o každém zásahu oznámení (i s vypnutými oznámeními)
//! a zásah se zapíše do auditu.

use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use antishield_core::cleanup::{CleanCategory, CleanOutcome};
use antishield_core::error::ErrorDto;
use antishield_core::fleet::{
    self as proto, Command, CommandKind, LastScan, MemoryState, ResultState, ThreatReport,
};
use antishield_core::status::{ComponentKind, ComponentState};
use antishield_core::system::{self, Machine};
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use super::member::{Approval, Outcome, ReportInput, approval_expiry};
use super::{audit, lock, post_result, runtime};
use crate::settings::PresetScan;
use crate::state::{AppState, now_ms};
use crate::story::StoryOutcome;

static MACHINE: OnceLock<Machine> = OnceLock::new();

/// Zásah správce uživatel vidí vždy, i s vypnutými oznámeními.
fn tell(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

/// „3,2 GB“ (desítková soustava jako v okně).
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    let text = if unit == 0 || value >= 100.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}").replace('.', ",").replace(",0", "")
    };
    format!("{text} {}", UNITS[unit])
}

fn category_name(category: CleanCategory) -> &'static str {
    match category {
        CleanCategory::AppCaches => "mezipaměti aplikací",
        CleanCategory::Logs => "staré protokoly",
        CleanCategory::Developer => "vývojářské mezipaměti",
        CleanCategory::Installers => "staré instalátory",
        CleanCategory::Leftovers => "zbytky po aplikacích",
        CleanCategory::LargeFiles => "velké staré soubory",
        CleanCategory::Trash => "Koš",
    }
}

/// „mezipaměti aplikací, staré protokoly a vývojářské mezipaměti“
pub fn category_list(categories: &[CleanCategory]) -> String {
    let names: Vec<&str> = categories.iter().map(|c| category_name(*c)).collect();
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} a {last}", rest.join(", ")),
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}

fn admin_name(app: &AppHandle) -> String {
    lock(&runtime(app).member)
        .as_ref()
        .map_or_else(|| "Správce firmy".to_string(), |m| m.admin_name.clone())
}

/// Najde, co jde uklidit (vlastní čerstvý sken), uklidí bezpečné položky
/// kategorií `clean` a spočítá, kolik zabírají kategorie `measure`.
fn clean_now(
    app: &AppHandle,
    clean: &[CleanCategory],
    measure: &[CleanCategory],
) -> Result<(CleanOutcome, u64), ErrorDto> {
    let scan = crate::care::fleet_scan(app)?;
    let ids: Vec<String> = proto::remote_selection(&scan, clean)
        .iter()
        .map(|item| item.id.clone())
        .collect();
    let measured = proto::remote_selection(&scan, measure)
        .iter()
        .map(|item| item.bytes)
        .sum();
    let outcome = if ids.is_empty() {
        CleanOutcome::default()
    } else {
        crate::care::fleet_clean(app, &ids)?
    };
    Ok((outcome, measured))
}

async fn clean_blocking(
    app: &AppHandle,
    clean: Vec<CleanCategory>,
    measure: Vec<CleanCategory>,
) -> Result<(CleanOutcome, u64), ErrorDto> {
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || clean_now(&worker, &clean, &measure))
        .await
        .map_err(|e| ErrorDto {
            code: "fleet_internal".into(),
            message: e.to_string(),
        })?
}

/// Provede příkaz (příkazy běží po jednom).
pub(super) async fn run(app: &AppHandle, command: Command) {
    let rt = runtime(app);
    let _one = rt.exec.lock().await;
    post_result(
        app,
        &command.id,
        ResultState::Running,
        Outcome::default(),
        None,
    )
    .await;
    let _ = app.emit("fleet-changed", ());
    match command.kind {
        CommandKind::Cleanup => cleanup(app, &command).await,
        CommandKind::Scan => scan(app, &command).await,
        CommandKind::Isolate => isolate(app, &command).await,
        CommandKind::Unenroll => unenroll(app, &command).await,
    }
    rt.report_due.store(true, Ordering::SeqCst);
    rt.member_wake.notify_one();
    let _ = app.emit("fleet-changed", ());
}

async fn cleanup(app: &AppHandle, command: &Command) {
    let rt = runtime(app);
    let Some(policy) = lock(&rt.member).as_ref().map(|m| m.policy.clone()) else {
        return;
    };
    let admin = admin_name(app);
    let (auto, consent) = policy.split(&command.categories);
    let (outcome, consent_bytes) = match clean_blocking(app, auto.clone(), consent.clone()).await {
        Ok(result) => result,
        Err(err) => {
            audit(
                app,
                "fleet_command",
                json!({ "commandId": command.id, "kind": command.kind, "state": "failed", "error": err.code }),
            );
            post_result(
                app,
                &command.id,
                ResultState::Failed,
                Outcome::default(),
                Some(&err.code),
            )
            .await;
            return;
        }
    };
    let done = Outcome {
        freed_bytes: outcome.freed_bytes,
        trashed_bytes: outcome.trashed_bytes,
        ..Outcome::default()
    };
    let total = done.freed_bytes + done.trashed_bytes;
    if total > 0 {
        tell(
            app,
            &format!("{admin} uklidil {}", format_bytes(total)),
            &format!("Úklid na dálku: {}.", category_list(&auto)),
        );
    }
    let asks = !consent.is_empty() && consent_bytes > 0;
    audit(
        app,
        "fleet_command",
        json!({
            "commandId": command.id,
            "kind": command.kind,
            "categories": command.categories,
            "state": if asks { "awaitingConsent" } else { "done" },
            "freedBytes": done.freed_bytes,
            "trashedBytes": done.trashed_bytes,
            "failed": outcome.failed.len(),
        }),
    );
    if asks {
        let now = now_ms();
        let approval = Approval {
            id: command.id.clone(),
            categories: consent.clone(),
            bytes: consent_bytes,
            requested_at_ms: now,
            expires_at_ms: approval_expiry(command, now),
            freed_bytes: done.freed_bytes,
            trashed_bytes: done.trashed_bytes,
        };
        let _ = rt.update_member(|m| m.add_approval(approval));
        tell(
            app,
            &format!("{admin} navrhuje úklid"),
            &format!(
                "{}: {}. Otevřete AntiShield a rozhodněte.",
                capitalize(&category_list(&consent)),
                format_bytes(consent_bytes)
            ),
        );
        post_result(app, &command.id, ResultState::AwaitingConsent, done, None).await;
        return;
    }
    post_result(app, &command.id, ResultState::Done, done, None).await;
}

/// Uživatel souhlasí, nebo odmítne úklid navržený správcem.
pub(super) async fn decide(app: &AppHandle, approval: Approval, approve: bool) {
    let rt = runtime(app);
    let _one = rt.exec.lock().await;
    let base = Outcome {
        freed_bytes: approval.freed_bytes,
        trashed_bytes: approval.trashed_bytes,
        ..Outcome::default()
    };
    if !approve {
        audit(
            app,
            "fleet_command",
            json!({ "commandId": approval.id, "kind": "cleanup", "state": "declined", "categories": approval.categories }),
        );
        post_result(app, &approval.id, ResultState::Declined, base, None).await;
        return;
    }
    post_result(app, &approval.id, ResultState::Running, base, None).await;
    match clean_blocking(app, approval.categories.clone(), Vec::new()).await {
        Ok((outcome, _)) => {
            let done = Outcome {
                freed_bytes: base.freed_bytes + outcome.freed_bytes,
                trashed_bytes: base.trashed_bytes + outcome.trashed_bytes,
                ..Outcome::default()
            };
            audit(
                app,
                "fleet_command",
                json!({
                    "commandId": approval.id,
                    "kind": "cleanup",
                    "state": "done",
                    "approvedByUser": true,
                    "categories": approval.categories,
                    "freedBytes": outcome.freed_bytes,
                    "trashedBytes": outcome.trashed_bytes,
                }),
            );
            post_result(app, &approval.id, ResultState::Done, done, None).await;
        }
        Err(err) => {
            post_result(
                app,
                &approval.id,
                ResultState::Failed,
                base,
                Some(&err.code),
            )
            .await;
        }
    }
    rt.report_due.store(true, Ordering::SeqCst);
    rt.member_wake.notify_one();
}

async fn scan(app: &AppHandle, command: &Command) {
    let admin = admin_name(app);
    tell(
        app,
        &format!("{admin} spustil kontrolu"),
        "Rychlá kontrola tohoto Macu na žádost správce. Běží na pozadí.",
    );
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<(u64, u64), ErrorDto> {
        let state = worker.state::<AppState>();
        let engine = state.engine()?;
        let busy_until = Instant::now() + Duration::from_secs(30 * 60);
        while engine.is_scan_running() {
            if Instant::now() > busy_until {
                return Err(ErrorDto {
                    code: "scan_busy".into(),
                    message: "another scan is still running".into(),
                });
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        let scan_id = crate::services::start_preset_scan(&worker, PresetScan::Quick)?;
        let deadline = Instant::now() + Duration::from_secs(3 * 60 * 60);
        loop {
            std::thread::sleep(Duration::from_secs(2));
            if let Some(summary) = state.last_summary()
                && summary.scan_id == scan_id
            {
                let threats = summary.findings.iter().filter(|f| !f.test_only).count();
                return Ok((summary.files_scanned, threats as u64));
            }
            if Instant::now() > deadline {
                return Err(ErrorDto {
                    code: "scan_timeout".into(),
                    message: "the scan did not finish in time".into(),
                });
            }
        }
    })
    .await;
    let (files, threats) = match result {
        Ok(Ok(done)) => done,
        Ok(Err(err)) => {
            post_result(
                app,
                &command.id,
                ResultState::Failed,
                Outcome::default(),
                Some(&err.code),
            )
            .await;
            return;
        }
        Err(_) => {
            post_result(
                app,
                &command.id,
                ResultState::Failed,
                Outcome::default(),
                Some("fleet_internal"),
            )
            .await;
            return;
        }
    };
    audit(
        app,
        "fleet_command",
        json!({ "commandId": command.id, "kind": "scan", "state": "done", "files": files, "threats": threats }),
    );
    let outcome = Outcome {
        files,
        threats,
        ..Outcome::default()
    };
    post_result(app, &command.id, ResultState::Done, outcome, None).await;
}

fn unresolved_threats(app: &AppHandle) -> Vec<String> {
    let state = app.state::<AppState>();
    let mut paths: Vec<String> = state
        .stories
        .lock()
        .map(|book| {
            book.list()
                .into_iter()
                .filter(|story| {
                    !story.finding.test_only
                        && matches!(
                            story.outcome,
                            StoryOutcome::Reported | StoryOutcome::Failed { .. }
                        )
                })
                .map(|story| story.finding.path)
                .collect()
        })
        .unwrap_or_default();
    paths.sort();
    paths.dedup();
    paths
}

async fn isolate(app: &AppHandle, command: &Command) {
    let admin = admin_name(app);
    let paths = unresolved_threats(app);
    if paths.is_empty() {
        post_result(
            app,
            &command.id,
            ResultState::Done,
            Outcome::default(),
            None,
        )
        .await;
        return;
    }
    // Stejná cesta jako tlačítko Vyčistit: nález se před izolací znovu ověří.
    match crate::commands::remediate(app.clone(), paths).await {
        Ok(reports) => {
            let isolated = reports.iter().filter(|r| r.quarantined.is_some()).count() as u64;
            if isolated > 0 {
                tell(
                    app,
                    &format!("{admin} izoloval hrozby"),
                    &format!("Do karantény: {isolated}. Soubory jde z karantény obnovit."),
                );
            }
            audit(
                app,
                "fleet_command",
                json!({ "commandId": command.id, "kind": "isolate", "state": "done", "threats": isolated }),
            );
            let outcome = Outcome {
                threats: isolated,
                ..Outcome::default()
            };
            post_result(app, &command.id, ResultState::Done, outcome, None).await;
        }
        Err(err) => {
            post_result(
                app,
                &command.id,
                ResultState::Failed,
                Outcome::default(),
                Some(&err.code),
            )
            .await;
        }
    }
}

async fn unenroll(app: &AppHandle, command: &Command) {
    let rt = runtime(app);
    post_result(
        app,
        &command.id,
        ResultState::Done,
        Outcome::default(),
        None,
    )
    .await;
    let fleet = lock(&rt.member)
        .as_ref()
        .map(|m| m.fleet_name.clone())
        .unwrap_or_default();
    rt.forget_member();
    audit(
        app,
        "fleet_left",
        json!({ "fleetName": fleet, "by": "admin" }),
    );
    tell(
        app,
        "Firemní správa skončila",
        &format!("Firma {fleet} tento Mac už nespravuje."),
    );
}

/// Údaje pro zprávu o stavu (jen to, co uživatel při připojení viděl).
pub(super) fn report_input(app: &AppHandle) -> ReportInput {
    let state = app.state::<AppState>();
    let machine = MACHINE.get_or_init(system::machine).clone();
    let protection = state.protection();
    let protection_note = protection
        .components
        .iter()
        .find(|c| c.kind == ComponentKind::RealTimeProtection)
        .and_then(|c| match &c.state {
            ComponentState::Degraded { reason } | ComponentState::Failed { reason } => {
                Some(reason.clone())
            }
            _ => None,
        });
    let engine = state.engine().ok();
    let rules_version = engine
        .as_ref()
        .map(|e| e.rules().info().version.clone())
        .unwrap_or_default();
    let rules_checked_at_ms = state
        .rules_status
        .lock()
        .ok()
        .and_then(|s| s.last_success_ms);
    let last_scan = state.last_summary().map(|summary| LastScan {
        at_ms: summary.finished_at_ms,
        files: summary.files_scanned,
        threats: summary.findings.iter().filter(|f| !f.test_only).count() as u64,
    });
    let threats = state
        .stories
        .lock()
        .map(|book| {
            book.list()
                .into_iter()
                .filter(|story| !story.finding.test_only)
                .take(proto::MAX_REPORT_THREATS)
                .map(|story| ThreatReport {
                    rule_name: story.finding.rule_name,
                    severity: story.finding.severity,
                    path: story.finding.path,
                    detected_at_ms: story.detected_at_ms,
                    quarantined: matches!(story.outcome, StoryOutcome::Quarantined { .. }),
                })
                .collect()
        })
        .unwrap_or_default();
    let quarantined = engine
        .as_ref()
        .and_then(|e| e.quarantine_items().ok())
        .map_or(0, |items| items.len() as u64);
    let vitals = system::home_dir().map(|home| antishield_core::speed::vitals(&home));
    let cleanup = crate::care::last_clean_scan(app).map(|scan| proto::cleanup_estimate(&scan));
    ReportInput {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        os_version: machine.os_version,
        model: machine.model,
        protection: protection.level,
        protection_note,
        rules_version,
        rules_checked_at_ms,
        last_scan,
        threats,
        quarantined,
        disk: vitals.and_then(|v| v.disk),
        memory: vitals.map_or(
            MemoryState {
                total: 0,
                used: 0,
                pressure: None,
            },
            |v| MemoryState {
                total: v.memory.total,
                used: v.memory.used,
                pressure: v.memory.pressure,
            },
        ),
        uptime_secs: vitals.map_or(0, |v| v.uptime_secs),
        cleanup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_categories_read_naturally_in_czech() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(540_000_000), "540 MB");
        assert_eq!(format_bytes(3_240_000_000), "3,2 GB");
        assert_eq!(format_bytes(2_000_000_000), "2 GB");
        assert_eq!(
            category_list(&[
                CleanCategory::AppCaches,
                CleanCategory::Logs,
                CleanCategory::Developer
            ]),
            "mezipaměti aplikací, staré protokoly a vývojářské mezipaměti"
        );
        assert_eq!(
            category_list(&[CleanCategory::Installers]),
            "staré instalátory"
        );
        assert_eq!(capitalize("staré instalátory"), "Staré instalátory");
    }
}
