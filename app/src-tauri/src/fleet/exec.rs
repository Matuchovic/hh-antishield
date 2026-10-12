//! Provedení příkazu správce na tomto Macu. Sem se dostane jen příkaz, který
//! prošel ověřením podpisu a zásad (`member::receive`). Úklid, kontrola,
//! karanténa i aktualizace používají stejné cesty a pojistky jako tlačítka
//! v okně. Restart, ukončení aplikací, soubory uživatele, Koš a rozšíření
//! zásad jdou jen přes souhlas uživatele (`decide`). Uživatel dostane
//! o každém zásahu oznámení (i s vypnutými oznámeními) a zásah se zapíše do
//! auditu.

use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use antishield_core::cleanup::{CleanCategory, CleanMethod, CleanOutcome, CleanScan};
use antishield_core::error::ErrorDto;
use antishield_core::fleet::{
    self as proto, CONSENT_ONLY, Command, CommandKind, EventReport, LastScan, MemoryState,
    QuarantineReport, ResultState, RunningApp, ShareScope, ThreatReport,
};
use antishield_core::inventory;
use antishield_core::speed::{self, QuitOutcome};
use antishield_core::status::{ComponentKind, ComponentState};
use antishield_core::system::{self, Machine};
use serde::Deserialize;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::UpdaterExt;

use super::member::{Approval, ApprovalApp, ApprovalKind, Outcome, ReportInput, approval_expiry};
use super::{audit, lock, post_result, runtime};
use crate::settings::PresetScan;
use crate::state::{AppState, now_ms};
use crate::story::StoryOutcome;

static MACHINE: OnceLock<Machine> = OnceLock::new();

/// Restart jde odložit nejvýš o den.
const MAX_SNOOZE_MINUTES: u32 = 24 * 60;

/// Co uživatel v žádosti správce vybral. Bez výběru platí celá žádost.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Choice {
    /// Úklid: kategorie se souhlasem, které uklidit.
    #[serde(default)]
    pub categories: Option<Vec<CleanCategory>>,
    /// Úklid: vybrané velké soubory (identifikátory položek skenu).
    #[serde(default)]
    pub items: Vec<String>,
    /// Aplikace k zavření (hloubkový úklid) nebo k ukončení.
    #[serde(default)]
    pub apps: Option<Vec<String>>,
    /// Restart: odložit o tolik minut.
    #[serde(default)]
    pub snooze_minutes: Option<u32>,
}

/// Zásah správce uživatel vidí vždy, i s vypnutými oznámeními.
fn tell(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

fn internal(err: impl std::fmt::Display) -> ErrorDto {
    ErrorDto {
        code: "fleet_internal".into(),
        message: err.to_string(),
    }
}

/// Práce mimo asynchronní vlákno (sken disku, procesy, systémové nástroje).
async fn blocking<T: Send + 'static>(
    app: &AppHandle,
    work: impl FnOnce(&AppHandle) -> Result<T, ErrorDto> + Send + 'static,
) -> Result<T, ErrorDto> {
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || work(&worker))
        .await
        .map_err(internal)?
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

/// „A, B a C“
fn join_list(names: &[String]) -> String {
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} a {last}", rest.join(", ")),
    }
}

/// „mezipaměti aplikací, staré protokoly a vývojářské mezipaměti“
pub fn category_list(categories: &[CleanCategory]) -> String {
    let names: Vec<String> = categories
        .iter()
        .map(|c| category_name(*c).to_string())
        .collect();
    join_list(&names)
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

fn own_pid() -> u32 {
    std::process::id()
}

/// Běžící aplikace s identifikátorem (pro hloubkový úklid).
fn running_apps() -> Vec<RunningApp> {
    speed::running_apps(own_pid())
        .into_iter()
        .filter_map(|app| {
            Some(RunningApp {
                id: app.bundle_id?,
                name: app.name,
            })
        })
        .collect()
}

fn ids_of(items: &[&antishield_core::cleanup::CleanItem]) -> Vec<String> {
    items.iter().map(|item| item.id.clone()).collect()
}

/// Kolik zabírá kategorie se souhlasem: u souborů uživatele a Koše všechno
/// (vybírá uživatel), jinak předvybrané položky.
fn consent_bytes(scan: &CleanScan, category: CleanCategory) -> u64 {
    scan.items
        .iter()
        .filter(|i| i.category == category && (CONSENT_ONLY.contains(&category) || i.recommended))
        .map(|i| i.bytes)
        .sum()
}

/// Co úklid najde: položky ke smazání hned a co čeká na souhlas.
#[derive(Debug, Default)]
struct CleanPlan {
    now: Vec<String>,
    consent: Vec<(CleanCategory, u64)>,
    apps: Vec<ApprovalApp>,
}

fn plan_cleanup(
    scan: &CleanScan,
    deep: bool,
    auto: &[CleanCategory],
    consent: &[CleanCategory],
) -> CleanPlan {
    let mut plan = CleanPlan::default();
    if deep {
        let running = running_apps();
        let deep_plan = proto::deep_plan(scan, auto, &running, now_ms());
        plan.now = ids_of(&deep_plan.now);
        plan.apps = deep_plan
            .apps
            .iter()
            .map(|a| ApprovalApp {
                id: a.id.clone(),
                name: a.name.clone(),
                bytes: 0,
                items: Vec::new(),
            })
            .collect();
        for item in &deep_plan.with_apps {
            if let Some(owner) = proto::cache_owner(&item.name, &running)
                && let Some(entry) = plan.apps.iter_mut().find(|a| a.id == owner.id)
            {
                entry.bytes += item.bytes;
                entry.items.push(item.id.clone());
            }
        }
    } else {
        plan.now = ids_of(&proto::remote_selection(scan, auto));
    }
    plan.consent = consent
        .iter()
        .map(|c| (*c, consent_bytes(scan, *c)))
        .filter(|(_, bytes)| *bytes > 0)
        .collect();
    plan
}

fn clean_ids(app: &AppHandle, ids: &[String]) -> Result<CleanOutcome, ErrorDto> {
    if ids.is_empty() {
        return Ok(CleanOutcome::default());
    }
    crate::care::fleet_clean(app, ids)
}

async fn fail(app: &AppHandle, command: &Command, base: Outcome, code: &str) {
    audit(
        app,
        "fleet_command",
        json!({ "commandId": command.id, "kind": command.kind, "state": "failed", "error": code }),
    );
    post_result(app, &command.id, ResultState::Failed, base, Some(code)).await;
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
        CommandKind::Restart => ask(app, &command, ApprovalKind::Restart).await,
        CommandKind::Policy => ask(app, &command, ApprovalKind::Policy).await,
        CommandKind::QuitApps => quit_request(app, &command).await,
        CommandKind::Update => update(app, &command).await,
        CommandKind::DeleteQuarantine => delete_quarantine(app, &command).await,
    }
    rt.report_due.store(true, Ordering::SeqCst);
    rt.member_wake.notify_one();
    let _ = app.emit("fleet-changed", ());
}

/// Shrnutí žádosti o souhlas s úklidem pro oznámení.
fn consent_summary(approval: &Approval) -> String {
    let mut parts = Vec::new();
    if !approval.categories.is_empty() {
        parts.push(capitalize(&category_list(&approval.categories)));
    }
    if !approval.apps.is_empty() {
        let names: Vec<String> = approval.apps.iter().map(|a| a.name.clone()).collect();
        parts.push(format!("zavřít {}", join_list(&names)));
    }
    format!("{}, {}", parts.join("; "), format_bytes(approval.bytes))
}

async fn cleanup(app: &AppHandle, command: &Command) {
    let rt = runtime(app);
    let Some(policy) = lock(&rt.member).as_ref().map(|m| m.policy.clone()) else {
        return;
    };
    let admin = admin_name(app);
    let (auto, consent) = policy.split(&command.categories);
    let deep = command.deep;
    let (work_auto, work_consent) = (auto.clone(), consent.clone());
    let result = blocking(app, move |app| {
        let scan = crate::care::fleet_scan(app)?;
        let plan = plan_cleanup(&scan, deep, &work_auto, &work_consent);
        let outcome = clean_ids(app, &plan.now)?;
        Ok((outcome, plan))
    })
    .await;
    let (outcome, plan) = match result {
        Ok(done) => done,
        Err(err) => return fail(app, command, Outcome::default(), &err.code).await,
    };
    let done = Outcome::bytes(outcome.freed_bytes, outcome.trashed_bytes);
    let total = done.freed_bytes + done.trashed_bytes;
    if total > 0 {
        tell(
            app,
            &format!("{admin} uklidil {}", format_bytes(total)),
            &format!(
                "{}: {}.",
                if deep {
                    "Hloubkový úklid na dálku"
                } else {
                    "Úklid na dálku"
                },
                category_list(&auto)
            ),
        );
    }
    let asks = !plan.consent.is_empty() || !plan.apps.is_empty();
    audit(
        app,
        "fleet_command",
        json!({
            "commandId": command.id,
            "kind": command.kind,
            "deep": deep,
            "categories": command.categories,
            "state": if asks { "awaitingConsent" } else { "done" },
            "freedBytes": done.freed_bytes,
            "trashedBytes": done.trashed_bytes,
            "failed": outcome.failed.len(),
        }),
    );
    if !asks {
        post_result(app, &command.id, ResultState::Done, done, None).await;
        return;
    }
    let now = now_ms();
    let mut approval = Approval::new(
        &command.id,
        ApprovalKind::Cleanup,
        now,
        approval_expiry(command, now),
    );
    approval.categories = plan.consent.iter().map(|(c, _)| *c).collect();
    approval.bytes = plan.consent.iter().map(|(_, b)| *b).sum::<u64>()
        + plan.apps.iter().map(|a| a.bytes).sum::<u64>();
    approval.freed_bytes = done.freed_bytes;
    approval.trashed_bytes = done.trashed_bytes;
    approval.apps = plan.apps;
    let summary = consent_summary(&approval);
    let _ = rt.update_member(|m| m.add_approval(approval));
    tell(
        app,
        &format!(
            "{admin} navrhuje {}",
            if deep { "hloubkový úklid" } else { "úklid" }
        ),
        &format!("{summary}. Otevřete AntiShield a vyberte, co uklidit."),
    );
    post_result(app, &command.id, ResultState::AwaitingConsent, done, None).await;
}

/// Žádost, o které rozhodne uživatel (restart, nové zásady).
async fn ask(app: &AppHandle, command: &Command, kind: ApprovalKind) {
    let rt = runtime(app);
    let admin = admin_name(app);
    let now = now_ms();
    let mut approval = Approval::new(&command.id, kind, now, approval_expiry(command, now));
    approval.policy = command.policy.clone();
    let _ = rt.update_member(|m| m.add_approval(approval));
    match kind {
        ApprovalKind::Restart => tell(
            app,
            &format!("{admin} žádá o restart"),
            "Uložte si rozdělanou práci. V AntiShieldu restartujete teď, nebo ho odložíte.",
        ),
        ApprovalKind::Policy => tell(
            app,
            &format!("{admin} žádá o rozšířenou správu"),
            "Otevřete AntiShield: uvidíte, co by správce navíc viděl a smí, a rozhodnete.",
        ),
        ApprovalKind::Cleanup | ApprovalKind::QuitApps => {}
    }
    audit(
        app,
        "fleet_command",
        json!({ "commandId": command.id, "kind": command.kind, "state": "awaitingConsent" }),
    );
    post_result(
        app,
        &command.id,
        ResultState::AwaitingConsent,
        Outcome::default(),
        None,
    )
    .await;
}

/// Žádost o ukončení aplikací: jen ty, které opravdu běží.
async fn quit_request(app: &AppHandle, command: &Command) {
    let rt = runtime(app);
    let admin = admin_name(app);
    let targets = command.targets.clone();
    let found = blocking(app, move |_| {
        Ok(speed::running_apps(own_pid())
            .into_iter()
            .filter_map(|a| {
                let id = a.bundle_id.filter(|id| targets.contains(id))?;
                Some(ApprovalApp {
                    id,
                    name: a.name,
                    bytes: a.memory,
                    items: Vec::new(),
                })
            })
            .collect::<Vec<_>>())
    })
    .await
    .unwrap_or_default();
    if found.is_empty() {
        audit(
            app,
            "fleet_command",
            json!({ "commandId": command.id, "kind": command.kind, "state": "done", "count": 0 }),
        );
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
    let names: Vec<String> = found.iter().map(|a| a.name.clone()).collect();
    let now = now_ms();
    let mut approval = Approval::new(
        &command.id,
        ApprovalKind::QuitApps,
        now,
        approval_expiry(command, now),
    );
    approval.bytes = found.iter().map(|a| a.bytes).sum();
    approval.apps = found;
    let _ = rt.update_member(|m| m.add_approval(approval));
    tell(
        app,
        &format!("{admin} navrhuje ukončit aplikace"),
        &format!(
            "{}. Aplikace se zeptají na uložení práce. Otevřete AntiShield a rozhodněte.",
            join_list(&names)
        ),
    );
    audit(
        app,
        "fleet_command",
        json!({ "commandId": command.id, "kind": command.kind, "state": "awaitingConsent" }),
    );
    post_result(
        app,
        &command.id,
        ResultState::AwaitingConsent,
        Outcome::default(),
        None,
    )
    .await;
}

/// Připomene žádosti, kterým skončil odklad (restart).
pub(super) fn remind(app: &AppHandle, due: &[Approval]) {
    let admin = admin_name(app);
    for approval in due {
        if approval.kind == ApprovalKind::Restart {
            tell(
                app,
                &format!("{admin} stále žádá o restart"),
                "Uložte si práci a restartujte, nebo restart v AntiShieldu znovu odložte.",
            );
        }
    }
}

/// Uživatel rozhodl o žádosti správce.
pub(super) async fn decide(app: &AppHandle, approval: Approval, approve: bool, choice: Choice) {
    let rt = runtime(app);
    let _one = rt.exec.lock().await;
    let base = Outcome::bytes(approval.freed_bytes, approval.trashed_bytes);
    if !approve {
        audit(
            app,
            "fleet_command",
            json!({ "commandId": approval.id, "kind": approval.kind, "state": "declined", "categories": approval.categories }),
        );
        post_result(app, &approval.id, ResultState::Declined, base, None).await;
    } else {
        match approval.kind {
            ApprovalKind::Cleanup => decide_cleanup(app, &approval, &choice, base).await,
            ApprovalKind::Restart => decide_restart(app, approval, &choice).await,
            ApprovalKind::QuitApps => decide_quit(app, &approval, &choice).await,
            ApprovalKind::Policy => decide_policy(app, &approval).await,
        }
    }
    rt.report_due.store(true, Ordering::SeqCst);
    rt.member_wake.notify_one();
}

fn chosen_apps(approval: &Approval, choice: &Choice) -> Vec<ApprovalApp> {
    approval
        .apps
        .iter()
        .filter(|a| {
            choice
                .apps
                .as_ref()
                .is_none_or(|chosen| chosen.contains(&a.id))
        })
        .cloned()
        .collect()
}

async fn decide_cleanup(app: &AppHandle, approval: &Approval, choice: &Choice, base: Outcome) {
    post_result(app, &approval.id, ResultState::Running, base.clone(), None).await;
    let categories: Vec<CleanCategory> = approval
        .categories
        .iter()
        .copied()
        .filter(|c| {
            choice
                .categories
                .as_ref()
                .is_none_or(|chosen| chosen.contains(c))
        })
        .collect();
    let apps = chosen_apps(approval, choice);
    let items = choice.items.clone();
    let work_categories = categories.clone();
    let result = blocking(app, move |app| {
        approved_cleanup(app, &work_categories, &items, &apps)
    })
    .await;
    match result {
        Ok((outcome, closed)) => {
            let done = Outcome {
                freed_bytes: base.freed_bytes + outcome.freed_bytes,
                trashed_bytes: base.trashed_bytes + outcome.trashed_bytes,
                count: closed.len() as u64,
                note: (!closed.is_empty()).then(|| join_list(&closed)),
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
                    "categories": categories,
                    "count": closed.len(),
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
}

/// Úklid, který uživatel potvrdil: kategorie se souhlasem, jím vybrané velké
/// soubory, Koš a mezipaměti aplikací, které dovolil zavřít.
fn approved_cleanup(
    app: &AppHandle,
    categories: &[CleanCategory],
    items: &[String],
    apps: &[ApprovalApp],
) -> Result<(CleanOutcome, Vec<String>), ErrorDto> {
    // Aplikace se ukončí běžně (zeptají se na uložení práce).
    let mut closed = Vec::new();
    if !apps.is_empty() {
        let running = speed::running_apps(own_pid());
        for wanted in apps {
            match running
                .iter()
                .find(|r| r.bundle_id.as_deref() == Some(wanted.id.as_str()))
            {
                None => closed.push(wanted.name.clone()),
                Some(target) => {
                    if matches!(
                        speed::quit_process(target, own_pid()),
                        Ok(QuitOutcome::Quit)
                    ) {
                        closed.push(wanted.name.clone());
                    }
                }
            }
        }
    }
    let scan = crate::care::fleet_scan(app)?;
    let running_now = running_apps();
    let mut outcome = CleanOutcome::default();
    // Koš nejdřív: soubory, které se teď přesunou do Koše, jde ještě vrátit.
    if categories.contains(&CleanCategory::Trash) {
        let trash: Vec<String> = scan
            .items
            .iter()
            .filter(|i| i.category == CleanCategory::Trash && i.method == CleanMethod::EmptyTrash)
            .map(|i| i.id.clone())
            .collect();
        if !trash.is_empty() {
            outcome = crate::care::fleet_clean_approved(app, &trash, true)?;
        }
    }
    let plain: Vec<CleanCategory> = categories
        .iter()
        .copied()
        .filter(|c| !CONSENT_ONLY.contains(c))
        .collect();
    let mut ids = ids_of(&proto::remote_selection(&scan, &plain));
    if categories.contains(&CleanCategory::LargeFiles) {
        ids.extend(
            scan.items
                .iter()
                .filter(|i| i.category == CleanCategory::LargeFiles && items.contains(&i.id))
                .map(|i| i.id.clone()),
        );
    }
    let approved: Vec<String> = apps.iter().flat_map(|a| a.items.iter().cloned()).collect();
    ids.extend(ids_of(&proto::deep_after_close(
        &scan,
        &approved,
        &running_now,
    )));
    ids.sort();
    ids.dedup();
    if !ids.is_empty() {
        let rest = crate::care::fleet_clean_approved(app, &ids, false)?;
        outcome.freed_bytes += rest.freed_bytes;
        outcome.trashed_bytes += rest.trashed_bytes;
        outcome.cleaned.extend(rest.cleaned);
        outcome.failed.extend(rest.failed);
    }
    Ok((outcome, closed))
}

async fn decide_restart(app: &AppHandle, approval: Approval, choice: &Choice) {
    let rt = runtime(app);
    let id = approval.id.clone();
    if let Some(minutes) = choice.snooze_minutes {
        let minutes = minutes.clamp(5, MAX_SNOOZE_MINUTES);
        let until = (now_ms() + u64::from(minutes) * 60_000).min(approval.expires_at_ms);
        let _ = rt.update_member(|m| m.snooze(approval, until));
        audit(
            app,
            "fleet_command",
            json!({ "commandId": id, "kind": "restart", "state": "snoozed", "untilMs": until }),
        );
        let outcome = Outcome {
            until_ms: Some(until),
            ..Outcome::default()
        };
        post_result(app, &id, ResultState::AwaitingConsent, outcome, None).await;
        return;
    }
    audit(
        app,
        "fleet_command",
        json!({ "commandId": id, "kind": "restart", "state": "done", "approvedByUser": true }),
    );
    // Výsledek musí odejít dřív, než se Mac restartuje.
    post_result(app, &id, ResultState::Done, Outcome::default(), None).await;
    let restarted = blocking(app, |_| {
        system::request_restart().map_err(|err| ErrorDto {
            code: if err.to_string().contains("automation") {
                "fleet_automation".into()
            } else {
                "fleet_restart_failed".into()
            },
            message: err.to_string(),
        })
    })
    .await;
    if let Err(err) = restarted {
        post_result(
            app,
            &id,
            ResultState::Failed,
            Outcome::default(),
            Some(&err.code),
        )
        .await;
        tell(
            app,
            "Restart se nepovedl",
            "Restartujte Mac z nabídky Apple. Pokud se systém ptal, jestli AntiShield smí ovládat Finder, povolte to.",
        );
    }
}

async fn decide_quit(app: &AppHandle, approval: &Approval, choice: &Choice) {
    post_result(
        app,
        &approval.id,
        ResultState::Running,
        Outcome::default(),
        None,
    )
    .await;
    let wanted = chosen_apps(approval, choice);
    let result = blocking(app, move |_| {
        let running = speed::running_apps(own_pid());
        let mut quit = Vec::new();
        for app in &wanted {
            let done = match running
                .iter()
                .find(|r| r.bundle_id.as_deref() == Some(app.id.as_str()))
            {
                None => true,
                Some(target) => matches!(
                    speed::quit_process(target, own_pid()),
                    Ok(QuitOutcome::Quit)
                ),
            };
            if done {
                quit.push(app.name.clone());
            }
        }
        Ok(quit)
    })
    .await
    .unwrap_or_default();
    audit(
        app,
        "fleet_command",
        json!({ "commandId": approval.id, "kind": "quitApps", "state": "done", "approvedByUser": true, "count": result.len() }),
    );
    let outcome = Outcome {
        count: result.len() as u64,
        note: (!result.is_empty()).then(|| join_list(&result)),
        ..Outcome::default()
    };
    post_result(app, &approval.id, ResultState::Done, outcome, None).await;
}

async fn decide_policy(app: &AppHandle, approval: &Approval) {
    let rt = runtime(app);
    let accepted = approval.policy.clone().and_then(|policy| {
        rt.update_member(|m| m.accept_policy(policy.clone()).map(|()| policy))
            .ok()
            .flatten()
            .and_then(Result::ok)
    });
    match accepted {
        Some(policy) => {
            audit(
                app,
                "fleet_command",
                json!({ "commandId": approval.id, "kind": "policy", "state": "done", "approvedByUser": true, "policy": policy }),
            );
            post_result(
                app,
                &approval.id,
                ResultState::Done,
                Outcome::default(),
                None,
            )
            .await;
        }
        None => {
            post_result(
                app,
                &approval.id,
                ResultState::Failed,
                Outcome::default(),
                Some("fleet_malformed"),
            )
            .await;
        }
    }
}

/// Počká, než doběhne kontrola spuštěná jinde (nejvýš `limit`).
fn wait_for_scans(state: &AppState, limit: Duration) -> Result<(), ErrorDto> {
    let engine = state.engine()?;
    let until = Instant::now() + limit;
    while engine.is_scan_running() {
        if Instant::now() > until {
            return Err(ErrorDto {
                code: "scan_busy".into(),
                message: "another scan is still running".into(),
            });
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

async fn scan(app: &AppHandle, command: &Command) {
    let admin = admin_name(app);
    let full = command.full;
    tell(
        app,
        &format!(
            "{admin} spustil {}",
            if full { "úplnou kontrolu" } else { "kontrolu" }
        ),
        if full {
            "Úplná kontrola celého disku na žádost správce. Běží na pozadí a může trvat déle."
        } else {
            "Rychlá kontrola tohoto Macu na žádost správce. Běží na pozadí."
        },
    );
    let result = blocking(app, move |worker| {
        let state = worker.state::<AppState>();
        wait_for_scans(&state, Duration::from_secs(30 * 60))?;
        let preset = if full {
            PresetScan::Full
        } else {
            PresetScan::Quick
        };
        let scan_id = crate::services::start_preset_scan(worker, preset)?;
        let hours = if full { 8 } else { 3 };
        let deadline = Instant::now() + Duration::from_secs(hours * 60 * 60);
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
        Ok(done) => done,
        Err(err) => return fail(app, command, Outcome::default(), &err.code).await,
    };
    audit(
        app,
        "fleet_command",
        json!({ "commandId": command.id, "kind": "scan", "full": full, "state": "done", "files": files, "threats": threats }),
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
        Err(err) => fail(app, command, Outcome::default(), &err.code).await,
    }
}

async fn delete_quarantine(app: &AppHandle, command: &Command) {
    let admin = admin_name(app);
    let ids = command.targets.clone();
    let result = blocking(app, move |worker| {
        let engine = worker.state::<AppState>().engine()?;
        Ok(ids
            .iter()
            .filter(|id| engine.delete_quarantined(id).is_ok())
            .count() as u64)
    })
    .await;
    let deleted = match result {
        Ok(count) => count,
        Err(err) => return fail(app, command, Outcome::default(), &err.code).await,
    };
    let _ = app.emit("quarantine-changed", ());
    if deleted > 0 {
        tell(
            app,
            &format!("{admin} vysypal karanténu"),
            &format!("Smazáno z karantény: {deleted}. Tyto soubory už nejde obnovit."),
        );
    }
    audit(
        app,
        "fleet_command",
        json!({ "commandId": command.id, "kind": "deleteQuarantine", "state": "done", "count": deleted }),
    );
    let outcome = Outcome {
        count: deleted,
        ..Outcome::default()
    };
    post_result(app, &command.id, ResultState::Done, outcome, None).await;
}

/// Aktualizace pravidel a AntiShieldu. Aplikace se aktualizuje jen
/// podepsaným vydáním (podpis ověří updater) a pak se sama restartuje.
async fn update(app: &AppHandle, command: &Command) {
    let admin = admin_name(app);
    // Pravidla: chyba (např. právě běžící aktualizace) aktualizaci aplikace nebrání.
    let _ = crate::services::update_rules(app).await;
    let found = match app.updater() {
        Ok(updater) => updater.check().await.map_err(|e| e.to_string()),
        Err(err) => Err(err.to_string()),
    };
    let update = match found {
        Ok(Some(update)) => update,
        Ok(None) => {
            audit(
                app,
                "fleet_command",
                json!({ "commandId": command.id, "kind": "update", "state": "done", "count": 0 }),
            );
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
        Err(_) => return fail(app, command, Outcome::default(), "update").await,
    };
    if !crate::commands::update_location_ok() {
        return fail(app, command, Outcome::default(), "update_location").await;
    }
    let ready = blocking(app, |worker| {
        wait_for_scans(&worker.state::<AppState>(), Duration::from_secs(30 * 60))
    })
    .await;
    if let Err(err) = ready {
        return fail(app, command, Outcome::default(), &err.code).await;
    }
    let bytes = match update.download(|_, _| {}, || {}).await {
        Ok(bytes) => bytes,
        Err(_) => return fail(app, command, Outcome::default(), "update").await,
    };
    let version = update.version.clone();
    audit(
        app,
        "fleet_command",
        json!({ "commandId": command.id, "kind": "update", "state": "done", "count": 1, "version": version }),
    );
    // Výsledek odejde před instalací (aplikace se po ní restartuje).
    let outcome = Outcome {
        count: 1,
        note: Some(version.clone()),
        ..Outcome::default()
    };
    post_result(app, &command.id, ResultState::Done, outcome, None).await;
    tell(
        app,
        &format!("{admin} aktualizuje AntiShield"),
        &format!(
            "Instaluje se verze {version}. Aplikace se na chvíli zavře a ochrana se hned obnoví."
        ),
    );
    if update.install(bytes).is_err() {
        return fail(app, command, Outcome::default(), "update").await;
    }
    app.restart();
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

/// Druhy událostí auditu pro správce a údaje, které z nich smí odejít.
/// Seznamy uklizených položek ani jiné cesty mimo hrozby neodcházejí.
const EVENT_FIELDS: [(&str, &[&str]); 12] = [
    ("finding", &["path", "ruleId", "source"]),
    ("quarantined", &["path", "ruleId", "sha256"]),
    ("quarantine_restored", &["path"]),
    ("quarantine_deleted", &["path"]),
    ("quarantine_failed", &["path", "code"]),
    ("scan_finished", &["outcome", "filesScanned", "findings"]),
    ("rule_pack_installed", &["version"]),
    ("rule_pack_rejected", &["code", "source"]),
    ("audit_integrity_issue", &["detail", "sealed"]),
    (
        "fleet_command",
        &[
            "kind",
            "state",
            "deep",
            "full",
            "freedBytes",
            "trashedBytes",
            "threats",
            "files",
            "count",
            "approvedByUser",
        ],
    ),
    ("cleanup", &["source", "freedBytes", "trashedBytes"]),
    ("self_test", &["passed"]),
];

/// Událost auditu pro správce: jen vybrané druhy a krátké údaje.
fn event_for_admin(event: &antishield_core::types::AuditEvent) -> Option<EventReport> {
    let (_, fields) = EVENT_FIELDS.iter().find(|(kind, _)| *kind == event.kind)?;
    let source = event.data.as_object()?;
    // Testovací nálezy a prošlé self-testy jsou šum.
    if source.get("testOnly").and_then(serde_json::Value::as_bool) == Some(true)
        || (event.kind == "self_test"
            && source.get("passed").and_then(serde_json::Value::as_bool) != Some(false))
    {
        return None;
    }
    let mut data = serde_json::Map::new();
    for field in *fields {
        if let Some(value) = source.get(*field)
            && value.to_string().chars().count() <= 300
        {
            data.insert((*field).to_string(), value.clone());
        }
    }
    let data = serde_json::Value::Object(data);
    (data.to_string().chars().count() <= 580).then(|| EventReport {
        kind: event.kind.clone(),
        at_ms: event.ts_ms,
        data,
    })
}

/// Údaje pro zprávu o stavu. Podrobnosti rozšířené správy se zjišťují jen
/// tehdy, když je uživatel sdílí.
pub(super) fn report_input(app: &AppHandle) -> ReportInput {
    let state = app.state::<AppState>();
    let policy = lock(&runtime(app).member)
        .as_ref()
        .map(|m| m.policy.clone())
        .unwrap_or_else(proto::Policy::basic);
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
    let quarantine_items = engine
        .as_ref()
        .and_then(|e| e.quarantine_items().ok())
        .unwrap_or_default();
    let vitals = system::home_dir().map(|home| speed::vitals(&home));
    let cleanup = crate::care::last_clean_scan(app)
        .map(|scan| proto::cleanup_estimate(&scan, &running_apps(), now_ms()));
    let threats_shared = policy.shares(ShareScope::Threats);
    let mut quarantine: Vec<QuarantineReport> = if threats_shared {
        quarantine_items
            .iter()
            .filter(|item| !item.test_only)
            .map(|item| QuarantineReport {
                id: item.id.clone(),
                path: item.original_path.chars().take(1024).collect(),
                rule_name: item.rule_name.chars().take(200).collect(),
                severity: item.severity,
                at_ms: item.quarantined_at_ms,
                size: item.size,
                sha256: item.sha256.chars().take(64).collect(),
            })
            .collect()
    } else {
        Vec::new()
    };
    quarantine.sort_by_key(|q| std::cmp::Reverse(q.at_ms));
    let events = if threats_shared {
        engine
            .as_ref()
            .and_then(|e| e.recent_audit_events(300).ok())
            .unwrap_or_default()
            .iter()
            .filter_map(event_for_admin)
            .take(proto::MAX_REPORT_EVENTS)
            .collect()
    } else {
        Vec::new()
    };
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
        quarantined: quarantine_items.iter().filter(|i| !i.test_only).count() as u64,
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
        hardware: if policy.shares(ShareScope::Hardware) {
            inventory::hardware()
        } else {
            None
        },
        security: policy
            .shares(ShareScope::Security)
            .then(|| inventory::security(antishield_core::privacy::full_disk_access())),
        performance: if policy.shares(ShareScope::Performance) {
            crate::care::measure(app)
                .ok()
                .map(|report| inventory::performance(&report))
        } else {
            None
        },
        quarantine,
        events,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

    #[test]
    fn audit_events_leave_only_whitelisted_short_fields() {
        use antishield_core::types::AuditEvent;
        let event = |kind: &str, data: serde_json::Value| AuditEvent {
            seq: 1,
            ts_ms: 5,
            kind: kind.into(),
            data,
        };
        let cleaned = event(
            "cleanup",
            json!({ "source": "user", "freedBytes": 9, "cleaned": [{ "path": "/Users/jana/Documents/smlouva.pdf" }] }),
        );
        let out = event_for_admin(&cleaned).unwrap();
        assert_eq!(out.data, json!({ "source": "user", "freedBytes": 9 }));
        assert!(!out.data.to_string().contains("smlouva"));
        // Jiné druhy událostí (např. připojení k firmě) neodcházejí vůbec.
        assert!(event_for_admin(&event("fleet_joined", json!({ "fleetName": "X" }))).is_none());
        // Testovací nález a prošlý self-test jsou šum.
        assert!(
            event_for_admin(&event("finding", json!({ "path": "/x", "testOnly": true }))).is_none()
        );
        assert!(event_for_admin(&event("self_test", json!({ "passed": true }))).is_none());
        assert!(event_for_admin(&event("self_test", json!({ "passed": false }))).is_some());
        // Dlouhé hodnoty se vynechají.
        let long = event(
            "quarantined",
            json!({ "path": "x".repeat(400), "ruleId": "R" }),
        );
        assert_eq!(
            event_for_admin(&long).unwrap().data,
            json!({ "ruleId": "R" })
        );
    }

    #[test]
    fn consent_summary_names_categories_apps_and_size() {
        let mut approval = Approval::new("a", ApprovalKind::Cleanup, 0, 1);
        approval.categories = vec![CleanCategory::Installers, CleanCategory::Trash];
        approval.apps = vec![
            ApprovalApp {
                id: "com.google.Chrome".into(),
                name: "Google Chrome".into(),
                bytes: 1,
                items: vec![],
            },
            ApprovalApp {
                id: "com.tinyspeck.slackmacgap".into(),
                name: "Slack".into(),
                bytes: 1,
                items: vec![],
            },
        ];
        approval.bytes = 1_200_000_000;
        assert_eq!(
            consent_summary(&approval),
            "Staré instalátory a Koš; zavřít Google Chrome a Slack, 1,2 GB"
        );
    }
}
