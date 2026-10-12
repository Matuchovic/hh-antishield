//! Firemní správa: správce (CTO) posílá firemním Macům podepsané příkazy
//! přes schránku na serveru a dostává od nich šifrované zprávy o stavu.
//!
//! - `relay`: klient schránky (nedůvěryhodná, jen přenáší text).
//! - `admin`, `member`: stav správce a spravovaného Macu, bez sítě.
//! - `exec`: provedení příkazu na Macu přes stávající úklid, kontrolu a
//!   karanténu, oznámení uživateli a audit.
//! - tento modul: uložení stavu (0600), služby na pozadí a příkazy pro okno.

pub mod admin;
mod exec;
pub mod member;
pub mod relay;
pub mod view;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use antishield_core::cleanup::CleanCategory;
use antishield_core::error::ErrorDto;
use antishield_core::fleet::{
    ACTIVATION_PREFIX, CommandKind, FleetError, OneTimeCode, ResultState, read_json, write_private,
};
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};

use crate::state::{AppState, now_ms};
use admin::{AdminState, CommandOptions};
use member::{Invitation, MemberState, Outcome, Received};
use relay::{Relay, RelayError};
use view::{
    AdminView, ApprovalCategoryView, ApprovalDetails, ApprovalItemView, FleetStateView, InviteView,
    JoinPreview, MemberView, RelayStatus,
};

const FLEET_DIR: &str = "fleet";
const ADMIN_FILE: &str = "admin.json";
const MEMBER_FILE: &str = "member.json";
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

/// Spravovaný Mac se hlásí schránce zhruba každou půlminutu, po příkazu častěji.
const MEMBER_INTERVAL: Duration = Duration::from_secs(30);
const MEMBER_FAST_INTERVAL: Duration = Duration::from_secs(5);
/// Správce obnovuje stav firmy každou půlminutu, po příkazu každé 3 s.
const ADMIN_INTERVAL: Duration = Duration::from_secs(30);
const ADMIN_FAST_INTERVAL: Duration = Duration::from_secs(3);
const FAST_WINDOW_MS: u64 = 3 * 60 * 1000;
/// Bez role spí služba dlouho; probudí ji založení firmy nebo připojení.
const IDLE_INTERVAL: Duration = Duration::from_secs(3600);
/// Zpráva o stavu: po startu, po příkazu a jinak každých 15 minut.
const REPORT_INTERVAL_MS: u64 = 15 * 60 * 1000;
/// Odhad úklidu (sken domovské složky) nejvýš dvakrát denně.
const ESTIMATE_INTERVAL_MS: u64 = 12 * 60 * 60 * 1000;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn fleet_error(err: &FleetError) -> ErrorDto {
    ErrorDto {
        code: err.code().to_string(),
        message: err.to_string(),
    }
}

fn relay_error(err: &RelayError) -> ErrorDto {
    ErrorDto {
        code: err.code(),
        message: err.to_string(),
    }
}

fn app_error(code: &str, message: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: message.to_string(),
    }
}

/// Stav firemní správy v aplikaci (v `AppState`).
pub struct FleetRuntime {
    dir: PathBuf,
    relay: OnceLock<Option<Relay>>,
    admin: Mutex<Option<AdminState>>,
    member: Mutex<Option<MemberState>>,
    admin_relay: Mutex<RelayStatus>,
    member_problem: Mutex<Option<String>>,
    /// Pozvánka ověřená v náhledu; připojení použije přesně tu, kterou uživatel viděl.
    pending_join: Mutex<Option<Invitation>>,
    admin_wake: tokio::sync::Notify,
    member_wake: tokio::sync::Notify,
    admin_fast_until: AtomicU64,
    member_fast_until: AtomicU64,
    report_due: AtomicBool,
    last_report_ms: AtomicU64,
    last_estimate_try_ms: AtomicU64,
    /// Příkazy na Macu běží po jednom.
    exec: tokio::sync::Mutex<()>,
    signature: Mutex<String>,
}

impl std::fmt::Debug for FleetRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FleetRuntime")
    }
}

impl FleetRuntime {
    pub fn load(data_dir: &Path) -> Self {
        let dir = data_dir.join(FLEET_DIR);
        let mut admin = read_json::<AdminState>(&dir.join(ADMIN_FILE), MAX_STATE_BYTES)
            .ok()
            .flatten();
        // Firma z verze 0.7: nové pozvánky a nabídky ponesou rozšířenou správu.
        if let Some(state) = admin.as_mut()
            && state.upgrade_policy()
            && let Ok(bytes) = serde_json::to_vec(&*state)
        {
            let _ = write_private(&dir.join(ADMIN_FILE), &bytes);
        }
        let member = read_json::<MemberState>(&dir.join(MEMBER_FILE), MAX_STATE_BYTES)
            .ok()
            .flatten();
        Self {
            dir,
            relay: OnceLock::new(),
            admin: Mutex::new(admin),
            member: Mutex::new(member),
            admin_relay: Mutex::new(RelayStatus::default()),
            member_problem: Mutex::new(None),
            pending_join: Mutex::new(None),
            admin_wake: tokio::sync::Notify::new(),
            member_wake: tokio::sync::Notify::new(),
            admin_fast_until: AtomicU64::new(0),
            member_fast_until: AtomicU64::new(0),
            report_due: AtomicBool::new(true),
            last_report_ms: AtomicU64::new(0),
            last_estimate_try_ms: AtomicU64::new(0),
            exec: tokio::sync::Mutex::new(()),
            signature: Mutex::new(String::new()),
        }
    }

    fn relay(&self) -> Result<&Relay, ErrorDto> {
        self.relay
            .get_or_init(|| Relay::new().ok())
            .as_ref()
            .ok_or_else(|| app_error("fleet_unreachable", "the relay client could not start"))
    }

    fn save(&self, name: &str, value: &impl serde::Serialize) -> Result<(), ErrorDto> {
        let bytes =
            serde_json::to_vec(value).map_err(|e| app_error("fleet_save", &e.to_string()))?;
        write_private(&self.dir.join(name), &bytes)
            .map_err(|e| app_error("fleet_save", &e.to_string()))
    }

    /// Změní stav správce a uloží ho (bez správce `None`).
    fn update_admin<T>(
        &self,
        change: impl FnOnce(&mut AdminState) -> T,
    ) -> Result<Option<T>, ErrorDto> {
        let mut guard = lock(&self.admin);
        let Some(admin) = guard.as_mut() else {
            return Ok(None);
        };
        let out = change(admin);
        self.save(ADMIN_FILE, &*admin)?;
        Ok(Some(out))
    }

    fn update_member<T>(
        &self,
        change: impl FnOnce(&mut MemberState) -> T,
    ) -> Result<Option<T>, ErrorDto> {
        let mut guard = lock(&self.member);
        let Some(member) = guard.as_mut() else {
            return Ok(None);
        };
        let out = change(member);
        self.save(MEMBER_FILE, &*member)?;
        Ok(Some(out))
    }

    fn forget_member(&self) {
        *lock(&self.member) = None;
        *lock(&self.member_problem) = None;
        let _ = std::fs::remove_file(self.dir.join(MEMBER_FILE));
    }

    pub fn state_view(&self) -> FleetStateView {
        let now = now_ms();
        let relay = lock(&self.admin_relay).clone();
        FleetStateView {
            admin: lock(&self.admin).as_ref().map(|a| a.view(&relay, now)),
            member: lock(&self.member).as_ref().map(|m| self.member_view(m)),
        }
    }

    fn member_view(&self, member: &MemberState) -> MemberView {
        MemberView {
            fleet_name: member.fleet_name.clone(),
            admin_name: member.admin_name.clone(),
            admin_fingerprint: member.admin_fingerprint(),
            joined_at_ms: member.joined_at_ms,
            last_contact_ms: member.last_contact_ms,
            policy: member.policy.clone(),
            approvals: member
                .approvals
                .iter()
                .map(|a| view::ApprovalView {
                    id: a.id.clone(),
                    kind: a.kind,
                    categories: a.categories.clone(),
                    bytes: a.bytes,
                    requested_at_ms: a.requested_at_ms,
                    expires_at_ms: a.expires_at_ms,
                    apps: a
                        .apps
                        .iter()
                        .map(|app| view::ApprovalAppView {
                            id: app.id.clone(),
                            name: app.name.clone(),
                            bytes: app.bytes,
                        })
                        .collect(),
                    policy: a.policy.clone(),
                    snoozed_until_ms: a.snoozed_until_ms,
                })
                .collect(),
            problem: lock(&self.member_problem).clone(),
        }
    }

    fn admin_view(&self) -> Result<AdminView, ErrorDto> {
        self.state_view()
            .admin
            .ok_or_else(|| app_error("fleet_no_admin", "this Mac does not manage a fleet"))
    }

    fn member_view_now(&self) -> Result<MemberView, ErrorDto> {
        self.state_view()
            .member
            .ok_or_else(|| app_error("fleet_no_member", "this Mac is not managed"))
    }

    /// Okno se dozví o změně (bez času poslední kontroly, ten se mění pořád).
    fn emit_if_changed(&self, app: &AppHandle) {
        let mut view = self.state_view();
        if let Some(admin) = view.admin.as_mut() {
            admin.relay.checked_at_ms = None;
        }
        let signature = serde_json::to_string(&view).unwrap_or_default();
        let mut last = lock(&self.signature);
        if *last != signature {
            *last = signature;
            drop(last);
            let _ = app.emit("fleet-changed", ());
        }
    }

    fn fast(&self, until: &AtomicU64) {
        until.store(now_ms() + FAST_WINDOW_MS, Ordering::SeqCst);
    }
}

fn runtime(app: &AppHandle) -> &FleetRuntime {
    &app.state::<AppState>().inner().fleet
}

fn audit(app: &AppHandle, kind: &str, data: serde_json::Value) {
    if let Ok(engine) = app.state::<AppState>().engine() {
        engine.record_action(kind, data);
    }
}

// ---------- Správce ----------

async fn refresh_admin(app: &AppHandle) {
    let rt = runtime(app);
    let Some((fleet, token)) = lock(&rt.admin)
        .as_ref()
        .map(|a| (a.fleet_id.clone(), a.admin_token.clone()))
    else {
        return;
    };
    let status = match rt.relay() {
        Ok(relay) => match relay.admin_state(&fleet, &token).await {
            Ok(state) => {
                let ingest = rt
                    .update_admin(|a| a.ingest(&state, now_ms()))
                    .ok()
                    .flatten();
                for device in ingest.map(|i| i.remove).unwrap_or_default() {
                    if relay
                        .admin_remove_device(&fleet, &token, &device)
                        .await
                        .is_ok()
                    {
                        let _ = rt.update_admin(|a| a.forget_device(&device));
                    }
                }
                RelayStatus {
                    reachable: true,
                    checked_at_ms: Some(now_ms()),
                    error: None,
                }
            }
            Err(err) => RelayStatus {
                reachable: false,
                checked_at_ms: Some(now_ms()),
                error: Some(err.code()),
            },
        },
        Err(err) => RelayStatus {
            reachable: false,
            checked_at_ms: Some(now_ms()),
            error: Some(err.code),
        },
    };
    *lock(&rt.admin_relay) = status;
    rt.emit_if_changed(app);
}

#[tauri::command]
pub fn fleet_state(app: AppHandle) -> FleetStateView {
    runtime(&app).state_view()
}

/// Založí firmu: klíč správce zůstane na tomto Macu, schránka dostane jen
/// identifikátor a otisk tokenu. Potřebuje jednorázový aktivační kód.
#[tauri::command]
pub async fn fleet_create(
    app: AppHandle,
    activation: String,
    fleet_name: String,
    admin_name: String,
) -> Result<AdminView, ErrorDto> {
    let rt = runtime(&app);
    if lock(&rt.admin).is_some() {
        return Err(app_error(
            "fleet_exists",
            "this Mac already manages a fleet",
        ));
    }
    let code = OneTimeCode::parse(ACTIVATION_PREFIX, &activation).map_err(|e| fleet_error(&e))?;
    let state = AdminState::new(&fleet_name, &admin_name, now_ms()).map_err(|e| fleet_error(&e))?;
    rt.relay()?
        .create(&code.canonical(), &state.fleet_id, &state.admin_token)
        .await
        .map_err(|e| relay_error(&e))?;
    rt.save(ADMIN_FILE, &state)?;
    audit(
        &app,
        "fleet_created",
        json!({ "fleetId": state.fleet_id, "fleetName": state.fleet_name, "fingerprint": state.fingerprint() }),
    );
    *lock(&rt.admin) = Some(state);
    *lock(&rt.admin_relay) = RelayStatus {
        reachable: true,
        checked_at_ms: Some(now_ms()),
        error: None,
    };
    rt.admin_wake.notify_one();
    rt.emit_if_changed(&app);
    rt.admin_view()
}

#[tauri::command]
pub async fn fleet_refresh(app: AppHandle) -> Result<AdminView, ErrorDto> {
    refresh_admin(&app).await;
    runtime(&app).admin_view()
}

#[tauri::command]
pub async fn fleet_invite(app: AppHandle, name: String) -> Result<InviteView, ErrorDto> {
    let rt = runtime(&app);
    let now = now_ms();
    let (fleet, token, invite, bundle) = {
        let guard = lock(&rt.admin);
        let admin = guard
            .as_ref()
            .ok_or_else(|| app_error("fleet_no_admin", "this Mac does not manage a fleet"))?;
        let (invite, bundle) = admin.invite(&name, now).map_err(|e| fleet_error(&e))?;
        (
            admin.fleet_id.clone(),
            admin.admin_token.clone(),
            invite,
            bundle,
        )
    };
    rt.relay()?
        .admin_invite(
            &fleet,
            &token,
            &invite.token_id,
            &bundle,
            invite.expires_at_ms,
        )
        .await
        .map_err(|e| relay_error(&e))?;
    rt.update_admin(|a| a.invites.push(invite.clone()))?;
    audit(
        &app,
        "fleet_invite",
        json!({ "name": invite.name, "expiresAtMs": invite.expires_at_ms }),
    );
    rt.emit_if_changed(&app);
    Ok(InviteView {
        id: invite.token_id,
        name: invite.name,
        code: invite.code,
        created_at_ms: invite.created_at_ms,
        expires_at_ms: invite.expires_at_ms,
    })
}

/// Pošle příkaz vybraným Macům. Okno nesmí poslat odebrání (na to je
/// samostatný příkaz s potvrzením).
#[tauri::command]
pub async fn fleet_command(
    app: AppHandle,
    device_ids: Vec<String>,
    kind: CommandKind,
    categories: Vec<CleanCategory>,
    options: Option<CommandOptions>,
) -> Result<AdminView, ErrorDto> {
    if kind == CommandKind::Unenroll {
        return Err(app_error("fleet_not_allowed", "use the remove command"));
    }
    let options = options.unwrap_or_default();
    let mut first_error = None;
    let mut sent = 0;
    for device in device_ids.iter().take(200) {
        match send_command(&app, device, kind, &categories, &options).await {
            Ok(()) => sent += 1,
            Err(err) => {
                first_error.get_or_insert(err);
            }
        }
    }
    let rt = runtime(&app);
    if sent == 0
        && let Some(err) = first_error
    {
        return Err(err);
    }
    rt.fast(&rt.admin_fast_until);
    rt.admin_wake.notify_one();
    rt.emit_if_changed(&app);
    rt.admin_view()
}

async fn send_command(
    app: &AppHandle,
    device: &str,
    kind: CommandKind,
    categories: &[CleanCategory],
    options: &CommandOptions,
) -> Result<(), ErrorDto> {
    let rt = runtime(app);
    let (fleet, token, command, sealed) = {
        let guard = lock(&rt.admin);
        let admin = guard
            .as_ref()
            .ok_or_else(|| app_error("fleet_no_admin", "this Mac does not manage a fleet"))?;
        let (command, sealed) = admin
            .command(device, kind, categories, options, now_ms())
            .map_err(|e| fleet_error(&e))?;
        (
            admin.fleet_id.clone(),
            admin.admin_token.clone(),
            command,
            sealed,
        )
    };
    rt.relay()?
        .admin_command(
            &fleet,
            &token,
            &command.id,
            device,
            &sealed,
            command.expires_at_ms,
        )
        .await
        .map_err(|e| relay_error(&e))?;
    audit(
        app,
        "fleet_command_sent",
        json!({
            "deviceId": device,
            "commandId": command.id,
            "kind": kind,
            "categories": categories,
            "deep": options.deep,
            "full": options.full,
            "targets": options.targets.len(),
        }),
    );
    rt.update_admin(|a| a.record_command(command))?;
    Ok(())
}

/// Odebere Mac z firmy: Mac dostane podepsaný pokyn ke zrušení správy; Mac,
/// který se už odpojil (nebo ho schránka nezná), se smaže hned.
#[tauri::command]
pub async fn fleet_remove_device(app: AppHandle, id: String) -> Result<AdminView, ErrorDto> {
    let rt = runtime(&app);
    let active = lock(&rt.admin).as_ref().is_some_and(|a| {
        a.devices
            .iter()
            .any(|d| d.id == id && d.left_at_ms.is_none() && !d.gone && d.removing.is_none())
    });
    if active {
        send_command(
            &app,
            &id,
            CommandKind::Unenroll,
            &[],
            &CommandOptions::default(),
        )
        .await?;
    } else {
        let (fleet, token) = lock(&rt.admin)
            .as_ref()
            .map(|a| (a.fleet_id.clone(), a.admin_token.clone()))
            .ok_or_else(|| app_error("fleet_no_admin", "this Mac does not manage a fleet"))?;
        match rt.relay()?.admin_remove_device(&fleet, &token, &id).await {
            Ok(()) | Err(RelayError::Rejected(_)) => {
                rt.update_admin(|a| a.forget_device(&id))?;
            }
            Err(err) => return Err(relay_error(&err)),
        }
    }
    audit(&app, "fleet_device_removed", json!({ "deviceId": id }));
    rt.fast(&rt.admin_fast_until);
    rt.admin_wake.notify_one();
    rt.emit_if_changed(&app);
    rt.admin_view()
}

// ---------- Spravovaný Mac ----------

async fn fetch_invitation(rt: &FleetRuntime, code: &str) -> Result<Invitation, ErrorDto> {
    let code = Invitation::parse_code(code).map_err(|e| fleet_error(&e))?;
    let row = rt
        .relay()?
        .invite(&code.token_id())
        .await
        .map_err(|e| relay_error(&e))?;
    Invitation::open(&code, row, now_ms()).map_err(|e| fleet_error(&e))
}

/// Ověří kód a ukáže, co správce uvidí a smí (nic se zatím nemění).
#[tauri::command]
pub async fn fleet_join_preview(app: AppHandle, code: String) -> Result<JoinPreview, ErrorDto> {
    let rt = runtime(&app);
    if lock(&rt.member).is_some() {
        return Err(app_error(
            "fleet_member_exists",
            "this Mac is already managed",
        ));
    }
    let invitation = fetch_invitation(rt, &code).await?;
    let preview = JoinPreview {
        fleet_name: invitation.bundle.fleet_name.clone(),
        admin_name: invitation.bundle.admin_name.clone(),
        admin_fingerprint: invitation.bundle.admin.fingerprint(),
        device_name: invitation.bundle.device_name.clone(),
        policy: invitation.bundle.policy.clone(),
    };
    *lock(&rt.pending_join) = Some(invitation);
    Ok(preview)
}

/// Připojí Mac k firmě podle pozvánky z náhledu (uživatel ji potvrdil).
#[tauri::command]
pub async fn fleet_join(app: AppHandle, code: String) -> Result<MemberView, ErrorDto> {
    let rt = runtime(&app);
    if lock(&rt.member).is_some() {
        return Err(app_error(
            "fleet_member_exists",
            "this Mac is already managed",
        ));
    }
    let parsed = Invitation::parse_code(&code).map_err(|e| fleet_error(&e))?;
    let invitation = lock(&rt.pending_join)
        .take()
        .filter(|i| i.code.token_id() == parsed.token_id())
        .ok_or_else(|| app_error("fleet_invalid_code", "confirm the invitation again"))?;
    invitation
        .bundle
        .check(now_ms())
        .map_err(|e| fleet_error(&e))?;
    let (state, bundle) = MemberState::join(&invitation, now_ms()).map_err(|e| fleet_error(&e))?;
    rt.relay()?
        .enroll(
            &invitation.code.token_id(),
            &state.device_id,
            &state.device_token,
            &bundle,
        )
        .await
        .map_err(|e| relay_error(&e))?;
    rt.save(MEMBER_FILE, &state)?;
    audit(
        &app,
        "fleet_joined",
        json!({
            "fleetName": state.fleet_name,
            "adminName": state.admin_name,
            "adminFingerprint": state.admin_fingerprint(),
            "policy": state.policy,
        }),
    );
    *lock(&rt.member) = Some(state);
    rt.report_due.store(true, Ordering::SeqCst);
    rt.member_wake.notify_one();
    rt.emit_if_changed(&app);
    rt.member_view_now()
}

/// Odpojí Mac od firmy. Správce dostane podepsané oznámení; když schránka
/// není dostupná, Mac se odpojí i tak (správce ho uvidí jako offline).
#[tauri::command]
pub async fn fleet_leave(app: AppHandle) -> Result<(), ErrorDto> {
    let rt = runtime(&app);
    let Some((device, token, notice, fleet_name)) = lock(&rt.member).as_ref().map(|m| {
        (
            m.device_id.clone(),
            m.device_token.clone(),
            m.leave_notice(now_ms()),
            m.fleet_name.clone(),
        )
    }) else {
        return Ok(());
    };
    if let (Ok(relay), Ok(notice)) = (rt.relay(), notice) {
        let _ = relay.leave(&device, &token, &notice).await;
    }
    rt.forget_member();
    audit(
        &app,
        "fleet_left",
        json!({ "fleetName": fleet_name, "by": "user" }),
    );
    rt.emit_if_changed(&app);
    Ok(())
}

/// Uživatel rozhodl o žádosti správce (úklid, restart, aplikace, zásady).
/// Bez výběru platí celá žádost; restart jde odložit.
#[tauri::command]
pub async fn fleet_approve(
    app: AppHandle,
    id: String,
    approve: bool,
    choice: Option<exec::Choice>,
) -> Result<MemberView, ErrorDto> {
    let rt = runtime(&app);
    let approval = rt
        .update_member(|m| m.take_approval(&id))?
        .flatten()
        .ok_or_else(|| app_error("fleet_unknown_approval", "the request is no longer pending"))?;
    exec::decide(&app, approval, approve, choice.unwrap_or_default()).await;
    rt.emit_if_changed(&app);
    rt.member_view_now()
}

/// Co přesně žádost o úklid obsahuje na tomto Macu: velikosti kategorií,
/// velké soubory k výběru a obsah Koše. Jen pro uživatele tohoto Macu.
#[tauri::command]
pub fn fleet_approval_details(app: AppHandle, id: String) -> Result<ApprovalDetails, ErrorDto> {
    let rt = runtime(&app);
    let approval = lock(&rt.member)
        .as_ref()
        .and_then(|m| m.approvals.iter().find(|a| a.id == id).cloned())
        .ok_or_else(|| app_error("fleet_unknown_approval", "the request is no longer pending"))?;
    let scan = crate::care::last_clean_scan(&app).unwrap_or_default();
    let categories = approval
        .categories
        .iter()
        .map(|category| {
            let items: Vec<_> = scan
                .items
                .iter()
                .filter(|i| i.category == *category)
                .collect();
            let user_picks = *category == CleanCategory::LargeFiles;
            ApprovalCategoryView {
                category: *category,
                bytes: items
                    .iter()
                    .filter(|i| user_picks || *category == CleanCategory::Trash || i.recommended)
                    .map(|i| i.bytes)
                    .sum(),
                files: items.iter().map(|i| i.files).sum(),
                items: if user_picks {
                    items
                        .iter()
                        .take(100)
                        .map(|i| ApprovalItemView {
                            id: i.id.clone(),
                            name: i.name.clone(),
                            path: i.path.clone(),
                            bytes: i.bytes,
                            modified_ms: i.modified_ms,
                        })
                        .collect()
                } else {
                    Vec::new()
                },
            }
        })
        .collect();
    Ok(ApprovalDetails {
        categories,
        uptime_secs: antishield_core::system::home_dir()
            .map_or(0, |home| antishield_core::speed::vitals(&home).uptime_secs),
    })
}

/// Pošle výsledek příkazu správci (podepsaný, zašifrovaný).
async fn post_result(
    app: &AppHandle,
    command_id: &str,
    state: ResultState,
    outcome: Outcome,
    error: Option<&str>,
) {
    let rt = runtime(app);
    let Some(Some((device, token, sealed))) = rt
        .update_member(|m| {
            m.result(command_id, state, outcome, error, now_ms())
                .ok()
                .map(|sealed| (m.device_id.clone(), m.device_token.clone(), sealed))
        })
        .ok()
        .flatten()
    else {
        return;
    };
    if let Ok(relay) = rt.relay() {
        let _ = relay.result(&device, &token, command_id, &sealed).await;
    }
}

async fn member_cycle(app: &AppHandle) {
    let rt = runtime(app);
    let Some((device, token)) = lock(&rt.member)
        .as_ref()
        .map(|m| (m.device_id.clone(), m.device_token.clone()))
    else {
        return;
    };
    let Ok(relay) = rt.relay() else {
        return;
    };
    match relay.poll(&device, &token).await {
        Ok(rows) => {
            *lock(&rt.member_problem) = None;
            let _ = rt.update_member(|m| m.last_contact_ms = Some(now_ms()));
            for row in rows {
                let received = rt
                    .update_member(|m| m.receive(&row.id, &row.envelope, now_ms()))
                    .ok()
                    .flatten();
                match received {
                    Some(Received::New(command)) => {
                        rt.fast(&rt.member_fast_until);
                        let worker = app.clone();
                        tauri::async_runtime::spawn(async move {
                            exec::run(&worker, *command).await;
                        });
                    }
                    Some(Received::Repost(sealed)) => {
                        let _ = relay.result(&device, &token, &row.id, &sealed).await;
                    }
                    Some(Received::Reject(err)) => {
                        post_result(
                            app,
                            &row.id,
                            ResultState::Failed,
                            Outcome::default(),
                            Some(err.code()),
                        )
                        .await;
                    }
                    Some(Received::Ignore) | None => {}
                }
            }
        }
        Err(RelayError::Rejected(code)) => {
            *lock(&rt.member_problem) = Some(if code == "fleet_not_authorized" {
                "fleet_removed".into()
            } else {
                code
            });
        }
        Err(err) => *lock(&rt.member_problem) = Some(err.code()),
    }

    // Odložený restart se znovu připomene.
    let due = rt
        .update_member(|m| m.take_due_snoozes(now_ms()))
        .ok()
        .flatten()
        .unwrap_or_default();
    if !due.is_empty() {
        exec::remind(app, &due);
    }

    // Žádosti o souhlas, které vypršely.
    let expired = rt
        .update_member(|m| m.take_expired_approvals(now_ms()))
        .ok()
        .flatten()
        .unwrap_or_default();
    for approval in expired {
        let outcome = Outcome::bytes(approval.freed_bytes, approval.trashed_bytes);
        post_result(app, &approval.id, ResultState::Expired, outcome, None).await;
    }

    // Zpráva o stavu.
    let now = now_ms();
    let due = rt.report_due.swap(false, Ordering::SeqCst)
        || now.saturating_sub(rt.last_report_ms.load(Ordering::SeqCst)) >= REPORT_INTERVAL_MS;
    if due {
        send_report(app).await;
    }
    rt.emit_if_changed(app);
}

async fn send_report(app: &AppHandle) {
    let rt = runtime(app);
    let now = now_ms();
    // Odhad úklidu: z posledního skenu, nejvýš dvakrát denně nový (na pozadí).
    let stale = crate::care::last_clean_scan(app)
        .is_none_or(|scan| now.saturating_sub(scan.finished_at_ms) > ESTIMATE_INTERVAL_MS);
    if stale
        && now.saturating_sub(rt.last_estimate_try_ms.load(Ordering::SeqCst)) > ESTIMATE_INTERVAL_MS
        && !crate::care::clean_scan_running(app)
    {
        rt.last_estimate_try_ms.store(now, Ordering::SeqCst);
        let worker = app.clone();
        let _ =
            tauri::async_runtime::spawn_blocking(move || crate::care::fleet_scan(&worker)).await;
    }
    let worker = app.clone();
    let Ok(input) = tauri::async_runtime::spawn_blocking(move || exec::report_input(&worker)).await
    else {
        return;
    };
    let Some(Some((device, token, sealed))) = rt
        .update_member(|m| {
            m.report(input, now_ms())
                .ok()
                .map(|sealed| (m.device_id.clone(), m.device_token.clone(), sealed))
        })
        .ok()
        .flatten()
    else {
        return;
    };
    if let Ok(relay) = rt.relay()
        && relay.report(&device, &token, &sealed).await.is_ok()
    {
        rt.last_report_ms.store(now_ms(), Ordering::SeqCst);
    }
}

/// Spustí služby firemní správy (správce i spravovaný Mac).
pub fn start(app: &AppHandle) {
    let admin_app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let rt = runtime(&admin_app);
            let has_admin = lock(&rt.admin).is_some();
            if has_admin {
                refresh_admin(&admin_app).await;
            }
            let wait = if !has_admin {
                IDLE_INTERVAL
            } else if now_ms() < rt.admin_fast_until.load(Ordering::SeqCst) {
                ADMIN_FAST_INTERVAL
            } else {
                ADMIN_INTERVAL
            };
            let _ = tokio::time::timeout(wait, rt.admin_wake.notified()).await;
        }
    });
    let member_app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Příkazy přerušené ukončením aplikace správce uvidí jako nepovedené.
        let interrupted = lock(&runtime(&member_app).member)
            .as_ref()
            .map(MemberState::interrupted)
            .unwrap_or_default();
        for id in interrupted {
            post_result(
                &member_app,
                &id,
                ResultState::Failed,
                Outcome::default(),
                Some("interrupted"),
            )
            .await;
        }
        loop {
            let rt = runtime(&member_app);
            let has_member = lock(&rt.member).is_some();
            if has_member {
                member_cycle(&member_app).await;
            }
            let wait = if !has_member {
                IDLE_INTERVAL
            } else if now_ms() < rt.member_fast_until.load(Ordering::SeqCst) {
                MEMBER_FAST_INTERVAL
            } else {
                // Rozptyl, ať se Macy nehlásí všechny ve stejnou chvíli.
                MEMBER_INTERVAL + Duration::from_millis(now_ms() % 5_000)
            };
            let _ = tokio::time::timeout(wait, rt.member_wake.notified()).await;
        }
    });
}
