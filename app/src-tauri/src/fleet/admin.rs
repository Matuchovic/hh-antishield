//! Správce firmy: klíče, pozvánky, podepsané příkazy a ověřování zpráv
//! z firemních Maců. Bez sítě: schránku volá `fleet` (glue) a sem předá jen
//! to, co přišlo; nic z toho se nebere bez ověření podpisu.

use antishield_core::cleanup::CleanCategory;
use antishield_core::fleet::{
    self as proto, ADMIN_BUNDLE, AdminBundle, COMMAND, COMMAND_LIFETIME_MS, Command, CommandKind,
    CommandResult, DEVICE_BUNDLE, DeviceBundle, FleetError, INVITE_LIFETIME_MS, INVITE_PREFIX,
    Identity, IdentitySecret, OneTimeCode, Policy, PublicKeys, Report, ResultState, VERSION,
};
use serde::{Deserialize, Serialize};

use super::relay::RelayState;
use super::view::{AdminView, CommandView, DeviceView, InviteView, RelayStatus};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const COMMAND_KEEP_MS: u64 = 30 * DAY_MS;
const MAX_COMMANDS: usize = 500;
/// Kolik posledních zásahů ukazuje detail Macu.
const COMMANDS_PER_DEVICE: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminInvite {
    pub token_id: String,
    pub name: String,
    /// Kód pro Mac (tajný, dokud ho Mac nepoužije; soubor má práva 0600).
    pub code: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDevice {
    pub id: String,
    pub name: String,
    pub keys: PublicKeys,
    pub joined_at_ms: u64,
    pub last_seen_ms: Option<u64>,
    pub report: Option<Report>,
    pub left_at_ms: Option<u64>,
    /// Mac se odebírá: identifikátor příkazu k odpojení.
    pub removing: Option<String>,
    /// Schránka Mac nezná (smazaný mimo aplikaci).
    #[serde(default)]
    pub gone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminCommand {
    pub id: String,
    pub device_id: String,
    pub kind: CommandKind,
    pub categories: Vec<CleanCategory>,
    pub sent_at_ms: u64,
    pub expires_at_ms: u64,
    pub delivered_at_ms: Option<u64>,
    pub result: Option<CommandResult>,
    #[serde(default)]
    pub deep: bool,
    #[serde(default)]
    pub full: bool,
    #[serde(default)]
    pub targets: Vec<String>,
}

/// Volby příkazu z rozhraní (hloubkový úklid, úplná kontrola, cíle).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandOptions {
    #[serde(default)]
    pub deep: bool,
    #[serde(default)]
    pub full: bool,
    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminState {
    pub v: u8,
    pub fleet_id: String,
    pub fleet_name: String,
    pub admin_name: String,
    pub admin_token: String,
    pub secret: IdentitySecret,
    pub policy: Policy,
    pub created_at_ms: u64,
    #[serde(default)]
    pub invites: Vec<AdminInvite>,
    #[serde(default)]
    pub devices: Vec<AdminDevice>,
    #[serde(default)]
    pub commands: Vec<AdminCommand>,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AdminState({}, {} devices)",
            self.fleet_name,
            self.devices.len()
        )
    }
}

/// Co je po zpracování stavu schránky potřeba udělat ve schránce.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ingest {
    /// Macy ke smazání ze schránky (neověřitelné nebo dokončené odebrání).
    pub remove: Vec<String>,
}

fn command_state(command: &AdminCommand, now: u64) -> &'static str {
    match command.result.as_ref().map(|r| r.state) {
        Some(ResultState::Running) => "running",
        Some(ResultState::AwaitingConsent) => "awaitingConsent",
        Some(ResultState::Done) => "done",
        Some(ResultState::Declined) => "declined",
        Some(ResultState::Failed) => "failed",
        Some(ResultState::Expired) => "expired",
        None if command.expires_at_ms <= now => "expired",
        None if command.delivered_at_ms.is_some() => "delivered",
        None => "queued",
    }
}

fn command_view(command: &AdminCommand, now: u64) -> CommandView {
    let result = command.result.as_ref();
    CommandView {
        id: command.id.clone(),
        kind: command.kind,
        categories: command.categories.clone(),
        sent_at_ms: command.sent_at_ms,
        updated_at_ms: result
            .map(|r| r.at_ms)
            .or(command.delivered_at_ms)
            .unwrap_or(command.sent_at_ms),
        state: command_state(command, now),
        freed_bytes: result.map_or(0, |r| r.freed_bytes),
        trashed_bytes: result.map_or(0, |r| r.trashed_bytes),
        files: result.map_or(0, |r| r.files),
        threats: result.map_or(0, |r| r.threats),
        error: result.and_then(|r| r.error.clone()),
        deep: command.deep,
        full: command.full,
        targets: command.targets.clone(),
        count: result.map_or(0, |r| r.count),
        note: result.and_then(|r| r.note.clone()),
        until_ms: result.and_then(|r| r.until_ms),
    }
}

impl AdminState {
    /// Nová firma: klíče správce, identifikátor a token pro schránku.
    pub fn new(fleet_name: &str, admin_name: &str, now: u64) -> Result<Self, FleetError> {
        let identity = Identity::generate()?;
        Ok(Self {
            v: VERSION,
            fleet_id: proto::random_id()?,
            fleet_name: proto::clean_name(fleet_name)?,
            admin_name: proto::clean_name(admin_name)?,
            admin_token: proto::random_token()?,
            secret: identity.secret(),
            policy: Policy::standard(),
            created_at_ms: now,
            invites: Vec::new(),
            devices: Vec::new(),
            commands: Vec::new(),
        })
    }

    pub fn identity(&self) -> Identity {
        Identity::from_secret(&self.secret)
    }

    pub fn fingerprint(&self) -> String {
        self.identity().public().fingerprint()
    }

    /// Pozvánka pro jeden Mac: kód (pro uživatele) a balíček svázaný s kódem
    /// (pro schránku). Uloží se, až ji schránka přijme.
    pub fn invite(&self, name: &str, now: u64) -> Result<(AdminInvite, String), FleetError> {
        let name = proto::clean_name(name)?;
        let code = OneTimeCode::generate(INVITE_PREFIX)?;
        let expires_at_ms = now + INVITE_LIFETIME_MS;
        let bundle = AdminBundle {
            v: VERSION,
            fleet_id: self.fleet_id.clone(),
            fleet_name: self.fleet_name.clone(),
            admin_name: self.admin_name.clone(),
            admin: self.identity().public(),
            policy: self.policy.clone(),
            device_name: name.clone(),
            expires_at_ms,
        };
        let bound = code.bind(ADMIN_BUNDLE, &bundle)?;
        Ok((
            AdminInvite {
                token_id: code.token_id(),
                name,
                code: code.display(),
                created_at_ms: now,
                expires_at_ms,
            },
            bound,
        ))
    }

    /// Firma z verze 0.7 nabízela jen základní zásady: nové pozvánky
    /// a nabídky ponesou rozšířenou správu. Vrací, jestli se něco změnilo.
    pub fn upgrade_policy(&mut self) -> bool {
        if self.policy.covers(&Policy::standard()) {
            return false;
        }
        self.policy = Policy::standard();
        true
    }

    /// Podepsaný příkaz zašifrovaný pro jeden Mac. Kontroluje stejné meze
    /// jako Mac (zásady, které Mac potvrdil); Mac je ale ověří znovu sám.
    pub fn command(
        &self,
        device_id: &str,
        kind: CommandKind,
        categories: &[CleanCategory],
        options: &CommandOptions,
        now: u64,
    ) -> Result<(AdminCommand, String), FleetError> {
        let device = self
            .devices
            .iter()
            .find(|d| d.id == device_id && d.left_at_ms.is_none() && !d.gone)
            .ok_or(FleetError::WrongTarget)?;
        if device.removing.is_some() {
            return Err(FleetError::WrongTarget);
        }
        let mut command = Command::new(
            proto::random_id()?,
            self.fleet_id.clone(),
            device.id.clone(),
            kind,
            categories.to_vec(),
            now,
            now + COMMAND_LIFETIME_MS,
        );
        command.deep = options.deep;
        command.full = options.full;
        command.targets = options.targets.clone();
        if kind == CommandKind::Policy {
            command.policy = Some(self.policy.clone());
        }
        let accepted = device
            .report
            .as_ref()
            .map_or_else(Policy::basic, Report::accepted_policy);
        proto::check_command(&command, &accepted)?;
        let sealed = proto::sign_and_seal(&self.identity(), &device.keys, COMMAND, &command)?;
        Ok((
            AdminCommand {
                id: command.id,
                device_id: device.id.clone(),
                kind,
                categories: command.categories,
                sent_at_ms: now,
                expires_at_ms: command.expires_at_ms,
                delivered_at_ms: None,
                result: None,
                deep: command.deep,
                full: command.full,
                targets: command.targets,
            },
            sealed,
        ))
    }

    pub fn record_command(&mut self, command: AdminCommand) {
        if command.kind == CommandKind::Unenroll
            && let Some(device) = self.devices.iter_mut().find(|d| d.id == command.device_id)
        {
            device.removing = Some(command.id.clone());
        }
        self.commands.insert(0, command);
        self.commands.truncate(MAX_COMMANDS);
    }

    pub fn forget_device(&mut self, device_id: &str) {
        self.devices.retain(|d| d.id != device_id);
        self.commands.retain(|c| c.device_id != device_id);
    }

    /// Zpracuje stav ze schránky: ověří nové Macy podle pozvánek, přijme jen
    /// podepsané zprávy a výsledky (novější než známé), zjistí odpojení.
    pub fn ingest(&mut self, state: &RelayState, now: u64) -> Ingest {
        // Časy ze schránky se převedou na hodiny tohoto Macu.
        let offset = i128::from(now) - i128::from(state.now_ms);
        let local = |ms: u64| u64::try_from((i128::from(ms) + offset).max(0)).unwrap_or(0);
        let identity = self.identity();
        let mut out = Ingest::default();

        for row in &state.devices {
            if !self.devices.iter().any(|d| d.id == row.id) {
                // Nový Mac: klíče musí být svázané s kódem pozvánky, který
                // zná jen tento správce. Jinak ho schránka podvrhla.
                let verified = self
                    .invites
                    .iter()
                    .position(|i| i.token_id == row.invite_token_id)
                    .and_then(|index| {
                        let invite = &self.invites[index];
                        let code = OneTimeCode::parse(INVITE_PREFIX, &invite.code).ok()?;
                        let bundle: DeviceBundle = code.unbind(DEVICE_BUNDLE, &row.bundle).ok()?;
                        bundle
                            .check(&self.fleet_id, &invite.token_id, &row.id)
                            .ok()?;
                        Some((index, bundle))
                    });
                let Some((index, bundle)) = verified else {
                    out.remove.push(row.id.clone());
                    continue;
                };
                let invite = self.invites.remove(index);
                self.devices.push(AdminDevice {
                    id: row.id.clone(),
                    name: invite.name,
                    keys: bundle.device,
                    joined_at_ms: local(row.created_at_ms),
                    last_seen_ms: None,
                    report: None,
                    left_at_ms: None,
                    removing: None,
                    gone: false,
                });
            }
            let Some(device) = self.devices.iter_mut().find(|d| d.id == row.id) else {
                continue;
            };
            device.gone = false;
            device.last_seen_ms = row.last_seen_ms.map(local);
            if let Some(sealed) = &row.report
                && let Ok(report) =
                    proto::open_report(&identity, &device.keys, &self.fleet_id, &device.id, sealed)
                && device
                    .report
                    .as_ref()
                    .is_none_or(|known| report.seq > known.seq)
            {
                device.report = Some(report);
            }
            if device.left_at_ms.is_none()
                && let Some(sealed) = &row.left_notice
                && proto::open_leave(&identity, &device.keys, &self.fleet_id, &device.id, sealed)
                    .is_ok()
            {
                device.left_at_ms = row.last_seen_ms.map(local).or(Some(now));
            }
        }

        for command in &mut self.commands {
            let Some(row) = state.commands.iter().find(|c| c.id == command.id) else {
                continue;
            };
            command.delivered_at_ms = row.delivered_at_ms.map(local);
            let device = self.devices.iter().find(|d| d.id == command.device_id);
            if let (Some(sealed), Some(device)) = (&row.result, device)
                && let Ok(result) =
                    proto::open_result(&identity, &device.keys, &device.id, &command.id, sealed)
                && command
                    .result
                    .as_ref()
                    .is_none_or(|known| result.seq > known.seq)
            {
                command.result = Some(result);
            }
        }

        // Macy, které schránka nezná; dokončená odebrání se smažou ze schránky.
        for device in &mut self.devices {
            device.gone = !state.devices.iter().any(|row| row.id == device.id);
            let Some(removing) = &device.removing else {
                continue;
            };
            let finished = device.gone
                || device.left_at_ms.is_some()
                || self.commands.iter().any(|c| {
                    &c.id == removing
                        && (c.expires_at_ms <= now
                            || c.result.as_ref().is_some_and(|r| r.state.is_final()))
                });
            if finished {
                out.remove.push(device.id.clone());
            }
        }

        self.invites.retain(|i| i.expires_at_ms > now);
        self.commands
            .retain(|c| now.saturating_sub(c.sent_at_ms) < COMMAND_KEEP_MS);
        out
    }

    pub fn view(&self, relay: &RelayStatus, now: u64) -> AdminView {
        AdminView {
            fleet_name: self.fleet_name.clone(),
            admin_name: self.admin_name.clone(),
            fingerprint: self.fingerprint(),
            policy: self.policy.clone(),
            devices: self
                .devices
                .iter()
                .filter(|d| d.removing.is_none())
                .map(|d| DeviceView {
                    id: d.id.clone(),
                    name: d.name.clone(),
                    fingerprint: d.keys.fingerprint(),
                    joined_at_ms: d.joined_at_ms,
                    last_seen_ms: d.last_seen_ms,
                    left: d.left_at_ms.is_some() || d.gone,
                    policy: d
                        .report
                        .as_ref()
                        .map_or_else(Policy::basic, Report::accepted_policy),
                    report: d.report.clone(),
                    commands: self
                        .commands
                        .iter()
                        .filter(|c| c.device_id == d.id && c.kind != CommandKind::Unenroll)
                        .take(COMMANDS_PER_DEVICE)
                        .map(|c| command_view(c, now))
                        .collect(),
                })
                .collect(),
            invites: self
                .invites
                .iter()
                .filter(|i| i.expires_at_ms > now)
                .map(|i| InviteView {
                    id: i.token_id.clone(),
                    name: i.name.clone(),
                    code: i.code.clone(),
                    created_at_ms: i.created_at_ms,
                    expires_at_ms: i.expires_at_ms,
                })
                .collect(),
            relay: relay.clone(),
        }
    }
}
