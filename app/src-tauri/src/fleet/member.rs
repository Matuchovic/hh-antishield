//! Spravovaný Mac: připojení k firmě, příjem podepsaných příkazů, výsledky,
//! zprávy o stavu a souhlasy uživatele. Bez sítě a bez zásahů do systému;
//! to dělají `fleet::exec` a `fleet` (glue) podle toho, co tady projde.

use antishield_core::cleanup::CleanCategory;
use antishield_core::fleet::{
    self as proto, ADMIN_BUNDLE, AdminBundle, COMMAND_LIFETIME_MS, CleanupEstimate, Command,
    CommandKind, CommandResult, DEVICE_BUNDLE, DeviceBundle, FleetError, INVITE_PREFIX, Identity,
    IdentitySecret, LEAVE, LastScan, LeaveNotice, Membership, MemoryState, OneTimeCode, Policy,
    PublicKeys, REPORT, RESULT, Report, ResultState, ThreatReport, VERSION,
};
use antishield_core::speed::DiskInfo;
use antishield_core::status::ProtectionLevel;
use serde::{Deserialize, Serialize};

use super::relay::InviteRow;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Jak dlouho si Mac pamatuje provedené příkazy (příkaz platí nejvýš 8 dní).
const EXECUTED_KEEP_MS: u64 = 30 * DAY_MS;
/// Víc příkazů za hodinu Mac neprovede (ochrana před zahlcením).
pub const MAX_COMMANDS_PER_HOUR: usize = 30;

/// Provedený (nebo odmítnutý) příkaz: pro ochranu před opakováním a pro
/// opětovné poslání výsledku, když se ztratil.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Executed {
    pub id: String,
    pub at_ms: u64,
    pub kind: CommandKind,
    /// Poslední zapečetěný výsledek pro správce.
    pub result: Option<String>,
}

/// Úklid, který čeká na souhlas uživatele.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub id: String,
    pub categories: Vec<CleanCategory>,
    pub bytes: u64,
    pub requested_at_ms: u64,
    pub expires_at_ms: u64,
    /// Co se z téhož příkazu uklidilo hned (kategorie bez souhlasu).
    pub freed_bytes: u64,
    pub trashed_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberState {
    pub v: u8,
    pub fleet_id: String,
    pub fleet_name: String,
    pub admin_name: String,
    pub admin: PublicKeys,
    pub policy: Policy,
    pub device_id: String,
    pub device_token: String,
    pub secret: IdentitySecret,
    pub joined_at_ms: u64,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub executed: Vec<Executed>,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    #[serde(default)]
    pub last_contact_ms: Option<u64>,
}

impl std::fmt::Debug for MemberState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemberState({}, {})", self.fleet_name, self.device_id)
    }
}

/// Pozvánka ověřená kódem (balíček správce je pravý a platný).
#[derive(Debug, Clone)]
pub struct Invitation {
    pub code: OneTimeCode,
    pub bundle: AdminBundle,
}

impl Invitation {
    /// Ověří pozvánku ze schránky kódem, který uživatel zadal.
    pub fn open(code: &OneTimeCode, row: Option<InviteRow>, now: u64) -> Result<Self, FleetError> {
        let row = row.ok_or(FleetError::InvalidCode)?;
        let bundle: AdminBundle = code.unbind(ADMIN_BUNDLE, &row.bundle)?;
        bundle.check(now)?;
        Ok(Self {
            code: code.clone(),
            bundle,
        })
    }

    pub fn parse_code(text: &str) -> Result<OneTimeCode, FleetError> {
        OneTimeCode::parse(INVITE_PREFIX, text)
    }
}

/// Co přišlo ze schránky a co s tím.
#[derive(Debug)]
pub enum Received {
    /// Nový platný příkaz: provést.
    New(Command),
    /// Opakované doručení: znovu poslat uložený výsledek.
    Repost(String),
    /// Opakované doručení bez výsledku (příkaz ještě běží).
    Ignore,
    /// Neplatný nebo nepovolený příkaz: odmítnout (výsledek „selhalo“).
    Reject(FleetError),
}

/// Číselné výsledky příkazu.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Outcome {
    pub freed_bytes: u64,
    pub trashed_bytes: u64,
    pub files: u64,
    pub threats: u64,
}

/// Údaje do zprávy o stavu (sbírá aplikace).
#[derive(Debug, Clone)]
pub struct ReportInput {
    pub app_version: String,
    pub os_version: String,
    pub model: String,
    pub protection: ProtectionLevel,
    pub protection_note: Option<String>,
    pub rules_version: String,
    pub rules_checked_at_ms: Option<u64>,
    pub last_scan: Option<LastScan>,
    pub threats: Vec<ThreatReport>,
    pub quarantined: u64,
    pub disk: Option<DiskInfo>,
    pub memory: MemoryState,
    pub uptime_secs: u64,
    pub cleanup: Option<CleanupEstimate>,
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

impl MemberState {
    /// Připojí Mac: nové klíče a token, svázané s kódem pozvánky.
    pub fn join(invitation: &Invitation, now: u64) -> Result<(Self, String), FleetError> {
        let identity = Identity::generate()?;
        let device_id = proto::random_id()?;
        let bundle = DeviceBundle {
            v: VERSION,
            fleet_id: invitation.bundle.fleet_id.clone(),
            token_id: invitation.code.token_id(),
            device_id: device_id.clone(),
            device: identity.public(),
        };
        let bound = invitation.code.bind(DEVICE_BUNDLE, &bundle)?;
        let state = Self {
            v: VERSION,
            fleet_id: invitation.bundle.fleet_id.clone(),
            fleet_name: invitation.bundle.fleet_name.clone(),
            admin_name: invitation.bundle.admin_name.clone(),
            admin: invitation.bundle.admin,
            policy: invitation.bundle.policy.clone(),
            device_id,
            device_token: proto::random_token()?,
            secret: identity.secret(),
            joined_at_ms: now,
            seq: 0,
            executed: Vec::new(),
            approvals: Vec::new(),
            last_contact_ms: None,
        };
        Ok((state, bound))
    }

    pub fn identity(&self) -> Identity {
        Identity::from_secret(&self.secret)
    }

    pub fn admin_fingerprint(&self) -> String {
        self.admin.fingerprint()
    }

    /// Ověří příkaz ze schránky (`row_id` je jeho identifikátor ve schránce).
    pub fn receive(&mut self, row_id: &str, envelope: &str, now: u64) -> Received {
        self.prune(now);
        let identity = self.identity();
        let membership = Membership {
            fleet_id: &self.fleet_id,
            device_id: &self.device_id,
            admin: &self.admin,
            policy: &self.policy,
        };
        let executed = &self.executed;
        let accepted = proto::accept_command(&identity, &membership, envelope, now, |id| {
            executed.iter().any(|e| e.id == id)
        });
        match accepted {
            Ok(command) if command.id != row_id => Received::Reject(FleetError::WrongTarget),
            Ok(command) => {
                let recent = self
                    .executed
                    .iter()
                    .filter(|e| now.saturating_sub(e.at_ms) < 60 * 60 * 1000)
                    .count();
                if recent >= MAX_COMMANDS_PER_HOUR {
                    return Received::Reject(FleetError::NotAllowed("too many commands".into()));
                }
                self.executed.push(Executed {
                    id: command.id.clone(),
                    at_ms: now,
                    kind: command.kind,
                    result: None,
                });
                Received::New(command)
            }
            Err(FleetError::Replay) => self
                .executed
                .iter()
                .find(|e| e.id == row_id)
                .and_then(|e| e.result.clone())
                .map_or(Received::Ignore, Received::Repost),
            Err(err) => Received::Reject(err),
        }
    }

    /// Podepsaný a zašifrovaný výsledek pro správce (uloží se k příkazu).
    pub fn result(
        &mut self,
        command_id: &str,
        state: ResultState,
        outcome: Outcome,
        error: Option<&str>,
        now: u64,
    ) -> Result<String, FleetError> {
        self.seq += 1;
        let result = CommandResult {
            v: VERSION,
            command_id: command_id.to_string(),
            device_id: self.device_id.clone(),
            seq: self.seq,
            at_ms: now,
            state,
            freed_bytes: outcome.freed_bytes,
            trashed_bytes: outcome.trashed_bytes,
            files: outcome.files,
            threats: outcome.threats,
            error: error.map(|e| truncate(e, 200)),
        };
        let sealed = proto::sign_and_seal(&self.identity(), &self.admin, RESULT, &result)?;
        if let Some(entry) = self.executed.iter_mut().find(|e| e.id == command_id) {
            entry.result = Some(sealed.clone());
        }
        Ok(sealed)
    }

    /// Podepsaná a zašifrovaná zpráva o stavu pro správce.
    pub fn report(&mut self, input: ReportInput, now: u64) -> Result<String, FleetError> {
        self.seq += 1;
        let mut threats = input.threats;
        threats.truncate(proto::MAX_REPORT_THREATS);
        for threat in &mut threats {
            threat.rule_name = truncate(&threat.rule_name, 200);
            threat.path = truncate(&threat.path, 1024);
        }
        let report = Report {
            v: VERSION,
            device_id: self.device_id.clone(),
            fleet_id: self.fleet_id.clone(),
            seq: self.seq,
            created_at_ms: now,
            app_version: truncate(&input.app_version, 40),
            os_version: truncate(&input.os_version, 80),
            model: truncate(&input.model, 120),
            protection: input.protection,
            protection_note: input.protection_note.map(|n| truncate(&n, 200)),
            rules_version: truncate(&input.rules_version, 60),
            rules_checked_at_ms: input.rules_checked_at_ms,
            last_scan: input.last_scan,
            threats,
            quarantined: input.quarantined,
            disk: input.disk,
            memory: input.memory,
            uptime_secs: input.uptime_secs,
            cleanup: input.cleanup,
        };
        proto::sign_and_seal(&self.identity(), &self.admin, REPORT, &report)
    }

    /// Podepsané oznámení správci, že uživatel Mac odpojil.
    pub fn leave_notice(&self, now: u64) -> Result<String, FleetError> {
        let notice = LeaveNotice {
            v: VERSION,
            fleet_id: self.fleet_id.clone(),
            device_id: self.device_id.clone(),
            at_ms: now,
        };
        proto::sign_and_seal(&self.identity(), &self.admin, LEAVE, &notice)
    }

    pub fn add_approval(&mut self, approval: Approval) {
        self.approvals.retain(|a| a.id != approval.id);
        self.approvals.push(approval);
    }

    pub fn take_approval(&mut self, id: &str) -> Option<Approval> {
        let index = self.approvals.iter().position(|a| a.id == id)?;
        Some(self.approvals.remove(index))
    }

    /// Žádosti, o kterých uživatel nerozhodl do konce platnosti příkazu.
    pub fn take_expired_approvals(&mut self, now: u64) -> Vec<Approval> {
        let (expired, pending): (Vec<_>, Vec<_>) = std::mem::take(&mut self.approvals)
            .into_iter()
            .partition(|a| a.expires_at_ms <= now);
        self.approvals = pending;
        expired
    }

    fn prune(&mut self, now: u64) {
        self.executed
            .retain(|e| now.saturating_sub(e.at_ms) < EXECUTED_KEEP_MS);
    }
}

/// Platnost žádosti o souhlas: do konce platnosti příkazu, nejvýš týden.
pub fn approval_expiry(command: &Command, now: u64) -> u64 {
    command.expires_at_ms.min(now + COMMAND_LIFETIME_MS)
}
