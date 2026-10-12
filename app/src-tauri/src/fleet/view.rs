//! Co z firemní správy vidí rozhraní (stejné tvary jako `lib/types.ts`).

use antishield_core::cleanup::CleanCategory;
use antishield_core::fleet::{CommandKind, Policy, Report};
use serde::Serialize;

use super::member::ApprovalKind;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatus {
    pub reachable: bool,
    pub checked_at_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandView {
    pub id: String,
    pub kind: CommandKind,
    pub categories: Vec<CleanCategory>,
    pub sent_at_ms: u64,
    pub updated_at_ms: u64,
    /// queued, delivered, running, awaitingConsent, done, declined, failed, expired
    pub state: &'static str,
    pub freed_bytes: u64,
    pub trashed_bytes: u64,
    pub files: u64,
    pub threats: u64,
    pub error: Option<String>,
    pub deep: bool,
    pub full: bool,
    /// Aplikace k ukončení, položky karantény.
    pub targets: Vec<String>,
    pub count: u64,
    pub note: Option<String>,
    /// Restart odložený uživatelem.
    pub until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub joined_at_ms: u64,
    pub last_seen_ms: Option<u64>,
    /// Uživatel Mac odpojil, nebo ho schránka nezná.
    pub left: bool,
    /// Zásady, se kterými uživatel Macu souhlasil.
    pub policy: Policy,
    pub report: Option<Report>,
    pub commands: Vec<CommandView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    pub id: String,
    pub name: String,
    pub code: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminView {
    pub fleet_name: String,
    pub admin_name: String,
    pub fingerprint: String,
    pub policy: Policy,
    pub devices: Vec<DeviceView>,
    pub invites: Vec<InviteView>,
    pub relay: RelayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalAppView {
    pub id: String,
    pub name: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalView {
    pub id: String,
    /// cleanup, restart, quitApps, policy
    pub kind: ApprovalKind,
    pub categories: Vec<CleanCategory>,
    pub bytes: u64,
    pub requested_at_ms: u64,
    pub expires_at_ms: u64,
    pub apps: Vec<ApprovalAppView>,
    /// Nabízené zásady.
    pub policy: Option<Policy>,
    pub snoozed_until_ms: Option<u64>,
}

/// Položka úklidu v žádosti (jen pro uživatele tohoto Macu, správce ji nevidí).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalItemView {
    pub id: String,
    pub name: String,
    pub path: String,
    pub bytes: u64,
    pub modified_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalCategoryView {
    pub category: CleanCategory,
    pub bytes: u64,
    /// Velké soubory (k výběru) a obsah Koše (počet).
    pub items: Vec<ApprovalItemView>,
    pub files: u64,
}

/// Podrobnosti žádosti pro dialog na tomto Macu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalDetails {
    pub categories: Vec<ApprovalCategoryView>,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub fleet_name: String,
    pub admin_name: String,
    pub admin_fingerprint: String,
    pub joined_at_ms: u64,
    pub last_contact_ms: Option<u64>,
    pub policy: Policy,
    pub approvals: Vec<ApprovalView>,
    /// Kód potíže se schránkou (např. `fleet_unreachable`), jinak `None`.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinPreview {
    pub fleet_name: String,
    pub admin_name: String,
    pub admin_fingerprint: String,
    pub device_name: String,
    pub policy: Policy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetStateView {
    pub admin: Option<AdminView>,
    pub member: Option<MemberView>,
}
