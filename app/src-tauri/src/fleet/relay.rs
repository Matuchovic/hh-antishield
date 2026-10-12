//! Klient schránky firemní správy (Supabase, funkce PostgREST
//! `antishield_fleet_*`). Schránka je nedůvěryhodná: co z ní přijde, ověří
//! podpisy v `antishield_core::fleet`; tady se jen posílá a přijímá text.

use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Projekt schránky (Supabase „Matucha“, EU – Frankfurt).
pub const RELAY_URL: &str = "https://kreultaunitwjmtduitp.supabase.co";
/// Veřejný klíč projektu. Není tajný: data chrání tokeny, podpisy a šifrování.
pub const RELAY_KEY: &str = "sb_publishable_RDUswaV3bl8hgI3F2VZM2Q_jf9wuW-g";

const TIMEOUT: Duration = Duration::from_secs(20);
/// Odpověď větší než tohle se nečte (stav firmy se stovkami Maců je menší).
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// Schránka požadavek odmítla (kód z SQL, např. `fleet_not_authorized`).
    Rejected(String),
    /// Schránka není dostupná (síť, server).
    Unreachable(String),
    /// Nečekaná odpověď.
    Protocol(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(code) => write!(f, "the relay refused the request ({code})"),
            Self::Unreachable(reason) => write!(f, "the relay is not reachable ({reason})"),
            Self::Protocol(reason) => write!(f, "unexpected relay response ({reason})"),
        }
    }
}

impl RelayError {
    /// Kód pro rozhraní (texty v češtině vybírá rozhraní).
    pub fn code(&self) -> String {
        match self {
            Self::Rejected(code) => code.clone(),
            Self::Unreachable(_) => "fleet_unreachable".into(),
            Self::Protocol(_) => "fleet_protocol".into(),
        }
    }
}

/// Jak schránka vidí firmu (vše citlivé je zašifrované a podepsané).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayState {
    pub now_ms: u64,
    pub devices: Vec<RelayDevice>,
    pub commands: Vec<RelayCommand>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDevice {
    pub id: String,
    pub bundle: String,
    pub invite_token_id: String,
    pub report: Option<String>,
    pub last_seen_ms: Option<u64>,
    pub left_notice: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayCommand {
    pub id: String,
    pub delivered_at_ms: Option<u64>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InviteRow {
    pub bundle: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandRow {
    pub id: String,
    pub envelope: String,
}

#[derive(Debug, Deserialize)]
struct PostgrestError {
    message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Relay {
    client: reqwest::Client,
    base: String,
    key: String,
}

impl Relay {
    pub fn new() -> Result<Self, RelayError> {
        Self::with(RELAY_URL, RELAY_KEY)
    }

    pub fn with(base: &str, key: &str) -> Result<Self, RelayError> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("HH-AntiShield/", env!("CARGO_PKG_VERSION")))
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| RelayError::Unreachable(e.to_string()))?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_string(),
            key: key.to_string(),
        })
    }

    async fn call(&self, function: &str, args: Value) -> Result<Vec<u8>, RelayError> {
        let body = serde_json::to_vec(&args).map_err(|e| RelayError::Protocol(e.to_string()))?;
        let mut response = self
            .client
            .post(format!("{}/rest/v1/rpc/{function}", self.base))
            .header("apikey", &self.key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| RelayError::Unreachable(e.to_string()))?;
        let status = response.status();
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| RelayError::Unreachable(e.to_string()))?
        {
            if data.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(RelayError::Protocol("response too large".into()));
            }
            data.extend_from_slice(&chunk);
        }
        if status.is_success() {
            return Ok(data);
        }
        let message = serde_json::from_slice::<PostgrestError>(&data)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_default();
        if message.starts_with("fleet_") && message.len() <= 64 {
            Err(RelayError::Rejected(message))
        } else if status.is_server_error() {
            Err(RelayError::Unreachable(format!("HTTP {status}")))
        } else {
            Err(RelayError::Protocol(format!(
                "HTTP {status}: {}",
                message.chars().take(200).collect::<String>()
            )))
        }
    }

    async fn call_json<T: DeserializeOwned>(
        &self,
        function: &str,
        args: Value,
    ) -> Result<T, RelayError> {
        let data = self.call(function, args).await?;
        serde_json::from_slice(&data).map_err(|e| RelayError::Protocol(e.to_string()))
    }

    async fn call_void(&self, function: &str, args: Value) -> Result<(), RelayError> {
        self.call(function, args).await.map(|_| ())
    }

    // ---------- Správce ----------

    pub async fn create(
        &self,
        activation: &str,
        fleet: &str,
        admin_token: &str,
    ) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_create",
            json!({ "p_activation": activation, "p_fleet": fleet, "p_admin_token": admin_token }),
        )
        .await
    }

    pub async fn admin_invite(
        &self,
        fleet: &str,
        token: &str,
        token_id: &str,
        bundle: &str,
        expires_at_ms: u64,
    ) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_admin_invite",
            json!({
                "p_fleet": fleet,
                "p_token": token,
                "p_token_id": token_id,
                "p_bundle": bundle,
                "p_expires_at_ms": expires_at_ms,
            }),
        )
        .await
    }

    pub async fn admin_state(&self, fleet: &str, token: &str) -> Result<RelayState, RelayError> {
        self.call_json(
            "antishield_fleet_admin_state",
            json!({ "p_fleet": fleet, "p_token": token }),
        )
        .await
    }

    pub async fn admin_command(
        &self,
        fleet: &str,
        token: &str,
        command: &str,
        device: &str,
        envelope: &str,
        expires_at_ms: u64,
    ) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_admin_command",
            json!({
                "p_fleet": fleet,
                "p_token": token,
                "p_command": command,
                "p_device": device,
                "p_envelope": envelope,
                "p_expires_at_ms": expires_at_ms,
            }),
        )
        .await
    }

    pub async fn admin_remove_device(
        &self,
        fleet: &str,
        token: &str,
        device: &str,
    ) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_admin_remove_device",
            json!({ "p_fleet": fleet, "p_token": token, "p_device": device }),
        )
        .await
    }

    /// Smaže celou firmu ve schránce (úklid po živém testu).
    #[cfg(test)]
    pub async fn admin_delete_fleet(&self, fleet: &str, token: &str) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_admin_delete_fleet",
            json!({ "p_fleet": fleet, "p_token": token }),
        )
        .await
    }

    // ---------- Firemní Mac ----------

    pub async fn invite(&self, token_id: &str) -> Result<Option<InviteRow>, RelayError> {
        let rows: Vec<InviteRow> = self
            .call_json("antishield_fleet_invite", json!({ "p_token_id": token_id }))
            .await?;
        Ok(rows.into_iter().next())
    }

    pub async fn enroll(
        &self,
        token_id: &str,
        device: &str,
        device_token: &str,
        bundle: &str,
    ) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_enroll",
            json!({
                "p_token_id": token_id,
                "p_device": device,
                "p_device_token": device_token,
                "p_bundle": bundle,
            }),
        )
        .await
    }

    pub async fn poll(&self, device: &str, token: &str) -> Result<Vec<CommandRow>, RelayError> {
        self.call_json(
            "antishield_fleet_poll",
            json!({ "p_device": device, "p_token": token }),
        )
        .await
    }

    pub async fn report(&self, device: &str, token: &str, report: &str) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_report",
            json!({ "p_device": device, "p_token": token, "p_report": report }),
        )
        .await
    }

    pub async fn result(
        &self,
        device: &str,
        token: &str,
        command: &str,
        result: &str,
    ) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_result",
            json!({ "p_device": device, "p_token": token, "p_command": command, "p_result": result }),
        )
        .await
    }

    pub async fn leave(&self, device: &str, token: &str, notice: &str) -> Result<(), RelayError> {
        self.call_void(
            "antishield_fleet_leave",
            json!({ "p_device": device, "p_token": token, "p_notice": notice }),
        )
        .await
    }
}
