//! Chyby celé operace. Chyba jednoho souboru při kontrole není chyba operace,
//! ale položka [`crate::SkippedItem`] ve výsledku.

use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("rule pack is too large ({size} bytes, limit {limit} bytes)")]
    RulePackTooLarge { size: usize, limit: usize },
    #[error("rule pack signature is invalid")]
    RulePackSignatureInvalid,
    #[error("rule pack is signed with an unknown key: {key_id}")]
    RulePackUnknownKey { key_id: String },
    #[error("rule pack is malformed: {0}")]
    RulePackMalformed(String),
    #[error("rule pack requires engine {required}, this engine is {current}")]
    RulePackIncompatible { required: String, current: String },
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("a scan is already running")]
    ScanAlreadyRunning,
    #[error("audit log error: {0}")]
    Audit(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl EngineError {
    /// Stabilní kód chyby; rozhraní podle něj vybírá lokalizovaný text.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RulePackTooLarge { .. } => "rule_pack_too_large",
            Self::RulePackSignatureInvalid => "rule_pack_signature_invalid",
            Self::RulePackUnknownKey { .. } => "rule_pack_unknown_key",
            Self::RulePackMalformed(_) => "rule_pack_malformed",
            Self::RulePackIncompatible { .. } => "rule_pack_incompatible",
            Self::InvalidRequest(_) => "invalid_request",
            Self::ScanAlreadyRunning => "scan_already_running",
            Self::Audit(_) => "audit",
            Self::Io(_) => "io",
        }
    }
}

/// Serializovatelná podoba chyby pro rozhraní (Tauri, CLI s `--json`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDto {
    pub code: String,
    pub message: String,
}

impl From<&EngineError> for ErrorDto {
    fn from(e: &EngineError) -> Self {
        Self {
            code: e.code().to_string(),
            message: e.to_string(),
        }
    }
}
