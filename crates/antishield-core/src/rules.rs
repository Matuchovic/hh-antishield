//! Podepsaná sada pravidel.
//!
//! Pořadí kontrol při načtení je záměrné: nejdřív velikost, pak podpis Ed25519
//! nad přesnými bajty souboru a **teprve potom** parsování JSON. Nepodepsaný
//! obsah se tak k parseru vůbec nedostane.

use std::collections::{HashMap, HashSet};
use std::fmt;

use aho_corasick::{AhoCorasick, MatchKind};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::ENGINE_VERSION;
use crate::error::EngineError;
use crate::types::{RulePackInfo, Severity};

pub const MAX_PACK_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_SIGNATURE_FILE_SIZE: usize = 4 * 1024;
pub const FORMAT_VERSION: u32 = 1;
pub const MIN_PATTERN_LEN: usize = 8;
pub const MAX_PATTERN_LEN: usize = 1024;
pub const MAX_RULES: usize = 100_000;
const MAX_ID_LEN: usize = 64;
const MAX_TEXT_LEN: usize = 2_000;

/// SHA-256 prázdného souboru; jako indikátor by označil každý prázdný soubor.
const EMPTY_FILE_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Testovací klíč pro v0.1. Smí podepsat jen sadu s `test_pack: true`.
pub const TEST_KEY_ID: &str = "hh-test-2026-10";
const TEST_PUBLIC_KEY_HEX: &str = include_str!("../../../rules/keys/hh-test-2026-10.pub.hex");

/// Veřejný klíč, kterému engine věří.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    /// Testovací klíč smí podepsat jen testovací sadu.
    pub test_only: bool,
}

/// Klíče zabudované do enginu.
pub fn builtin_trusted_keys() -> Vec<TrustedKey> {
    let mut keys = Vec::new();
    if let Some(public_key) = decode_key_hex(TEST_PUBLIC_KEY_HEX) {
        keys.push(TrustedKey {
            key_id: TEST_KEY_ID.to_string(),
            public_key,
            test_only: true,
        });
    }
    keys
}

fn decode_key_hex(text: &str) -> Option<[u8; 32]> {
    hex::decode(text.trim()).ok()?.try_into().ok()
}

/// Text ve dvou jazycích.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Localized {
    pub cs: String,
    pub en: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureFile {
    format_version: u32,
    key_id: String,
    algorithm: String,
    signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    format_version: u32,
    pack_id: String,
    sequence: u64,
    version: String,
    created_at_unix: i64,
    expires_at_unix: i64,
    min_engine_version: String,
    test_pack: bool,
    rules: Vec<RuleDef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleKind {
    Sha256,
    Bytes,
    Eicar,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDef {
    id: String,
    version: u32,
    kind: RuleKind,
    name: String,
    description: Localized,
    severity: Severity,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    pattern_hex: Option<String>,
}

/// Metadata pravidla, která se propisují do nálezu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: String,
    pub version: u32,
    pub name: String,
    pub description: Localized,
    pub severity: Severity,
    pub test_only: bool,
}

/// Ověřená a připravená sada pravidel.
pub struct RulePack {
    info: RulePackInfo,
    rules: Vec<RuleMeta>,
    hash_index: HashMap<[u8; 32], usize>,
    patterns: Option<AhoCorasick>,
    pattern_rules: Vec<usize>,
    pattern_bytes: Vec<Vec<u8>>,
    max_pattern_len: usize,
    eicar_rule: Option<usize>,
}

impl fmt::Debug for RulePack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RulePack")
            .field("info", &self.info)
            .field("rules", &self.rules.len())
            .field("hash_rules", &self.hash_index.len())
            .field("pattern_rules", &self.pattern_rules.len())
            .field("eicar_rule", &self.eicar_rule)
            .finish()
    }
}

impl RulePack {
    /// Ověří podpis a načte sadu. `now_unix` slouží jen k označení vypršení.
    pub fn load(
        pack: &[u8],
        signature: &[u8],
        keys: &[TrustedKey],
        now_unix: i64,
    ) -> Result<Self, EngineError> {
        if pack.len() > MAX_PACK_SIZE {
            return Err(EngineError::RulePackTooLarge {
                size: pack.len(),
                limit: MAX_PACK_SIZE,
            });
        }
        if signature.len() > MAX_SIGNATURE_FILE_SIZE {
            return Err(EngineError::RulePackMalformed(
                "signature file is too large".into(),
            ));
        }
        let sig: SignatureFile = serde_json::from_slice(signature)
            .map_err(|e| EngineError::RulePackMalformed(format!("signature file: {e}")))?;
        if sig.format_version != 1 || sig.algorithm != "ed25519" {
            return Err(EngineError::RulePackMalformed(
                "unsupported signature format".into(),
            ));
        }
        let key = keys
            .iter()
            .find(|k| k.key_id == sig.key_id)
            .ok_or_else(|| EngineError::RulePackUnknownKey {
                key_id: sig.key_id.clone(),
            })?;
        let sig_bytes: [u8; 64] = hex::decode(sig.signature_hex.trim())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(EngineError::RulePackSignatureInvalid)?;
        let verifying_key = VerifyingKey::from_bytes(&key.public_key)
            .map_err(|_| EngineError::RulePackSignatureInvalid)?;
        verifying_key
            .verify_strict(pack, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| EngineError::RulePackSignatureInvalid)?;

        // Teprve podepsaný obsah jde do parseru.
        let file: PackFile = serde_json::from_slice(pack)
            .map_err(|e| EngineError::RulePackMalformed(format!("rule pack: {e}")))?;
        Self::compile(file, key, now_unix)
    }

    fn compile(file: PackFile, key: &TrustedKey, now_unix: i64) -> Result<Self, EngineError> {
        let bad = |msg: String| EngineError::RulePackMalformed(msg);
        if file.format_version != FORMAT_VERSION {
            return Err(bad(format!(
                "unsupported format_version {}",
                file.format_version
            )));
        }
        if key.test_only && !file.test_pack {
            return Err(bad("a test key may only sign a test pack".into()));
        }
        let required = parse_version(&file.min_engine_version)
            .ok_or_else(|| bad("min_engine_version is not x.y.z".into()))?;
        let current = parse_version(ENGINE_VERSION).unwrap_or((0, 0, 0));
        if required > current {
            return Err(EngineError::RulePackIncompatible {
                required: file.min_engine_version.clone(),
                current: ENGINE_VERSION.to_string(),
            });
        }
        check_text("pack_id", &file.pack_id, MAX_ID_LEN)?;
        check_text("version", &file.version, MAX_ID_LEN)?;
        if file.rules.is_empty() || file.rules.len() > MAX_RULES {
            return Err(bad(format!(
                "rule count must be 1..={MAX_RULES}, got {}",
                file.rules.len()
            )));
        }

        let mut rules = Vec::with_capacity(file.rules.len());
        let mut ids = HashSet::new();
        let mut hash_index = HashMap::new();
        let mut pattern_bytes = Vec::new();
        let mut pattern_rules = Vec::new();
        let mut eicar_rule = None;

        for def in file.rules {
            check_id(&def.id)?;
            if !ids.insert(def.id.clone()) {
                return Err(bad(format!("duplicate rule id {}", def.id)));
            }
            check_text("name", &def.name, 200)?;
            check_text("description.cs", &def.description.cs, MAX_TEXT_LEN)?;
            check_text("description.en", &def.description.en, MAX_TEXT_LEN)?;
            let index = rules.len();
            match def.kind {
                RuleKind::Sha256 => {
                    if def.pattern_hex.is_some() {
                        return Err(bad(format!("{}: sha256 rule has pattern_hex", def.id)));
                    }
                    let digest = def
                        .sha256
                        .as_deref()
                        .and_then(|h| hex::decode(h).ok())
                        .and_then(|v| <[u8; 32]>::try_from(v).ok())
                        .ok_or_else(|| bad(format!("{}: sha256 must be 64 hex chars", def.id)))?;
                    if digest == EMPTY_FILE_SHA256 {
                        return Err(bad(format!(
                            "{}: the empty-file hash is not allowed",
                            def.id
                        )));
                    }
                    if hash_index.insert(digest, index).is_some() {
                        return Err(bad(format!("{}: duplicate sha256 indicator", def.id)));
                    }
                }
                RuleKind::Bytes => {
                    if def.sha256.is_some() {
                        return Err(bad(format!("{}: bytes rule has sha256", def.id)));
                    }
                    let pattern = def
                        .pattern_hex
                        .as_deref()
                        .and_then(|h| hex::decode(h).ok())
                        .ok_or_else(|| bad(format!("{}: pattern_hex is not hex", def.id)))?;
                    if !(MIN_PATTERN_LEN..=MAX_PATTERN_LEN).contains(&pattern.len()) {
                        return Err(bad(format!(
                            "{}: pattern length must be {MIN_PATTERN_LEN}..={MAX_PATTERN_LEN} bytes",
                            def.id
                        )));
                    }
                    pattern_bytes.push(pattern);
                    pattern_rules.push(index);
                }
                RuleKind::Eicar => {
                    if def.sha256.is_some() || def.pattern_hex.is_some() {
                        return Err(bad(format!("{}: eicar rule takes no data", def.id)));
                    }
                    if eicar_rule.replace(index).is_some() {
                        return Err(bad("more than one eicar rule".into()));
                    }
                }
            }
            rules.push(RuleMeta {
                test_only: def.severity == Severity::TestOnly || file.test_pack,
                id: def.id,
                version: def.version,
                name: def.name,
                description: def.description,
                severity: def.severity,
            });
        }

        let max_pattern_len = pattern_bytes.iter().map(Vec::len).max().unwrap_or(0);
        let patterns = if pattern_bytes.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::Standard)
                    .build(&pattern_bytes)
                    .map_err(|e| bad(format!("pattern automaton: {e}")))?,
            )
        };

        let info = RulePackInfo {
            pack_id: file.pack_id,
            version: file.version,
            sequence: file.sequence,
            rule_count: u32::try_from(rules.len()).unwrap_or(u32::MAX),
            signing_key_id: key.key_id.clone(),
            test_pack: file.test_pack,
            created_at_unix: file.created_at_unix,
            expires_at_unix: file.expires_at_unix,
            expired: now_unix > file.expires_at_unix,
        };

        Ok(Self {
            info,
            rules,
            hash_index,
            patterns,
            pattern_rules,
            pattern_bytes,
            max_pattern_len,
            eicar_rule,
        })
    }

    pub fn info(&self) -> &RulePackInfo {
        &self.info
    }

    pub fn rule(&self, index: usize) -> &RuleMeta {
        &self.rules[index]
    }

    pub fn rules(&self) -> &[RuleMeta] {
        &self.rules
    }

    pub fn hash_rule(&self, digest: &[u8; 32]) -> Option<usize> {
        self.hash_index.get(digest).copied()
    }

    pub fn patterns(&self) -> Option<&AhoCorasick> {
        self.patterns.as_ref()
    }

    pub fn pattern_count(&self) -> usize {
        self.pattern_rules.len()
    }

    pub fn pattern_rule(&self, pattern: usize) -> usize {
        self.pattern_rules[pattern]
    }

    pub fn pattern(&self, pattern: usize) -> &[u8] {
        &self.pattern_bytes[pattern]
    }

    pub fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
    }

    pub fn eicar_rule(&self) -> Option<usize> {
        self.eicar_rule
    }
}

fn check_id(id: &str) -> Result<(), EngineError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(EngineError::RulePackMalformed(format!(
            "rule id {id:?} must be 1..={MAX_ID_LEN} chars of A-Z, 0-9, '-' or '_'"
        )))
    }
}

fn check_text(field: &str, value: &str, max: usize) -> Result<(), EngineError> {
    if value.trim().is_empty() || value.chars().count() > max {
        return Err(EngineError::RulePackMalformed(format!(
            "{field} must be 1..={max} characters"
        )));
    }
    Ok(())
}

/// Parsuje `x.y.z` (případnou příponu za `-` ignoruje).
pub(crate) fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let core = text.split('-').next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (parts.next()??, parts.next()??, parts.next()??);
    if parts.next().is_some() {
        return None;
    }
    Some(v)
}

/// Podepisování sad pravidel (CLI a testy). Aplikace tuto část neobsahuje.
#[cfg(feature = "signing")]
pub mod signing {
    use ed25519_dalek::{Signer, SigningKey};

    /// Veřejný klíč k soukromému semínku.
    pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    /// Vrátí obsah souboru `.sig` pro přesné bajty sady.
    pub fn sign_pack(pack: &[u8], seed: &[u8; 32], key_id: &str) -> String {
        let signature = SigningKey::from_bytes(seed).sign(pack);
        let value = serde_json::json!({
            "format_version": 1,
            "key_id": key_id,
            "algorithm": "ed25519",
            "signature_hex": hex::encode(signature.to_bytes()),
        });
        format!("{value:#}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("1.2.3-test.1"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("a.b.c"), None);
    }

    #[test]
    fn rule_ids() {
        assert!(check_id("HH-TEST-0001").is_ok());
        assert!(check_id("hh-test").is_err());
        assert!(check_id("").is_err());
        assert!(check_id(&"A".repeat(65)).is_err());
    }
}
