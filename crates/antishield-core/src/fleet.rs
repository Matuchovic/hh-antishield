//! Firemní správa: kryptografie a protokol mezi správcem a firemními Macy.
//!
//! Server je jen schránka a nic z obsahu nevidí ani nemůže podvrhnout:
//! - Příkaz podepíše klíč správce (Ed25519) a zašifruje se jen pro cílový Mac
//!   (X25519, HKDF-SHA256, ChaCha20-Poly1305). Mac ho přijme jen s platným
//!   podpisem, pro svou firmu a sebe, v době platnosti a jen jednou.
//! - Zprávy a výsledky z Macu podepíše klíč Macu a zašifrují se jen pro správce.
//! - Klíče si správce a Mac předají přes schránku, ale svážou je jednorázovým
//!   kódem (HMAC). Schránka kód nezná, takže klíče nemůže vyměnit za své.
//! - Mac provede jen příkazy z pevného seznamu a jen v mezích zásad, se
//!   kterými jeho uživatel souhlasil. Velké soubory a Koš nikdy, ani když by to
//!   příkaz správce chtěl.
//!
//! Modul nedělá síť ani nic neuklízí; to dělá aplikace podle ověřených dat.

use std::io::Write;
use std::path::Path;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use data_encoding::{BASE64URL_NOPAD, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as BoxPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::cleanup::{CleanCategory, CleanItem, CleanMethod, CleanScan};
use crate::speed::{DiskInfo, MemoryPressure};
use crate::status::ProtectionLevel;

/// Verze protokolu ve všech zprávách.
pub const VERSION: u8 = 1;
const DOMAIN: &str = "hh-antishield/fleet/v1/";

/// Kód pozvánky Macu do firmy.
pub const INVITE_PREFIX: &str = "HHF1";
/// Aktivační kód pro založení firmy (vydává provozovatel schránky).
pub const ACTIVATION_PREFIX: &str = "HHA1";

const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 24 * 60 * MINUTE_MS;
/// Jak dlouho platí pozvánka a příkaz (offline Mac ho provede, až se připojí).
pub const INVITE_LIFETIME_MS: u64 = 7 * DAY_MS;
pub const COMMAND_LIFETIME_MS: u64 = 7 * DAY_MS;
/// Delší platnost Mac odmítne (ochrana proti „věčným“ příkazům).
pub const MAX_COMMAND_LIFETIME_MS: u64 = 8 * DAY_MS;
/// Tolerance rozdílu hodin mezi Macy.
pub const CLOCK_SKEW_MS: u64 = 10 * MINUTE_MS;
pub const MAX_NAME_CHARS: usize = 60;
pub const MAX_REPORT_THREATS: usize = 20;
const MAX_PATH_CHARS: usize = 1024;
const MAX_TEXT_CHARS: usize = 200;
/// Největší zpráva, kterou modul otevře (zašifrovaný text v base64).
pub const MAX_SEALED_CHARS: usize = 64 * 1024;

/// Kategorie, které na dálku nejdou nikdy: soubory uživatele a Koš.
pub const NEVER_REMOTE: [CleanCategory; 2] = [CleanCategory::LargeFiles, CleanCategory::Trash];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FleetError {
    #[error("the code is not valid")]
    InvalidCode,
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("the message is not authentic")]
    NotAuthentic,
    #[error("the message is for another fleet or device")]
    WrongTarget,
    #[error("the message has expired")]
    Expired,
    #[error("the command was already processed")]
    Replay,
    #[error("not allowed: {0}")]
    NotAllowed(String),
    #[error("the system random number generator failed")]
    Random,
}

impl FleetError {
    /// Stabilní kód chyby; rozhraní podle něj vybírá text.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidCode => "fleet_invalid_code",
            Self::Malformed(_) => "fleet_malformed",
            Self::NotAuthentic => "fleet_not_authentic",
            Self::WrongTarget => "fleet_wrong_target",
            Self::Expired => "fleet_expired",
            Self::Replay => "fleet_replay",
            Self::NotAllowed(_) => "fleet_not_allowed",
            Self::Random => "fleet_random",
        }
    }
}

fn malformed(what: impl Into<String>) -> FleetError {
    FleetError::Malformed(what.into())
}

// ---------- Kódování ----------

pub fn b64(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

pub fn unb64(text: &str) -> Result<Vec<u8>, FleetError> {
    BASE64URL_NOPAD
        .decode(text.as_bytes())
        .map_err(|_| malformed("base64"))
}

fn unb64_32(text: &str) -> Result<[u8; 32], FleetError> {
    unb64(text)?.try_into().map_err(|_| malformed("key length"))
}

/// Klíče a tajemství v JSON jako base64url.
mod b64_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::b64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        super::unb64_32(&text).map_err(serde::de::Error::custom)
    }
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], FleetError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| FleetError::Random)?;
    Ok(out)
}

/// Náhodný token pro schránku (32 B, base64url).
pub fn random_token() -> Result<String, FleetError> {
    Ok(b64(&random_bytes::<32>()?))
}

/// Náhodný identifikátor příkazu (UUID v4).
pub fn random_id() -> Result<String, FleetError> {
    let mut bytes = random_bytes::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok() && id.len() == 36
}

/// Jméno pro zobrazení: bez řídicích znaků, 1–60 znaků.
pub fn clean_name(name: &str) -> Result<String, FleetError> {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).collect();
    let cleaned = cleaned.trim();
    let count = cleaned.chars().count();
    if count == 0 || count > MAX_NAME_CHARS {
        return Err(FleetError::NotAllowed(format!(
            "a name must have 1 to {MAX_NAME_CHARS} characters"
        )));
    }
    Ok(cleaned.to_string())
}

fn bounded_text(text: &str, max: usize) -> bool {
    text.chars().count() <= max && !text.chars().any(char::is_control)
}

// ---------- Klíče ----------

/// Veřejné klíče správce nebo Macu: podpis (Ed25519) a šifrování (X25519).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicKeys {
    #[serde(with = "b64_32")]
    pub sign: [u8; 32],
    #[serde(with = "b64_32", rename = "box")]
    pub seal: [u8; 32],
}

impl PublicKeys {
    /// Otisk k ověření mezi lidmi (64 bitů, šestnáctkově, např. „7F3A91C24B0E5D11“).
    pub fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(DOMAIN.as_bytes());
        hash.update(b"fingerprint\0");
        hash.update(self.sign);
        hash.update(self.seal);
        hex::encode_upper(&hash.finalize()[..8])
    }
}

/// Tajné klíče (ukládají se jen do souboru s právy 0600, v paměti se mažou).
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentitySecret {
    #[serde(with = "b64_32")]
    sign: [u8; 32],
    #[serde(with = "b64_32", rename = "box")]
    seal: [u8; 32],
}

impl Drop for IdentitySecret {
    fn drop(&mut self) {
        self.sign.zeroize();
        self.seal.zeroize();
    }
}

impl std::fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentitySecret(…)")
    }
}

/// Klíče správce nebo Macu.
pub struct Identity {
    sign: SigningKey,
    seal: StaticSecret,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.public().fingerprint())
    }
}

impl Identity {
    pub fn generate() -> Result<Self, FleetError> {
        let secret = IdentitySecret {
            sign: random_bytes()?,
            seal: random_bytes()?,
        };
        Ok(Self::from_secret(&secret))
    }

    pub fn from_secret(secret: &IdentitySecret) -> Self {
        Self {
            sign: SigningKey::from_bytes(&secret.sign),
            seal: StaticSecret::from(secret.seal),
        }
    }

    pub fn secret(&self) -> IdentitySecret {
        IdentitySecret {
            sign: self.sign.to_bytes(),
            seal: self.seal.to_bytes(),
        }
    }

    pub fn public(&self) -> PublicKeys {
        PublicKeys {
            sign: self.sign.verifying_key().to_bytes(),
            seal: BoxPublicKey::from(&self.seal).to_bytes(),
        }
    }
}

// ---------- Šifrování a podpis ----------

fn context_label(context: &str) -> Vec<u8> {
    format!("{DOMAIN}{context}").into_bytes()
}

fn seal_key(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    // 32 bajtů je vždy v limitu HKDF-SHA256.
    let _ = hkdf.expand(&context_label("seal"), &mut key);
    key
}

/// Zašifruje zprávu jen pro držitele klíče `recipient` (jednorázový klíč
/// odesílatele, X25519 + HKDF-SHA256 + ChaCha20-Poly1305). `context` je
/// součástí ověření, takže zprávu nejde vydávat za jiný druh.
pub fn seal(recipient: &[u8; 32], context: &str, plaintext: &[u8]) -> Result<String, FleetError> {
    let ephemeral = StaticSecret::from(random_bytes::<32>()?);
    let ephemeral_public = BoxPublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&BoxPublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(FleetError::NotAllowed("invalid recipient key".into()));
    }
    let mut key = seal_key(shared.as_bytes(), &ephemeral_public, recipient);
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    key.zeroize();
    // Klíč je pro každou zprávu nový, proto stačí nulová nonce.
    let ciphertext = cipher
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: plaintext,
                aad: &context_label(context),
            },
        )
        .map_err(|_| malformed("encryption"))?;
    let mut out = Vec::with_capacity(1 + 32 + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&ciphertext);
    Ok(b64(&out))
}

/// Otevře zprávu zašifrovanou pro `identity`.
pub fn open(identity: &Identity, context: &str, sealed: &str) -> Result<Vec<u8>, FleetError> {
    if sealed.len() > MAX_SEALED_CHARS {
        return Err(malformed("message too large"));
    }
    let bytes = unb64(sealed)?;
    if bytes.len() < 1 + 32 + 16 || bytes[0] != VERSION {
        return Err(malformed("sealed message"));
    }
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&bytes[1..33]);
    let shared = identity.seal.diffie_hellman(&BoxPublicKey::from(ephemeral));
    if !shared.was_contributory() {
        return Err(FleetError::NotAuthentic);
    }
    let recipient = BoxPublicKey::from(&identity.seal).to_bytes();
    let mut key = seal_key(shared.as_bytes(), &ephemeral, &recipient);
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    key.zeroize();
    cipher
        .decrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &bytes[33..],
                aad: &context_label(context),
            },
        )
        .map_err(|_| FleetError::NotAuthentic)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    /// Podepsaná data (base64url).
    p: String,
    /// Podpis Ed25519 (base64url).
    s: String,
}

fn signed_message(context: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = context_label(context);
    message.push(0);
    message.extend_from_slice(payload);
    message
}

/// Podepíše data klíčem `identity` (s oddělením podle druhu zprávy).
pub fn sign(identity: &Identity, context: &str, payload: &[u8]) -> Vec<u8> {
    let signature = identity.sign.sign(&signed_message(context, payload));
    let signed = Signed {
        p: b64(payload),
        s: b64(&signature.to_bytes()),
    };
    serde_json::to_vec(&signed).unwrap_or_default()
}

/// Ověří podpis klíčem `signer` a vrátí podepsaná data.
pub fn verify(signer: &[u8; 32], context: &str, signed: &[u8]) -> Result<Vec<u8>, FleetError> {
    let signed: Signed = serde_json::from_slice(signed).map_err(|_| malformed("signed message"))?;
    let payload = unb64(&signed.p)?;
    let signature: [u8; 64] = unb64(&signed.s)?
        .try_into()
        .map_err(|_| malformed("signature length"))?;
    let key = VerifyingKey::from_bytes(signer).map_err(|_| FleetError::NotAuthentic)?;
    key.verify_strict(
        &signed_message(context, &payload),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| FleetError::NotAuthentic)?;
    Ok(payload)
}

/// Podepíše a zašifruje hodnotu pro příjemce.
pub fn sign_and_seal<T: Serialize>(
    sender: &Identity,
    recipient: &PublicKeys,
    context: &str,
    value: &T,
) -> Result<String, FleetError> {
    let payload = serde_json::to_vec(value).map_err(|e| malformed(e.to_string()))?;
    seal(&recipient.seal, context, &sign(sender, context, &payload))
}

/// Otevře zprávu pro `recipient`, ověří podpis odesílatele a přečte hodnotu.
pub fn open_and_verify<T: DeserializeOwned>(
    recipient: &Identity,
    sender: &PublicKeys,
    context: &str,
    sealed: &str,
) -> Result<T, FleetError> {
    let signed = open(recipient, context, sealed)?;
    let payload = verify(&sender.sign, context, &signed)?;
    serde_json::from_slice(&payload).map_err(|e| malformed(e.to_string()))
}

// ---------- Jednorázové kódy ----------

const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford() -> &'static Encoding {
    static ENCODING: std::sync::OnceLock<Encoding> = std::sync::OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str(CROCKFORD);
        // Abeceda je pevná a platná; selhat nemůže.
        spec.encoding().unwrap_or_else(|_| BASE64URL_NOPAD.clone())
    })
}

fn checksum(prefix: &str, secret: &[u8; 15]) -> char {
    let mut hash = Sha256::new();
    hash.update(prefix.as_bytes());
    hash.update(secret);
    let index = usize::from(hash.finalize()[0] & 31);
    CROCKFORD
        .as_bytes()
        .get(index)
        .copied()
        .map_or('0', char::from)
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    #[allow(clippy::expect_used)]
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Jednorázový tajný kód: 120 náhodných bitů a kontrolní znak, např.
/// `HHF1-7K2MQ-9TBW4-XDR8P-L3NCV-4QZ8M`. Schránka zná jen odvozený
/// identifikátor, ne kód; vazby klíčů (HMAC) proto podvrhnout nemůže.
#[derive(Clone)]
pub struct OneTimeCode {
    prefix: &'static str,
    secret: [u8; 15],
}

impl Drop for OneTimeCode {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for OneTimeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OneTimeCode({}-…)", self.prefix)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    /// Vázaná data (base64url).
    p: String,
    /// HMAC-SHA256 (base64url).
    m: String,
}

impl OneTimeCode {
    pub fn generate(prefix: &'static str) -> Result<Self, FleetError> {
        Ok(Self {
            prefix,
            secret: random_bytes()?,
        })
    }

    /// Přečte kód (velikost písmen, mezery a pomlčky nevadí; O = 0, I a L = 1).
    pub fn parse(prefix: &'static str, text: &str) -> Result<Self, FleetError> {
        let compact: String = text
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            })
            .collect();
        let body = compact
            .strip_prefix(prefix)
            .ok_or(FleetError::InvalidCode)?;
        if body.len() != 25 || !body.is_ascii() {
            return Err(FleetError::InvalidCode);
        }
        let (data, check) = body.split_at(24);
        let secret: [u8; 15] = crockford()
            .decode(data.as_bytes())
            .map_err(|_| FleetError::InvalidCode)?
            .try_into()
            .map_err(|_| FleetError::InvalidCode)?;
        if !check.starts_with(checksum(prefix, &secret)) {
            return Err(FleetError::InvalidCode);
        }
        Ok(Self { prefix, secret })
    }

    /// Podoba bez pomlček (tak ji posílá aplikace schránce).
    pub fn canonical(&self) -> String {
        format!(
            "{}{}{}",
            self.prefix,
            crockford().encode(&self.secret),
            checksum(self.prefix, &self.secret)
        )
    }

    /// Podoba pro lidi: prefix a pět skupin po pěti znacích.
    pub fn display(&self) -> String {
        let canonical = self.canonical();
        let body = &canonical[self.prefix.len()..];
        let groups: Vec<&str> = (0..5).filter_map(|i| body.get(i * 5..i * 5 + 5)).collect();
        format!("{}-{}", self.prefix, groups.join("-"))
    }

    /// Identifikátor pozvánky ve schránce (odvozený, kód z něj zjistit nejde).
    pub fn token_id(&self) -> String {
        b64(&hmac(&self.secret, &[DOMAIN.as_bytes(), b"token-id"])[..16])
    }

    /// SHA-256 kanonické podoby (tak schránka ukládá aktivační kódy).
    pub fn digest_hex(&self) -> String {
        hex::encode(Sha256::digest(self.canonical().as_bytes()))
    }

    fn mac(&self, label: &str, payload: &[u8]) -> [u8; 32] {
        let key = hmac(&self.secret, &[DOMAIN.as_bytes(), b"bind-key"]);
        hmac(&key, &[label.as_bytes(), b"\0", payload])
    }

    /// Sváže hodnotu s kódem: kdo kód nezná, nevytvoří ani nezmění ji.
    pub fn bind<T: Serialize>(&self, label: &str, value: &T) -> Result<String, FleetError> {
        let payload = serde_json::to_vec(value).map_err(|e| malformed(e.to_string()))?;
        let bound = Bound {
            p: b64(&payload),
            m: b64(&self.mac(label, &payload)),
        };
        serde_json::to_string(&bound).map_err(|e| malformed(e.to_string()))
    }

    pub fn unbind<T: DeserializeOwned>(&self, label: &str, text: &str) -> Result<T, FleetError> {
        if text.len() > 8 * 1024 {
            return Err(malformed("bound value too large"));
        }
        let bound: Bound = serde_json::from_str(text).map_err(|_| malformed("bound value"))?;
        let payload = unb64(&bound.p)?;
        let mac = unb64(&bound.m)?;
        // Porovnání v konstantním čase.
        let key = hmac(&self.secret, &[DOMAIN.as_bytes(), b"bind-key"]);
        let mut check =
            <HmacSha256 as KeyInit>::new_from_slice(&key).map_err(|_| FleetError::NotAuthentic)?;
        check.update(label.as_bytes());
        check.update(b"\0");
        check.update(&payload);
        check
            .verify_slice(&mac)
            .map_err(|_| FleetError::NotAuthentic)?;
        serde_json::from_slice(&payload).map_err(|e| malformed(e.to_string()))
    }
}

// ---------- Zásady ----------

/// Co smí správce na Macu na dálku. Uživatel je vidí a potvrdí při připojení.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    /// Hned (uživatel dostane oznámení).
    pub auto: Vec<CleanCategory>,
    /// Jen po souhlasu uživatele.
    pub consent: Vec<CleanCategory>,
}

impl Policy {
    /// Výchozí zásady: mezipaměti a protokoly hned, instalátory a zbytky se souhlasem.
    pub fn standard() -> Self {
        Self {
            auto: vec![
                CleanCategory::AppCaches,
                CleanCategory::Logs,
                CleanCategory::Developer,
            ],
            consent: vec![CleanCategory::Installers, CleanCategory::Leftovers],
        }
    }

    pub fn validate(&self) -> Result<(), FleetError> {
        let all: Vec<CleanCategory> = self.auto.iter().chain(&self.consent).copied().collect();
        for (i, category) in all.iter().enumerate() {
            if NEVER_REMOTE.contains(category) {
                return Err(FleetError::NotAllowed(format!(
                    "{category:?} is never remote"
                )));
            }
            if all[..i].contains(category) {
                return Err(FleetError::NotAllowed("a category is listed twice".into()));
            }
        }
        Ok(())
    }

    /// Rozdělí kategorie příkazu na „hned“ a „se souhlasem“.
    pub fn split(&self, categories: &[CleanCategory]) -> (Vec<CleanCategory>, Vec<CleanCategory>) {
        let auto = categories
            .iter()
            .copied()
            .filter(|c| self.auto.contains(c))
            .collect();
        let consent = categories
            .iter()
            .copied()
            .filter(|c| self.consent.contains(c))
            .collect();
        (auto, consent)
    }
}

// ---------- Připojení Macu ----------

/// Co Mac uvidí před připojením (svázané s kódem pozvánky).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminBundle {
    pub v: u8,
    pub fleet_id: String,
    pub fleet_name: String,
    pub admin_name: String,
    pub admin: PublicKeys,
    pub policy: Policy,
    /// Jméno, pod kterým správce Mac uvidí.
    pub device_name: String,
    pub expires_at_ms: u64,
}

pub const ADMIN_BUNDLE: &str = "admin-bundle";
pub const DEVICE_BUNDLE: &str = "device-bundle";

impl AdminBundle {
    /// Kontrola na Macu po ověření vazby: verze, platnost, jména a zásady.
    pub fn check(&self, now_ms: u64) -> Result<(), FleetError> {
        if self.v != VERSION || !valid_id(&self.fleet_id) {
            return Err(malformed("admin bundle"));
        }
        if self.expires_at_ms <= now_ms {
            return Err(FleetError::Expired);
        }
        for name in [&self.fleet_name, &self.admin_name, &self.device_name] {
            if clean_name(name)? != *name {
                return Err(malformed("name"));
            }
        }
        self.policy.validate()
    }
}

/// Klíče Macu pro správce (svázané s kódem pozvánky).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceBundle {
    pub v: u8,
    pub fleet_id: String,
    pub token_id: String,
    /// Identifikátor Macu ve schránce (svázaný s klíči, schránka ho nevymění).
    pub device_id: String,
    pub device: PublicKeys,
}

impl DeviceBundle {
    /// Kontrola u správce: verze, firma, pozvánka a identifikátor ze schránky.
    pub fn check(&self, fleet_id: &str, token_id: &str, device_id: &str) -> Result<(), FleetError> {
        if self.v != VERSION || !valid_id(&self.device_id) {
            return Err(malformed("device bundle"));
        }
        if self.fleet_id != fleet_id || self.token_id != token_id || self.device_id != device_id {
            return Err(FleetError::WrongTarget);
        }
        Ok(())
    }
}

// ---------- Příkazy ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CommandKind {
    /// Úklid kategorií (část „se souhlasem“ čeká na uživatele).
    Cleanup,
    /// Rychlá kontrola.
    Scan,
    /// Izolace nalezených hrozeb do karantény.
    Isolate,
    /// Správce Mac odebral z firmy.
    Unenroll,
}

pub const COMMAND: &str = "command";
pub const REPORT: &str = "report";
pub const RESULT: &str = "result";
pub const LEAVE: &str = "leave";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Command {
    pub v: u8,
    pub id: String,
    pub fleet_id: String,
    pub device_id: String,
    pub kind: CommandKind,
    pub categories: Vec<CleanCategory>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Kde Mac ve firmě je a komu věří (z připojení).
#[derive(Debug, Clone, Copy)]
pub struct Membership<'a> {
    pub fleet_id: &'a str,
    pub device_id: &'a str,
    pub admin: &'a PublicKeys,
    pub policy: &'a Policy,
}

/// Mac přijme příkaz jen s platným podpisem správce, pro svou firmu a sebe,
/// v době platnosti, poprvé a v mezích zásad. Velké soubory a Koš nikdy.
pub fn accept_command(
    identity: &Identity,
    membership: &Membership<'_>,
    sealed: &str,
    now_ms: u64,
    seen: impl Fn(&str) -> bool,
) -> Result<Command, FleetError> {
    let command: Command = open_and_verify(identity, membership.admin, COMMAND, sealed)?;
    if command.v != VERSION || !valid_id(&command.id) {
        return Err(malformed("command"));
    }
    if command.fleet_id != membership.fleet_id || command.device_id != membership.device_id {
        return Err(FleetError::WrongTarget);
    }
    if command.issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS)
        || command.expires_at_ms <= now_ms
        || command.expires_at_ms.saturating_sub(command.issued_at_ms) > MAX_COMMAND_LIFETIME_MS
    {
        return Err(FleetError::Expired);
    }
    if seen(&command.id) {
        return Err(FleetError::Replay);
    }
    match command.kind {
        CommandKind::Cleanup => {
            if command.categories.is_empty() {
                return Err(FleetError::NotAllowed("no category".into()));
            }
            for (i, category) in command.categories.iter().enumerate() {
                let allowed = membership.policy.auto.contains(category)
                    || membership.policy.consent.contains(category);
                if !allowed
                    || NEVER_REMOTE.contains(category)
                    || command.categories[..i].contains(category)
                {
                    return Err(FleetError::NotAllowed(format!("{category:?}")));
                }
            }
        }
        CommandKind::Scan | CommandKind::Isolate | CommandKind::Unenroll => {
            if !command.categories.is_empty() {
                return Err(FleetError::NotAllowed("categories".into()));
            }
        }
    }
    Ok(command)
}

// ---------- Zprávy a výsledky z Macu ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResultState {
    Running,
    AwaitingConsent,
    Done,
    Declined,
    Failed,
    /// Uživatel o souhlasu nerozhodl do konce platnosti příkazu.
    Expired,
}

impl ResultState {
    /// Konečný stav: příkaz už nic dalšího neudělá.
    pub fn is_final(self) -> bool {
        !matches!(self, Self::Running | Self::AwaitingConsent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandResult {
    pub v: u8,
    pub command_id: String,
    pub device_id: String,
    /// Pořadí výsledků Macu (starší výsledek nepřepíše novější).
    pub seq: u64,
    pub at_ms: u64,
    pub state: ResultState,
    pub freed_bytes: u64,
    pub trashed_bytes: u64,
    pub files: u64,
    pub threats: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LastScan {
    pub at_ms: u64,
    pub files: u64,
    pub threats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreatReport {
    pub rule_name: String,
    pub severity: crate::Severity,
    pub path: String,
    pub detected_at_ms: u64,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryBytes {
    pub category: CleanCategory,
    pub bytes: u64,
}

/// Kolik jde uklidit: jen velikosti po kategoriích, bez názvů souborů.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupEstimate {
    pub measured_at_ms: u64,
    pub categories: Vec<CategoryBytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryState {
    pub total: u64,
    pub used: u64,
    pub pressure: Option<MemoryPressure>,
}

/// Stav Macu pro správce. Obsahuje jen to, co uživatel při připojení viděl:
/// ochranu, hrozby, disk, paměť a velikosti k úklidu. Žádné soubory uživatele.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub v: u8,
    pub device_id: String,
    pub fleet_id: String,
    pub seq: u64,
    pub created_at_ms: u64,
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

impl Report {
    /// Kontrola u správce: rozumné délky textů a počty.
    pub fn check(&self) -> Result<(), FleetError> {
        let texts = [
            (&self.app_version, 40),
            (&self.os_version, 80),
            (&self.model, 120),
            (&self.rules_version, 60),
        ];
        if self.v != VERSION
            || texts.iter().any(|(text, max)| !bounded_text(text, *max))
            || self
                .protection_note
                .as_ref()
                .is_some_and(|n| !bounded_text(n, MAX_TEXT_CHARS))
            || self.threats.len() > MAX_REPORT_THREATS
            || self.threats.iter().any(|t| {
                !bounded_text(&t.rule_name, MAX_TEXT_CHARS)
                    || !bounded_text(&t.path, MAX_PATH_CHARS)
            })
            || self
                .cleanup
                .as_ref()
                .is_some_and(|c| c.categories.len() > 7)
        {
            return Err(malformed("report"));
        }
        Ok(())
    }
}

/// Uživatel Mac od firmy odpojil (podepsané oznámení pro správce).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaveNotice {
    pub v: u8,
    pub fleet_id: String,
    pub device_id: String,
    pub at_ms: u64,
}

/// Správce otevře zprávu Macu a ověří, že je opravdu od něj a pro tuto firmu.
pub fn open_report(
    admin: &Identity,
    device: &PublicKeys,
    fleet_id: &str,
    device_id: &str,
    sealed: &str,
) -> Result<Report, FleetError> {
    let report: Report = open_and_verify(admin, device, REPORT, sealed)?;
    if report.fleet_id != fleet_id || report.device_id != device_id {
        return Err(FleetError::WrongTarget);
    }
    report.check()?;
    Ok(report)
}

pub fn open_result(
    admin: &Identity,
    device: &PublicKeys,
    device_id: &str,
    command_id: &str,
    sealed: &str,
) -> Result<CommandResult, FleetError> {
    let result: CommandResult = open_and_verify(admin, device, RESULT, sealed)?;
    if result.v != VERSION || result.device_id != device_id || result.command_id != command_id {
        return Err(FleetError::WrongTarget);
    }
    if result
        .error
        .as_ref()
        .is_some_and(|e| !bounded_text(e, MAX_TEXT_CHARS))
    {
        return Err(malformed("result"));
    }
    Ok(result)
}

pub fn open_leave(
    admin: &Identity,
    device: &PublicKeys,
    fleet_id: &str,
    device_id: &str,
    sealed: &str,
) -> Result<LeaveNotice, FleetError> {
    let notice: LeaveNotice = open_and_verify(admin, device, LEAVE, sealed)?;
    if notice.v != VERSION || notice.fleet_id != fleet_id || notice.device_id != device_id {
        return Err(FleetError::WrongTarget);
    }
    Ok(notice)
}

// ---------- Úklid na dálku ----------

/// Co Mac na dálku uklidí: jen předvybrané (bezpečné) položky z vlastního
/// čerstvého skenu v kategoriích příkazu. Nikdy soubory uživatele, Koš ani
/// jeho vysypání, i kdyby to příkaz chtěl.
pub fn remote_selection<'a>(
    scan: &'a CleanScan,
    categories: &[CleanCategory],
) -> Vec<&'a CleanItem> {
    scan.items
        .iter()
        .filter(|item| {
            item.recommended
                && item.method != CleanMethod::EmptyTrash
                && categories.contains(&item.category)
                && !NEVER_REMOTE.contains(&item.category)
        })
        .collect()
}

/// Kolik jde uklidit, pro správce: u kategorií na dálku jen předvybrané
/// položky, u souborů uživatele a Koše celková velikost (jen k informaci).
pub fn cleanup_estimate(scan: &CleanScan) -> CleanupEstimate {
    let mut categories: Vec<CategoryBytes> = Vec::new();
    for item in &scan.items {
        let counts = NEVER_REMOTE.contains(&item.category) || item.recommended;
        if !counts {
            continue;
        }
        match categories.iter_mut().find(|c| c.category == item.category) {
            Some(entry) => entry.bytes += item.bytes,
            None => categories.push(CategoryBytes {
                category: item.category,
                bytes: item.bytes,
            }),
        }
    }
    CleanupEstimate {
        measured_at_ms: scan.finished_at_ms,
        categories,
    }
}

// ---------- Uložení ----------

/// Zapíše soubor jen pro vlastníka (0600) atomicky: dočasný soubor, fsync,
/// přejmenování. Složka se vytvoří s právy 0700.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let temp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)
}

/// Načte JSON s limitem velikosti; chybějící soubor je `None`.
pub fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> std::io::Result<Option<T>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("file too large"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const FLEET: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    const DEVICE: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

    fn command(kind: CommandKind, categories: Vec<CleanCategory>) -> Command {
        Command {
            v: VERSION,
            id: random_id().unwrap(),
            fleet_id: FLEET.into(),
            device_id: DEVICE.into(),
            kind,
            categories,
            issued_at_ms: NOW,
            expires_at_ms: NOW + COMMAND_LIFETIME_MS,
        }
    }

    struct Pair {
        admin: Identity,
        device: Identity,
        policy: Policy,
    }

    impl Pair {
        fn new() -> Self {
            Self {
                admin: Identity::generate().unwrap(),
                device: Identity::generate().unwrap(),
                policy: Policy::standard(),
            }
        }

        fn issue(&self, cmd: &Command) -> String {
            sign_and_seal(&self.admin, &self.device.public(), COMMAND, cmd).unwrap()
        }

        fn accept(&self, sealed: &str, now: u64) -> Result<Command, FleetError> {
            let admin = self.admin.public();
            let membership = Membership {
                fleet_id: FLEET,
                device_id: DEVICE,
                admin: &admin,
                policy: &self.policy,
            };
            accept_command(&self.device, &membership, sealed, now, |_| false)
        }
    }

    #[test]
    fn codes_round_trip_tolerate_typing_and_reject_typos() {
        let code = OneTimeCode::generate(INVITE_PREFIX).unwrap();
        let shown = code.display();
        assert!(shown.starts_with("HHF1-"));
        assert_eq!(shown.len(), 4 + 5 * 6);
        let typed = shown
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        let parsed = OneTimeCode::parse(INVITE_PREFIX, &typed).unwrap();
        assert_eq!(parsed.canonical(), code.canonical());
        assert_eq!(parsed.token_id(), code.token_id());
        // Překlep v jednom znaku odhalí kontrolní znak (nebo dekódování).
        let mut chars: Vec<char> = code.canonical().chars().collect();
        chars[6] = if chars[6] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(
            OneTimeCode::parse(INVITE_PREFIX, &typo).unwrap_err(),
            FleetError::InvalidCode
        );
        // Jiný druh kódu se nezamění.
        assert!(OneTimeCode::parse(ACTIVATION_PREFIX, &shown).is_err());
        assert!(OneTimeCode::parse(INVITE_PREFIX, "HHF1-ABC").is_err());
    }

    #[test]
    fn binding_detects_swapped_keys_and_wrong_codes() {
        let code = OneTimeCode::generate(INVITE_PREFIX).unwrap();
        let admin = Identity::generate().unwrap();
        let bundle = AdminBundle {
            v: VERSION,
            fleet_id: FLEET.into(),
            fleet_name: "H&H Security".into(),
            admin_name: "Martin Horák".into(),
            admin: admin.public(),
            policy: Policy::standard(),
            device_name: "Petr Novák".into(),
            expires_at_ms: NOW + INVITE_LIFETIME_MS,
        };
        let bound = code.bind(ADMIN_BUNDLE, &bundle).unwrap();
        let back: AdminBundle = code.unbind(ADMIN_BUNDLE, &bound).unwrap();
        assert_eq!(back, bundle);
        back.check(NOW).unwrap();
        assert_eq!(
            back.check(NOW + INVITE_LIFETIME_MS).unwrap_err(),
            FleetError::Expired
        );

        // Schránka vymění klíče správce za své: Mac to pozná.
        let attacker = Identity::generate().unwrap();
        let mut forged: Bound = serde_json::from_str(&bound).unwrap();
        let mut payload: AdminBundle = serde_json::from_slice(&unb64(&forged.p).unwrap()).unwrap();
        payload.admin = attacker.public();
        forged.p = b64(&serde_json::to_vec(&payload).unwrap());
        let forged = serde_json::to_string(&forged).unwrap();
        assert_eq!(
            code.unbind::<AdminBundle>(ADMIN_BUNDLE, &forged)
                .unwrap_err(),
            FleetError::NotAuthentic
        );
        // Jiný kód nebo jiný druh vazby neprojde.
        let other = OneTimeCode::generate(INVITE_PREFIX).unwrap();
        assert!(other.unbind::<AdminBundle>(ADMIN_BUNDLE, &bound).is_err());
        assert!(code.unbind::<AdminBundle>(DEVICE_BUNDLE, &bound).is_err());
    }

    #[test]
    fn bundles_with_forbidden_policy_or_bad_names_are_refused() {
        let admin = Identity::generate().unwrap();
        let mut bundle = AdminBundle {
            v: VERSION,
            fleet_id: FLEET.into(),
            fleet_name: "Firma".into(),
            admin_name: "Správce".into(),
            admin: admin.public(),
            policy: Policy::standard(),
            device_name: "Mac".into(),
            expires_at_ms: NOW + 1,
        };
        bundle.policy.auto.push(CleanCategory::LargeFiles);
        assert!(matches!(bundle.check(NOW), Err(FleetError::NotAllowed(_))));
        bundle.policy = Policy {
            auto: vec![CleanCategory::Logs],
            consent: vec![CleanCategory::Trash],
        };
        assert!(bundle.check(NOW).is_err());
        bundle.policy = Policy::standard();
        bundle.fleet_name = "Firma\u{7}".into();
        assert!(bundle.check(NOW).is_err());
        assert_eq!(clean_name("  Jana  ").unwrap(), "Jana");
        assert!(clean_name("").is_err());
        assert!(clean_name(&"x".repeat(61)).is_err());
    }

    #[test]
    fn commands_are_accepted_only_when_signed_targeted_fresh_and_allowed() {
        let pair = Pair::new();
        let cleanup = command(
            CommandKind::Cleanup,
            vec![CleanCategory::AppCaches, CleanCategory::Installers],
        );
        let accepted = pair.accept(&pair.issue(&cleanup), NOW + 1000).unwrap();
        assert_eq!(accepted, cleanup);
        let (auto, consent) = pair.policy.split(&accepted.categories);
        assert_eq!(auto, vec![CleanCategory::AppCaches]);
        assert_eq!(consent, vec![CleanCategory::Installers]);

        // Podepsáno jiným klíčem (útočník, schránka).
        let forged = sign_and_seal(
            &Identity::generate().unwrap(),
            &pair.device.public(),
            COMMAND,
            &cleanup,
        )
        .unwrap();
        assert_eq!(
            pair.accept(&forged, NOW).unwrap_err(),
            FleetError::NotAuthentic
        );

        // Pro jiný Mac nebo jinou firmu.
        let mut other = cleanup.clone();
        other.device_id = "2b4e28ba-2fa1-41d2-883f-0016d3cca427".into();
        assert_eq!(
            pair.accept(&pair.issue(&other), NOW).unwrap_err(),
            FleetError::WrongTarget
        );
        let mut other = cleanup.clone();
        other.fleet_id = "8c9e6679-7425-40de-944b-e07fc1f90ae7".into();
        assert_eq!(
            pair.accept(&pair.issue(&other), NOW).unwrap_err(),
            FleetError::WrongTarget
        );

        // Prošlý, z budoucnosti, nebo s příliš dlouhou platností.
        assert_eq!(
            pair.accept(&pair.issue(&cleanup), cleanup.expires_at_ms)
                .unwrap_err(),
            FleetError::Expired
        );
        assert_eq!(
            pair.accept(&pair.issue(&cleanup), NOW - CLOCK_SKEW_MS - 1)
                .unwrap_err(),
            FleetError::Expired
        );
        let mut forever = cleanup.clone();
        forever.expires_at_ms = NOW + MAX_COMMAND_LIFETIME_MS + 1;
        assert_eq!(
            pair.accept(&pair.issue(&forever), NOW).unwrap_err(),
            FleetError::Expired
        );

        // Podruhé (opakování starého příkazu schránkou).
        let admin = pair.admin.public();
        let membership = Membership {
            fleet_id: FLEET,
            device_id: DEVICE,
            admin: &admin,
            policy: &pair.policy,
        };
        assert_eq!(
            accept_command(
                &pair.device,
                &membership,
                &pair.issue(&cleanup),
                NOW,
                |id| id == cleanup.id
            )
            .unwrap_err(),
            FleetError::Replay
        );
    }

    #[test]
    fn personal_files_and_trash_never_run_remotely_even_when_signed() {
        let mut pair = Pair::new();
        for category in NEVER_REMOTE {
            let cmd = command(CommandKind::Cleanup, vec![category]);
            assert!(matches!(
                pair.accept(&pair.issue(&cmd), NOW),
                Err(FleetError::NotAllowed(_))
            ));
        }
        // Ani kdyby je zásady (podvržené) obsahovaly.
        pair.policy.auto.push(CleanCategory::LargeFiles);
        let cmd = command(CommandKind::Cleanup, vec![CleanCategory::LargeFiles]);
        assert!(matches!(
            pair.accept(&pair.issue(&cmd), NOW),
            Err(FleetError::NotAllowed(_))
        ));
        // Kategorie mimo zásady, prázdný úklid, kategorie u jiného příkazu, duplicity.
        let pair = Pair {
            policy: Policy {
                auto: vec![CleanCategory::Logs],
                consent: vec![],
            },
            ..Pair::new()
        };
        for cmd in [
            command(CommandKind::Cleanup, vec![CleanCategory::AppCaches]),
            command(CommandKind::Cleanup, vec![]),
            command(CommandKind::Scan, vec![CleanCategory::Logs]),
            command(
                CommandKind::Cleanup,
                vec![CleanCategory::Logs, CleanCategory::Logs],
            ),
        ] {
            assert!(matches!(
                pair.accept(&pair.issue(&cmd), NOW),
                Err(FleetError::NotAllowed(_))
            ));
        }
        for kind in [
            CommandKind::Scan,
            CommandKind::Isolate,
            CommandKind::Unenroll,
        ] {
            pair.accept(&pair.issue(&command(kind, vec![])), NOW)
                .unwrap();
        }
    }

    #[test]
    fn sealed_messages_resist_tampering_and_context_confusion() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let sealed = sign_and_seal(&alice, &bob.public(), REPORT, &"stav").unwrap();
        let text: String = open_and_verify(&bob, &alice.public(), REPORT, &sealed).unwrap();
        assert_eq!(text, "stav");
        // Jiný druh zprávy, jiný příjemce, jiný odesílatel.
        assert_eq!(
            open_and_verify::<String>(&bob, &alice.public(), RESULT, &sealed).unwrap_err(),
            FleetError::NotAuthentic
        );
        assert!(open_and_verify::<String>(&alice, &alice.public(), REPORT, &sealed).is_err());
        assert_eq!(
            open_and_verify::<String>(&bob, &bob.public(), REPORT, &sealed).unwrap_err(),
            FleetError::NotAuthentic
        );
        // Změněný bajt šifrovaného textu.
        let mut bytes = unb64(&sealed).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            open_and_verify::<String>(&bob, &alice.public(), REPORT, &b64(&bytes)).unwrap_err(),
            FleetError::NotAuthentic
        );
        // Neplatný klíč příjemce (nulový bod) se odmítne.
        assert!(seal(&[0u8; 32], REPORT, b"x").is_err());
        assert!(open(&bob, REPORT, "####").is_err());
        assert!(open(&bob, REPORT, &"A".repeat(MAX_SEALED_CHARS + 1)).is_err());
    }

    #[test]
    fn reports_results_and_leave_notices_reach_only_the_admin_intact() {
        let pair = Pair::new();
        let report = Report {
            v: VERSION,
            device_id: DEVICE.into(),
            fleet_id: FLEET.into(),
            seq: 3,
            created_at_ms: NOW,
            app_version: "0.7.0".into(),
            os_version: "macOS 26.0.1".into(),
            model: "MacBook Pro (Apple M3 Pro)".into(),
            protection: ProtectionLevel::Monitored,
            protection_note: None,
            rules_version: "2026.10.12".into(),
            rules_checked_at_ms: Some(NOW),
            last_scan: Some(LastScan {
                at_ms: NOW,
                files: 10,
                threats: 0,
            }),
            threats: vec![],
            quarantined: 0,
            disk: Some(DiskInfo {
                total: 500,
                free: 41,
            }),
            memory: MemoryState {
                total: 16,
                used: 10,
                pressure: Some(MemoryPressure::Normal),
            },
            uptime_secs: 3600,
            cleanup: Some(CleanupEstimate {
                measured_at_ms: NOW,
                categories: vec![CategoryBytes {
                    category: CleanCategory::AppCaches,
                    bytes: 6,
                }],
            }),
        };
        let sealed = sign_and_seal(&pair.device, &pair.admin.public(), REPORT, &report).unwrap();
        let opened =
            open_report(&pair.admin, &pair.device.public(), FLEET, DEVICE, &sealed).unwrap();
        assert_eq!(opened, report);
        assert_eq!(
            open_report(
                &pair.admin,
                &pair.device.public(),
                FLEET,
                "2b4e28ba-2fa1-41d2-883f-0016d3cca427",
                &sealed
            )
            .unwrap_err(),
            FleetError::WrongTarget
        );
        // Zpráva jiného Macu (jiný klíč) se nevydá za zprávu tohoto.
        let other = Identity::generate().unwrap();
        let forged = sign_and_seal(&other, &pair.admin.public(), REPORT, &report).unwrap();
        assert_eq!(
            open_report(&pair.admin, &pair.device.public(), FLEET, DEVICE, &forged).unwrap_err(),
            FleetError::NotAuthentic
        );
        // Příliš dlouhé texty se odmítnou.
        let mut long = report.clone();
        long.model = "x".repeat(500);
        let sealed = sign_and_seal(&pair.device, &pair.admin.public(), REPORT, &long).unwrap();
        assert!(open_report(&pair.admin, &pair.device.public(), FLEET, DEVICE, &sealed).is_err());

        let result = CommandResult {
            v: VERSION,
            command_id: "c".into(),
            device_id: DEVICE.into(),
            seq: 1,
            at_ms: NOW,
            state: ResultState::Done,
            freed_bytes: 5,
            trashed_bytes: 0,
            files: 0,
            threats: 0,
            error: None,
        };
        let sealed = sign_and_seal(&pair.device, &pair.admin.public(), RESULT, &result).unwrap();
        assert_eq!(
            open_result(&pair.admin, &pair.device.public(), DEVICE, "c", &sealed).unwrap(),
            result
        );
        assert_eq!(
            open_result(&pair.admin, &pair.device.public(), DEVICE, "d", &sealed).unwrap_err(),
            FleetError::WrongTarget
        );
        // Výsledek nejde vydávat za zprávu o stavu a naopak.
        assert!(open_report(&pair.admin, &pair.device.public(), FLEET, DEVICE, &sealed).is_err());

        let notice = LeaveNotice {
            v: VERSION,
            fleet_id: FLEET.into(),
            device_id: DEVICE.into(),
            at_ms: NOW,
        };
        let sealed = sign_and_seal(&pair.device, &pair.admin.public(), LEAVE, &notice).unwrap();
        assert_eq!(
            open_leave(&pair.admin, &pair.device.public(), FLEET, DEVICE, &sealed).unwrap(),
            notice
        );
    }

    fn item(
        id: &str,
        category: CleanCategory,
        bytes: u64,
        recommended: bool,
        method: CleanMethod,
    ) -> CleanItem {
        CleanItem {
            id: id.into(),
            category,
            path: format!("/Users/x/{id}"),
            name: id.into(),
            bytes,
            files: 1,
            modified_ms: None,
            recommended,
            method,
            note: None,
        }
    }

    #[test]
    fn remote_cleanup_takes_only_safe_items_and_never_user_files() {
        let scan = CleanScan {
            items: vec![
                item(
                    "cache",
                    CleanCategory::AppCaches,
                    100,
                    true,
                    CleanMethod::Delete,
                ),
                item(
                    "running",
                    CleanCategory::AppCaches,
                    50,
                    false,
                    CleanMethod::Delete,
                ),
                item(
                    "archives",
                    CleanCategory::Developer,
                    70,
                    false,
                    CleanMethod::MoveToTrash,
                ),
                item(
                    "dmg",
                    CleanCategory::Installers,
                    30,
                    true,
                    CleanMethod::MoveToTrash,
                ),
                item(
                    "movie",
                    CleanCategory::LargeFiles,
                    900,
                    true,
                    CleanMethod::MoveToTrash,
                ),
                item(
                    "trash",
                    CleanCategory::Trash,
                    400,
                    true,
                    CleanMethod::EmptyTrash,
                ),
            ],
            started_at_ms: NOW - 10,
            finished_at_ms: NOW,
            complete: true,
            unreadable: vec![],
        };
        let ids = |list: Vec<&CleanItem>| list.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
        assert_eq!(
            ids(remote_selection(
                &scan,
                &[CleanCategory::AppCaches, CleanCategory::Developer]
            )),
            vec!["cache"]
        );
        assert_eq!(
            ids(remote_selection(&scan, &[CleanCategory::Installers])),
            vec!["dmg"]
        );
        // Soubory uživatele a Koš ani na výslovné přání.
        assert!(remote_selection(&scan, &NEVER_REMOTE).is_empty());

        let estimate = cleanup_estimate(&scan);
        assert_eq!(estimate.measured_at_ms, NOW);
        let bytes = |cat| {
            estimate
                .categories
                .iter()
                .find(|c| c.category == cat)
                .map_or(0, |c| c.bytes)
        };
        assert_eq!(
            bytes(CleanCategory::AppCaches),
            100,
            "only recommended items count"
        );
        assert_eq!(bytes(CleanCategory::Developer), 0);
        assert_eq!(bytes(CleanCategory::Installers), 30);
        assert_eq!(
            bytes(CleanCategory::LargeFiles),
            900,
            "shown to the admin, never cleaned"
        );
        assert_eq!(bytes(CleanCategory::Trash), 400);
    }

    #[test]
    fn device_bundles_bind_the_relay_device_id() {
        let device = Identity::generate().unwrap();
        let bundle = DeviceBundle {
            v: VERSION,
            fleet_id: FLEET.into(),
            token_id: "tok".into(),
            device_id: DEVICE.into(),
            device: device.public(),
        };
        bundle.check(FLEET, "tok", DEVICE).unwrap();
        assert_eq!(
            bundle
                .check(FLEET, "tok", "2b4e28ba-2fa1-41d2-883f-0016d3cca427")
                .unwrap_err(),
            FleetError::WrongTarget
        );
        assert_eq!(
            bundle.check(FLEET, "other", DEVICE).unwrap_err(),
            FleetError::WrongTarget
        );
        assert!(ResultState::Done.is_final() && ResultState::Expired.is_final());
        assert!(!ResultState::Running.is_final() && !ResultState::AwaitingConsent.is_final());
    }

    #[test]
    fn identities_survive_storage_and_files_are_private() {
        let identity = Identity::generate().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fleet").join("device.json");
        write_private(&path, &serde_json::to_vec(&identity.secret()).unwrap()).unwrap();
        let secret: IdentitySecret = read_json(&path, 4096).unwrap().unwrap();
        let restored = Identity::from_secret(&secret);
        assert_eq!(restored.public(), identity.public());
        assert_eq!(restored.public().fingerprint().len(), 16);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert!(
            read_json::<IdentitySecret>(&tmp.path().join("missing.json"), 10)
                .unwrap()
                .is_none()
        );
        assert!(read_json::<IdentitySecret>(&path, 10).is_err());
        assert!(format!("{:?}", identity.secret()).contains('…'));
    }
}
