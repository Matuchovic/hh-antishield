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
//!   kterými jeho uživatel souhlasil. Velké soubory a Koš jen se souhlasem
//!   uživatele, který sám vybere, co se smaže; restart a ukončení aplikací
//!   taky jen po jeho potvrzení. Rozšíření zásad musí uživatel potvrdit.
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

/// Soubory uživatele a Koš: na dálku nikdy hned, jen se souhlasem uživatele,
/// který sám vybere položky.
pub const CONSENT_ONLY: [CleanCategory; 2] = [CleanCategory::LargeFiles, CleanCategory::Trash];
/// Nejvýš tolik aplikací v jednom příkazu k ukončení.
pub const MAX_APP_TARGETS: usize = 12;
/// Nejvýš tolik položek karantény v jednom příkazu ke smazání.
pub const MAX_QUARANTINE_TARGETS: usize = 50;
/// Meze podrobností ve zprávě o stavu.
pub const MAX_REPORT_APPS: usize = 12;
pub const MAX_REPORT_LOGIN_ITEMS: usize = 40;
pub const MAX_REPORT_QUARANTINE: usize = 30;
pub const MAX_REPORT_EVENTS: usize = 40;
pub const MAX_REPORT_OS_UPDATES: usize = 12;
const MAX_EVENT_DATA_CHARS: usize = 600;

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

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

/// Kontrolní znak (Luhn mod 32) přes prefix i data: odhalí každý překlep
/// v jednom znaku, záměnu druhu kódu a prohození sousedních znaků (kromě
/// dvojice 0/Z). Otisk by jeden překlep ze 32 propustil.
fn checksum(prefix: &str, data: &str) -> char {
    const N: usize = 32;
    let sum: usize = prefix
        .chars()
        .chain(data.chars())
        .rev()
        .enumerate()
        .map(|(i, c)| {
            let value = CROCKFORD.find(c).unwrap_or(0);
            let addend = if i % 2 == 0 { value * 2 } else { value };
            addend / N + addend % N
        })
        .sum();
    CROCKFORD
        .as_bytes()
        .get((N - sum % N) % N)
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
        if !check.starts_with(checksum(prefix, data)) {
            return Err(FleetError::InvalidCode);
        }
        Ok(Self { prefix, secret })
    }

    /// Podoba bez pomlček (tak ji posílá aplikace schránce).
    pub fn canonical(&self) -> String {
        let data = crockford().encode(&self.secret);
        let check = checksum(self.prefix, &data);
        format!("{}{data}{check}", self.prefix)
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

/// Zásahy nad rámec úklidu kategorií (rozšířená správa, od verze 0.8).
/// Restart a ukončení aplikací Mac vždy nejdřív nabídne uživateli.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemoteAction {
    /// Hloubkový úklid: mezipaměti aplikací, které neběží, i čerstvé; běžící
    /// aplikace se zavřou jen se souhlasem uživatele.
    DeepClean,
    /// Úplná kontrola celého disku.
    FullScan,
    /// Smazání položek z karantény.
    QuarantineDelete,
    /// Aktualizace AntiShieldu (podepsaná vydání) a pravidel.
    Updates,
    /// Žádost o restart (uživatel potvrdí, nebo odloží).
    Restart,
    /// Žádost o ukončení aplikací (uživatel vybere).
    QuitApps,
}

/// Co Mac správci posílá navíc (rozšířená správa, od verze 0.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShareScope {
    /// Čip, jádra, paměť, sériové číslo, baterie.
    Hardware,
    /// FileVault, firewall, SIP, Gatekeeper, aktualizace macOS, záloha.
    Security,
    /// Vytížení, nejnáročnější aplikace, položky po přihlášení.
    Performance,
    /// Karanténa podrobně a časová osa ochrany.
    Threats,
}

pub const ALL_ACTIONS: [RemoteAction; 6] = [
    RemoteAction::DeepClean,
    RemoteAction::FullScan,
    RemoteAction::QuarantineDelete,
    RemoteAction::Updates,
    RemoteAction::Restart,
    RemoteAction::QuitApps,
];

pub const ALL_SCOPES: [ShareScope; 4] = [
    ShareScope::Hardware,
    ShareScope::Security,
    ShareScope::Performance,
    ShareScope::Threats,
];

/// Co smí správce na Macu na dálku. Uživatel je vidí a potvrdí při připojení;
/// rozšíření potvrzuje znovu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    /// Hned (uživatel dostane oznámení).
    pub auto: Vec<CleanCategory>,
    /// Jen po souhlasu uživatele.
    pub consent: Vec<CleanCategory>,
    /// Zásahy nad rámec úklidu kategorií.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<RemoteAction>,
    /// Podrobnosti, které Mac posílá navíc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub share: Vec<ShareScope>,
}

fn has_duplicates<T: PartialEq>(list: &[T]) -> bool {
    list.iter()
        .enumerate()
        .any(|(i, item)| list[..i].contains(item))
}

impl Policy {
    /// Zásady verze 0.7: mezipaměti a protokoly hned, instalátory a zbytky se
    /// souhlasem, nic dalšího. Platí pro Macy, které zatím nic víc nepotvrdily.
    pub fn basic() -> Self {
        Self {
            auto: vec![
                CleanCategory::AppCaches,
                CleanCategory::Logs,
                CleanCategory::Developer,
            ],
            consent: vec![CleanCategory::Installers, CleanCategory::Leftovers],
            actions: Vec::new(),
            share: Vec::new(),
        }
    }

    /// Rozšířená správa: navíc velké soubory a Koš se souhlasem, všechny
    /// zásahy a podrobnosti.
    pub fn standard() -> Self {
        let mut policy = Self::basic();
        policy
            .consent
            .extend([CleanCategory::LargeFiles, CleanCategory::Trash]);
        policy.actions = ALL_ACTIONS.to_vec();
        policy.share = ALL_SCOPES.to_vec();
        policy
    }

    pub fn allows(&self, action: RemoteAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn shares(&self, scope: ShareScope) -> bool {
        self.share.contains(&scope)
    }

    /// Obsahuje tyto zásady všechno, co `other` (a případně víc)?
    pub fn covers(&self, other: &Self) -> bool {
        other.auto.iter().all(|c| self.auto.contains(c))
            && other
                .consent
                .iter()
                .all(|c| self.consent.contains(c) || self.auto.contains(c))
            && other.actions.iter().all(|a| self.actions.contains(a))
            && other.share.iter().all(|s| self.share.contains(s))
    }

    pub fn validate(&self) -> Result<(), FleetError> {
        let all: Vec<CleanCategory> = self.auto.iter().chain(&self.consent).copied().collect();
        if has_duplicates(&all) {
            return Err(FleetError::NotAllowed("a category is listed twice".into()));
        }
        if let Some(category) = self.auto.iter().find(|c| CONSENT_ONLY.contains(c)) {
            return Err(FleetError::NotAllowed(format!(
                "{category:?} needs the user's consent"
            )));
        }
        if has_duplicates(&self.actions) || has_duplicates(&self.share) {
            return Err(FleetError::NotAllowed("an item is listed twice".into()));
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
    /// Úklid kategorií (část „se souhlasem“ čeká na uživatele), případně hloubkový.
    Cleanup,
    /// Rychlá, nebo úplná kontrola.
    Scan,
    /// Izolace nalezených hrozeb do karantény.
    Isolate,
    /// Správce Mac odebral z firmy.
    Unenroll,
    /// Žádost o restart (uživatel potvrdí, nebo odloží).
    Restart,
    /// Žádost o ukončení aplikací (uživatel vybere).
    QuitApps,
    /// Aktualizace AntiShieldu a pravidel.
    Update,
    /// Smazání položek z karantény.
    DeleteQuarantine,
    /// Nabídka nových zásad (uživatel je potvrdí).
    Policy,
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
    /// Úklid: hloubkový (mezipaměti neběžících aplikací i čerstvé; běžící
    /// aplikace zavře jen se souhlasem uživatele).
    #[serde(default, skip_serializing_if = "is_false")]
    pub deep: bool,
    /// Kontrola: úplná (celý disk) místo rychlé.
    #[serde(default, skip_serializing_if = "is_false")]
    pub full: bool,
    /// Ukončení aplikací: identifikátory aplikací; karanténa: položky.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Nabídka zásad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}

impl Command {
    /// Nový příkaz bez voleb (úklid, kontrola, izolace…).
    pub fn new(
        id: String,
        fleet_id: String,
        device_id: String,
        kind: CommandKind,
        categories: Vec<CleanCategory>,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            v: VERSION,
            id,
            fleet_id,
            device_id,
            kind,
            categories,
            issued_at_ms,
            expires_at_ms,
            deep: false,
            full: false,
            targets: Vec::new(),
            policy: None,
        }
    }
}

/// Identifikátor položky karantény (jen bezpečné znaky).
fn valid_quarantine_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Rozumí AntiShield této verze rozšířené správě (příkaz `policy` a další
/// zásahy z 0.8)? Starší Mac takový příkaz nepřečte a odmítne.
pub fn supports_extended(app_version: &str) -> bool {
    let mut parts = app_version
        .split(['.', '-', '+'])
        .map(|part| part.parse::<u64>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    (major, minor) >= (0, 8)
}

/// Volby příkazu sedí k jeho druhu a k zásadám Macu. Stejné meze kontroluje
/// správce před odesláním i Mac po přijetí.
pub fn check_command(command: &Command, policy: &Policy) -> Result<(), FleetError> {
    let refuse = |what: &str| Err(FleetError::NotAllowed(what.into()));
    let bare =
        !command.deep && !command.full && command.targets.is_empty() && command.policy.is_none();
    let needs = |action: RemoteAction| -> Result<(), FleetError> {
        if policy.allows(action) {
            Ok(())
        } else {
            Err(FleetError::NotAllowed(format!(
                "{action:?} is not in the policy"
            )))
        }
    };
    if command.kind != CommandKind::Cleanup && !command.categories.is_empty() {
        return refuse("categories");
    }
    match command.kind {
        CommandKind::Cleanup => {
            if command.categories.is_empty() {
                return refuse("no category");
            }
            if has_duplicates(&command.categories) {
                return refuse("a category is listed twice");
            }
            for category in &command.categories {
                if !policy.auto.contains(category) && !policy.consent.contains(category) {
                    return Err(FleetError::NotAllowed(format!("{category:?}")));
                }
            }
            if command.full || !command.targets.is_empty() || command.policy.is_some() {
                return refuse("options");
            }
            if command.deep {
                needs(RemoteAction::DeepClean)?;
            }
        }
        CommandKind::Scan => {
            if command.deep || !command.targets.is_empty() || command.policy.is_some() {
                return refuse("options");
            }
            if command.full {
                needs(RemoteAction::FullScan)?;
            }
        }
        CommandKind::Isolate | CommandKind::Unenroll => {
            if !bare {
                return refuse("options");
            }
        }
        CommandKind::Restart | CommandKind::Update => {
            if !bare {
                return refuse("options");
            }
            needs(if command.kind == CommandKind::Restart {
                RemoteAction::Restart
            } else {
                RemoteAction::Updates
            })?;
        }
        CommandKind::QuitApps => {
            needs(RemoteAction::QuitApps)?;
            if command.deep || command.full || command.policy.is_some() {
                return refuse("options");
            }
            if command.targets.is_empty()
                || command.targets.len() > MAX_APP_TARGETS
                || has_duplicates(&command.targets)
                || !command
                    .targets
                    .iter()
                    .all(|t| crate::system::valid_bundle_id(t))
            {
                return refuse("apps");
            }
        }
        CommandKind::DeleteQuarantine => {
            needs(RemoteAction::QuarantineDelete)?;
            if command.deep || command.full || command.policy.is_some() {
                return refuse("options");
            }
            if command.targets.is_empty()
                || command.targets.len() > MAX_QUARANTINE_TARGETS
                || has_duplicates(&command.targets)
                || !command.targets.iter().all(|t| valid_quarantine_id(t))
            {
                return refuse("quarantine items");
            }
        }
        CommandKind::Policy => {
            if command.deep || command.full || !command.targets.is_empty() {
                return refuse("options");
            }
            command
                .policy
                .as_ref()
                .ok_or_else(|| FleetError::NotAllowed("no policy".into()))?
                .validate()?;
        }
    }
    Ok(())
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
/// v době platnosti, poprvé a v mezích zásad.
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
    // Podvržené zásady (s Košem „hned“) neprojdou ani tady.
    membership.policy.validate()?;
    check_command(&command, membership.policy)?;
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
    /// Počet: ukončené nebo zavřené aplikace, smazané položky karantény.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub count: u64,
    /// Krátká poznámka (nová verze, názvy aplikací).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Uživatel restart odložil do této chvíle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
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
    /// Počet položek (u velkých souborů a Koše).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub items: u64,
}

/// Hloubkový úklid: kolik jde hned a kolik až po zavření aplikací.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepEstimate {
    pub now_bytes: u64,
    pub apps_bytes: u64,
    /// Kolik běžících aplikací by se muselo zavřít.
    pub apps: u64,
}

/// Kolik jde uklidit: jen velikosti po kategoriích, bez názvů souborů.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupEstimate {
    pub measured_at_ms: u64,
    pub categories: Vec<CategoryBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deep: Option<DeepEstimate>,
}

// ---------- Podrobnosti o Macu (rozšířená správa) ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatteryReport {
    pub cycles: u32,
    /// Kapacita proti nové baterii v procentech.
    pub health_pct: Option<u8>,
    /// Baterie potřebuje servis (kapacita pod 80 % nebo hlášená porucha).
    pub service: bool,
    pub charge_pct: Option<u8>,
    pub charging: bool,
    pub on_power: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareReport {
    /// „Apple M2“
    pub chip: String,
    /// „Mac14,2“
    pub model_id: String,
    pub serial: Option<String>,
    pub cores: u32,
    pub performance_cores: Option<u32>,
    pub efficiency_cores: Option<u32>,
    pub memory: u64,
    pub battery: Option<BatteryReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsUpdate {
    pub title: String,
    pub version: Option<String>,
    pub restart: bool,
    pub recommended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupReport {
    /// Time Machine má nastavený disk pro zálohy.
    pub configured: bool,
    pub auto: Option<bool>,
    pub last_ms: Option<u64>,
}

/// Zabezpečení systému. `None`: stav nejde zjistit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReport {
    pub filevault: Option<bool>,
    pub firewall: Option<bool>,
    pub stealth: Option<bool>,
    pub sip: Option<bool>,
    pub gatekeeper: Option<bool>,
    pub xprotect: Option<String>,
    /// Automatické hledání a instalace bezpečnostních aktualizací macOS.
    pub auto_updates: Option<bool>,
    /// Čekající aktualizace macOS.
    pub os_updates: Option<Vec<OsUpdate>>,
    pub backup: Option<BackupReport>,
    /// AntiShield má plný přístup k disku.
    pub full_disk_access: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUsage {
    pub name: String,
    pub bundle_id: Option<String>,
    /// Podíl celého procesoru v promile (123 = 12,3 %).
    pub cpu_permille: u32,
    pub memory: u64,
    pub processes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginItemReport {
    pub label: String,
    /// Název programu bez cesty.
    pub program: Option<String>,
    pub enabled: bool,
    /// Položka pro celý systém.
    pub system: bool,
    pub running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceReport {
    pub measured_at_ms: u64,
    pub cpu_permille: u32,
    pub cores: u32,
    pub swap_used: u64,
    pub apps: Vec<AppUsage>,
    pub login_items: Vec<LoginItemReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineReport {
    pub id: String,
    pub path: String,
    pub rule_name: String,
    pub severity: crate::Severity,
    pub at_ms: u64,
    pub size: u64,
    pub sha256: String,
}

/// Událost ochrany z auditu Macu (jen vybrané druhy a údaje).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventReport {
    pub kind: String,
    pub at_ms: u64,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryState {
    pub total: u64,
    pub used: u64,
    pub pressure: Option<MemoryPressure>,
}

/// Stav Macu pro správce. Obsahuje jen to, co uživatel potvrdil: ochranu,
/// hrozby, disk, paměť a velikosti k úklidu, s rozšířenou správou i podrobnosti
/// podle zásad. Žádné dokumenty ani názvy souborů mimo zachycené hrozby.
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
    /// Zásady, se kterými uživatel Macu souhlasil (od 0.8; bez nich základní).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware: Option<HardwareReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance: Option<PerformanceReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<QuarantineReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<EventReport>,
}

fn bounded_opt(text: Option<&String>, max: usize) -> bool {
    text.is_none_or(|t| bounded_text(t, max))
}

impl Report {
    /// Zásady Macu: potvrzené, nebo základní (Mac s verzí 0.7).
    pub fn accepted_policy(&self) -> Policy {
        self.policy.clone().unwrap_or_else(Policy::basic)
    }

    /// Kontrola u správce: rozumné délky textů a počty, podrobnosti jen
    /// v mezích zásad, které Mac sám uvádí.
    pub fn check(&self) -> Result<(), FleetError> {
        let texts = [
            (&self.app_version, 40),
            (&self.os_version, 80),
            (&self.model, 120),
            (&self.rules_version, 60),
        ];
        let policy = self.accepted_policy();
        let shares = |scope| policy.shares(scope);
        let base_ok = self.v == VERSION
            && texts.iter().all(|(text, max)| bounded_text(text, *max))
            && bounded_opt(self.protection_note.as_ref(), MAX_TEXT_CHARS)
            && self.threats.len() <= MAX_REPORT_THREATS
            && self.threats.iter().all(|t| {
                bounded_text(&t.rule_name, MAX_TEXT_CHARS) && bounded_text(&t.path, MAX_PATH_CHARS)
            })
            && self
                .cleanup
                .as_ref()
                .is_none_or(|c| c.categories.len() <= 7)
            && self.policy.as_ref().is_none_or(|p| p.validate().is_ok());
        let hardware_ok = self.hardware.as_ref().is_none_or(|h| {
            shares(ShareScope::Hardware)
                && bounded_text(&h.chip, 120)
                && bounded_text(&h.model_id, 40)
                && bounded_opt(h.serial.as_ref(), 40)
        });
        let security_ok = self.security.as_ref().is_none_or(|s| {
            shares(ShareScope::Security)
                && bounded_opt(s.xprotect.as_ref(), 40)
                && s.os_updates.as_ref().is_none_or(|list| {
                    list.len() <= MAX_REPORT_OS_UPDATES
                        && list.iter().all(|u| {
                            bounded_text(&u.title, MAX_TEXT_CHARS)
                                && bounded_opt(u.version.as_ref(), 40)
                        })
                })
        });
        let performance_ok = self.performance.as_ref().is_none_or(|p| {
            shares(ShareScope::Performance)
                && p.apps.len() <= MAX_REPORT_APPS
                && p.apps.iter().all(|a| {
                    bounded_text(&a.name, 120) && bounded_opt(a.bundle_id.as_ref(), MAX_TEXT_CHARS)
                })
                && p.login_items.len() <= MAX_REPORT_LOGIN_ITEMS
                && p.login_items.iter().all(|i| {
                    bounded_text(&i.label, MAX_TEXT_CHARS)
                        && bounded_opt(i.program.as_ref(), MAX_TEXT_CHARS)
                })
        });
        let threats_ok = (self.quarantine.is_empty() && self.events.is_empty())
            || (shares(ShareScope::Threats)
                && self.quarantine.len() <= MAX_REPORT_QUARANTINE
                && self.quarantine.iter().all(|q| {
                    valid_quarantine_id(&q.id)
                        && bounded_text(&q.path, MAX_PATH_CHARS)
                        && bounded_text(&q.rule_name, MAX_TEXT_CHARS)
                        && bounded_text(&q.sha256, 64)
                })
                && self.events.len() <= MAX_REPORT_EVENTS
                && self.events.iter().all(|e| {
                    bounded_text(&e.kind, 40)
                        && e.data.is_object()
                        && e.data.to_string().chars().count() <= MAX_EVENT_DATA_CHARS
                }));
        if base_ok && hardware_ok && security_ok && performance_ok && threats_ok {
            Ok(())
        } else {
            Err(malformed("report"))
        }
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
    if !bounded_opt(result.error.as_ref(), MAX_TEXT_CHARS)
        || !bounded_opt(result.note.as_ref(), MAX_TEXT_CHARS)
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

/// Co Mac na dálku uklidí bez výběru uživatele: jen předvybrané (bezpečné)
/// položky z vlastního čerstvého skenu v kategoriích příkazu. Soubory
/// uživatele a Koš nikdy; ty jdou jen přes souhlas s výběrem položek.
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
                && !CONSENT_ONLY.contains(&item.category)
        })
        .collect()
}

/// Běžící aplikace (hloubkový úklid: jejich mezipaměti teď mazat nejde).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningApp {
    pub id: String,
    pub name: String,
}

/// Slova, podle kterých se mezipaměť s aplikací nepáruje (moc obecná).
const GENERIC_TOKENS: [&str; 20] = [
    "apple",
    "apps",
    "agent",
    "cache",
    "caches",
    "client",
    "data",
    "desktop",
    "framework",
    "helper",
    "launcher",
    "macos",
    "plugin",
    "service",
    "services",
    "shared",
    "software",
    "support",
    "update",
    "updater",
];

fn name_tokens(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|t| t.len() >= 4 && !GENERIC_TOKENS.contains(&t.as_str()))
}

/// Běžící aplikace, které mezipaměť (podle názvu složky) asi patří. Raději
/// přiřadí víc než míň: mezipaměť běžící aplikace se hned nesmaže.
pub fn cache_owner<'a>(name: &str, apps: &'a [RunningApp]) -> Option<&'a RunningApp> {
    let lower = name.to_ascii_lowercase();
    let exact = apps.iter().find(|app| {
        let id = app.id.to_ascii_lowercase();
        lower == id || lower.starts_with(&format!("{id}.")) || id.starts_with(&format!("{lower}."))
    });
    if exact.is_some() {
        return exact;
    }
    let tokens: Vec<String> = name_tokens(name).collect();
    apps.iter().find(|app| {
        name_tokens(&app.id)
            .chain(name_tokens(&app.name))
            .any(|t| tokens.contains(&t))
    })
}

/// Mezipaměť změněná před chvílí: zapisuje do ní něco, co neznáme. Hloubkový
/// úklid ji nechá být.
const ACTIVE_WRITE_MS: u64 = 2 * 60 * 1000;

/// Plán hloubkového úklidu.
#[derive(Debug, Default)]
pub struct DeepPlan<'a> {
    /// Smazat hned: předvybrané položky a mezipaměti, které nepatří běžící
    /// aplikaci (i čerstvé).
    pub now: Vec<&'a CleanItem>,
    /// Až po zavření aplikací (souhlas uživatele).
    pub with_apps: Vec<&'a CleanItem>,
    /// Aplikace, které by se musely zavřít.
    pub apps: Vec<&'a RunningApp>,
}

/// Hloubkový úklid kategorií `categories`: k předvybraným položkám přidá
/// mezipaměti, které nepatří žádné běžící aplikaci, i když jsou čerstvé.
/// Mezipaměti běžících aplikací odloží na souhlas uživatele. Soubory uživatele,
/// Koš a archivy nikdy.
pub fn deep_plan<'a>(
    scan: &'a CleanScan,
    categories: &[CleanCategory],
    apps: &'a [RunningApp],
    now_ms: u64,
) -> DeepPlan<'a> {
    let mut plan = DeepPlan::default();
    for item in &scan.items {
        if !categories.contains(&item.category)
            || CONSENT_ONLY.contains(&item.category)
            || item.method == CleanMethod::EmptyTrash
        {
            continue;
        }
        if item.category != CleanCategory::AppCaches {
            if item.recommended {
                plan.now.push(item);
            }
            continue;
        }
        if let Some(owner) = cache_owner(&item.name, apps) {
            plan.with_apps.push(item);
            if !plan.apps.iter().any(|a| a.id == owner.id) {
                plan.apps.push(owner);
            }
            continue;
        }
        let quiet = item
            .modified_ms
            .is_none_or(|ms| now_ms.saturating_sub(ms) >= ACTIVE_WRITE_MS);
        if item.recommended || (item.method == CleanMethod::Delete && quiet) {
            plan.now.push(item);
        }
    }
    plan
}

/// Po zavření aplikací: mezipaměti, které uživatel schválil a které už žádné
/// běžící aplikaci nepatří (aplikace, která zůstala otevřená, o ně nepřijde).
pub fn deep_after_close<'a>(
    scan: &'a CleanScan,
    approved: &[String],
    apps: &[RunningApp],
) -> Vec<&'a CleanItem> {
    scan.items
        .iter()
        .filter(|item| {
            item.category == CleanCategory::AppCaches
                && item.method == CleanMethod::Delete
                && approved.contains(&item.id)
                && cache_owner(&item.name, apps).is_none()
        })
        .collect()
}

/// Kolik jde uklidit, pro správce: u kategorií na dálku jen předvybrané
/// položky, u souborů uživatele a Koše celková velikost a počet (rozhodne
/// uživatel), k tomu odhad hloubkového úklidu.
pub fn cleanup_estimate(scan: &CleanScan, apps: &[RunningApp], now_ms: u64) -> CleanupEstimate {
    let mut categories: Vec<CategoryBytes> = Vec::new();
    for item in &scan.items {
        let consent_only = CONSENT_ONLY.contains(&item.category);
        if !consent_only && !item.recommended {
            continue;
        }
        let entry = match categories
            .iter_mut()
            .position(|c| c.category == item.category)
        {
            Some(index) => &mut categories[index],
            None => {
                categories.push(CategoryBytes {
                    category: item.category,
                    bytes: 0,
                    items: 0,
                });
                let last = categories.len() - 1;
                &mut categories[last]
            }
        };
        entry.bytes += item.bytes;
        if consent_only {
            entry.items += if item.method == CleanMethod::EmptyTrash {
                item.files
            } else {
                1
            };
        }
    }
    let plan = deep_plan(
        scan,
        &[
            CleanCategory::AppCaches,
            CleanCategory::Logs,
            CleanCategory::Developer,
        ],
        apps,
        now_ms,
    );
    CleanupEstimate {
        measured_at_ms: scan.finished_at_ms,
        categories,
        deep: Some(DeepEstimate {
            now_bytes: plan.now.iter().map(|i| i.bytes).sum(),
            apps_bytes: plan.with_apps.iter().map(|i| i.bytes).sum(),
            apps: plan.apps.len() as u64,
        }),
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
        Command::new(
            random_id().unwrap(),
            FLEET.into(),
            DEVICE.into(),
            kind,
            categories,
            NOW,
            NOW + COMMAND_LIFETIME_MS,
        )
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
        // Kontrolní znak počítá i s prefixem, ten musí být v abecedě.
        assert!(
            INVITE_PREFIX
                .chars()
                .chain(ACTIVATION_PREFIX.chars())
                .all(|c| CROCKFORD.contains(c))
        );
        let typed = shown
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        let parsed = OneTimeCode::parse(INVITE_PREFIX, &typed).unwrap();
        assert_eq!(parsed.canonical(), code.canonical());
        assert_eq!(parsed.token_id(), code.token_id());
        // Každý překlep v jednom znaku (i v kontrolním) odhalí kontrolní znak.
        let canonical = code.canonical();
        let symbols: Vec<char> = canonical.chars().collect();
        for position in INVITE_PREFIX.len()..symbols.len() {
            for other in CROCKFORD.chars().filter(|c| *c != symbols[position]) {
                let mut typo = symbols.clone();
                typo[position] = other;
                let typo: String = typo.into_iter().collect();
                assert_eq!(
                    OneTimeCode::parse(INVITE_PREFIX, &typo).unwrap_err(),
                    FleetError::InvalidCode,
                    "{typo}"
                );
            }
        }
        // Prohození sousedních znaků taky (Luhn nepozná jen dvojici 0/Z).
        for position in INVITE_PREFIX.len()..symbols.len() - 1 {
            let pair = (symbols[position], symbols[position + 1]);
            if pair.0 == pair.1 || matches!(pair, ('0', 'Z') | ('Z', '0')) {
                continue;
            }
            let mut swapped = symbols.clone();
            swapped.swap(position, position + 1);
            let swapped: String = swapped.into_iter().collect();
            assert!(
                OneTimeCode::parse(INVITE_PREFIX, &swapped).is_err(),
                "{swapped}"
            );
        }
        // Jiný druh kódu se nezamění, ani se stejným tělem.
        assert!(OneTimeCode::parse(ACTIVATION_PREFIX, &shown).is_err());
        let body = &canonical[INVITE_PREFIX.len()..];
        assert!(
            OneTimeCode::parse(ACTIVATION_PREFIX, &format!("{ACTIVATION_PREFIX}{body}")).is_err()
        );
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
        // Soubory uživatele a Koš nikdy „hned“, jen se souhlasem.
        bundle.policy.auto.push(CleanCategory::LargeFiles);
        assert!(matches!(bundle.check(NOW), Err(FleetError::NotAllowed(_))));
        bundle.policy = Policy {
            auto: vec![CleanCategory::Logs, CleanCategory::Trash],
            consent: vec![],
            actions: vec![],
            share: vec![],
        };
        assert!(matches!(bundle.check(NOW), Err(FleetError::NotAllowed(_))));
        bundle.policy.auto = vec![CleanCategory::Logs];
        bundle.policy.consent = vec![CleanCategory::Trash];
        bundle.check(NOW).unwrap();
        bundle.policy.actions = vec![RemoteAction::Restart, RemoteAction::Restart];
        assert!(bundle.check(NOW).is_err());
        bundle.policy = Policy::standard();
        bundle.check(NOW).unwrap();
        assert!(Policy::standard().covers(&Policy::basic()));
        assert!(!Policy::basic().covers(&Policy::standard()));
        // Zásady z verze 0.7 (bez nových polí) se načtou jako základní.
        let old: Policy = serde_json::from_str(
            r#"{"auto":["appCaches","logs","developer"],"consent":["installers","leftovers"]}"#,
        )
        .unwrap();
        assert_eq!(old, Policy::basic());
        assert!(!serde_json::to_string(&old).unwrap().contains("actions"));
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
    fn personal_files_and_trash_need_consent_and_extras_need_the_policy() {
        let not_allowed = |pair: &Pair, cmd: &Command| {
            matches!(
                pair.accept(&pair.issue(cmd), NOW),
                Err(FleetError::NotAllowed(_))
            )
        };
        // Základní zásady (verze 0.7): soubory uživatele, Koš ani nové zásahy.
        let basic = Pair {
            policy: Policy::basic(),
            ..Pair::new()
        };
        for category in CONSENT_ONLY {
            assert!(not_allowed(
                &basic,
                &command(CommandKind::Cleanup, vec![category])
            ));
        }
        let mut deep = command(CommandKind::Cleanup, vec![CleanCategory::AppCaches]);
        deep.deep = true;
        let mut full = command(CommandKind::Scan, vec![]);
        full.full = true;
        let mut quit = command(CommandKind::QuitApps, vec![]);
        quit.targets = vec!["com.google.Chrome".into()];
        let mut purge = command(CommandKind::DeleteQuarantine, vec![]);
        purge.targets = vec!["3f2a9c1e0b7d4a55".into()];
        let extras = [
            deep.clone(),
            full.clone(),
            quit.clone(),
            purge.clone(),
            command(CommandKind::Restart, vec![]),
            command(CommandKind::Update, vec![]),
        ];
        for cmd in &extras {
            assert!(not_allowed(&basic, cmd), "{:?}", cmd.kind);
        }

        // Rozšířená správa: Koš a velké soubory jen jako „se souhlasem“.
        let pair = Pair::new();
        let personal = command(
            CommandKind::Cleanup,
            vec![CleanCategory::LargeFiles, CleanCategory::Trash],
        );
        let accepted = pair.accept(&pair.issue(&personal), NOW).unwrap();
        let (auto, consent) = pair.policy.split(&accepted.categories);
        assert!(auto.is_empty());
        assert_eq!(consent, personal.categories);
        for cmd in &extras {
            pair.accept(&pair.issue(cmd), NOW).unwrap();
        }
        // Podvržené zásady s Košem „hned“ Mac odmítne celé.
        let mut forged = Pair::new();
        forged.policy.consent.retain(|c| *c != CleanCategory::Trash);
        forged.policy.auto.push(CleanCategory::Trash);
        assert!(not_allowed(
            &forged,
            &command(CommandKind::Cleanup, vec![CleanCategory::Trash])
        ));

        // Cíle: bezpečné identifikátory, v mezích, bez opakování.
        for bad in [
            vec![],
            vec!["com.evil\"; do shell script \"rm".to_string()],
            vec!["com.a.b".to_string(); 2],
            (0..=MAX_APP_TARGETS)
                .map(|i| format!("com.example.app{i}"))
                .collect(),
        ] {
            let mut cmd = quit.clone();
            cmd.targets = bad;
            assert!(not_allowed(&pair, &cmd));
        }
        for bad in [vec![], vec!["../../etc/passwd".to_string()]] {
            let mut cmd = purge.clone();
            cmd.targets = bad;
            assert!(not_allowed(&pair, &cmd));
        }
        // Volby, které k druhu příkazu nepatří.
        let mut odd = command(CommandKind::Cleanup, vec![CleanCategory::Logs]);
        odd.targets = vec!["com.a.b".into()];
        assert!(not_allowed(&pair, &odd));
        let mut odd = command(CommandKind::Scan, vec![]);
        odd.deep = true;
        assert!(not_allowed(&pair, &odd));
        let mut odd = command(CommandKind::Isolate, vec![]);
        odd.full = true;
        assert!(not_allowed(&pair, &odd));
        assert!(not_allowed(
            &pair,
            &command(CommandKind::Restart, vec![CleanCategory::Logs])
        ));
        let mut odd = command(CommandKind::Restart, vec![]);
        odd.policy = Some(Policy::standard());
        assert!(not_allowed(&pair, &odd));

        // Nabídka zásad: jen platné zásady (i Macu se základními).
        let mut offer = command(CommandKind::Policy, vec![]);
        assert!(not_allowed(&basic, &offer));
        offer.policy = Some(Policy::standard());
        basic.accept(&basic.issue(&offer), NOW).unwrap();
        let mut bad = Policy::standard();
        bad.auto.push(CleanCategory::LargeFiles);
        offer.policy = Some(bad);
        assert!(not_allowed(&basic, &offer));

        // Kategorie mimo zásady, prázdný úklid, kategorie u jiného příkazu, duplicity.
        let pair = Pair {
            policy: Policy {
                auto: vec![CleanCategory::Logs],
                consent: vec![],
                actions: vec![],
                share: vec![],
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
                    items: 0,
                }],
                deep: None,
            }),
            policy: None,
            hardware: None,
            security: None,
            performance: None,
            quarantine: vec![],
            events: vec![],
        };
        // Zpráva bez nových polí vypadá jako z verze 0.7 (správce 0.7 ji přečte).
        let json = serde_json::to_string(&report).unwrap();
        for field in [
            "policy",
            "hardware",
            "security",
            "performance",
            "quarantine",
            "events",
            "items",
            "deep",
        ] {
            assert!(!json.contains(&format!("\"{field}\"")), "{field}");
        }
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

        // Podrobnosti jen v mezích zásad, které Mac uvádí.
        let check = |r: &Report| {
            let sealed = sign_and_seal(&pair.device, &pair.admin.public(), REPORT, r).unwrap();
            open_report(&pair.admin, &pair.device.public(), FLEET, DEVICE, &sealed)
        };
        let mut detailed = report.clone();
        detailed.hardware = Some(HardwareReport {
            chip: "Apple M2".into(),
            model_id: "Mac14,2".into(),
            serial: Some("C02XK0AAJGH5".into()),
            cores: 8,
            performance_cores: Some(4),
            efficiency_cores: Some(4),
            memory: 16,
            battery: None,
        });
        detailed.events = vec![EventReport {
            kind: "quarantined".into(),
            at_ms: NOW,
            data: serde_json::json!({ "path": "/Users/x/Downloads/a.dmg", "ruleId": "R" }),
        }];
        assert!(
            check(&detailed).is_err(),
            "basic policy shares nothing more"
        );
        detailed.policy = Some(Policy::standard());
        assert_eq!(check(&detailed).unwrap(), detailed);
        let mut big = detailed.clone();
        big.events[0].data = serde_json::json!({ "path": "x".repeat(MAX_EVENT_DATA_CHARS) });
        assert!(check(&big).is_err());
        let mut big = detailed.clone();
        big.quarantine = vec![QuarantineReport {
            id: "../escape".into(),
            path: "/x".into(),
            rule_name: "R".into(),
            severity: crate::Severity::High,
            at_ms: NOW,
            size: 1,
            sha256: "ab".into(),
        }];
        assert!(check(&big).is_err());
        let mut partial = detailed.clone();
        partial.policy = Some(Policy {
            share: vec![ShareScope::Hardware],
            ..Policy::standard()
        });
        assert!(check(&partial).is_err(), "events need the threats scope");
        partial.events.clear();
        check(&partial).unwrap();

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
            count: 0,
            note: None,
            until_ms: None,
        };
        let sealed = sign_and_seal(&pair.device, &pair.admin.public(), RESULT, &result).unwrap();
        assert_eq!(
            open_result(&pair.admin, &pair.device.public(), DEVICE, "c", &sealed).unwrap(),
            result
        );
        let mut noisy = result.clone();
        noisy.note = Some("x\u{7}".into());
        let sealed = sign_and_seal(&pair.device, &pair.admin.public(), RESULT, &noisy).unwrap();
        assert!(open_result(&pair.admin, &pair.device.public(), DEVICE, "c", &sealed).is_err());
        let sealed = sign_and_seal(&pair.device, &pair.admin.public(), RESULT, &result).unwrap();
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
        // Soubory uživatele a Koš bez výběru uživatele nikdy.
        assert!(remote_selection(&scan, &CONSENT_ONLY).is_empty());

        let estimate = cleanup_estimate(&scan, &[], NOW);
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
            "shown to the admin, cleaned only by the user's choice"
        );
        assert_eq!(bytes(CleanCategory::Trash), 400);
        let items = |cat| {
            estimate
                .categories
                .iter()
                .find(|c| c.category == cat)
                .map_or(0, |c| c.items)
        };
        assert_eq!(items(CleanCategory::LargeFiles), 1);
        assert_eq!(items(CleanCategory::Trash), 1, "files in the Trash");
        assert_eq!(items(CleanCategory::AppCaches), 0);
    }

    #[test]
    fn deep_cleanup_spares_running_apps_until_the_user_closes_them() {
        let cache = |id: &str, recommended: bool, note: Option<&str>, age_ms: u64| CleanItem {
            note: note.map(str::to_string),
            modified_ms: Some(NOW - age_ms),
            ..item(
                id,
                CleanCategory::AppCaches,
                100,
                recommended,
                CleanMethod::Delete,
            )
        };
        let scan = CleanScan {
            items: vec![
                cache("com.old.tool", true, None, 30 * DAY_MS),
                cache("com.fresh.idle", false, Some("in use"), 5 * MINUTE_MS),
                cache("com.busy.right.now", false, Some("in use"), 30_000),
                cache("Google", false, Some("in use"), MINUTE_MS),
                cache(
                    "com.tinyspeck.slackmacgap",
                    false,
                    Some("app is running"),
                    0,
                ),
                item(
                    "archives",
                    CleanCategory::Developer,
                    70,
                    false,
                    CleanMethod::MoveToTrash,
                ),
                item(
                    "derived",
                    CleanCategory::Developer,
                    80,
                    true,
                    CleanMethod::Delete,
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
        let running = vec![
            RunningApp {
                id: "com.google.Chrome".into(),
                name: "Google Chrome".into(),
            },
            RunningApp {
                id: "com.tinyspeck.slackmacgap".into(),
                name: "Slack".into(),
            },
            RunningApp {
                id: "com.apple.Safari".into(),
                name: "Safari".into(),
            },
        ];
        let all = [
            CleanCategory::AppCaches,
            CleanCategory::Developer,
            CleanCategory::LargeFiles,
            CleanCategory::Trash,
        ];
        let plan = deep_plan(&scan, &all, &running, NOW);
        let ids = |list: &[&CleanItem]| list.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
        assert_eq!(
            ids(&plan.now),
            vec!["com.old.tool", "com.fresh.idle", "derived"],
            "fresh caches of closed apps go now, archives and user files never"
        );
        assert_eq!(
            ids(&plan.with_apps),
            vec!["Google", "com.tinyspeck.slackmacgap"]
        );
        let apps: Vec<&str> = plan.apps.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(apps, vec!["Google Chrome", "Slack"]);

        // Po zavření: smaže jen schválené mezipaměti aplikací, které už neběží.
        let approved = vec![
            "Google".to_string(),
            "com.tinyspeck.slackmacgap".to_string(),
        ];
        let still_running = vec![running[1].clone()];
        assert_eq!(
            ids(&deep_after_close(&scan, &approved, &still_running)),
            vec!["Google"]
        );
        assert!(deep_after_close(&scan, &[], &[]).is_empty());

        // Obecná slova aplikace nespárují.
        assert!(cache_owner("com.apple.Music", &running).is_none());
        assert!(cache_owner("SoftwareUpdate", &running).is_none());
        assert_eq!(
            cache_owner("com.google.Chrome.helper", &running).map(|a| a.name.as_str()),
            Some("Google Chrome")
        );

        let estimate = cleanup_estimate(&scan, &running, NOW).deep.unwrap();
        assert_eq!(estimate.now_bytes, 100 + 100 + 80);
        assert_eq!(estimate.apps_bytes, 200);
        assert_eq!(estimate.apps, 2);
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

    #[test]
    fn extended_management_needs_antishield_0_8() {
        for old in ["0.7.0", "0.7.9", "0.1.2", "", "x"] {
            assert!(!supports_extended(old), "{old}");
        }
        for new in ["0.8.0", "0.8.1-beta.1", "0.10.0", "1.0.0"] {
            assert!(supports_extended(new), "{new}");
        }
    }
}
