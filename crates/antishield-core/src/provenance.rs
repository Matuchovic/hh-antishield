//! Původ souboru pro příběh útoku: odkud a čím se dostal do počítače.
//!
//! Čte jen metadata, která při stažení zapsal systém nebo aplikace: na macOS
//! `com.apple.metadata:kMDItemWhereFroms` a `com.apple.quarantine`, na Linuxu
//! `user.xdg.origin.url`, na Windows datový proud `Zone.Identifier`. Obsah
//! souboru nečte. Adresy se ukládají bez parametrů, fragmentu a přihlašovacích
//! údajů (podepsané odkazy v nich nesou tokeny); texty se zkracují.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Hodnota metadat větší než tento limit se nečte (poškození nebo útok).
const MAX_ATTR_BYTES: usize = 64 * 1024;
/// Nejdelší uložený text (adresa, odesílatel, aplikace).
const MAX_TEXT_CHARS: usize = 300;

/// Kudy soubor přišel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Channel {
    Web,
    Email,
    AirDrop,
    Messages,
    ExternalDrive,
    #[default]
    Unknown,
}

/// Co o původu souboru víme. Všechno je volitelné: metadata nemusí existovat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub channel: Channel,
    /// Adresa, ze které byl soubor stažen (bez parametrů).
    pub download_url: Option<String>,
    /// Stránka, ze které stahování začalo.
    pub referrer_url: Option<String>,
    /// Odesílatel e-mailu, ze kterého je příloha (macOS Mail).
    pub email_from: Option<String>,
    /// Aplikace, která soubor uložila (Safari, Google Chrome, Mail, …).
    pub saved_by: Option<String>,
    /// Kdy soubor dorazil podle značky systému (ms od epochy).
    pub arrived_at_ms: Option<u64>,
    pub created_at_ms: Option<u64>,
    pub modified_at_ms: Option<u64>,
}

/// Přečte původ souboru. Nikdy nepanikaří; co nejde zjistit, zůstane prázdné.
pub fn read(path: &Path) -> Provenance {
    let mut provenance = Provenance::default();
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        provenance.created_at_ms = meta.created().ok().and_then(epoch_ms);
        provenance.modified_at_ms = meta.modified().ok().and_then(epoch_ms);
    }
    platform::fill(path, &mut provenance);
    // Program uvnitř aplikace: značky stažení nese obvykle balíček `.app`.
    if provenance.download_url.is_none()
        && provenance.saved_by.is_none()
        && let Some(bundle) = app_bundle(path)
    {
        platform::fill(&bundle, &mut provenance);
    }
    provenance.channel = classify(path, &provenance);
    provenance
}

/// Nejvzdálenější balíček `.app`, ve kterém soubor leží.
fn app_bundle(path: &Path) -> Option<std::path::PathBuf> {
    path.ancestors()
        .skip(1)
        .filter(|ancestor| ancestor.extension().is_some_and(|ext| ext == "app"))
        .last()
        .map(Path::to_path_buf)
}

fn epoch_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Text bez řídicích znaků, zkrácený.
fn clean_text(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// `scheme://host/path` bez přihlašovacích údajů, parametrů a fragmentu.
/// Jiné než webové adresy vrací `None`.
pub fn sanitize_url(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ftp") {
        return None;
    }
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, ""),
    };
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    clean_text(&format!("{scheme}://{host}{path}"))
}

/// Odesílatel ve tvaru „Jméno <adresa>“ nebo jen adresa.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn looks_like_sender(text: &str) -> bool {
    let text = text.trim();
    text.contains('@') && !text.contains("://") && !text.contains(char::is_whitespace)
        || (text.contains('<') && text.ends_with('>') && text.contains('@'))
}

/// Položky `kMDItemWhereFroms`: stahování (adresa, stránka) nebo e-mail
/// (odesílatel, předmět, odkaz `message:`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn apply_where_froms(items: &[String], provenance: &mut Provenance) {
    let mut urls = items.iter().filter_map(|item| sanitize_url(item));
    provenance.download_url = urls.next();
    provenance.referrer_url = urls.next();
    provenance.email_from = items
        .iter()
        .find(|item| looks_like_sender(item))
        .and_then(|item| clean_text(item));
    if items.iter().any(|item| item.starts_with("message:")) && provenance.saved_by.is_none() {
        provenance.saved_by = Some("Mail".into());
    }
}

/// `com.apple.quarantine`: „příznaky;čas (hex s);aplikace;UUID“.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn apply_quarantine(text: &str, provenance: &mut Provenance) {
    let mut parts = text.split(';');
    let _flags = parts.next();
    if let Some(seconds) = parts
        .next()
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
    {
        provenance.arrived_at_ms = seconds.checked_mul(1000);
    }
    if let Some(agent) = parts.next() {
        let agent = agent.trim().trim_end_matches(".app");
        if let Some(agent) = clean_text(agent) {
            provenance.saved_by = Some(agent);
        }
    }
}

/// `Zone.Identifier` (Windows): `HostUrl` je adresa souboru, `ReferrerUrl` stránka.
#[cfg_attr(not(windows), allow(dead_code))]
fn apply_zone_identifier(text: &str, provenance: &mut Provenance) {
    for line in text.lines() {
        if let Some(url) = line.strip_prefix("HostUrl=") {
            provenance.download_url = sanitize_url(url);
        } else if let Some(url) = line.strip_prefix("ReferrerUrl=") {
            provenance.referrer_url = sanitize_url(url);
        }
    }
}

fn classify(path: &Path, provenance: &Provenance) -> Channel {
    let text = path.to_string_lossy();
    let saved_by = provenance.saved_by.as_deref().unwrap_or_default();
    if text.contains("/Library/Mail/")
        || text.contains("/Library/Containers/com.apple.mail/")
        || saved_by == "Mail"
        || provenance.email_from.is_some()
    {
        Channel::Email
    } else if saved_by == "sharingd" || saved_by.eq_ignore_ascii_case("AirDrop") {
        Channel::AirDrop
    } else if saved_by.contains("Messages") || saved_by.contains("MobileSMS") {
        Channel::Messages
    } else if provenance.download_url.is_some() || provenance.referrer_url.is_some() {
        Channel::Web
    } else if cfg!(target_os = "macos") && text.starts_with("/Volumes/") {
        Channel::ExternalDrive
    } else {
        Channel::Unknown
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn attr(path: &Path, name: &str) -> Option<Vec<u8>> {
    // Pevná vyrovnávací paměť: větší hodnota vrátí ERANGE a přeskočí se.
    // `lgetxattr` nenásleduje symbolický odkaz.
    let mut buffer = vec![0u8; MAX_ATTR_BYTES];
    let length = rustix::fs::lgetxattr(path, name, &mut buffer[..]).ok()?;
    buffer.truncate(length);
    Some(buffer)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub fn fill(path: &Path, provenance: &mut Provenance) {
        if let Some(text) =
            attr(path, "com.apple.quarantine").and_then(|bytes| String::from_utf8(bytes).ok())
        {
            apply_quarantine(&text, provenance);
        }
        if let Some(bytes) = attr(path, "com.apple.metadata:kMDItemWhereFroms")
            && let Ok(plist::Value::Array(values)) =
                plist::Value::from_reader(std::io::Cursor::new(bytes))
        {
            let items: Vec<String> = values
                .iter()
                .filter_map(|value| value.as_string().map(str::to_string))
                .take(8)
                .collect();
            apply_where_froms(&items, provenance);
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn fill(path: &Path, provenance: &mut Provenance) {
        let text = |name: &str| attr(path, name).and_then(|bytes| String::from_utf8(bytes).ok());
        provenance.download_url = text("user.xdg.origin.url").and_then(|url| sanitize_url(&url));
        provenance.referrer_url = text("user.xdg.referrer.url").and_then(|url| sanitize_url(&url));
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::io::Read;

    pub fn fill(path: &Path, provenance: &mut Provenance) {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        let mut bytes = Vec::new();
        let read = std::fs::File::open(Path::new(&stream))
            .and_then(|file| file.take(MAX_ATTR_BYTES as u64).read_to_end(&mut bytes));
        if read.is_ok()
            && let Ok(text) = String::from_utf8(bytes)
        {
            apply_zone_identifier(&text, provenance);
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod platform {
    use super::*;

    pub fn fill(_path: &Path, _provenance: &mut Provenance) {}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn urls_lose_tokens_credentials_and_fragments() {
        assert_eq!(
            sanitize_url("https://user:pw@cdn.example.com/files/setup.dmg?token=abc#x").as_deref(),
            Some("https://cdn.example.com/files/setup.dmg")
        );
        assert_eq!(
            sanitize_url("HTTP://example.com").as_deref(),
            Some("http://example.com")
        );
        assert_eq!(sanitize_url("javascript:alert(1)"), None);
        assert_eq!(sanitize_url("file:///etc/passwd"), None);
        assert_eq!(sanitize_url("message:%3C1234%40mail%3E"), None);
    }

    #[test]
    fn browser_downloads_and_mail_attachments_are_recognized() {
        let mut web = Provenance::default();
        apply_quarantine("0083;6527a1b2;Google Chrome.app;F2A5", &mut web);
        apply_where_froms(
            &[
                "https://dl.example.com/invoice.zip?sig=1".into(),
                "https://example.com/download".into(),
            ],
            &mut web,
        );
        assert_eq!(web.saved_by.as_deref(), Some("Google Chrome"));
        assert_eq!(web.arrived_at_ms, Some(0x6527_a1b2 * 1000));
        assert_eq!(
            web.download_url.as_deref(),
            Some("https://dl.example.com/invoice.zip")
        );
        assert_eq!(
            web.referrer_url.as_deref(),
            Some("https://example.com/download")
        );
        assert_eq!(
            classify(Path::new("/Users/eva/Downloads/invoice.zip"), &web),
            Channel::Web
        );

        let mut mail = Provenance::default();
        apply_where_froms(
            &[
                "Eva Nováková <eva@example.com>".into(),
                "Faktura".into(),
                "message:%3C1234%40example.com%3E".into(),
            ],
            &mut mail,
        );
        assert_eq!(
            mail.email_from.as_deref(),
            Some("Eva Nováková <eva@example.com>")
        );
        assert_eq!(mail.saved_by.as_deref(), Some("Mail"));
        assert_eq!(classify(Path::new("/tmp/a.pdf"), &mail), Channel::Email);
    }

    #[test]
    fn windows_zone_identifier_and_bad_input() {
        let mut provenance = Provenance::default();
        apply_zone_identifier(
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/\r\nHostUrl=https://dl.example.com/a.exe?x=1\r\n",
            &mut provenance,
        );
        assert_eq!(
            provenance.download_url.as_deref(),
            Some("https://dl.example.com/a.exe")
        );
        assert_eq!(
            provenance.referrer_url.as_deref(),
            Some("https://example.com/")
        );

        let mut broken = Provenance::default();
        apply_quarantine("zz;not-hex;\u{7}\u{1b}", &mut broken);
        assert_eq!(broken.arrived_at_ms, None);
        assert_eq!(broken.saved_by, None, "control characters only");
    }

    #[test]
    fn programs_inside_an_app_use_the_outermost_bundle() {
        assert_eq!(
            app_bundle(Path::new(
                "/Applications/X.app/Contents/Frameworks/H.app/Contents/MacOS/h"
            )),
            Some(std::path::PathBuf::from("/Applications/X.app"))
        );
        assert_eq!(app_bundle(Path::new("/Users/eva/Downloads/a.dmg")), None);
    }

    #[test]
    fn reading_a_plain_file_never_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let provenance = read(&file);
        assert!(provenance.modified_at_ms.is_some());
        assert_eq!(provenance.channel, Channel::Unknown);
        assert_eq!(read(&tmp.path().join("missing")), Provenance::default());
    }
}
