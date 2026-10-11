//! Soukromí na macOS: které aplikace mají přístup ke kameře, mikrofonu,
//! nahrávání obrazovky, zpřístupnění, sledování vstupu a plnému přístupu
//! k disku. Databáze oprávnění (TCC) se jen čte (`sqlite3 -readonly`);
//! AntiShield sám nic nepovoluje ani neodebírá, jen ukáže, kde to změnit.
//! Čtení vyžaduje, aby měl AntiShield plný přístup k disku.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Sledovaná oprávnění: (služba TCC, náš klíč).
const SERVICES: [(&str, &str); 6] = [
    ("kTCCServiceCamera", "camera"),
    ("kTCCServiceMicrophone", "microphone"),
    ("kTCCServiceScreenCapture", "screen"),
    ("kTCCServiceAccessibility", "accessibility"),
    ("kTCCServiceListenEvent", "input"),
    ("kTCCServiceSystemPolicyAllFiles", "fullDisk"),
];
/// Oprávnění, která zneužívá spyware a keyloggery: nové se ohlásí.
pub const SENSITIVE: [&str; 4] = ["screen", "accessibility", "input", "fullDisk"];
const MAX_GRANTS: usize = 2_000;
const MAX_CLIENT_LEN: usize = 300;

/// Aplikace s oprávněním.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    /// `camera`, `microphone`, `screen`, `accessibility`, `input`, `fullDisk`.
    pub service: String,
    /// Identifikátor aplikace (bundle ID) nebo cesta k programu.
    pub client: String,
}

/// Výsledek kontroly soukromí.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyReport {
    /// `None` mimo macOS.
    pub full_disk_access: Option<bool>,
    /// Povolená oprávnění (jen s plným přístupem k disku).
    pub grants: Vec<Grant>,
    /// Proč přehled chybí (anglicky, rozhraní přeloží).
    pub problem: Option<String>,
}

fn home() -> Option<PathBuf> {
    crate::system::home_dir()
}

/// Databáze oprávnění: uživatelská a systémová.
fn databases() -> Vec<PathBuf> {
    let mut dbs = Vec::new();
    if let Some(home) = home() {
        dbs.push(home.join("Library/Application Support/com.apple.TCC/TCC.db"));
    }
    dbs.push(PathBuf::from(
        "/Library/Application Support/com.apple.TCC/TCC.db",
    ));
    dbs
}

/// Má AntiShield plný přístup k disku? Bez něj macOS nedovolí číst databázi
/// oprávnění ani poštu. Mimo macOS `None`.
pub fn full_disk_access() -> Option<bool> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let db = databases().into_iter().next()?;
    Some(std::fs::File::open(db).is_ok())
}

/// Rozbor výstupu `sqlite3 -json`: povolená sledovaná oprávnění.
fn parse_rows(json: &str, out: &mut Vec<Grant>) {
    let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(json) else {
        return;
    };
    for row in rows {
        let service = row
            .get("service")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some((_, key)) = SERVICES.iter().find(|(name, _)| *name == service) else {
            continue;
        };
        // auth_value 2 = povoleno, 3 = omezeně povoleno.
        let allowed = matches!(row.get("auth_value").and_then(|v| v.as_i64()), Some(2 | 3));
        let client = row
            .get("client")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if allowed && !client.is_empty() && out.len() < MAX_GRANTS {
            out.push(Grant {
                service: (*key).to_string(),
                client: client.chars().take(MAX_CLIENT_LEN).collect(),
            });
        }
    }
}

/// Přehled oprávnění aplikací (jen čtení).
pub fn report() -> PrivacyReport {
    let fda = full_disk_access();
    if fda != Some(true) {
        return PrivacyReport {
            full_disk_access: fda,
            grants: Vec::new(),
            problem: Some(if fda.is_none() {
                "not available on this system".into()
            } else {
                "full disk access is required".into()
            }),
        };
    }
    let names: Vec<String> = SERVICES
        .iter()
        .map(|(name, _)| format!("'{name}'"))
        .collect();
    let query = format!(
        "SELECT service, client, auth_value FROM access WHERE service IN ({});",
        names.join(",")
    );
    let mut grants = Vec::new();
    let mut read_any = false;
    for db in databases() {
        if !db.exists() {
            continue;
        }
        let output = std::process::Command::new("/usr/bin/sqlite3")
            .args(["-readonly", "-json"])
            .arg(&db)
            .arg(&query)
            .output();
        if let Ok(output) = output
            && output.status.success()
        {
            read_any = true;
            parse_rows(&String::from_utf8_lossy(&output.stdout), &mut grants);
        }
    }
    grants.sort();
    grants.dedup();
    PrivacyReport {
        full_disk_access: fda,
        grants,
        problem: (!read_any).then(|| "the permission database could not be read".into()),
    }
}

/// Nová citlivá oprávnění oproti předchozímu stavu (pro upozornění).
pub fn new_sensitive<'a>(before: &[Grant], now: &'a [Grant]) -> Vec<&'a Grant> {
    now.iter()
        .filter(|g| SENSITIVE.contains(&g.service.as_str()) && !before.contains(g))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allowed_permissions_are_read_from_the_database_output() {
        let json = r#"[
            {"service":"kTCCServiceScreenCapture","client":"com.example.recorder","auth_value":2},
            {"service":"kTCCServiceCamera","client":"us.zoom.xos","auth_value":2},
            {"service":"kTCCServiceMicrophone","client":"com.denied.app","auth_value":0},
            {"service":"kTCCServiceAppleEvents","client":"com.other","auth_value":2}
        ]"#;
        let mut grants = Vec::new();
        parse_rows(json, &mut grants);
        assert_eq!(
            grants,
            vec![
                Grant {
                    service: "screen".into(),
                    client: "com.example.recorder".into()
                },
                Grant {
                    service: "camera".into(),
                    client: "us.zoom.xos".into()
                },
            ]
        );
        parse_rows("not json", &mut grants);
        assert_eq!(grants.len(), 2);
    }

    #[test]
    fn only_new_sensitive_permissions_are_reported() {
        let old = vec![Grant {
            service: "screen".into(),
            client: "a".into(),
        }];
        let now = vec![
            Grant {
                service: "screen".into(),
                client: "a".into(),
            },
            Grant {
                service: "screen".into(),
                client: "spy".into(),
            },
            Grant {
                service: "camera".into(),
                client: "zoom".into(),
            },
        ];
        let fresh = new_sensitive(&old, &now);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].client, "spy");
    }
}
