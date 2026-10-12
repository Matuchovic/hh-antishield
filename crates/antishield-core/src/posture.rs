//! Bezpečnost systému: jen čte stav ochran operačního systému a radí, jak je
//! zapnout. Nic nemění a ochrany systému nikdy nevypíná.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Výsledek jedné kontroly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PostureState {
    /// Ochrana je zapnutá.
    Ok,
    /// Ochrana je vypnutá nebo slabá.
    Warning,
    /// Stav nejde zjistit (chybí oprávnění, nepodporovaný systém).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureCheck {
    pub id: String,
    pub title: String,
    pub state: PostureState,
    pub detail: String,
    /// Jak ochranu zapnout (prázdné, když je v pořádku).
    pub advice: String,
}

const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_OUTPUT: u64 = 64 * 1024;

/// Spustí systémový příkaz (pevná absolutní cesta) s časovým limitem.
pub(crate) fn run(program: &str, args: &[&str]) -> Option<String> {
    run_limited(program, args, MAX_OUTPUT)
}

/// Přečte rouru celou na pozadí (nad limit zahazuje), aby program při
/// velkém výstupu nečekal na plnou rouru.
fn drain<R: Read + Send + 'static>(pipe: R, max_output: u64) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut limited = pipe.take(max_output);
        let mut buf = Vec::new();
        let _ = limited.read_to_end(&mut buf);
        let _ = std::io::copy(&mut limited.into_inner(), &mut std::io::sink());
        let _ = tx.send(buf);
    });
    rx
}

/// Jako `run`, s vlastním limitem velikosti výstupu.
pub(crate) fn run_limited(program: &str, args: &[&str], max_output: u64) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take().map(|p| drain(p, max_output));
    let stderr = child.stderr.take().map(|p| drain(p, max_output));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    // Rouru může držet ještě potomek programu: déle než chvíli se nečeká.
    let collect = |rx: Option<std::sync::mpsc::Receiver<Vec<u8>>>| {
        rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(2)).ok())
    };
    let mut text = String::from_utf8_lossy(&collect(stdout)?).into_owned();
    text.push_str(&String::from_utf8_lossy(
        &collect(stderr).unwrap_or_default(),
    ));
    Some(text)
}

fn check(id: &str, title: &str, state: PostureState, detail: &str, advice: &str) -> PostureCheck {
    PostureCheck {
        id: id.into(),
        title: title.into(),
        state,
        detail: detail.into(),
        advice: if state == PostureState::Ok {
            String::new()
        } else {
            advice.into()
        },
    }
}

/// Vyhodnotí výstup příkazu podle textů pro „zapnuto“ a „vypnuto“.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
pub(crate) fn classify(output: Option<&str>, on: &[&str], off: &[&str]) -> PostureState {
    let Some(text) = output.map(str::to_ascii_lowercase) else {
        return PostureState::Unknown;
    };
    if off.iter().any(|needle| text.contains(needle)) {
        PostureState::Warning
    } else if on.iter().any(|needle| text.contains(needle)) {
        PostureState::Ok
    } else {
        PostureState::Unknown
    }
}

/// Verze definic XProtect (vestavěná ochrana macOS).
#[cfg(target_os = "macos")]
pub(crate) fn xprotect_version() -> Option<String> {
    plist::Value::from_file(
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    )
    .ok()
    .and_then(|v| {
        v.as_dictionary()?
            .get("CFBundleShortVersionString")?
            .as_string()
            .map(str::to_string)
    })
}

#[cfg(target_os = "macos")]
pub fn checks() -> Vec<PostureCheck> {
    let gatekeeper = run("/usr/sbin/spctl", &["--status"]);
    let sip = run("/usr/bin/csrutil", &["status"]);
    let filevault = run("/usr/bin/fdesetup", &["status"]);
    let firewall = run(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    );
    let xprotect = xprotect_version();
    vec![
        check(
            "gatekeeper",
            "Gatekeeper",
            classify(
                gatekeeper.as_deref(),
                &["assessments enabled"],
                &["assessments disabled"],
            ),
            "Ověřuje aplikace stažené z internetu před spuštěním.",
            "Zapněte ho příkazem „sudo spctl --master-enable“ nebo v Nastavení systému → Soukromí a zabezpečení.",
        ),
        check(
            "sip",
            "Ochrana integrity systému (SIP)",
            classify(sip.as_deref(), &["status: enabled"], &["status: disabled"]),
            "Brání změnám systémových souborů i s právy správce.",
            "Zapíná se v režimu obnovy příkazem „csrutil enable“.",
        ),
        check(
            "filevault",
            "Šifrování disku FileVault",
            classify(
                filevault.as_deref(),
                &["filevault is on"],
                &["filevault is off"],
            ),
            "Chrání data, když se Mac ztratí nebo ho někdo ukradne.",
            "Zapněte ho v Nastavení systému → Soukromí a zabezpečení → FileVault.",
        ),
        check(
            "firewall",
            "Firewall",
            classify(
                firewall.as_deref(),
                &["is enabled", "state = 1", "state = 2"],
                &["is disabled", "state = 0"],
            ),
            "Blokuje nevyžádaná příchozí spojení.",
            "Zapněte ho v Nastavení systému → Síť → Firewall.",
        ),
        check(
            "xprotect",
            "XProtect (antivirus macOS)",
            if xprotect.is_some() {
                PostureState::Ok
            } else {
                PostureState::Unknown
            },
            &match &xprotect {
                Some(version) => format!("Vestavěná ochrana Applu, verze definic {version}."),
                None => "Verzi definic XProtect nejde zjistit.".to_string(),
            },
            "Nechte zapnuté automatické bezpečnostní aktualizace v Nastavení systému → Obecné → Aktualizace softwaru.",
        ),
    ]
}

#[cfg(windows)]
pub fn checks() -> Vec<PostureCheck> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let powershell = format!(r"{system_root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    let defender = run(
        &powershell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-MpComputerStatus).RealTimeProtectionEnabled",
        ],
    );
    let firewall = run(
        &format!(r"{system_root}\System32\netsh.exe"),
        &["advfirewall", "show", "allprofiles", "state"],
    );
    let firewall_state = match firewall.as_deref().map(str::to_ascii_lowercase) {
        Some(text) if text.contains("off") => PostureState::Warning,
        Some(text) if text.contains("on") => PostureState::Ok,
        _ => PostureState::Unknown,
    };
    vec![
        check(
            "defender",
            "Ochrana v reálném čase Microsoft Defender",
            classify(defender.as_deref(), &["true"], &["false"]),
            "Vestavěný antivirus Windows.",
            "Zapněte ji v Zabezpečení Windows → Ochrana před viry a hrozbami.",
        ),
        check(
            "firewall",
            "Firewall Windows",
            firewall_state,
            "Blokuje nevyžádaná příchozí spojení ve všech profilech sítě.",
            "Zapněte ho v Zabezpečení Windows → Firewall a ochrana sítě.",
        ),
    ]
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn checks() -> Vec<PostureCheck> {
    let _ = run;
    vec![check(
        "unsupported",
        "Bezpečnost systému",
        PostureState::Unknown,
        "Kontrola je dostupná na macOS a Windows.",
        "",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_prefers_off() {
        assert_eq!(
            classify(
                Some("Assessments enabled"),
                &["assessments enabled"],
                &["disabled"]
            ),
            PostureState::Ok
        );
        assert_eq!(
            classify(
                Some("assessments disabled"),
                &["assessments"],
                &["disabled"]
            ),
            PostureState::Warning
        );
        assert_eq!(classify(None, &["on"], &["off"]), PostureState::Unknown);
        assert_eq!(
            classify(Some("???"), &["on"], &["off"]),
            PostureState::Unknown
        );
    }

    #[test]
    fn commands_time_out_or_fail_quietly() {
        assert_eq!(run("/nonexistent/program", &[]), None);
    }
}
