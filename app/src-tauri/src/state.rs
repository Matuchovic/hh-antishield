//! Stav aplikace sdílený mezi příkazy a službami na pozadí.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use antishield_core::error::ErrorDto;
use antishield_core::privacy::PrivacyReport;
use antishield_core::status::{
    ComponentKind, ComponentState, ComponentStatus, ProtectionSummary, summarize_protection,
};
use antishield_core::watch::FolderWatcher;
use antishield_core::{Engine, EngineConfig, Finding, ScanHandle, ScanSummary};
use serde::Serialize;

use crate::settings::Settings;
use crate::story::{ActivityLog, StoryBook};

/// Kolik posledních výběrů z dialogu si pamatujeme.
const MAX_SELECTIONS: usize = 20;
/// Kolik posledních zásahů hlídání držíme pro rozhraní.
const MAX_DETECTIONS: usize = 200;
/// Souhrn poslední kontroly, aby ho přehled ukázal i po restartu.
const LAST_SUMMARY_FILE: &str = "last-summary.json";
/// Větší soubor se souhrnem se nečte (poškození nebo podvržení).
const MAX_SUMMARY_BYTES: u64 = 8 * 1024 * 1024;
/// Aktualizace pravidel je „živá“, když poslední úspěch není starší.
const RULES_FRESH_MS: u64 = 48 * 60 * 60 * 1000;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Co se stalo se souborem zachyceným hlídáním.
#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum DetectionAction {
    Quarantined { item_id: String },
    Detected,
    Failed { reason: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub at_ms: u64,
    pub finding: Finding,
    pub action: DetectionAction,
}

/// Stav aktualizací pravidel.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesStatus {
    pub last_check_ms: Option<u64>,
    pub last_success_ms: Option<u64>,
    pub last_error: Option<String>,
    pub checking: bool,
}

/// Běh hlídání složek.
#[derive(Debug, Default)]
pub struct ProtectionRuntime {
    pub watcher: Option<FolderWatcher>,
    pub started_at_ms: Option<u64>,
    pub error: Option<String>,
    /// Hlídaná složka, ve které systém nedovolil číst soubory (na macOS
    /// Soukromí a zabezpečení → Soubory a složky). Hlídání pak není účinné.
    pub access_denied: Option<PathBuf>,
}

/// Jde ve složce číst? Selže, když systém přístup zakázal.
pub fn folder_readable(folder: &Path) -> bool {
    std::fs::read_dir(folder).is_ok()
}

/// Přehled pro rozhraní: co se hlídá a co se stalo.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInfo {
    pub watched: Vec<String>,
    pub watching_since_ms: Option<u64>,
    pub watch_error: Option<String>,
    pub access_denied: Option<PathBuf>,
    pub detections: Vec<Detection>,
    pub rules: RulesStatus,
    pub last_scheduled_run_ms: Option<u64>,
    pub background_problem: Option<String>,
    pub last_catch_up: Option<CatchUp>,
    /// Hlídají se i složky položek po přihlášení.
    pub startup_watched: bool,
    pub programs_checked: u64,
    pub programs_since_ms: Option<u64>,
    /// Plný přístup k disku (jen macOS; jinde `None`).
    pub full_disk_access: Option<bool>,
    /// Co ochrana zkontrolovala od spuštění (radar).
    pub activity: ActivityLog,
}

pub struct AppState {
    pub data_dir: PathBuf,
    engine: OnceLock<Result<Arc<Engine>, ErrorDto>>,
    settings: Mutex<Settings>,
    selections: Mutex<VecDeque<(String, Vec<PathBuf>)>>,
    current_scan: Mutex<Option<ScanHandle>>,
    last_summary: Arc<Mutex<Option<ScanSummary>>>,
    /// Souhrn z minulého spuštění (jen k zobrazení; nálezy z něj se před
    /// vyčištěním znovu ověří, soubor na disku o zásahu nerozhoduje).
    restored_summary: Option<ScanSummary>,
    pending_update: Mutex<Option<tauri_plugin_updater::Update>>,
    pub rules_status: Mutex<RulesStatus>,
    pub protection: Mutex<ProtectionRuntime>,
    detections: Mutex<VecDeque<Detection>>,
    pub last_scheduled_run_ms: Mutex<Option<u64>>,
    /// Aplikace běží jako agent na pozadí (spustil ji launchd / přihlášení).
    pub background_launch: AtomicBool,
    /// Uživatel ochranu z lišty vědomě vypnul (agent se nemá obnovit).
    pub explicit_quit: AtomicBool,
    /// Proč ochrana na pozadí neběží (např. aplikace není v Aplikacích).
    pub background_problem: Mutex<Option<String>>,
    pub last_catch_up: Mutex<Option<CatchUp>>,
    /// Kolik spuštěných programů hlídání zkontrolovalo a od kdy.
    pub programs_checked: AtomicU64,
    pub programs_since_ms: Mutex<Option<u64>>,
    /// Poslední přehled oprávnění aplikací a kdy vznikl.
    pub privacy: Mutex<Option<(u64, PrivacyReport)>>,
    /// Příběhy útoků (uložené, jen k zobrazení).
    pub stories: Mutex<StoryBook>,
    /// Co ochrana zkontrolovala od spuštění (radar).
    pub activity: Mutex<ActivityLog>,
}

/// Kontrola souborů, které přibyly, když ochrana neběžela.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatchUp {
    pub at_ms: u64,
    pub since_ms: u64,
    pub checked: usize,
    pub complete: bool,
}

pub fn now_ms() -> u64 {
    antishield_core::now_ms()
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Self {
        let settings = Settings::load(&data_dir.join("settings.json"));
        let restored_summary = load_summary(&data_dir.join(LAST_SUMMARY_FILE));
        let stories = StoryBook::load(&data_dir);
        Self {
            data_dir,
            engine: OnceLock::new(),
            settings: Mutex::new(settings),
            selections: Mutex::new(VecDeque::new()),
            current_scan: Mutex::new(None),
            last_summary: Arc::new(Mutex::new(None)),
            restored_summary,
            pending_update: Mutex::new(None),
            rules_status: Mutex::new(RulesStatus::default()),
            protection: Mutex::new(ProtectionRuntime::default()),
            detections: Mutex::new(VecDeque::new()),
            last_scheduled_run_ms: Mutex::new(None),
            background_launch: AtomicBool::new(false),
            explicit_quit: AtomicBool::new(false),
            background_problem: Mutex::new(None),
            last_catch_up: Mutex::new(None),
            programs_checked: AtomicU64::new(0),
            programs_since_ms: Mutex::new(None),
            privacy: Mutex::new(None),
            stories: Mutex::new(stories),
            activity: Mutex::new(ActivityLog::default()),
        }
    }

    /// Spustí engine (volá se na pozadí, aby okno naskočilo hned).
    pub fn init_engine(&self) -> bool {
        let result = Engine::new(EngineConfig::new(&self.data_dir))
            .map(|engine| {
                engine.self_test();
                Arc::new(engine)
            })
            .map_err(|err| ErrorDto::from(&err));
        let ok = result.is_ok();
        let _ = self.engine.set(result);
        ok
    }

    pub fn engine(&self) -> Result<Arc<Engine>, ErrorDto> {
        match self.engine.get() {
            Some(Ok(engine)) => Ok(engine.clone()),
            Some(Err(err)) => Err(err.clone()),
            None => Err(ErrorDto {
                code: "engine_starting".into(),
                message: "the engine is still starting".into(),
            }),
        }
    }

    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    pub fn set_settings(&self, settings: Settings) -> Result<(), ErrorDto> {
        settings.save(&self.data_dir.join("settings.json"))?;
        *lock(&self.settings) = settings;
        Ok(())
    }

    /// Stav komponent: engine + to, co běží v aplikaci (hlídání, aktualizace).
    pub fn protection(&self) -> ProtectionSummary {
        let mut components: Vec<ComponentStatus> = match self.engine() {
            Ok(engine) => engine.component_statuses(),
            Err(err) => ComponentKind::ALL
                .iter()
                .map(|kind| ComponentStatus {
                    kind: *kind,
                    state: match kind {
                        ComponentKind::DetectionEngine
                        | ComponentKind::RulePack
                        | ComponentKind::OnDemandScan => {
                            if err.code == "engine_starting" {
                                ComponentState::Degraded {
                                    reason: err.message.clone(),
                                }
                            } else {
                                ComponentState::Failed {
                                    reason: err.message.clone(),
                                }
                            }
                        }
                        _ => ComponentState::NotImplemented,
                    },
                })
                .collect(),
        };
        let settings = self.settings();
        let realtime = {
            let mut runtime = lock(&self.protection);
            // Po povolení přístupu v systému se stav sám vrátí do pořádku.
            if let Some(folder) = &runtime.access_denied
                && folder_readable(folder)
            {
                runtime.access_denied = None;
            }
            if !settings.protection_enabled {
                ComponentState::Disabled
            } else if let Some(error) = &runtime.error {
                ComponentState::Failed {
                    reason: error.clone(),
                }
            } else if runtime.access_denied.is_some() {
                ComponentState::Degraded {
                    reason: "no access to files in a watched folder".into(),
                }
            } else {
                match (&runtime.watcher, runtime.started_at_ms) {
                    (Some(watcher), Some(since)) if !watcher.watched().is_empty() => {
                        ComponentState::Running {
                            verified_at_ms: since,
                        }
                    }
                    (Some(_), _) => ComponentState::Degraded {
                        reason: "no watched folder exists".into(),
                    },
                    _ => ComponentState::Degraded {
                        reason: "folder watching is starting".into(),
                    },
                }
            }
        };
        let updates = {
            let rules = lock(&self.rules_status);
            if !settings.rules_auto_update {
                ComponentState::Disabled
            } else {
                match (rules.last_success_ms, &rules.last_error) {
                    (Some(at), None) if now_ms().saturating_sub(at) <= RULES_FRESH_MS => {
                        ComponentState::Running { verified_at_ms: at }
                    }
                    (_, Some(error)) => ComponentState::Degraded {
                        reason: error.clone(),
                    },
                    _ => ComponentState::Degraded {
                        reason: "rule updates have not run yet".into(),
                    },
                }
            }
        };
        let (email, privacy) = self.mail_and_privacy_states(settings.protection_enabled);
        for component in &mut components {
            match component.kind {
                ComponentKind::RealTimeProtection => component.state = realtime.clone(),
                ComponentKind::Updates => component.state = updates.clone(),
                ComponentKind::EmailProtection => component.state = email.clone(),
                ComponentKind::PrivacyProtection => component.state = privacy.clone(),
                _ => {}
            }
        }
        ProtectionSummary {
            level: summarize_protection(&components),
            components,
        }
    }

    /// Přílohy Apple Mail a přehled oprávnění: obojí potřebuje plný přístup
    /// k disku. Mimo macOS zatím nejsou.
    fn mail_and_privacy_states(
        &self,
        protection_enabled: bool,
    ) -> (ComponentState, ComponentState) {
        let Some(fda) = antishield_core::privacy::full_disk_access() else {
            return (
                ComponentState::NotImplemented,
                ComponentState::NotImplemented,
            );
        };
        let need_fda = || ComponentState::Degraded {
            reason: "full disk access is required".into(),
        };
        let mail_dirs = antishield_core::system::mail_folders();
        let email = if !protection_enabled {
            ComponentState::Disabled
        } else if mail_dirs.is_empty() {
            ComponentState::Degraded {
                reason: "apple mail is not used".into(),
            }
        } else if !fda {
            need_fda()
        } else {
            let runtime = lock(&self.protection);
            match (&runtime.watcher, runtime.started_at_ms) {
                (Some(watcher), Some(since))
                    if watcher.watched().iter().any(|p| mail_dirs.contains(p)) =>
                {
                    ComponentState::Running {
                        verified_at_ms: since,
                    }
                }
                _ => ComponentState::Degraded {
                    reason: "mail folders are not watched".into(),
                },
            }
        };
        let privacy = if !fda {
            need_fda()
        } else {
            match &*lock(&self.privacy) {
                Some((at, report)) if report.problem.is_none() => ComponentState::Running {
                    verified_at_ms: *at,
                },
                Some((_, report)) => ComponentState::Degraded {
                    reason: report.problem.clone().unwrap_or_default(),
                },
                None => ComponentState::Degraded {
                    reason: "the permission overview is starting".into(),
                },
            }
        };
        (email, privacy)
    }

    pub fn remember_selection(&self, id: String, paths: Vec<PathBuf>) {
        let mut selections = lock(&self.selections);
        selections.push_back((id, paths));
        while selections.len() > MAX_SELECTIONS {
            selections.pop_front();
        }
    }

    pub fn selection(&self, id: &str) -> Option<Vec<PathBuf>> {
        lock(&self.selections)
            .iter()
            .find(|(selection_id, _)| selection_id == id)
            .map(|(_, paths)| paths.clone())
    }

    pub fn set_current_scan(&self, handle: ScanHandle) {
        *lock(&self.current_scan) = Some(handle);
    }

    pub fn current_scan(&self) -> Option<ScanHandle> {
        lock(&self.current_scan).clone()
    }

    pub fn last_summary_slot(&self) -> Arc<Mutex<Option<ScanSummary>>> {
        self.last_summary.clone()
    }

    /// Poslední kontrola: z tohoto spuštění, jinak uložená z minulého.
    pub fn last_summary(&self) -> Option<ScanSummary> {
        lock(&self.last_summary)
            .clone()
            .or_else(|| self.restored_summary.clone())
    }

    /// Cesty nálezů z minulého spuštění (bez nálezu z tohoto spuštění), které
    /// se před vyčištěním musí znovu zkontrolovat.
    pub fn restored_finding_paths(&self, paths: &[String]) -> Vec<PathBuf> {
        let mut found: Vec<String> = lock(&self.stories).unresolved_paths(paths);
        if lock(&self.last_summary).is_none() {
            found.extend(
                self.restored_summary
                    .iter()
                    .flat_map(|summary| summary.findings.iter())
                    .filter(|finding| paths.contains(&finding.path))
                    .map(|finding| finding.path.clone()),
            );
        }
        found.sort();
        found.dedup();
        found.into_iter().map(PathBuf::from).collect()
    }

    pub fn set_pending_update(&self, update: Option<tauri_plugin_updater::Update>) {
        *lock(&self.pending_update) = update;
    }

    pub fn take_pending_update(&self) -> Option<tauri_plugin_updater::Update> {
        lock(&self.pending_update).take()
    }

    pub fn add_detection(&self, detection: Detection) {
        let mut list = lock(&self.detections);
        list.push_front(detection);
        list.truncate(MAX_DETECTIONS);
    }

    /// Nálezy, které backend sám vytvořil (poslední kontrola, hlídání).
    /// Rozhraní smí čistit jen tyto, ne libovolné cesty.
    pub fn known_findings(&self, paths: &[String]) -> Vec<Finding> {
        let mut found: Vec<Finding> = Vec::new();
        let mut push = |finding: &Finding| {
            if paths.contains(&finding.path) && !found.iter().any(|f| f.path == finding.path) {
                found.push(finding.clone());
            }
        };
        // Jen nálezy z tohoto spuštění; uložené z minulého se ověřují znovu.
        if let Some(summary) = lock(&self.last_summary).as_ref() {
            summary.findings.iter().for_each(&mut push);
        }
        for detection in lock(&self.detections).iter() {
            if matches!(
                detection.action,
                DetectionAction::Detected | DetectionAction::Failed { .. }
            ) {
                push(&detection.finding);
            }
        }
        found
    }

    pub fn runtime_info(&self) -> RuntimeInfo {
        // Kontrola přístupu (otevření souboru) a nastavení dřív než zámek
        // ochrany (vždy stejné pořadí zámků).
        let full_disk_access = antishield_core::privacy::full_disk_access();
        let chosen = self.settings().watch_paths();
        let runtime = lock(&self.protection);
        let watched: &[PathBuf] = runtime.watcher.as_ref().map_or(&[], |w| w.watched());
        RuntimeInfo {
            // Složky vybrané uživatelem; složky položek po přihlášení zvlášť.
            watched: watched
                .iter()
                .filter(|p| chosen.contains(p))
                .map(|p| p.display().to_string())
                .collect(),
            startup_watched: watched.iter().any(|p| !chosen.contains(p)),
            programs_checked: self.programs_checked.load(Ordering::Relaxed),
            programs_since_ms: *lock(&self.programs_since_ms),
            watching_since_ms: runtime.started_at_ms,
            watch_error: runtime.error.clone(),
            access_denied: runtime.access_denied.clone(),
            detections: lock(&self.detections).iter().cloned().collect(),
            rules: lock(&self.rules_status).clone(),
            last_scheduled_run_ms: *lock(&self.last_scheduled_run_ms),
            background_problem: lock(&self.background_problem).clone(),
            last_catch_up: lock(&self.last_catch_up).clone(),
            full_disk_access,
            activity: lock(&self.activity).clone(),
        }
    }
}

/// Uloží souhrn kontroly (přes dočasný soubor, aby se nezapsal napůl).
pub fn save_summary(data_dir: &Path, summary: &ScanSummary) {
    let Ok(bytes) = serde_json::to_vec(summary) else {
        return;
    };
    let path = data_dir.join(LAST_SUMMARY_FILE);
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, bytes).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn load_summary(path: &Path) -> Option<ScanSummary> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_SUMMARY_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_SUMMARY_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Self-test bez okna. Data jdou do dočasné složky, uživatelská data se nemění.
pub fn headless_self_test() -> i32 {
    let dir = std::env::temp_dir().join(format!("antishield-selftest-{}", std::process::id()));
    let code = match Engine::new(EngineConfig::new(&dir)) {
        Ok(engine) => {
            let report = engine.self_test();
            match serde_json::to_string_pretty(&report) {
                Ok(text) => println!("{text}"),
                Err(err) => eprintln!("{err}"),
            }
            if report.passed { 0 } else { 1 }
        }
        Err(err) => {
            eprintln!("engine: {err}");
            2
        }
    };
    // Mažeme jen vlastní dočasnou složku self-testu.
    let _ = std::fs::remove_dir_all(&dir);
    code
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn realtime(state: &AppState) -> ComponentState {
        state
            .protection()
            .components
            .into_iter()
            .find(|c| c.kind == ComponentKind::RealTimeProtection)
            .unwrap()
            .state
    }

    #[test]
    fn denied_folder_access_is_reported_until_access_returns() {
        let dir = std::env::temp_dir().join(format!("antishield-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = AppState::new(dir.clone());
        lock(&state.protection).access_denied = Some(dir.join("missing"));
        assert!(matches!(
            realtime(&state),
            ComponentState::Degraded { reason } if reason == "no access to files in a watched folder"
        ));
        // Jakmile jde složka číst, stav se sám opraví.
        lock(&state.protection).access_denied = Some(dir.clone());
        assert!(!matches!(
            realtime(&state),
            ComponentState::Degraded { reason } if reason == "no access to files in a watched folder"
        ));
        assert!(lock(&state.protection).access_denied.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn summary_with_finding(path: &str) -> ScanSummary {
        serde_json::from_value(serde_json::json!({
            "scanId": "s1", "outcome": { "type": "completed" }, "roots": ["/tmp"],
            "startedAtMs": 1, "finishedAtMs": 2, "filesScanned": 10, "bytesScanned": 100,
            "archivesNotInspected": 0, "yaraIncomplete": 0, "skippedTotal": 0,
            "skippedByReason": [], "skippedSample": [], "engineVersion": "0.4.1",
            "rulePack": { "packId": "p", "version": "1", "sequence": 1, "ruleCount": 1,
                "signingKeyId": "k", "testPack": false, "createdAtUnix": 0, "expiresAtUnix": 0,
                "expired": false, "yaraRuleCount": 0, "sources": [] },
            "findings": [{ "path": path, "sha256": "00", "ruleId": "r", "ruleName": "r",
                "ruleVersion": 1, "ruleDescription": "", "severity": "high", "testOnly": false,
                "evidence": [], "identity": { "device": 0, "inode": 0, "size": 0, "modifiedSec": 0,
                    "modifiedNsec": 0, "changedSec": 0, "changedNsec": 0 },
                "changedDuringRead": false, "archiveEntry": null, "origin": null }]
        }))
        .unwrap()
    }

    #[test]
    fn the_last_scan_survives_a_restart_but_is_rechecked_before_cleaning() {
        let tmp = tempfile::tempdir().unwrap();
        save_summary(tmp.path(), &summary_with_finding("/x/evil.app"));

        let state = AppState::new(tmp.path().to_path_buf());
        assert_eq!(state.last_summary().map(|s| s.files_scanned), Some(10));
        let paths = vec!["/x/evil.app".to_string()];
        // Uložený nález sám nic neizoluje, jen se znovu zkontroluje.
        assert!(state.known_findings(&paths).is_empty());
        assert_eq!(
            state.restored_finding_paths(&paths),
            vec![PathBuf::from("/x/evil.app")]
        );

        // Nová kontrola v tomto spuštění má přednost.
        *lock(&state.last_summary) = Some(summary_with_finding("/x/evil.app"));
        assert_eq!(state.known_findings(&paths).len(), 1);
        assert!(state.restored_finding_paths(&paths).is_empty());
    }

    #[test]
    fn a_damaged_summary_file_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(LAST_SUMMARY_FILE), b"{ not json").unwrap();
        assert!(
            AppState::new(tmp.path().to_path_buf())
                .last_summary()
                .is_none()
        );
    }
}
