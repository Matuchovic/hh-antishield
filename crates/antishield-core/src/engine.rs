//! Engine: spojuje pravidla, skener, audit a stav pro aplikaci a CLI.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::Serialize;

use serde_json::json;

use crate::audit::AuditLog;
use crate::error::EngineError;
use crate::inspect::{FileInspector, InspectResult};
use crate::quarantine::{Quarantine, QuarantineItem};
use crate::rules::{self, MAX_PACK_SIZE, MAX_SIGNATURE_FILE_SIZE, RulePack, TrustedKey};
use crate::scan::{self, ScanContext, ScanHandle, ScanObserver};
use crate::status::{
    ComponentKind, ComponentState, ComponentStatus, ProtectionSummary, summarize_protection,
};
use crate::types::{
    AuditEvent, EngineInfo, Finding, FindingOrigin, RulePackInfo, ScanLimits, ScanRequest,
    SelfTestReport,
};
use crate::{ENGINE_VERSION, now_ms, platform_label, selftest};

/// Testovací sada pravidel zabudovaná do enginu (podepsaná, ověřuje se při načtení).
const EMBEDDED_PACK: &[u8] = include_bytes!("../../../rules/test-pack.json");
const EMBEDDED_SIGNATURE: &[u8] = include_bytes!("../../../rules/test-pack.json.sig");

/// Odkud načíst sadu pravidel.
#[derive(Debug, Clone)]
pub enum RuleSource {
    /// Nainstalovaná aktualizace z `data_dir/rules`, jinak zabudovaná sada.
    InstalledOrEmbedded,
    /// Testovací sada zabudovaná do binárky.
    Embedded,
    Files {
        pack: PathBuf,
        signature: PathBuf,
    },
    Bytes {
        pack: Vec<u8>,
        signature: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Adresář pro data enginu (auditní log).
    pub data_dir: PathBuf,
    pub rules: RuleSource,
    /// Důvěryhodné klíče; `None` = klíče zabudované v enginu.
    pub trusted_keys: Option<Vec<TrustedKey>>,
}

impl EngineConfig {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            rules: RuleSource::InstalledOrEmbedded,
            trusted_keys: None,
        }
    }
}

/// Aktivní sada pravidel; při aktualizaci se vymění celá najednou.
#[derive(Debug, Clone)]
struct ActiveRules {
    pack: Arc<RulePack>,
    signature: Vec<u8>,
    loaded_at_ms: u64,
}

/// Výsledek instalace aktualizace pravidel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RuleUpdateOutcome {
    Installed { rule_pack: RulePackInfo },
    UpToDate { rule_pack: RulePackInfo },
}

/// Co se při vyčištění nálezu povedlo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemediationReport {
    pub path: String,
    pub quarantined: Option<QuarantineItem>,
    pub process_terminated: bool,
    pub startup_disabled: bool,
    /// Kroky, které se nepovedly (srozumitelný kód chyby a text).
    pub problems: Vec<String>,
}

#[derive(Debug)]
pub struct Engine {
    rules: RwLock<ActiveRules>,
    keys: Vec<TrustedKey>,
    rules_dir: PathBuf,
    quarantine: Quarantine,
    audit: Arc<Mutex<AuditLog>>,
    audit_healthy: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    loaded_at_ms: u64,
    last_self_test: Mutex<Option<SelfTestReport>>,
}

/// Záznam pro karanténu doprovodného souboru (např. plist položky po spuštění).
fn snapshot_finding(path: &Path, label: &str, cause: &Finding) -> Result<Finding, EngineError> {
    use sha2::{Digest, Sha256};
    let (mut file, meta) = match crate::platform::open_regular(path) {
        Ok(opened) => opened,
        Err(crate::platform::OpenError::NotRegular) => {
            return Err(EngineError::FileChanged("not a regular file".into()));
        }
        Err(crate::platform::OpenError::Io(err)) => return Err(err.into()),
    };
    const MAX_COMPANION: u64 = 16 * 1024 * 1024;
    let mut data = Vec::new();
    (&mut file).take(MAX_COMPANION + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_COMPANION {
        return Err(EngineError::InvalidRequest(
            "startup item file is too large".into(),
        ));
    }
    Ok(Finding {
        path: path.display().to_string(),
        sha256: hex::encode(Sha256::digest(&data)),
        rule_id: "STARTUP-ITEM".into(),
        rule_name: if label.is_empty() {
            "Položka po spuštění".into()
        } else {
            label.chars().take(200).collect()
        },
        rule_version: 1,
        rule_description: format!("Spouštěla soubor zachycený pravidlem {}.", cause.rule_id),
        severity: cause.severity,
        test_only: cause.test_only,
        evidence: Vec::new(),
        identity: crate::platform::identity(&meta),
        changed_during_read: false,
        archive_entry: None,
        origin: None,
    })
}

fn now_unix() -> i64 {
    i64::try_from(now_ms() / 1000).unwrap_or(i64::MAX)
}

/// Název adresáře nainstalované sady: `seq-<číslo>`.
fn installed_dir_name(sequence: u64) -> String {
    format!("seq-{sequence}")
}

fn valid_installed_dir(name: &str) -> bool {
    name.strip_prefix("seq-")
        .is_some_and(|n| !n.is_empty() && n.len() <= 20 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Zapíše soubor atomicky: dočasný soubor, fsync, přejmenování.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension("tmp");
    let _ = fs::remove_file(&temp);
    let mut options = OpenOptions::new();
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
    fs::rename(&temp, path)
}

/// Sada pravidel a její podpis jako bajty.
type PackBytes = (Vec<u8>, Vec<u8>);

/// Načte nainstalovanou sadu, pokud existuje.
fn read_installed(rules_dir: &Path) -> Option<Result<PackBytes, EngineError>> {
    let current = fs::read_to_string(rules_dir.join("current")).ok()?;
    let name = current.trim();
    if !valid_installed_dir(name) {
        return Some(Err(EngineError::RulePackMalformed(
            "installed rule pack pointer is invalid".into(),
        )));
    }
    let dir = rules_dir.join(name);
    Some((|| {
        Ok((
            read_bounded(&dir.join("pack.json"), MAX_PACK_SIZE)?,
            read_bounded(&dir.join("pack.json.sig"), MAX_SIGNATURE_FILE_SIZE)?,
        ))
    })())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, EngineError> {
    let mut data = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(EngineError::RulePackTooLarge {
            size: data.len(),
            limit,
        });
    }
    Ok(data)
}

impl Engine {
    /// Otevře auditní log, ověří podpis a načte pravidla. Neprovede self-test;
    /// ten spouští volající přes [`Engine::self_test`].
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        let mut audit = AuditLog::open(&config.data_dir.join("audit"))?;
        audit.append(
            "engine_started",
            json!({ "engineVersion": ENGINE_VERSION, "platform": platform_label() }),
            true,
        )?;
        if let Some(issue) = audit.integrity_issue().map(str::to_string) {
            // Poškozený soubor je uzavřený, zápis pokračuje v novém (viz `AuditLog::open`).
            audit.append(
                "audit_integrity_issue",
                json!({ "detail": issue, "sealed": true }),
                true,
            )?;
        }

        let keys = config
            .trusted_keys
            .unwrap_or_else(rules::builtin_trusted_keys);
        let rules_dir = config.data_dir.join("rules");
        let now_unix = now_unix();

        // Nainstalovaná aktualizace má přednost; když neprojde, použije se zabudovaná sada.
        let mut installed = None;
        if matches!(config.rules, RuleSource::InstalledOrEmbedded)
            && let Some(read) = read_installed(&rules_dir)
        {
            let loaded = read.and_then(|(pack, signature)| {
                let rules = RulePack::load(&pack, &signature, &keys, now_unix)?;
                if rules.info().test_pack {
                    return Err(EngineError::InvalidRequest(
                        "an installed rule pack must not be a test pack".into(),
                    ));
                }
                Ok((rules, signature))
            });
            match loaded {
                Ok(found) => installed = Some(found),
                Err(err) => {
                    let _ = audit.append(
                        "rule_pack_rejected",
                        json!({ "source": "installed", "code": err.code(), "message": err.to_string() }),
                        true,
                    );
                }
            }
        }

        let (pack, signature) = match config.rules {
            RuleSource::InstalledOrEmbedded | RuleSource::Embedded => {
                (EMBEDDED_PACK.to_vec(), EMBEDDED_SIGNATURE.to_vec())
            }
            RuleSource::Files { pack, signature } => (
                read_bounded(&pack, MAX_PACK_SIZE)?,
                read_bounded(&signature, MAX_SIGNATURE_FILE_SIZE)?,
            ),
            RuleSource::Bytes { pack, signature } => (pack, signature),
        };
        let (rules, signature) = match installed {
            Some(found) => found,
            None => match RulePack::load(&pack, &signature, &keys, now_unix) {
                Ok(rules) => (rules, signature),
                Err(err) => {
                    let _ = audit.append(
                        "rule_pack_rejected",
                        json!({ "code": err.code(), "message": err.to_string() }),
                        true,
                    );
                    return Err(err);
                }
            },
        };
        audit.append("rule_pack_loaded", json!(rules.info()), true)?;
        let quarantine = Quarantine::open(&config.data_dir.join("quarantine"))?;

        Ok(Self {
            rules: RwLock::new(ActiveRules {
                pack: Arc::new(rules),
                signature,
                loaded_at_ms: now_ms(),
            }),
            keys,
            rules_dir,
            quarantine,
            audit: Arc::new(Mutex::new(audit)),
            audit_healthy: Arc::new(AtomicBool::new(true)),
            running: Arc::new(AtomicBool::new(false)),
            loaded_at_ms: now_ms(),
            last_self_test: Mutex::new(None),
        })
    }

    pub fn info(&self) -> EngineInfo {
        EngineInfo {
            engine_version: ENGINE_VERSION.to_string(),
            platform: platform_label(),
            rule_pack: self.rules().info().clone(),
        }
    }

    fn active(&self) -> ActiveRules {
        match self.rules.read() {
            Ok(active) => active.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Aktuální sada pravidel. Běžící kontrola si drží tu, se kterou začala.
    pub fn rules(&self) -> Arc<RulePack> {
        self.active().pack
    }

    /// Podpis aktivní sady; aplikace podle něj pozná, že aktualizace není nová.
    pub fn rules_signature(&self) -> Vec<u8> {
        self.active().signature
    }

    /// Ověří a nainstaluje aktualizaci pravidel. Přijme jen produkční sadu
    /// s platným podpisem, novější než aktivní, která projde self-testem.
    /// Uloží ji atomicky a vymění za běhu; probíhající kontrolu neovlivní.
    pub fn install_rule_pack(
        &self,
        pack: &[u8],
        signature: &[u8],
    ) -> Result<RuleUpdateOutcome, EngineError> {
        let result = self.install_rule_pack_inner(pack, signature);
        match &result {
            Ok(RuleUpdateOutcome::Installed { rule_pack }) => {
                self.audit("rule_pack_installed", json!(rule_pack), true);
            }
            Ok(RuleUpdateOutcome::UpToDate { .. }) => {}
            Err(err) => self.audit(
                "rule_pack_rejected",
                json!({ "source": "update", "code": err.code(), "message": err.to_string() }),
                true,
            ),
        }
        result
    }

    fn install_rule_pack_inner(
        &self,
        pack: &[u8],
        signature: &[u8],
    ) -> Result<RuleUpdateOutcome, EngineError> {
        let loaded = RulePack::load(pack, signature, &self.keys, now_unix())?;
        let info = loaded.info().clone();
        if info.test_pack {
            return Err(EngineError::InvalidRequest(
                "a test rule pack cannot be installed as an update".into(),
            ));
        }
        let current = self.rules();
        if !current.info().test_pack {
            let installed = current.info().sequence;
            if info.sequence < installed {
                return Err(EngineError::RulePackRollback {
                    current: installed,
                    offered: info.sequence,
                });
            }
            if info.sequence == installed {
                return Ok(RuleUpdateOutcome::UpToDate {
                    rule_pack: current.info().clone(),
                });
            }
        }
        let report = selftest::run(&loaded);
        if !report.passed {
            let failed: Vec<String> = report
                .checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.clone())
                .collect();
            return Err(EngineError::RulePackSelfTest(failed.join(", ")));
        }

        let name = installed_dir_name(info.sequence);
        let dir = self.rules_dir.join(&name);
        fs::create_dir_all(&dir)?;
        write_atomic(&dir.join("pack.json"), pack)?;
        write_atomic(&dir.join("pack.json.sig"), signature)?;
        write_atomic(&self.rules_dir.join("current"), name.as_bytes())?;
        self.prune_installed(&name);

        let replacement = ActiveRules {
            pack: Arc::new(loaded),
            signature: signature.to_vec(),
            loaded_at_ms: now_ms(),
        };
        match self.rules.write() {
            Ok(mut active) => *active = replacement,
            Err(poisoned) => *poisoned.into_inner() = replacement,
        }
        if let Ok(mut last) = self.last_self_test.lock() {
            *last = Some(report);
        }
        Ok(RuleUpdateOutcome::Installed { rule_pack: info })
    }

    /// Ponechá aktivní a jednu předchozí sadu, starší smaže.
    fn prune_installed(&self, keep: &str) {
        let Ok(entries) = fs::read_dir(&self.rules_dir) else {
            return;
        };
        let mut others: Vec<(u64, PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == keep || !valid_installed_dir(&name) {
                    return None;
                }
                let sequence = name.strip_prefix("seq-")?.parse().ok()?;
                Some((sequence, entry.path()))
            })
            .collect();
        others.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        for (_, path) in others.into_iter().skip(1) {
            let _ = fs::remove_dir_all(path);
        }
    }

    /// Přesune soubor z nálezu do karantény (jen pokud se od kontroly nezměnil).
    pub fn quarantine_finding(&self, finding: &Finding) -> Result<QuarantineItem, EngineError> {
        let result = self.quarantine.add(finding);
        match &result {
            Ok(item) => self.audit(
                "quarantined",
                json!({ "id": item.id, "path": item.original_path, "sha256": item.sha256, "ruleId": item.rule_id }),
                true,
            ),
            Err(err) => self.audit(
                "quarantine_failed",
                json!({ "path": finding.path, "code": err.code(), "message": err.to_string() }),
                true,
            ),
        }
        result
    }

    /// Zkontroluje jednotlivé soubory (hlídání složek). Nálezy zapíše do auditu.
    pub fn inspect_paths(&self, paths: &[PathBuf]) -> Vec<(PathBuf, InspectResult)> {
        let rules = self.rules();
        let mut inspector = FileInspector::new(&rules, ScanLimits::default());
        let mut results = Vec::with_capacity(paths.len());
        for path in paths {
            let result = inspector.inspect(&resolve_parent(path));
            if let InspectResult::Scanned { findings, .. } = &result {
                for finding in findings {
                    self.audit(
                        "finding",
                        json!({
                            "source": "watch",
                            "path": finding.path,
                            "sha256": finding.sha256,
                            "ruleId": finding.rule_id,
                            "testOnly": finding.test_only,
                            "archiveEntry": finding.archive_entry,
                        }),
                        true,
                    );
                }
            }
            results.push((path.clone(), result));
        }
        results
    }

    /// Vyčistí nález: ukončí proces, přesune soubor do karantény a vypne
    /// položku po spuštění, která ho spouštěla. Každý krok se zapíše do auditu.
    pub fn remediate(&self, finding: &Finding) -> RemediationReport {
        let mut report = RemediationReport {
            path: finding.path.clone(),
            ..RemediationReport::default()
        };
        if let Some(FindingOrigin::Process { pid, .. }) = &finding.origin {
            match crate::system::terminate_process(*pid, Path::new(&finding.path)) {
                Ok(terminated) => report.process_terminated = terminated,
                Err(err) => report.problems.push(format!("{}: {err}", err.code())),
            }
        }
        match self.quarantine_finding(finding) {
            Ok(item) => report.quarantined = Some(item),
            Err(err) => report.problems.push(format!("{}: {err}", err.code())),
        }
        if let Some(FindingOrigin::StartupItem { location, label }) = &finding.origin
            && report.quarantined.is_some()
        {
            match self.disable_startup_item(location, label, finding) {
                Ok(()) => report.startup_disabled = true,
                Err(err) => report.problems.push(format!("{}: {err}", err.code())),
            }
        }
        self.audit("remediated", json!(report), true);
        report
    }

    /// Vypne položku po spuštění: soubor (plist, zástupce) přesune do karantény,
    /// záznam v registru (Windows, jen HKCU) smaže.
    fn disable_startup_item(
        &self,
        location: &str,
        label: &str,
        cause: &Finding,
    ) -> Result<(), EngineError> {
        let path = Path::new(location);
        if path.is_absolute() {
            if path == Path::new(&cause.path) {
                return Ok(()); // Sama položka už je v karanténě.
            }
            if !crate::system::is_startup_location(path) {
                return Err(EngineError::InvalidRequest(
                    "not a startup item location".into(),
                ));
            }
            let companion = snapshot_finding(path, label, cause)?;
            self.quarantine_finding(&companion).map(|_| ())
        } else {
            #[cfg(windows)]
            {
                crate::system::remove_registry_startup(location)
            }
            #[cfg(not(windows))]
            {
                Err(EngineError::InvalidRequest(
                    "unsupported startup item location".into(),
                ))
            }
        }
    }

    pub fn quarantine_items(&self) -> Result<Vec<QuarantineItem>, EngineError> {
        self.quarantine.list()
    }

    pub fn restore_quarantined(&self, id: &str) -> Result<QuarantineItem, EngineError> {
        let item = self.quarantine.restore(id)?;
        self.audit(
            "quarantine_restored",
            json!({ "id": item.id, "path": item.original_path }),
            true,
        );
        Ok(item)
    }

    pub fn delete_quarantined(&self, id: &str) -> Result<QuarantineItem, EngineError> {
        let item = self.quarantine.delete(id)?;
        self.audit(
            "quarantine_deleted",
            json!({ "id": item.id, "path": item.original_path }),
            true,
        );
        Ok(item)
    }

    /// Zapíše do auditu zásah, který provedla aplikace (čištění, zrychlení).
    pub fn record_action(&self, kind: &str, data: serde_json::Value) {
        self.audit(kind, data, true);
    }

    fn audit(&self, kind: &str, data: serde_json::Value, sync: bool) {
        let ok = match self.audit.lock() {
            Ok(mut log) => log.append(kind, data, sync).is_ok(),
            Err(_) => false,
        };
        if !ok {
            self.audit_healthy.store(false, Ordering::SeqCst);
        }
    }

    /// Spustí self-test, uloží výsledek pro stav komponent a zapíše ho do auditu.
    pub fn self_test(&self) -> SelfTestReport {
        let report = selftest::run(&self.rules());
        self.audit("self_test", json!(report), true);
        if let Ok(mut last) = self.last_self_test.lock() {
            *last = Some(report.clone());
        }
        report
    }

    /// Spustí kontrolu a hned vrátí ovladač. Najednou běží nejvýš jedna kontrola.
    pub fn start_scan(
        &self,
        request: ScanRequest,
        observer: Arc<dyn ScanObserver>,
    ) -> Result<ScanHandle, EngineError> {
        scan::spawn_scan(
            ScanContext {
                rules: self.rules(),
                audit: self.audit.clone(),
                audit_healthy: self.audit_healthy.clone(),
                running: self.running.clone(),
            },
            request,
            observer,
        )
    }

    pub fn is_scan_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn recent_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, EngineError> {
        let log = self
            .audit
            .lock()
            .map_err(|_| EngineError::Audit("audit log lock poisoned".into()))?;
        log.recent(limit.min(1_000))
    }

    pub fn audit_dir(&self) -> Option<PathBuf> {
        self.audit.lock().ok().map(|log| log.dir().to_path_buf())
    }

    /// Stav jednotlivých komponent, jak je engine sám zná.
    pub fn component_statuses(&self) -> Vec<ComponentStatus> {
        let last_test = self.last_self_test.lock().ok().and_then(|g| g.clone());
        let engine_state = match last_test {
            Some(report) if report.passed => ComponentState::Running {
                verified_at_ms: report.ran_at_ms,
            },
            Some(report) => ComponentState::Failed {
                reason: report
                    .checks
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| c.detail.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
            },
            None => ComponentState::Degraded {
                reason: "self-test has not run yet".into(),
            },
        };
        let active = self.active();
        let info = active.pack.info();
        let rules_state = if info.expired {
            ComponentState::Degraded {
                reason: "rule pack has expired".into(),
            }
        } else {
            ComponentState::Running {
                verified_at_ms: active.loaded_at_ms,
            }
        };
        let quarantine_state = if self.quarantine.is_healthy() {
            ComponentState::Running {
                verified_at_ms: now_ms(),
            }
        } else {
            ComponentState::Failed {
                reason: "quarantine storage is not writable".into(),
            }
        };
        // Problém s integritou z otevření je zapsaný v logu (`audit_integrity_issue`)
        // a poškozený soubor uzavřený; zápis od té doby pokračuje v pořádku.
        let audit_state = if !self.audit_healthy.load(Ordering::SeqCst) {
            ComponentState::Failed {
                reason: "audit log cannot be written".into(),
            }
        } else {
            ComponentState::Running {
                verified_at_ms: self.loaded_at_ms,
            }
        };

        ComponentKind::ALL
            .iter()
            .map(|kind| ComponentStatus {
                kind: *kind,
                state: match kind {
                    ComponentKind::DetectionEngine => engine_state.clone(),
                    ComponentKind::RulePack => rules_state.clone(),
                    ComponentKind::AuditLog => audit_state.clone(),
                    ComponentKind::Quarantine => quarantine_state.clone(),
                    ComponentKind::OnDemandScan => ComponentState::Running {
                        verified_at_ms: self.loaded_at_ms,
                    },
                    _ => ComponentState::NotImplemented,
                },
            })
            .collect()
    }

    pub fn protection_summary(&self) -> ProtectionSummary {
        let components = self.component_statuses();
        ProtectionSummary {
            level: summarize_protection(&components),
            components,
        }
    }
}

/// Cesta s vyřešenými symlinky v nadřazených složkách, stejně jako u kořene
/// kontroly. Na macOS se soubor otevírá s `O_NOFOLLOW_ANY`, takže bez toho by
/// cesta přes `/var` → `/private/var` skončila jako „symlink“. Poslední složka
/// se neřeší: symlink místo souboru se dál odmítne.
#[cfg(unix)]
fn resolve_parent(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            std::fs::canonicalize(parent).map_or_else(|_| path.to_path_buf(), |dir| dir.join(name))
        }
        _ => path.to_path_buf(),
    }
}

/// Na Windows se kontroluje jen samotný soubor (reparse point se odmítne);
/// kanonická cesta by navíc dostala předponu `\\?\`.
#[cfg(not(unix))]
fn resolve_parent(path: &Path) -> PathBuf {
    path.to_path_buf()
}
