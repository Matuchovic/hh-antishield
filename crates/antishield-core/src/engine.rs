//! Engine: spojuje pravidla, skener, audit a stav pro aplikaci a CLI.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::audit::AuditLog;
use crate::error::EngineError;
use crate::rules::{self, MAX_PACK_SIZE, MAX_SIGNATURE_FILE_SIZE, RulePack, TrustedKey};
use crate::scan::{self, ScanContext, ScanHandle, ScanObserver};
use crate::status::{
    ComponentKind, ComponentState, ComponentStatus, ProtectionSummary, summarize_protection,
};
use crate::types::{AuditEvent, EngineInfo, ScanRequest, SelfTestReport};
use crate::{ENGINE_VERSION, now_ms, platform_label, selftest};

/// Testovací sada pravidel zabudovaná do enginu (podepsaná, ověřuje se při načtení).
const EMBEDDED_PACK: &[u8] = include_bytes!("../../../rules/test-pack.json");
const EMBEDDED_SIGNATURE: &[u8] = include_bytes!("../../../rules/test-pack.json.sig");

/// Odkud načíst sadu pravidel.
#[derive(Debug, Clone)]
pub enum RuleSource {
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
            rules: RuleSource::Embedded,
            trusted_keys: None,
        }
    }
}

#[derive(Debug)]
pub struct Engine {
    rules: Arc<RulePack>,
    audit: Arc<Mutex<AuditLog>>,
    audit_healthy: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    loaded_at_ms: u64,
    last_self_test: Mutex<Option<SelfTestReport>>,
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
            audit.append("audit_integrity_issue", json!({ "detail": issue }), true)?;
        }

        let (pack, signature) = match config.rules {
            RuleSource::Embedded => (EMBEDDED_PACK.to_vec(), EMBEDDED_SIGNATURE.to_vec()),
            RuleSource::Files { pack, signature } => (
                read_bounded(&pack, MAX_PACK_SIZE)?,
                read_bounded(&signature, MAX_SIGNATURE_FILE_SIZE)?,
            ),
            RuleSource::Bytes { pack, signature } => (pack, signature),
        };
        let keys = config
            .trusted_keys
            .unwrap_or_else(rules::builtin_trusted_keys);
        let now_unix = i64::try_from(now_ms() / 1000).unwrap_or(i64::MAX);
        let rules = match RulePack::load(&pack, &signature, &keys, now_unix) {
            Ok(rules) => rules,
            Err(err) => {
                let _ = audit.append(
                    "rule_pack_rejected",
                    json!({ "code": err.code(), "message": err.to_string() }),
                    true,
                );
                return Err(err);
            }
        };
        audit.append("rule_pack_loaded", json!(rules.info()), true)?;

        Ok(Self {
            rules: Arc::new(rules),
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
            rule_pack: self.rules.info().clone(),
        }
    }

    pub fn rules(&self) -> &RulePack {
        &self.rules
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
        let report = selftest::run(&self.rules);
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
                rules: self.rules.clone(),
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
        let info = self.rules.info();
        let rules_state = if info.expired {
            ComponentState::Degraded {
                reason: "rule pack has expired".into(),
            }
        } else {
            ComponentState::Running {
                verified_at_ms: self.loaded_at_ms,
            }
        };
        let integrity = self
            .audit
            .lock()
            .ok()
            .and_then(|log| log.integrity_issue().map(str::to_string));
        let audit_state = if !self.audit_healthy.load(Ordering::SeqCst) {
            ComponentState::Failed {
                reason: "audit log cannot be written".into(),
            }
        } else if let Some(issue) = integrity {
            ComponentState::Degraded { reason: issue }
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
