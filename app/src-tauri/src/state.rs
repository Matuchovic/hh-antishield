//! Stav aplikace sdílený mezi příkazy.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use antishield_core::error::ErrorDto;
use antishield_core::status::{
    ComponentKind, ComponentState, ComponentStatus, ProtectionSummary, summarize_protection,
};
use antishield_core::{Engine, EngineConfig, EngineError, ScanHandle, ScanSummary};

/// Kolik posledních výběrů z dialogu si pamatujeme.
const MAX_SELECTIONS: usize = 20;

pub struct AppState {
    engine: Result<Engine, ErrorDto>,
    selections: Mutex<VecDeque<(String, Vec<PathBuf>)>>,
    current_scan: Mutex<Option<ScanHandle>>,
    last_summary: Arc<Mutex<Option<ScanSummary>>>,
}

impl AppState {
    /// Chyba při startu enginu aplikaci neshodí: rozhraní ji pravdivě ukáže.
    pub fn new(engine: Result<Engine, EngineError>) -> Self {
        let engine = engine.map_err(|err| ErrorDto::from(&err));
        if let Ok(engine) = &engine {
            engine.self_test();
        }
        Self {
            engine,
            selections: Mutex::new(VecDeque::new()),
            current_scan: Mutex::new(None),
            last_summary: Arc::new(Mutex::new(None)),
        }
    }

    pub fn engine(&self) -> Result<&Engine, ErrorDto> {
        self.engine.as_ref().map_err(Clone::clone)
    }

    pub fn protection(&self) -> ProtectionSummary {
        match &self.engine {
            Ok(engine) => engine.protection_summary(),
            Err(err) => {
                let components: Vec<ComponentStatus> = ComponentKind::ALL
                    .iter()
                    .map(|kind| ComponentStatus {
                        kind: *kind,
                        state: match kind {
                            ComponentKind::DetectionEngine
                            | ComponentKind::RulePack
                            | ComponentKind::OnDemandScan => ComponentState::Failed {
                                reason: err.message.clone(),
                            },
                            ComponentKind::AuditLog => ComponentState::Degraded {
                                reason: err.message.clone(),
                            },
                            _ => ComponentState::NotImplemented,
                        },
                    })
                    .collect();
                ProtectionSummary {
                    level: summarize_protection(&components),
                    components,
                }
            }
        }
    }

    pub fn remember_selection(&self, id: String, paths: Vec<PathBuf>) {
        if let Ok(mut selections) = self.selections.lock() {
            selections.push_back((id, paths));
            while selections.len() > MAX_SELECTIONS {
                selections.pop_front();
            }
        }
    }

    pub fn selection(&self, id: &str) -> Option<Vec<PathBuf>> {
        self.selections.lock().ok().and_then(|selections| {
            selections
                .iter()
                .find(|(selection_id, _)| selection_id == id)
                .map(|(_, paths)| paths.clone())
        })
    }

    pub fn set_current_scan(&self, handle: ScanHandle) {
        if let Ok(mut current) = self.current_scan.lock() {
            *current = Some(handle);
        }
    }

    pub fn current_scan(&self) -> Option<ScanHandle> {
        self.current_scan
            .lock()
            .ok()
            .and_then(|current| current.clone())
    }

    pub fn last_summary_slot(&self) -> Arc<Mutex<Option<ScanSummary>>> {
        self.last_summary.clone()
    }

    pub fn last_summary(&self) -> Option<ScanSummary> {
        self.last_summary.lock().ok().and_then(|last| last.clone())
    }
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
