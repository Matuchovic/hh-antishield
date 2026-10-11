//! H&H AntiShield – přenositelné jádro detekce.
//!
//! Verze 0.1 je **ruční skener**: čte soubory vybrané uživatelem, počítá SHA-256
//! a porovnává je s podepsanou sadou testovacích pravidel. Soubory nikdy nemění.
//! Nejde o úplnou antivirovou ochranu; přesný rozsah popisuje `docs/feature-status.md`.
//!
//! Moduly:
//! - [`rules`]: načtení a ověření podepsané sady pravidel,
//! - [`matcher`]: porovnání obsahu souboru po blocích,
//! - [`scan`]: bezpečné procházení a čtení souborů ve vláknech,
//! - [`audit`]: řetězený auditní log,
//! - [`status`]: pravdivý stav ochranných komponent,
//! - [`selftest`]: ověření detekce na vzorku v paměti,
//! - [`engine`]: spojení všeho dohromady pro aplikaci a CLI.

pub mod audit;
#[cfg(target_os = "macos")]
mod container;
pub mod engine;
pub mod error;
pub mod inspect;
pub mod matcher;
mod platform;
pub mod posture;
pub mod privacy;
pub mod provenance;
pub mod quarantine;
pub mod rules;
pub mod scan;
pub mod selftest;
pub mod status;
pub mod system;
pub mod testvectors;
pub mod types;
pub mod watch;

pub use engine::{Engine, EngineConfig, RemediationReport, RuleSource, RuleUpdateOutcome};
pub use error::EngineError;
pub use inspect::InspectResult;
pub use quarantine::QuarantineItem;
pub use scan::{ScanHandle, ScanObserver};
pub use types::*;

/// Verze enginu (z `Cargo.toml`).
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Aktuální čas v milisekundách od epochy UNIX.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Označení platformy pro informace o enginu, např. `macos-aarch64`.
pub fn platform_label() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}
