//! Engine: pravdivý stav komponent a odmítnutí neplatných pravidel.
#![allow(clippy::unwrap_used)]

mod common;

use antishield_core::status::{ComponentKind, ComponentState, ProtectionLevel};
use antishield_core::{Engine, EngineConfig, EngineError, RuleSource};

#[test]
fn status_is_not_ready_until_self_test_passes() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = Engine::new(EngineConfig::new(tmp.path())).unwrap();
    assert_eq!(engine.protection_summary().level, ProtectionLevel::NotReady);
    assert!(engine.self_test().passed);
    let summary = engine.protection_summary();
    assert_eq!(summary.level, ProtectionLevel::ManualScanOnly);
    for status in &summary.components {
        match status.kind {
            ComponentKind::DetectionEngine
            | ComponentKind::RulePack
            | ComponentKind::AuditLog
            | ComponentKind::OnDemandScan => {
                assert!(status.state.is_running(), "{status:?}");
            }
            _ => assert_eq!(status.state, ComponentState::NotImplemented, "{status:?}"),
        }
    }
}

#[test]
fn tampered_rule_files_stop_the_engine_and_are_audited() {
    let tmp = tempfile::tempdir().unwrap();
    let pack_path = tmp.path().join("pack.json");
    let sig_path = tmp.path().join("pack.json.sig");
    let mut pack = include_bytes!("../../../rules/test-pack.json").to_vec();
    pack[100] ^= 0x01;
    std::fs::write(&pack_path, &pack).unwrap();
    std::fs::write(
        &sig_path,
        include_bytes!("../../../rules/test-pack.json.sig"),
    )
    .unwrap();
    let mut config = EngineConfig::new(tmp.path().join("state"));
    config.rules = RuleSource::Files {
        pack: pack_path,
        signature: sig_path,
    };
    assert!(matches!(
        Engine::new(config),
        Err(EngineError::RulePackSignatureInvalid)
    ));
    let report = antishield_core::audit::verify_dir(&tmp.path().join("state/audit")).unwrap();
    assert!(report.ok);
    let log = std::fs::read_to_string(tmp.path().join("state/audit/audit-000001.jsonl")).unwrap();
    assert!(log.contains("rule_pack_rejected"));
}

#[test]
fn info_reports_versions() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = common::engine(tmp.path());
    let info = engine.info();
    assert_eq!(info.engine_version, antishield_core::ENGINE_VERSION);
    assert!(info.rule_pack.test_pack);
    assert!(!info.platform.is_empty());
}
