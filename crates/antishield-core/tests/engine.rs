//! Engine: pravdivý stav komponent a odmítnutí neplatných pravidel.
#![allow(clippy::unwrap_used)]

mod common;

use antishield_core::rules::builtin_trusted_keys;
use antishield_core::status::{ComponentKind, ComponentState, ProtectionLevel};
use antishield_core::testvectors::eicar;
use antishield_core::{
    Engine, EngineConfig, EngineError, RuleSource, RuleUpdateOutcome, ScanRequest,
};
use serde_json::json;

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
            | ComponentKind::Quarantine
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

/// Zabudované klíče + testovací klíč jako produkční (pro sady `test_pack: false`).
fn keys_with_production_test_key() -> Vec<antishield_core::rules::TrustedKey> {
    let mut keys = builtin_trusted_keys();
    keys.extend(common::trusted(false));
    keys
}

fn production_engine(dir: &std::path::Path) -> Engine {
    let mut config = EngineConfig::new(dir);
    config.trusted_keys = Some(keys_with_production_test_key());
    Engine::new(config).unwrap()
}

const SELFTEST_YARA: &str = include_str!("../../../rules/yara/hh-selftest.yar");

/// Produkční sada, která projde self-testem (EICAR, vzor, YARA).
fn production_pack(sequence: u64, yara: &str) -> (Vec<u8>, Vec<u8>) {
    let mut pack = common::yara_pack(json!([common::yara_source("hh", yara)]));
    pack["test_pack"] = false.into();
    pack["sequence"] = sequence.into();
    pack["rules"]
        .as_array_mut()
        .unwrap()
        .push(common::rule("EICAR", "eicar", json!({})));
    common::signed(&pack)
}

#[test]
fn rule_updates_install_persist_and_refuse_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = production_engine(tmp.path());
    assert!(engine.rules().info().test_pack);

    let (pack, sig) = production_pack(5, SELFTEST_YARA);
    let outcome = engine.install_rule_pack(&pack, &sig).unwrap();
    assert!(matches!(outcome, RuleUpdateOutcome::Installed { .. }));
    assert_eq!(engine.rules().info().sequence, 5);
    assert!(!engine.rules().info().test_pack);
    assert_eq!(engine.rules_signature(), sig);
    assert!(matches!(
        engine.install_rule_pack(&pack, &sig).unwrap(),
        RuleUpdateOutcome::UpToDate { .. }
    ));

    let (older, older_sig) = production_pack(4, SELFTEST_YARA);
    assert!(matches!(
        engine.install_rule_pack(&older, &older_sig),
        Err(EngineError::RulePackRollback {
            current: 5,
            offered: 4
        })
    ));
    let mut tampered = pack.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    assert!(matches!(
        engine.install_rule_pack(&tampered, &sig),
        Err(EngineError::RulePackSignatureInvalid)
    ));
    let test_pack = include_bytes!("../../../rules/test-pack.json");
    let test_sig = include_bytes!("../../../rules/test-pack.json.sig");
    assert!(matches!(
        engine.install_rule_pack(test_pack, test_sig),
        Err(EngineError::InvalidRequest(_))
    ));
    assert_eq!(engine.rules().info().sequence, 5);

    // Po restartu se načte nainstalovaná sada.
    drop(engine);
    let restarted = production_engine(tmp.path());
    assert_eq!(restarted.rules().info().sequence, 5);
    assert!(restarted.self_test().passed);
}

#[test]
fn rule_updates_must_pass_the_self_test() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = production_engine(tmp.path());
    let (pack, sig) = production_pack(7, "rule Unrelated { condition: false }");
    assert!(matches!(
        engine.install_rule_pack(&pack, &sig),
        Err(EngineError::RulePackSelfTest(failed)) if failed.contains("yara_engine")
    ));
    assert!(engine.rules().info().test_pack);
}

#[test]
fn damaged_installed_pack_falls_back_to_embedded() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = production_engine(tmp.path());
    let (pack, sig) = production_pack(9, SELFTEST_YARA);
    engine.install_rule_pack(&pack, &sig).unwrap();
    drop(engine);
    let stored = tmp.path().join("rules/seq-9/pack.json");
    let mut bytes = std::fs::read(&stored).unwrap();
    bytes[10] ^= 0x01;
    std::fs::write(&stored, bytes).unwrap();
    let restarted = production_engine(tmp.path());
    assert!(restarted.rules().info().test_pack);
    let events = restarted.recent_audit_events(20).unwrap();
    assert!(events.iter().any(|e| e.kind == "rule_pack_rejected"));
}

fn scan_one(engine: &Engine, path: &std::path::Path) -> antishield_core::ScanSummary {
    common::scan(engine, ScanRequest::new(vec![path.to_path_buf()])).1
}

#[test]
fn quarantine_moves_neutralizes_and_restores() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = common::engine(&tmp.path().join("state"));
    let file = tmp.path().join("data").join("eicar.com");
    common::write(&file, &eicar());
    let summary = scan_one(&engine, &file);
    let finding = summary.findings.first().unwrap().clone();

    let item = engine.quarantine_finding(&finding).unwrap();
    assert!(!file.exists());
    let stored = std::fs::read(
        tmp.path()
            .join("state/quarantine")
            .join(format!("{}.bin", item.id)),
    )
    .unwrap();
    assert!(
        !stored
            .windows(eicar().len())
            .any(|w| w == eicar().as_slice())
    );
    assert_eq!(engine.quarantine_items().unwrap().len(), 1);
    // Obsah karantény sám nic nenajde.
    let rescan = scan_one(&engine, &tmp.path().join("state/quarantine"));
    assert!(rescan.findings.is_empty());

    common::write(&file, b"new file in the way");
    assert!(matches!(
        engine.restore_quarantined(&item.id),
        Err(EngineError::RestoreConflict(_))
    ));
    std::fs::remove_file(&file).unwrap();
    engine.restore_quarantined(&item.id).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), eicar());
    assert!(engine.quarantine_items().unwrap().is_empty());

    let summary = scan_one(&engine, &file);
    let item = engine
        .quarantine_finding(summary.findings.first().unwrap())
        .unwrap();
    engine.delete_quarantined(&item.id).unwrap();
    assert!(engine.quarantine_items().unwrap().is_empty());
    assert!(!file.exists());
    assert!(matches!(
        engine.delete_quarantined("not-an-id"),
        Err(EngineError::QuarantineItemNotFound(_))
    ));
    let kinds: Vec<String> = engine
        .recent_audit_events(50)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    for kind in ["quarantined", "quarantine_restored", "quarantine_deleted"] {
        assert!(kinds.iter().any(|k| k == kind), "{kind}");
    }
}

#[test]
fn quarantine_refuses_files_changed_after_the_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = common::engine(&tmp.path().join("state"));
    let file = tmp.path().join("data").join("eicar.com");
    common::write(&file, &eicar());
    let finding = scan_one(&engine, &file).findings.first().unwrap().clone();
    std::thread::sleep(std::time::Duration::from_millis(20));
    common::write(&file, b"replaced with something else entirely");
    assert!(matches!(
        engine.quarantine_finding(&finding),
        Err(EngineError::FileChanged(_))
    ));
    assert!(file.exists());
    assert!(engine.quarantine_items().unwrap().is_empty());
}
