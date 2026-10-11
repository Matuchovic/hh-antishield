//! Společné pomůcky pro integrační testy. Používají jen neškodná data.
#![allow(dead_code, clippy::unwrap_used)]

use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use antishield_core::rules::{TrustedKey, signing};
use antishield_core::{
    Engine, EngineConfig, RuleSource, ScanEvent, ScanObserver, ScanRequest, ScanSummary,
};

pub const KEY_ID: &str = "test-key";
pub const SEED: [u8; 32] = [7u8; 32];

/// Testovací značka; v knihovně záměrně není, aby engine neoznačil sám sebe.
pub fn marker() -> Vec<u8> {
    b"HH-ANTISHIELD-TEST-MARKER-0001".to_vec()
}

pub fn trusted(test_only: bool) -> Vec<TrustedKey> {
    vec![TrustedKey {
        key_id: KEY_ID.into(),
        public_key: signing::public_key(&SEED),
        test_only,
    }]
}

/// Sestaví a podepíše sadu pravidel z JSON hodnoty.
pub fn signed(pack: &serde_json::Value) -> (Vec<u8>, Vec<u8>) {
    let bytes = serde_json::to_vec_pretty(pack).unwrap();
    let signature = signing::sign_pack(&bytes, &SEED, KEY_ID).into_bytes();
    (bytes, signature)
}

pub fn base_pack(rules: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "format_version": 1,
        "pack_id": "unit-test",
        "sequence": 1,
        "version": "1-test",
        "created_at_unix": 0,
        "expires_at_unix": 4_102_444_800i64,
        "min_engine_version": "0.1.0",
        "test_pack": true,
        "rules": rules,
    })
}

/// Zdroj YARA pro testovací sadu (formát 2).
pub fn yara_source(id: &str, source: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": format!("Source {id}"),
        "url": "https://example.com/rules",
        "license": "MIT",
        "source": source,
    })
}

/// Sada s jedním testovacím vzorem a zdroji YARA.
pub fn yara_pack(sources: serde_json::Value) -> serde_json::Value {
    let mut pack = base_pack(serde_json::json!([rule(
        "T-1",
        "bytes",
        serde_json::json!({ "pattern_hex": hex::encode(marker()) })
    )]));
    pack["format_version"] = 2.into();
    pack["yara"] = sources;
    pack
}

pub fn rule(id: &str, kind: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut value = serde_json::json!({
        "id": id,
        "version": 1,
        "kind": kind,
        "name": format!("Rule {id}"),
        "severity": "test_only",
        "description": { "cs": "Testovací pravidlo", "en": "Test rule" },
    });
    if let (Some(target), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            target.insert(k.clone(), v.clone());
        }
    }
    value
}

/// Engine se zabudovanou testovací sadou a dočasným adresářem dat.
pub fn engine(data_dir: &Path) -> Engine {
    let engine = Engine::new(EngineConfig::new(data_dir)).unwrap();
    assert!(engine.self_test().passed);
    engine
}

pub fn engine_with_pack(data_dir: &Path, pack: &serde_json::Value) -> Engine {
    let (pack, signature) = signed(pack);
    let mut config = EngineConfig::new(data_dir);
    config.rules = RuleSource::Bytes { pack, signature };
    config.trusted_keys = Some(trusted(true));
    Engine::new(config).unwrap()
}

pub struct Collector {
    tx: Mutex<Sender<ScanEvent>>,
}

impl ScanObserver for Collector {
    fn on_event(&self, event: ScanEvent) {
        let _ = self.tx.lock().unwrap().send(event);
    }
}

pub fn collector() -> (Arc<Collector>, Receiver<ScanEvent>) {
    let (tx, rx) = mpsc::channel();
    (Arc::new(Collector { tx: Mutex::new(tx) }), rx)
}

/// Spustí kontrolu a počká na `Finished`. Vrací všechny události a souhrn.
pub fn scan(engine: &Engine, request: ScanRequest) -> (Vec<ScanEvent>, ScanSummary) {
    let (observer, rx) = collector();
    engine.start_scan(request, observer).unwrap();
    collect(&rx)
}

pub fn collect(rx: &Receiver<ScanEvent>) -> (Vec<ScanEvent>, ScanSummary) {
    let mut events = Vec::new();
    loop {
        let event = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("scan did not finish within 60 s");
        if let ScanEvent::Finished { summary, .. } = &event {
            let summary = summary.clone();
            events.push(event);
            return (events, summary);
        }
        events.push(event);
    }
}

pub fn write(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, data).unwrap();
}

pub fn finding_rules(summary: &ScanSummary, file_name: &str) -> Vec<String> {
    let mut ids: Vec<String> = summary
        .findings
        .iter()
        .filter(|f| f.path.ends_with(file_name))
        .map(|f| f.rule_id.clone())
        .collect();
    ids.sort();
    ids
}

pub fn skipped_reasons(summary: &ScanSummary, file_name: &str) -> Vec<String> {
    summary
        .skipped_sample
        .iter()
        .filter(|s| s.path.ends_with(file_name))
        .map(|s| s.reason.code().to_string())
        .collect()
}
