//! Sada pravidel: podpis se ověřuje před parsováním a nevalidní sady se odmítnou.
#![allow(clippy::unwrap_used)]

mod common;

use antishield_core::EngineError;
use antishield_core::rules::{MAX_PACK_SIZE, RulePack, builtin_trusted_keys, signing};
use common::{KEY_ID, SEED, base_pack, rule, signed, trusted};
use serde_json::json;

const NOW: i64 = 1_791_590_400;

fn load(pack: &serde_json::Value) -> Result<RulePack, EngineError> {
    let (bytes, sig) = signed(pack);
    RulePack::load(&bytes, &sig, &trusted(true), NOW)
}

fn sha_rule(id: &str, hex: &str) -> serde_json::Value {
    rule(id, "sha256", json!({ "sha256": hex }))
}

const SOME_HASH: &str = "9165bb977ff9815b22c7b87a7721697a88d6669a69c4b4b40689f3774632c64a";

#[test]
fn embedded_pack_verifies_with_builtin_key() {
    let pack = include_bytes!("../../../rules/test-pack.json");
    let sig = include_bytes!("../../../rules/test-pack.json.sig");
    let loaded = RulePack::load(pack, sig, &builtin_trusted_keys(), NOW).unwrap();
    assert!(loaded.info().test_pack);
    assert_eq!(loaded.info().rule_count, 6);
    assert_eq!(loaded.info().yara_rule_count, 1);
    assert_eq!(loaded.info().sources.len(), 1);
    assert!(loaded.eicar_rule().is_some());
    assert!(loaded.yara().is_some());
}

const YARA_OK: &str =
    r#"rule Demo_Rule { meta: score = 85 strings: $a = "HARMLESS-YARA-DEMO" condition: $a }"#;

#[test]
fn yara_sources_compile_and_count() {
    let pack = common::yara_pack(json!([
        common::yara_source("alpha", YARA_OK),
        common::yara_source(
            "beta",
            "rule B1 { condition: false } rule B2 { condition: false }"
        ),
    ]));
    let (bytes, sig) = common::signed(&pack);
    let loaded = RulePack::load(&bytes, &sig, &common::trusted(true), NOW).unwrap();
    let info = loaded.info();
    assert_eq!(info.yara_rule_count, 3);
    assert_eq!(info.rule_count, 4);
    let counts: Vec<(String, u32)> = info
        .sources
        .iter()
        .map(|s| (s.id.clone(), s.rule_count))
        .collect();
    assert_eq!(counts, [("alpha".to_string(), 1), ("beta".to_string(), 2)]);
}

#[test]
fn invalid_yara_sources_are_rejected() {
    let bad_sources = [
        json!([common::yara_source(
            "alpha",
            "rule Broken { condition: $missing }"
        )]),
        json!([common::yara_source("Alpha", YARA_OK)]),
        json!([common::yara_source("1alpha", YARA_OK)]),
        json!([
            common::yara_source("alpha", YARA_OK),
            common::yara_source("alpha", YARA_OK)
        ]),
        json!([{ "id": "alpha", "name": "x", "url": "http://insecure.example", "license": "MIT", "source": YARA_OK }]),
        json!([{ "id": "alpha", "name": "x", "url": "https://example.com", "license": "", "source": YARA_OK }]),
    ];
    for sources in bad_sources {
        let (bytes, sig) = common::signed(&common::yara_pack(sources.clone()));
        let result = RulePack::load(&bytes, &sig, &common::trusted(true), NOW);
        assert!(
            matches!(result, Err(EngineError::RulePackMalformed(_))),
            "{sources}: {result:?}"
        );
    }
}

#[test]
fn valid_pack_loads() {
    let pack = base_pack(json!([
        sha_rule("A-1", SOME_HASH),
        rule(
            "A-2",
            "bytes",
            json!({ "pattern_hex": hex::encode(b"0123456789") })
        ),
        rule("A-3", "eicar", json!({})),
    ]));
    let loaded = load(&pack).unwrap();
    assert_eq!(loaded.info().rule_count, 3);
    assert_eq!(loaded.pattern_count(), 1);
    assert!(!loaded.info().expired);
}

#[test]
fn tampered_pack_is_rejected_before_parsing() {
    let pack = base_pack(json!([sha_rule("A-1", SOME_HASH)]));
    let (mut bytes, sig) = signed(&pack);
    let last = bytes.len() - 2;
    bytes[last] ^= 0x01;
    assert!(matches!(
        RulePack::load(&bytes, &sig, &trusted(true), NOW),
        Err(EngineError::RulePackSignatureInvalid)
    ));
    // Nesmyslný obsah s neplatným podpisem: chyba podpisu, ne chyba parseru.
    assert!(matches!(
        RulePack::load(b"{not json", &sig, &trusted(true), NOW),
        Err(EngineError::RulePackSignatureInvalid)
    ));
}

#[test]
fn wrong_or_unknown_key_is_rejected() {
    let pack = base_pack(json!([sha_rule("A-1", SOME_HASH)]));
    let bytes = serde_json::to_vec(&pack).unwrap();
    let other_seed = [9u8; 32];
    let sig = signing::sign_pack(&bytes, &other_seed, KEY_ID);
    assert!(matches!(
        RulePack::load(&bytes, sig.as_bytes(), &trusted(true), NOW),
        Err(EngineError::RulePackSignatureInvalid)
    ));
    let sig = signing::sign_pack(&bytes, &SEED, "someone-else");
    assert!(matches!(
        RulePack::load(&bytes, sig.as_bytes(), &trusted(true), NOW),
        Err(EngineError::RulePackUnknownKey { .. })
    ));
}

#[test]
fn malformed_signature_files_are_rejected() {
    let pack = base_pack(json!([sha_rule("A-1", SOME_HASH)]));
    let (bytes, _) = signed(&pack);
    for sig in [
        "".to_string(),
        "{}".to_string(),
        json!({"format_version":1,"key_id":KEY_ID,"algorithm":"ed25519","signature_hex":"abcd"})
            .to_string(),
        json!({"format_version":1,"key_id":KEY_ID,"algorithm":"rsa","signature_hex":"00"})
            .to_string(),
        "x".repeat(5000),
    ] {
        assert!(
            RulePack::load(&bytes, sig.as_bytes(), &trusted(true), NOW).is_err(),
            "accepted signature file {sig:.40}"
        );
    }
}

#[test]
fn oversized_pack_is_rejected_without_parsing() {
    let bytes = vec![b' '; MAX_PACK_SIZE + 1];
    let sig = signing::sign_pack(&bytes, &SEED, KEY_ID);
    assert!(matches!(
        RulePack::load(&bytes, sig.as_bytes(), &trusted(true), NOW),
        Err(EngineError::RulePackTooLarge { .. })
    ));
}

#[test]
fn invalid_rules_are_rejected() {
    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let cases = vec![
        (
            "duplicate id",
            json!([sha_rule("A-1", SOME_HASH), sha_rule("A-1", empty_hash)]),
        ),
        ("empty-file hash", json!([sha_rule("A-1", empty_hash)])),
        (
            "duplicate hash",
            json!([sha_rule("A-1", SOME_HASH), sha_rule("A-2", SOME_HASH)]),
        ),
        ("short hash", json!([sha_rule("A-1", "abcd")])),
        (
            "short pattern",
            json!([rule("A-1", "bytes", json!({ "pattern_hex": "41424344" }))]),
        ),
        (
            "bad hex",
            json!([rule("A-1", "bytes", json!({ "pattern_hex": "zz" }))]),
        ),
        (
            "mixed data",
            json!([rule(
                "A-1",
                "sha256",
                json!({ "sha256": SOME_HASH, "pattern_hex": "4142434445464748" })
            )]),
        ),
        (
            "eicar with data",
            json!([rule("A-1", "eicar", json!({ "sha256": SOME_HASH }))]),
        ),
        (
            "two eicar rules",
            json!([
                rule("A-1", "eicar", json!({})),
                rule("A-2", "eicar", json!({}))
            ]),
        ),
        ("lowercase id", json!([sha_rule("a-1", SOME_HASH)])),
        (
            "unknown field",
            json!([rule(
                "A-1",
                "sha256",
                json!({ "sha256": SOME_HASH, "extra": 1 })
            )]),
        ),
        ("no rules", json!([])),
    ];
    for (name, rules) in cases {
        let result = load(&base_pack(rules));
        assert!(
            matches!(result, Err(EngineError::RulePackMalformed(_))),
            "{name}: expected RulePackMalformed, got {result:?}"
        );
    }
}

#[test]
fn test_key_cannot_sign_production_pack() {
    let mut pack = base_pack(json!([sha_rule("A-1", SOME_HASH)]));
    pack["test_pack"] = json!(false);
    assert!(matches!(
        load(&pack),
        Err(EngineError::RulePackMalformed(_))
    ));
    // Produkční klíč produkční sadu podepsat smí.
    let (bytes, sig) = signed(&pack);
    assert!(RulePack::load(&bytes, &sig, &trusted(false), NOW).is_ok());
}

#[test]
fn newer_engine_requirement_is_rejected() {
    let mut pack = base_pack(json!([sha_rule("A-1", SOME_HASH)]));
    pack["min_engine_version"] = json!("99.0.0");
    assert!(matches!(
        load(&pack),
        Err(EngineError::RulePackIncompatible { .. })
    ));
}

#[test]
fn expired_pack_is_marked() {
    let mut pack = base_pack(json!([sha_rule("A-1", SOME_HASH)]));
    pack["expires_at_unix"] = json!(NOW - 1);
    assert!(load(&pack).unwrap().info().expired);
}
