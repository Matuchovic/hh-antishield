//! Porovnání obsahu: výsledek nesmí záviset na tom, jak je soubor rozdělen na bloky.
#![allow(clippy::unwrap_used)]

mod common;

use antishield_core::Evidence;
use antishield_core::matcher::scan_buffer;
use antishield_core::rules::RulePack;
use antishield_core::testvectors::{eicar, synthetic_sample};
use common::{base_pack, rule, signed, trusted};
use proptest::prelude::*;
use serde_json::json;

const PATTERNS: [&[u8]; 4] = [
    b"ABCDEFGH",
    b"HH-ANTISHIELD-TEST-MARKER-0001",
    b"EFGHIJKLMNOP",
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08",
];

fn pattern_pack() -> RulePack {
    let rules: Vec<serde_json::Value> = PATTERNS
        .iter()
        .enumerate()
        .map(|(i, p)| {
            rule(
                &format!("P-{i}"),
                "bytes",
                json!({ "pattern_hex": hex::encode(p) }),
            )
        })
        .collect();
    let (bytes, sig) = signed(&base_pack(json!(rules)));
    RulePack::load(&bytes, &sig, &trusted(true), 0).unwrap()
}

/// Naivní reference: první výskyt každého vzoru.
fn naive_first_hits(data: &[u8]) -> Vec<Option<u64>> {
    PATTERNS
        .iter()
        .map(|p| {
            data.windows(p.len())
                .position(|w| w == *p)
                .map(|pos| pos as u64)
        })
        .collect()
}

fn engine_first_hits(pack: &RulePack, data: &[u8], chunk: usize) -> Vec<Option<u64>> {
    let verdict = scan_buffer(pack, data, chunk);
    let mut hits = vec![None; PATTERNS.len()];
    for m in verdict.matches {
        if let Evidence::BytePattern { offset, .. } = m.evidence {
            hits[m.rule_index] = Some(offset);
        }
    }
    hits
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn chunking_does_not_change_matches(
        noise in proptest::collection::vec(prop_oneof![Just(b'A'), Just(b'E'), Just(b'H'), Just(0u8), any::<u8>()], 0..3000),
        inserts in proptest::collection::vec((0usize..4, 0usize..3000), 0..6),
        chunk in 1usize..700,
    ) {
        let mut data = noise;
        for (pattern, position) in inserts {
            let at = position.min(data.len());
            let bytes = PATTERNS[pattern];
            data.splice(at..at, bytes.iter().copied());
        }
        let pack = pattern_pack();
        let expected = naive_first_hits(&data);
        prop_assert_eq!(engine_first_hits(&pack, &data, chunk), expected.clone());
        prop_assert_eq!(engine_first_hits(&pack, &data, data.len().max(1)), expected);
    }
}

#[test]
fn pattern_spanning_many_tiny_chunks() {
    let pack = pattern_pack();
    let mut data = vec![b'x'; 10];
    data.extend_from_slice(PATTERNS[1]);
    data.extend_from_slice(b"tail");
    for chunk in [1, 2, 3, 29, 30, 31, 1024] {
        assert_eq!(
            engine_first_hits(&pack, &data, chunk)[1],
            Some(10),
            "chunk {chunk}"
        );
    }
}

#[test]
fn hash_is_independent_of_chunking() {
    let pack = pattern_pack();
    let data = synthetic_sample(7);
    let reference = scan_buffer(&pack, &data, data.len()).sha256;
    for chunk in [1, 13, 4095, 4096] {
        assert_eq!(scan_buffer(&pack, &data, chunk).sha256, reference);
    }
}

#[test]
fn eicar_rule_follows_the_official_definition() {
    let pack = {
        let (bytes, sig) = signed(&base_pack(json!([rule("E-1", "eicar", json!({}))])));
        RulePack::load(&bytes, &sig, &trusted(true), 0).unwrap()
    };
    let detected = |data: &[u8]| !scan_buffer(&pack, data, 16).matches.is_empty();
    let sample = eicar();
    assert!(detected(&sample));
    let mut padded = sample.clone();
    padded.resize(128, b' ');
    assert!(
        detected(&padded),
        "trailing whitespace up to 128 bytes is allowed"
    );
    let mut too_long = sample.clone();
    too_long.resize(129, b' ');
    assert!(!detected(&too_long), "129 bytes exceeds the definition");
    let mut prefixed = vec![b'\n'];
    prefixed.extend_from_slice(&sample);
    assert!(!detected(&prefixed), "the string must start the file");
    let mut changed = sample.clone();
    changed[10] ^= 0x20;
    assert!(!detected(&changed));
    assert!(!detected(&sample[..60]));
}
