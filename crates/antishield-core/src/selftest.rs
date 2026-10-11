//! Self-test: ověří, že detekce s načtenou sadou pravidel opravdu funguje.
//! Běží jen v paměti, žádný testovací soubor se nezapisuje na disk.

use sha2::{Digest, Sha256};

use crate::matcher::{EICAR_SHA256, scan_buffer};
use crate::now_ms;
use crate::rules::RulePack;
use crate::testvectors;
use crate::types::{SelfTestCheck, SelfTestReport};

/// Neškodná značka, kterou hledá pravidlo `HH_YARA_SELFTEST` v každé sadě s YARA.
pub const YARA_SELFTEST_MARKER: &[u8] = b"HH-ANTISHIELD-YARA-SELFTEST-0001";
pub const YARA_SELFTEST_RULE: &str = "HH_YARA_SELFTEST";

fn check(name: &str, passed: bool, detail: String) -> SelfTestCheck {
    SelfTestCheck {
        name: name.to_string(),
        passed,
        detail,
    }
}

pub fn run(rules: &RulePack) -> SelfTestReport {
    let info = rules.info();
    let mut checks = vec![check(
        "signature",
        true,
        format!(
            "sada {} {} ověřena klíčem {}",
            info.pack_id, info.version, info.signing_key_id
        ),
    )];

    let eicar = testvectors::eicar();
    let vector_ok = Sha256::digest(&eicar).as_slice() == EICAR_SHA256.as_slice();
    checks.push(check(
        "test_vector",
        vector_ok,
        "testovací vzorek EICAR v paměti je neporušený".into(),
    ));

    // Detekce musí fungovat při různém dělení na bloky.
    let mut detected_by: Vec<String> = Vec::new();
    let mut all_detected = vector_ok;
    for chunk in [68usize, 7, 1] {
        let verdict = scan_buffer(rules, &eicar, chunk);
        if verdict.matches.is_empty() {
            all_detected = false;
        }
        for m in &verdict.matches {
            let id = &rules.rule(m.rule_index).id;
            if !detected_by.contains(id) {
                detected_by.push(id.clone());
            }
        }
    }
    checks.push(check(
        "eicar_detected",
        all_detected,
        if all_detected {
            format!("vzorek EICAR zachycen pravidly {}", detected_by.join(", "))
        } else {
            "sada pravidel nezachytila vzorek EICAR".into()
        },
    ));

    let mut clean = eicar;
    if let Some(last) = clean.last_mut() {
        *last ^= 0x01;
    }
    let clean_ok = scan_buffer(rules, &clean, 68).matches.is_empty();
    checks.push(check(
        "clean_not_detected",
        clean_ok,
        if clean_ok {
            "pozměněný vzorek nebyl označen".into()
        } else {
            "pozměněný vzorek byl označen (falešný poplach)".into()
        },
    ));

    if rules.pattern_count() > 0 {
        let pattern = rules.pattern(0).to_vec();
        let mut data = vec![b'A'; 100];
        data.extend_from_slice(&pattern);
        data.extend_from_slice(&[b'B'; 100]);
        // Blok končí uprostřed vzoru, takže se ověří i hledání přes hranici bloků.
        let chunk = 100 + pattern.len() / 2;
        let verdict = scan_buffer(rules, &data, chunk);
        let found = verdict
            .matches
            .iter()
            .any(|m| m.rule_index == rules.pattern_rule(0));
        checks.push(check(
            "pattern_across_chunks",
            found,
            if found {
                "bajtový vzor nalezen i přes hranici bloků".into()
            } else {
                "bajtový vzor přes hranici bloků nebyl nalezen".into()
            },
        ));
    }

    if let Some(yara) = rules.yara() {
        // Každá sada s YARA obsahuje neškodné pravidlo HH_YARA_SELFTEST.
        let mut data = vec![b'A'; 64];
        data.extend_from_slice(YARA_SELFTEST_MARKER);
        data.extend_from_slice(&[b'B'; 64]);
        let mut scanner = yara_x::Scanner::new(yara);
        let found = scanner.scan(&data).is_ok_and(|results| {
            results
                .matching_rules()
                .any(|rule| rule.identifier() == YARA_SELFTEST_RULE)
        });
        checks.push(check(
            "yara_engine",
            found,
            if found {
                format!(
                    "engine YARA-X zachytil testovací vzorek (pravidel YARA: {})",
                    rules.info().yara_rule_count
                )
            } else {
                "engine YARA-X testovací vzorek nezachytil".into()
            },
        ));
    }

    SelfTestReport {
        passed: checks.iter().all(|c| c.passed),
        ran_at_ms: now_ms(),
        checks,
    }
}
