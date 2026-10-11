//! Sestavení produkční sady pravidel z balíčku YARA Forge.
//!
//! Do sady jdou jen zdroje, jejichž licence dovoluje komerční použití.
//! Každé pravidlo se zkusí přeložit samostatně (YARA-X); co neprojde,
//! se vynechá a započítá do statistiky. Výsledek je nepodepsaný JSON.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Licence povolené v produkční sadě (klasifikace podle textu licence).
pub const ALLOWED_LICENSES: [&str; 7] = [
    "MIT",
    "Apache-2.0",
    "BSD",
    "DRL-1.1",
    "CC0-1.0",
    "Unlicense",
    "CC-BY-4.0",
];

/// Jeden zdroj (repozitář) z balíčku YARA Forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub url: String,
    pub license_text: String,
    pub rules: Vec<String>,
}

/// Rozpozná licenci podle textu. `None` = neznámá nebo nevhodná.
pub fn classify_license(text: &str) -> Option<&'static str> {
    let t = text.to_ascii_lowercase();
    if t.contains("noncommercial")
        || t.contains("non-commercial")
        || t.contains("gnu general public")
        || t.contains("gnu affero")
        || t.contains("gnu lesser")
        || t.contains("elastic license")
        || t.contains("no license set")
    {
        return None;
    }
    if t.contains("detection rule license") {
        Some("DRL-1.1")
    } else if t.contains("apache license") {
        Some("Apache-2.0")
    } else if t.contains("permission is hereby granted, free of charge") {
        Some("MIT")
    } else if t.contains("redistribution and use in source and binary forms") {
        Some("BSD")
    } else if t.contains("unlicense") || t.contains("this is free and unencumbered software") {
        Some("Unlicense")
    } else if t.contains("cc0") {
        Some("CC0-1.0")
    } else if t.contains("creative commons attribution 4.0") || t.contains("cc by 4.0") {
        Some("CC-BY-4.0")
    } else {
        None
    }
}

fn header_value(header: &str, key: &str) -> String {
    header
        .lines()
        .find_map(|line| {
            line.trim_start_matches([' ', '*'])
                .strip_prefix(key)
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default()
}

/// Rozdělí text na pravidla podle normalizovaného formátu YARA Forge:
/// pravidlo začíná na řádku `rule …`/`private rule …` a končí řádkem `}`.
fn split_rules(body: &str) -> Vec<String> {
    let mut rules = Vec::new();
    let mut current: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim_start();
        let starts = trimmed.starts_with("rule ")
            || trimmed.starts_with("private rule ")
            || trimmed.starts_with("global rule ")
            || trimmed.starts_with("global private rule ")
            || trimmed.starts_with("private global rule ");
        if current.is_none() && starts {
            current = Some(String::new());
        }
        if let Some(rule) = current.as_mut() {
            rule.push_str(line);
            rule.push('\n');
            if line.trim_end() == "}" {
                rules.extend(current.take());
            }
        }
    }
    rules
}

/// Načte balíček YARA Forge: importy a zdroje s licencemi a pravidly.
pub fn parse_forge(text: &str) -> (Vec<String>, Vec<Section>) {
    const MARKER: &str = " * YARA Rule Set";
    let imports: Vec<String> = text
        .lines()
        .filter(|line| line.trim_start().starts_with("import \""))
        .map(|line| line.trim().to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut sections = Vec::new();
    let mut parts = text.split(MARKER);
    parts.next(); // hlavička balíčku
    for part in parts {
        let Some(end) = part.find("*/") else {
            continue;
        };
        let header = &part[..end];
        let body = &part[end + 2..];
        let license_text = header
            .split_once("LICENSE")
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default();
        sections.push(Section {
            name: header_value(header, "Repository Name:"),
            url: header_value(header, "Repository:"),
            license_text,
            rules: split_rules(body),
        });
    }
    (imports, sections)
}

/// Jmenný prostor ze jména zdroje: malá písmena, číslice, podtržítka.
fn namespace(name: &str, used: &mut BTreeMap<String, usize>) -> String {
    let mut id: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    id = id.trim_matches('_').chars().take(48).collect();
    if !id.starts_with(|c: char| c.is_ascii_lowercase()) {
        id = format!("src_{id}");
    }
    let count = used.entry(id.clone()).or_insert(0);
    *count += 1;
    if *count > 1 {
        id = format!("{id}_{count}");
    }
    id
}

/// Statistika sestavení (pro souhrn v CI).
#[derive(Debug, Default)]
pub struct BuildStats {
    pub included: Vec<(String, String, usize)>,
    pub excluded_license: Vec<(String, String)>,
    pub failed_rules: usize,
}

/// Přeloží pravidla zdroje jedno po druhém; vrátí zdrojový text přijatých pravidel.
fn accepted_rules(imports: &[String], rules: &[String], failed: &mut usize) -> (String, usize) {
    let header = if imports.is_empty() {
        String::new()
    } else {
        format!("{}\n", imports.join("\n"))
    };
    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace("check");
    let mut accepted = header.clone();
    let mut count = 0;
    for rule in rules {
        let source = format!("{header}{rule}");
        if compiler.add_source(source.as_str()).is_ok() {
            accepted.push_str(rule);
            count += 1;
        } else {
            *failed += 1;
        }
    }
    (accepted, count)
}

/// Sestaví nepodepsanou sadu: základní pravidla + self-test YARA + zdroje Forge.
pub fn build_pack(
    base: &Value,
    selftest_yara: &str,
    forge_text: &str,
    sequence: u64,
    version: &str,
    created_at_unix: i64,
    valid_days: i64,
) -> Result<(Value, BuildStats), String> {
    let mut pack = base.clone();
    let object = pack.as_object_mut().ok_or("base pack must be an object")?;
    object.insert("format_version".into(), json!(2));
    object.insert("sequence".into(), json!(sequence));
    object.insert("version".into(), json!(version));
    object.insert("created_at_unix".into(), json!(created_at_unix));
    object.insert(
        "expires_at_unix".into(),
        json!(created_at_unix + valid_days * 86_400),
    );
    object.insert("test_pack".into(), json!(false));

    let mut sources = vec![json!({
        "id": "hh",
        "name": "H&H AntiShield",
        "url": "https://github.com/Matuchovic/hh-antishield",
        "license": "LicenseRef-HH-Proprietary",
        "source": selftest_yara,
    })];
    let mut stats = BuildStats::default();
    let mut used = BTreeMap::from([("hh".to_string(), 1)]);
    let (imports, sections) = parse_forge(forge_text);
    for section in sections {
        let Some(license) = classify_license(&section.license_text)
            .filter(|license| ALLOWED_LICENSES.contains(license))
        else {
            stats
                .excluded_license
                .push((section.name.clone(), section.url.clone()));
            continue;
        };
        if !section.url.starts_with("https://") {
            stats
                .excluded_license
                .push((section.name.clone(), section.url.clone()));
            continue;
        }
        let (source, count) = accepted_rules(&imports, &section.rules, &mut stats.failed_rules);
        if count == 0 {
            continue;
        }
        let id = namespace(&section.name, &mut used);
        stats
            .included
            .push((section.name.clone(), license.to_string(), count));
        sources.push(json!({
            "id": id,
            "name": section.name.chars().take(200).collect::<String>(),
            "url": section.url,
            "license": license,
            "source": source,
        }));
    }
    object.insert("yara".into(), Value::Array(sources));
    Ok((pack, stats))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const FORGE: &str = r#"/*
 * YARA-Forge Rule Package
 */

import "math"
import "pe"

/*
 * YARA Rule Set
 * Repository Name: Good Rules
 * Repository: https://github.com/example/good
 * Retrieval Date: 2026-10-11
 *
 * LICENSE
 *
 * MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy
 */
private rule GOOD_Helper {
   condition:
      uint16(0) == 0x5a4d
}

rule GOOD_Uses_Helper {
   meta:
      score = 70
   condition:
      GOOD_Helper and math.entropy(0, filesize) > 7.0
}

rule GOOD_Broken {
   condition:
      $undefined
}

rule GOOD_Marker {
   strings:
      $a = "FORGE-TEST-MARKER"
   condition:
      $a
}

/*
 * YARA Rule Set
 * Repository Name: Copyleft Rules
 * Repository: https://github.com/example/gpl
 *
 * LICENSE
 *
 * GNU GENERAL PUBLIC LICENSE Version 2
 */
rule GPL_Rule {
   condition:
      true
}
"#;

    #[test]
    fn licenses_are_classified_conservatively() {
        assert_eq!(
            classify_license("MIT License\nPermission is hereby granted, free of charge"),
            Some("MIT")
        );
        assert_eq!(
            classify_license("Detection Rule License (DRL) 1.1"),
            Some("DRL-1.1")
        );
        assert_eq!(
            classify_license("Apache License Version 2.0"),
            Some("Apache-2.0")
        );
        assert_eq!(classify_license("GNU GENERAL PUBLIC LICENSE"), None);
        assert_eq!(
            classify_license("Creative Commons Attribution-NonCommercial 4.0"),
            None
        );
        assert_eq!(classify_license("Elastic License 2.0"), None);
        assert_eq!(classify_license("NO LICENSE SET"), None);
        assert_eq!(classify_license("something else"), None);
    }

    #[test]
    fn forge_package_builds_into_a_loadable_pack() {
        let (imports, sections) = parse_forge(FORGE);
        assert_eq!(imports, ["import \"math\"", "import \"pe\""]);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].name, "Good Rules");
        assert_eq!(sections[0].url, "https://github.com/example/good");
        assert_eq!(sections[0].rules.len(), 4);

        let base = json!({
            "format_version": 1, "pack_id": "hh-antishield", "sequence": 0, "version": "x",
            "created_at_unix": 0, "expires_at_unix": 0, "min_engine_version": "0.1.0",
            "test_pack": true,
            "rules": [{ "id": "HH-EICAR", "version": 1, "kind": "eicar", "name": "EICAR",
                "description": { "cs": "Test", "en": "Test" }, "severity": "test_only" }]
        });
        let selftest = include_str!("../../../rules/yara/hh-selftest.yar");
        let (pack, stats) =
            build_pack(&base, selftest, FORGE, 42, "2026.10.11", 1_791_590_400, 45).unwrap();
        assert_eq!(
            stats.included,
            [("Good Rules".to_string(), "MIT".to_string(), 3)]
        );
        assert_eq!(stats.excluded_license.len(), 1);
        assert_eq!(stats.failed_rules, 1);
        assert_eq!(pack["test_pack"], json!(false));
        assert_eq!(pack["sequence"], json!(42));
        let yara = pack["yara"].as_array().unwrap();
        assert_eq!(yara.len(), 2);
        assert_eq!(yara[1]["id"], json!("good_rules"));
        assert_eq!(yara[1]["license"], json!("MIT"));

        // Výsledná sada musí projít i kontrolou enginu.
        use antishield_core::rules::{TrustedKey, signing};
        let bytes = serde_json::to_vec(&pack).unwrap();
        let seed = [3u8; 32];
        let sig = signing::sign_pack(&bytes, &seed, "k");
        let keys = [TrustedKey {
            key_id: "k".into(),
            public_key: signing::public_key(&seed),
            test_only: false,
        }];
        let loaded =
            antishield_core::rules::RulePack::load(&bytes, sig.as_bytes(), &keys, 1_791_590_400)
                .unwrap();
        assert_eq!(loaded.info().yara_rule_count, 4);
        assert!(antishield_core::selftest::run(&loaded).passed);
    }
}
