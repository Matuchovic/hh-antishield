//! Auditní log: řetězení odhalí úpravu, vynechání i přehození záznamů.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use antishield_core::audit::{AuditLog, verify_dir};
use serde_json::json;

fn log_with_records(dir: &Path, count: u64) -> PathBuf {
    let mut log = AuditLog::open(dir).unwrap();
    for i in 0..count {
        log.append("test", json!({ "i": i }), false).unwrap();
    }
    dir.join("audit-000001.jsonl")
}

#[test]
fn fresh_log_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    log_with_records(tmp.path(), 5);
    let report = verify_dir(tmp.path()).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.records, 5);
}

#[test]
fn reopening_continues_the_chain() {
    let tmp = tempfile::tempdir().unwrap();
    log_with_records(tmp.path(), 3);
    let mut log = AuditLog::open(tmp.path()).unwrap();
    assert!(log.integrity_issue().is_none());
    assert_eq!(log.append("again", json!({}), true).unwrap(), 4);
    let report = verify_dir(tmp.path()).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(log.recent(2).unwrap().first().map(|e| e.seq), Some(4));
}

#[test]
fn modified_record_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let file = log_with_records(tmp.path(), 4);
    let text = fs::read_to_string(&file).unwrap();
    fs::write(&file, text.replacen("\"i\":1", "\"i\":9", 1)).unwrap();
    assert!(!verify_dir(tmp.path()).unwrap().ok);
}

#[test]
fn deleted_record_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let file = log_with_records(tmp.path(), 4);
    let lines: Vec<String> = fs::read_to_string(&file)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    let kept = [&lines[0], &lines[2], &lines[3]]
        .iter()
        .map(|l| format!("{l}\n"))
        .collect::<String>();
    fs::write(&file, kept).unwrap();
    assert!(!verify_dir(tmp.path()).unwrap().ok);
}

#[test]
fn reordered_records_are_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let file = log_with_records(tmp.path(), 4);
    let mut lines: Vec<String> = fs::read_to_string(&file)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    lines.swap(1, 2);
    fs::write(
        &file,
        lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
    )
    .unwrap();
    assert!(!verify_dir(tmp.path()).unwrap().ok);
}

#[test]
fn truncated_last_record_is_reported_once_and_logging_continues() {
    let tmp = tempfile::tempdir().unwrap();
    let file = log_with_records(tmp.path(), 3);
    let mut text = fs::read_to_string(&file).unwrap();
    text.truncate(text.len() - 10);
    fs::write(&file, &text).unwrap();

    let mut log = AuditLog::open(tmp.path()).unwrap();
    assert!(log.integrity_issue().is_some());
    // Poslední platný je záznam 2; zápis pokračuje v novém souboru.
    assert_eq!(log.append("after-crash", json!({}), true).unwrap(), 3);
    drop(log);
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        text,
        "the damaged file is kept as is"
    );
    assert!(tmp.path().join("audit-000002.jsonl").exists());

    let reopened = AuditLog::open(tmp.path()).unwrap();
    assert!(reopened.integrity_issue().is_none(), "reported only once");
    let report = verify_dir(tmp.path()).unwrap();
    assert!(!report.ok, "the damaged line must stay visible");
    assert_eq!(report.problems.len(), 1, "{report:?}");
    assert_eq!(report.records, 3);
}

#[test]
fn broken_chain_is_sealed_and_the_new_file_links_to_the_last_record() {
    let tmp = tempfile::tempdir().unwrap();
    let file = log_with_records(tmp.path(), 4);
    let text = fs::read_to_string(&file).unwrap();
    fs::write(&file, text.replacen("\"i\":1", "\"i\":9", 1)).unwrap();

    let mut log = AuditLog::open(tmp.path()).unwrap();
    let issue = log.integrity_issue().unwrap().to_string();
    assert!(issue.contains("chain broken at seq 3"), "{issue}");
    assert_eq!(log.append("next", json!({}), true).unwrap(), 5);
    drop(log);

    assert!(
        AuditLog::open(tmp.path())
            .unwrap()
            .integrity_issue()
            .is_none()
    );
    let report = verify_dir(tmp.path()).unwrap();
    // Jen původní přetržení; nový soubor na řetěz navazuje.
    assert_eq!(report.problems.len(), 1, "{report:?}");
    assert_eq!(report.files, 2);
}
