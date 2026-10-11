//! Kontrola souborového systému na neškodných datech v dočasné složce.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;
use std::time::{Duration, Instant};

use antishield_core::testvectors::{eicar, synthetic_sample};
use antishield_core::{EngineError, ScanEvent, ScanOutcome, ScanRequest};
use common::{engine, finding_rules, marker, scan, skipped_reasons, write};

fn request(root: &std::path::Path) -> ScanRequest {
    ScanRequest::new(vec![root.to_path_buf()])
}

#[test]
fn detects_test_samples_and_explains_them() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("eicar.com"), &eicar());
    write(
        &root.join("nested/deeper/synthetic.bin"),
        &synthetic_sample(2),
    );
    let mut with_marker = vec![b'.'; 3000];
    with_marker.extend_from_slice(&marker());
    write(&root.join("marker.dat"), &with_marker);
    write(&root.join("clean.txt"), b"hello");
    write(&root.join("empty.txt"), b"");

    let engine = engine(&tmp.path().join("state"));
    let (_, summary) = scan(&engine, request(&root));
    assert_eq!(summary.outcome, ScanOutcome::Completed);
    assert_eq!(summary.files_scanned, 5);
    assert_eq!(
        finding_rules(&summary, "eicar.com"),
        ["HH-TEST-EICAR", "HH-TEST-EICAR-SHA256"]
    );
    assert_eq!(
        finding_rules(&summary, "synthetic.bin"),
        ["HH-TEST-SYNTH-0002"]
    );
    assert_eq!(
        finding_rules(&summary, "marker.dat"),
        ["HH-TEST-MARKER-0001"]
    );
    assert!(finding_rules(&summary, "clean.txt").is_empty());
    assert!(finding_rules(&summary, "empty.txt").is_empty());
    for finding in &summary.findings {
        assert!(finding.test_only);
        assert!(!finding.rule_description.is_empty());
        assert_eq!(finding.evidence.len(), 1);
        assert_eq!(finding.sha256.len(), 64);
    }
}

#[test]
fn events_arrive_in_order_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("eicar.com"), &eicar());
    let engine = engine(&tmp.path().join("state"));
    let (events, _) = scan(&engine, request(&root));
    assert!(matches!(events.first(), Some(ScanEvent::Started { .. })));
    assert!(matches!(events.last(), Some(ScanEvent::Finished { .. })));
    let finished = events
        .iter()
        .filter(|e| matches!(e, ScanEvent::Finished { .. }))
        .count();
    let started = events
        .iter()
        .filter(|e| matches!(e, ScanEvent::Started { .. }))
        .count();
    assert_eq!((started, finished), (1, 1));
    let findings = events
        .iter()
        .filter(|e| matches!(e, ScanEvent::FindingDetected { .. }))
        .count();
    assert_eq!(findings, 2);
}

#[test]
fn archives_are_not_expanded_but_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    // Minimální ZIP se „stored“ položkou obsahující EICAR: obsah se nerozbaluje.
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&[0u8; 26]);
    zip.extend_from_slice(&eicar());
    write(&root.join("archive.zip"), &zip);
    let engine = engine(&tmp.path().join("state"));
    let (_, summary) = scan(&engine, request(&root));
    assert!(summary.findings.is_empty());
    assert_eq!(summary.archives_not_inspected, 1);
}

#[test]
fn oversized_files_are_skipped_without_reading() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    fs::create_dir_all(&root).unwrap();
    // Řídký soubor 5 GiB: na disk se skutečně nezapíše.
    let big = fs::File::create(root.join("big.bin")).unwrap();
    big.set_len(5 * 1024 * 1024 * 1024).unwrap();
    let engine = engine(&tmp.path().join("state"));
    let started = Instant::now();
    let (_, summary) = scan(&engine, request(&root));
    assert_eq!(skipped_reasons(&summary, "big.bin"), ["tooLarge"]);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn custom_size_limit_is_respected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("eicar.com"), &eicar());
    let engine = engine(&tmp.path().join("state"));
    let mut req = request(&root);
    req.limits.max_file_size_bytes = 10;
    let (_, summary) = scan(&engine, req);
    assert!(summary.findings.is_empty());
    assert_eq!(skipped_reasons(&summary, "eicar.com"), ["tooLarge"]);
}

#[cfg(unix)]
#[test]
fn symlinks_fifos_and_sockets_are_never_followed_or_read() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    let outside = tmp.path().join("outside");
    write(&outside.join("eicar.com"), &eicar());
    write(&root.join("plain.txt"), b"x");
    symlink(outside.join("eicar.com"), root.join("link-file")).unwrap();
    symlink(&outside, root.join("link-dir")).unwrap();
    symlink(root.join("self-loop"), root.join("self-loop")).unwrap();
    let fifo = std::ffi::CString::new(root.join("pipe").to_str().unwrap()).unwrap();
    // SAFETY: platná cesta zakončená NUL.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
    assert_eq!(rc, 0);
    let _socket = std::os::unix::net::UnixListener::bind(root.join("sock")).unwrap();

    let engine = engine(&tmp.path().join("state"));
    let started = Instant::now();
    let (_, summary) = scan(&engine, request(&root));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "FIFO must not block the scan"
    );
    assert!(
        summary.findings.is_empty(),
        "nothing outside the root may be read"
    );
    assert_eq!(skipped_reasons(&summary, "link-file"), ["symlink"]);
    assert_eq!(skipped_reasons(&summary, "link-dir"), ["symlink"]);
    assert_eq!(skipped_reasons(&summary, "self-loop"), ["symlink"]);
    assert_eq!(skipped_reasons(&summary, "pipe"), ["notRegularFile"]);
    assert_eq!(skipped_reasons(&summary, "sock"), ["notRegularFile"]);
    assert_eq!(summary.files_scanned, 1);
}

#[cfg(unix)]
#[test]
fn unreadable_files_are_reported_and_the_scan_continues() {
    use std::os::unix::fs::PermissionsExt;
    // Root čte všechno; test má smysl jen pod běžným uživatelem.
    #[allow(unsafe_code)]
    let running_as_root = unsafe { libc::geteuid() } == 0;
    if running_as_root {
        eprintln!("skipped: running as root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("locked.txt"), b"secret");
    write(&root.join("eicar.com"), &eicar());
    fs::set_permissions(root.join("locked.txt"), fs::Permissions::from_mode(0o000)).unwrap();
    let engine = engine(&tmp.path().join("state"));
    let (_, summary) = scan(&engine, request(&root));
    assert_eq!(
        skipped_reasons(&summary, "locked.txt"),
        ["permissionDenied"]
    );
    assert_eq!(summary.findings.len(), 2);
}

#[cfg(unix)]
#[test]
fn hardlinks_are_read_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("a.bin"), &synthetic_sample(1));
    fs::hard_link(root.join("a.bin"), root.join("b.bin")).unwrap();
    let engine = engine(&tmp.path().join("state"));
    let (_, summary) = scan(&engine, request(&root));
    assert_eq!(summary.files_scanned, 1);
    assert_eq!(summary.findings.len(), 1);
}

#[test]
fn unusual_names_and_deep_paths_are_reported_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    let names = [
        "mezera v názvu.bin",
        "-začíná-pomlčkou.bin",
        "emoji-🛡️.bin",
        "Příliš žluťoučký kůň.bin",
    ];
    for name in names {
        write(&root.join(name), &eicar());
    }
    #[cfg(unix)]
    write(&root.join("nový\nřádek.bin"), &eicar());
    // macOS cestu delší než PATH_MAX (1024 B) neumí vytvořit ani otevřít;
    // jinde ověřujeme i cesty delší než 1024 B.
    let limit = if cfg!(target_os = "macos") { 1000 } else { 1500 };
    let mut deep = root.clone();
    let mut i = 0;
    while deep.as_os_str().len() + 40 < limit {
        deep.push(format!("slozka-{i:02}-s-dlouhym-nazvem"));
        i += 1;
    }
    write(&deep.join("hluboko.bin"), &eicar());
    if !cfg!(target_os = "macos") {
        assert!(deep.as_os_str().len() > 1024);
    }

    let engine = engine(&tmp.path().join("state"));
    let (_, summary) = scan(&engine, request(&root));
    for name in names {
        assert_eq!(finding_rules(&summary, name).len(), 2, "{name}");
    }
    assert_eq!(finding_rules(&summary, "hluboko.bin").len(), 2);
    assert!(summary.skipped_total == 0, "{:?}", summary.skipped_sample);
}

#[test]
fn depth_limit_is_respected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("a/b/c/eicar.com"), &eicar());
    let engine = engine(&tmp.path().join("state"));
    let mut req = request(&root);
    req.limits.max_depth = 2;
    let (_, summary) = scan(&engine, req);
    assert!(summary.findings.is_empty());
}

#[test]
fn file_roots_and_missing_roots() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("single.com");
    write(&file, &eicar());
    let missing = tmp.path().join("missing");
    let engine = engine(&tmp.path().join("state"));
    let (_, summary) = scan(&engine, ScanRequest::new(vec![file, missing]));
    assert_eq!(summary.findings.len(), 2);
    assert_eq!(skipped_reasons(&summary, "missing"), ["notFound"]);
}

#[test]
fn many_files_and_cancellation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    for i in 0..4000 {
        write(
            &root.join(format!("d{}/f{i}.txt", i % 40)),
            format!("soubor {i}").as_bytes(),
        );
    }
    let engine = engine(&tmp.path().join("state"));

    let (_, summary) = scan(&engine, request(&root));
    assert_eq!(summary.outcome, ScanOutcome::Completed);
    assert_eq!(summary.files_scanned, 4000);

    let (observer, rx) = common::collector();
    let handle = engine.start_scan(request(&root), observer).unwrap();
    handle.cancel();
    let cancelled_at = Instant::now();
    let (_, summary) = common::collect(&rx);
    assert_eq!(summary.outcome, ScanOutcome::Cancelled);
    assert!(cancelled_at.elapsed() < Duration::from_millis(2500));
    assert!(summary.files_scanned <= 4000);
}

#[test]
fn only_one_scan_runs_at_a_time() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    for i in 0..2000 {
        write(&root.join(format!("f{i}.txt")), b"x");
    }
    let engine = engine(&tmp.path().join("state"));
    let (observer, rx) = common::collector();
    let first = engine.start_scan(request(&root), observer).unwrap();
    let (second_observer, _rx2) = common::collector();
    let second = engine.start_scan(request(&root), second_observer);
    if !first.is_finished() {
        assert!(matches!(second, Err(EngineError::ScanAlreadyRunning)));
    }
    let _ = common::collect(&rx);
}

#[test]
fn invalid_requests_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = engine(&tmp.path().join("state"));
    let (observer, _rx) = common::collector();
    assert!(matches!(
        engine.start_scan(ScanRequest::new(vec![]), observer.clone()),
        Err(EngineError::InvalidRequest(_))
    ));
    assert!(matches!(
        engine.start_scan(
            ScanRequest::new(vec!["relative/path".into()]),
            observer.clone()
        ),
        Err(EngineError::InvalidRequest(_))
    ));
    let mut req = ScanRequest::new(vec![tmp.path().to_path_buf()]);
    req.limits.worker_threads = 0;
    assert!(matches!(
        engine.start_scan(req, observer),
        Err(EngineError::InvalidRequest(_))
    ));
}

#[test]
fn scans_are_written_to_the_audit_log() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("eicar.com"), &eicar());
    let state = tmp.path().join("state");
    let engine = engine(&state);
    let _ = scan(&engine, request(&root));
    let kinds: Vec<String> = engine
        .recent_audit_events(50)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    for kind in [
        "engine_started",
        "rule_pack_loaded",
        "self_test",
        "scan_started",
        "finding",
        "scan_finished",
    ] {
        assert!(
            kinds.iter().any(|k| k == kind),
            "missing {kind} in {kinds:?}"
        );
    }
    let report = antishield_core::audit::verify_dir(&state.join("audit")).unwrap();
    assert!(report.ok, "{report:?}");
}

#[test]
fn next_scan_starts_right_after_finished() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("data");
    write(&root.join("a.txt"), b"x");
    let engine = engine(&tmp.path().join("state"));
    // Po události Finished musí jít hned spustit další kontrola.
    for _ in 0..50 {
        let (observer, rx) = common::collector();
        engine.start_scan(request(&root), observer).unwrap();
        let (_, summary) = common::collect(&rx);
        assert_eq!(summary.outcome, ScanOutcome::Completed);
    }
}
