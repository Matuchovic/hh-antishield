//! Kontrola souborů ve vláknech.
//!
//! - Jedno vlákno prochází stromy (bez sledování symlinků, bez přechodu na jiný svazek).
//! - Pracovní vlákna čtou soubory po 1 MiB a porovnávají je s pravidly.
//! - Koordinátor jako jediný volá observer, hlídá zaseknuté čtení a ukončení.
//!
//! Engine soubory jen čte. Nic nemaže, nepřesouvá ani nespouští.

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use walkdir::WalkDir;

use crate::audit::AuditLog;
use crate::error::EngineError;
use crate::inspect::{CHUNK_SIZE, FileOutcome, Hooks, inspect_file};
use crate::platform;
use crate::rules::RulePack;
use crate::types::{
    Finding, FindingOrigin, ScanEvent, ScanLimits, ScanOutcome, ScanProgress, ScanRequest,
    ScanSummary, SkipCount, SkipReason, SkippedItem,
};
use crate::{ENGINE_VERSION, now_ms};

/// Příjemce událostí kontroly. Volá se jen z vlákna koordinátora, v pořadí
/// `Started`, `Progress`/`FindingDetected`, `Finished` (přesně jednou).
pub trait ScanObserver: Send + Sync {
    fn on_event(&self, event: ScanEvent);
}

/// Ovladač běžící kontroly.
#[derive(Debug, Clone)]
pub struct ScanHandle {
    scan_id: String,
    cancel: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl ScanHandle {
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    /// Jen nastaví příznak. Kontrola skončí po rozpracovaném bloku.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }
}

pub(crate) struct ScanContext {
    pub rules: Arc<RulePack>,
    pub audit: Arc<Mutex<AuditLog>>,
    pub audit_healthy: Arc<AtomicBool>,
    pub running: Arc<AtomicBool>,
}

const QUEUE_CAPACITY: usize = 512;
const TICK: Duration = Duration::from_millis(50);
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const CANCEL_GRACE: Duration = Duration::from_secs(2);
const MAX_SKIPPED_SAMPLE: usize = 100;
const MAX_WORKER_REPLACEMENTS: usize = 4;
const MAX_ROOTS: usize = 256;
const MAX_WORKERS: usize = 16;

pub(crate) fn validate_request(request: &ScanRequest) -> Result<(), EngineError> {
    let limits = &request.limits;
    if request.roots.is_empty() || request.roots.len() > MAX_ROOTS {
        return Err(EngineError::InvalidRequest(format!(
            "between 1 and {MAX_ROOTS} roots are required"
        )));
    }
    if request.roots.iter().any(|r| !r.is_absolute()) {
        return Err(EngineError::InvalidRequest(
            "roots must be absolute paths".into(),
        ));
    }
    if limits.worker_threads == 0 || limits.worker_threads > MAX_WORKERS {
        return Err(EngineError::InvalidRequest(format!(
            "worker_threads must be 1..={MAX_WORKERS}"
        )));
    }
    if limits.stall_timeout_ms < 100 || limits.max_depth == 0 {
        return Err(EngineError::InvalidRequest(
            "stall_timeout_ms must be >= 100 and max_depth >= 1".into(),
        ));
    }
    Ok(())
}

/// Spustí kontrolu ve vlastním vlákně a hned vrátí ovladač.
pub(crate) fn spawn_scan(
    ctx: ScanContext,
    request: ScanRequest,
    observer: Arc<dyn ScanObserver>,
) -> Result<ScanHandle, EngineError> {
    validate_request(&request)?;
    if ctx.running.swap(true, Ordering::SeqCst) {
        return Err(EngineError::ScanAlreadyRunning);
    }
    let handle = ScanHandle {
        scan_id: uuid::Uuid::new_v4().to_string(),
        cancel: Arc::new(AtomicBool::new(false)),
        finished: Arc::new(AtomicBool::new(false)),
    };
    let thread_handle = handle.clone();
    let running = ctx.running.clone();
    let spawned = thread::Builder::new()
        .name("antishield-scan".into())
        .spawn(move || {
            let started_at_ms = now_ms();
            let finished_sent = Arc::new(AtomicBool::new(false));
            let result = catch_unwind(AssertUnwindSafe(|| {
                run_scan(
                    &ctx,
                    &request,
                    observer.as_ref(),
                    &thread_handle,
                    &finished_sent,
                )
            }));
            // Bez závěrečné události skončí run_scan jen pádem. Pak uvolníme
            // stav a pošleme selhání, aby Finished přišlo vždy právě jednou.
            if result.is_err() && !finished_sent.load(Ordering::SeqCst) {
                let summary = ScanSummary {
                    scan_id: thread_handle.scan_id.clone(),
                    outcome: ScanOutcome::Failed {
                        reason: "internal error in the scan coordinator".into(),
                    },
                    roots: display_roots(&request.roots),
                    started_at_ms,
                    finished_at_ms: now_ms(),
                    files_scanned: 0,
                    bytes_scanned: 0,
                    archives_not_inspected: 0,
                    yara_incomplete: 0,
                    findings: Vec::new(),
                    skipped_total: 0,
                    skipped_by_reason: Vec::new(),
                    skipped_sample: Vec::new(),
                    rule_pack: ctx.rules.info().clone(),
                    engine_version: ENGINE_VERSION.to_string(),
                };
                release(&ctx, &thread_handle);
                observer.on_event(ScanEvent::Finished {
                    scan_id: thread_handle.scan_id.clone(),
                    summary,
                });
            }
        });
    if let Err(err) = spawned {
        running.store(false, Ordering::SeqCst);
        return Err(EngineError::Io(err));
    }
    Ok(handle)
}

fn display_roots(roots: &[PathBuf]) -> Vec<String> {
    roots.iter().map(|p| p.display().to_string()).collect()
}

struct WorkItem {
    id: u64,
    path: PathBuf,
}

enum Msg {
    Finding(Box<Finding>),
    Skipped(SkippedItem),
    Done {
        item_id: u64,
        scanned: bool,
        archive: bool,
        yara_incomplete: bool,
    },
    WalkerDone,
}

/// Stav jednoho pracovního vlákna, který čte koordinátor.
struct Slot {
    /// ID právě zpracovávané položky (0 = žádná). Kdo ji první vynuluje, ten ji „vlastní“.
    item: AtomicU64,
    last_progress_ms: AtomicU64,
    abandoned: AtomicBool,
    path: Mutex<Option<String>>,
}

impl Slot {
    fn new() -> Self {
        Self {
            item: AtomicU64::new(0),
            last_progress_ms: AtomicU64::new(0),
            abandoned: AtomicBool::new(false),
            path: Mutex::new(None),
        }
    }

    fn set_path(&self, value: Option<String>) {
        let mut guard = match self.path.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = value;
    }

    fn path(&self) -> Option<String> {
        match self.path.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

struct Shared {
    cancel: Arc<AtomicBool>,
    abort: AtomicBool,
    queued: AtomicU64,
    bytes: AtomicU64,
    walker_progress_ms: AtomicU64,
    epoch: Instant,
    limits: ScanLimits,
    stay_on_volume: bool,
    rules: Arc<RulePack>,
    origins: HashMap<PathBuf, FindingOrigin>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || self.abort.load(Ordering::Relaxed)
    }

    fn touch_walker(&self) {
        self.walker_progress_ms
            .store(self.now_ms(), Ordering::Relaxed);
    }
}

#[derive(Default)]
struct Tally {
    findings: Vec<Finding>,
    skipped_total: u64,
    skipped_counts: HashMap<&'static str, u64>,
    skipped_sample: Vec<SkippedItem>,
    files_scanned: u64,
    archives: u64,
    yara_incomplete: u64,
    done_items: u64,
}

impl Tally {
    fn skip(&mut self, item: SkippedItem) {
        self.skipped_total += 1;
        *self.skipped_counts.entry(item.reason.code()).or_insert(0) += 1;
        if self.skipped_sample.len() < MAX_SKIPPED_SAMPLE {
            self.skipped_sample.push(item);
        }
    }
}

fn run_scan(
    ctx: &ScanContext,
    request: &ScanRequest,
    observer: &dyn ScanObserver,
    handle: &ScanHandle,
    finished_sent: &AtomicBool,
) {
    let scan_id = handle.scan_id.clone();
    let started_at_ms = now_ms();
    let roots = display_roots(&request.roots);
    let audit = |kind: &str, data: serde_json::Value, sync: bool| {
        let ok = match ctx.audit.lock() {
            Ok(mut log) => log.append(kind, data, sync).is_ok(),
            Err(_) => false,
        };
        if !ok {
            ctx.audit_healthy.store(false, Ordering::SeqCst);
        }
    };

    observer.on_event(ScanEvent::Started {
        scan_id: scan_id.clone(),
        roots: roots.clone(),
    });
    audit(
        "scan_started",
        json!({ "scanId": scan_id, "roots": roots, "limits": request.limits }),
        true,
    );

    let shared = Arc::new(Shared {
        cancel: handle.cancel.clone(),
        abort: AtomicBool::new(false),
        queued: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        walker_progress_ms: AtomicU64::new(0),
        epoch: Instant::now(),
        limits: request.limits.clone(),
        stay_on_volume: request.stay_on_volume,
        rules: ctx.rules.clone(),
        origins: request.origins.clone(),
    });

    let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem>(QUEUE_CAPACITY);
    let work_rx = Arc::new(Mutex::new(work_rx));
    let (msg_tx, msg_rx) = mpsc::channel::<Msg>();

    let mut tally = Tally::default();
    let mut walker_done = false;
    let mut outcome: Option<ScanOutcome> = None;

    {
        let shared = shared.clone();
        let msg_tx = msg_tx.clone();
        let roots = request.roots.clone();
        if let Err(err) = thread::Builder::new()
            .name("antishield-walk".into())
            .spawn(move || walker(&shared, &roots, &work_tx, &msg_tx))
        {
            outcome = Some(ScanOutcome::Failed {
                reason: format!("cannot start the directory walker: {err}"),
            });
            walker_done = true;
        }
    }

    let mut slots: Vec<Arc<Slot>> = Vec::new();
    let spawn_worker = |slots: &mut Vec<Arc<Slot>>| -> bool {
        let slot = Arc::new(Slot::new());
        let (shared, rx, tx, worker_slot) = (
            shared.clone(),
            work_rx.clone(),
            msg_tx.clone(),
            slot.clone(),
        );
        let spawned = thread::Builder::new()
            .name("antishield-worker".into())
            .spawn(move || worker(&shared, &rx, &tx, &worker_slot))
            .is_ok();
        if spawned {
            slots.push(slot);
        }
        spawned
    };
    for _ in 0..request.limits.worker_threads {
        spawn_worker(&mut slots);
    }
    if slots.is_empty() && outcome.is_none() {
        outcome = Some(ScanOutcome::Failed {
            reason: "cannot start worker threads".into(),
        });
        shared.abort.store(true, Ordering::SeqCst);
    }

    let mut abandoned: HashSet<u64> = HashSet::new();
    let mut replacements = 0usize;
    let mut last_progress = Instant::now()
        .checked_sub(PROGRESS_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut cancel_seen: Option<Instant> = None;
    shared.touch_walker();

    while outcome.is_none() {
        match msg_rx.recv_timeout(TICK) {
            Ok(Msg::Finding(finding)) => {
                audit(
                    "finding",
                    json!({
                        "scanId": scan_id,
                        "path": finding.path,
                        "sha256": finding.sha256,
                        "ruleId": finding.rule_id,
                        "ruleVersion": finding.rule_version,
                        "testOnly": finding.test_only,
                        "evidence": finding.evidence,
                    }),
                    true,
                );
                observer.on_event(ScanEvent::FindingDetected {
                    scan_id: scan_id.clone(),
                    finding: (*finding).clone(),
                });
                tally.findings.push(*finding);
            }
            Ok(Msg::Skipped(item)) => tally.skip(item),
            Ok(Msg::Done {
                item_id,
                scanned,
                archive,
                yara_incomplete,
            }) => {
                // Pozdní výsledek položky, kterou už koordinátor odepsal jako zaseknutou.
                if !abandoned.remove(&item_id) {
                    tally.done_items += 1;
                    tally.files_scanned += u64::from(scanned);
                    tally.archives += u64::from(archive);
                    tally.yara_incomplete += u64::from(yara_incomplete);
                }
            }
            Ok(Msg::WalkerDone) | Err(RecvTimeoutError::Disconnected) => walker_done = true,
            Err(RecvTimeoutError::Timeout) => {}
        }

        let now = shared.now_ms();
        let stall = shared.limits.stall_timeout_ms;

        // Zaseknuté čtení: položku odepsat, vlákno nechat doběhnout a nahradit ho.
        let mut lost_workers = 0usize;
        for slot in &slots {
            let item = slot.item.load(Ordering::SeqCst);
            if item == 0 || slot.abandoned.load(Ordering::SeqCst) {
                continue;
            }
            let last = slot.last_progress_ms.load(Ordering::SeqCst);
            if now.saturating_sub(last) <= stall {
                continue;
            }
            if slot
                .item
                .compare_exchange(item, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                slot.abandoned.store(true, Ordering::SeqCst);
                abandoned.insert(item);
                tally.done_items += 1;
                tally.skip(SkippedItem {
                    path: slot.path().unwrap_or_default(),
                    reason: SkipReason::Timeout { limit_ms: stall },
                });
                lost_workers += 1;
            }
        }
        for _ in 0..lost_workers {
            if replacements < MAX_WORKER_REPLACEMENTS && !shared.stopped() {
                replacements += 1;
                spawn_worker(&mut slots);
            }
        }
        let active_workers = slots
            .iter()
            .filter(|s| !s.abandoned.load(Ordering::SeqCst))
            .count();

        if last_progress.elapsed() >= PROGRESS_INTERVAL {
            last_progress = Instant::now();
            let current_path = slots
                .iter()
                .find(|s| s.item.load(Ordering::SeqCst) != 0)
                .and_then(|s| s.path());
            observer.on_event(ScanEvent::Progress {
                scan_id: scan_id.clone(),
                progress: ScanProgress {
                    files_scanned: tally.files_scanned,
                    bytes_scanned: shared.bytes.load(Ordering::Relaxed),
                    items_skipped: tally.skipped_total,
                    findings: tally.findings.len() as u64,
                    current_path,
                    elapsed_ms: now,
                },
            });
        }

        let cancelled = shared.cancel.load(Ordering::SeqCst);
        if walker_done && tally.done_items >= shared.queued.load(Ordering::SeqCst) {
            outcome = Some(if cancelled {
                ScanOutcome::Cancelled
            } else {
                ScanOutcome::Completed
            });
        } else if cancelled {
            let since = *cancel_seen.get_or_insert_with(Instant::now);
            if since.elapsed() >= CANCEL_GRACE {
                outcome = Some(ScanOutcome::Cancelled);
            }
        } else if !walker_done
            && now.saturating_sub(shared.walker_progress_ms.load(Ordering::Relaxed)) > stall
        {
            outcome = Some(ScanOutcome::Failed {
                reason: "directory traversal stopped responding".into(),
            });
        } else if active_workers == 0 {
            outcome = Some(ScanOutcome::Failed {
                reason: "too many files stopped responding".into(),
            });
        }
    }

    shared.abort.store(true, Ordering::SeqCst);
    let outcome = outcome.unwrap_or(ScanOutcome::Completed);

    // Doručit nálezy, které dorazily před ukončením.
    while let Ok(msg) = msg_rx.try_recv() {
        match msg {
            Msg::Finding(finding) => tally.findings.push(*finding),
            Msg::Skipped(item) => tally.skip(item),
            _ => {}
        }
    }

    let mut skipped_by_reason: Vec<SkipCount> = tally
        .skipped_counts
        .iter()
        .map(|(reason, count)| SkipCount {
            reason: (*reason).to_string(),
            count: *count,
        })
        .collect();
    skipped_by_reason.sort_by(|a, b| b.count.cmp(&a.count).then(a.reason.cmp(&b.reason)));

    let summary = ScanSummary {
        scan_id: scan_id.clone(),
        outcome: outcome.clone(),
        roots: roots.clone(),
        started_at_ms,
        finished_at_ms: now_ms(),
        files_scanned: tally.files_scanned,
        bytes_scanned: shared.bytes.load(Ordering::Relaxed),
        archives_not_inspected: tally.archives,
        yara_incomplete: tally.yara_incomplete,
        findings: tally.findings,
        skipped_total: tally.skipped_total,
        skipped_by_reason,
        skipped_sample: tally.skipped_sample,
        rule_pack: ctx.rules.info().clone(),
        engine_version: ENGINE_VERSION.to_string(),
    };
    audit(
        "scan_finished",
        json!({
            "scanId": scan_id,
            "outcome": outcome,
            "filesScanned": summary.files_scanned,
            "bytesScanned": summary.bytes_scanned,
            "findings": summary.findings.len(),
            "skipped": summary.skipped_total,
            "archivesNotInspected": summary.archives_not_inspected,
            "yaraIncomplete": summary.yara_incomplete,
            "durationMs": summary.finished_at_ms.saturating_sub(started_at_ms),
        }),
        true,
    );
    finished_sent.store(true, Ordering::SeqCst);
    // Uvolnit před závěrečnou událostí: kdo na Finished hned spustí další
    // kontrolu, nesmí dostat ScanAlreadyRunning.
    release(ctx, handle);
    observer.on_event(ScanEvent::Finished { scan_id, summary });
}

fn release(ctx: &ScanContext, handle: &ScanHandle) {
    handle.finished.store(true, Ordering::SeqCst);
    ctx.running.store(false, Ordering::SeqCst);
}

fn send_skip(tx: &Sender<Msg>, path: &Path, reason: SkipReason) {
    let _ = tx.send(Msg::Skipped(SkippedItem {
        path: path.display().to_string(),
        reason,
    }));
}

fn walker(
    shared: &Shared,
    roots: &[PathBuf],
    work_tx: &SyncSender<WorkItem>,
    msg_tx: &Sender<Msg>,
) {
    platform::prepare_scan_thread();
    let mut next_id: u64 = 1;
    let mut seen_hardlinks: HashSet<(u64, u64)> = HashSet::new();

    'roots: for root in roots {
        if shared.stopped() {
            break;
        }
        shared.touch_walker();
        // Kořen jednou převedeme na skutečnou cestu; pod ním už symlinky nesledujeme.
        let canonical = match std::fs::canonicalize(root) {
            Ok(path) => path,
            Err(err) => {
                send_skip(msg_tx, root, platform::classify_io_error(&err));
                continue;
            }
        };
        if let Ok(false) = platform::is_local_volume(&canonical) {
            send_skip(msg_tx, root, SkipReason::OtherVolume);
            continue;
        }
        let root_device = std::fs::metadata(&canonical)
            .ok()
            .and_then(|m| platform::device_id(&m));

        let walk = WalkDir::new(&canonical)
            .follow_links(false)
            .same_file_system(shared.stay_on_volume)
            .max_depth(shared.limits.max_depth);
        for entry in walk {
            if shared.stopped() {
                break 'roots;
            }
            shared.touch_walker();
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    let path = err.path().unwrap_or(root.as_path()).to_path_buf();
                    let reason = match err.io_error() {
                        Some(io_err) => platform::classify_io_error(io_err),
                        None => SkipReason::Symlink,
                    };
                    send_skip(msg_tx, &path, reason);
                    continue;
                }
            };
            let file_type = entry.file_type();
            let path = entry.path();
            if file_type.is_symlink() {
                send_skip(msg_tx, path, SkipReason::Symlink);
                continue;
            }
            if file_type.is_dir() {
                if shared.stay_on_volume
                    && entry.depth() > 0
                    && let (Some(root_dev), Ok(meta)) = (root_device, entry.metadata())
                    && platform::device_id(&meta).is_some_and(|dev| dev != root_dev)
                {
                    send_skip(msg_tx, path, SkipReason::OtherVolume);
                }
                continue;
            }
            if !file_type.is_file() {
                send_skip(msg_tx, path, SkipReason::NotRegularFile);
                continue;
            }
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(err) => {
                    let reason = err
                        .io_error()
                        .map(platform::classify_io_error)
                        .unwrap_or(SkipReason::NotFound);
                    send_skip(msg_tx, path, reason);
                    continue;
                }
            };
            if let Some(reason) = platform::precheck(path, &meta) {
                send_skip(msg_tx, path, reason);
                continue;
            }
            if let Some(key) = platform::hardlink_key(&meta)
                && !seen_hardlinks.insert(key)
            {
                continue;
            }
            let item = WorkItem {
                id: next_id,
                path: path.to_path_buf(),
            };
            next_id += 1;
            shared.queued.fetch_add(1, Ordering::SeqCst);
            if !send_work(shared, work_tx, item) {
                shared.queued.fetch_sub(1, Ordering::SeqCst);
                break 'roots;
            }
        }
    }
    let _ = msg_tx.send(Msg::WalkerDone);
}

/// Neblokující odeslání do fronty: při plné frontě čeká a průběžně kontroluje zrušení.
fn send_work(shared: &Shared, tx: &SyncSender<WorkItem>, mut item: WorkItem) -> bool {
    loop {
        match tx.try_send(item) {
            Ok(()) => return true,
            Err(TrySendError::Full(returned)) => {
                if shared.stopped() {
                    return false;
                }
                item = returned;
                shared.touch_walker();
                thread::sleep(Duration::from_millis(2));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

fn new_yara_scanner(shared: &Shared) -> Option<yara_x::Scanner<'_>> {
    shared.rules.yara().map(|rules| {
        let mut scanner = yara_x::Scanner::new(rules);
        scanner.set_timeout(Duration::from_millis(shared.limits.yara_timeout_ms));
        scanner
    })
}

fn worker(shared: &Shared, rx: &Mutex<Receiver<WorkItem>>, tx: &Sender<Msg>, slot: &Slot) {
    platform::prepare_scan_thread();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    // Jeden skener YARA na vlákno: jeho vytvoření není zadarmo.
    let mut yara = new_yara_scanner(shared);
    let mut content = Vec::new();
    loop {
        if slot.abandoned.load(Ordering::SeqCst) || shared.abort.load(Ordering::SeqCst) {
            return;
        }
        let received = {
            let guard = match rx.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.recv_timeout(Duration::from_millis(200))
        };
        let item = match received {
            Ok(item) => item,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if shared.stopped() {
            let _ = tx.send(Msg::Done {
                item_id: item.id,
                scanned: false,
                archive: false,
                yara_incomplete: false,
            });
            continue;
        }

        slot.set_path(Some(item.path.display().to_string()));
        slot.last_progress_ms
            .store(shared.now_ms(), Ordering::SeqCst);
        slot.item.store(item.id, Ordering::SeqCst);

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            scan_file(
                shared,
                &item.path,
                &mut buffer,
                &mut content,
                yara.as_mut(),
                slot,
            )
        }));
        if outcome.is_err() {
            // Po pádu nemusí být stav skeneru konzistentní.
            yara = new_yara_scanner(shared);
        }

        // Kdo položku první uvolní, ten ji vlastní. Pokud ji koordinátor mezitím
        // odepsal jako zaseknutou, vlákno skončí a výsledek zahodí.
        let owned = slot
            .item
            .compare_exchange(item.id, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        slot.set_path(None);
        if !owned {
            return;
        }

        let display = item.path.display().to_string();
        let (scanned, archive, yara_incomplete) = match outcome {
            Ok(FileOutcome::Scanned {
                findings,
                archive,
                yara_incomplete,
            }) => {
                for finding in findings {
                    let _ = tx.send(Msg::Finding(Box::new(finding)));
                }
                (true, archive, yara_incomplete)
            }
            Ok(FileOutcome::Skipped(reason)) => {
                let _ = tx.send(Msg::Skipped(SkippedItem {
                    path: display,
                    reason,
                }));
                (false, false, false)
            }
            Ok(FileOutcome::Cancelled) => (false, false, false),
            Err(panic) => {
                let message = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unexpected internal error".into());
                let _ = tx.send(Msg::Skipped(SkippedItem {
                    path: display,
                    reason: SkipReason::InternalError { message },
                }));
                (false, false, false)
            }
        };
        let _ = tx.send(Msg::Done {
            item_id: item.id,
            scanned,
            archive,
            yara_incomplete,
        });
    }
}

fn scan_file(
    shared: &Shared,
    path: &Path,
    buffer: &mut [u8],
    content: &mut Vec<u8>,
    yara: Option<&mut yara_x::Scanner<'_>>,
    slot: &Slot,
) -> FileOutcome {
    let stopped = || shared.stopped();
    let progress = |read: u64| {
        if read > 0 {
            shared.bytes.fetch_add(read, Ordering::Relaxed);
        }
        slot.last_progress_ms
            .store(shared.now_ms(), Ordering::SeqCst);
    };
    inspect_file(
        &shared.rules,
        &shared.limits,
        path,
        shared.origins.get(path),
        buffer,
        content,
        yara,
        &Hooks {
            stopped: &stopped,
            progress: &progress,
        },
    )
}
