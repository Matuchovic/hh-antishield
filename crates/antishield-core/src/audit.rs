//! Auditní log: JSON Lines s hashovým řetězením.
//!
//! Každý záznam nese SHA-256 předchozího řádku (`prev`), takže úprava,
//! vynechání nebo přehození záznamu je při ověření vidět. Útočník se stejnými
//! právy ale může přepsat celý log; to řeší až zápis privilegovanou komponentou
//! nebo odesílání na server v dalších verzích.
//!
//! Zapisovat smí jen jeden proces (výhradní zámek); dva zapisovatelé by
//! navazovali na stejný záznam a řetěz by se přetrhl. Poškozený soubor (useknutý
//! zápis po pádu, přetržený řetěz) se při otevření uzavře a zápis pokračuje
//! v novém souboru navázaném na poslední platný záznam. Problém se tak ohlásí
//! jednou, ověření celého logu ho ale ukazuje dál.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::EngineError;
use crate::now_ms;
use crate::types::AuditEvent;

pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
pub const KEEP_FILES: usize = 5;
/// Soubor větší než tento limit se při otevření nečte celý (poškození nebo útok).
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const LOCK_FILE: &str = "audit.lock";
/// Jak dlouho počkat, než log uvolní jiný proces (např. končící instance při restartu).
const LOCK_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    seq: u64,
    ts_ms: u64,
    kind: String,
    data: serde_json::Value,
    prev: String,
}

fn hash_hex(line: &[u8]) -> String {
    hex::encode(Sha256::digest(line))
}

fn file_name(index: u32) -> String {
    format!("audit-{index:06}.jsonl")
}

/// Seznam souborů logu seřazený podle pořadového čísla.
fn list_files(dir: &Path) -> Result<Vec<(u32, PathBuf)>, EngineError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(number) = name
            .strip_prefix("audit-")
            .and_then(|rest| rest.strip_suffix(".jsonl"))
        else {
            continue;
        };
        if let Ok(index) = number.parse::<u32>() {
            files.push((index, entry.path()));
        }
    }
    files.sort_by_key(|(index, _)| *index);
    Ok(files)
}

fn read_limited(path: &Path) -> Result<Vec<u8>, EngineError> {
    let mut data = Vec::new();
    File::open(path)?
        .take(MAX_READ_BYTES + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_READ_BYTES {
        return Err(EngineError::Audit(format!(
            "{} is larger than {MAX_READ_BYTES} bytes",
            path.display()
        )));
    }
    Ok(data)
}

/// Výsledek čtení jednoho souboru logu.
struct ParsedFile {
    /// (záznam, hash jeho řádku)
    records: Vec<(Record, String)>,
    problems: Vec<String>,
}

fn parse_file(data: &[u8], name: &str) -> ParsedFile {
    let mut records = Vec::new();
    let mut problems = Vec::new();
    // Soubor nekončí znakem nového řádku: poslední zápis je useknutý.
    let truncated = !data.is_empty() && !data.ends_with(b"\n");
    let mut lines: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();
    // split na konci vrátí prázdný kus za posledním '\n'; useknutý řádek ponecháme jako problém.
    if lines.last().is_some_and(|last| last.is_empty()) {
        lines.pop();
    }
    let count = lines.len();
    for (i, line) in lines.into_iter().enumerate() {
        if truncated && i + 1 == count {
            problems.push(format!("{name}: the last record is truncated"));
            break;
        }
        match serde_json::from_slice::<Record>(line) {
            Ok(record) => records.push((record, hash_hex(line))),
            Err(err) => problems.push(format!(
                "{name}: line {} is not a valid record: {err}",
                i + 1
            )),
        }
    }
    ParsedFile { records, problems }
}

/// Výhradní zámek logu. Když ho drží jiný proces, počká nejvýš `wait`.
fn lock_dir(dir: &Path, wait: Duration) -> Result<File, EngineError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_FILE))?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(EngineError::Audit(
                    "the audit log is in use by another AntiShield process".into(),
                ));
            }
            // Souborový systém bez zámků (některé síťové disky): log jde
            // dál používat jako dřív, ochrana se kvůli tomu nevypíná.
            Err(TryLockError::Error(_)) => return Ok(file),
        }
    }
}

/// Smaže nejstarší soubory logu nad limit `KEEP_FILES` (jen podle přesného vzoru názvu).
fn prune(dir: &Path) -> Result<(), EngineError> {
    let files = list_files(dir)?;
    if files.len() > KEEP_FILES {
        for (_, old) in &files[..files.len() - KEEP_FILES] {
            fs::remove_file(old)?;
        }
    }
    Ok(())
}

/// Otevřený auditní log.
#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    file: File,
    index: u32,
    size: u64,
    last_hash: String,
    next_seq: u64,
    integrity_issue: Option<String>,
    /// Drží výhradní zámek logu po celou dobu otevření.
    _lock: File,
}

impl AuditLog {
    /// Otevře (nebo založí) log v adresáři `dir`. Když log používá jiný
    /// proces, chvíli počká; pak skončí chybou (dva zapisovatelé by ho poškodili).
    pub fn open(dir: &Path) -> Result<Self, EngineError> {
        Self::open_waiting(dir, LOCK_WAIT)
    }

    fn open_waiting(dir: &Path, wait: Duration) -> Result<Self, EngineError> {
        fs::create_dir_all(dir)?;
        restrict_dir_permissions(dir);
        let lock = lock_dir(dir, wait)?;
        let files = list_files(dir)?;
        let mut index = files.last().map_or(1, |(i, _)| *i);
        let mut last_hash = GENESIS.to_string();
        let mut next_seq = 1;
        let mut problems: Vec<String> = Vec::new();

        // Poslední platný záznam hledáme v aktuálním souboru, případně v předchozích
        // (aktuální soubor může být prázdný hned po rotaci).
        for (position, (file_index, path)) in files.iter().rev().enumerate() {
            let name = file_name(*file_index);
            let data = match read_limited(path) {
                Ok(data) => data,
                Err(err) => {
                    problems.push(err.to_string());
                    continue;
                }
            };
            let parsed = parse_file(&data, &name);
            if position == 0 {
                problems.extend(parsed.problems.iter().cloned());
                let mut prev: Option<&str> = None;
                for (record, line_hash) in &parsed.records {
                    if prev.is_some_and(|expected| record.prev != expected) {
                        problems.push(format!("{name}: chain broken at seq {}", record.seq));
                    }
                    prev = Some(line_hash);
                }
            }
            if let Some((record, hash)) = parsed.records.last() {
                last_hash = hash.clone();
                next_seq = record.seq + 1;
                break;
            }
        }

        // Poškozený soubor necháme, jak je (ověření celého logu ho ukáže),
        // a pokračujeme v novém souboru navázaném na poslední platný záznam.
        // Příští otevření tak stejný problém nehlásí znovu.
        let seal = !problems.is_empty();
        if seal {
            index += 1;
        }
        let path = dir.join(file_name(index));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        if seal {
            prune(dir)?;
        }
        let size = file.metadata()?.len();
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
            index,
            size,
            last_hash,
            next_seq,
            integrity_issue: (!problems.is_empty()).then(|| problems.join("; ")),
            _lock: lock,
        })
    }

    /// Popis problému s integritou nalezeného při otevření, jinak `None`.
    pub fn integrity_issue(&self) -> Option<&str> {
        self.integrity_issue.as_deref()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Připíše záznam. `sync` vynutí zápis na disk (nálezy, konec kontroly).
    pub fn append(
        &mut self,
        kind: &str,
        data: serde_json::Value,
        sync: bool,
    ) -> Result<u64, EngineError> {
        let record = Record {
            seq: self.next_seq,
            ts_ms: now_ms(),
            kind: kind.to_string(),
            data,
            prev: self.last_hash.clone(),
        };
        let line = serde_json::to_string(&record).map_err(|e| EngineError::Audit(e.to_string()))?;
        let line_len = line.len() as u64 + 1;
        if self.size > 0 && self.size + line_len > MAX_FILE_BYTES {
            self.rotate()?;
        }
        let mut bytes = line.into_bytes();
        let hash = hash_hex(&bytes);
        bytes.push(b'\n');
        self.file.write_all(&bytes)?;
        if sync {
            self.file.sync_data()?;
        }
        self.size += line_len;
        self.last_hash = hash;
        self.next_seq += 1;
        Ok(record.seq)
    }

    fn rotate(&mut self) -> Result<(), EngineError> {
        self.file.sync_data()?;
        self.index += 1;
        let path = self.dir.join(file_name(self.index));
        self.file = OpenOptions::new().create(true).append(true).open(path)?;
        self.size = 0;
        prune(&self.dir)
    }

    /// Posledních `limit` záznamů, nejnovější první.
    pub fn recent(&self, limit: usize) -> Result<Vec<AuditEvent>, EngineError> {
        let files = list_files(&self.dir)?;
        let mut events = Vec::new();
        for (index, path) in files.iter().rev() {
            let data = read_limited(path)?;
            let parsed = parse_file(&data, &file_name(*index));
            for (record, _) in parsed.records.into_iter().rev() {
                events.push(AuditEvent {
                    seq: record.seq,
                    ts_ms: record.ts_ms,
                    kind: record.kind,
                    data: record.data,
                });
                if events.len() >= limit {
                    return Ok(events);
                }
            }
        }
        Ok(events)
    }
}

#[cfg(unix)]
fn restrict_dir_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_dir: &Path) {}

/// Výsledek ověření celého logu.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub files: usize,
    pub records: u64,
    pub ok: bool,
    pub problems: Vec<String>,
}

/// Ověří řetězec napříč všemi soubory logu.
pub fn verify_dir(dir: &Path) -> Result<VerifyReport, EngineError> {
    let files = list_files(dir)?;
    let mut problems = Vec::new();
    let mut records = 0u64;
    let mut prev_hash: Option<String> = None;
    let mut prev_seq: Option<u64> = None;
    for (position, (index, path)) in files.iter().enumerate() {
        let name = file_name(*index);
        let data = read_limited(path)?;
        let parsed = parse_file(&data, &name);
        problems.extend(parsed.problems);
        for (i, (record, line_hash)) in parsed.records.iter().enumerate() {
            records += 1;
            let first_overall = position == 0 && i == 0;
            match &prev_hash {
                Some(expected) if &record.prev != expected => {
                    problems.push(format!("{name}: chain broken at seq {}", record.seq));
                }
                None if first_overall && *index == 1 && record.prev != GENESIS => {
                    problems.push(format!("{name}: the first record does not start the chain"));
                }
                _ => {}
            }
            if let Some(seq) = prev_seq
                && record.seq != seq + 1
            {
                problems.push(format!(
                    "{name}: sequence jumps from {seq} to {}",
                    record.seq
                ));
            }
            prev_hash = Some(line_hash.clone());
            prev_seq = Some(record.seq);
        }
    }
    Ok(VerifyReport {
        files: files.len(),
        records,
        ok: problems.is_empty(),
        problems,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_one_process_writes_the_log() {
        let tmp = tempfile::tempdir().unwrap();
        let mut first = AuditLog::open(tmp.path()).unwrap();
        first.append("first", json!({}), false).unwrap();

        let err = AuditLog::open_waiting(tmp.path(), Duration::from_millis(100)).unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");

        drop(first);
        // Krátké čekání: proces spouštěný souběžným testem může po fork držet
        // kopii zámku, než spustí svůj program.
        let mut second = AuditLog::open_waiting(tmp.path(), Duration::from_secs(5)).unwrap();
        assert!(second.integrity_issue().is_none());
        assert_eq!(second.append("second", json!({}), false).unwrap(), 2);
        assert!(verify_dir(tmp.path()).unwrap().ok);
    }
}
