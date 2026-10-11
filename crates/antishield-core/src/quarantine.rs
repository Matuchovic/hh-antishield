//! Karanténa: nalezený soubor se přesune do úložiště enginu a znehodnotí,
//! takže ho nejde omylem spustit ani znovu najít. Jde ho obnovit nebo smazat.
//!
//! Bezpečnostní zásady:
//! - Do karantény jde jen soubor, jehož obsah (SHA-256) a identita se od
//!   kontroly nezměnily. Jinak operace skončí chybou a soubor zůstane.
//! - Soubor se otevírá bez následování symbolických odkazů.
//! - Originál se smaže až po úplném a synchronizovaném zápisu kopie;
//!   když smazání selže, kopie se odstraní a nic se nezmění.
//! - Obnova nikdy nepřepíše existující soubor.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::EngineError;
use crate::now_ms;
use crate::platform::{self, OpenError};
use crate::types::{FileIdentity, Finding, Severity};

const KEY_LEN: usize = 32;
const CHUNK: usize = 1024 * 1024;
const MAX_ITEMS: usize = 10_000;
const MAX_META_BYTES: u64 = 64 * 1024;

/// Položka v karanténě, jak ji vidí rozhraní.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at_ms: u64,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub test_only: bool,
}

/// Metadata na disku (obsahuje i klíč pro znehodnocení obsahu).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredItem {
    id: String,
    original_path: String,
    sha256: String,
    size: u64,
    quarantined_at_ms: u64,
    rule_id: String,
    rule_name: String,
    severity: Severity,
    test_only: bool,
    key_hex: String,
    #[serde(default)]
    mode: Option<u32>,
}

impl StoredItem {
    fn public(&self) -> QuarantineItem {
        QuarantineItem {
            id: self.id.clone(),
            original_path: self.original_path.clone(),
            sha256: self.sha256.clone(),
            size: self.size,
            quarantined_at_ms: self.quarantined_at_ms,
            rule_id: self.rule_id.clone(),
            rule_name: self.rule_name.clone(),
            severity: self.severity,
            test_only: self.test_only,
        }
    }
}

#[derive(Debug)]
pub struct Quarantine {
    dir: PathBuf,
}

fn changed(message: &str) -> EngineError {
    EngineError::FileChanged(message.to_string())
}

fn xor_in_place(data: &mut [u8], key: &[u8; KEY_LEN], offset: u64) {
    for (i, byte) in data.iter_mut().enumerate() {
        let position = (offset + i as u64) as usize % KEY_LEN;
        *byte ^= key[position];
    }
}

fn new_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key
}

fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn valid_id(id: &str) -> bool {
    id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// Stejný soubor jako při kontrole (bez ohledu na ctime, který mění i xattr)?
fn same_file(expected: &FileIdentity, now: &FileIdentity) -> bool {
    expected.size == now.size
        && expected.modified_sec == now.modified_sec
        && expected.modified_nsec == now.modified_nsec
        && expected.device == now.device
        && expected.inode == now.inode
}

#[cfg(unix)]
fn file_mode(meta: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_meta: &fs::Metadata) -> Option<u32> {
    None
}

impl Quarantine {
    pub fn open(dir: &Path) -> Result<Self, EngineError> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn paths(&self, id: &str) -> (PathBuf, PathBuf) {
        (
            self.dir.join(format!("{id}.bin")),
            self.dir.join(format!("{id}.json")),
        )
    }

    /// Je úložiště zapisovatelné? (pro stav komponenty)
    pub fn is_healthy(&self) -> bool {
        let probe = self.dir.join(".probe");
        let ok = create_private(&probe).is_ok() || probe.exists();
        let _ = fs::remove_file(&probe);
        ok
    }

    /// Přesune nalezený soubor do karantény.
    pub fn add(&self, finding: &Finding) -> Result<QuarantineItem, EngineError> {
        let path = Path::new(&finding.path);
        if !path.is_absolute() {
            return Err(EngineError::InvalidRequest("path must be absolute".into()));
        }
        let (mut source, meta) = match platform::open_regular(path) {
            Ok(opened) => opened,
            Err(OpenError::NotRegular) => return Err(changed("not a regular file any more")),
            Err(OpenError::Io(err)) => return Err(EngineError::Io(err)),
        };
        if !same_file(&finding.identity, &platform::identity(&meta)) {
            return Err(changed("the file changed after the scan"));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let (bin_path, json_path) = self.paths(&id);
        let key = new_key();
        let result = (|| -> Result<StoredItem, EngineError> {
            let mut out = create_private(&bin_path)?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; CHUNK];
            let mut offset = 0u64;
            loop {
                let read = match source.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err.into()),
                };
                hasher.update(&buffer[..read]);
                xor_in_place(&mut buffer[..read], &key, offset);
                out.write_all(&buffer[..read])?;
                offset += read as u64;
            }
            out.sync_all()?;
            if hex::encode(hasher.finalize()) != finding.sha256 || offset != finding.identity.size {
                return Err(changed("the file content changed after the scan"));
            }
            let stored = StoredItem {
                id: id.clone(),
                original_path: finding.path.clone(),
                sha256: finding.sha256.clone(),
                size: offset,
                quarantined_at_ms: now_ms(),
                rule_id: finding.rule_id.clone(),
                rule_name: finding.rule_name.clone(),
                severity: finding.severity,
                test_only: finding.test_only,
                key_hex: hex::encode(key),
                mode: file_mode(&meta),
            };
            let mut json = create_private(&json_path)?;
            json.write_all(&serde_json::to_vec_pretty(&stored).map_err(io::Error::other)?)?;
            json.sync_all()?;
            Ok(stored)
        })();

        let stored = match result {
            Ok(stored) => stored,
            Err(err) => {
                let _ = fs::remove_file(&bin_path);
                let _ = fs::remove_file(&json_path);
                return Err(err);
            }
        };

        // Smazat originál, jen pokud na cestě pořád leží stejný soubor.
        let still_same = fs::symlink_metadata(path)
            .map(|now| same_file(&finding.identity, &platform::identity(&now)))
            .unwrap_or(false);
        let removed = if still_same {
            drop(source);
            fs::remove_file(path).map_err(EngineError::Io)
        } else {
            Err(changed("the file was replaced during quarantine"))
        };
        if let Err(err) = removed {
            let _ = fs::remove_file(&bin_path);
            let _ = fs::remove_file(&json_path);
            return Err(err);
        }
        Ok(stored.public())
    }

    fn read_item(&self, id: &str) -> Result<StoredItem, EngineError> {
        if !valid_id(id) {
            return Err(EngineError::QuarantineItemNotFound(id.to_string()));
        }
        let (_, json_path) = self.paths(id);
        let mut text = Vec::new();
        File::open(&json_path)
            .map_err(|_| EngineError::QuarantineItemNotFound(id.to_string()))?
            .take(MAX_META_BYTES)
            .read_to_end(&mut text)?;
        let item: StoredItem = serde_json::from_slice(&text)
            .map_err(|e| EngineError::Io(io::Error::other(format!("quarantine metadata: {e}"))))?;
        if item.id != id {
            return Err(EngineError::QuarantineItemNotFound(id.to_string()));
        }
        Ok(item)
    }

    /// Položky v karanténě, nejnovější první.
    pub fn list(&self) -> Result<Vec<QuarantineItem>, EngineError> {
        let mut items = Vec::new();
        for entry in fs::read_dir(&self.dir)?.flatten().take(MAX_ITEMS * 2) {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json")
                && let Ok(item) = self.read_item(id)
            {
                items.push(item.public());
            }
        }
        items.sort_by_key(|item| std::cmp::Reverse(item.quarantined_at_ms));
        Ok(items)
    }

    /// Vrátí soubor na původní místo. Existující soubor nikdy nepřepíše.
    pub fn restore(&self, id: &str) -> Result<QuarantineItem, EngineError> {
        let item = self.read_item(id)?;
        let target = PathBuf::from(&item.original_path);
        if fs::symlink_metadata(&target).is_ok() {
            return Err(EngineError::RestoreConflict(item.original_path.clone()));
        }
        let parent = target
            .parent()
            .ok_or_else(|| EngineError::InvalidRequest("original path has no parent".into()))?;
        let key: [u8; KEY_LEN] = hex::decode(&item.key_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| EngineError::Io(io::Error::other("quarantine key is damaged")))?;
        let (bin_path, json_path) = self.paths(id);
        let temp = parent.join(format!(".antishield-restore-{id}"));
        let result = (|| -> Result<(), EngineError> {
            let mut input = File::open(&bin_path)?;
            let mut out = create_private(&temp)?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; CHUNK];
            let mut offset = 0u64;
            loop {
                let read = match input.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err.into()),
                };
                xor_in_place(&mut buffer[..read], &key, offset);
                hasher.update(&buffer[..read]);
                out.write_all(&buffer[..read])?;
                offset += read as u64;
            }
            out.sync_all()?;
            if hex::encode(hasher.finalize()) != item.sha256 {
                return Err(EngineError::Io(io::Error::other(
                    "quarantined content is damaged",
                )));
            }
            #[cfg(unix)]
            if let Some(mode) = item.mode {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temp, fs::Permissions::from_mode(mode & 0o777))?;
            }
            // Bez přepsání: když mezitím vznikl soubor se stejným jménem, skončit.
            if fs::symlink_metadata(&target).is_ok() {
                return Err(EngineError::RestoreConflict(item.original_path.clone()));
            }
            fs::rename(&temp, &target)?;
            Ok(())
        })();
        if let Err(err) = result {
            let _ = fs::remove_file(&temp);
            return Err(err);
        }
        let _ = fs::remove_file(&bin_path);
        let _ = fs::remove_file(&json_path);
        Ok(item.public())
    }

    /// Trvale smaže položku z karantény.
    pub fn delete(&self, id: &str) -> Result<QuarantineItem, EngineError> {
        let item = self.read_item(id)?;
        let (bin_path, json_path) = self.paths(id);
        fs::remove_file(&bin_path)?;
        fs::remove_file(&json_path)?;
        Ok(item.public())
    }
}
