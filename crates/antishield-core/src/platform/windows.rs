//! Windows: body přesměrování (symlinky, junctions) a cloudové zástupce
//! (OneDrive) se nečtou. Jen standardní knihovna, konstanty z Win32 API.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::types::{FileIdentity, SkipReason};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_SHARE_DELETE: u32 = 0x4;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
/// Rozdíl mezi epochou Windows (1601) a UNIX (1970) ve 100ns jednotkách.
const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

pub fn precheck(_path: &Path, meta: &Metadata) -> Option<SkipReason> {
    let attrs = meta.file_attributes();
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Some(SkipReason::Symlink);
    }
    if attrs
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
    {
        return Some(SkipReason::NotDownloaded);
    }
    None
}

/// Otevře přímo bod přesměrování (nenásleduje ho) a nebrání ostatním
/// programům v práci se souborem.
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

pub fn is_reparse_point(meta: &Metadata) -> bool {
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn split_filetime(value: u64) -> (i64, u32) {
    let since_unix = value.saturating_sub(EPOCH_DIFF_100NS);
    let secs = i64::try_from(since_unix / 10_000_000).unwrap_or(i64::MAX);
    let nsec = u32::try_from((since_unix % 10_000_000) * 100).unwrap_or(0);
    (secs, nsec)
}

/// Číslo souboru a svazku je ve standardní knihovně zatím nestabilní;
/// ve v0.1 se proto identita skládá jen z velikosti a časů.
pub fn identity(meta: &Metadata) -> FileIdentity {
    let (modified_sec, modified_nsec) = split_filetime(meta.last_write_time());
    let (changed_sec, changed_nsec) = split_filetime(meta.creation_time());
    FileIdentity {
        device: 0,
        inode: 0,
        size: meta.file_size(),
        modified_sec,
        modified_nsec,
        changed_sec,
        changed_nsec,
    }
}

pub fn hardlink_key(_meta: &Metadata) -> Option<(u64, u64)> {
    None
}

pub fn device_id(_meta: &Metadata) -> Option<u64> {
    None
}

pub fn prepare_scan_thread() {}

/// ERROR_CANT_ACCESS_FILE (1920) vrací otevření některých bodů přesměrování.
pub fn is_symlink_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(1920)
}

pub fn is_dataless_error(_err: &io::Error) -> bool {
    false
}

/// Síťové cesty (UNC) ve v0.1 přeskakujeme. Namapované síťové disky
/// rozpozná až další verze.
pub fn is_local_volume(path: &Path) -> io::Result<bool> {
    let text = path.as_os_str().to_string_lossy();
    let unc =
        text.starts_with(r"\\?\UNC\") || (text.starts_with(r"\\") && !text.starts_with(r"\\?\"));
    Ok(!unc)
}
