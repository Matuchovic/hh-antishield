//! Tenká platformní vrstva. Vše ostatní v jádru je přenositelné.
//!
//! Každá platforma poskytuje stejné funkce:
//! - `precheck`: rozhodnutí podle metadat z `lstat` ještě před otevřením,
//! - `open_regular`: otevření bez sledování symlinků a bez blokování,
//! - `identity`, `hardlink_key`, `device_id`: identita souboru,
//! - `prepare_scan_thread`: nastavení vlákna (macOS: nestahovat z iCloudu, nízká priorita),
//! - `is_local_volume`: síťové svazky ve v0.1 přeskakujeme,
//! - `is_symlink_error`, `is_dataless_error`: rozpoznání chyb.

use std::fs::{File, Metadata};
use std::io;
use std::path::Path;

use crate::types::{FileIdentity, SkipReason};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod other_unix;
#[cfg(unix)]
mod unix_common;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
use other_unix as imp;
#[cfg(windows)]
use windows as imp;

/// Proč se soubor nepodařilo otevřít ke čtení.
#[derive(Debug)]
pub enum OpenError {
    /// Nejde o běžný soubor (FIFO, zařízení, adresář, bod přesměrování).
    NotRegular,
    Io(io::Error),
}

/// Rozhodnutí podle metadat z `lstat` ještě před otevřením souboru.
pub fn precheck(path: &Path, meta: &Metadata) -> Option<SkipReason> {
    imp::precheck(path, meta)
}

/// Otevře běžný soubor jen ke čtení: bez sledování symlinků, bez blokování
/// na FIFO. Vrací i metadata z otevřeného deskriptoru (`fstat`).
pub fn open_regular(path: &Path) -> Result<(File, Metadata), OpenError> {
    let file = imp::open_no_follow(path).map_err(OpenError::Io)?;
    let meta = file.metadata().map_err(OpenError::Io)?;
    if !meta.is_file() || imp::is_reparse_point(&meta) {
        return Err(OpenError::NotRegular);
    }
    Ok((file, meta))
}

pub fn identity(meta: &Metadata) -> FileIdentity {
    imp::identity(meta)
}

/// Klíč pro vynechání opakovaného čtení stejného souboru přes hardlinky.
pub fn hardlink_key(meta: &Metadata) -> Option<(u64, u64)> {
    imp::hardlink_key(meta)
}

pub fn device_id(meta: &Metadata) -> Option<u64> {
    imp::device_id(meta)
}

pub fn prepare_scan_thread() {
    imp::prepare_scan_thread();
}

pub fn is_local_volume(path: &Path) -> io::Result<bool> {
    imp::is_local_volume(path)
}

/// Shoduje se obsahová verze souboru (velikost a časy změn)?
pub fn same_version(a: &FileIdentity, b: &FileIdentity) -> bool {
    a.size == b.size
        && a.modified_sec == b.modified_sec
        && a.modified_nsec == b.modified_nsec
        && a.changed_sec == b.changed_sec
        && a.changed_nsec == b.changed_nsec
}

/// Převede chybu I/O na důvod přeskočení.
pub fn classify_io_error(err: &io::Error) -> SkipReason {
    if imp::is_symlink_error(err) {
        return SkipReason::Symlink;
    }
    if imp::is_dataless_error(err) {
        return SkipReason::NotDownloaded;
    }
    match err.kind() {
        io::ErrorKind::PermissionDenied => SkipReason::PermissionDenied,
        io::ErrorKind::NotFound => SkipReason::NotFound,
        _ => SkipReason::ReadError {
            code: err.raw_os_error(),
            message: err.to_string(),
        },
    }
}
