//! macOS: `O_NOFOLLOW_ANY`, nestažené soubory z iCloudu, priorita vláken.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub use super::unix_common::{
    device_id, hardlink_key, identity, is_reparse_point, is_symlink_error,
};
use crate::types::SkipReason;

/// `st_flags`: soubor je jen zástupce, data jsou v cloudu (sys/stat.h).
const SF_DATALESS: u32 = 0x4000_0000;
/// sys/resource.h
const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: c_int = 3;
const IOPOL_SCOPE_THREAD: c_int = 1;
const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: c_int = 1;
/// sys/qos.h: QOS_CLASS_UTILITY
const QOS_CLASS_UTILITY: u32 = 0x11;

unsafe extern "C" {
    fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;
    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: c_int) -> c_int;
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn st_flags(path: &Path) -> io::Result<u32> {
    let c = c_path(path)?;
    // SAFETY: `c` je platný řetězec zakončený NUL, `st` je platný výstupní buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::lstat(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.st_flags)
}

pub fn precheck(path: &Path, _meta: &Metadata) -> Option<SkipReason> {
    match st_flags(path) {
        Ok(flags) if flags & SF_DATALESS != 0 => Some(SkipReason::NotDownloaded),
        _ => None,
    }
}

/// `O_NOFOLLOW_ANY` odmítne symlink v kterékoli části cesty, ne jen v poslední.
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY | libc::O_NONBLOCK)
        .open(path)
}

pub fn prepare_scan_thread() {
    // SAFETY: obě funkce jen mění nastavení aktuálního vlákna; návratové kódy
    // nejsou kritické (kontrola dataless souborů běží i přes `st_flags`).
    unsafe {
        let _ = setiopolicy_np(
            IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
            IOPOL_SCOPE_THREAD,
            IOPOL_MATERIALIZE_DATALESS_FILES_OFF,
        );
        let _ = pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
    }
}

/// Čtení nestaženého souboru s vypnutým stahováním vrací `EDEADLK`.
pub fn is_dataless_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EDEADLK)
}

pub fn is_local_volume(path: &Path) -> io::Result<bool> {
    let c = c_path(path)?;
    // SAFETY: `c` je platný řetězec, `st` je platný výstupní buffer.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.f_flags & (libc::MNT_LOCAL as u32) != 0)
}
