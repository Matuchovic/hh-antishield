//! Linux: pro vývoj a CI. Produkt pro Linux zatím není.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub use super::unix_common::{
    device_id, hardlink_key, identity, is_reparse_point, is_symlink_error,
};
use crate::types::SkipReason;

/// Typy síťových souborových systémů (statfs `f_type`).
const NETWORK_FS: [i64; 5] = [
    0x6969,      // NFS
    0x517b,      // SMB
    0xff53_4d42, // CIFS
    0xfe53_4d42, // SMB2
    0x0102_1997, // 9P
];

pub fn precheck(_path: &Path, _meta: &Metadata) -> Option<SkipReason> {
    None
}

/// Linux nemá `O_NOFOLLOW_ANY`; `O_NOFOLLOW` hlídá jen poslední část cesty.
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

pub fn prepare_scan_thread() {}

pub fn is_dataless_error(_err: &io::Error) -> bool {
    false
}

pub fn is_local_volume(path: &Path) -> io::Result<bool> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `c` je platný řetězec zakončený NUL, `st` je platný výstupní buffer.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    let fs_type = st.f_type as i64;
    Ok(!NETWORK_FS.contains(&fs_type))
}
