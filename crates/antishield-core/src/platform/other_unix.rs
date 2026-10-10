//! Ostatní unixové systémy: jen základní chování (nepodporovaná platforma).

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub use super::unix_common::{
    device_id, hardlink_key, identity, is_reparse_point, is_symlink_error,
};
use crate::types::SkipReason;

pub fn precheck(_path: &Path, _meta: &Metadata) -> Option<SkipReason> {
    None
}

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

pub fn is_local_volume(_path: &Path) -> io::Result<bool> {
    Ok(true)
}
