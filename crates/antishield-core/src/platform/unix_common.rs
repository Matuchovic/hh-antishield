//! Společné části pro unixové systémy (macOS, Linux).

use std::fs::Metadata;
use std::io;
use std::os::unix::fs::MetadataExt;

use crate::types::FileIdentity;

pub fn identity(meta: &Metadata) -> FileIdentity {
    FileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.size(),
        modified_sec: meta.mtime(),
        modified_nsec: u32::try_from(meta.mtime_nsec()).unwrap_or(0),
        changed_sec: meta.ctime(),
        changed_nsec: u32::try_from(meta.ctime_nsec()).unwrap_or(0),
    }
}

pub fn hardlink_key(meta: &Metadata) -> Option<(u64, u64)> {
    (meta.nlink() > 1).then(|| (meta.dev(), meta.ino()))
}

pub fn device_id(meta: &Metadata) -> Option<u64> {
    Some(meta.dev())
}

/// `open` s `O_NOFOLLOW` na symlinku vrací `ELOOP`.
pub fn is_symlink_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

pub fn is_reparse_point(_meta: &Metadata) -> bool {
    false
}
