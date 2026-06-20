// SPDX-License-Identifier: MPL-2.0

//! File-descriptor close syscall.

use alloc::vec::Vec;

use super::{
    Errno, Error, FdFlags, RawFileDesc, Result, current_fd_table, unshare_current_fd_table,
};
use crate::fd_table::FileDesc;

const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
const CLOSE_RANGE_VALID_FLAGS: u32 = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;

pub(super) fn sys_close(raw_fd: RawFileDesc) -> Result<isize> {
    let fd_table = current_fd_table()?;
    let _handle = fd_table.lock().remove(raw_fd)?;
    Ok(0)
}

pub(super) fn sys_close_range(first: u32, last: u32, raw_flags: u32) -> Result<isize> {
    if last < first || raw_flags & !CLOSE_RANGE_VALID_FLAGS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    if raw_flags & CLOSE_RANGE_UNSHARE != 0 {
        unshare_current_fd_table()?;
    }
    let fd_table = current_fd_table()?;
    let mut files_to_drop = Vec::new();

    {
        let mut fd_table = fd_table.lock();
        let table_len = u32::try_from(fd_table.len()).unwrap_or(u32::MAX);
        if first >= table_len {
            return Ok(0);
        }

        let actual_last = last.min(table_len - 1);
        for raw_fd in first..=actual_last {
            let fd = FileDesc::try_from(raw_fd as RawFileDesc)?;
            if raw_flags & CLOSE_RANGE_CLOEXEC != 0 {
                if let Ok(entry) = fd_table.get_entry(fd) {
                    entry.set_flags(entry.flags() | FdFlags::CLOEXEC);
                }
                continue;
            }

            if let Some(file) = fd_table.close_file(fd) {
                files_to_drop.push(file);
            }
        }
    }

    drop(files_to_drop);
    Ok(0)
}
