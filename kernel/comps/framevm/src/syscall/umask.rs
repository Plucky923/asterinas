// SPDX-License-Identifier: MPL-2.0

//! File mode creation mask syscall.

use super::{FileCreationMask, Result, with_current_fs_info};

pub(super) fn sys_umask(mask: u16) -> Result<isize> {
    let new_mask = FileCreationMask::try_from(mask)?;
    let old_mask = with_current_fs_info(|fs| Ok(fs.swap_umask(new_mask)))?;
    Ok(old_mask.get() as isize)
}
