// SPDX-License-Identifier: MPL-2.0

//! `set_tid_address(2)` implementation, shaped after `kernel/src/syscall/set_tid_address.rs`.

use core::sync::atomic::Ordering;

use super::{Result, with_current_user_task_data};

pub(super) fn sys_set_tid_address(clear_child_tid: usize) -> Result<isize> {
    with_current_user_task_data(|task_data| {
        task_data
            .clear_child_tid
            .store(clear_child_tid, Ordering::SeqCst);
        Ok(task_data.tid as isize)
    })
}
