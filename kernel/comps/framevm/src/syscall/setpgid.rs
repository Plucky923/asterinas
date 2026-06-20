// SPDX-License-Identifier: MPL-2.0

//! `setpgid(2)` implementation, shaped after `kernel/src/syscall/setpgid.rs`.

use super::{Result, with_current_user_task_data};
use crate::process::set_process_group;

pub(super) fn sys_setpgid(raw_pid: i32, raw_pgid: i32) -> Result<isize> {
    with_current_user_task_data(|task_data| {
        set_process_group(&task_data.process, raw_pid, raw_pgid)?;
        Ok(0)
    })
}
