// SPDX-License-Identifier: MPL-2.0

//! `setsid(2)` implementation, shaped after `kernel/src/syscall/setsid.rs`.

use super::{Result, with_current_user_task_data};
use crate::process::create_session;

pub(super) fn sys_setsid() -> Result<isize> {
    with_current_user_task_data(|task_data| Ok(create_session(&task_data.process)? as isize))
}
