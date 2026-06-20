// SPDX-License-Identifier: MPL-2.0

//! `set_robust_list(2)` implementation, shaped after `kernel/src/syscall/set_robust_list.rs`.

use ostd::{mm::VmSpace, task::Task};

use super::{Errno, Error, Result};
use crate::{robust_list::RobustListHead, task::UserTaskData};

pub(super) fn sys_set_robust_list(
    robust_list_head_ptr: usize,
    len: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    if len != RobustListHead::BYTE_LEN {
        return Err(Error::new(Errno::EINVAL));
    }

    let robust_list_head = RobustListHead::read_from_user(vm_space, robust_list_head_ptr)?;
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let task_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;
    *task_data.robust_list.lock() = Some(robust_list_head);

    Ok(0)
}
