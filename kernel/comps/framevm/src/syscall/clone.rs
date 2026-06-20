// SPDX-License-Identifier: MPL-2.0

use ostd::arch::cpu::context::UserContext;

use super::{CLONE_VFORK, CLONE_VM, Result, clone_user_task};

/// Creates a new task.
pub(super) fn sys_clone(
    ctx: &mut UserContext,
    flags: u64,
    child_stack: usize,
    parent_tidptr: usize,
    child_tidptr: usize,
    tls: usize,
) -> Result<isize> {
    let child_tid = clone_user_task(ctx, child_stack, flags, parent_tidptr, child_tidptr, tls)?;
    Ok(child_tid as isize)
}

/// Creates a fork-style child task with a private VM snapshot.
pub(super) fn sys_fork(ctx: &mut UserContext) -> Result<isize> {
    let child_tid = clone_user_task(ctx, 0, 0, 0, 0, 0)?;
    Ok(child_tid as isize)
}

/// Creates a vfork-style child task.
pub(super) fn sys_vfork(ctx: &mut UserContext) -> Result<isize> {
    let child_tid = clone_user_task(ctx, 0, CLONE_VM | CLONE_VFORK, 0, 0, 0)?;
    Ok(child_tid as isize)
}
