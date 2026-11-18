// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::prelude::*;

#[inline(always)]
pub(super) fn sys_getpid(ctx: &Context) -> Result<SyscallReturn> {
    let pid = ctx.process.pid();
    Ok(SyscallReturn::Return(pid as _))
}
