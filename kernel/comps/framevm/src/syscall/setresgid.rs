// SPDX-License-Identifier: MPL-2.0

//! Sets real, effective, and saved-set group IDs.

use super::{Result, SyscallReturn};
use crate::{context::Context, process::Gid};

pub fn sys_setresgid(rgid: i32, egid: i32, sgid: i32, ctx: &Context) -> Result<SyscallReturn> {
    ctx.process
        .set_resgid(optional_gid(rgid), optional_gid(egid), optional_gid(sgid))?;
    Ok(SyscallReturn::Return(0))
}

fn optional_gid(raw_gid: i32) -> Option<Gid> {
    (raw_gid >= 0).then(|| Gid::new(raw_gid.cast_unsigned()))
}
