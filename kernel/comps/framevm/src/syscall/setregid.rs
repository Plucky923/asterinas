// SPDX-License-Identifier: MPL-2.0

//! Sets real and effective group IDs.

use super::{Result, SyscallReturn};
use crate::{context::Context, process::Gid};

pub fn sys_setregid(rgid: i32, egid: i32, ctx: &Context) -> Result<SyscallReturn> {
    ctx.process
        .set_regid(optional_gid(rgid), optional_gid(egid))?;
    Ok(SyscallReturn::Return(0))
}

fn optional_gid(raw_gid: i32) -> Option<Gid> {
    (raw_gid >= 0).then(|| Gid::new(raw_gid.cast_unsigned()))
}
