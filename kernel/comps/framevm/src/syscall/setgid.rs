// SPDX-License-Identifier: MPL-2.0

//! Sets group IDs.

use super::{Errno, Error, Result, SyscallReturn};
use crate::{context::Context, process::Gid};

pub fn sys_setgid(gid: i32, ctx: &Context) -> Result<SyscallReturn> {
    if gid < 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    ctx.process.set_gid(Gid::new(gid.cast_unsigned()))?;
    Ok(SyscallReturn::Return(0))
}
