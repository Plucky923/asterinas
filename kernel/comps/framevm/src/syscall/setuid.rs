// SPDX-License-Identifier: MPL-2.0

//! Sets user IDs.

use super::{Errno, Error, Result, SyscallReturn};
use crate::{context::Context, process::Uid};

pub fn sys_setuid(uid: i32, ctx: &Context) -> Result<SyscallReturn> {
    if uid < 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    ctx.process.set_uid(Uid::new(uid.cast_unsigned()))?;
    Ok(SyscallReturn::Return(0))
}
