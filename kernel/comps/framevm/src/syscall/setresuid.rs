// SPDX-License-Identifier: MPL-2.0

//! Sets real, effective, and saved-set user IDs.

use super::{Result, SyscallReturn};
use crate::{context::Context, process::Uid};

pub fn sys_setresuid(ruid: i32, euid: i32, suid: i32, ctx: &Context) -> Result<SyscallReturn> {
    ctx.process
        .set_resuid(optional_uid(ruid), optional_uid(euid), optional_uid(suid))?;
    Ok(SyscallReturn::Return(0))
}

fn optional_uid(raw_uid: i32) -> Option<Uid> {
    (raw_uid >= 0).then(|| Uid::new(raw_uid.cast_unsigned()))
}
