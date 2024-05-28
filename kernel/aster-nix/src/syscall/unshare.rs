// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{do_unshare, CloneFlags},
};

pub fn sys_unshare(unshare_flags: u64) -> Result<SyscallReturn> {
    let unshare_flags: crate::process::CloneFlags = CloneFlags::from(unshare_flags);
    debug!("flags = {:?}", unshare_flags);
    do_unshare(unshare_flags)?;
    Ok(SyscallReturn::Return(0))
}
