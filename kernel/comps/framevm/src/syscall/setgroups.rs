// SPDX-License-Identifier: MPL-2.0

//! Sets supplementary group IDs.

use alloc::vec::Vec;

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, SyscallReturn, read_u32_from_user};
use crate::{context::Context, process::Gid};

const NGROUPS_MAX: usize = 65_536;

pub fn sys_setgroups(
    size: usize,
    group_list_addr: usize,
    ctx: &Context,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    if size > NGROUPS_MAX {
        return Err(Error::new(Errno::EINVAL));
    }

    let mut groups = Vec::new();
    for idx in 0..size {
        let addr = group_list_addr
            .checked_add(idx * size_of::<u32>())
            .ok_or(Error::new(Errno::EFAULT))?;
        groups.push(Gid::new(read_u32_from_user(vm_space, addr)?));
    }

    ctx.process.set_groups(groups);
    Ok(SyscallReturn::Return(0))
}
