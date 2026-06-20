// SPDX-License-Identifier: MPL-2.0

//! Returns real, effective, and saved-set group IDs.

use ostd::mm::VmSpace;

use super::{Result, SyscallReturn, write_to_user};
use crate::{context::Context, process::Gid};

pub fn sys_getresgid(
    rgid_ptr: usize,
    egid_ptr: usize,
    sgid_ptr: usize,
    ctx: &Context,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    let credentials = ctx.posix_thread.credentials();
    write_gid(vm_space, rgid_ptr, credentials.rgid())?;
    write_gid(vm_space, egid_ptr, credentials.egid())?;
    write_gid(vm_space, sgid_ptr, credentials.sgid())?;
    Ok(SyscallReturn::Return(0))
}

fn write_gid(vm_space: &VmSpace, addr: usize, gid: Gid) -> Result<()> {
    let raw_gid = <Gid as Into<u32>>::into(gid);
    write_to_user(vm_space, addr, &raw_gid.to_ne_bytes())
}
