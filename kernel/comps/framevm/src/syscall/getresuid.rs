// SPDX-License-Identifier: MPL-2.0

//! Returns real, effective, and saved-set user IDs.

use ostd::mm::VmSpace;

use super::{Result, SyscallReturn, write_to_user};
use crate::{context::Context, process::Uid};

pub fn sys_getresuid(
    ruid_ptr: usize,
    euid_ptr: usize,
    suid_ptr: usize,
    ctx: &Context,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    let credentials = ctx.posix_thread.credentials();
    write_uid(vm_space, ruid_ptr, credentials.ruid())?;
    write_uid(vm_space, euid_ptr, credentials.euid())?;
    write_uid(vm_space, suid_ptr, credentials.suid())?;
    Ok(SyscallReturn::Return(0))
}

fn write_uid(vm_space: &VmSpace, addr: usize, uid: Uid) -> Result<()> {
    let raw_uid = <Uid as Into<u32>>::into(uid);
    write_to_user(vm_space, addr, &raw_uid.to_ne_bytes())
}
