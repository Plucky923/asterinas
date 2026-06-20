// SPDX-License-Identifier: MPL-2.0

//! Sets Linux capability sets.

use ostd::mm::VmSpace;

use super::{
    Errno, Error, Result, SyscallReturn,
    capget::{LINUX_CAPABILITY_VERSION_3, read_cap_data, read_cap_header},
    write_to_user,
};
use crate::context::Context;

pub fn sys_capset(
    cap_user_header_addr: usize,
    cap_user_data_addr: usize,
    ctx: &Context,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    let header = read_cap_header(vm_space, cap_user_header_addr)?;
    if header.version != LINUX_CAPABILITY_VERSION_3 {
        write_to_user(
            vm_space,
            cap_user_header_addr,
            &LINUX_CAPABILITY_VERSION_3.to_ne_bytes(),
        )?;
        return Err(Error::new(Errno::EINVAL));
    }

    if header.pid != 0 && header.pid != ctx.posix_thread.tid() {
        return Err(Error::new(Errno::EPERM));
    }

    let capsets = read_cap_data(vm_space, cap_user_data_addr)?;
    ctx.process.update_credentials(|credentials| {
        credentials.set_capsets(capsets.permitted, capsets.effective, capsets.inheritable)
    })?;

    Ok(SyscallReturn::Return(0))
}
