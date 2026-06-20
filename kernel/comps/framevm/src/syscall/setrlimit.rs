// SPDX-License-Identifier: MPL-2.0

//! Resource-limit update syscall.

use ostd::mm::VmSpace;

use super::{
    Errno, Error, Result,
    prlimit64::{do_prlimit64, read_raw_rlimit64},
};

pub(super) fn sys_setrlimit(
    resource_raw: usize,
    new_rlim_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let resource = u32::try_from(resource_raw).map_err(|_| Error::new(Errno::EINVAL))?;
    let new_raw = read_raw_rlimit64(vm_space, new_rlim_addr)?;
    do_prlimit64(resource, Some(new_raw))?;
    Ok(0)
}
