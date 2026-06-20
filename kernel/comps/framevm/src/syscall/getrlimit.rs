// SPDX-License-Identifier: MPL-2.0

//! Resource-limit read syscall.

use ostd::mm::VmSpace;

use super::{
    Errno, Error, Result,
    prlimit64::{do_prlimit64, write_raw_rlimit64},
};

pub(super) fn sys_getrlimit(
    resource_raw: usize,
    rlim_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let resource = u32::try_from(resource_raw).map_err(|_| Error::new(Errno::EINVAL))?;
    let old_raw = do_prlimit64(resource, None)?;
    write_raw_rlimit64(vm_space, rlim_addr, old_raw)?;
    Ok(0)
}
