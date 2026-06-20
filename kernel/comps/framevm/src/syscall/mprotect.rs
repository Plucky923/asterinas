// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{Result, mmap::page_flags_from_prot, protect_range};

/// Changes memory protection on a mapped range.
pub(super) fn sys_mprotect(
    addr: usize,
    len: usize,
    prot: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    protect_range(vm_space, addr, len, page_flags_from_prot(prot)?)?;
    Ok(0)
}
