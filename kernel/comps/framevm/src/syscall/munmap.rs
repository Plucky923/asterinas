// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{Result, unmap_range};

/// Removes mapped pages from an address range.
pub(super) fn sys_munmap(addr: usize, len: usize, vm_space: &VmSpace) -> Result<isize> {
    unmap_range(vm_space, addr, len)?;
    Ok(0)
}
