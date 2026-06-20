// SPDX-License-Identifier: MPL-2.0

//! Current CPU query syscall.

use ostd::{cpu::CpuId, mm::VmSpace};

use super::{Result, write_to_user};

pub(super) fn sys_getcpu(
    cpu_addr: usize,
    node_addr: usize,
    _tcache_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let current_cpu = u32::from(CpuId::current_racy());
    let current_node = 0u32;

    if cpu_addr != 0 {
        write_to_user(vm_space, cpu_addr, &current_cpu.to_ne_bytes())?;
    }
    if node_addr != 0 {
        write_to_user(vm_space, node_addr, &current_node.to_ne_bytes())?;
    }

    Ok(0)
}
