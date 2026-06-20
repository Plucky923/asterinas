// SPDX-License-Identifier: MPL-2.0

use ostd::mm::{MAX_USERSPACE_VADDR, VmSpace};

use super::{Errno, Error, Result, with_current_user_task_data};

/// Sets or gets architecture-specific thread state.
pub(super) fn sys_arch_prctl(code: usize, addr: usize, _vm_space: &VmSpace) -> Result<isize> {
    const ARCH_SET_GS: usize = 0x1001;
    const ARCH_SET_FS: usize = 0x1002;
    const ARCH_GET_FS: usize = 0x1003;
    const ARCH_GET_GS: usize = 0x1004;

    match code {
        ARCH_SET_GS => with_current_user_task_data(|task_data| {
            validate_user_base(addr)?;
            task_data.set_gs_base(addr);
            Ok(0)
        }),
        ARCH_SET_FS => with_current_user_task_data(|task_data| {
            validate_user_base(addr)?;
            task_data.set_fs_base(addr);
            Ok(0)
        }),
        ARCH_GET_FS => with_current_user_task_data(|task_data| Ok(task_data.fs_base() as isize)),
        ARCH_GET_GS => with_current_user_task_data(|task_data| {
            let guard = ostd::irq::disable_local();
            let gs_base = task_data.gs_base(&guard) as isize;
            drop(guard);
            Ok(gs_base)
        }),
        _ => Err(Error::new(Errno::EINVAL)),
    }
}

fn validate_user_base(addr: usize) -> Result<()> {
    if addr >= MAX_USERSPACE_VADDR {
        return Err(Error::new(Errno::EPERM));
    }
    Ok(())
}
