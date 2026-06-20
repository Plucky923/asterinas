// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{
    Errno, Error, Result, TryWaitResult, current_user_tid, peek_wait_for_exit,
    reactivate_current_vm_space, try_wait_for_exit, wait_for_exit, wait_for_exit_no_reap,
    write_to_user,
};

/// Waits for a child task to exit.
pub(super) fn sys_wait4(
    pid: i32,
    status_ptr: usize,
    options: i32,
    rusage_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    const WNOHANG: u32 = 0x1;
    const WSTOPPED: u32 = 0x2;
    const WEXITED: u32 = 0x4;
    const WCONTINUED: u32 = 0x8;
    const WNOWAIT: u32 = 0x01000000;
    const WNOTHREAD: u32 = 0x20000000;
    const WALL: u32 = 0x40000000;
    const WCLONE: u32 = 0x80000000;
    const SUPPORTED_OPTIONS: u32 =
        WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT | WNOTHREAD | WALL | WCLONE;

    let options = options as u32;
    if options & !SUPPORTED_OPTIONS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if options & WNOWAIT != 0 && options & (WSTOPPED | WCONTINUED) != 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let parent_tid = current_user_tid()?;
    let no_reap = options & WNOWAIT != 0;
    let info = if options & WNOHANG != 0 {
        let try_result = if no_reap {
            peek_wait_for_exit(parent_tid, pid)
        } else {
            try_wait_for_exit(parent_tid, pid)
        };
        match try_result {
            TryWaitResult::Exited(info) => info,
            TryWaitResult::StillRunning => return Ok(0),
            TryWaitResult::NoChild => return Err(Error::new(Errno::ECHILD)),
        }
    } else if no_reap {
        wait_for_exit_no_reap(parent_tid, pid)?
    } else {
        wait_for_exit(parent_tid, pid)?
    };
    reactivate_current_vm_space()?;
    if status_ptr != 0 {
        let status = ((info.code as u32) & 0xff) << 8;
        write_to_user(vm_space, status_ptr, &status.to_ne_bytes())?;
    }
    if rusage_addr != 0 {
        write_empty_rusage(vm_space, rusage_addr)?;
    }
    Ok(info.tid as isize)
}

fn write_empty_rusage(vm_space: &VmSpace, rusage_addr: usize) -> Result<()> {
    const TIMEVAL_SIZE: usize = 16;
    const RUSAGE_COUNTER_COUNT: usize = 14;
    const RUSAGE_SIZE: usize = TIMEVAL_SIZE * 2 + RUSAGE_COUNTER_COUNT * 8;

    write_to_user(vm_space, rusage_addr, &[0; RUSAGE_SIZE])
}
