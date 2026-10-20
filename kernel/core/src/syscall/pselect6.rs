// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::mm::VmIo;

use super::{
    SyscallReturn,
    rt_sigprocmask::{RequireFullSize, UserSigSetPtr},
    select::do_sys_select,
};
use crate::{
    fs::file::file_table::RawFileDesc,
    prelude::*,
    process::{
        posix_thread::{ContextPthreadAdminApi, Personality},
        signal::sig_mask::SigMask,
    },
    time::{read_monotonic_time, timespec_t},
};

pub(super) fn sys_pselect6(
    nfds: RawFileDesc,
    readfds_addr: Vaddr,
    writefds_addr: Vaddr,
    exceptfds_addr: Vaddr,
    timespec_addr: Vaddr,
    sigmask_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let user_space = ctx.user_space();

    let timeout = if timespec_addr != 0 {
        let time_spec = user_space.read_val::<timespec_t>(timespec_addr)?;
        Some(Duration::try_from(time_spec)?)
    } else {
        None
    };

    let end_time = timeout.map(|timeout| {
        if timeout.is_zero() {
            Duration::ZERO
        } else {
            read_monotonic_time().saturating_add(timeout)
        }
    });

    if sigmask_addr != 0 {
        let sigmask_with_size = user_space.read_val::<SigMaskWithSize>(sigmask_addr)?;
        if sigmask_with_size.addr != 0 {
            let sigmask_ptr = {
                let size_policy = RequireFullSize::new(sigmask_with_size.size)?;
                UserSigSetPtr::new(&user_space, sigmask_with_size.addr, size_policy)
            };
            let sigmask: SigMask = sigmask_ptr.read_val()?;
            ctx.save_and_set_sig_mask(sigmask);
        }
    }

    let result = do_sys_select(
        nfds,
        readfds_addr,
        writefds_addr,
        exceptfds_addr,
        end_time,
        ctx,
    );

    if let Some(end_time) = end_time.filter(|end_time| !end_time.is_zero())
        && ctx.posix_thread.personality() & Personality::STICKY_TIMEOUTS.bits() == 0
    {
        let remaining = timespec_t::from(end_time.saturating_sub(read_monotonic_time()));
        // This is the raw Linux ABI; libc pselect protects its const argument
        // with a copy. Timeout copy failures do not replace the syscall result.
        let _ = user_space.write_val(timespec_addr, &remaining);
    }

    result
}

// Reference: <https://elixir.bootlin.com/linux/v6.19.8/source/fs/select.c#L763-L772>
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct SigMaskWithSize {
    addr: Vaddr,
    size: usize,
}
