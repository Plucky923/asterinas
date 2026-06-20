// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, write_to_user};
use crate::time;

/// Gets the current guest time.
pub(super) fn sys_gettimeofday(timeval_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    if timeval_addr == 0 {
        return Ok(0);
    }

    let now_ns = time::realtime_ns().ok_or(Error::new(Errno::EINVAL))?;
    let sec = (now_ns / 1_000_000_000) as i64;
    let usec = ((now_ns % 1_000_000_000) / 1_000) as i64;

    let mut timeval = [0u8; 16];
    timeval[..8].copy_from_slice(&sec.to_ne_bytes());
    timeval[8..].copy_from_slice(&usec.to_ne_bytes());
    write_to_user(vm_space, timeval_addr, &timeval)?;

    Ok(0)
}
