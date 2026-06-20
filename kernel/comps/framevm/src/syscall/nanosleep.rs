// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, read_guest_time_ns, read_i64_from_user};
use crate::time;

const TIMER_ABSTIME: i32 = 1;
const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const CLOCK_PROCESS_CPUTIME_ID: usize = 2;
const CLOCK_THREAD_CPUTIME_ID: usize = 3;
const CLOCK_MONOTONIC_RAW: usize = 4;
const CLOCK_REALTIME_COARSE: usize = 5;
const CLOCK_MONOTONIC_COARSE: usize = 6;
const CLOCK_BOOTTIME: usize = 7;

/// Sleeps until the requested relative timeout expires.
pub(super) fn sys_nanosleep(
    request_timespec_addr: usize,
    _remain_timespec_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let sleep_duration_ns = read_relative_timespec_ns(vm_space, request_timespec_addr)?;
    sleep_relative_ns(sleep_duration_ns)?;
    Ok(0)
}

/// Sleeps on a supported Linux clock.
pub(super) fn sys_clock_nanosleep(
    clock_id: usize,
    flags: i32,
    request_timespec_addr: usize,
    _remain_timespec_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    validate_sleep_clock(clock_id)?;

    let request_time_ns = read_timespec_ns(vm_space, request_timespec_addr)?;
    if flags & TIMER_ABSTIME != 0 {
        let deadline_ns = if clock_id == CLOCK_REALTIME {
            time::monotonic_deadline_from_realtime_ns(request_time_ns)
                .ok_or(Error::new(Errno::EINVAL))?
        } else {
            request_time_ns
        };
        time::sleep_until_ns(deadline_ns)?;
        return Ok(0);
    }

    sleep_relative_ns(request_time_ns)?;
    Ok(0)
}

pub(super) fn read_relative_timespec_ns(vm_space: &VmSpace, timespec_addr: usize) -> Result<u64> {
    read_timespec_ns(vm_space, timespec_addr)
}

fn sleep_relative_ns(sleep_duration_ns: u64) -> Result<()> {
    if sleep_duration_ns == 0 {
        return Ok(());
    }
    let deadline_ns = read_guest_time_ns()?
        .checked_add(sleep_duration_ns)
        .ok_or(Error::new(Errno::EINVAL))?;
    time::sleep_until_ns(deadline_ns)
}

fn read_timespec_ns(vm_space: &VmSpace, timespec_addr: usize) -> Result<u64> {
    const NS_PER_SEC: i64 = 1_000_000_000;

    let sec = read_i64_from_user(vm_space, timespec_addr)?;
    let nsec_addr = timespec_addr
        .checked_add(8)
        .ok_or(Error::new(Errno::EFAULT))?;
    let nsec = read_i64_from_user(vm_space, nsec_addr)?;
    if sec < 0 || !(0..NS_PER_SEC).contains(&nsec) {
        return Err(Error::new(Errno::EINVAL));
    }

    (sec as u64)
        .checked_mul(NS_PER_SEC as u64)
        .and_then(|sec_ns| sec_ns.checked_add(nsec as u64))
        .ok_or(Error::new(Errno::EINVAL))
}

fn validate_sleep_clock(clock_id: usize) -> Result<()> {
    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => Ok(()),
        CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID
        | CLOCK_MONOTONIC_RAW
        | CLOCK_REALTIME_COARSE
        | CLOCK_MONOTONIC_COARSE => Err(Error::with_message(
            Errno::EOPNOTSUPP,
            "unsupported clockid for clock_nanosleep",
        )),
        _ => Err(Error::new(Errno::EINVAL)),
    }
}

pub(super) fn duration_from_ns(timeout_ns: u64) -> Duration {
    const NS_PER_SEC: u64 = 1_000_000_000;

    Duration::new(timeout_ns / NS_PER_SEC, (timeout_ns % NS_PER_SEC) as u32)
}
