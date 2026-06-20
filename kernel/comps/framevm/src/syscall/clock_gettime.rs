// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicU64, Ordering};

use ostd::{
    arch::{read_tsc, tsc_freq},
    mm::VmSpace,
    task::Task,
};

use super::{Errno, Error, Result, write_to_user};
use crate::{
    process::pid_table,
    return_errno_with_message,
    task::{self, UserTaskData},
    time,
};

static LAST_GUEST_MONO_NS: AtomicU64 = AtomicU64::new(0);
static GUEST_MONO_BACKWARD_COUNT: AtomicU64 = AtomicU64::new(0);

/// Gets current time for a Linux clock id.
pub(super) fn sys_clock_gettime(
    clock_id_raw: usize,
    timespec_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let clock_id = DecodedClockId::try_from(clock_id_raw as i32)?;
    let (sec, nsec) = read_guest_clock(clock_id)?;
    update_monotonic_regression_counter(clock_id, sec, nsec);

    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_ne_bytes());
    buf[8..16].copy_from_slice(&nsec.to_ne_bytes());

    write_to_user(vm_space, timespec_addr, &buf)?;
    Ok(0)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum DecodedClockId {
    Fixed(ClockId),
    Dynamic(DynamicClockIdInfo),
}

impl TryFrom<i32> for DecodedClockId {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        if value >= 0 {
            return Ok(Self::Fixed(ClockId::try_from(value as usize)?));
        }
        Ok(Self::Dynamic(DynamicClockIdInfo::try_from(value)?))
    }
}

#[expect(non_camel_case_types)]
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum ClockId {
    CLOCK_REALTIME = 0,
    CLOCK_MONOTONIC = 1,
    CLOCK_PROCESS_CPUTIME_ID = 2,
    CLOCK_THREAD_CPUTIME_ID = 3,
    CLOCK_MONOTONIC_RAW = 4,
    CLOCK_REALTIME_COARSE = 5,
    CLOCK_MONOTONIC_COARSE = 6,
    CLOCK_BOOTTIME = 7,
}

impl TryFrom<usize> for ClockId {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        match value {
            0 => Ok(Self::CLOCK_REALTIME),
            1 => Ok(Self::CLOCK_MONOTONIC),
            2 => Ok(Self::CLOCK_PROCESS_CPUTIME_ID),
            3 => Ok(Self::CLOCK_THREAD_CPUTIME_ID),
            4 => Ok(Self::CLOCK_MONOTONIC_RAW),
            5 => Ok(Self::CLOCK_REALTIME_COARSE),
            6 => Ok(Self::CLOCK_MONOTONIC_COARSE),
            7 => Ok(Self::CLOCK_BOOTTIME),
            _ => Err(Error::with_message(Errno::EINVAL, "unsupported clock_id")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum DynamicClockIdInfo {
    Pid(u32, DynamicClockType),
    Tid(u32, DynamicClockType),
    Fd(u32),
}

impl TryFrom<i32> for DynamicClockIdInfo {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        const CPU_CLOCK_TYPE_MASK: i32 = 0b11;
        const ID_TYPE_MASK: i32 = 0b100;
        const INVALID_MASK: i32 = CPU_CLOCK_TYPE_MASK | ID_TYPE_MASK;

        if value & INVALID_MASK == INVALID_MASK {
            return Err(Error::new(Errno::EINVAL));
        }

        let id = !(value >> 3) as u32;
        let clock_type = DynamicClockType::try_from(value & CPU_CLOCK_TYPE_MASK)?;
        if clock_type == DynamicClockType::Fd {
            return Ok(Self::Fd(id));
        }
        if value & ID_TYPE_MASK != 0 {
            Ok(Self::Tid(id, clock_type))
        } else {
            Ok(Self::Pid(id, clock_type))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicClockType {
    Profiling,
    Virtual,
    Scheduling,
    Fd,
}

impl TryFrom<i32> for DynamicClockType {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Profiling),
            1 => Ok(Self::Virtual),
            2 => Ok(Self::Scheduling),
            3 => Ok(Self::Fd),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }
}

fn read_guest_clock(clock_id: DecodedClockId) -> Result<(u64, u64)> {
    match clock_id {
        DecodedClockId::Fixed(clock_id) => read_fixed_clock(clock_id),
        DecodedClockId::Dynamic(clock_id) => read_dynamic_clock(clock_id),
    }
}

fn read_fixed_clock(clock_id: ClockId) -> Result<(u64, u64)> {
    match clock_id {
        ClockId::CLOCK_REALTIME | ClockId::CLOCK_REALTIME_COARSE => read_realtime_clock(),
        ClockId::CLOCK_MONOTONIC
        | ClockId::CLOCK_MONOTONIC_RAW
        | ClockId::CLOCK_MONOTONIC_COARSE
        | ClockId::CLOCK_BOOTTIME => read_tsc_clock(),
        ClockId::CLOCK_PROCESS_CPUTIME_ID => read_process_cpu_clock(),
        ClockId::CLOCK_THREAD_CPUTIME_ID => read_thread_cpu_clock(),
    }
}

fn read_dynamic_clock(clock_id: DynamicClockIdInfo) -> Result<(u64, u64)> {
    match clock_id {
        DynamicClockIdInfo::Pid(pid, DynamicClockType::Profiling) => {
            read_process_cpu_clock_by_pid(pid)
        }
        DynamicClockIdInfo::Tid(tid, DynamicClockType::Profiling) => {
            read_thread_cpu_clock_by_tid(tid)
        }
        DynamicClockIdInfo::Pid(_, DynamicClockType::Virtual)
        | DynamicClockIdInfo::Tid(_, DynamicClockType::Virtual)
        | DynamicClockIdInfo::Pid(_, DynamicClockType::Scheduling)
        | DynamicClockIdInfo::Tid(_, DynamicClockType::Scheduling)
        | DynamicClockIdInfo::Fd(_) => Err(Error::with_message(
            Errno::EOPNOTSUPP,
            "the dynamic clock type is not supported yet",
        )),
        DynamicClockIdInfo::Pid(_, DynamicClockType::Fd)
        | DynamicClockIdInfo::Tid(_, DynamicClockType::Fd) => unreachable!(),
    }
}

fn read_realtime_clock() -> Result<(u64, u64)> {
    Ok(ns_to_timespec(
        time::realtime_ns().ok_or(Error::new(Errno::EINVAL))?,
    ))
}

fn read_tsc_clock() -> Result<(u64, u64)> {
    cycles_to_timespec(read_tsc())
}

fn read_process_cpu_clock() -> Result<(u64, u64)> {
    cycles_to_timespec(current_cpu_time_cycles(
        UserTaskData::process_cpu_time_cycles,
    )?)
}

fn read_thread_cpu_clock() -> Result<(u64, u64)> {
    cycles_to_timespec(current_cpu_time_cycles(
        UserTaskData::thread_cpu_time_cycles,
    )?)
}

fn read_process_cpu_clock_by_pid(pid: u32) -> Result<(u64, u64)> {
    if let Some(cycles) = current_process_cpu_time_cycles_if_pid(pid)? {
        return cycles_to_timespec(cycles);
    }

    let process = pid_table::pid_table_mut()
        .get_process(pid)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid clock ID"))?;
    cycles_to_timespec(process.cpu_time_cycles())
}

fn read_thread_cpu_clock_by_tid(tid: u32) -> Result<(u64, u64)> {
    let cycles = task::thread_cpu_time_cycles_for_tid(tid)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid clock ID"))?;
    cycles_to_timespec(cycles)
}

fn current_process_cpu_time_cycles_if_pid(pid: u32) -> Result<Option<u64>> {
    current_user_task_data(|task_data| {
        (task_data.process.pid() == pid).then(|| task_data.process_cpu_time_cycles())
    })
}

fn current_cpu_time_cycles(read_fn: fn(&UserTaskData) -> u64) -> Result<u64> {
    current_user_task_data(read_fn)
}

fn current_user_task_data<T>(read_fn: impl FnOnce(&UserTaskData) -> T) -> Result<T> {
    let current = Task::current().ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "CPU-time clock requires a current task")
    })?;
    let task_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "CPU-time clock requires a user task"))?;

    Ok(read_fn(task_data))
}

fn cycles_to_timespec(cycles: u64) -> Result<(u64, u64)> {
    let freq = tsc_freq();

    if freq == 0 {
        return_errno_with_message!(Errno::EINVAL, "TSC frequency not initialized");
    }

    let total_nsec = u128::from(cycles)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "clock value overflow"))?
        / u128::from(freq);
    let sec = (total_nsec / 1_000_000_000) as u64;
    let nsec = (total_nsec % 1_000_000_000) as u64;
    Ok((sec, nsec))
}

fn ns_to_timespec(total_nsec: u64) -> (u64, u64) {
    (total_nsec / 1_000_000_000, total_nsec % 1_000_000_000)
}

fn update_monotonic_regression_counter(clock_id: DecodedClockId, sec: u64, nsec: u64) {
    let DecodedClockId::Fixed(clock_id) = clock_id else {
        return;
    };
    if !matches!(
        clock_id,
        ClockId::CLOCK_MONOTONIC
            | ClockId::CLOCK_MONOTONIC_RAW
            | ClockId::CLOCK_MONOTONIC_COARSE
            | ClockId::CLOCK_BOOTTIME
    ) {
        return;
    }

    let now_ns = sec.saturating_mul(1_000_000_000) + nsec;
    let prev = LAST_GUEST_MONO_NS.load(Ordering::Relaxed);
    if now_ns < prev {
        GUEST_MONO_BACKWARD_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    let mut cur = prev;
    while now_ns > cur {
        match LAST_GUEST_MONO_NS.compare_exchange(cur, now_ns, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(updated) => cur = updated,
        }
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn decodes_dynamic_process_profiling_clock() {
        let clock_id = ((!123_i32) << 3) | 0;

        assert_eq!(
            DynamicClockIdInfo::try_from(clock_id).unwrap(),
            DynamicClockIdInfo::Pid(123, DynamicClockType::Profiling)
        );
    }

    #[ktest]
    fn decodes_dynamic_thread_profiling_clock() {
        let clock_id = ((!456_i32) << 3) | 0b100;

        assert_eq!(
            DynamicClockIdInfo::try_from(clock_id).unwrap(),
            DynamicClockIdInfo::Tid(456, DynamicClockType::Profiling)
        );
    }

    #[ktest]
    fn rejects_invalid_dynamic_clock_id() {
        assert_eq!(
            DynamicClockIdInfo::try_from(-1).unwrap_err().errno(),
            Errno::EINVAL
        );
    }
}
