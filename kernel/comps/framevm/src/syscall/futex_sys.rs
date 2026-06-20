// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, nanosleep::read_relative_timespec_ns, read_guest_time_ns};
use crate::futex::{self, FutexOp};

/// Performs futex wait and wake operations.
pub(super) fn sys_futex(
    futex_addr: usize,
    futex_op_bits: u32,
    futex_val: u32,
    utime_addr: usize,
    futex_new_addr: usize,
    bitset: u32,
    vm_space: &VmSpace,
) -> Result<isize> {
    futex::init();

    let (futex_op, futex_flags) = futex::futex_op_and_flags_from_u32(futex_op_bits)?;
    let _private_mapping = futex_flags.is_private();

    let result = match futex_op {
        FutexOp::FUTEX_WAIT => {
            let wait_deadline_ns = futex_wait_deadline_ns(
                vm_space,
                futex_op,
                futex_flags.uses_clock_realtime(),
                utime_addr,
            )?;
            futex::futex_wait(futex_addr, futex_val, wait_deadline_ns, || {
                atomic_load_u32(vm_space, futex_addr)
            })?;
            0
        }
        FutexOp::FUTEX_WAIT_BITSET => {
            let wait_deadline_ns = futex_wait_deadline_ns(
                vm_space,
                futex_op,
                futex_flags.uses_clock_realtime(),
                utime_addr,
            )?;
            futex::futex_wait_bitset(futex_addr, futex_val, bitset, wait_deadline_ns, || {
                atomic_load_u32(vm_space, futex_addr)
            })?;
            0
        }
        FutexOp::FUTEX_WAKE => {
            futex::futex_wake(futex_addr, futex::futex_val_to_max_count(futex_val))?
        }
        FutexOp::FUTEX_WAKE_BITSET => {
            futex::futex_wake_bitset(futex_addr, futex::futex_val_to_max_count(futex_val), bitset)?
        }
        FutexOp::FUTEX_REQUEUE => {
            let max_nwakes = futex::futex_val_to_max_count(futex_val);
            let max_nrequeues = (utime_addr as i32).max(0) as usize;
            futex::futex_requeue(futex_addr, max_nwakes, max_nrequeues, futex_new_addr)?
        }
        FutexOp::FUTEX_WAKE_OP => {
            let futex_val_2 = utime_addr as u32;
            futex::futex_wake_op(
                futex_addr,
                futex_new_addr,
                futex::futex_val_to_max_count(futex_val),
                futex::futex_val_to_max_count(futex_val_2),
                bitset,
                |calculate_new_value| {
                    atomic_fetch_update_u32(vm_space, futex_new_addr, calculate_new_value)
                },
            )?
        }
        _ => {
            return Err(Error::with_message(
                Errno::EINVAL,
                "unsupported futex operation",
            ));
        }
    };

    Ok(result as isize)
}

fn atomic_load_u32(vm_space: &VmSpace, addr: usize) -> Result<u32> {
    vm_space
        .reader(addr, size_of::<u32>())
        .map_err(Error::from)?
        .atomic_load::<u32>()
        .map_err(Error::from)
}

fn atomic_fetch_update_u32(
    vm_space: &VmSpace,
    addr: usize,
    calculate_new_value: &mut dyn FnMut(u32) -> u32,
) -> Result<u32> {
    loop {
        let (reader, writer) = vm_space
            .reader_writer(addr, size_of::<u32>())
            .map_err(Error::from)?;
        let old_value = reader.atomic_load::<u32>().map_err(Error::from)?;
        let new_value = calculate_new_value(old_value);
        let (_, exchanged) = writer
            .atomic_compare_exchange(&reader, old_value, new_value)
            .map_err(Error::from)?;
        if exchanged {
            return Ok(old_value);
        }
    }
}

fn futex_wait_deadline_ns(
    vm_space: &VmSpace,
    futex_op: FutexOp,
    uses_clock_realtime: bool,
    timeout_addr: usize,
) -> Result<Option<u64>> {
    if uses_clock_realtime && futex_op == FutexOp::FUTEX_WAIT {
        return Err(Error::with_message(
            Errno::ENOSYS,
            "FUTEX_WAIT cannot use CLOCK_REALTIME",
        ));
    }

    if timeout_addr != 0 {
        if uses_clock_realtime {
            return Err(Error::with_message(
                Errno::ENOSYS,
                "realtime futex timeout is not supported yet",
            ));
        }

        let timeout_ns = read_relative_timespec_ns(vm_space, timeout_addr)?;
        let deadline_ns = if futex_op == FutexOp::FUTEX_WAIT {
            read_guest_time_ns()?
                .checked_add(timeout_ns)
                .ok_or(Error::new(Errno::EINVAL))?
        } else {
            timeout_ns
        };
        return Ok(Some(deadline_ns));
    }

    Ok(None)
}
