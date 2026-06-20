// SPDX-License-Identifier: MPL-2.0

//! Process-control syscall.

use core::sync::atomic::Ordering;

use ostd::{mm::VmSpace, task::Task};

use super::{Errno, Error, Result, SyscallReturn, read_from_user_to_vec, write_to_user};
use crate::{context::Context, process::CapabilitySet, task::UserTaskData};

const THREAD_NAME_LEN: usize = 16;
const PR_SET_PDEATHSIG: i32 = 1;
const PR_GET_PDEATHSIG: i32 = 2;
const PR_GET_DUMPABLE: i32 = 3;
const PR_SET_DUMPABLE: i32 = 4;
const PR_GET_KEEPCAPS: i32 = 7;
const PR_SET_KEEPCAPS: i32 = 8;
const PR_SET_NAME: i32 = 15;
const PR_GET_NAME: i32 = 16;
const PR_CAPBSET_READ: i32 = 23;
const PR_CAPBSET_DROP: i32 = 24;
const PR_GET_SECUREBITS: i32 = 27;
const PR_SET_SECUREBITS: i32 = 28;
const PR_SET_TIMERSLACK: i32 = 29;
const PR_GET_TIMERSLACK: i32 = 30;
const PR_SET_CHILD_SUBREAPER: i32 = 36;
const PR_GET_CHILD_SUBREAPER: i32 = 37;

pub fn sys_prctl(
    option: i32,
    arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    ctx: &Context,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    match option {
        PR_SET_PDEATHSIG => {
            let signal = parse_parent_death_signal(arg2)?;
            ctx.process.set_parent_death_signal(signal)?;
            Ok(SyscallReturn::Return(0))
        }
        PR_GET_PDEATHSIG => {
            let signal = ctx.process.parent_death_signal() as i32;
            write_to_user(vm_space, arg2, &signal.to_ne_bytes())?;
            Ok(SyscallReturn::Return(0))
        }
        PR_GET_DUMPABLE => Ok(SyscallReturn::Return(0)),
        PR_SET_DUMPABLE => {
            let dumpable = u32::try_from(arg2).map_err(|_| Error::new(Errno::EINVAL))?;
            if !matches!(dumpable, 0 | 1) {
                return Err(Error::new(Errno::EINVAL));
            }
            Ok(SyscallReturn::Return(0))
        }
        PR_GET_KEEPCAPS => {
            let keep_caps = ctx.posix_thread.credentials().keep_capabilities() as isize;
            Ok(SyscallReturn::Return(keep_caps))
        }
        PR_SET_KEEPCAPS => {
            let keep_capabilities = parse_keep_capabilities(arg2)?;
            ctx.process.update_credentials(|credentials| {
                credentials.set_keep_capabilities(keep_capabilities)
            })?;
            Ok(SyscallReturn::Return(0))
        }
        PR_SET_NAME => {
            let name = read_thread_name(vm_space, arg2)?;
            with_current_task_data(|task_data| {
                *task_data.thread_name.lock() = name;
                Ok(())
            })?;
            Ok(SyscallReturn::Return(0))
        }
        PR_GET_NAME => {
            let name = with_current_task_data(|task_data| Ok(*task_data.thread_name.lock()))?;
            write_to_user(vm_space, arg2, &name[..thread_name_write_len(&name)])?;
            Ok(SyscallReturn::Return(0))
        }
        PR_CAPBSET_READ => {
            let capability = parse_capability(arg2)?;
            let contains = ctx
                .posix_thread
                .credentials()
                .bounding_capset()
                .contains(capability) as isize;
            Ok(SyscallReturn::Return(contains))
        }
        PR_CAPBSET_DROP => {
            let capability = parse_capability(arg2)?;
            ctx.process.update_credentials(|credentials| {
                credentials.drop_bounding_capability(capability)
            })?;
            Ok(SyscallReturn::Return(0))
        }
        PR_GET_SECUREBITS => {
            let securebits = ctx.posix_thread.credentials().securebits();
            Ok(SyscallReturn::Return(securebits as isize))
        }
        PR_SET_SECUREBITS => {
            let securebits = parse_securebits(arg2);
            ctx.process
                .update_credentials(|credentials| credentials.set_securebits(securebits))?;
            Ok(SyscallReturn::Return(0))
        }
        PR_SET_TIMERSLACK => {
            if (arg2 as isize) < 0 {
                return Err(Error::new(Errno::EINVAL));
            }
            with_current_task_data(|task_data| {
                let slack = if arg2 == 0 {
                    task_data.default_timer_slack_ns.load(Ordering::Relaxed)
                } else {
                    arg2 as u64
                };
                task_data.timer_slack_ns.store(slack, Ordering::Relaxed);
                Ok(())
            })?;
            Ok(SyscallReturn::Return(0))
        }
        PR_GET_TIMERSLACK => {
            let slack = with_current_task_data(|task_data| {
                Ok(task_data.timer_slack_ns.load(Ordering::Relaxed))
            })?;
            Ok(SyscallReturn::Return(slack as isize))
        }
        PR_SET_CHILD_SUBREAPER => {
            ctx.process.set_child_subreaper(arg2 != 0);
            Ok(SyscallReturn::Return(0))
        }
        PR_GET_CHILD_SUBREAPER => {
            let is_child_subreaper = ctx.process.is_child_subreaper() as u32;
            write_to_user(vm_space, arg2, &is_child_subreaper.to_ne_bytes())?;
            Ok(SyscallReturn::Return(0))
        }
        _ => Err(Error::new(Errno::EINVAL)),
    }
}

fn parse_parent_death_signal(arg: usize) -> Result<u32> {
    let signal = (arg as u8) as u32;
    if !(1..=64).contains(&signal) {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(signal)
}

fn parse_keep_capabilities(arg: usize) -> Result<bool> {
    let keep_capabilities = arg as u32;
    if keep_capabilities > 1 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(keep_capabilities != 0)
}

fn parse_securebits(arg: usize) -> u16 {
    arg as u16
}

fn read_thread_name(vm_space: &VmSpace, addr: usize) -> Result<[u8; THREAD_NAME_LEN]> {
    let mut name = [0u8; THREAD_NAME_LEN];
    for (idx, slot) in name.iter_mut().take(THREAD_NAME_LEN - 1).enumerate() {
        let byte_addr = addr.checked_add(idx).ok_or(Error::new(Errno::EFAULT))?;
        let byte = read_from_user_to_vec(vm_space, byte_addr, 1)?[0];
        if byte == 0 {
            break;
        }
        *slot = byte;
    }
    Ok(name)
}

fn thread_name_write_len(name: &[u8; THREAD_NAME_LEN]) -> usize {
    name.iter()
        .position(|byte| *byte == 0)
        .map_or(THREAD_NAME_LEN, |idx| idx + 1)
}

fn parse_capability(capability: usize) -> Result<CapabilitySet> {
    let capability = u32::try_from(capability).map_err(|_| Error::new(Errno::EINVAL))?;
    CapabilitySet::from_capability_number(capability).ok_or(Error::new(Errno::EINVAL))
}

fn with_current_task_data<T>(f: impl FnOnce(&UserTaskData) -> Result<T>) -> Result<T> {
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let task_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;
    f(task_data)
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn parent_death_signal_arg_matches_kernel_u8_truncation() {
        assert_eq!(parse_parent_death_signal(257).unwrap(), 1);
        assert_eq!(
            parse_parent_death_signal(256).unwrap_err().errno(),
            Errno::EINVAL
        );
        assert_eq!(
            parse_parent_death_signal(65).unwrap_err().errno(),
            Errno::EINVAL
        );
    }

    #[ktest]
    fn keep_capabilities_arg_matches_kernel_u32_truncation() {
        assert!(!parse_keep_capabilities(1usize << 32).unwrap());
        assert!(parse_keep_capabilities((1usize << 32) + 1).unwrap());
        assert_eq!(
            parse_keep_capabilities(2).unwrap_err().errno(),
            Errno::EINVAL
        );
    }

    #[ktest]
    fn securebits_arg_matches_kernel_u16_truncation() {
        assert_eq!(parse_securebits((1usize << 16) | 0x12), 0x12);
    }

    #[ktest]
    fn thread_name_get_writes_c_string_len() {
        let mut name = [0u8; THREAD_NAME_LEN];
        name[..3].copy_from_slice(b"ash");

        assert_eq!(thread_name_write_len(&name), 4);
        assert_eq!(
            thread_name_write_len(&[b'a'; THREAD_NAME_LEN]),
            THREAD_NAME_LEN
        );
    }
}
