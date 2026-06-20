// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use ostd::mm::VmSpace;

use super::{
    Errno, Error, Result, read_u32_from_user, read_u64_from_user, read_usize_from_user,
    with_current_user_task_data, write_to_user,
};
use crate::signal::{RawSignalAction, sanitize_signal_action_flags, sanitize_signal_mask};

/// Sets or queries a signal action.
pub(super) fn sys_rt_sigaction(
    signal_raw: usize,
    action_addr: usize,
    old_action_addr: usize,
    sigset_size: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let signal = u8::try_from(signal_raw).map_err(|_| Error::new(Errno::EINVAL))?;

    if sigset_size != 8 {
        return Err(Error::new(Errno::EINVAL));
    }

    with_current_user_task_data(|task_data| {
        let old_action = if action_addr != 0 {
            let new_action = read_raw_signal_action(vm_space, action_addr)?;
            task_data.signal_actions.set(signal, new_action)?
        } else {
            task_data.signal_actions.get(signal)?
        };

        if old_action_addr != 0 {
            write_raw_signal_action(vm_space, old_action_addr, old_action)?;
        }
        Ok(0)
    })
}

/// Sets or queries the signal mask.
pub(super) fn sys_rt_sigprocmask(
    mask_op_raw: u32,
    new_set_addr: usize,
    old_set_addr: usize,
    sigset_size: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let mask_op = SignalMaskOp::try_from(mask_op_raw)?;

    if sigset_size != 8 {
        return Err(Error::new(Errno::EINVAL));
    }

    with_current_user_task_data(|task_data| {
        let old_mask = task_data.signal_mask.load(Ordering::SeqCst);
        if old_set_addr != 0 {
            write_to_user(vm_space, old_set_addr, &old_mask.to_ne_bytes())?;
        }

        if new_set_addr != 0 {
            let new_mask = sanitize_signal_mask(read_u64_from_user(vm_space, new_set_addr)?);
            let updated_mask = match mask_op {
                SignalMaskOp::Block => old_mask | new_mask,
                SignalMaskOp::Unblock => old_mask & !new_mask,
                SignalMaskOp::SetMask => new_mask,
            };
            task_data
                .signal_mask
                .store(sanitize_signal_mask(updated_mask), Ordering::SeqCst);
        }
        Ok(0)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalMaskOp {
    Block,
    Unblock,
    SetMask,
}

impl TryFrom<u32> for SignalMaskOp {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Block),
            1 => Ok(Self::Unblock),
            2 => Ok(Self::SetMask),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }
}

fn read_raw_signal_action(vm_space: &VmSpace, addr: usize) -> Result<RawSignalAction> {
    Ok(RawSignalAction {
        handler_ptr: read_usize_from_user(vm_space, addr)?,
        flags: sanitize_signal_action_flags(read_u32_from_user(vm_space, addr + 8)?),
        restorer_ptr: read_usize_from_user(vm_space, addr + 16)?,
        mask: sanitize_signal_mask(read_u64_from_user(vm_space, addr + 24)?),
    })
}

fn write_raw_signal_action(vm_space: &VmSpace, addr: usize, action: RawSignalAction) -> Result<()> {
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&action.handler_ptr.to_ne_bytes());
    buf[8..12].copy_from_slice(&action.flags.to_ne_bytes());
    buf[16..24].copy_from_slice(&action.restorer_ptr.to_ne_bytes());
    buf[24..32].copy_from_slice(&action.mask.to_ne_bytes());
    write_to_user(vm_space, addr, &buf)
}
