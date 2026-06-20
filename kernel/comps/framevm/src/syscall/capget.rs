// SPDX-License-Identifier: MPL-2.0

//! Gets Linux capability sets.

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, SyscallReturn, read_u32_from_user, write_to_user};
use crate::{context::Context, process::CapabilitySet, task};

pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const USER_CAP_DATA_SIZE: usize = 12;

pub fn sys_capget(
    cap_user_header_addr: usize,
    cap_user_data_addr: usize,
    ctx: &Context,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    let header = read_cap_header(vm_space, cap_user_header_addr)?;

    if header.version != LINUX_CAPABILITY_VERSION_3 {
        write_to_user(
            vm_space,
            cap_user_header_addr,
            &LINUX_CAPABILITY_VERSION_3.to_ne_bytes(),
        )?;
        if cap_user_data_addr == 0 {
            return Ok(SyscallReturn::Return(0));
        }
        return Err(Error::new(Errno::EINVAL));
    }

    if cap_user_data_addr == 0 {
        return Ok(SyscallReturn::Return(0));
    }
    if header.pid > i32::MAX as u32 {
        return Err(Error::new(Errno::EINVAL));
    }

    let credentials = if header.pid == 0 || header.pid == ctx.posix_thread.tid() {
        ctx.posix_thread.credentials()
    } else {
        task::process_for_tid(header.pid)
            .ok_or(Error::new(Errno::ESRCH))?
            .credentials()
    };

    write_cap_data(
        vm_space,
        cap_user_data_addr,
        credentials.effective_capset(),
        credentials.permitted_capset(),
        credentials.inheritable_capset(),
    )?;

    Ok(SyscallReturn::Return(0))
}

pub(super) struct CapHeader {
    pub version: u32,
    pub pid: u32,
}

pub(super) fn read_cap_header(vm_space: &VmSpace, addr: usize) -> Result<CapHeader> {
    Ok(CapHeader {
        version: read_u32_from_user(vm_space, addr)?,
        pid: read_u32_from_user(vm_space, user_addr_add(addr, 4)?)?,
    })
}

pub(super) fn read_cap_data(vm_space: &VmSpace, addr: usize) -> Result<CapabilitySetTuple> {
    let lo = read_one_cap_data(vm_space, addr)?;
    let hi = read_one_cap_data(vm_space, user_addr_add(addr, USER_CAP_DATA_SIZE)?)?;
    Ok(CapabilitySetTuple {
        effective: CapabilitySet::from_lo_hi(lo.effective, hi.effective),
        permitted: CapabilitySet::from_lo_hi(lo.permitted, hi.permitted),
        inheritable: CapabilitySet::from_lo_hi(lo.inheritable, hi.inheritable),
    })
}

fn write_cap_data(
    vm_space: &VmSpace,
    addr: usize,
    effective: CapabilitySet,
    permitted: CapabilitySet,
    inheritable: CapabilitySet,
) -> Result<()> {
    let (effective_lo, effective_hi) = effective.to_lo_hi();
    let (permitted_lo, permitted_hi) = permitted.to_lo_hi();
    let (inheritable_lo, inheritable_hi) = inheritable.to_lo_hi();
    write_one_cap_data(
        vm_space,
        addr,
        RawCapData {
            effective: effective_lo,
            permitted: permitted_lo,
            inheritable: inheritable_lo,
        },
    )?;
    write_one_cap_data(
        vm_space,
        user_addr_add(addr, USER_CAP_DATA_SIZE)?,
        RawCapData {
            effective: effective_hi,
            permitted: permitted_hi,
            inheritable: inheritable_hi,
        },
    )
}

fn read_one_cap_data(vm_space: &VmSpace, addr: usize) -> Result<RawCapData> {
    Ok(RawCapData {
        effective: read_u32_from_user(vm_space, addr)?,
        permitted: read_u32_from_user(vm_space, user_addr_add(addr, 4)?)?,
        inheritable: read_u32_from_user(vm_space, user_addr_add(addr, 8)?)?,
    })
}

fn write_one_cap_data(vm_space: &VmSpace, addr: usize, data: RawCapData) -> Result<()> {
    write_to_user(vm_space, addr, &data.effective.to_ne_bytes())?;
    write_to_user(
        vm_space,
        user_addr_add(addr, 4)?,
        &data.permitted.to_ne_bytes(),
    )?;
    write_to_user(
        vm_space,
        user_addr_add(addr, 8)?,
        &data.inheritable.to_ne_bytes(),
    )
}

fn user_addr_add(addr: usize, offset: usize) -> Result<usize> {
    addr.checked_add(offset).ok_or(Error::new(Errno::EFAULT))
}

pub(super) struct CapabilitySetTuple {
    pub effective: CapabilitySet,
    pub permitted: CapabilitySet,
    pub inheritable: CapabilitySet,
}

struct RawCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
