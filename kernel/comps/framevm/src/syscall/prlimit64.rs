// SPDX-License-Identifier: MPL-2.0

//! Resource-limit syscall helpers.

use alloc::sync::Arc;

use ostd::mm::VmSpace;

use super::{
    Errno, Error, RawRLimit64, ResourceType, Result, SYSCTL_NR_OPEN, current_resource_limits,
    read_u64_from_user, with_current_user_task_data, write_to_user,
};
use crate::{
    process::{Credentials, ProcessIdentity},
    resource::ResourceLimits,
    task,
};

pub(super) fn sys_prlimit64(
    pid: usize,
    resource_raw: usize,
    new_rlim_addr: usize,
    old_rlim_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let resource = u32::try_from(resource_raw).map_err(|_| Error::new(Errno::EINVAL))?;
    let new_raw = if new_rlim_addr == 0 {
        None
    } else {
        Some(read_raw_rlimit64(vm_space, new_rlim_addr)?)
    };
    let target = rlimit_target(pid)?;
    let old_raw = do_prlimit64_for_target(
        resource,
        new_raw,
        target.resource_limits.as_ref(),
        target.can_raise_hard_limit,
    )?;
    if old_rlim_addr != 0 {
        write_raw_rlimit64(vm_space, old_rlim_addr, old_raw)?;
    }
    Ok(0)
}

pub(super) fn do_prlimit64(resource: u32, new_raw: Option<RawRLimit64>) -> Result<RawRLimit64> {
    let resource_limits = current_resource_limits()?;
    let can_raise_hard_limit = with_current_user_task_data(|task_data| {
        Ok(task_data.process.credentials().has_sys_resource())
    })?;
    do_prlimit64_for_target(
        resource,
        new_raw,
        resource_limits.as_ref(),
        can_raise_hard_limit,
    )
}

fn do_prlimit64_for_target(
    resource: u32,
    new_raw: Option<RawRLimit64>,
    resource_limits: &ResourceLimits,
    can_raise_hard_limit: bool,
) -> Result<RawRLimit64> {
    let resource = ResourceType::try_from(resource)?;
    let rlimit = resource_limits.get_rlimit(resource);
    if let Some(new_raw) = new_raw {
        if resource == ResourceType::NoFile && new_raw.max > SYSCTL_NR_OPEN {
            return Err(Error::new(Errno::EPERM));
        }
        return rlimit.set_raw_rlimit(new_raw, can_raise_hard_limit);
    }

    Ok(rlimit.get_raw_rlimit())
}

struct RLimitTarget {
    resource_limits: Arc<ResourceLimits>,
    can_raise_hard_limit: bool,
}

fn rlimit_target(pid: usize) -> Result<RLimitTarget> {
    with_current_user_task_data(|current_task_data| {
        let current_process = current_task_data.process.clone();
        let current_credentials = current_process.credentials();
        let can_raise_hard_limit = current_credentials.has_sys_resource();

        if pid == 0 || pid == current_process.pid() as usize {
            return Ok(RLimitTarget {
                resource_limits: current_task_data.resource_limits.clone(),
                can_raise_hard_limit,
            });
        }

        let pid = u32::try_from(pid).map_err(|_| Error::new(Errno::ESRCH))?;
        let (target_process, resource_limits) =
            task::process_resource_limits_for_pid(pid).ok_or(Error::new(Errno::ESRCH))?;
        check_rlimit_perm(&target_process, &current_credentials)?;
        Ok(RLimitTarget {
            resource_limits,
            can_raise_hard_limit,
        })
    })
}

fn check_rlimit_perm(
    target_process: &ProcessIdentity,
    current_credentials: &Credentials,
) -> Result<()> {
    if current_credentials.has_sys_resource() {
        return Ok(());
    }

    let target_credentials = target_process.credentials();
    if can_access_resource_limits(current_credentials, &target_credentials) {
        return Ok(());
    }

    Err(Error::new(Errno::EPERM))
}

fn can_access_resource_limits(current: &Credentials, target: &Credentials) -> bool {
    current.ruid() == target.ruid()
        && current.ruid() == target.euid()
        && current.ruid() == target.suid()
        && current.rgid() == target.rgid()
        && current.rgid() == target.egid()
        && current.rgid() == target.sgid()
}

pub(super) fn read_raw_rlimit64(vm_space: &VmSpace, addr: usize) -> Result<RawRLimit64> {
    Ok(RawRLimit64 {
        cur: read_u64_from_user(vm_space, addr)?,
        max: read_u64_from_user(vm_space, addr + 8)?,
    })
}

pub(super) fn write_raw_rlimit64(vm_space: &VmSpace, addr: usize, raw: RawRLimit64) -> Result<()> {
    write_to_user(vm_space, addr, &raw.cur.to_ne_bytes())?;
    write_to_user(vm_space, addr + 8, &raw.max.to_ne_bytes())
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;
    use crate::process::{Gid, Uid};

    #[ktest]
    fn rlimit_permission_matches_kernel_uid_gid_shape() {
        let current = nonroot_credentials(1000, 1000);
        let same_identity = nonroot_credentials(1000, 1000);
        let different_uid = nonroot_credentials(1001, 1000);
        let different_gid = nonroot_credentials(1000, 1001);

        assert!(can_access_resource_limits(&current, &same_identity));
        assert!(!can_access_resource_limits(&current, &different_uid));
        assert!(!can_access_resource_limits(&current, &different_gid));
    }

    fn nonroot_credentials(uid: u32, gid: u32) -> Credentials {
        let mut credentials = Credentials::new_root();
        credentials.set_gid(Gid::new(gid)).unwrap();
        credentials.set_uid(Uid::new(uid)).unwrap();
        credentials
    }
}
