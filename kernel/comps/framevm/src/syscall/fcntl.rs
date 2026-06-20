// SPDX-License-Identifier: MPL-2.0

//! File-descriptor control syscall.

use super::{
    Errno, Error, FdFlags, RawFileDesc, Result, StatusFlags, current_fd_table, current_nofile_limit,
};
use crate::{
    fd_table::FileDesc,
    process::{Pid, pid_table},
};

pub(super) fn sys_fcntl(raw_fd: RawFileDesc, cmd: i32, arg: u64) -> Result<isize> {
    let fd = FileDesc::try_from(raw_fd)?;

    const F_DUPFD: i32 = 0;
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const F_GETLK: i32 = 5;
    const F_SETLK: i32 = 6;
    const F_SETLKW: i32 = 7;
    const F_SETOWN: i32 = 8;
    const F_GETOWN: i32 = 9;
    const F_DUPFD_CLOEXEC: i32 = 1030;
    const F_ADD_SEALS: i32 = 1033;
    const F_GET_SEALS: i32 = 1034;

    match cmd {
        F_DUPFD => {
            let nofile_limit = current_nofile_limit()?;
            let ceil_fd = FileDesc::try_from(arg as RawFileDesc)?;
            if !ceil_fd.is_below_nofile_limit(nofile_limit) {
                return Err(Error::new(Errno::EINVAL));
            }
            let fd_table = current_fd_table()?;
            let new_fd = fd_table
                .lock()
                .dup_ceil(fd, ceil_fd, FdFlags::empty(), nofile_limit)?;
            Ok(new_fd.into())
        }
        F_DUPFD_CLOEXEC => {
            let nofile_limit = current_nofile_limit()?;
            let ceil_fd = FileDesc::try_from(arg as RawFileDesc)?;
            if !ceil_fd.is_below_nofile_limit(nofile_limit) {
                return Err(Error::new(Errno::EINVAL));
            }
            let fd_table = current_fd_table()?;
            let new_fd = fd_table
                .lock()
                .dup_ceil(fd, ceil_fd, FdFlags::CLOEXEC, nofile_limit)?;
            Ok(new_fd.into())
        }
        F_GETFD => {
            let fd_table = current_fd_table()?;
            let flags = fd_table.lock().get_entry(fd)?.flags();
            Ok(flags.bits() as isize)
        }
        F_SETFD => {
            let flags = if arg > u64::from(u8::MAX) {
                return Err(Error::new(Errno::EINVAL));
            } else {
                FdFlags::from_bits(arg as u8).ok_or(Error::new(Errno::EINVAL))?
            };
            let fd_table = current_fd_table()?;
            fd_table.lock().get_entry(fd)?.set_flags(flags);
            Ok(0)
        }
        F_GETFL => {
            let fd_table = current_fd_table()?;
            let file = fd_table.lock().get_file(fd)?;
            Ok((file.status_flags().bits() | file.access_mode().bits()) as isize)
        }
        F_SETFL => {
            let valid_flags_mask = StatusFlags::O_APPEND
                | StatusFlags::O_ASYNC
                | StatusFlags::O_DIRECT
                | StatusFlags::O_NOATIME
                | StatusFlags::O_NONBLOCK;
            let fd_table = current_fd_table()?;
            let file = fd_table.lock().get_file(fd)?;
            let mut status_flags = file.status_flags();
            status_flags.remove(valid_flags_mask);
            status_flags.insert(StatusFlags::from_bits_truncate(arg as u32) & valid_flags_mask);
            file.set_status_flags(status_flags)?;
            Ok(0)
        }
        F_SETOWN => {
            let owner_pid = owner_pid_from_arg(arg)?;
            if let Some(pid) = owner_pid {
                let _ = pid_table::pid_table_mut()
                    .get_process(pid)
                    .ok_or(Error::new(Errno::ESRCH))?;
            }
            let fd_table = current_fd_table()?;
            fd_table.lock().get_entry(fd)?.set_owner(owner_pid);
            Ok(0)
        }
        F_GETOWN => {
            let fd_table = current_fd_table()?;
            Ok(fd_table.lock().get_entry(fd)?.owner().unwrap_or(0) as isize)
        }
        F_GETLK | F_SETLK | F_SETLKW | F_ADD_SEALS | F_GET_SEALS => {
            Err(Error::new(Errno::EOPNOTSUPP))
        }
        _ => Err(Error::new(Errno::EINVAL)),
    }
}

fn owner_pid_from_arg(arg: u64) -> Result<Option<Pid>> {
    let pid = (arg as i32).unsigned_abs();
    if pid > i32::MAX as u32 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok((pid != 0).then_some(pid as Pid))
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn setown_owner_arg_matches_kernel_pid_storage() {
        assert_eq!(owner_pid_from_arg(0).unwrap(), None);
        assert_eq!(owner_pid_from_arg(123).unwrap(), Some(123));
        assert_eq!(owner_pid_from_arg((-123i32) as u64).unwrap(), Some(123));
        assert_eq!(
            owner_pid_from_arg(i32::MIN as u64).unwrap_err().errno(),
            Errno::EINVAL
        );
    }
}
