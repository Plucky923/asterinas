// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;
use core::{sync::atomic::Ordering, time::Duration};

use ostd::mm::VmSpace;

use super::{
    Errno, Error, Result,
    nanosleep::{duration_from_ns, read_relative_timespec_ns},
    poll::{PollFd, do_poll},
    read_fixed_from_user, read_i64_from_user, read_u64_from_user, read_usize_from_user,
    sanitize_signal_mask, with_current_user_task_data, write_to_user,
};
use crate::{events::IoEvents, fd_table::FileDesc};

const FD_SETSIZE: usize = 1024;
const FD_SET_BYTES: usize = FD_SETSIZE / 8;
const USEC_PER_SEC: i64 = 1_000_000;

/// Waits for readiness on sets of file descriptors.
pub(super) fn sys_select(
    nfds: usize,
    readfds_addr: usize,
    writefds_addr: usize,
    exceptfds_addr: usize,
    timeval_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let timeout = read_timeval_timeout(vm_space, timeval_addr)?;
    do_sys_select(
        nfds,
        readfds_addr,
        writefds_addr,
        exceptfds_addr,
        timeout,
        vm_space,
    )
}

/// Waits for readiness on sets of file descriptors with an optional signal mask.
pub(super) fn sys_pselect6(
    nfds: usize,
    readfds_addr: usize,
    writefds_addr: usize,
    exceptfds_addr: usize,
    timespec_addr: usize,
    sigmask_pack_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let timeout = if timespec_addr == 0 {
        None
    } else {
        Some(duration_from_ns(read_relative_timespec_ns(
            vm_space,
            timespec_addr,
        )?))
    };
    let old_signal_mask = apply_pselect_signal_mask(vm_space, sigmask_pack_addr)?;

    let select_result = do_sys_select(
        nfds,
        readfds_addr,
        writefds_addr,
        exceptfds_addr,
        timeout,
        vm_space,
    );
    if let Some(old_signal_mask) = old_signal_mask {
        with_current_user_task_data(|task_data| {
            task_data
                .signal_mask
                .store(old_signal_mask, Ordering::SeqCst);
            Ok(())
        })?;
    }
    select_result
}

fn do_sys_select(
    nfds: usize,
    readfds_addr: usize,
    writefds_addr: usize,
    exceptfds_addr: usize,
    timeout: Option<Duration>,
    vm_space: &VmSpace,
) -> Result<isize> {
    if nfds > FD_SETSIZE {
        return Err(Error::new(Errno::EINVAL));
    }

    let mut readfds = read_fdset(vm_space, readfds_addr)?;
    let mut writefds = read_fdset(vm_space, writefds_addr)?;
    let mut exceptfds = read_fdset(vm_space, exceptfds_addr)?;

    let ready_count = do_select(
        nfds,
        readfds.as_mut(),
        writefds.as_mut(),
        exceptfds.as_mut(),
        timeout.as_ref(),
    )?;

    write_fdset(vm_space, readfds_addr, readfds.as_ref())?;
    write_fdset(vm_space, writefds_addr, writefds.as_ref())?;
    write_fdset(vm_space, exceptfds_addr, exceptfds.as_ref())?;
    Ok(ready_count as isize)
}

fn do_select(
    nfds: usize,
    mut readfds: Option<&mut FdSet>,
    mut writefds: Option<&mut FdSet>,
    mut exceptfds: Option<&mut FdSet>,
    timeout: Option<&Duration>,
) -> Result<usize> {
    let mut poll_fds = Vec::new();
    for raw_fd in 0..nfds {
        let events = convert_rwe_to_events(
            readfds.as_ref().is_some_and(|fdset| fdset.is_set(raw_fd)),
            writefds.as_ref().is_some_and(|fdset| fdset.is_set(raw_fd)),
            exceptfds.as_ref().is_some_and(|fdset| fdset.is_set(raw_fd)),
        );
        if events.is_empty() {
            continue;
        }

        let fd = FileDesc::try_from(raw_fd as i32).ok();
        poll_fds.push(PollFd::new(fd, events));
    }

    clear_fdset(readfds.as_deref_mut());
    clear_fdset(writefds.as_deref_mut());
    clear_fdset(exceptfds.as_deref_mut());

    if do_poll(&mut poll_fds, timeout)? == 0 {
        return Ok(0);
    }

    let mut total_revents = 0usize;
    for poll_fd in &poll_fds {
        let Some(fd) = poll_fd.fd() else {
            continue;
        };
        let raw_fd = i32::from(fd) as usize;
        let (readable, writable, except) = convert_events_to_rwe(poll_fd.revents())?;
        if readable && let Some(fdset) = readfds.as_deref_mut() {
            fdset.set(raw_fd)?;
            total_revents += 1;
        }
        if writable && let Some(fdset) = writefds.as_deref_mut() {
            fdset.set(raw_fd)?;
            total_revents += 1;
        }
        if except && let Some(fdset) = exceptfds.as_deref_mut() {
            fdset.set(raw_fd)?;
            total_revents += 1;
        }
    }

    Ok(total_revents)
}

fn read_timeval_timeout(vm_space: &VmSpace, timeval_addr: usize) -> Result<Option<Duration>> {
    if timeval_addr == 0 {
        return Ok(None);
    }

    let sec = read_i64_from_user(vm_space, timeval_addr)?;
    let usec = read_i64_from_user(vm_space, timeval_addr + 8)?;
    if sec < 0 || !(0..USEC_PER_SEC).contains(&usec) {
        return Err(Error::new(Errno::EINVAL));
    }

    Ok(Some(Duration::new(sec as u64, (usec as u32) * 1_000)))
}

fn apply_pselect_signal_mask(vm_space: &VmSpace, sigmask_pack_addr: usize) -> Result<Option<u64>> {
    if sigmask_pack_addr == 0 {
        return Ok(None);
    }

    let sigmask_addr = read_usize_from_user(vm_space, sigmask_pack_addr)?;
    let sigmask_size = read_usize_from_user(vm_space, sigmask_pack_addr + size_of::<usize>())?;
    if sigmask_addr == 0 {
        return Ok(None);
    }
    if sigmask_size != size_of::<u64>() {
        return Err(Error::new(Errno::EINVAL));
    }

    let new_signal_mask = sanitize_signal_mask(read_u64_from_user(vm_space, sigmask_addr)?);
    with_current_user_task_data(|task_data| {
        Ok(Some(
            task_data
                .signal_mask
                .swap(new_signal_mask, Ordering::SeqCst),
        ))
    })
}

fn read_fdset(vm_space: &VmSpace, fdset_addr: usize) -> Result<Option<FdSet>> {
    if fdset_addr == 0 {
        return Ok(None);
    }

    Ok(Some(FdSet {
        bytes: read_fixed_from_user::<FD_SET_BYTES>(vm_space, fdset_addr)?,
    }))
}

fn write_fdset(vm_space: &VmSpace, fdset_addr: usize, fdset: Option<&FdSet>) -> Result<()> {
    let Some(fdset) = fdset else {
        return Ok(());
    };

    write_to_user(vm_space, fdset_addr, &fdset.bytes)
}

fn clear_fdset(fdset: Option<&mut FdSet>) {
    if let Some(fdset) = fdset {
        fdset.clear();
    }
}

fn convert_rwe_to_events(readable: bool, writable: bool, except: bool) -> IoEvents {
    let mut events = IoEvents::empty();
    if readable {
        events |= IoEvents::IN;
    }
    if writable {
        events |= IoEvents::OUT;
    }
    if except {
        events |= IoEvents::PRI;
    }
    events
}

fn convert_events_to_rwe(events: IoEvents) -> Result<(bool, bool, bool)> {
    if events.contains(IoEvents::NVAL) {
        return Err(Error::new(Errno::EBADF));
    }

    let readable = events.intersects(IoEvents::IN | IoEvents::HUP | IoEvents::ERR);
    let writable = events.intersects(IoEvents::OUT | IoEvents::ERR);
    let except = events.contains(IoEvents::PRI);
    Ok((readable, writable, except))
}

struct FdSet {
    bytes: [u8; FD_SET_BYTES],
}

impl FdSet {
    fn is_set(&self, fd: usize) -> bool {
        if fd >= FD_SETSIZE {
            return false;
        }
        let byte = self.bytes[fd / 8];
        (byte & (1u8 << (fd % 8))) != 0
    }

    fn set(&mut self, fd: usize) -> Result<()> {
        if fd >= FD_SETSIZE {
            return Err(Error::new(Errno::EINVAL));
        }
        self.bytes[fd / 8] |= 1u8 << (fd % 8);
        Ok(())
    }

    fn clear(&mut self) {
        self.bytes.fill(0);
    }
}
