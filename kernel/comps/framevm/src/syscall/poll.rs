// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;
use core::{sync::atomic::Ordering, time::Duration};

use ostd::{mm::VmSpace, sync::SpinLock};

use super::{
    Errno, Error, Result, current_fd_table, current_nofile_limit,
    nanosleep::{duration_from_ns, read_relative_timespec_ns},
    reactivate_current_vm_space, read_i16_from_user, read_i32_from_user, read_u64_from_user,
    sanitize_signal_mask, with_current_user_task_data, write_to_user,
};
use crate::{
    events::IoEvents,
    fd_table::{FileDesc, FileTable, RawFileDesc},
    pollee::{PollHandle, Poller},
};

/// Polls file descriptors.
pub(super) fn sys_poll(
    fds_addr: usize,
    nfds: usize,
    timeout_millis: isize,
    vm_space: &VmSpace,
) -> Result<isize> {
    if nfds as u64 > current_nofile_limit()? {
        return Err(Error::new(Errno::EINVAL));
    }

    poll_with_timeout(
        vm_space,
        fds_addr,
        nfds,
        poll_timeout_from_millis(timeout_millis)?,
    )
}

/// Polls file descriptors with an optional temporary signal mask.
pub(super) fn sys_ppoll(
    fds_addr: usize,
    nfds: usize,
    timespec_addr: usize,
    sigmask_addr: usize,
    sigmask_size: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    if nfds as u64 > current_nofile_limit()? {
        return Err(Error::new(Errno::EINVAL));
    }

    const SIGSET_SIZE: usize = 8;

    let timeout = poll_timeout_from_timespec(vm_space, timespec_addr)?;
    let old_signal_mask = if sigmask_addr != 0 {
        if sigmask_size != SIGSET_SIZE {
            return Err(Error::new(Errno::EINVAL));
        }

        let new_signal_mask = sanitize_signal_mask(read_u64_from_user(vm_space, sigmask_addr)?);
        Some(with_current_user_task_data(|task_data| {
            Ok(task_data
                .signal_mask
                .swap(new_signal_mask, Ordering::SeqCst))
        })?)
    } else {
        None
    };

    let poll_result = poll_with_timeout(vm_space, fds_addr, nfds, timeout);
    if let Some(old_signal_mask) = old_signal_mask {
        with_current_user_task_data(|task_data| {
            task_data
                .signal_mask
                .store(old_signal_mask, Ordering::SeqCst);
            Ok(())
        })?;
    }
    poll_result
}

fn poll_with_timeout(
    vm_space: &VmSpace,
    fds_addr: usize,
    nfds: usize,
    timeout: Option<Duration>,
) -> Result<isize> {
    let mut poll_fds = read_poll_fds(vm_space, fds_addr, nfds)?;
    let ready_count = do_poll(&mut poll_fds, timeout.as_ref());
    write_poll_fds(vm_space, fds_addr, &poll_fds)?;
    Ok(ready_count? as isize)
}

fn poll_timeout_from_millis(timeout: isize) -> Result<Option<Duration>> {
    if timeout < 0 {
        return Ok(None);
    }

    Ok(Some(Duration::from_millis(timeout as u64)))
}

fn poll_timeout_from_timespec(
    vm_space: &VmSpace,
    timespec_addr: usize,
) -> Result<Option<Duration>> {
    if timespec_addr == 0 {
        return Ok(None);
    }

    let timeout_ns = read_relative_timespec_ns(vm_space, timespec_addr)?;
    Ok(Some(duration_from_ns(timeout_ns)))
}

pub(super) struct PollFd {
    fd: Option<FileDesc>,
    events: IoEvents,
    revents: IoEvents,
}

impl PollFd {
    pub(super) fn new(fd: Option<FileDesc>, events: IoEvents) -> Self {
        Self {
            fd,
            events,
            revents: IoEvents::empty(),
        }
    }

    fn from_raw(fd: RawFileDesc, events: i16) -> Self {
        Self {
            fd: FileDesc::try_from(fd).ok(),
            events: IoEvents::from_bits_truncate((events as u16) as u32),
            revents: IoEvents::empty(),
        }
    }

    pub(super) const fn fd(&self) -> Option<FileDesc> {
        self.fd
    }

    pub(super) const fn revents(&self) -> IoEvents {
        self.revents
    }

    fn raw_revents(&self) -> i16 {
        self.revents.bits() as i16
    }

    fn revents_for_missing_file(&self) -> IoEvents {
        if self.fd.is_some() {
            IoEvents::NVAL
        } else {
            IoEvents::empty()
        }
    }
}

fn read_poll_fds(vm_space: &VmSpace, fds_addr: usize, nfds: usize) -> Result<Vec<PollFd>> {
    let mut poll_fds = Vec::with_capacity(nfds);
    for idx in 0..nfds {
        let pollfd_addr = pollfd_addr(fds_addr, idx)?;
        let fd = read_i32_from_user(vm_space, pollfd_addr)?;
        let events = read_i16_from_user(vm_space, pollfd_addr + 4)?;
        poll_fds.push(PollFd::from_raw(fd, events));
    }
    Ok(poll_fds)
}

fn write_poll_fds(vm_space: &VmSpace, fds_addr: usize, poll_fds: &[PollFd]) -> Result<()> {
    for (idx, poll_fd) in poll_fds.iter().enumerate() {
        let pollfd_addr = pollfd_addr(fds_addr, idx)?;
        write_to_user(
            vm_space,
            pollfd_addr + 6,
            &poll_fd.raw_revents().to_ne_bytes(),
        )?;
    }
    Ok(())
}

fn pollfd_addr(fds_addr: usize, idx: usize) -> Result<usize> {
    fds_addr
        .checked_add(
            idx.checked_mul(RAW_POLLFD_SIZE)
                .ok_or(Error::new(Errno::EFAULT))?,
        )
        .ok_or(Error::new(Errno::EFAULT))
}

const RAW_POLLFD_SIZE: usize = 8;

pub(super) fn do_poll(poll_fds: &mut [PollFd], timeout: Option<&Duration>) -> Result<usize> {
    let fd_table = current_fd_table()?;

    reactivate_current_vm_space()?;
    let mut poller = Poller::new(timeout)?;
    let ready_count = poll_once(poll_fds, fd_table.as_ref(), Some(poller.as_handle_mut()));
    if ready_count != 0 {
        return Ok(ready_count);
    }
    if timeout.is_some_and(Duration::is_zero) {
        return Ok(0);
    }

    loop {
        match poller.wait() {
            Ok(()) => (),
            Err(error) if error.errno() == Errno::ETIME => return Ok(0),
            Err(error) => return Err(error),
        }

        reactivate_current_vm_space()?;
        let ready_count = poll_once(poll_fds, fd_table.as_ref(), None);
        if ready_count != 0 {
            return Ok(ready_count);
        }
    }
}

fn poll_once(
    poll_fds: &mut [PollFd],
    fd_table: &SpinLock<FileTable>,
    mut poller: Option<&mut PollHandle>,
) -> usize {
    let mut ready_count = 0usize;
    for poll_fd in poll_fds {
        poll_fd.revents = poll_fd_revents(fd_table, poll_fd, &mut poller);

        if !poll_fd.revents.is_empty() {
            ready_count += 1;
        }
    }

    ready_count
}

fn poll_fd_revents(
    fd_table: &SpinLock<FileTable>,
    poll_fd: &PollFd,
    poller: &mut Option<&mut PollHandle>,
) -> IoEvents {
    let Some(fd) = poll_fd.fd else {
        return IoEvents::empty();
    };

    let raw_fd = RawFileDesc::from(fd);
    let handle = fd_table.lock().get(raw_fd);
    match handle {
        Ok(file) => {
            let poller = poller.as_mut().map(|poller| &mut **poller);
            file.poll_revents(poll_fd.events, poller)
        }
        Err(_) => poll_fd.revents_for_missing_file(),
    }
}
