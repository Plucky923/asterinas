// SPDX-License-Identifier: MPL-2.0

//! Kernel-style syscall context for the trimmed kernel image.

use alloc::sync::Arc;

use ostd::{
    mm::{Fallible, Vaddr, VmSpace, VmWriter},
    task::Task,
};

use crate::{
    error::{Errno, Error, Result},
    process::{PosixThread, ProcessIdentity},
    task::UserTaskData,
};

/// The context that can be accessed from the current POSIX thread.
///
/// This keeps the same syscall-facing shape as `kernel/src/context.rs`, so
/// Syscall handlers can be copied from the kernel and then backed by
/// the trimmed kernel image's process/VFS objects.
#[derive(Clone)]
pub struct Context<'a> {
    pub(crate) process: Arc<ProcessIdentity>,
    pub(crate) posix_thread: PosixThread,
    vm_space: &'a VmSpace,
}

impl<'a> Context<'a> {
    /// Creates a syscall context from the current user task.
    pub(crate) fn from_current(vm_space: &'a VmSpace) -> Result<Self> {
        let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
        let task_data = current
            .data()
            .downcast_ref::<UserTaskData>()
            .ok_or(Error::new(Errno::EINVAL))?;

        let process = task_data.process.clone();
        let credentials = process.credentials();
        Ok(Self {
            process,
            posix_thread: PosixThread::new(task_data.tid, credentials),
            vm_space,
        })
    }

    /// Gets the userspace of the current task.
    pub(crate) const fn user_space(&self) -> CurrentUserSpace<'a> {
        CurrentUserSpace {
            vm_space: self.vm_space,
        }
    }
}

/// The user's memory space of the current task.
pub(crate) struct CurrentUserSpace<'a> {
    vm_space: &'a VmSpace,
}

impl<'a> CurrentUserSpace<'a> {
    /// Creates a writer to write data into the user space of the current task.
    pub(crate) fn writer(&self, vaddr: Vaddr, len: usize) -> Result<VmWriter<'a, Fallible>> {
        Ok(self.vm_space.writer(vaddr, len)?)
    }

    /// Returns the current `VmSpace`.
    #[expect(
        dead_code,
        reason = "Kernel syscall context shape is filled as handlers are copied"
    )]
    pub(crate) const fn vm_space(&self) -> &'a VmSpace {
        self.vm_space
    }
}
