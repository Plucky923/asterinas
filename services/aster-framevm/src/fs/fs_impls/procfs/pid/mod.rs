// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use super::{
    decimal_string, signed_decimal_string,
    template::{
        ProcDir, ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry, StaticDirEntry,
        listed_entries_from_table, lookup_child_from_table, visit_listed_entries,
    },
};
use crate::{
    fs::{
        file::{InodeType, mkmod},
        vfs::inode::{Inode, RevalidationPolicy},
    },
    prelude::*,
    process::{Process, posix_thread::AsPosixThread},
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]`.
pub struct PidDirOps {
    process: Weak<Process>,
}

impl PidDirOps {
    pub fn new_inode(process: Arc<Process>, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3493>
        ProcDir::new(
            Self {
                process: Arc::downgrade(&process),
            },
            parent,
            mkmod!(a+rx),
        )
    }

    pub fn process(&self) -> Option<Arc<Process>> {
        self.process.upgrade()
    }

    fn main_thread(&self) -> Option<Arc<Thread>> {
        self.process().map(|process| process.main_thread())
    }

    const STATIC_ENTRIES: &[StaticEntryWithOps<PidDirOps>] = &[
        ("cmdline", InodeType::File, CmdlineFileOps::new_inode),
        ("stat", InodeType::File, StatFileOps::new_inode),
        ("status", InodeType::File, StatusFileOps::new_inode),
    ];
}

impl ProcDirOps for PidDirOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.main_thread()
    }

    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if self.process().is_none() {
            return_errno_with_message!(Errno::ESRCH, "the process does not exist");
        }

        if let Some(child) = lookup_child_from_table(name, Self::STATIC_ENTRIES, |f| {
            (f)(self, this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the file does not exist");
    }

    fn revalidation_policy(&self) -> RevalidationPolicy {
        RevalidationPolicy::REVALIDATE_EXISTS
    }

    fn revalidate_exists(&self, _name: &str, _child: &dyn Inode) -> bool {
        self.process().is_some()
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        if self.process().is_none() {
            return_errno_with_message!(Errno::ENOENT, "the process does not exist");
        }

        visit_listed_entries(
            offset,
            listed_entries_from_table(Self::STATIC_ENTRIES),
            visit_fn,
        )
    }
}

struct CmdlineFileOps {
    process: Weak<Process>,
}

impl CmdlineFileOps {
    pub fn new_inode(dir: &PidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3340>
        ProcFile::new(
            Self {
                process: dir.process.clone(),
            },
            parent,
            mkmod!(a+r),
        )
    }
}

impl ProcFileOps for CmdlineFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.process.upgrade().map(|process| process.main_thread())
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let Some(process) = self.process.upgrade() else {
            return_errno_with_message!(Errno::ESRCH, "the process does not exist");
        };

        let vmar_guard = process.lock_vmar();
        let Some(init_stack_reader) = vmar_guard.init_stack_reader() else {
            return Ok(0);
        };

        init_stack_reader.argv(offset, writer)
    }
}

struct StatFileOps {
    process: Weak<Process>,
}

impl StatFileOps {
    pub fn new_inode(dir: &PidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3341>
        ProcFile::new(
            Self {
                process: dir.process.clone(),
            },
            parent,
            mkmod!(a+r),
        )
    }
}

impl ProcFileOps for StatFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.process.upgrade().map(|process| process.main_thread())
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let Some(process) = self.process.upgrade() else {
            return_errno_with_message!(Errno::ESRCH, "the process does not exist");
        };
        let thread = process.main_thread();
        let posix_thread = thread.as_posix_thread().unwrap();
        let comm = posix_thread
            .thread_name()
            .lock()
            .name()
            .to_string_lossy()
            .into_owned();
        let state = if thread.is_exited() { 'Z' } else { 'R' };
        let tty_nr = process
            .terminal()
            .map(|terminal| terminal.id().as_encoded_u64())
            .unwrap_or(0);
        let tpgid = process
            .terminal()
            .and_then(|terminal| terminal.job_control().foreground())
            .map(|pgrp| pgrp.pgid() as i64)
            .unwrap_or(-1);
        let pid = decimal_string(process.pid() as u64);
        let ppid = decimal_string(process.parent().pid() as u64);
        let pgrp = decimal_string(process.pgid() as u64);
        let session = decimal_string(process.sid() as u64);
        let tty_nr = decimal_string(tty_nr);
        let tpgid = signed_decimal_string(tpgid);

        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(
            printer,
            "{} ({}) {} {} {} {} {} {} 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            pid, comm, state, ppid, pgrp, session, tty_nr, tpgid,
        )?;
        Ok(printer.bytes_written())
    }
}

struct StatusFileOps {
    process: Weak<Process>,
}

impl StatusFileOps {
    pub fn new_inode(dir: &PidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3326>
        ProcFile::new(
            Self {
                process: dir.process.clone(),
            },
            parent,
            mkmod!(a+r),
        )
    }
}

impl ProcFileOps for StatusFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.process.upgrade().map(|process| process.main_thread())
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let Some(process) = self.process.upgrade() else {
            return_errno_with_message!(Errno::ESRCH, "the process does not exist");
        };
        let thread = process.main_thread();
        let posix_thread = thread.as_posix_thread().unwrap();
        let credentials = posix_thread.credentials();
        let state = if thread.is_exited() {
            "Z (zombie)"
        } else {
            "R (running)"
        };
        let pid = decimal_string(process.pid() as u64);
        let ppid = decimal_string(process.parent().pid() as u64);
        let ruid = decimal_string(u64::from(u32::from(credentials.ruid())));
        let euid = decimal_string(u64::from(u32::from(credentials.euid())));
        let suid = decimal_string(u64::from(u32::from(credentials.suid())));
        let fsuid = decimal_string(u64::from(u32::from(credentials.fsuid())));
        let rgid = decimal_string(u64::from(u32::from(credentials.rgid())));
        let egid = decimal_string(u64::from(u32::from(credentials.egid())));
        let sgid = decimal_string(u64::from(u32::from(credentials.sgid())));
        let fsgid = decimal_string(u64::from(u32::from(credentials.fsgid())));
        let threads = decimal_string(process.tasks().lock().as_slice().len() as u64);

        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(
            printer,
            "Name:\t{}",
            posix_thread.thread_name().lock().name().to_string_lossy()
        )?;
        writeln!(printer, "State:\t{}", state)?;
        writeln!(printer, "Tgid:\t{}", pid)?;
        writeln!(printer, "Pid:\t{}", pid)?;
        writeln!(printer, "PPid:\t{}", ppid)?;
        writeln!(printer, "TracerPid:\t0")?;
        writeln!(printer, "Uid:\t{}\t{}\t{}\t{}", ruid, euid, suid, fsuid,)?;
        writeln!(printer, "Gid:\t{}\t{}\t{}\t{}", rgid, egid, sgid, fsgid,)?;
        writeln!(printer, "Threads:\t{}", threads)?;
        Ok(printer.bytes_written())
    }
}

type StaticEntryWithOps<T> = StaticDirEntry<fn(&T, Weak<dyn Inode>) -> Arc<dyn Inode>>;
