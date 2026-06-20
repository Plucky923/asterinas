// SPDX-License-Identifier: MPL-2.0

//! Linux syscall surface for the kernel image.
//!
//! The syscall ABI handling follows `kernel/src/syscall` structure. This crate
//! is a trimmed kernel image, so syscall handlers operate on kernel-owned
//! process, file-table, rootfs, and address-space objects.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::str;

use ostd::{
    arch::cpu::context::UserContext,
    mm::{
        VmReader, VmSpace, VmWriter,
        io::{FallibleVmRead, FallibleVmWrite},
    },
    sync::SpinLock,
    task::Task,
};

use crate::{
    cpu::LinuxAbi,
    error::{Errno, Error, Result},
    fd_table::{AccessMode, FdFlags, FileLike, FileTable, RawFileDesc, StatusFlags},
    fs_context::{AT_EMPTY_PATH, AT_FDCWD, EmptyPathStr, FileCreationMask, ThreadFsInfo},
    resource::{RawRLimit64, ResourceLimits, ResourceType, SYSCTL_NR_OPEN},
    rootfs::{FileKind, FileMetadata, RootDirEntry, RootFs},
    signal::sanitize_signal_mask,
    task::{
        CLONE_VFORK, CLONE_VM, TryWaitResult, UserTaskData, clone_user_task,
        notify_current_exec_boundary, peek_wait_for_exit, set_current_exit_code, try_wait_for_exit,
        wait_for_exit, wait_for_exit_no_reap,
    },
    time,
    vm::{
        ExistingMapping, create_vm_space, discard_range, is_range_fully_mapped, map_anonymous,
        page_flags_at, protect_range, unmap_range,
    },
};

mod accept;
mod access;
#[cfg_attr(target_arch = "x86_64", path = "syscall/arch/x86.rs")]
mod arch;
mod arch_prctl;
mod bind;
mod brk;
mod capget;
mod capset;
mod chdir;
mod chmod;
mod clock_gettime;
mod clone;
mod close;
mod connect;
mod dup;
mod execve;
mod fcntl;
mod fsync;
mod futex_sys;
mod getcpu;
mod getcwd;
mod getdents64;
mod getegid;
mod geteuid;
mod getgid;
mod getgroups;
mod getpeername;
mod getpgid;
mod getpgrp;
mod getpid;
mod getppid;
mod getrandom;
mod getresgid;
mod getresuid;
mod getrlimit;
mod getsid;
mod getsockname;
mod getsockopt;
mod gettid;
mod gettimeofday;
mod getuid;
mod ioctl;
mod link;
mod listen;
mod lseek;
mod madvise;
mod mkdir;
mod mmap;
mod mprotect;
mod mremap;
mod munmap;
mod nanosleep;
mod open;
mod pipe;
mod poll;
mod prctl;
mod preadwrite;
mod prlimit64;
mod read;
mod readlink;
mod recvfrom;
mod recvmsg;
mod rename;
mod rmdir;
mod rseq;
mod sched_yield;
mod select;
mod sendfile;
mod sendmsg;
mod sendto;
mod set_robust_list;
mod set_tid_address;
mod setgid;
mod setgroups;
mod setpgid;
mod setregid;
mod setresgid;
mod setresuid;
mod setreuid;
mod setrlimit;
mod setsid;
mod setsockopt;
mod setuid;
mod shutdown;
mod signal_sys;
mod socket;
mod socketpair;
mod stat;
mod statfs;
mod statx;
mod symlink;
mod sync;
mod truncate;
mod umask;
mod uname;
mod unlink;
mod wait4;
mod write;

use self::{
    accept::{sys_accept, sys_accept4},
    access::{sys_access, sys_faccessat, sys_faccessat2},
    arch_prctl::sys_arch_prctl,
    bind::sys_bind,
    brk::sys_brk,
    capget::sys_capget,
    capset::sys_capset,
    chdir::{sys_chdir, sys_fchdir},
    chmod::{sys_chmod, sys_fchmod, sys_fchmodat, sys_fchmodat2},
    clock_gettime::sys_clock_gettime,
    clone::{sys_clone, sys_fork, sys_vfork},
    close::{sys_close, sys_close_range},
    connect::sys_connect,
    dup::{sys_dup, sys_dup2, sys_dup3},
    execve::sys_execve,
    fcntl::sys_fcntl,
    fsync::{sys_fdatasync, sys_fsync},
    futex_sys::sys_futex,
    getcpu::sys_getcpu,
    getcwd::sys_getcwd,
    getdents64::sys_getdents64,
    getegid::sys_getegid,
    geteuid::sys_geteuid,
    getgid::sys_getgid,
    getgroups::sys_getgroups,
    getpeername::sys_getpeername,
    getpgid::sys_getpgid,
    getpgrp::sys_getpgrp,
    getpid::sys_getpid,
    getppid::sys_getppid,
    getrandom::sys_getrandom,
    getresgid::sys_getresgid,
    getresuid::sys_getresuid,
    getrlimit::sys_getrlimit,
    getsid::sys_getsid,
    getsockname::sys_getsockname,
    getsockopt::sys_getsockopt,
    gettid::sys_gettid,
    gettimeofday::sys_gettimeofday,
    getuid::sys_getuid,
    ioctl::sys_ioctl,
    link::{sys_link, sys_linkat},
    listen::sys_listen,
    lseek::sys_lseek,
    madvise::sys_madvise,
    mkdir::{sys_mkdir, sys_mkdirat},
    mmap::sys_mmap,
    mprotect::sys_mprotect,
    mremap::sys_mremap,
    munmap::sys_munmap,
    nanosleep::{sys_clock_nanosleep, sys_nanosleep},
    open::{sys_open, sys_openat},
    pipe::{sys_pipe, sys_pipe2},
    poll::{sys_poll, sys_ppoll},
    prctl::sys_prctl,
    preadwrite::{sys_pread64, sys_pwrite64},
    prlimit64::sys_prlimit64,
    read::sys_read,
    readlink::{sys_readlink, sys_readlinkat},
    recvfrom::sys_recvfrom,
    recvmsg::sys_recvmsg,
    rename::{sys_rename, sys_renameat, sys_renameat2},
    rmdir::sys_rmdir,
    rseq::sys_rseq,
    sched_yield::sys_sched_yield,
    select::{sys_pselect6, sys_select},
    sendfile::sys_sendfile,
    sendmsg::sys_sendmsg,
    sendto::sys_sendto,
    set_robust_list::sys_set_robust_list,
    set_tid_address::sys_set_tid_address,
    setgid::sys_setgid,
    setgroups::sys_setgroups,
    setpgid::sys_setpgid,
    setregid::sys_setregid,
    setresgid::sys_setresgid,
    setresuid::sys_setresuid,
    setreuid::sys_setreuid,
    setrlimit::sys_setrlimit,
    setsid::sys_setsid,
    setsockopt::sys_setsockopt,
    setuid::sys_setuid,
    shutdown::sys_shutdown,
    signal_sys::{sys_rt_sigaction, sys_rt_sigprocmask},
    socket::sys_socket,
    socketpair::sys_socketpair,
    stat::{sys_fstat, sys_lstat, sys_newfstatat, sys_stat},
    statfs::{sys_fstatfs, sys_statfs},
    statx::sys_statx,
    symlink::{sys_symlink, sys_symlinkat},
    sync::{sys_sync, sys_syncfs},
    truncate::{sys_ftruncate, sys_truncate},
    umask::sys_umask,
    uname::sys_uname,
    unlink::{sys_unlink, sys_unlinkat},
    wait4::sys_wait4,
    write::{sys_write, sys_writev},
};

const O_CLOEXEC: u32 = 0o2000000;
const O_CREAT: u32 = 0o100;
const O_DIRECTORY: u32 = 0o200000;
const O_EXCL: u32 = 0o200;
const O_NOFOLLOW: u32 = 0o400000;
const O_TMPFILE: u32 = 0o20000000;
const O_TRUNC: u32 = 0o1000;
const PAGE_SIZE: usize = 4096;
const AT_NO_AUTOMOUNT: u32 = 1 << 11;
const AT_SYMLINK_NOFOLLOW: u32 = 1 << 8;

pub fn handle_syscall(user_context: &mut UserContext, vm_space: &VmSpace) -> bool {
    let syscall_argument = SyscallArgument::new_from_context(user_context);
    let syscall_return = arch::syscall_dispatch(
        syscall_argument.syscall_number,
        syscall_argument.args,
        user_context,
        vm_space,
    );

    match syscall_return {
        Ok(SyscallReturn::Return(ret)) => {
            user_context.set_syscall_ret(ret as usize);
        }
        Ok(SyscallReturn::NoReturn) => {}
        Ok(SyscallReturn::Exit) => return true,
        Err(e) => {
            let errno = -(e.errno() as i64);
            user_context.set_syscall_ret(errno as usize);
        }
    }

    false
}

struct SyscallArgument {
    syscall_number: u64,
    args: [u64; 6],
}

impl SyscallArgument {
    fn new_from_context(user_context: &UserContext) -> Self {
        Self {
            syscall_number: user_context.syscall_num() as u64,
            args: user_context.syscall_args().map(|argument| argument as u64),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SyscallReturn {
    Return(isize),
    NoReturn,
    Exit,
}

impl From<isize> for SyscallReturn {
    fn from(value: isize) -> Self {
        Self::Return(value)
    }
}

trait IntoSyscallReturn {
    fn into_syscall_return(self) -> SyscallReturn;
}

impl IntoSyscallReturn for isize {
    fn into_syscall_return(self) -> SyscallReturn {
        SyscallReturn::Return(self)
    }
}

impl IntoSyscallReturn for SyscallReturn {
    fn into_syscall_return(self) -> SyscallReturn {
        self
    }
}

fn log_unknown_syscall(_syscall_number: u64) {}

fn current_fd_table() -> Result<Arc<SpinLock<FileTable>>> {
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let task_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;
    Ok(task_data.fd_table())
}

fn unshare_current_fd_table() -> Result<()> {
    with_current_user_task_data(|task_data| {
        task_data.unshare_fd_table();
        Ok(())
    })
}

fn current_resource_limits() -> Result<Arc<ResourceLimits>> {
    with_current_user_task_data(|task_data| Ok(task_data.resource_limits.clone()))
}

fn current_nofile_limit() -> Result<u64> {
    with_current_user_task_data(|task_data| {
        Ok(task_data
            .resource_limits
            .get_rlimit(ResourceType::NoFile)
            .get_cur())
    })
}

fn current_fd_file(fd: i32) -> Result<Option<Arc<dyn FileLike>>> {
    let fd_table = current_fd_table()?;
    Ok(fd_table.lock().get_optional(fd))
}

fn metadata_from_fd(fd: i32) -> Result<FileMetadata> {
    if let Some(file) = current_fd_file(fd)? {
        return Ok(file.metadata().unwrap_or(FileMetadata {
            mode: 0o666,
            size: 0,
            kind: FileKind::Special,
            nlink: 1,
        }));
    }

    Err(Error::new(Errno::EBADF))
}

fn with_current_user_task_data<T>(f: impl FnOnce(&UserTaskData) -> Result<T>) -> Result<T> {
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let task_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;
    f(task_data)
}

fn current_working_directory() -> Result<String> {
    with_current_user_task_data(|task_data| Ok(task_data.fs.lock().cwd().to_string()))
}

fn current_user_tid() -> Result<u32> {
    with_current_user_task_data(|task_data| Ok(task_data.tid))
}

fn reactivate_current_vm_space() -> Result<()> {
    with_current_user_task_data(|task_data| {
        task_data.vm_space().activate();
        Ok(())
    })
}

fn with_current_fs_info<T>(f: impl FnOnce(&mut ThreadFsInfo) -> Result<T>) -> Result<T> {
    with_current_user_task_data(|task_data| {
        let mut fs = task_data.fs.lock();
        f(&mut fs)
    })
}

fn resolve_guest_path(path: &str) -> Result<String> {
    with_current_user_task_data(|task_data| task_data.fs.lock().resolve_path(path))
}

fn resolve_guest_path_at(
    dirfd: i32,
    path: &str,
    empty_path_policy: EmptyPathStr,
) -> Result<String> {
    let dirfd_base = if dirfd != AT_FDCWD && !path.starts_with('/') {
        Some(if path.is_empty() {
            path_from_fd(dirfd)?
        } else {
            directory_path_from_fd(dirfd)?
        })
    } else {
        None
    };

    with_current_user_task_data(|task_data| {
        task_data.fs.lock().resolve_path_at_with_base(
            dirfd,
            path,
            dirfd_base.as_deref(),
            empty_path_policy,
        )
    })
}

fn path_from_fd(fd: i32) -> Result<String> {
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    file.path().ok_or(Error::new(Errno::EOPNOTSUPP))
}

fn directory_path_from_fd(fd: i32) -> Result<String> {
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    file.directory_path().ok_or(Error::new(Errno::ENOTDIR))
}

// ============ File I/O Syscalls ============

fn metadata_for_path(pathname: &str, follow_tail_link: bool) -> Result<FileMetadata> {
    if is_console_path(&pathname) {
        return Ok(console_metadata());
    }
    if follow_tail_link {
        RootFs::get()?.metadata(pathname)
    } else {
        RootFs::get()?.metadata_no_follow(pathname)
    }
}

fn validate_stat_flags(flags: u32) -> Result<u32> {
    const VALID_FLAGS: u32 = AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW;
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(flags)
}

fn is_console_path(path: &str) -> bool {
    matches!(path, "/dev/tty" | "/dev/console" | "/dev/ttyS0")
}

fn is_null_path(path: &str) -> bool {
    path == "/dev/null"
}

fn console_metadata() -> FileMetadata {
    FileMetadata {
        mode: 0o666,
        size: 0,
        kind: FileKind::Special,
        nlink: 1,
    }
}

fn read_guest_time_ns() -> Result<u64> {
    time::monotonic_ns().ok_or(Error::new(Errno::EINVAL))
}

// ============ Helper Functions ============

/// Read from user space into a Vec (ONE copy - this is the syscall boundary copy)
fn read_from_user_to_vec(vm_space: &VmSpace, addr: usize, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut reader = vm_space.reader(addr, len).map_err(Error::from)?;
    reader
        .read_fallible(&mut VmWriter::from(&mut buf as &mut [u8]))
        .map_err(Error::from)?;
    Ok(buf)
}

fn read_fixed_from_user<const LEN: usize>(vm_space: &VmSpace, addr: usize) -> Result<[u8; LEN]> {
    let buf = read_from_user_to_vec(vm_space, addr, LEN)?;
    let mut fixed = [0u8; LEN];
    fixed.copy_from_slice(&buf);
    Ok(fixed)
}

fn read_i32_from_user(vm_space: &VmSpace, addr: usize) -> Result<i32> {
    let buf = read_from_user_to_vec(vm_space, addr, 4)?;
    Ok(i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

fn read_u32_from_user(vm_space: &VmSpace, addr: usize) -> Result<u32> {
    let buf = read_from_user_to_vec(vm_space, addr, 4)?;
    Ok(u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

fn read_i64_from_user(vm_space: &VmSpace, addr: usize) -> Result<i64> {
    let buf = read_from_user_to_vec(vm_space, addr, 8)?;
    Ok(i64::from_ne_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]))
}

fn read_u64_from_user(vm_space: &VmSpace, addr: usize) -> Result<u64> {
    let buf = read_from_user_to_vec(vm_space, addr, 8)?;
    Ok(u64::from_ne_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]))
}

fn read_i16_from_user(vm_space: &VmSpace, addr: usize) -> Result<i16> {
    let buf = read_from_user_to_vec(vm_space, addr, 2)?;
    Ok(i16::from_ne_bytes([buf[0], buf[1]]))
}

fn read_usize_from_user(vm_space: &VmSpace, addr: usize) -> Result<usize> {
    let buf = read_from_user_to_vec(vm_space, addr, size_of::<usize>())?;
    Ok(usize::from_ne_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]))
}

fn read_c_string(vm_space: &VmSpace, addr: usize) -> Result<String> {
    const MAX_PATH_LEN: usize = 4096;
    let mut bytes = Vec::new();
    for offset in 0..MAX_PATH_LEN {
        let byte = read_from_user_to_vec(vm_space, addr + offset, 1)?[0];
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| Error::new(Errno::EINVAL));
        }
        bytes.push(byte);
    }
    Err(Error::new(Errno::EINVAL))
}

fn read_string_array(vm_space: &VmSpace, addr: usize) -> Result<Vec<String>> {
    const MAX_STRING_COUNT: usize = 256;

    if addr == 0 {
        return Ok(Vec::new());
    }

    let mut strings = Vec::new();
    for idx in 0..MAX_STRING_COUNT {
        let ptr = read_usize_from_user(vm_space, addr + idx * size_of::<usize>())?;
        if ptr == 0 {
            return Ok(strings);
        }
        strings.push(read_c_string(vm_space, ptr)?);
    }

    Err(Error::new(Errno::EINVAL))
}

/// Write to user space (ONE copy - this is the syscall boundary copy)
fn write_to_user(vm_space: &VmSpace, addr: usize, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut writer = vm_space.writer(addr, data.len()).map_err(Error::from)?;
    let mut reader = VmReader::from(data);
    writer
        .write_fallible(&mut reader)
        .map_err(|(e, _)| Error::from(e))?;
    Ok(())
}
