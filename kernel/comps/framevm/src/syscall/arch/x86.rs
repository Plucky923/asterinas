// SPDX-License-Identifier: MPL-2.0

//! System call dispatch in the x86 architecture.

use ostd::{arch::cpu::context::UserContext, mm::VmSpace};

use super::{
    Errno, Error, IntoSyscallReturn, Result, SyscallReturn, log_unknown_syscall,
    set_current_exit_code, sys_accept, sys_accept4, sys_access, sys_arch_prctl, sys_bind, sys_brk,
    sys_capget, sys_capset, sys_chdir, sys_chmod, sys_clock_gettime, sys_clock_nanosleep,
    sys_clone, sys_close, sys_close_range, sys_connect, sys_dup, sys_dup2, sys_dup3, sys_execve,
    sys_faccessat, sys_faccessat2, sys_fchdir, sys_fchmod, sys_fchmodat, sys_fchmodat2, sys_fcntl,
    sys_fdatasync, sys_fork, sys_fstat, sys_fstatfs, sys_fsync, sys_ftruncate, sys_futex,
    sys_getcpu, sys_getcwd, sys_getdents64, sys_getegid, sys_geteuid, sys_getgid, sys_getgroups,
    sys_getpeername, sys_getpgid, sys_getpgrp, sys_getpid, sys_getppid, sys_getrandom,
    sys_getresgid, sys_getresuid, sys_getrlimit, sys_getsid, sys_getsockname, sys_getsockopt,
    sys_gettid, sys_gettimeofday, sys_getuid, sys_ioctl, sys_link, sys_linkat, sys_listen,
    sys_lseek, sys_lstat, sys_madvise, sys_mkdir, sys_mkdirat, sys_mmap, sys_mprotect, sys_mremap,
    sys_munmap, sys_nanosleep, sys_newfstatat, sys_open, sys_openat, sys_pipe, sys_pipe2, sys_poll,
    sys_ppoll, sys_prctl, sys_pread64, sys_prlimit64, sys_pselect6, sys_pwrite64, sys_read,
    sys_readlink, sys_readlinkat, sys_recvfrom, sys_recvmsg, sys_rename, sys_renameat,
    sys_renameat2, sys_rmdir, sys_rseq, sys_rt_sigaction, sys_rt_sigprocmask, sys_sched_yield,
    sys_select, sys_sendfile, sys_sendmsg, sys_sendto, sys_set_robust_list, sys_set_tid_address,
    sys_setgid, sys_setgroups, sys_setpgid, sys_setregid, sys_setresgid, sys_setresuid,
    sys_setreuid, sys_setrlimit, sys_setsid, sys_setsockopt, sys_setuid, sys_shutdown, sys_socket,
    sys_socketpair, sys_stat, sys_statfs, sys_statx, sys_symlink, sys_symlinkat, sys_sync,
    sys_syncfs, sys_truncate, sys_umask, sys_uname, sys_unlink, sys_unlinkat, sys_vfork, sys_wait4,
    sys_write, sys_writev,
};
use crate::context::Context;

type SyscallArgs = [usize; 6];

macro_rules! impl_syscall_nums_and_dispatch_fn {
    ( $( $name: ident = $num: literal => $handler: expr );* $(;)? ) => {
        $(
            pub const $name: u64 = $num;
        )*

        pub(super) fn syscall_dispatch(
            syscall_number: u64,
            args: [u64; 6],
            user_context: &mut UserContext,
            vm_space: &VmSpace,
        ) -> Result<SyscallReturn> {
            let args = args.map(|arg| arg as usize);
            match syscall_number {
                $(
                    $num => {
                        let _ = $name;
                        $handler(args, user_context, vm_space)
                            .map(IntoSyscallReturn::into_syscall_return)
                    }
                )*
                SYS_EXIT | SYS_EXIT_GROUP => {
                    set_current_exit_code(args[0] as i32);
                    Ok(SyscallReturn::Exit)
                }
                _ => {
                    log_unknown_syscall(syscall_number);
                    Err(Error::new(Errno::ENOSYS))
                }
            }
        }
    };
}

pub const SYS_EXIT: u64 = 60;
pub const SYS_EXIT_GROUP: u64 = 231;

impl_syscall_nums_and_dispatch_fn! {
    SYS_READ = 0               => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_read(args[0] as i32, args[1], args[2], vm_space);
    SYS_WRITE = 1              => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_write(args[0] as i32, args[1], args[2], vm_space);
    SYS_OPEN = 2               => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_open(args[0], args[1], args[2], vm_space);
    SYS_CLOSE = 3              => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_close(args[0] as i32);
    SYS_STAT = 4               => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_stat(args[0], args[1], vm_space);
    SYS_FSTAT = 5              => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_fstat(args[0] as i32, args[1], vm_space);
    SYS_LSTAT = 6              => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_lstat(args[0], args[1], vm_space);
    SYS_POLL = 7               => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_poll(args[0], args[1], args[2] as isize, vm_space);
    SYS_LSEEK = 8              => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_lseek(args[0] as i32, args[1] as isize, args[2] as i32);
    SYS_MMAP = 9               => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_mmap(args[0], args[1], args[2], args[3], args[4] as isize, args[5], vm_space);
    SYS_MPROTECT = 10          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_mprotect(args[0], args[1], args[2], vm_space);
    SYS_MUNMAP = 11            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_munmap(args[0], args[1], vm_space);
    SYS_BRK = 12               => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_brk(args[0]);
    SYS_RT_SIGACTION = 13      => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_rt_sigaction(args[0], args[1], args[2], args[3], vm_space);
    SYS_RT_SIGPROCMASK = 14    => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_rt_sigprocmask(args[0] as u32, args[1], args[2], args[3], vm_space);
    SYS_IOCTL = 16             => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_ioctl(args[0] as i32, args[1], args[2], vm_space);
    SYS_PREAD64 = 17           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_pread64(args[0] as i32, args[1], args[2], args[3] as i64, vm_space);
    SYS_PWRITE64 = 18          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_pwrite64(args[0] as i32, args[1], args[2], args[3] as i64, vm_space);
    SYS_WRITEV = 20            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_writev(args[0] as i32, args[1], args[2], vm_space);
    SYS_ACCESS = 21            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_access(args[0], args[1] as u16, vm_space);
    SYS_PIPE = 22              => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_pipe(args[0], vm_space);
    SYS_SELECT = 23            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_select(args[0], args[1], args[2], args[3], args[4], vm_space);
    SYS_SCHED_YIELD = 24       => |_args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_sched_yield();
    SYS_MREMAP = 25            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_mremap(args[0], args[1], args[2], args[3] as i32, args[4], vm_space);
    SYS_MADVISE = 28           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_madvise(args[0], args[1], args[2] as i32, vm_space);
    SYS_NANOSLEEP = 35         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_nanosleep(args[0], args[1], vm_space);
    SYS_DUP = 32               => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_dup(args[0] as i32);
    SYS_DUP2 = 33              => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_dup2(args[0] as i32, args[1] as i32);
    SYS_GETPID = 39            => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getpid(&Context::from_current(vm_space)?);
    SYS_SENDFILE = 40          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_sendfile(args[0] as i32, args[1] as i32, args[2], args[3] as isize, vm_space);
    SYS_SOCKET = 41            => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_socket(args[0] as i32, args[1] as i32, args[2] as i32);
    SYS_CONNECT = 42           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_connect(args[0] as i32, args[1], args[2] as u32, vm_space);
    SYS_ACCEPT = 43            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_accept(args[0] as i32, args[1], args[2], vm_space);
    SYS_SENDTO = 44            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_sendto(args[0] as i32, args[1], args[2], args[3] as i32, args[4], args[5], vm_space);
    SYS_RECVFROM = 45          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_recvfrom(args[0] as i32, args[1], args[2], args[3] as i32, args[4], args[5], vm_space);
    SYS_SENDMSG = 46           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_sendmsg(args[0] as i32, args[1], args[2] as i32, vm_space);
    SYS_RECVMSG = 47           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_recvmsg(args[0] as i32, args[1], args[2] as i32, vm_space);
    SYS_SHUTDOWN = 48          => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_shutdown(args[0] as i32, args[1] as i32);
    SYS_BIND = 49              => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_bind(args[0] as i32, args[1], args[2] as u32, vm_space);
    SYS_LISTEN = 50            => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_listen(args[0] as i32, args[1] as i32);
    SYS_GETSOCKNAME = 51       => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getsockname(args[0] as i32, args[1], args[2], vm_space);
    SYS_GETPEERNAME = 52       => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getpeername(args[0] as i32, args[1], args[2], vm_space);
    SYS_SOCKETPAIR = 53        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_socketpair(args[0] as i32, args[1] as i32, args[2] as i32, args[3], vm_space);
    SYS_SETSOCKOPT = 54        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setsockopt(args[0] as i32, args[1] as i32, args[2] as i32, args[3], args[4], vm_space);
    SYS_GETSOCKOPT = 55        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getsockopt(args[0] as i32, args[1] as i32, args[2] as i32, args[3], args[4], vm_space);
    SYS_CLONE = 56             => |args: SyscallArgs, ctx: &mut UserContext, _vm_space: &VmSpace| sys_clone(ctx, args[0] as u64, args[1], args[2], args[3], args[4]);
    SYS_FORK = 57              => |_args: SyscallArgs, ctx: &mut UserContext, _vm_space: &VmSpace| sys_fork(ctx);
    SYS_VFORK = 58             => |_args: SyscallArgs, ctx: &mut UserContext, _vm_space: &VmSpace| sys_vfork(ctx);
    SYS_EXECVE = 59            => |args: SyscallArgs, ctx: &mut UserContext, vm_space: &VmSpace| sys_execve(ctx, args[0], args[1], args[2], vm_space);
    SYS_WAIT4 = 61             => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_wait4(args[0] as i32, args[1], args[2] as i32, args[3], vm_space);
    SYS_UNAME = 63             => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_uname(args[0], vm_space);
    SYS_FCNTL = 72             => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_fcntl(args[0] as i32, args[1] as i32, args[2] as u64);
    SYS_FSYNC = 74             => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_fsync(args[0] as i32);
    SYS_FDATASYNC = 75         => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_fdatasync(args[0] as i32);
    SYS_TRUNCATE = 76          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_truncate(args[0], args[1] as isize, vm_space);
    SYS_FTRUNCATE = 77         => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_ftruncate(args[0] as i32, args[1] as isize);
    SYS_GETCWD = 79            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getcwd(args[0], args[1], vm_space);
    SYS_CHDIR = 80             => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_chdir(args[0], vm_space);
    SYS_FCHDIR = 81            => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_fchdir(args[0] as i32);
    SYS_RENAME = 82            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_rename(args[0], args[1], vm_space);
    SYS_MKDIR = 83             => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_mkdir(args[0], args[1], vm_space);
    SYS_RMDIR = 84             => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_rmdir(args[0], vm_space);
    SYS_LINK = 86              => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_link(args[0], args[1], vm_space);
    SYS_UNLINK = 87            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_unlink(args[0], vm_space);
    SYS_SYMLINK = 88           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_symlink(args[0], args[1], vm_space);
    SYS_READLINK = 89          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_readlink(args[0], args[1], args[2], vm_space);
    SYS_CHMOD = 90             => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_chmod(args[0], args[1], vm_space);
    SYS_FCHMOD = 91            => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_fchmod(args[0] as i32, args[1]);
    SYS_UMASK = 95             => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_umask(args[0] as u16);
    SYS_GETTIMEOFDAY = 96      => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_gettimeofday(args[0], vm_space);
    SYS_GETRLIMIT = 97         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getrlimit(args[0], args[1], vm_space);
    SYS_GETUID = 102           => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getuid(&Context::from_current(vm_space)?);
    SYS_GETGID = 104           => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getgid(&Context::from_current(vm_space)?);
    SYS_SETUID = 105           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setuid(args[0] as i32, &Context::from_current(vm_space)?);
    SYS_SETGID = 106           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setgid(args[0] as i32, &Context::from_current(vm_space)?);
    SYS_GETEUID = 107          => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_geteuid(&Context::from_current(vm_space)?);
    SYS_GETEGID = 108          => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getegid(&Context::from_current(vm_space)?);
    SYS_SETPGID = 109          => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_setpgid(args[0] as i32, args[1] as i32);
    SYS_GETPPID = 110          => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getppid(&Context::from_current(vm_space)?);
    SYS_GETPGRP = 111          => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getpgrp(&Context::from_current(vm_space)?);
    SYS_SETSID = 112           => |_args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_setsid();
    SYS_SETREUID = 113         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setreuid(args[0] as i32, args[1] as i32, &Context::from_current(vm_space)?);
    SYS_SETREGID = 114         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setregid(args[0] as i32, args[1] as i32, &Context::from_current(vm_space)?);
    SYS_GETGROUPS = 115        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getgroups(args[0] as i32, args[1], &Context::from_current(vm_space)?, vm_space);
    SYS_SETGROUPS = 116        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setgroups(args[0], args[1], &Context::from_current(vm_space)?, vm_space);
    SYS_SETRESUID = 117        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setresuid(args[0] as i32, args[1] as i32, args[2] as i32, &Context::from_current(vm_space)?);
    SYS_GETRESUID = 118        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getresuid(args[0], args[1], args[2], &Context::from_current(vm_space)?, vm_space);
    SYS_SETRESGID = 119        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setresgid(args[0] as i32, args[1] as i32, args[2] as i32, &Context::from_current(vm_space)?);
    SYS_GETRESGID = 120        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getresgid(args[0], args[1], args[2], &Context::from_current(vm_space)?, vm_space);
    SYS_GETPGID = 121          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getpgid(args[0] as u32, &Context::from_current(vm_space)?);
    SYS_GETSID = 124           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getsid(args[0] as u32, &Context::from_current(vm_space)?);
    SYS_CAPGET = 125           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_capget(args[0], args[1], &Context::from_current(vm_space)?, vm_space);
    SYS_CAPSET = 126           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_capset(args[0], args[1], &Context::from_current(vm_space)?, vm_space);
    SYS_STATFS = 137           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_statfs(args[0], args[1], vm_space);
    SYS_FSTATFS = 138          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_fstatfs(args[0] as i32, args[1], vm_space);
    SYS_PRCTL = 157            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_prctl(args[0] as i32, args[1], args[2], args[3], args[4], &Context::from_current(vm_space)?, vm_space);
    SYS_ARCH_PRCTL = 158       => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_arch_prctl(args[0], args[1], vm_space);
    SYS_SETRLIMIT = 160        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_setrlimit(args[0], args[1], vm_space);
    SYS_SYNC = 162             => |_args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_sync();
    SYS_GETTID = 186           => |_args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_gettid(&Context::from_current(vm_space)?);
    SYS_FUTEX = 202            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_futex(args[0], args[1] as u32, args[2] as u32, args[3], args[4], args[5] as u32, vm_space);
    SYS_GETDENTS64 = 217       => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getdents64(args[0] as i32, args[1], args[2], vm_space);
    SYS_SET_TID_ADDRESS = 218  => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_set_tid_address(args[0]);
    SYS_CLOCK_GETTIME = 228    => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_clock_gettime(args[0], args[1], vm_space);
    SYS_CLOCK_NANOSLEEP = 230  => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_clock_nanosleep(args[0], args[1] as i32, args[2], args[3], vm_space);
    SYS_OPENAT = 257           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_openat(args[0] as i32, args[1], args[2], args[3], vm_space);
    SYS_MKDIRAT = 258          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_mkdirat(args[0] as i32, args[1], args[2], vm_space);
    SYS_FSTATAT = 262          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_newfstatat(args[0] as i32, args[1], args[2], args[3] as u32, vm_space);
    SYS_UNLINKAT = 263         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_unlinkat(args[0] as i32, args[1], args[2], vm_space);
    SYS_RENAMEAT = 264         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_renameat(args[0] as i32, args[1], args[2] as i32, args[3], vm_space);
    SYS_LINKAT = 265           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_linkat(args[0] as i32, args[1], args[2] as i32, args[3], args[4], vm_space);
    SYS_SYMLINKAT = 266        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_symlinkat(args[0], args[1] as i32, args[2], vm_space);
    SYS_READLINKAT = 267       => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_readlinkat(args[0] as i32, args[1], args[2], args[3], vm_space);
    SYS_FCHMODAT = 268         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_fchmodat(args[0] as i32, args[1], args[2], vm_space);
    SYS_FACCESSAT = 269        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_faccessat(args[0] as i32, args[1], args[2] as u16, vm_space);
    SYS_PSELECT6 = 270         => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_pselect6(args[0], args[1], args[2], args[3], args[4], args[5], vm_space);
    SYS_PPOLL = 271            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_ppoll(args[0], args[1], args[2], args[3], args[4], vm_space);
    SYS_SET_ROBUST_LIST = 273  => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_set_robust_list(args[0], args[1], vm_space);
    SYS_ACCEPT4 = 288          => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_accept4(args[0] as i32, args[1], args[2], args[3] as i32, vm_space);
    SYS_DUP3 = 292             => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_dup3(args[0] as i32, args[1] as i32, args[2]);
    SYS_PIPE2 = 293            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_pipe2(args[0], args[1], vm_space);
    SYS_PRLIMIT64 = 302        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_prlimit64(args[0], args[1], args[2], args[3], vm_space);
    SYS_SYNCFS = 306           => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_syncfs(args[0] as i32);
    SYS_GETCPU = 309           => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getcpu(args[0], args[1], args[2], vm_space);
    SYS_RENAMEAT2 = 316        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_renameat2(args[0] as i32, args[1], args[2] as i32, args[3], args[4], vm_space);
    SYS_GETRANDOM = 318        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_getrandom(args[0], args[1], args[2] as u32, &Context::from_current(vm_space)?);
    SYS_STATX = 332            => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_statx(args[0] as i32, args[1], args[2] as u32, args[3] as u32, args[4], vm_space);
    SYS_RSEQ = 334             => |_args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_rseq();
    SYS_CLOSE_RANGE = 436      => |args: SyscallArgs, _ctx: &mut UserContext, _vm_space: &VmSpace| sys_close_range(args[0] as u32, args[1] as u32, args[2] as u32);
    SYS_FACCESSAT2 = 439       => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_faccessat2(args[0] as i32, args[1], args[2] as u16, args[3] as u32, vm_space);
    SYS_FCHMODAT2 = 452        => |args: SyscallArgs, _ctx: &mut UserContext, vm_space: &VmSpace| sys_fchmodat2(args[0] as i32, args[1], args[2], args[3], vm_space);
}
