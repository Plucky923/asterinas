// SPDX-License-Identifier: MPL-2.0

//! System call handlers.

#![cfg_attr(
    any(
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "aarch64"
    ),
    expect(dead_code)
)]

pub(crate) use clock_gettime::ClockId;
use ostd::arch::cpu::context::UserContext;
pub(crate) use timer_create::create_timer_for_clock;

use crate::{cpu::LinuxAbi, prelude::*};

#[cfg_attr(target_arch = "x86_64", path = "arch/x86.rs")]
#[cfg_attr(target_arch = "riscv64", path = "arch/riscv.rs")]
#[cfg_attr(target_arch = "loongarch64", path = "arch/loongarch.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/arm.rs")]
mod arch;

mod accept;
mod access;
mod alarm;
#[cfg(target_arch = "x86_64")]
mod arch_prctl;
mod bind;
mod brk;
mod capget;
mod capset;
mod chdir;
mod chmod;
mod chown;
mod chroot;
mod clock_gettime;
mod clone;
mod close;
mod connect;
mod constants;
mod dup;
mod epoll;
mod eventfd;
mod execve;
mod exit;
mod exit_group;
mod fadvise64;
mod fallocate;
mod fcntl;
mod flock;
mod fork;
mod fsconfig;
mod fsmount;
mod fsopen;
mod fsync;
mod futex;
mod get_ioprio;
mod get_priority;
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
mod getrusage;
mod getsid;
mod getsockname;
mod getsockopt;
mod gettid;
mod gettimeofday;
mod getuid;
mod getxattr;
mod inotify;
mod ioctl;
mod kill;
mod link;
mod listen;
mod listmount;
mod listxattr;
mod lseek;
mod madvise;
mod memfd_create;
mod mkdir;
mod mknod;
mod mmap;
mod mount;
mod move_mount;
mod mprotect;
mod mremap;
mod msync;
mod munmap;
mod nanosleep;
mod open;
mod pause;
mod personality;
mod pidfd_getfd;
mod pidfd_open;
mod pidfd_send_signal;
mod pipe;
mod pivot_root;
mod poll;
mod ppoll;
mod prctl;
mod pread64;
mod preadv;
mod prlimit64;
mod pselect6;
mod ptrace;
mod pwrite64;
mod pwritev;
mod read;
mod readlink;
mod reboot;
mod recvfrom;
mod recvmsg;
mod removexattr;
mod rename;
mod rmdir;
mod rt_sigaction;
mod rt_sigpending;
mod rt_sigprocmask;
mod rt_sigreturn;
mod rt_sigsuspend;
mod rt_sigtimedwait;
mod sched_affinity;
mod sched_get_priority_max;
mod sched_get_priority_min;
mod sched_getattr;
mod sched_getparam;
mod sched_getscheduler;
mod sched_setattr;
mod sched_setparam;
mod sched_setscheduler;
mod sched_yield;
mod select;
mod semctl;
mod semget;
mod semop;
mod sendfile;
mod sendmmsg;
mod sendmsg;
mod sendto;
mod set_ioprio;
mod set_priority;
mod set_robust_list;
mod set_tid_address;
mod setdomainname;
mod setfsgid;
mod setfsuid;
mod setgid;
mod setgroups;
mod sethostname;
mod setitimer;
mod setns;
mod setpgid;
mod setregid;
mod setresgid;
mod setresuid;
mod setreuid;
mod setsid;
mod setsockopt;
mod setuid;
mod setxattr;
mod shutdown;
mod sigaltstack;
mod signalfd;
mod socket;
mod socketpair;
mod stat;
mod statfs;
mod statx;
mod symlink;
mod sync;
mod sysinfo;
mod tgkill;
mod time;
mod timer_create;
mod timer_settime;
mod timerfd_create;
mod timerfd_gettime;
mod timerfd_settime;
mod truncate;
mod umask;
mod umount;
mod uname;
mod unlink;
mod unshare;
mod utimens;
mod wait4;
mod waitid;
mod write;

/// Reads the arguments for the selected syscall and invokes its handler.
macro_rules! syscall_handler {
    (0, $handler:ident, $ctx:ident, $user_ctx:ident $(, $regs:expr)?) => {
        $handler($ctx $(, $regs)?)
    };
    (1, $($call:tt)*) => {
        $crate::syscall::syscall_handler!(@args 1 [0] $($call)*)
    };
    (2, $($call:tt)*) => {
        $crate::syscall::syscall_handler!(@args 2 [0, 1] $($call)*)
    };
    (3, $($call:tt)*) => {
        $crate::syscall::syscall_handler!(@args 3 [0, 1, 2] $($call)*)
    };
    (4, $($call:tt)*) => {
        $crate::syscall::syscall_handler!(@args 4 [0, 1, 2, 3] $($call)*)
    };
    (5, $($call:tt)*) => {
        $crate::syscall::syscall_handler!(@args 5 [0, 1, 2, 3, 4] $($call)*)
    };
    (6, $($call:tt)*) => {
        $crate::syscall::syscall_handler!(@args 6 [0, 1, 2, 3, 4, 5] $($call)*)
    };
    (@args $count:literal [$($index:literal),+] $handler:ident, $ctx:ident, $user_ctx:ident $(, $regs:expr)?) => {{
        let args = $crate::cpu::LinuxAbi::syscall_args::<$count>(&*$user_ctx);
        $handler($(args[$index] as _,)+ $ctx $(, $regs)?)
    }};
}

macro_rules! dispatch_fn_inner {
    ($ctx:ident, $user_ctx:ident, $handler:ident(args[..$count:tt])) => {
        $crate::syscall::syscall_handler!($count, $handler, $ctx, $user_ctx)
    };
    ($ctx:ident, $user_ctx:ident, $handler:ident(args[..$count:tt], &user_ctx)) => {
        $crate::syscall::syscall_handler!($count, $handler, $ctx, $user_ctx, &*$user_ctx)
    };
    ($ctx:ident, $user_ctx:ident, $handler:ident(args[..$count:tt], &mut user_ctx)) => {
        $crate::syscall::syscall_handler!($count, $handler, $ctx, $user_ctx, $user_ctx)
    };
}

macro_rules! impl_syscall_nums_and_dispatch_fn {
    ( $( $name: ident = $num: literal => $handler: ident $args: tt );* $(;)? ) => {
        // First, define the syscall numbers
        $(
            pub(crate) const $name: u64 = $num;
        )*

        // Then, define the dispatcher function
        pub(super) fn syscall_dispatch(
            syscall_number: u64,
            ctx: &$crate::context::Context,
            user_ctx: &mut ostd::arch::cpu::context::UserContext,
        ) {
            match syscall_number {
                $(
                    $num => {
                        $crate::syscall::log_syscall_entry!($name);
                        let result = $crate::syscall::dispatch_fn_inner!(ctx, user_ctx, $handler $args);
                        $crate::syscall::write_syscall_result(user_ctx, result);
                    }
                )*
                _ => {
                    ostd::warn!("Unimplemented syscall number: {}", syscall_number);
                    let error = $crate::error::Error::with_message(
                        $crate::error::Errno::ENOSYS,
                        "Syscall was unimplemented",
                    );
                    $crate::syscall::write_syscall_error(user_ctx, error);
                }
            }
        }
    }
}

// Export macros to sub-modules
use dispatch_fn_inner;
use impl_syscall_nums_and_dispatch_fn;
use syscall_handler;

/// Syscall return
#[derive(Clone, Copy, Debug)]
enum SyscallReturn {
    /// Sets the syscall return register to this value.
    Return(isize),
    /// Keeps the register value supplied by the handler.
    NoReturn,
}

pub(crate) fn handle_syscall(syscall_number: usize, ctx: &Context, user_ctx: &mut UserContext) {
    arch::syscall_dispatch(syscall_number as u64, ctx, user_ctx);
}

#[inline(always)]
fn write_syscall_result(user_ctx: &mut UserContext, result: Result<SyscallReturn>) {
    match result {
        Ok(SyscallReturn::Return(value)) => user_ctx.set_syscall_ret(value as usize),
        Ok(SyscallReturn::NoReturn) => {}
        Err(error) => write_syscall_error(user_ctx, error),
    }
}

#[cold]
#[inline(never)]
fn write_syscall_error(user_ctx: &mut UserContext, error: Error) {
    debug!("syscall return error: {:?}", error);
    let errno = error.error() as i32;
    user_ctx.set_syscall_ret((-errno) as usize);
}

macro_rules! log_syscall_entry {
    ($syscall_name: tt) => {
        if ostd::log_enabled!(ostd::log::Level::Debug) {
            let syscall_name_str = stringify!($syscall_name);
            let pid = $crate::current!().pid();
            let tid = {
                use $crate::process::posix_thread::AsPosixThread;
                $crate::context::current_thread!()
                    .as_posix_thread()
                    .unwrap()
                    .tid()
            };
            ostd::debug!(
                "[pid={}][tid={}][id={}][{}]",
                pid,
                tid,
                $syscall_name,
                syscall_name_str
            );
        }
    };
}

use log_syscall_entry;
