// SPDX-License-Identifier: MPL-2.0

//! Syscall handler for FrameVM
//!
//! # Zero-Copy Design
//!
//! The syscall layer is the ONLY place where data is copied:
//! - Send: User buffer → DataPacket (ONE copy)
//! - Recv: DataPacket → User buffer (ONE copy)
//!
//! All internal transfers use RRef<DataPacket> for zero-copy.

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    str,
    sync::atomic::{AtomicU64, Ordering},
};

use aster_framevisor::{
    arch,
    arch::cpu::context::UserContext,
    mm::{
        VmReader, VmSpace, VmWriter,
        io::{FallibleVmRead, FallibleVmWrite},
    },
    task::Task,
};
use aster_framevsock::{DataPacket, flow_control::MAX_PKT_BUF_SIZE, trace};
use exchangeable::RRef;

use crate::{
    error::{Errno, Error, Result},
    fd_table::FdTable,
    return_errno_with_message,
    task::{CLONE_VM, clone_user_task, set_current_exit_code, wait_for_exit},
    vsock::{
        addr::{AF_FRAMEVSOCK, FrameVsockAddr, SockAddrVm},
        socket::FrameVsockSocket,
    },
};

// Syscall numbers (x86_64) - only those needed by vsock_echo_server
pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_CLOSE: usize = 3;
pub const SYS_GETPID: usize = 39;
pub const SYS_SOCKET: usize = 41;
pub const SYS_ACCEPT: usize = 43;
pub const SYS_CONNECT: usize = 42;
pub const SYS_SENDTO: usize = 44;
pub const SYS_RECVFROM: usize = 45;
pub const SYS_BIND: usize = 49;
pub const SYS_LISTEN: usize = 50;
pub const SYS_CLONE: usize = 56;
pub const SYS_FORK: usize = 57;
pub const SYS_EXIT: usize = 60;
pub const SYS_WAIT4: usize = 61;
pub const SYS_GETTID: usize = 186;
pub const SYS_CLOCK_GETTIME: usize = 228;

// Socket types
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_NONBLOCK: i32 = 0x800;

pub fn handle_syscall(user_context: &mut UserContext, vm_space: &VmSpace) -> bool {
    let syscall_num = user_context.rax();
    let result = match syscall_num {
        SYS_READ => sys_read(user_context, vm_space),
        SYS_WRITE => sys_write(user_context, vm_space),
        SYS_CLOSE => sys_close(user_context),
        SYS_SOCKET => sys_socket(user_context),
        SYS_CONNECT => sys_connect(user_context, vm_space),
        SYS_ACCEPT => sys_accept(user_context, vm_space),
        SYS_SENDTO => sys_sendto(user_context, vm_space),
        SYS_RECVFROM => sys_recvfrom(user_context, vm_space),
        SYS_BIND => sys_bind(user_context, vm_space),
        SYS_LISTEN => sys_listen(user_context),
        SYS_CLONE => sys_clone(user_context),
        SYS_FORK => sys_fork(user_context),
        SYS_GETPID => sys_getpid(),
        SYS_GETTID => sys_gettid(),
        SYS_CLOCK_GETTIME => sys_clock_gettime(user_context, vm_space),
        SYS_EXIT => {
            let code = user_context.rdi() as i32;
            set_current_exit_code(code);
            return true;
        }
        SYS_WAIT4 => sys_wait4(user_context, vm_space),
        _ => {
            framevm_logln!("[FrameVM] Unknown syscall: {}", syscall_num);
            Err(Error::new(Errno::ENOSYS))
        }
    };

    match result {
        Ok(ret) => user_context.set_rax(ret as usize),
        Err(e) => {
            let errno = -(e.errno() as i64);
            user_context.set_rax(errno as usize);
        }
    }

    false
}

fn current_fd_table() -> Result<Arc<spin::Mutex<FdTable>>> {
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let task_data = current
        .data()
        .downcast_ref::<crate::task::UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;
    Ok(task_data.fd_table.clone())
}

// ============ File I/O Syscalls ============

/// sys_read - Read from file descriptor (socket)
///
/// For connected sockets, this is equivalent to recvfrom with no address.
fn sys_read(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let buf_addr = ctx.rsi();
    let count = ctx.rdx();

    // stdin not supported
    if fd == 0 {
        return_errno_with_message!(Errno::ENOTSUP, "stdin not supported");
    }

    // For sockets, delegate to recv logic
    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();
    recv_to_user_via_safe_path(&socket, vm_space, buf_addr, count)
}

/// sys_write - Write to stdout/stderr or socket
///
/// Zero-copy path for socket:
/// 1. Read from user buffer into Vec<u8> (ONE copy)
/// 2. Create DataPacket with the Vec
/// 3. Send via socket (zero-copy RRef transfer)
fn sys_write(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let buf_addr = ctx.rsi();
    let count = ctx.rdx();

    // For fd 1, 2 (stdout/stderr), print to console
    if fd == 1 || fd == 2 {
        let buf = read_from_user_to_vec(vm_space, buf_addr, count)?;
        match str::from_utf8(&buf) {
            Ok(s) => write_stdio(s),
            Err(_) => framevm_logln!("[FrameVM] (hex): {:x?}", buf),
        }
        return Ok(count as isize);
    }

    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();

    // Get addresses for packet header
    let (local, peer) = socket.addrs()?;

    // Read from user space directly into Vec (ONE copy)
    let data = read_from_user_to_vec(vm_space, buf_addr, count)?;
    let len = data.len();

    // Create DataPacket with the data (zero-copy: Vec is moved)
    let mut packet = DataPacket::new_rw(local.cid, peer.cid, local.port, peer.port, data);

    // Add credit info to header
    packet.header.buf_alloc = socket.get_buf_alloc();
    packet.header.fwd_cnt = socket.get_fwd_cnt();

    // Send packet (zero-copy: RRef ownership transfer)
    socket.send_packet(RRef::new(packet))?;

    Ok(len as isize)
}

fn sys_close(ctx: &mut UserContext) -> Result<isize> {
    let fd = ctx.rdi() as i32;

    // Ignore close on stdio
    if fd <= 2 {
        return Ok(0);
    }

    let fd_table = current_fd_table()?;
    let _handle = fd_table.lock().remove(fd)?;
    Ok(0)
}

// ============ Socket Syscalls ============

fn sys_socket(ctx: &mut UserContext) -> Result<isize> {
    let domain = ctx.rdi() as i32;
    let sock_type = ctx.rsi() as i32;

    if domain != AF_FRAMEVSOCK {
        return_errno_with_message!(Errno::EAFNOSUPPORT, "unsupported domain");
    }

    if sock_type & 0xf != SOCK_STREAM {
        return_errno_with_message!(Errno::ESOCKTNOSUPPORT, "unsupported socket type");
    }

    let nonblocking = (sock_type & SOCK_NONBLOCK) != 0;
    let socket = Arc::new(FrameVsockSocket::new(nonblocking));
    let fd_table = current_fd_table()?;
    let fd = fd_table.lock().alloc(socket);

    Ok(fd as isize)
}

fn sys_bind(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let addr_ptr = ctx.rsi();
    let addr_len = ctx.rdx();

    let addr = read_sockaddr(vm_space, addr_ptr, addr_len)?;
    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();
    socket.bind(addr)?;

    Ok(0)
}

fn sys_listen(ctx: &mut UserContext) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let backlog = ctx.rsi() as u32;

    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();
    socket.listen(backlog)?;
    Ok(0)
}

/// sys_clone - create a new thread (simplified)
///
/// Args (x86_64 ABI):
/// - rdi: flags
/// - rsi: child_stack
/// - rdx: parent_tidptr (ignored)
/// - r10: child_tidptr (ignored)
/// - r8:  tls (ignored)
fn sys_clone(ctx: &mut UserContext) -> Result<isize> {
    let flags = ctx.rdi() as u64;
    let child_stack = ctx.rsi();

    let child_tid = clone_user_task(ctx, child_stack, flags)?;
    Ok(child_tid as isize)
}

/// sys_fork - simplified fork (mapped to clone with thread semantics)
fn sys_fork(ctx: &mut UserContext) -> Result<isize> {
    // fork semantics: memory is shared in current FrameVM model (CLONE_VM),
    // but file descriptor table must be a logical copy (not CLONE_FILES).
    let flags = CLONE_VM;
    let child_tid = clone_user_task(ctx, 0, flags)?;
    Ok(child_tid as isize)
}

/// sys_getpid - return the single "process" ID
fn sys_getpid() -> Result<isize> {
    Ok(1)
}

/// sys_gettid - return current thread ID
fn sys_gettid() -> Result<isize> {
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let task_data = current
        .data()
        .downcast_ref::<crate::task::UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;
    Ok(task_data.tid as isize)
}

fn sys_wait4(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let pid = ctx.rdi() as i32;
    let status_ptr = ctx.rsi();
    let options = ctx.rdx() as i32;

    if options != 0 {
        return_errno_with_message!(Errno::EINVAL, "wait4 options not supported");
    }

    let info = wait_for_exit(pid);
    if status_ptr != 0 {
        let status = ((info.code as u32) & 0xff) << 8;
        write_to_user(vm_space, status_ptr, &status.to_ne_bytes())?;
    }
    Ok(info.tid as isize)
}

fn sys_accept(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let addr_ptr = ctx.rsi();
    let addrlen_ptr = ctx.rdx();

    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();
    let conn = socket.accept()?;
    let new_fd = fd_table.lock().alloc(conn.clone());

    if addr_ptr != 0 && addrlen_ptr != 0 {
        let addr_len = read_u32_from_user(vm_space, addrlen_ptr)?;
        let sockaddr = if let Some(peer) = conn.peer_addr() {
            SockAddrVm::from_addr(peer)
        } else {
            SockAddrVm::default()
        };
        let bytes = sockaddr.to_bytes();
        let write_len = (addr_len as usize).min(SockAddrVm::SIZE);
        write_to_user(vm_space, addr_ptr, &bytes[..write_len])?;
        write_to_user(
            vm_space,
            addrlen_ptr,
            &(SockAddrVm::SIZE as u32).to_ne_bytes(),
        )?;
    }

    Ok(new_fd as isize)
}

fn sys_connect(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let addr_ptr = ctx.rsi();
    let addr_len = ctx.rdx();

    let addr = read_sockaddr(vm_space, addr_ptr, addr_len)?;
    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();
    socket.connect(addr)?;

    Ok(0)
}

/// sys_sendto - Send data to socket
///
/// Zero-copy path:
/// 1. Read from user buffer into Vec<u8> (ONE copy, chunked)
/// 2. Create DataPacket with each chunk
/// 3. Send via socket (zero-copy RRef transfer)
fn sys_sendto(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let _trace = trace::TraceGuard::new(&trace::GUEST_SYS_SENDTO);
    let fd = ctx.rdi() as i32;
    let buf_addr = ctx.rsi();
    let len = ctx.rdx();
    // flags, dest_addr, addrlen ignored for stream socket

    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();

    if len == 0 {
        return Ok(0);
    }

    // Chunk user buffer to avoid oversized packets (internal fragmentation only).
    let mut total_sent = 0usize;
    let mut offset = 0usize;
    let max_chunk = MAX_PKT_BUF_SIZE as usize;

    while offset < len {
        let chunk_len = (len - offset).min(max_chunk);
        let chunk_addr = buf_addr
            .checked_add(offset)
            .ok_or_else(|| Error::new(Errno::EFAULT))?;

        let data = match read_from_user_to_vec(vm_space, chunk_addr, chunk_len) {
            Ok(buf) => buf,
            Err(e) => {
                return if total_sent > 0 {
                    Ok(total_sent as isize)
                } else {
                    Err(e)
                };
            }
        };

        match socket.send_owned(data) {
            Ok(sent) => {
                total_sent += sent;
                offset += sent;
            }
            Err(e) => {
                return if total_sent > 0 {
                    Ok(total_sent as isize)
                } else {
                    Err(e)
                };
            }
        }
    }

    Ok(total_sent as isize)
}

/// sys_recvfrom - Receive data from socket
///
/// Path:
/// 1. Dequeue packet data from socket
/// 2. Copy data to user buffer (ONE copy)
///
/// Uses the safe receive helper that keeps socket queue lock scope short.
fn sys_recvfrom(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let _trace = trace::TraceGuard::new(&trace::GUEST_SYS_RECVFROM);
    let fd = ctx.rdi() as i32;
    let buf_addr = ctx.rsi();
    let len = ctx.rdx();
    // flags, src_addr, addrlen ignored for stream socket

    let fd_table = current_fd_table()?;
    let socket = fd_table.lock().get(fd)?.socket();

    recv_to_user_via_safe_path(&socket, vm_space, buf_addr, len)
}

/// Receive into userspace without holding socket RX queue lock during user copy.
///
/// This follows Linux-style ordering more closely:
/// dequeue under lock, copy to userspace outside the queue lock.
/// It avoids long lock hold time or lock-order risks when user memory copy
/// incurs page faults under high load.
fn recv_to_user_via_safe_path(
    socket: &Arc<FrameVsockSocket>,
    vm_space: &VmSpace,
    buf_addr: usize,
    len: usize,
) -> Result<isize> {
    if len == 0 {
        return Ok(0);
    }

    let mut vm_writer = vm_space.writer(buf_addr, len).map_err(Error::from)?;

    let copied = socket.recv_to_user(len, |chunk| {
        let mut reader = VmReader::from(chunk);
        match vm_writer.write_fallible(&mut reader) {
            Ok(n) => Ok(n),
            Err((e, n)) => {
                if n > 0 {
                    Ok(n)
                } else {
                    Err(Error::from(e))
                }
            }
        }
    })?;

    Ok(copied as isize)
}

// ============ Time Syscalls ============

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;

static LAST_GUEST_MONO_NS: AtomicU64 = AtomicU64::new(0);
static GUEST_MONO_BACKWARD_COUNT: AtomicU64 = AtomicU64::new(0);

/// sys_clock_gettime - Get current time
fn sys_clock_gettime(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let clock_id = ctx.rdi();
    let timespec_addr = ctx.rsi();

    // Only support CLOCK_REALTIME and CLOCK_MONOTONIC for now
    // Since we don't have a real RTC source easily accessible here without more dependencies,
    // we use TSC for both, but treating them as monotonic time since boot.
    if clock_id != CLOCK_REALTIME && clock_id != CLOCK_MONOTONIC {
        return_errno_with_message!(Errno::EINVAL, "unsupported clock_id");
    }

    // Read TSC using safe API
    let tsc = arch::read_tsc();
    let freq = arch::tsc_freq();

    if freq == 0 {
        return_errno_with_message!(Errno::EINVAL, "TSC frequency not initialized");
    }

    // Calculate time from TSC
    // time = tsc / freq (seconds)
    // ns = (tsc % freq) * 1_000_000_000 / freq
    let sec = tsc / freq;
    let nsec = (tsc % freq) * 1_000_000_000 / freq;
    let now_ns = sec.saturating_mul(1_000_000_000) + nsec;
    if clock_id == CLOCK_MONOTONIC {
        let prev = LAST_GUEST_MONO_NS.load(Ordering::Relaxed);
        if now_ns < prev {
            GUEST_MONO_BACKWARD_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        let mut cur = prev;
        while now_ns > cur {
            match LAST_GUEST_MONO_NS.compare_exchange(
                cur,
                now_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(updated) => cur = updated,
            }
        }
    }

    // struct timespec { time_t tv_sec; long tv_nsec; };
    // 64-bit: 8 bytes sec + 8 bytes nsec
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_ne_bytes());
    buf[8..16].copy_from_slice(&nsec.to_ne_bytes());

    write_to_user(vm_space, timespec_addr, &buf)?;

    Ok(0)
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

fn read_u32_from_user(vm_space: &VmSpace, addr: usize) -> Result<u32> {
    let buf = read_from_user_to_vec(vm_space, addr, 4)?;
    Ok(u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))
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

fn read_sockaddr(vm_space: &VmSpace, addr: usize, len: usize) -> Result<FrameVsockAddr> {
    if len < SockAddrVm::SIZE {
        return_errno_with_message!(Errno::EINVAL, "address too short");
    }

    let buf = read_from_user_to_vec(vm_space, addr, SockAddrVm::SIZE)?;
    let sockaddr = SockAddrVm::from_bytes(&buf)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid address"))?;

    if sockaddr.family as i32 != AF_FRAMEVSOCK {
        return_errno_with_message!(Errno::EAFNOSUPPORT, "wrong address family");
    }

    Ok(sockaddr.to_addr())
}

/// Writes guest stdout/stderr bytes to the host-visible FrameVM log.
fn write_stdio(s: &str) {
    aster_framevisor::framevm_write_str(s);
}
