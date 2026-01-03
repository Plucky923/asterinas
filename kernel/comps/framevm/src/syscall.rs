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
use core::str;

use aster_framevisor::{
    arch::cpu::context::UserContext,
    mm::{
        io::{FallibleVmRead, FallibleVmWrite},
        VmReader, VmSpace, VmWriter,
    },
    println,
};
use aster_framevsock::DataPacket;
use exchangeable::RRef;

use crate::{
    error::{Errno, Error, Result},
    return_errno_with_message,
    vsock::{
        self,
        addr::{FrameVsockAddr, SockAddrVm, AF_FRAMEVSOCK},
        socket::FrameVsockSocket,
    },
};

// Syscall numbers (x86_64) - only those needed by vsock_echo_server
pub const SYS_WRITE: usize = 1;
pub const SYS_CLOSE: usize = 3;
pub const SYS_SOCKET: usize = 41;
pub const SYS_ACCEPT: usize = 43;
pub const SYS_SENDTO: usize = 44;
pub const SYS_RECVFROM: usize = 45;
pub const SYS_BIND: usize = 49;
pub const SYS_LISTEN: usize = 50;
pub const SYS_EXIT: usize = 60;

// Socket types
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_NONBLOCK: i32 = 0x800;

pub fn handle_syscall(user_context: &mut UserContext, vm_space: &VmSpace) -> bool {
    let syscall_num = user_context.rax();
    let result = match syscall_num {
        SYS_WRITE => sys_write(user_context, vm_space),
        SYS_CLOSE => sys_close(user_context),
        SYS_SOCKET => sys_socket(user_context),
        SYS_ACCEPT => sys_accept(user_context),
        SYS_SENDTO => sys_sendto(user_context, vm_space),
        SYS_RECVFROM => sys_recvfrom(user_context, vm_space),
        SYS_BIND => sys_bind(user_context, vm_space),
        SYS_LISTEN => sys_listen(user_context),
        SYS_EXIT => {
            println!("[FrameVM] SYS_EXIT called with code {}", user_context.rdi());
            return true;
        }
        _ => {
            println!("[FrameVM] Unknown syscall: {}", syscall_num);
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

// ============ File I/O Syscalls ============

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
            Ok(s) => print_str(s),
            Err(_) => println!("[FrameVM] (hex): {:x?}", buf),
        }
        return Ok(count as isize);
    }

    let socket = vsock::get_socket(fd)?;

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

    let socket = vsock::remove_socket(fd)?;
    socket.close()?;
    Ok(0)
}

// ============ Socket Syscalls ============

fn sys_socket(ctx: &mut UserContext) -> Result<isize> {
    let domain = ctx.rdi() as i32;
    let sock_type = ctx.rsi() as i32;
    let _protocol = ctx.rdx() as i32;

    println!("[FrameVM] socket(domain={}, type={})", domain, sock_type);

    if domain != AF_FRAMEVSOCK {
        return_errno_with_message!(Errno::EAFNOSUPPORT, "unsupported domain");
    }

    if sock_type & 0xf != SOCK_STREAM {
        return_errno_with_message!(Errno::ESOCKTNOSUPPORT, "unsupported socket type");
    }

    let nonblocking = (sock_type & SOCK_NONBLOCK) != 0;
    let socket = Arc::new(FrameVsockSocket::new(nonblocking));
    let fd = vsock::alloc_fd(socket);

    println!("[FrameVM] socket() -> fd={}", fd);
    Ok(fd as isize)
}

fn sys_bind(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let addr_ptr = ctx.rsi();
    let addr_len = ctx.rdx();

    let addr = read_sockaddr(vm_space, addr_ptr, addr_len)?;
    let socket = vsock::get_socket(fd)?;
    socket.bind(addr)?;

    println!("[FrameVM] bind(fd={}) -> addr={:?}", fd, addr);
    Ok(0)
}

fn sys_listen(ctx: &mut UserContext) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let backlog = ctx.rsi() as u32;

    println!("[FrameVM] listen(fd={}, backlog={})", fd, backlog);

    let socket = vsock::get_socket(fd)?;
    socket.listen(backlog)?;
    Ok(0)
}

fn sys_accept(ctx: &mut UserContext) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    // addr and addrlen ignored for simplicity

    println!("[FrameVM] accept(fd={})", fd);

    let socket = vsock::get_socket(fd)?;
    let conn = socket.accept()?;
    let new_fd = vsock::alloc_fd(conn);

    println!("[FrameVM] accept() -> fd={}", new_fd);
    Ok(new_fd as isize)
}

/// sys_sendto - Send data to socket
///
/// Zero-copy path:
/// 1. Read from user buffer into Vec<u8> (ONE copy)
/// 2. Create DataPacket with the Vec
/// 3. Send via socket (zero-copy RRef transfer)
fn sys_sendto(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let buf_addr = ctx.rsi();
    let len = ctx.rdx();
    // flags, dest_addr, addrlen ignored for stream socket

    let socket = vsock::get_socket(fd)?;

    // Get addresses for packet header
    let (local, peer) = socket.addrs()?;

    // Read from user space directly into Vec (ONE copy)
    let data = read_from_user_to_vec(vm_space, buf_addr, len)?;
    let sent_len = data.len();

    // Create DataPacket with the data (zero-copy: Vec is moved)
    let mut packet = DataPacket::new_rw(local.cid, peer.cid, local.port, peer.port, data);

    // Add credit info to header
    packet.header.buf_alloc = socket.get_buf_alloc();
    packet.header.fwd_cnt = socket.get_fwd_cnt();

    // Send packet (zero-copy: RRef ownership transfer)
    socket.send_packet(RRef::new(packet))?;

    println!("[FrameVM] sendto(fd={}, len={}) -> {}", fd, len, sent_len);
    Ok(sent_len as isize)
}

/// sys_recvfrom - Receive data from socket
///
/// Zero-copy path:
/// 1. Get packet from socket (RRef<DataPacket>)
/// 2. Copy data directly from packet to user buffer (ONE copy)
fn sys_recvfrom(ctx: &mut UserContext, vm_space: &VmSpace) -> Result<isize> {
    let fd = ctx.rdi() as i32;
    let buf_addr = ctx.rsi();
    let len = ctx.rdx();
    // flags, src_addr, addrlen ignored for stream socket

    let socket = vsock::get_socket(fd)?;

    // Get a packet from the socket (zero-copy: packet is RRef)
    let packet = socket.recv_packet()?;

    // Copy directly from packet data to user space (ONE copy)
    let to_copy = packet.data.len().min(len);
    write_to_user(vm_space, buf_addr, &packet.data[..to_copy])?;

    println!("[FrameVM] recvfrom(fd={}, len={}) -> {}", fd, len, to_copy);
    Ok(to_copy as isize)
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

/// Print string to console (for stdout/stderr)
fn print_str(s: &str) {
    println!("{}", s);
}
