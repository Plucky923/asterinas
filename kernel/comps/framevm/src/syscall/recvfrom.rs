// SPDX-License-Identifier: MPL-2.0

use alloc::vec;

use ostd::mm::VmSpace;

use super::{
    Result, reactivate_current_vm_space,
    socket::{socket_file_from_fd, write_socket_addr_to_user},
    write_to_user,
};
use crate::net::socket::SendRecvFlags;

/// Receives data from a socket.
pub(super) fn sys_recvfrom(
    fd: i32,
    buf_addr: usize,
    len: usize,
    flags: i32,
    src_addr: usize,
    addrlen_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let file = socket_file_from_fd(fd)?;
    let flags = SendRecvFlags::from_user_bits(flags)?;
    let mut buf = vec![0u8; len];
    let (recv_len, message_header) = file.as_socket_or_err()?.recvmsg(&mut buf, flags)?;

    reactivate_current_vm_space()?;
    write_to_user(vm_space, buf_addr, &buf[..recv_len])?;

    if let Some(socket_addr) = message_header.addr()
        && src_addr != 0
    {
        write_socket_addr_to_user(vm_space, socket_addr, src_addr, addrlen_addr)?;
    }

    Ok(recv_len as isize)
}
