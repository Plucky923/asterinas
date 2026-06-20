// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use ostd::mm::VmSpace;

use super::{
    Result, read_from_user_to_vec,
    socket::{read_socket_addr_from_user, socket_file_from_fd},
};
use crate::net::socket::{MessageHeader, SendRecvFlags};

/// Sends data to a socket.
pub(super) fn sys_sendto(
    fd: i32,
    buf_addr: usize,
    len: usize,
    flags: i32,
    dest_addr: usize,
    addrlen: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let socket_addr = if dest_addr == 0 {
        None
    } else {
        Some(read_socket_addr_from_user(vm_space, dest_addr, addrlen)?)
    };
    let flags = SendRecvFlags::from_user_bits(flags)?;
    let file = socket_file_from_fd(fd)?;
    let buf = read_from_user_to_vec(vm_space, buf_addr, len)?;
    let sent_len = file.as_socket_or_err()?.sendmsg(
        &buf,
        MessageHeader::new(socket_addr, Vec::new()),
        flags,
    )?;
    Ok(sent_len as isize)
}
