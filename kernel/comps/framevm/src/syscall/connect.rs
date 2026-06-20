// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{
    Result,
    socket::{read_socket_addr_from_user, socket_file_from_fd},
};

/// Connects a socket.
pub(super) fn sys_connect(
    fd: i32,
    sockaddr_addr: usize,
    addrlen: u32,
    vm_space: &VmSpace,
) -> Result<isize> {
    let socket_addr = read_socket_addr_from_user(vm_space, sockaddr_addr, addrlen as usize)?;
    let file = socket_file_from_fd(fd)?;
    file.as_socket_or_err()?.connect(socket_addr)?;
    Ok(0)
}
