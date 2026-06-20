// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{
    Result,
    socket::{socket_file_from_fd, write_socket_addr_to_user},
};

/// Gets the local address of a socket.
pub(super) fn sys_getsockname(
    fd: i32,
    addr: usize,
    addrlen_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let file = socket_file_from_fd(fd)?;
    let socket_addr = file.as_socket_or_err()?.addr()?;
    write_socket_addr_to_user(vm_space, &socket_addr, addr, addrlen_addr)?;
    Ok(0)
}
