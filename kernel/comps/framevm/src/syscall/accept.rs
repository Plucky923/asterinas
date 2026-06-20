// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{
    Result, current_fd_table, current_nofile_limit,
    socket::{socket_file_from_fd, socket_flags, write_socket_addr_to_user},
};

/// Accepts a connection on a socket.
pub(super) fn sys_accept(
    fd: i32,
    sockaddr_addr: usize,
    addrlen_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    do_accept(fd, sockaddr_addr, addrlen_addr, 0, vm_space)
}

/// Accepts a connection on a socket with descriptor flags.
pub(super) fn sys_accept4(
    fd: i32,
    sockaddr_addr: usize,
    addrlen_addr: usize,
    flags: i32,
    vm_space: &VmSpace,
) -> Result<isize> {
    do_accept(fd, sockaddr_addr, addrlen_addr, flags, vm_space)
}

fn do_accept(
    fd: i32,
    sockaddr_addr: usize,
    addrlen_addr: usize,
    flags: i32,
    vm_space: &VmSpace,
) -> Result<isize> {
    let file = socket_file_from_fd(fd)?;
    let (connected_socket, socket_addr) = file.as_socket_or_err()?.accept()?;
    let (fd_flags, status_flags) = socket_flags(flags)?;
    connected_socket.set_status_flags(status_flags)?;

    if sockaddr_addr != 0 {
        write_socket_addr_to_user(vm_space, &socket_addr, sockaddr_addr, addrlen_addr)?;
    }

    let nofile_limit = current_nofile_limit()?;
    let fd_table = current_fd_table()?;
    Ok(fd_table
        .lock()
        .insert_file(connected_socket, fd_flags, nofile_limit)?
        .into())
}
