// SPDX-License-Identifier: MPL-2.0

use core::cmp::min;

use ostd::mm::VmSpace;

use super::{Errno, Result, read_u32_from_user, socket::socket_file_from_fd, write_to_user};
use crate::{
    net::socket::{SocketOptionAccess, validate_socket_option, validate_socket_option_level},
    return_errno_with_message,
};

/// Gets a socket option.
pub(super) fn sys_getsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: usize,
    optlen_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    validate_socket_option_level(level)?;
    if optlen_addr == 0 {
        return_errno_with_message!(Errno::EINVAL, "optlen is null pointer");
    }

    let optlen = read_u32_from_user(vm_space, optlen_addr)?;
    let file = socket_file_from_fd(fd)?;
    let socket = file.as_socket_or_err()?;
    validate_socket_option(level, optname, SocketOptionAccess::Get)?;
    let value = socket.get_option(level, optname)?;
    let write_len = min(value.len(), optlen as usize);
    if write_len != 0 {
        write_to_user(vm_space, optval, &value[..write_len])?;
    }
    write_to_user(vm_space, optlen_addr, &(write_len as u32).to_ne_bytes())?;
    Ok(0)
}
