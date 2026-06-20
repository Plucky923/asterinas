// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{Errno, Result, read_from_user_to_vec, socket::socket_file_from_fd};
use crate::{
    net::socket::{SocketOptionAccess, validate_socket_option, validate_socket_option_level},
    return_errno_with_message,
};

/// Sets a socket option.
pub(super) fn sys_setsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: usize,
    optlen: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    validate_socket_option_level(level)?;
    if optval == 0 {
        return_errno_with_message!(Errno::EINVAL, "optval is null pointer");
    }

    let file = socket_file_from_fd(fd)?;
    let socket = file.as_socket_or_err()?;
    validate_socket_option(level, optname, SocketOptionAccess::Set)?;
    let option = read_from_user_to_vec(vm_space, optval, optlen)?;
    socket.set_option(level, optname, &option)?;
    Ok(0)
}
