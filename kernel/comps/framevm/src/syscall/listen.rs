// SPDX-License-Identifier: MPL-2.0

use super::{Result, socket::socket_file_from_fd};

/// Marks a socket as accepting connections.
pub(super) fn sys_listen(fd: i32, backlog: i32) -> Result<isize> {
    let file = socket_file_from_fd(fd)?;
    file.as_socket_or_err()?.listen(backlog as usize)?;
    Ok(0)
}
