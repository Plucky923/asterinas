// SPDX-License-Identifier: MPL-2.0

use super::{Result, socket::socket_file_from_fd};
use crate::net::socket::SockShutdownCmd;

/// Shuts down part of a full-duplex socket.
pub(super) fn sys_shutdown(fd: i32, how: i32) -> Result<isize> {
    let cmd = SockShutdownCmd::try_from(how)?;
    let file = socket_file_from_fd(fd)?;
    file.as_socket_or_err()?.shutdown(cmd)?;
    Ok(0)
}
