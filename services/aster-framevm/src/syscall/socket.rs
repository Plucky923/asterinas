// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs::file::{FileLike, file_table::FdFlags},
    net::socket::{
        unix::{UnixDatagramSocket, UnixStreamSocket},
        vsock::VsockStreamSocket,
    },
    prelude::*,
    util::net::{CSocketAddrFamily, SOCK_TYPE_MASK, SockFlags, SockType},
};

pub fn sys_socket(domain: i32, type_: i32, _protocol: i32, ctx: &Context) -> Result<SyscallReturn> {
    let domain = CSocketAddrFamily::try_from(domain)?;
    let sock_type = SockType::try_from(type_ & SOCK_TYPE_MASK)?;
    let sock_flags = SockFlags::from_bits_truncate(type_ & !SOCK_TYPE_MASK);
    debug!(
        "domain = {:?}, sock_type = {:?}, sock_flags = {:?}",
        domain, sock_type, sock_flags
    );

    let is_nonblocking = sock_flags.contains(SockFlags::SOCK_NONBLOCK);
    let file_like = match (domain, sock_type) {
        (CSocketAddrFamily::AF_UNIX, SockType::SOCK_STREAM) => {
            UnixStreamSocket::new(is_nonblocking, false) as Arc<dyn FileLike>
        }
        (CSocketAddrFamily::AF_UNIX, SockType::SOCK_SEQPACKET) => {
            UnixStreamSocket::new(is_nonblocking, true) as Arc<dyn FileLike>
        }
        (CSocketAddrFamily::AF_UNIX, SockType::SOCK_RAW | SockType::SOCK_DGRAM) => {
            UnixDatagramSocket::new(is_nonblocking) as Arc<dyn FileLike>
        }
        (CSocketAddrFamily::AF_VSOCK, SockType::SOCK_STREAM) => {
            Arc::new(VsockStreamSocket::new(is_nonblocking)) as Arc<dyn FileLike>
        }
        _ => return_errno_with_message!(Errno::EAFNOSUPPORT, "unsupported domain"),
    };

    let fd = {
        let file_table = ctx.thread_local.borrow_file_table();
        let mut file_table_locked = file_table.unwrap().write();
        let fd_flags = if sock_flags.contains(SockFlags::SOCK_CLOEXEC) {
            FdFlags::CLOEXEC
        } else {
            FdFlags::empty()
        };
        file_table_locked.insert(file_like, fd_flags)
    };

    Ok(SyscallReturn::Return(fd.into()))
}
