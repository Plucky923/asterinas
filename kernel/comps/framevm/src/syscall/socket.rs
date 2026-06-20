// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use core::cmp::min;

use ostd::mm::VmSpace;

use super::{
    Errno, Error, FdFlags, FileLike, Result, StatusFlags, current_fd_file, current_fd_table,
    current_nofile_limit, read_from_user_to_vec, read_i32_from_user, write_to_user,
};
use crate::{
    net::socket::{
        SocketAddr,
        unix::{AF_UNIX, UnixSocketAddr, UnixStreamSocket},
        vsock::{AF_VSOCK, CSocketAddrVm, VsockStreamSocket},
    },
    return_errno_with_message,
};

const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_RAW: i32 = 3;
const SOCK_RDM: i32 = 4;
const SOCK_SEQPACKET: i32 = 5;
const SOCK_DCCP: i32 = 6;
const SOCK_PACKET: i32 = 10;
pub(super) const SOCK_TYPE_MASK: i32 = 0xf;
pub(super) const SOCK_NONBLOCK: i32 = 1 << 11;
pub(super) const SOCK_CLOEXEC: i32 = 1 << 19;
const SOCK_FLAGS_MASK: i32 = SOCK_NONBLOCK | SOCK_CLOEXEC;
const SOCKADDR_STORAGE_LEN: usize = 128;
const CSOCKADDR_UNIX_UNNAMED_LEN: usize = size_of::<u16>();

/// Creates a socket.
pub(super) fn sys_socket(domain: i32, socket_type: i32, _protocol: i32) -> Result<isize> {
    let socket_kind = socket_type & SOCK_TYPE_MASK;
    validate_socket_kind(socket_kind)?;
    let (fd_flags, status_flags) = socket_flags(socket_type & !SOCK_TYPE_MASK)?;
    let is_nonblocking = status_flags.contains(StatusFlags::O_NONBLOCK);
    let file: Arc<dyn FileLike> = match (domain, socket_kind) {
        (AF_UNIX, SOCK_STREAM) => UnixStreamSocket::new(is_nonblocking),
        (AF_UNIX, SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET) => {
            return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported AF_UNIX socket type")
        }
        (AF_VSOCK, SOCK_STREAM) => Arc::new(VsockStreamSocket::new(is_nonblocking)),
        (AF_VSOCK, _) => {
            return_errno_with_message!(Errno::EAFNOSUPPORT, "unsupported AF_VSOCK socket type")
        }
        _ => return_errno_with_message!(Errno::EAFNOSUPPORT, "unsupported domain"),
    };
    let nofile_limit = current_nofile_limit()?;
    let fd_table = current_fd_table()?;
    Ok(fd_table
        .lock()
        .insert_file(file, fd_flags, nofile_limit)?
        .into())
}

pub(super) fn socket_flags(raw_flags: i32) -> Result<(FdFlags, StatusFlags)> {
    let raw_flags = raw_flags & SOCK_FLAGS_MASK;

    let fd_flags = if raw_flags & SOCK_CLOEXEC != 0 {
        FdFlags::CLOEXEC
    } else {
        FdFlags::empty()
    };
    let status_flags = if raw_flags & SOCK_NONBLOCK != 0 {
        StatusFlags::O_NONBLOCK
    } else {
        StatusFlags::empty()
    };
    Ok((fd_flags, status_flags))
}

pub(super) fn validate_socket_kind(socket_kind: i32) -> Result<()> {
    match socket_kind {
        SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_RDM | SOCK_SEQPACKET | SOCK_DCCP
        | SOCK_PACKET => Ok(()),
        _ => Err(Error::new(Errno::EINVAL)),
    }
}

pub(super) fn socket_file_from_fd(fd: i32) -> Result<Arc<dyn FileLike>> {
    if fd < 0 {
        return Err(Error::new(Errno::EBADF));
    }

    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    let _ = file.as_socket_or_err()?;
    Ok(file)
}

pub(super) fn read_socket_addr_from_user(
    vm_space: &VmSpace,
    addr: usize,
    addr_len: usize,
) -> Result<SocketAddr> {
    if addr_len > SOCKADDR_STORAGE_LEN {
        return_errno_with_message!(Errno::EINVAL, "the socket address length is too large");
    }

    if addr_len < size_of::<u16>() {
        return_errno_with_message!(Errno::EINVAL, "the socket address length is too small");
    }

    let family_bytes = read_from_user_to_vec(vm_space, addr, size_of::<u16>())?;
    let family = u16::from_ne_bytes([family_bytes[0], family_bytes[1]]);
    match i32::from(family) {
        AF_UNIX => {
            if addr_len != CSOCKADDR_UNIX_UNNAMED_LEN {
                return_errno_with_message!(
                    Errno::EOPNOTSUPP,
                    "only unnamed AF_UNIX socket addresses are supported"
                );
            }
            Ok(SocketAddr::Unix(UnixSocketAddr::Unnamed))
        }
        AF_VSOCK => {
            if addr_len < CSocketAddrVm::SIZE {
                return_errno_with_message!(Errno::EINVAL, "the socket address length is too small");
            }

            let bytes = read_from_user_to_vec(vm_space, addr, CSocketAddrVm::SIZE)?;
            Ok(SocketAddr::Vsock(CSocketAddrVm::from_bytes(&bytes)?.into()))
        }
        _ => return_errno_with_message!(Errno::EAFNOSUPPORT, "unsupported socket address family"),
    }
}

pub(super) fn write_socket_addr_to_user(
    vm_space: &VmSpace,
    socket_addr: &SocketAddr,
    addr: usize,
    addr_len_addr: usize,
) -> Result<()> {
    let max_len = read_i32_from_user(vm_space, addr_len_addr)?;
    if max_len < 0 {
        return_errno_with_message!(
            Errno::EINVAL,
            "the socket address length cannot be negative"
        );
    }

    match *socket_addr {
        SocketAddr::Unix(_) => {
            let family = (AF_UNIX as u16).to_ne_bytes();
            let written_len = min(family.len(), max_len as usize);
            write_to_user(vm_space, addr, &family[..written_len])?;
            write_to_user(
                vm_space,
                addr_len_addr,
                &(CSOCKADDR_UNIX_UNNAMED_LEN as i32).to_ne_bytes(),
            )
        }
        SocketAddr::Vsock(vsock_addr) => {
            let bytes = CSocketAddrVm::from(vsock_addr).to_bytes();
            let written_len = min(bytes.len(), max_len as usize);
            write_to_user(vm_space, addr, &bytes[..written_len])?;
            write_to_user(vm_space, addr_len_addr, &(bytes.len() as i32).to_ne_bytes())
        }
    }
}
