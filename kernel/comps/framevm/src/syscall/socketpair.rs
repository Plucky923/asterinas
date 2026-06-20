// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use ostd::mm::VmSpace;

use super::{
    Errno, Error, FileLike, Result, current_fd_table, current_nofile_limit,
    socket::{SOCK_TYPE_MASK, socket_flags, validate_socket_kind},
    write_to_user,
};
use crate::{
    net::socket::unix::{AF_UNIX, UnixStreamSocket},
    return_errno, return_errno_with_message,
};

const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_RAW: i32 = 3;
const SOCK_SEQPACKET: i32 = 5;
const IPPROTO_IP: i32 = 0;
const IPPROTO_ICMP: i32 = 1;
const IPPROTO_IGMP: i32 = 2;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_EGP: i32 = 8;
const IPPROTO_PUP: i32 = 12;
const IPPROTO_UDP: i32 = 17;
const IPPROTO_IDP: i32 = 22;
const IPPROTO_TP: i32 = 29;
const IPPROTO_DCCP: i32 = 33;
const IPPROTO_IPV6: i32 = 41;
const IPPROTO_RSVP: i32 = 46;
const IPPROTO_GRE: i32 = 47;
const IPPROTO_ESP: i32 = 50;
const IPPROTO_AH: i32 = 51;
const IPPROTO_MTP: i32 = 92;
const IPPROTO_BEETPH: i32 = 94;
const IPPROTO_ENCAP: i32 = 98;
const IPPROTO_PIM: i32 = 103;
const IPPROTO_COMP: i32 = 108;
const IPPROTO_SCTP: i32 = 132;
const IPPROTO_UDPLITE: i32 = 136;
const IPPROTO_MPLS: i32 = 137;
const IPPROTO_ETHERNET: i32 = 143;
const IPPROTO_RAW: i32 = 255;
const IPPROTO_MPTCP: i32 = 262;

/// Creates a pair of connected sockets.
pub(super) fn sys_socketpair(
    domain: i32,
    socket_type: i32,
    protocol: i32,
    socket_fds_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let socket_kind = socket_type & SOCK_TYPE_MASK;
    validate_socket_kind(socket_kind)?;
    let (fd_flags, status_flags) = socket_flags(socket_type & !SOCK_TYPE_MASK)?;
    validate_socketpair_protocol(protocol)?;

    if domain != AF_UNIX {
        return_errno_with_message!(
            Errno::EAFNOSUPPORT,
            "creating a socket pair for this family is not supported"
        );
    }

    if socket_kind != SOCK_STREAM {
        match socket_kind {
            SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET => {
                return_errno_with_message!(Errno::EOPNOTSUPP, "socket pair type is not supported")
            }
            _ => return_errno!(Errno::ESOCKTNOSUPPORT),
        }
    }

    let is_nonblocking = status_flags.contains(super::StatusFlags::O_NONBLOCK);
    let (socket_a, socket_b) = UnixStreamSocket::new_pair(is_nonblocking);
    let socket_a: Arc<dyn FileLike> = socket_a;
    let socket_b: Arc<dyn FileLike> = socket_b;

    let fd_table = current_fd_table()?;
    let nofile_limit = current_nofile_limit()?;
    let (fd_a, fd_b) = {
        let mut fd_table = fd_table.lock();
        let fd_a = fd_table.insert_file(socket_a, fd_flags, nofile_limit)?;
        let fd_b = match fd_table.insert_file(socket_b, fd_flags, nofile_limit) {
            Ok(fd_b) => fd_b,
            Err(error) => {
                let _ = fd_table.close_file(fd_a);
                return Err(error);
            }
        };
        (i32::from(fd_a), i32::from(fd_b))
    };
    write_to_user(vm_space, socket_fds_addr, &fd_a.to_ne_bytes())?;
    write_to_user(
        vm_space,
        socket_fds_addr + size_of::<i32>(),
        &fd_b.to_ne_bytes(),
    )?;
    Ok(0)
}

fn validate_socketpair_protocol(protocol: i32) -> Result<()> {
    match protocol {
        IPPROTO_IP | IPPROTO_ICMP | IPPROTO_IGMP | IPPROTO_TCP | IPPROTO_EGP | IPPROTO_PUP
        | IPPROTO_UDP | IPPROTO_IDP | IPPROTO_TP | IPPROTO_DCCP | IPPROTO_IPV6 | IPPROTO_RSVP
        | IPPROTO_GRE | IPPROTO_ESP | IPPROTO_AH | IPPROTO_MTP | IPPROTO_BEETPH | IPPROTO_ENCAP
        | IPPROTO_PIM | IPPROTO_COMP | IPPROTO_SCTP | IPPROTO_UDPLITE | IPPROTO_MPLS
        | IPPROTO_ETHERNET | IPPROTO_RAW | IPPROTO_MPTCP => Ok(()),
        _ => Err(Error::new(Errno::EINVAL)),
    }
}
