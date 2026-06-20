// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use ostd::mm::VmSpace;

use super::{
    Errno, Result, read_from_user_to_vec, read_u32_from_user, read_usize_from_user,
    socket::{read_socket_addr_from_user, socket_file_from_fd},
};
use crate::{
    net::socket::{MessageHeader, SendRecvFlags},
    return_errno_with_message,
};

const MSGHDR_NAME_OFFSET: usize = 0;
const MSGHDR_NAMELEN_OFFSET: usize = 8;
const MSGHDR_IOV_OFFSET: usize = 16;
const MSGHDR_IOVLEN_OFFSET: usize = 24;
const MSGHDR_CONTROL_OFFSET: usize = 32;
const MSGHDR_CONTROLLEN_OFFSET: usize = 40;
const IOV_MAX: usize = 1024;
const IOV_ENTRY_SIZE: usize = size_of::<usize>() * 2;
const IOV_LEN_OFFSET: usize = size_of::<usize>();

/// Sends data on a socket from a user message header.
pub(super) fn sys_sendmsg(
    fd: i32,
    msghdr_addr: usize,
    flags: i32,
    vm_space: &VmSpace,
) -> Result<isize> {
    let file = socket_file_from_fd(fd)?;
    let message_header = read_message_header(vm_space, msghdr_addr)?;
    let input = read_iovs(vm_space, msghdr_addr)?;
    let flags = SendRecvFlags::from_user_bits(flags)?;
    let sent_len = file
        .as_socket_or_err()?
        .sendmsg(&input, message_header, flags)?;
    Ok(sent_len as isize)
}

fn read_message_header(vm_space: &VmSpace, msghdr_addr: usize) -> Result<MessageHeader> {
    let name_addr = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_NAME_OFFSET)?;
    let name_len = read_u32_from_user(vm_space, msghdr_addr + MSGHDR_NAMELEN_OFFSET)? as usize;
    let control_addr = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_CONTROL_OFFSET)?;
    let control_len = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_CONTROLLEN_OFFSET)?;
    if control_addr != 0 || control_len != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "control messages are not supported");
    }

    let socket_addr = if name_addr == 0 {
        None
    } else {
        Some(read_socket_addr_from_user(vm_space, name_addr, name_len)?)
    };
    Ok(MessageHeader::new(socket_addr, Vec::new()))
}

fn read_iovs(vm_space: &VmSpace, msghdr_addr: usize) -> Result<Vec<u8>> {
    let iov_addr = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_IOV_OFFSET)?;
    let iov_len = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_IOVLEN_OFFSET)?;
    if iov_len > IOV_MAX {
        return_errno_with_message!(Errno::EMSGSIZE, "too many iov entries");
    }

    let mut input = Vec::new();
    for index in 0..iov_len {
        let entry_offset = index.checked_mul(IOV_ENTRY_SIZE).ok_or(Errno::EFAULT)?;
        let entry_addr = iov_addr.checked_add(entry_offset).ok_or(Errno::EFAULT)?;
        let base = read_usize_from_user(vm_space, entry_addr)?;
        let len_addr = entry_addr
            .checked_add(IOV_LEN_OFFSET)
            .ok_or(Errno::EFAULT)?;
        let len = read_usize_from_user(vm_space, len_addr)?;
        let new_len = input.checked_len_add(len)?;
        input.reserve(len);
        input.extend(read_from_user_to_vec(vm_space, base, len)?);
        debug_assert_eq!(input.len(), new_len);
    }
    Ok(input)
}

trait CheckedVecLen {
    fn checked_len_add(&self, len: usize) -> Result<usize>;
}

impl CheckedVecLen for Vec<u8> {
    fn checked_len_add(&self, len: usize) -> Result<usize> {
        self.len().checked_add(len).ok_or(Errno::EINVAL.into())
    }
}
