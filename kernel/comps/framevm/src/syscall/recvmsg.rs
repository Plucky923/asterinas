// SPDX-License-Identifier: MPL-2.0

use alloc::vec;
use core::cmp::min;

use ostd::mm::VmSpace;

use super::{
    Errno, Result, reactivate_current_vm_space, read_usize_from_user,
    socket::{socket_file_from_fd, write_socket_addr_to_user},
    write_to_user,
};
use crate::{net::socket::SendRecvFlags, return_errno_with_message};

const MSGHDR_NAME_OFFSET: usize = 0;
const MSGHDR_NAMELEN_OFFSET: usize = 8;
const MSGHDR_IOV_OFFSET: usize = 16;
const MSGHDR_IOVLEN_OFFSET: usize = 24;
const MSGHDR_CONTROL_OFFSET: usize = 32;
const MSGHDR_CONTROLLEN_OFFSET: usize = 40;
const MSGHDR_FLAGS_OFFSET: usize = 48;
const IOV_MAX: usize = 1024;
const IOV_ENTRY_SIZE: usize = size_of::<usize>() * 2;
const IOV_LEN_OFFSET: usize = size_of::<usize>();

/// Receives data on a socket into a user message header.
pub(super) fn sys_recvmsg(
    fd: i32,
    msghdr_addr: usize,
    flags: i32,
    vm_space: &VmSpace,
) -> Result<isize> {
    let file = socket_file_from_fd(fd)?;
    let flags = SendRecvFlags::from_user_bits(flags)?;
    let total_len = iovs_total_len(vm_space, msghdr_addr)?;
    let mut output = vec![0u8; total_len];
    let (recv_len, message_header) = file.as_socket_or_err()?.recvmsg(&mut output, flags)?;

    reactivate_current_vm_space()?;
    write_iovs(vm_space, msghdr_addr, &output[..recv_len])?;
    if let Some(socket_addr) = message_header.addr() {
        let name_addr = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_NAME_OFFSET)?;
        if name_addr != 0 {
            write_socket_addr_to_user(
                vm_space,
                socket_addr,
                name_addr,
                msghdr_addr + MSGHDR_NAMELEN_OFFSET,
            )?;
        }
    }
    write_to_user(
        vm_space,
        msghdr_addr + MSGHDR_CONTROLLEN_OFFSET,
        &0usize.to_ne_bytes(),
    )?;
    write_to_user(
        vm_space,
        msghdr_addr + MSGHDR_FLAGS_OFFSET,
        &0i32.to_ne_bytes(),
    )?;
    Ok(recv_len as isize)
}

fn iovs_total_len(vm_space: &VmSpace, msghdr_addr: usize) -> Result<usize> {
    let control_addr = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_CONTROL_OFFSET)?;
    let control_len = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_CONTROLLEN_OFFSET)?;
    if control_addr != 0 || control_len != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "control messages are not supported");
    }

    let iov_addr = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_IOV_OFFSET)?;
    let iov_len = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_IOVLEN_OFFSET)?;
    if iov_len > IOV_MAX {
        return_errno_with_message!(Errno::EMSGSIZE, "too many iov entries");
    }

    let mut total_len = 0usize;
    for index in 0..iov_len {
        let entry_offset = index.checked_mul(IOV_ENTRY_SIZE).ok_or(Errno::EFAULT)?;
        let entry_addr = iov_addr.checked_add(entry_offset).ok_or(Errno::EFAULT)?;
        let len_addr = entry_addr
            .checked_add(IOV_LEN_OFFSET)
            .ok_or(Errno::EFAULT)?;
        let len = read_usize_from_user(vm_space, len_addr)?;
        total_len = total_len.checked_add(len).ok_or(Errno::EINVAL)?;
    }
    Ok(total_len)
}

fn write_iovs(vm_space: &VmSpace, msghdr_addr: usize, data: &[u8]) -> Result<()> {
    let iov_addr = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_IOV_OFFSET)?;
    let iov_len = read_usize_from_user(vm_space, msghdr_addr + MSGHDR_IOVLEN_OFFSET)?;
    let mut written_len = 0usize;
    for index in 0..iov_len {
        if written_len == data.len() {
            break;
        }

        let entry_offset = index.checked_mul(IOV_ENTRY_SIZE).ok_or(Errno::EFAULT)?;
        let entry_addr = iov_addr.checked_add(entry_offset).ok_or(Errno::EFAULT)?;
        let base = read_usize_from_user(vm_space, entry_addr)?;
        let len_addr = entry_addr
            .checked_add(IOV_LEN_OFFSET)
            .ok_or(Errno::EFAULT)?;
        let len = read_usize_from_user(vm_space, len_addr)?;
        let chunk_len = min(len, data.len() - written_len);
        write_to_user(vm_space, base, &data[written_len..written_len + chunk_len])?;
        written_len += chunk_len;
    }
    Ok(())
}
