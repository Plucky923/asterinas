// SPDX-License-Identifier: MPL-2.0

//! Symbolic-link target read syscalls.

use ostd::mm::VmSpace;

use super::{
    EmptyPathStr, Errno, Error, Result, RootFs, read_c_string, resolve_guest_path,
    resolve_guest_path_at, write_to_user,
};

pub(super) fn sys_readlink(
    pathname_addr: usize,
    buf_addr: usize,
    buf_size: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let pathname = resolve_guest_path(&read_c_string(vm_space, pathname_addr)?)?;
    readlink_to_user(vm_space, &pathname, buf_addr, buf_size)
}

pub(super) fn sys_readlinkat(
    dirfd: i32,
    pathname_addr: usize,
    buf_addr: usize,
    buf_size: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let pathname = resolve_guest_path_at(
        dirfd,
        &read_c_string(vm_space, pathname_addr)?,
        EmptyPathStr::Allow,
    )?;
    readlink_to_user(vm_space, &pathname, buf_addr, buf_size)
}

fn readlink_to_user(
    vm_space: &VmSpace,
    pathname: &str,
    buf_addr: usize,
    buf_size: usize,
) -> Result<isize> {
    if buf_size == 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let target = RootFs::get()?.readlink(pathname)?;
    let bytes = target.as_bytes();
    let write_len = bytes.len().min(buf_size);
    write_to_user(vm_space, buf_addr, &bytes[..write_len])?;
    Ok(write_len as isize)
}
