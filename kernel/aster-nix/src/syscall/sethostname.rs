// SPDX-License-Identifier: MPL-2.0

use crate::{
    prelude::*,
    process::namespace::uts_namespace::UTS_FIELD_LEN,
    syscall::{constants::MAX_FILENAME_LEN, SyscallReturn},
    util::read_cstring_from_user,
};

pub fn sys_sethostname(name: Vaddr, len: i32) -> Result<SyscallReturn> {
    if len < 0 || len as usize >= UTS_FIELD_LEN {
        return_errno_with_message!(Errno::EINVAL, "Invalid len");
    }
    let new_host_name = read_cstring_from_user(name, MAX_FILENAME_LEN)?;
    current!()
        .namespaces()
        .lock()
        .uts_ns()
        .sethostname(new_host_name);
    Ok(SyscallReturn::Return(0))
}
