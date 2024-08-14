// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::prelude::*;

pub fn sys_uname(old_uname_addr: Vaddr) -> Result<SyscallReturn> {
    debug!("old uname addr = 0x{:x}", old_uname_addr);
    let uts_name = current!().namespaces().lock().uts_ns().name();
    write_val_to_user(old_uname_addr, &uts_name)?;
    Ok(SyscallReturn::Return(0))
}
