// SPDX-License-Identifier: MPL-2.0

//! System information syscall.

use ostd::mm::VmSpace;

use super::{Result, write_to_user};

const UTS_FIELD_LEN: usize = 65;
const UTS_FIELD_COUNT: usize = 6;

const SYSNAME: &str = "Linux";
const NODENAME: &str = "(none)";
const RELEASE: &str = "5.13.0";
const VERSION: &str = {
    const BUILD_TIMESTAMP: &str = if let Some(timestamp) = option_env!("ASTER_BUILD_TIMESTAMP") {
        timestamp
    } else {
        "Thu Jan  1 00:00:00 UTC 1970"
    };

    const_format::formatcp!("#1 SMP {BUILD_TIMESTAMP}")
};
const _: () = assert!(VERSION.len() <= UTS_FIELD_LEN - 1);

const MACHINE: &str = {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            "x86_64"
        } else if #[cfg(target_arch = "riscv64")] {
            "riscv64"
        } else if #[cfg(target_arch = "loongarch64")] {
            "loongarch64"
        } else if #[cfg(target_arch = "aarch64")] {
            "aarch64"
        } else {
            "unknown"
        }
    }
};
const DOMAINNAME: &str = "(none)";

pub(super) fn sys_uname(uts_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    let mut uts = [0u8; UTS_FIELD_LEN * UTS_FIELD_COUNT];
    write_uts_field(&mut uts, 0, SYSNAME);
    write_uts_field(&mut uts, 1, NODENAME);
    write_uts_field(&mut uts, 2, RELEASE);
    write_uts_field(&mut uts, 3, VERSION);
    write_uts_field(&mut uts, 4, MACHINE);
    write_uts_field(&mut uts, 5, DOMAINNAME);
    write_to_user(vm_space, uts_addr, &uts)?;
    Ok(0)
}

fn write_uts_field(uts: &mut [u8], index: usize, value: &str) {
    let start = index * UTS_FIELD_LEN;
    let bytes = value.as_bytes();
    let len = bytes.len().min(UTS_FIELD_LEN - 1);
    uts[start..start + len].copy_from_slice(&bytes[..len]);
}
