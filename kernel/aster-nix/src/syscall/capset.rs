// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{
        credentials::{
            c_types::{cap_user_data_t, cap_user_header_t, LINUX_CAPABILITY_VERSION_3},
            linuxcapability::{Capability, CAP_VALID_MASK},
        },
        credentials_mut,
    },
    util::read_val_from_user,
};

/// Convert the high 32 bits to a u64 and shift them left by 32 bits,
/// then combine them with the low 32 bits, and apply a mask.
fn mk_kernel_cap(low: u32, high: u32) -> u64 {
    ((low as u64) | ((high as u64) << 32)) & CAP_VALID_MASK
}

pub fn sys_capset(cap_user_header_addr: Vaddr, cap_user_data_addr: Vaddr) -> Result<SyscallReturn> {
    let cap_user_header: cap_user_header_t =
        read_val_from_user::<cap_user_header_t>(cap_user_header_addr)?;

    // Validate the `header`.
    if cap_user_header.version != LINUX_CAPABILITY_VERSION_3 {
        // Return an error if the version is not supported.
        // For simplicity, we assume that the header version is CAPABILITY_VERSION_3.
        return_errno_with_message!(Errno::EINVAL, "not supported (capability version is not 3)");
    };

    // Set capabilities for the current process only (just like Linux).
    // The ability to set capabilities of any other process(es) has been deprecated and removed.
    // Extract target pid and validate whether it represents the current process.
    let header_pid = cap_user_header.pid;
    if header_pid != 0 && header_pid != current!().pid() {
        return_errno_with_message!(Errno::EINVAL, "invalid pid");
    }

    // Convert the cap(u32) to u64
    let cap_user_data: cap_user_data_t = read_val_from_user::<cap_user_data_t>(cap_user_data_addr)?;
    let inheritablecap = mk_kernel_cap(cap_user_data.inheritable, 0);
    let permittedcap = mk_kernel_cap(cap_user_data.permitted, 0);
    let effectivecap = mk_kernel_cap(cap_user_data.effective, 0);

    let credentials = credentials_mut();
    // Set capabilities
    credentials.set_inheritablecap(Capability(inheritablecap));
    credentials.set_permittedcap(Capability(permittedcap));
    credentials.set_effectivecap(Capability(effectivecap));

    Ok(SyscallReturn::Return(0))
}
