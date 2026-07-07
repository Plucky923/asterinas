// SPDX-License-Identifier: MPL-2.0

//! Network objects for the trimmed kernel image.

pub mod socket;
pub mod uts_ns;

/// Initializes network providers after the first kernel thread starts.
pub fn init_in_first_kthread() -> crate::error::Result<()> {
    socket::vsock::init()
}
