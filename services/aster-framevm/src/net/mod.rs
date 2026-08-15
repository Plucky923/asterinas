// SPDX-License-Identifier: MPL-2.0

//! Network objects for the trimmed kernel image.

pub mod iface;
pub mod socket;
pub mod uts_ns;

/// Initializes network providers after the first kernel thread starts.
pub fn init_in_first_kthread() -> crate::error::Result<()> {
    iface::init();
    socket::vsock::init()?;
    iface::init_in_first_kthread();
    Ok(())
}

/// Stops network tasks owned by this FrameVM.
pub fn shutdown() {
    iface::shutdown();
}
