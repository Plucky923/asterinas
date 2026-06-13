// SPDX-License-Identifier: MPL-2.0

//! CPU management for FrameVisor.

mod id;

pub use id::init_cpu_id;

/// Initialize the CPU subsystem.
pub fn init_cpu() {
    init_cpu_id();
}
