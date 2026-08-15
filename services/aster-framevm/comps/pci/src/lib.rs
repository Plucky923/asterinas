// SPDX-License-Identifier: MPL-2.0

//! The shared PCI bus implementation built for FrameVM.

#![no_std]
#![deny(unsafe_code)]

macro_rules! __log_prefix {
    () => {
        "pci: "
    };
}

pub mod bus;
pub mod capability;
pub mod cfg_space;
#[expect(
    dead_code,
    reason = "the shared module retains Host-only PCI reservation support"
)]
pub mod common_device;
mod device_info;
mod enumeration;
mod platform;

extern crate alloc;

use component::{ComponentInitError, init_component};
pub use device_info::{PciDeviceId, PciDeviceLocation};
use ostd::{
    FramevisorError,
    sync::{Mutex, Once},
};

use self::{bus::PciBus, common_device::PciCommonDevice};

#[init_component]
fn pci_init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

struct FrameVmPciState {
    bus: Mutex<PciBus>,
    initialized: Mutex<bool>,
}

impl FrameVmPciState {
    fn new() -> Self {
        Self {
            bus: Mutex::new(PciBus::new()),
            initialized: Mutex::new(false),
        }
    }

    fn initialize(&self) {
        let mut initialized = self.initialized.lock();
        if *initialized {
            return;
        }

        enumeration::enumerate(platform::init(), &self.bus);
        *initialized = true;
    }
}

// Each loaded service image owns its own PCI bus.  A process-global
// FrameVisor-local registry is unnecessary and would outlive the image that
// owns the bus.
static FRAMEVM_PCI_STATE: Once<alloc::sync::Arc<FrameVmPciState>> = Once::new();

/// Initializes common PCI enumeration for the current FrameVM.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    let state = current_state().map_err(|_| ComponentInitError::Unknown)?;
    state.initialize();
    Ok(())
}

/// Runs a closure with the current FrameVM's PCI bus.
pub fn with_bus<T>(access_fn: impl FnOnce(&mut PciBus) -> T) -> T {
    let state = current_state().expect("PCI access requires a current FrameVM");
    state.initialize();
    access_fn(&mut state.bus.lock())
}

fn current_state() -> Result<alloc::sync::Arc<FrameVmPciState>, FramevisorError> {
    Ok(FRAMEVM_PCI_STATE
        .call_once(|| alloc::sync::Arc::new(FrameVmPciState::new()))
        .clone())
}
