use alloc::sync::Arc;

use ostd::{early_println, mm::VmSpace as OstdVmSpace};

pub struct VmSpace {
    vmspace: OstdVmSpace,
}

impl VmSpace {
    pub fn new() -> Self {
        early_println!("[framevisor] Creating VM space...");
        let vmspace = OstdVmSpace::new();
        early_println!("[framevisor] VM space created: {:?}", vmspace);
        early_println!("[framevisor] DEBUG");
        Self { vmspace }
    }
}

pub fn init_vm_space() {
    VmSpace::new();
    early_println!("[framevisor] Initializing VM space...");
}
