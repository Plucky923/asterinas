mod vm_space;

use ostd::early_println;
pub use vm_space::{init_vm_space, VmSpace};

pub fn init_mm() {
    early_println!("[framevisor] Initializing MM...");
    init_vm_space();
}
