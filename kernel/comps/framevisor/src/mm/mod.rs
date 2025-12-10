pub mod frame;
pub(crate) mod page_prop;
pub(crate) mod page_table;
pub mod vm_space;

pub use frame::FrameAllocOptions;
use ostd::early_println;
pub use vm_space::{init_vm_space, VmSpace};

use crate::mm::frame::init_frame;

/// Virtual addresses.
pub type Vaddr = usize;

/// Physical addresses.
pub type Paddr = usize;

/// Device addresses.
pub type Daddr = usize;

pub fn init_mm() {
    early_println!("[framevisor] Initializing MM...");
    init_vm_space();
    init_frame();
}
