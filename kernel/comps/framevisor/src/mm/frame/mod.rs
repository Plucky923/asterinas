pub mod allocator;
pub mod meta;
pub mod segment;
pub mod untyped;

pub use allocator::FrameAllocOptions;
use ostd::early_println;

pub fn init_frame() {
    early_println!("[framevisor] Initializing frame...");
    allocator::init_frame_allocator();
    early_println!("[framevisor] Frame initialized");
}
