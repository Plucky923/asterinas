//! Frame allocation primitives for FrameVisor.

pub mod allocator;
pub mod meta;
pub mod segment;
pub mod untyped;

pub use allocator::FrameAllocOptions;
use ostd::early_println;

use crate::prelude::Result;

pub fn init_frame() -> Result<()> {
    early_println!("[framevisor] Initializing frame...");
    allocator::init_frame_allocator()?;
    early_println!("[framevisor] Frame initialized");
    Ok(())
}
