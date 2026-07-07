//! Frame allocation primitives exposed through the OSTD-compatible surface.

pub mod allocator;
mod frame_ref;
pub mod meta;
pub mod segment;
pub mod untyped;

pub use allocator::FrameAllocOptions;
pub use frame_ref::FrameRef;
use host_ostd::early_println;

use crate::prelude::Result;

pub(super) fn init_frame() -> Result<()> {
    early_println!("[framevisor] Initializing frame...");
    allocator::init_frame_allocator()?;
    early_println!("[framevisor] Frame initialized");
    Ok(())
}
