//! The prelude.

use crate::Error as FrameError;

/// A specialized [`Result`] type for this crate.
///
/// [`Result`]: core::result::Result
pub type Result<T, E = FrameError> = core::result::Result<T, E>;

#[cfg(ktest)]
pub use host_ostd::prelude::ktest;

pub use crate::{
    alert, crit, debug, early_print as print, early_println as println, emerg, error, info,
    mm::{HasPaddr, HasSize, Paddr, Vaddr},
    notice,
    panic::abort,
    warn,
};
