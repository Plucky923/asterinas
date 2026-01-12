//! Common result aliases used across FrameVisor modules.

pub type Result<T> = core::result::Result<T, crate::error::Error>;
