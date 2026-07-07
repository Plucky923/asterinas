//! FrameV RNG metadata.
//!
//! This module defines stable RNG device identity, IRQ metadata, ring count,
//! minimum ring depth, and the default notification target.

use framev_device::{
    FrameVDeviceId, FrameVDeviceInfo, FrameVDeviceType, IrqLine, IrqTarget, well_known,
};

/// The default `framev-rng` device ID.
pub const DEFAULT_DEVICE_ID: FrameVDeviceId = well_known::DEFAULT_RNG_DEVICE_ID;

/// The default `framev-rng` software IRQ line.
pub const DEFAULT_IRQ_LINE: IrqLine = IrqLine::new(3);

/// Returns the default `framev-rng` device metadata.
pub const fn default_device_info() -> FrameVDeviceInfo {
    FrameVDeviceInfo::new(DEFAULT_DEVICE_ID, FrameVDeviceType::Rng, DEFAULT_IRQ_LINE)
}

/// The initial number of FrameV RNG rings.
pub const RING_COUNT: usize = 1;

/// The minimum RNG request-ring depth.
pub const MIN_RING_DEPTH: usize = 1;

/// The default RNG completion notification target.
pub const DEFAULT_NOTIFICATION_TARGET: IrqTarget = IrqTarget::Untargeted;
