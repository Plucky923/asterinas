//! FrameV console metadata.
//!
//! This module defines stable console device identity, IRQ metadata, ring count,
//! and the default notification target.

use framev_device::{
    FrameVDeviceId, FrameVDeviceInfo, FrameVDeviceType, IrqLine, IrqTarget, well_known,
};

/// The default `framev-console` device ID.
pub const DEFAULT_DEVICE_ID: FrameVDeviceId = well_known::DEFAULT_CONSOLE_DEVICE_ID;

/// The default `framev-console` software IRQ line.
pub const DEFAULT_IRQ_LINE: IrqLine = IrqLine::new(1);

/// The initial number of FrameV console rings.
pub const RING_COUNT: usize = 2;

/// The default input and output notification target.
pub const DEFAULT_NOTIFICATION_TARGET: IrqTarget = IrqTarget::Untargeted;

/// Returns the default `framev-console` device metadata.
pub const fn default_device_info() -> FrameVDeviceInfo {
    FrameVDeviceInfo::new(
        DEFAULT_DEVICE_ID,
        FrameVDeviceType::Console,
        DEFAULT_IRQ_LINE,
    )
}
