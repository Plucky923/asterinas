//! FrameV payload-free IRQ delivery primitives.
//!
//! This module defines routing targets and the common delivery abstraction used
//! by backend device classes and the owning VM device aggregate.

use crate::descriptor::IrqLine;

/// A FrameV IRQ delivery target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqTarget {
    Untargeted,
    Vcpu(usize),
}

/// A successful notification result that hides enqueue/coalescing details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrqAccepted;

/// Common IRQ delivery authority for FrameV devices.
pub trait IrqDelivery {
    type Error;

    /// Delivers a payload-free device IRQ notification.
    fn notify_irq(&self, irq_line: IrqLine, target: IrqTarget) -> Result<IrqAccepted, Self::Error>;
}
