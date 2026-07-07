// SPDX-License-Identifier: MPL-2.0

//! IHT event sources for one FrameVM vCPU.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Product-level IHT event category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IhtEventKind {
    TimerTick,
    DeviceEvent,
}

/// Closed set of IHT event sources for one vCPU.
pub enum IhtEventSource {
    Timer(TimerTickSource),
    Device(DeviceEventSource),
}

impl IhtEventSource {
    /// Returns the source's product event kind.
    pub const fn kind(&self) -> IhtEventKind {
        match self {
            Self::Timer(_) => IhtEventKind::TimerTick,
            Self::Device(_) => IhtEventKind::DeviceEvent,
        }
    }

    /// Returns whether the source has pending work.
    pub fn has_pending(&self) -> bool {
        match self {
            Self::Timer(source) => source.has_pending(),
            Self::Device(source) => source.has_pending(),
        }
    }
}

/// Coalesced virtual timer tick source.
pub struct TimerTickSource {
    pending_ticks: AtomicU64,
}

impl TimerTickSource {
    /// Creates an empty timer tick source.
    pub const fn new() -> Self {
        Self {
            pending_ticks: AtomicU64::new(0),
        }
    }

    /// Records one pending virtual timer tick.
    pub fn record_tick(&self) -> bool {
        self.pending_ticks.fetch_add(1, Ordering::AcqRel) == 0
    }

    /// Returns the number of pending coalesced ticks.
    pub fn pending_ticks(&self) -> u64 {
        self.pending_ticks.load(Ordering::Acquire)
    }

    /// Returns whether the timer source has pending work.
    pub fn has_pending(&self) -> bool {
        self.pending_ticks() != 0
    }

    /// Takes all currently coalesced ticks.
    pub fn take_ticks(&self) -> u64 {
        self.pending_ticks.swap(0, Ordering::AcqRel)
    }
}

impl Default for TimerTickSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Device-originated IHT event source.
pub struct DeviceEventSource {
    pending: AtomicBool,
}

impl DeviceEventSource {
    /// Creates an empty device event source.
    pub const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
        }
    }

    /// Records that device work is pending for this vCPU.
    pub fn mark_pending(&self) {
        self.pending.store(true, Ordering::Release);
    }

    /// Clears the pending marker after a bounded device-source drain step.
    pub fn clear_pending(&self) {
        self.pending.store(false, Ordering::Release);
    }

    /// Returns whether device work is pending.
    pub fn has_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

impl Default for DeviceEventSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of one bounded event-source drain step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IhtDrainOutcome {
    NoWork,
    Drained,
    StillPending,
    StopBeforeNextStep,
}
