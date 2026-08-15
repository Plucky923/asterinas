// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use crate::SystemTime;

/// Generic interface for RTC drivers
pub trait Driver {
    /// Creates a RTC driver.
    /// Returns [`Some<Self>`] on success, [`None`] otherwise (e.g. platform unsupported).
    #[expect(
        dead_code,
        reason = "the FrameVM profile installs the Host-backed RTC directly"
    )]
    fn try_new() -> Option<Self>
    where
        Self: Sized;

    /// Reads RTC.
    fn read_rtc(&self) -> SystemTime;
}

pub fn init_rtc_driver() -> Arc<dyn Driver + Send + Sync> {
    Arc::new(FrameVmRtc)
}

struct FrameVmRtc;

impl Driver for FrameVmRtc {
    fn try_new() -> Option<Self> {
        Some(Self)
    }

    fn read_rtc(&self) -> SystemTime {
        let host_time = ostd::timer::read_wall_clock();
        SystemTime {
            year: host_time.year,
            month: host_time.month,
            day: host_time.day,
            hour: host_time.hour,
            minute: host_time.minute,
            second: host_time.second,
            nanos: host_time.nanos,
        }
    }
}
