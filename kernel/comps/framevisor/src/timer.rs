// SPDX-License-Identifier: MPL-2.0

//! Host time and the FrameVM timer compatibility surface.

use core::time::Duration;

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::{task, vm};

/// The timer frequency in Hz.
pub const TIMER_FREQ: u64 = 1000;

/// Returns the Host wall clock for FrameVM services.
pub fn read_wall_clock() -> aster_time::SystemTime {
    let start = aster_time::read_start_time();
    let Ok(month) = Month::try_from(start.month) else {
        unreachable!("the Host RTC returned an invalid month")
    };
    let Ok(date) = Date::from_calendar_date(start.year as i32, month, start.day) else {
        unreachable!("the Host RTC returned an invalid date")
    };
    let Ok(nanosecond) = u32::try_from(start.nanos) else {
        unreachable!("the Host RTC returned an invalid nanosecond")
    };
    let Ok(time) = Time::from_hms_nano(start.hour, start.minute, start.second, nanosecond) else {
        unreachable!("the Host RTC returned an invalid time")
    };
    let start_nanos = PrimitiveDateTime::new(date, time)
        .assume_utc()
        .unix_timestamp_nanos();
    let elapsed = aster_time::read_monotonic_time();
    let elapsed_nanos =
        i128::from(elapsed.as_secs()) * 1_000_000_000 + i128::from(elapsed.subsec_nanos());
    let Some(now_nanos) = start_nanos.checked_add(elapsed_nanos) else {
        unreachable!("the Host wall clock exceeded its supported range")
    };
    let Ok(now) = OffsetDateTime::from_unix_timestamp_nanos(now_nanos) else {
        unreachable!("the Host wall clock exceeded its supported range")
    };

    aster_time::SystemTime {
        year: now.year() as u16,
        month: now.month() as u8,
        day: now.day(),
        hour: now.hour(),
        minute: now.minute(),
        second: now.second(),
        nanos: u64::from(now.nanosecond()),
    }
}

/// Jiffies is a term used to denote the units of time measurement by the kernel.
#[derive(Clone, Copy, Debug)]
pub struct Jiffies(u64);

impl Jiffies {
    /// The maximum value of [`Jiffies`].
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a new instance.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the elapsed time from the current FrameVM clock.
    pub fn elapsed() -> Self {
        let Some(vm) = task::current_frame_vm() else {
            return Self::new(0);
        };
        Self::new(vm.elapsed_jiffies())
    }

    /// Gets the number of jiffies.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Adds the given number of jiffies, saturating at [`Jiffies::MAX`] on overflow.
    pub fn add(&mut self, jiffies: u64) {
        self.0 = self.0.saturating_add(jiffies);
    }

    /// Gets the [`Duration`] calculated from the jiffies counts.
    pub fn as_duration(self) -> Duration {
        let secs = self.0 / TIMER_FREQ;
        let nanos = ((self.0 % TIMER_FREQ) * 1_000_000_000) / TIMER_FREQ;
        Duration::new(secs, nanos as u32)
    }
}

impl From<Jiffies> for Duration {
    fn from(value: Jiffies) -> Self {
        value.as_duration()
    }
}

/// Registers a function that runs on the current FrameVM vCPU's timer.
pub fn register_callback_on_cpu(callback: fn()) {
    let frame_vcpu_id = task::current_frame_vcpu_id()
        .expect("timer callback registration requires a current CPU context");
    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        .expect("timer callback registration requires an owning FrameVM runtime");
    vm.register_timer_callback(frame_vcpu_id, callback)
        .expect("timer callback registration requires an owning vCPU runtime");
}
