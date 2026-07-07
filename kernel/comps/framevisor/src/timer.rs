// SPDX-License-Identifier: MPL-2.0

//! The timer support.

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::{
    irq,
    vm::{self, FrameVcpuId, VmId},
};

/// The timer frequency in Hz.
///
/// Here we choose 1000Hz since 1000Hz is easier for unit conversion and convenient for timer.
/// What's more, the frequency cannot be set too high or too low, 1000Hz is a modest choice.
///
/// For system performance reasons, this rate cannot be set too high, otherwise most of the time is
/// spent in executing timer code.
pub const TIMER_FREQ: u64 = 1000;

/// Jiffies is a term used to denote the units of time measurement by the kernel.
///
/// A jiffy represents one tick of the system timer interrupt,
/// whose frequency is equal to [`TIMER_FREQ`] Hz.
#[derive(Clone, Copy, Debug)]
pub struct Jiffies(u64);

impl Jiffies {
    /// The maximum value of [`Jiffies`].
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a new instance.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the elapsed time since the system boots up.
    pub fn elapsed() -> Self {
        let Some(vm_id) = current_vm_id() else {
            return Self::new(0);
        };

        let Some(vm) = vm::get_vm_by_id(vm_id) else {
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

/// A VM-wide clocksource fed by virtual timer accounting.
///
/// The clock is anchored when the VM runtime starts or resets, then advanced by
/// the latest virtual timer deadline delivered to any vCPU.  Multiple vCPUs
/// therefore share one monotonic VM timebase instead of contributing one elapsed
/// jiffy stream each.
pub(crate) struct VmClock {
    base_tsc: AtomicU64,
    latest_tsc: AtomicU64,
    frequency_hz: u64,
}

impl VmClock {
    /// Creates a clock anchored to the current architecture counter.
    pub(crate) fn new() -> Self {
        Self::new_at(crate::arch::read_tsc(), crate::arch::tsc_freq())
    }

    pub(crate) fn new_at(base_tsc: u64, frequency_hz: u64) -> Self {
        Self {
            base_tsc: AtomicU64::new(base_tsc),
            latest_tsc: AtomicU64::new(base_tsc),
            frequency_hz,
        }
    }

    /// Records a virtual timer deadline observed for this VM.
    pub(crate) fn record_deadline(&self, deadline_tsc: u64) {
        self.latest_tsc.fetch_max(deadline_tsc, Ordering::AcqRel);
    }

    /// Returns elapsed jiffies from the VM-wide virtual timer timebase.
    pub(crate) fn elapsed_jiffies(&self) -> u64 {
        if self.frequency_hz == 0 {
            return 0;
        }

        let base_tsc = self.base_tsc.load(Ordering::Acquire);
        let latest_tsc = self.latest_tsc.load(Ordering::Acquire);
        cycles_to_jiffies(latest_tsc.saturating_sub(base_tsc), self.frequency_hz)
    }

    /// Re-anchors the clock to the current architecture counter.
    pub(crate) fn reset(&self) {
        let base_tsc = crate::arch::read_tsc();
        self.base_tsc.store(base_tsc, Ordering::Release);
        self.latest_tsc.store(base_tsc, Ordering::Release);
    }
}

fn cycles_to_jiffies(cycles: u64, frequency_hz: u64) -> u64 {
    if frequency_hz == 0 {
        return 0;
    }

    let jiffies = (cycles as u128).saturating_mul(TIMER_FREQ as u128) / frequency_hz as u128;
    jiffies.min(u64::MAX as u128) as u64
}

pub(crate) type TimerCallback = Arc<dyn Fn() + Sync + Send>;

/// Registers a function that will be executed during the timer interrupt on the current CPU.
pub fn register_callback_on_cpu<F>(func: F)
where
    F: Fn() + Sync + Send + 'static,
{
    register_callback_on_cpu_inner(Arc::new(func));
}

#[inline(never)]
fn register_callback_on_cpu_inner(callback: TimerCallback) {
    let frame_vcpu_id = current_frame_vcpu_id()
        .expect("timer callback registration requires a current CPU context");

    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        .expect("timer callback registration requires an owning FrameVM runtime");
    let ctx = vm
        .iht_context(frame_vcpu_id.vcpu_index())
        .expect("timer callback registration requires an owning vCPU runtime");
    ctx.register_timer_callback(callback);
}

pub(crate) fn dispatch_registered_callbacks(frame_vcpu_id: FrameVcpuId, ticks: u64) {
    if ticks == 0 {
        return;
    }

    let Some(vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return;
    };
    let Some(ctx) = vm.iht_context(frame_vcpu_id.vcpu_index()) else {
        return;
    };
    let callbacks = ctx.timer_callbacks_snapshot();

    for _ in 0..ticks {
        for callback in &callbacks {
            irq::enter_timer_interrupt(|| callback());
        }
    }
}

pub(crate) fn clear_callbacks_for_vm(vm_id: VmId) {
    if let Some(vm) = vm::get_vm_by_id(vm_id) {
        vm.clear_timer_runtime();
    }
}

fn current_frame_vcpu_id() -> Option<FrameVcpuId> {
    crate::task::current_frame_vcpu_id()
}

fn current_vm_id() -> Option<VmId> {
    current_frame_vcpu_id().map(|frame_vcpu_id| frame_vcpu_id.vm_id())
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn vm_clock_converts_cycles_to_timer_freq_jiffies() {
        assert_eq!(cycles_to_jiffies(1_500_000, 1_000_000), 1_500);
    }

    #[ktest]
    fn vm_clock_zero_frequency_returns_zero() {
        assert_eq!(cycles_to_jiffies(1_500_000, 0), 0);
    }

    #[ktest]
    fn vm_clock_conversion_saturates() {
        assert_eq!(cycles_to_jiffies(u64::MAX, 1), u64::MAX);
    }

    #[ktest]
    fn vm_clock_uses_latest_recorded_deadline() {
        let clock = VmClock::new_at(1_000, 1_000);

        clock.record_deadline(2_500);
        assert_eq!(clock.elapsed_jiffies(), 1_500);

        clock.record_deadline(1_500);
        assert_eq!(clock.elapsed_jiffies(), 1_500);
    }
}
