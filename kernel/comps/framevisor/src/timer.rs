// SPDX-License-Identifier: MPL-2.0

//! The timer support.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::time::Duration;

use host_ostd::sync::RwLock;
#[cfg(not(feature = "host-api"))]
use vm::{FrameTaskGroupId, VmId};

#[cfg(not(feature = "host-api"))]
use crate::service_domain as vm;
#[cfg(feature = "host-api")]
use crate::vm::{FrameTaskGroupId, VmId};

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

        let elapsed = JIFFIES.read().get(&vm_id).copied().unwrap_or_default();
        Self::new(elapsed)
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

type TimerCallback = Arc<dyn Fn() + Sync + Send>;

static CALLBACKS: RwLock<BTreeMap<FrameTaskGroupId, Vec<TimerCallback>>> =
    RwLock::new(BTreeMap::new());
static JIFFIES: RwLock<BTreeMap<VmId, u64>> = RwLock::new(BTreeMap::new());

/// Registers a function that will be executed during the timer interrupt on the current CPU.
pub fn register_callback_on_cpu<F>(func: F)
where
    F: Fn() + Sync + Send + 'static,
{
    let task_group_id = current_task_group_id()
        .expect("timer callback registration requires a current CPU context");

    CALLBACKS
        .write()
        .entry(task_group_id)
        .or_default()
        .push(Arc::new(func));
}

pub(crate) fn advance_timer_ticks(task_group_id: FrameTaskGroupId, ticks: u64) {
    for _ in 0..ticks {
        advance_jiffies(task_group_id);
    }
}

pub(crate) fn dispatch_registered_callbacks(task_group_id: FrameTaskGroupId, ticks: u64) {
    if ticks == 0 {
        return;
    }

    let callbacks = CALLBACKS
        .read()
        .get(&task_group_id)
        .cloned()
        .unwrap_or_default();

    for _ in 0..ticks {
        for callback in &callbacks {
            callback();
        }
    }
}

#[cfg(feature = "host-api")]
pub(crate) fn clear_callbacks_for_vm(vm_id: VmId) {
    CALLBACKS
        .write()
        .retain(|task_group_id, _| task_group_id.vm_id() != vm_id);
    JIFFIES.write().remove(&vm_id);
}

fn advance_jiffies(task_group_id: FrameTaskGroupId) {
    if task_group_id.vcpu_id() != 0 {
        return;
    }

    let mut jiffies = JIFFIES.write();
    let elapsed = jiffies.entry(task_group_id.vm_id()).or_default();
    *elapsed = elapsed.saturating_add(1);
}

fn current_task_group_id() -> Option<FrameTaskGroupId> {
    crate::task::current_frame_task_group_id()
}

fn current_vm_id() -> Option<VmId> {
    current_task_group_id().map(|task_group_id| task_group_id.vm_id())
}
