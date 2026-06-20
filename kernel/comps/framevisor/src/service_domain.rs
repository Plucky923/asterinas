// SPDX-License-Identifier: MPL-2.0

//! Private service-payload execution keys.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use host_ostd::sync::RwLock;

/// Opaque service instance identifier used by the service-payload facade.
pub(crate) type VmId = u32;

/// Identifies one service CPU execution lane.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ServiceCpuKey {
    service_id: VmId,
    cpu_id: usize,
}

impl ServiceCpuKey {
    /// Creates an execution-lane key.
    pub(crate) const fn new(service_id: VmId, cpu_id: usize) -> Self {
        Self { service_id, cpu_id }
    }

    /// Returns the owning service identifier.
    pub(crate) const fn vm_id(&self) -> VmId {
        self.service_id
    }

    /// Returns the owning service CPU identifier.
    pub(crate) const fn vcpu_id(&self) -> usize {
        self.cpu_id
    }
}

/// Internal alias used by shared host/service implementation code.
pub(crate) type FrameTaskGroupId = ServiceCpuKey;

/// Lightweight service-payload task group handle.
pub(crate) struct FrameTaskGroup {
    id: FrameTaskGroupId,
    schedule_count: AtomicU64,
    runtime_cycles: AtomicU64,
    pending_timer_ticks: AtomicU64,
    delivered_timer_ticks: AtomicU64,
    needs_resched: AtomicBool,
}

impl FrameTaskGroup {
    fn new(id: FrameTaskGroupId) -> Self {
        Self {
            id,
            schedule_count: AtomicU64::new(0),
            runtime_cycles: AtomicU64::new(0),
            pending_timer_ticks: AtomicU64::new(0),
            delivered_timer_ticks: AtomicU64::new(0),
            needs_resched: AtomicBool::new(false),
        }
    }

    /// Returns this service CPU key.
    pub(crate) const fn id(&self) -> FrameTaskGroupId {
        self.id
    }

    /// Records a scheduling-in event.
    pub(crate) fn record_schedule_in(&self, _is_iht: bool) {
        self.schedule_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a runtime interval.
    pub(crate) fn record_runtime_cycles(&self, start_cycles: u64, end_cycles: u64, _is_iht: bool) {
        self.runtime_cycles
            .fetch_add(end_cycles.saturating_sub(start_cycles), Ordering::Relaxed);
    }

    /// Returns whether scheduler work is pending.
    pub(crate) fn needs_resched(&self) -> bool {
        self.needs_resched.load(Ordering::Acquire)
    }

    /// Coalesces a virtual timer tick.
    pub(crate) fn inject_timer_tick(&self) {
        self.pending_timer_ticks.fetch_add(1, Ordering::AcqRel);
        self.needs_resched.store(true, Ordering::Release);
    }

    /// Returns whether timer work is pending.
    pub(crate) fn has_pending_timer_work(&self) -> bool {
        self.pending_timer_ticks.load(Ordering::Acquire) != 0
    }

    /// Drains pending timer ticks.
    pub(crate) fn take_pending_timer_ticks(&self) -> u64 {
        let ticks = self.pending_timer_ticks.swap(0, Ordering::AcqRel);
        if ticks != 0 {
            self.delivered_timer_ticks
                .fetch_add(ticks, Ordering::Relaxed);
        }
        self.needs_resched.store(false, Ordering::Release);
        ticks
    }
}

/// Lightweight service-payload VM handle.
pub(crate) struct FrameVm {
    id: VmId,
}

impl FrameVm {
    fn new(id: VmId) -> Self {
        Self { id }
    }

    /// Returns the service CPU count visible to copied kernel code.
    pub(crate) fn vcpu_count(&self) -> usize {
        1
    }

    /// Returns a service CPU task group handle.
    pub(crate) fn task_group(&self, cpu_id: usize) -> Option<Arc<FrameTaskGroup>> {
        (cpu_id < self.vcpu_count())
            .then(|| get_or_create_task_group(FrameTaskGroupId::new(self.id, cpu_id)))
    }

    /// Returns no concrete IHT context from service-payload code.
    pub(crate) fn iht_context(&self, _cpu_id: usize) -> Option<Arc<crate::iht::IhtContext>> {
        None
    }
}

/// Returns a service-payload VM handle.
pub(crate) fn get_vm_by_id(id: VmId) -> Option<FrameVm> {
    Some(FrameVm::new(id))
}

/// Returns no implicit VM from service-payload code.
pub(crate) fn get_vm() -> Option<FrameVm> {
    None
}

/// Returns a service-payload task group handle.
pub(crate) fn get_task_group_by_id(id: FrameTaskGroupId) -> Option<Arc<FrameTaskGroup>> {
    Some(get_or_create_task_group(id))
}

/// Returns the service CPU count visible to copied kernel code.
pub(crate) fn get_vcpu_count() -> usize {
    boot_vcpu_count()
}

static TASK_GROUPS: RwLock<BTreeMap<FrameTaskGroupId, Arc<FrameTaskGroup>>> =
    RwLock::new(BTreeMap::new());

fn get_or_create_task_group(id: FrameTaskGroupId) -> Arc<FrameTaskGroup> {
    if let Some(task_group) = TASK_GROUPS.read().get(&id).cloned() {
        return task_group;
    }

    let mut task_groups = TASK_GROUPS.write();
    task_groups
        .entry(id)
        .or_insert_with(|| Arc::new(FrameTaskGroup::new(id)))
        .clone()
}

fn boot_vcpu_count() -> usize {
    const DEFAULT_SERVICE_VCPU_COUNT: usize = 1;
    const MAX_SERVICE_VCPU_COUNT: usize = 4;

    let cmdline = &crate::boot::boot_info().kernel_cmdline;
    cmdline
        .split_whitespace()
        .find_map(|arg| {
            let (key, value) = arg.split_once('=')?;
            (key == "ostd.vcpu_count").then_some(value)
        })
        .and_then(parse_usize)
        .filter(|count| (1..=MAX_SERVICE_VCPU_COUNT).contains(count))
        .unwrap_or(DEFAULT_SERVICE_VCPU_COUNT)
}

fn parse_usize(value: &str) -> Option<usize> {
    let mut number = 0usize;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = usize::from(byte - b'0');
        number = number.checked_mul(10)?.checked_add(digit)?;
    }
    Some(number)
}
