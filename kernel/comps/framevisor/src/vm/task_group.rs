// SPDX-License-Identifier: MPL-2.0

//! Host-visible scheduling state for FrameVM vCPU domains.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use host_ostd::{arch::read_tsc, cpu::CpuId, util::id_set::Id};

use super::VmId;
#[cfg(feature = "host-api")]
use crate::task;
use crate::{error::Error, prelude::Result};

/// Default CPU share for a FrameVM task group.
pub const DEFAULT_FRAME_TASK_GROUP_SHARE: u32 = 1024;

/// Minimum accepted FrameVM task group share.
pub const MIN_FRAME_TASK_GROUP_SHARE: u32 = 2;

/// Maximum accepted FrameVM task group share.
pub const MAX_FRAME_TASK_GROUP_SHARE: u32 = 262_144;

/// Identifies one host-visible FrameVM scheduling entity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FrameTaskGroupId {
    vm_id: VmId,
    vcpu_id: usize,
}

impl FrameTaskGroupId {
    /// Creates an identifier for one FrameVM vCPU task group.
    pub const fn new(vm_id: VmId, vcpu_id: usize) -> Self {
        Self { vm_id, vcpu_id }
    }

    /// Returns the owning VM ID.
    pub const fn vm_id(&self) -> VmId {
        self.vm_id
    }

    /// Returns the owning vCPU ID.
    pub const fn vcpu_id(&self) -> usize {
        self.vcpu_id
    }
}

/// A stable snapshot of FrameVM task group scheduling state.
#[derive(Clone, Copy, Debug)]
pub struct FrameTaskGroupSnapshot {
    id: FrameTaskGroupId,
    share: u32,
    nice_hint: i8,
    schedule_count: u64,
    runtime_cycles: u64,
    service_schedule_count: u64,
    service_runtime_cycles: u64,
    iht_schedule_count: u64,
    iht_runtime_cycles: u64,
    pending_timer_ticks: u64,
    delivered_timer_ticks: u64,
    last_host_deadline: u64,
    schedule_cpu_mask: u64,
    last_schedule_cpu: u32,
    needs_resched: bool,
}

impl FrameTaskGroupSnapshot {
    /// Returns the task group identifier.
    pub const fn id(&self) -> FrameTaskGroupId {
        self.id
    }

    /// Returns the configured CPU share.
    pub const fn share(&self) -> u32 {
        self.share
    }

    /// Returns the host fair-scheduler nice hint derived from `share`.
    pub const fn nice_hint(&self) -> i8 {
        self.nice_hint
    }

    /// Returns how many times a host backing task was scheduled in.
    pub const fn schedule_count(&self) -> u64 {
        self.schedule_count
    }

    /// Returns accumulated host runtime in TSC cycles.
    pub const fn runtime_cycles(&self) -> u64 {
        self.runtime_cycles
    }

    /// Returns how many times service tasks were scheduled in.
    pub const fn service_schedule_count(&self) -> u64 {
        self.service_schedule_count
    }

    /// Returns accumulated service-task runtime in TSC cycles.
    pub const fn service_runtime_cycles(&self) -> u64 {
        self.service_runtime_cycles
    }

    /// Returns how many times IHT tasks were scheduled in.
    pub const fn iht_schedule_count(&self) -> u64 {
        self.iht_schedule_count
    }

    /// Returns accumulated IHT runtime in TSC cycles.
    pub const fn iht_runtime_cycles(&self) -> u64 {
        self.iht_runtime_cycles
    }

    /// Returns coalesced virtual timer ticks not yet handled by IHT.
    pub const fn pending_timer_ticks(&self) -> u64 {
        self.pending_timer_ticks
    }

    /// Returns virtual timer ticks already delivered to IHT.
    pub const fn delivered_timer_ticks(&self) -> u64 {
        self.delivered_timer_ticks
    }

    /// Returns the latest host timer deadline recorded for this group.
    pub const fn last_host_deadline(&self) -> u64 {
        self.last_host_deadline
    }

    /// Returns the host CPUs on which this group has been scheduled.
    pub const fn schedule_cpu_mask(&self) -> u64 {
        self.schedule_cpu_mask
    }

    /// Returns the last host CPU on which this group was scheduled.
    pub const fn last_schedule_cpu(&self) -> u32 {
        self.last_schedule_cpu
    }

    /// Returns whether this group must run scheduler/IHT work before a task.
    pub const fn needs_resched(&self) -> bool {
        self.needs_resched
    }
}

/// Host-visible scheduling entity for one FrameVM vCPU.
pub struct FrameTaskGroup {
    id: FrameTaskGroupId,
    share: AtomicU32,
    schedule_count: AtomicU64,
    runtime_cycles: AtomicU64,
    service_schedule_count: AtomicU64,
    service_runtime_cycles: AtomicU64,
    iht_schedule_count: AtomicU64,
    iht_runtime_cycles: AtomicU64,
    schedule_cpu_mask: AtomicU64,
    last_schedule_cpu: AtomicU32,
    timer: VcpuTimerState,
}

/// Virtual timer state for one vCPU scheduling domain.
pub struct VcpuTimerState {
    pending_timer_ticks: AtomicU64,
    delivered_timer_ticks: AtomicU64,
    last_host_deadline: AtomicU64,
    needs_resched: AtomicBool,
}

impl VcpuTimerState {
    /// Creates an empty timer state.
    pub const fn new() -> Self {
        Self {
            pending_timer_ticks: AtomicU64::new(0),
            delivered_timer_ticks: AtomicU64::new(0),
            last_host_deadline: AtomicU64::new(0),
            needs_resched: AtomicBool::new(false),
        }
    }

    /// Coalesces one virtual timer tick.
    pub fn inject_tick(&self, host_deadline: u64) {
        self.last_host_deadline
            .store(host_deadline, Ordering::Release);
        self.pending_timer_ticks.fetch_add(1, Ordering::AcqRel);
        self.needs_resched.store(true, Ordering::Release);
    }

    /// Returns whether this vCPU domain has pending scheduler ticks.
    pub fn has_pending_scheduler_ticks(&self) -> bool {
        self.pending_timer_ticks.load(Ordering::Acquire) != 0
    }

    /// Returns whether this vCPU domain has pending timer work.
    pub fn has_pending_work(&self) -> bool {
        self.has_pending_scheduler_ticks()
    }

    /// Returns whether the next entry must handle scheduler state first.
    pub fn needs_resched(&self) -> bool {
        self.needs_resched.load(Ordering::Acquire)
    }

    /// Drains coalesced timer ticks for IHT processing.
    pub fn take_pending_ticks(&self) -> u64 {
        let ticks = self.pending_timer_ticks.swap(0, Ordering::AcqRel);
        if ticks != 0 {
            self.delivered_timer_ticks
                .fetch_add(ticks, Ordering::Relaxed);
        }
        self.needs_resched.store(false, Ordering::Release);
        ticks
    }

    /// Returns coalesced timer ticks not yet handled by IHT.
    pub fn pending_ticks(&self) -> u64 {
        self.pending_timer_ticks.load(Ordering::Acquire)
    }

    /// Returns virtual timer ticks already delivered to IHT.
    pub fn delivered_ticks(&self) -> u64 {
        self.delivered_timer_ticks.load(Ordering::Acquire)
    }

    /// Returns the latest host timer deadline recorded for this vCPU domain.
    pub fn last_host_deadline(&self) -> u64 {
        self.last_host_deadline.load(Ordering::Acquire)
    }

    /// Clears all pending and delivered timer state for a new accounting window.
    pub fn reset(&self) {
        self.pending_timer_ticks.store(0, Ordering::Release);
        self.delivered_timer_ticks.store(0, Ordering::Release);
        self.last_host_deadline.store(0, Ordering::Release);
        self.needs_resched.store(false, Ordering::Release);
    }
}

impl FrameTaskGroup {
    /// Creates a task group with the default share.
    pub fn new(id: FrameTaskGroupId) -> Self {
        Self {
            id,
            share: AtomicU32::new(DEFAULT_FRAME_TASK_GROUP_SHARE),
            schedule_count: AtomicU64::new(0),
            runtime_cycles: AtomicU64::new(0),
            service_schedule_count: AtomicU64::new(0),
            service_runtime_cycles: AtomicU64::new(0),
            iht_schedule_count: AtomicU64::new(0),
            iht_runtime_cycles: AtomicU64::new(0),
            schedule_cpu_mask: AtomicU64::new(0),
            last_schedule_cpu: AtomicU32::new(u32::MAX),
            timer: VcpuTimerState::new(),
        }
    }

    /// Returns the task group identifier.
    pub const fn id(&self) -> FrameTaskGroupId {
        self.id
    }

    /// Returns the configured CPU share.
    pub fn share(&self) -> u32 {
        self.share.load(Ordering::Acquire)
    }

    /// Returns runtime normalized by this group's configured share.
    pub fn normalized_runtime_cycles(&self) -> u64 {
        self.runtime_cycles()
            .saturating_mul(u64::from(DEFAULT_FRAME_TASK_GROUP_SHARE))
            / u64::from(self.share().max(1))
    }

    /// Updates the configured CPU share.
    pub fn set_share(&self, share: u32) -> Result<()> {
        validate_frame_task_group_share(share)?;
        self.share.store(share, Ordering::Release);
        #[cfg(feature = "host-api")]
        task::update_frame_task_group_share(self.id);
        Ok(())
    }

    /// Returns the host fair-scheduler nice hint derived from `share`.
    pub fn nice_hint(&self) -> i8 {
        share_to_nice_hint(self.share())
    }

    /// Records that a backing task in this group was scheduled in.
    pub fn record_schedule_in(&self, is_iht: bool) {
        let cpu = CpuId::current_racy().as_usize();
        if cpu < u64::BITS as usize {
            self.schedule_cpu_mask
                .fetch_or(1u64 << cpu, Ordering::Relaxed);
        }
        self.last_schedule_cpu.store(cpu as u32, Ordering::Relaxed);
        self.schedule_count.fetch_add(1, Ordering::Relaxed);
        if is_iht {
            self.iht_schedule_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.service_schedule_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Resets runtime accounting counters while preserving scheduling policy.
    pub fn reset_accounting(&self) {
        self.schedule_count.store(0, Ordering::Release);
        self.runtime_cycles.store(0, Ordering::Release);
        self.service_schedule_count.store(0, Ordering::Release);
        self.service_runtime_cycles.store(0, Ordering::Release);
        self.iht_schedule_count.store(0, Ordering::Release);
        self.iht_runtime_cycles.store(0, Ordering::Release);
        self.schedule_cpu_mask.store(0, Ordering::Release);
        self.last_schedule_cpu.store(u32::MAX, Ordering::Release);
        self.timer.reset();
    }

    /// Returns accumulated runtime in TSC cycles.
    pub fn runtime_cycles(&self) -> u64 {
        self.runtime_cycles.load(Ordering::Acquire)
    }

    /// Charges a backing task runtime interval to this group.
    pub fn record_runtime_cycles(&self, start_cycles: u64, end_cycles: u64, is_iht: bool) {
        let delta = end_cycles.saturating_sub(start_cycles);
        self.runtime_cycles.fetch_add(delta, Ordering::Relaxed);
        if is_iht {
            self.iht_runtime_cycles.fetch_add(delta, Ordering::Relaxed);
        } else {
            self.service_runtime_cycles
                .fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// Coalesces one virtual timer tick for this vCPU domain.
    pub fn inject_timer_tick(&self) {
        self.inject_timer_tick_at(read_tsc());
    }

    /// Coalesces one virtual timer tick with a known host deadline.
    pub fn inject_timer_tick_at(&self, host_deadline: u64) {
        self.timer.inject_tick(host_deadline);
    }

    /// Returns whether this vCPU domain has pending timer ticks.
    pub fn has_pending_timer_ticks(&self) -> bool {
        self.timer.has_pending_scheduler_ticks()
    }

    /// Returns whether this vCPU domain has pending timer work for IHT.
    pub fn has_pending_timer_work(&self) -> bool {
        self.timer.has_pending_work()
    }

    /// Returns whether the next FrameVM entry must handle scheduler state first.
    pub fn needs_resched(&self) -> bool {
        self.timer.needs_resched()
    }

    /// Drains coalesced timer ticks for IHT processing.
    pub fn take_pending_timer_ticks(&self) -> u64 {
        self.timer.take_pending_ticks()
    }

    /// Returns the number of virtual timer ticks delivered to IHT.
    pub fn delivered_timer_ticks(&self) -> u64 {
        self.timer.delivered_ticks()
    }

    /// Returns coalesced timer ticks not yet handled by IHT.
    pub fn pending_timer_ticks(&self) -> u64 {
        self.timer.pending_ticks()
    }

    /// Returns the latest host timer deadline recorded for this group.
    pub fn last_host_deadline(&self) -> u64 {
        self.timer.last_host_deadline()
    }

    /// Returns a stable snapshot.
    pub fn snapshot(&self) -> FrameTaskGroupSnapshot {
        FrameTaskGroupSnapshot {
            id: self.id,
            share: self.share(),
            nice_hint: self.nice_hint(),
            schedule_count: self.schedule_count.load(Ordering::Acquire),
            runtime_cycles: self.runtime_cycles.load(Ordering::Acquire),
            service_schedule_count: self.service_schedule_count.load(Ordering::Acquire),
            service_runtime_cycles: self.service_runtime_cycles.load(Ordering::Acquire),
            iht_schedule_count: self.iht_schedule_count.load(Ordering::Acquire),
            iht_runtime_cycles: self.iht_runtime_cycles.load(Ordering::Acquire),
            pending_timer_ticks: self.pending_timer_ticks(),
            delivered_timer_ticks: self.delivered_timer_ticks(),
            last_host_deadline: self.last_host_deadline(),
            schedule_cpu_mask: self.schedule_cpu_mask.load(Ordering::Acquire),
            last_schedule_cpu: self.last_schedule_cpu.load(Ordering::Acquire),
            needs_resched: self.needs_resched(),
        }
    }
}

/// Validates a FrameVM task group CPU share.
pub fn validate_frame_task_group_share(share: u32) -> Result<()> {
    if (MIN_FRAME_TASK_GROUP_SHARE..=MAX_FRAME_TASK_GROUP_SHARE).contains(&share) {
        Ok(())
    } else {
        Err(Error::InvalidArgs)
    }
}

/// Converts a CFS-style share into the closest host `nice` hint.
pub fn share_to_nice_hint(share: u32) -> i8 {
    let share = share.clamp(MIN_FRAME_TASK_GROUP_SHARE, MAX_FRAME_TASK_GROUP_SHARE);

    if share == DEFAULT_FRAME_TASK_GROUP_SHARE {
        return 0;
    }

    if share > DEFAULT_FRAME_TASK_GROUP_SHARE {
        share_to_negative_nice_hint(share)
    } else {
        share_to_positive_nice_hint(share)
    }
}

fn share_to_negative_nice_hint(share: u32) -> i8 {
    let mut nice = 0i8;
    let mut threshold = DEFAULT_FRAME_TASK_GROUP_SHARE;
    while nice > -20 && threshold < share {
        threshold = threshold.saturating_mul(5).saturating_add(3) / 4;
        nice -= 1;
    }
    nice
}

fn share_to_positive_nice_hint(share: u32) -> i8 {
    let mut nice = 0i8;
    let mut threshold = DEFAULT_FRAME_TASK_GROUP_SHARE;
    while nice < 19 && share < threshold {
        threshold = threshold.saturating_mul(4) / 5;
        nice += 1;
    }
    nice
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn default_share_maps_to_default_nice() {
        assert_eq!(share_to_nice_hint(DEFAULT_FRAME_TASK_GROUP_SHARE), 0);
    }

    #[ktest]
    fn share_mapping_preserves_priority_direction() {
        assert!(share_to_nice_hint(DEFAULT_FRAME_TASK_GROUP_SHARE * 2) < 0);
        assert!(share_to_nice_hint(DEFAULT_FRAME_TASK_GROUP_SHARE / 2) > 0);
    }

    #[ktest]
    fn share_validation_rejects_out_of_range_values() {
        assert!(validate_frame_task_group_share(MIN_FRAME_TASK_GROUP_SHARE).is_ok());
        assert!(validate_frame_task_group_share(MAX_FRAME_TASK_GROUP_SHARE).is_ok());
        assert!(validate_frame_task_group_share(MIN_FRAME_TASK_GROUP_SHARE - 1).is_err());
        assert!(validate_frame_task_group_share(MAX_FRAME_TASK_GROUP_SHARE + 1).is_err());
    }

    #[ktest]
    fn timer_ticks_are_coalesced_until_iht_drains_them() {
        let task_group = FrameTaskGroup::new(FrameTaskGroupId::new(0, 0));

        task_group.inject_timer_tick_at(11);
        task_group.inject_timer_tick_at(13);

        assert!(task_group.has_pending_timer_ticks());
        assert!(task_group.needs_resched());
        assert_eq!(task_group.pending_timer_ticks(), 2);
        assert_eq!(task_group.delivered_timer_ticks(), 0);
        assert_eq!(task_group.last_host_deadline(), 13);

        assert_eq!(task_group.take_pending_timer_ticks(), 2);
        assert!(!task_group.has_pending_timer_ticks());
        assert!(!task_group.needs_resched());
        assert_eq!(task_group.pending_timer_ticks(), 0);
        assert_eq!(task_group.delivered_timer_ticks(), 2);
    }

    #[ktest]
    fn reset_accounting_clears_timer_state() {
        let task_group = FrameTaskGroup::new(FrameTaskGroupId::new(0, 0));
        task_group.record_schedule_in(false);
        task_group.record_runtime_cycles(10, 20, false);
        task_group.inject_timer_tick_at(30);

        task_group.reset_accounting();
        let snapshot = task_group.snapshot();

        assert_eq!(snapshot.schedule_count(), 0);
        assert_eq!(snapshot.runtime_cycles(), 0);
        assert_eq!(snapshot.service_schedule_count(), 0);
        assert_eq!(snapshot.service_runtime_cycles(), 0);
        assert_eq!(snapshot.iht_schedule_count(), 0);
        assert_eq!(snapshot.iht_runtime_cycles(), 0);
        assert_eq!(snapshot.pending_timer_ticks(), 0);
        assert_eq!(snapshot.delivered_timer_ticks(), 0);
        assert_eq!(snapshot.last_host_deadline(), 0);
        assert!(!snapshot.needs_resched());
    }

    #[ktest]
    fn timer_work_tracks_scheduler_ticks() {
        let task_group = FrameTaskGroup::new(FrameTaskGroupId::new(0, 0));

        task_group.inject_timer_tick_at(40);

        assert!(task_group.has_pending_timer_ticks());
        assert!(task_group.has_pending_timer_work());
        assert!(task_group.needs_resched());
        assert_eq!(task_group.pending_timer_ticks(), 1);
        assert_eq!(task_group.take_pending_timer_ticks(), 1);
        assert!(!task_group.has_pending_timer_work());
    }
}
