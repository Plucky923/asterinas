// SPDX-License-Identifier: MPL-2.0
use aster_util::per_cpu_counter::PerCpuCounter;
use ostd::{
    cpu::{CpuId, PrivilegeLevel},
    irq::InterruptLevel,
    timer::Jiffies,
};
use spin::Once;

use crate::{prelude::*, sched::SchedPolicy, thread::Thread};

/// Represents CPU usage statistics for a system.
///
/// This structure contains various counters that track different types of CPU time.
/// All values are measured in jiffies (clock ticks).
///
/// TODO: Implement proper accounting for CPU time
#[derive(Clone, Copy, Debug)]
pub struct CpuTimeStats {
    /// Time spent in user mode.
    pub user: Jiffies,
    /// Time spent in user mode with low priority (nice).
    pub nice: Jiffies,
    /// Time spent in system/kernel mode.
    pub system: Jiffies,
    /// Time spent in the idle task.
    pub idle: Jiffies,
    /// Time spent waiting for I/O to complete.
    /// TODO: track this statistic.
    pub iowait: Jiffies,
    /// Time spent servicing hardware interrupts.
    pub irq: Jiffies,
    /// Time spent servicing software interrupts.
    pub softirq: Jiffies,
    /// Time stolen by other operating systems running in a virtualized environment.
    /// TODO: track this statistic.
    pub steal: Jiffies,
    /// Time spent running a virtual CPU for guest operating systems.
    /// TODO: track this statistic.
    pub guest: Jiffies,
    /// Time spent running a low priority virtual CPU for guest operating systems.
    /// TODO: track this statistic.
    pub guest_nice: Jiffies,
}

pub struct CpuTimeStatsManager {
    user: PerCpuCounter,
    nice: PerCpuCounter,
    system: PerCpuCounter,
    idle: PerCpuCounter,
    iowait: PerCpuCounter,
    irq: PerCpuCounter,
    softirq: PerCpuCounter,
    steal: PerCpuCounter,
    guest: PerCpuCounter,
    guest_nice: PerCpuCounter,
}

static SINGLETON: Once<CpuTimeStatsManager> = Once::new();

impl CpuTimeStatsManager {
    /// Returns the singleton instance after time statistics initialization.
    pub fn singleton() -> Option<&'static CpuTimeStatsManager> {
        SINGLETON.get()
    }

    /// Collects the time statistics on the specific CPU.
    ///
    /// Returns `None` when the CPU index is not a vCPU slot in this manager.
    pub fn collect_stats_on_cpu(&self, cpu: CpuId) -> Option<CpuTimeStats> {
        let vcpu_index = cpu.as_usize();
        let get = |counter: &PerCpuCounter| {
            counter
                .get_on_cpu(vcpu_index)
                .map(|value| Jiffies::new(value as u64))
        };

        Some(CpuTimeStats {
            user: get(&self.user)?,
            nice: get(&self.nice)?,
            system: get(&self.system)?,
            idle: get(&self.idle)?,
            iowait: get(&self.iowait)?,
            irq: get(&self.irq)?,
            softirq: get(&self.softirq)?,
            steal: get(&self.steal)?,
            guest: get(&self.guest)?,
            guest_nice: get(&self.guest_nice)?,
        })
    }

    /// Collects the time statistics across all CPUs.
    pub fn collect_stats_on_all_cpus(&self) -> CpuTimeStats {
        CpuTimeStats {
            user: Jiffies::new(self.user.sum_all_cpus() as u64),
            nice: Jiffies::new(self.nice.sum_all_cpus() as u64),
            system: Jiffies::new(self.system.sum_all_cpus() as u64),
            idle: Jiffies::new(self.idle.sum_all_cpus() as u64),
            iowait: Jiffies::new(self.iowait.sum_all_cpus() as u64),
            irq: Jiffies::new(self.irq.sum_all_cpus() as u64),
            softirq: Jiffies::new(self.softirq.sum_all_cpus() as u64),
            steal: Jiffies::new(self.steal.sum_all_cpus() as u64),
            guest: Jiffies::new(self.guest.sum_all_cpus() as u64),
            guest_nice: Jiffies::new(self.guest_nice.sum_all_cpus() as u64),
        }
    }

    fn inc_user_time(&self, vcpu_index: usize) -> bool {
        self.user.add_on_cpu(vcpu_index, 1).is_some()
    }

    fn inc_system_time(&self, vcpu_index: usize) -> bool {
        self.system.add_on_cpu(vcpu_index, 1).is_some()
    }

    fn inc_idle_time(&self, vcpu_index: usize) -> bool {
        self.idle.add_on_cpu(vcpu_index, 1).is_some()
    }

    fn new() -> Result<Self> {
        fn new_counter() -> Result<PerCpuCounter> {
            Ok(PerCpuCounter::new()?)
        }

        Ok(Self {
            user: new_counter()?,
            nice: new_counter()?,
            system: new_counter()?,
            idle: new_counter()?,
            iowait: new_counter()?,
            irq: new_counter()?,
            softirq: new_counter()?,
            steal: new_counter()?,
            guest: new_counter()?,
            guest_nice: new_counter()?,
        })
    }
}

fn update_cpu_statistics() {
    let Some(manager) = SINGLETON.get() else {
        return;
    };

    // Timer callbacks can also run while the service context is being
    // established. Statistics are best effort, so do not turn a missing or
    // stale FrameVM vCPU identity into an IRQ-time panic.
    let Some(vcpu_index) = ostd::task::current_cpu_index() else {
        return;
    };

    let recorded = match InterruptLevel::current() {
        // The kernel code is interrupted.
        InterruptLevel::L1(PrivilegeLevel::Kernel) => {
            if is_idle() {
                // Idle time is not counted towards CPU usage.
                manager.inc_idle_time(vcpu_index)
            } else {
                // Non-idle time is counted as kernel time.
                manager.inc_system_time(vcpu_index)
            }
        }
        // The user code is interrupted.
        InterruptLevel::L1(PrivilegeLevel::User) => manager.inc_user_time(vcpu_index),
        // The interrupt code is interrupted.
        InterruptLevel::L2 => manager.inc_system_time(vcpu_index),

        // We're handling timer interrupts, so this is unreachable.
        InterruptLevel::L0 => unreachable!("interrupts must not run in the task context"),
    };

    if !recorded {
        ostd::warn!("dropping CPU statistics for an invalid FrameVM vCPU index");
    }
}

fn is_idle() -> bool {
    if let Some(current_thread) = Thread::current() {
        current_thread.sched_attr().policy() == SchedPolicy::Idle
    } else {
        false
    }
}

pub fn init() -> Result<()> {
    let manager = CpuTimeStatsManager::new()?;
    SINGLETON.call_once(|| manager);
    Ok(())
}

pub fn init_on_each_cpu() {
    ostd::timer::register_callback_on_cpu(update_cpu_statistics);
}
