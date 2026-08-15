// SPDX-License-Identifier: MPL-2.0

//! Virtual CPU (vCPU) for FrameVM.
//!
//! A vCPU aggregates its interrupt handler, timer callbacks, and scheduling state.

use alloc::{sync::Arc, vec::Vec};

use host_ostd::{cpu::CpuId, sync::SpinLock};

use crate::{
    irq::{self, InterruptHandler},
    vm::{FrameSchedGroup, FrameVcpuId},
};

/// Single vCPU resource container.
pub struct Vcpu {
    /// vCPU ID
    id: usize,
    /// Per-vCPU interrupt delivery state.
    interrupt_handler: Arc<InterruptHandler>,
    /// Function-pointer callbacks owned by this FrameVM vCPU.
    timer_callbacks: SpinLock<Vec<fn()>>,
    /// Host scheduler entity for this vCPU.
    sched_group: Arc<FrameSchedGroup>,
}

impl Vcpu {
    /// Create a new vCPU instance.
    pub(crate) fn new(frame_vcpu_id: FrameVcpuId, share: u32) -> Self {
        let interrupt_handler = Arc::new(InterruptHandler::new(frame_vcpu_id));
        let sched_group = Arc::new(FrameSchedGroup::new(
            frame_vcpu_id,
            share,
            CpuId::bsp(),
            interrupt_handler.clone(),
        ));
        interrupt_handler.bind_group(&sched_group);
        Self {
            id: frame_vcpu_id.vcpu_index(),
            interrupt_handler,
            timer_callbacks: SpinLock::new(Vec::new()),
            sched_group,
        }
    }

    /// Get vCPU ID.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns this vCPU's interrupt handler.
    pub fn interrupt_handler(&self) -> &Arc<InterruptHandler> {
        &self.interrupt_handler
    }

    /// Get host scheduler entity.
    pub fn sched_group(&self) -> &Arc<FrameSchedGroup> {
        &self.sched_group
    }

    /// Registers a function-pointer timer callback for this vCPU.
    pub(crate) fn register_timer_callback(&self, callback: fn()) {
        self.timer_callbacks.lock().push(callback);
    }

    /// Dispatches this vCPU's timer callbacks for the given number of ticks.
    pub(crate) fn dispatch_timer_callbacks(&self, ticks: u64) {
        if ticks == 0 {
            return;
        }

        let callbacks = self.timer_callbacks.lock().clone();
        for _ in 0..ticks {
            irq::enter_timer_interrupt(|| {
                for callback in &callbacks {
                    callback();
                }
            });
        }
    }

    /// Clears timer callbacks after the VM has reached its quiescence boundary.
    pub(crate) fn clear_timer_callbacks(&self) {
        self.timer_callbacks.lock().clear();
    }
}
