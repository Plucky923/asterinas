// SPDX-License-Identifier: MPL-2.0

//! Virtual CPU (vCPU) for FrameVM.
//!
//! A vCPU aggregates per-CPU resources like IHT context and scheduling state.

use alloc::sync::Arc;

use host_ostd::cpu::CpuId;

use crate::{
    iht::IhtContext,
    vm::{FrameSchedGroup, FrameVcpuId},
};

/// Single vCPU resource container.
pub struct Vcpu {
    /// vCPU ID
    id: usize,
    /// IHT context for interrupt handling
    iht_context: Arc<IhtContext>,
    /// Host scheduler entity for this vCPU.
    sched_group: Arc<FrameSchedGroup>,
}

impl Vcpu {
    /// Create a new vCPU instance.
    pub fn new(frame_vcpu_id: FrameVcpuId, share: u32) -> Self {
        let iht_context = Arc::new(IhtContext::new(frame_vcpu_id));
        let sched_group = Arc::new(FrameSchedGroup::new(
            frame_vcpu_id,
            share,
            CpuId::bsp(),
            iht_context.clone(),
        ));
        iht_context.bind_group(&sched_group);
        Self {
            id: frame_vcpu_id.vcpu_index(),
            iht_context,
            sched_group,
        }
    }

    /// Get vCPU ID.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get IHT context.
    pub fn iht(&self) -> &Arc<IhtContext> {
        &self.iht_context
    }

    /// Get host scheduler entity.
    pub fn sched_group(&self) -> &Arc<FrameSchedGroup> {
        &self.sched_group
    }
}
