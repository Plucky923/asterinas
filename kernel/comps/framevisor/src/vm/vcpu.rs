// SPDX-License-Identifier: MPL-2.0

//! Virtual CPU (vCPU) for FrameVM.
//!
//! A vCPU aggregates per-CPU resources like IHT context and Vsock queues.

use alloc::sync::Arc;

#[cfg(feature = "host-api")]
use crate::vsock::VcpuQueues;
use crate::{
    iht::IhtContext,
    vm::{FrameTaskGroup, FrameTaskGroupId},
};

/// Single vCPU resource container.
pub struct Vcpu {
    /// vCPU ID
    id: usize,
    /// IHT context for interrupt handling
    iht_context: Arc<IhtContext>,
    /// Host-visible scheduling group for this vCPU
    task_group: Arc<FrameTaskGroup>,
    /// Vsock queues for communication
    #[cfg(feature = "host-api")]
    vsock_queues: VcpuQueues,
}

impl Vcpu {
    /// Create a new vCPU instance.
    pub fn new(task_group_id: FrameTaskGroupId) -> Self {
        let task_group = Arc::new(FrameTaskGroup::new(task_group_id));
        Self {
            id: task_group_id.vcpu_id(),
            iht_context: Arc::new(IhtContext::new(task_group_id)),
            task_group,
            #[cfg(feature = "host-api")]
            vsock_queues: VcpuQueues::new(),
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

    /// Get host-visible task group.
    pub fn task_group(&self) -> &Arc<FrameTaskGroup> {
        &self.task_group
    }

    /// Get Vsock queues.
    #[cfg(feature = "host-api")]
    pub fn vsock_queues(&self) -> &VcpuQueues {
        &self.vsock_queues
    }
}
