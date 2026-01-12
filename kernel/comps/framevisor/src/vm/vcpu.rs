// SPDX-License-Identifier: MPL-2.0

//! Virtual CPU (vCPU) for FrameVM.
//!
//! A vCPU aggregates per-CPU resources like IHT context and Vsock queues.

use alloc::sync::Arc;

use crate::{iht::IhtContext, vsock::VcpuQueues};

/// Single vCPU resource container.
pub struct Vcpu {
    /// vCPU ID
    id: usize,
    /// IHT context for interrupt handling
    iht_context: Arc<IhtContext>,
    /// Vsock queues for communication
    vsock_queues: VcpuQueues,
}

impl Vcpu {
    /// Create a new vCPU instance.
    pub fn new(id: usize) -> Self {
        Self {
            id,
            iht_context: Arc::new(IhtContext::new(id)),
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

    /// Get Vsock queues.
    pub fn vsock_queues(&self) -> &VcpuQueues {
        &self.vsock_queues
    }
}
