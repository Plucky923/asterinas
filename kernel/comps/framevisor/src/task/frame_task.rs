// SPDX-License-Identifier: MPL-2.0

//! FrameVM task binding metadata.

use alloc::sync::{Arc, Weak};

use crate::vm::FrameSchedGroup;

/// FrameVM host task kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameTaskKind {
    Service,
    Iht,
}

/// Task-local metadata for FrameVM service and IHT host tasks.
pub struct FrameTaskData {
    group: Weak<FrameSchedGroup>,
    vcpu_index: usize,
    kind: FrameTaskKind,
}

impl FrameTaskData {
    /// Creates FrameVM task metadata.
    pub fn new(group: &Arc<FrameSchedGroup>, kind: FrameTaskKind) -> Self {
        Self {
            group: Arc::downgrade(group),
            vcpu_index: group.vcpu_index(),
            kind,
        }
    }

    /// Returns the FrameVM task kind.
    pub const fn kind(&self) -> FrameTaskKind {
        self.kind
    }

    /// Returns the immutable vCPU index.
    pub const fn vcpu_index(&self) -> usize {
        self.vcpu_index
    }

    /// Upgrades and returns the owning FrameSchedGroup when it is still alive.
    pub fn group(&self) -> Option<Arc<FrameSchedGroup>> {
        self.group.upgrade()
    }
}
