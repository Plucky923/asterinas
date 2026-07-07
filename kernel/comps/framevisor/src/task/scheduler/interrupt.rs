// SPDX-License-Identifier: MPL-2.0

//! Virtual-interrupt scheduler bridge.

use alloc::sync::Arc;

use crate::{iht, task, vm::FrameVcpuId};

#[derive(Clone, Copy, Debug)]
pub(crate) struct VirtualInterruptToken {
    frame_vcpu_id: FrameVcpuId,
}

impl VirtualInterruptToken {
    fn new(frame_vcpu_id: FrameVcpuId) -> Self {
        Self { frame_vcpu_id }
    }
}

/// Returns whether a host-backed local runqueue has pending scheduler work.
pub(crate) fn frame_vcpu_needs_resched(frame_vcpu_id: FrameVcpuId) -> bool {
    iht::has_pending_work(frame_vcpu_id)
}

/// Returns whether local interrupts are enabled for a host-backed runqueue.
pub(crate) fn frame_vcpu_virtual_interrupts_enabled(frame_vcpu_id: FrameVcpuId) -> bool {
    iht::virtual_interrupts_enabled(frame_vcpu_id)
}

pub(crate) fn frame_vcpu_current_ostd_task(
    frame_vcpu_id: FrameVcpuId,
) -> Option<Arc<host_ostd::task::Task>> {
    let current = host_ostd::task::Task::current()?.cloned();
    (task::frame_vcpu_id_for_task(&current) == Some(frame_vcpu_id)).then_some(current)
}

pub(crate) fn enter_virtual_interrupt_disabled_section() -> Option<VirtualInterruptToken> {
    let frame_vcpu_id = task::current_frame_vcpu_for_virtual_interrupt()?;
    iht::disable_virtual_interrupts(frame_vcpu_id);
    Some(VirtualInterruptToken::new(frame_vcpu_id))
}

pub(crate) fn exit_virtual_interrupt_disabled_section(token: VirtualInterruptToken) {
    iht::enable_virtual_interrupts(token.frame_vcpu_id);
}
