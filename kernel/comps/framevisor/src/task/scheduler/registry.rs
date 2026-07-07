// SPDX-License-Identifier: MPL-2.0

//! Per-FrameVM scheduler registry.

use super::Scheduler;
use crate::{
    task::{self, Task},
    vm::{self, VmId},
};

/// Injects a task scheduler.
pub fn inject_scheduler(scheduler: &'static dyn Scheduler<Task>) {
    let vm_id = current_vm_id().expect("scheduler injection requires a current task context");
    let vm = vm::get_vm_by_id(vm_id).expect("scheduler injection requires an owning FrameVM");
    assert!(
        vm.install_scheduler(scheduler),
        "a scheduler has already been initialized"
    );
}

pub(crate) fn clear_scheduler() {
    if let Some(vm_id) = current_vm_id() {
        clear_scheduler_for_vm(vm_id);
        return;
    }

    for vm_id in vm::list_vms() {
        clear_scheduler_for_vm(vm_id);
    }
}

pub(crate) fn clear_scheduler_for_vm(vm_id: VmId) {
    if let Some(vm) = vm::get_vm_by_id(vm_id) {
        vm.clear_scheduler();
    }
}

pub(crate) fn scheduler_for_vm(vm_id: VmId) -> Option<&'static dyn Scheduler<Task>> {
    vm::get_vm_by_id(vm_id).and_then(|vm| vm.scheduler())
}

pub(crate) fn scheduler_for_current_vm() -> Option<&'static dyn Scheduler<Task>> {
    scheduler_for_vm(current_vm_id()?)
}

fn current_vm_id() -> Option<VmId> {
    task::current_frame_vcpu_id().map(|frame_vcpu_id| frame_vcpu_id.vm_id())
}
