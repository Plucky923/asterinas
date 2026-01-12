// SPDX-License-Identifier: MPL-2.0

//! Per-VM vsock active state tracking.

use alloc::collections::BTreeSet;

use ostd::sync::RwLock;
use spin::Once;

use crate::vm::VmId;

// ============================================================================
// Guest Vsock Active State (Per-VM)
// ============================================================================

/// Set of active VM IDs with vsock initialized.
static ACTIVE_VMS: Once<RwLock<BTreeSet<VmId>>> = Once::new();

fn get_active_vms() -> &'static RwLock<BTreeSet<VmId>> {
    ACTIVE_VMS.call_once(|| RwLock::new(BTreeSet::new()))
}

/// Set vsock active state for a specific VM.
///
/// Called by the Frontend Driver when vsock is initialized/shutdown.
pub fn set_vm_active(vm_id: VmId, active: bool) {
    let mut set = get_active_vms().write();
    if active {
        set.insert(vm_id);
    } else {
        set.remove(&vm_id);
    }
}

/// Check if a specific VM has active vsock.
#[inline]
pub fn is_vm_active(vm_id: VmId) -> bool {
    get_active_vms().read().contains(&vm_id)
}

/// Set vsock active state for VM 0 (backward compatible).
pub fn set_guest_active(active: bool) {
    set_vm_active(0, active);
}

/// Check if any VM has active vsock (backward compatible).
#[inline]
pub fn is_guest_active() -> bool {
    !get_active_vms().read().is_empty()
}

/// Get list of all active VM IDs.
pub fn get_active_vm_ids() -> alloc::vec::Vec<VmId> {
    get_active_vms().read().iter().copied().collect()
}

/// Get count of active VMs.
pub fn active_vm_count() -> usize {
    get_active_vms().read().len()
}
