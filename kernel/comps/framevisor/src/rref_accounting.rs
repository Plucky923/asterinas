// SPDX-License-Identifier: MPL-2.0

//! FrameVM accounting for shared exchange payloads.

use alloc::sync::Arc;

use aster_framevisor_exchangeable::{RRefAccounting, VmId};

use crate::{sync::Once, task, vm};

/// The only FrameVisor state exposed to the exchange layer.
struct FrameVmRRefAccounting;

impl RRefAccounting for FrameVmRRefAccounting {
    fn reserve(&self, owner: VmId, bytes: usize) -> bool {
        let Some(domain) = memory_domain(owner) else {
            return owner.is_host() || cfg!(ktest);
        };
        domain
            .reserve_rref(bytes)
            .and_then(|reservation| reservation.commit())
            .is_ok()
    }

    fn transfer(&self, source: VmId, target: VmId, bytes: usize) -> bool {
        if source == target {
            return true;
        }

        let target_domain = memory_domain(target);
        if let Some(domain) = &target_domain {
            if domain
                .reserve_rref(bytes)
                .and_then(|reservation| reservation.commit())
                .is_err()
            {
                return false;
            }
        } else if !target.is_host() && !cfg!(ktest) {
            return false;
        }

        let source_domain = memory_domain(source);
        if let Some(domain) = &source_domain {
            if domain.release_rref(bytes).is_err() {
                if let Some(target_domain) = &target_domain {
                    let _ = target_domain.release_rref(bytes);
                }
                return false;
            }
        } else if !source.is_host() && !cfg!(ktest) {
            if let Some(target_domain) = &target_domain {
                let _ = target_domain.release_rref(bytes);
            }
            return false;
        }

        true
    }

    fn release(&self, owner: VmId, bytes: usize) {
        let Some(domain) = memory_domain(owner) else {
            return;
        };
        if domain.release_rref(bytes).is_err() {
            ::log::error!("[framevisor] failed to release shared exchange charge");
        }
    }
}

fn memory_domain(owner: VmId) -> Option<vm::MemoryDomain> {
    owner
        .guest_id()
        .and_then(|_| vm::get_vm_by_id(owner))
        .map(|frame_vm| frame_vm.memory().clone())
}

static ACCOUNTING: Once<Arc<FrameVmRRefAccounting>> = Once::new();

/// Installs shared-payload accounting and the current VM context provider.
pub fn init() {
    let accounting = ACCOUNTING.call_once(|| Arc::new(FrameVmRRefAccounting));
    aster_framevisor_exchangeable::install_accounting(accounting.clone());
    aster_framevisor_exchangeable::init_current_vm_provider(current_vm);
}

fn current_vm() -> VmId {
    task::current_frame_vcpu_id()
        .map(|frame_vcpu_id| frame_vcpu_id.vm_id())
        .unwrap_or(VmId::Host)
}
