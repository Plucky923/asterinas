// SPDX-License-Identifier: MPL-2.0

//! FrameVM software IRQ routing for FrameV devices.

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use framev_device::{FrameVDeviceInfo, IrqLine};
use host_ostd::sync::SpinLock;

/// An error returned by FrameVM IRQ routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVmIrqRoutingError {
    DeviceNotFound,
    NoEligibleVcpu,
    StaleIrqRequest,
}

/// Runtime load visible to FrameVM IRQ routing for one vCPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VcpuIrqLoad {
    pub online: bool,
    pub runnable: bool,
    pub virtual_interrupts_enabled: bool,
    pub pending_work: usize,
}

/// A route for one FrameV software IRQ line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameVmIrqRoute {
    pub irq_line: IrqLine,
    pub affinity: Vec<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingIrq {
    coalesced_events: u64,
}

/// A routed FrameV IRQ notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVmIrqNotification {
    pub irq_line: IrqLine,
    pub target_vcpu: usize,
    pub coalesced: bool,
}

/// Per-FrameVM software IRQ routing state.
pub struct FrameVmIrqRouting {
    routes: BTreeMap<IrqLine, FrameVmIrqRoute>,
    pending_by_target: SpinLock<BTreeMap<(IrqLine, usize), PendingIrq>>,
    round_robin_cursor: AtomicUsize,
}

impl FrameVmIrqRouting {
    /// Creates IRQ routing from stable FrameV device metadata.
    pub fn new(devices: &[FrameVDeviceInfo], vcpu_count: usize) -> Result<Self> {
        if vcpu_count == 0 {
            return Err(FrameVmIrqRoutingError::NoEligibleVcpu);
        }

        let affinity = (0..vcpu_count).collect::<Vec<_>>();
        let routes = devices
            .iter()
            .map(|device| {
                (
                    device.irq_line,
                    FrameVmIrqRoute {
                        irq_line: device.irq_line,
                        affinity: affinity.clone(),
                    },
                )
            })
            .collect();

        Ok(Self {
            routes,
            pending_by_target: SpinLock::new(BTreeMap::new()),
            round_robin_cursor: AtomicUsize::new(0),
        })
    }

    /// Routes a FrameV IRQ line notification to a specific vCPU.
    pub(crate) fn notify_irq_line_on_vcpu(
        &self,
        irq_line: IrqLine,
        target_vcpu: usize,
        load_of: impl Fn(usize) -> Option<VcpuIrqLoad>,
    ) -> Result<FrameVmIrqNotification> {
        {
            let mut pending_by_target = self.pending_by_target.lock();
            if let Some(pending) = pending_by_target.get_mut(&(irq_line, target_vcpu)) {
                pending.coalesced_events = pending.coalesced_events.saturating_add(1);
                return Ok(FrameVmIrqNotification {
                    irq_line,
                    target_vcpu,
                    coalesced: true,
                });
            }
        }

        let route = self
            .routes
            .get(&irq_line)
            .ok_or(FrameVmIrqRoutingError::DeviceNotFound)?;
        if !route.affinity.contains(&target_vcpu) {
            return Err(FrameVmIrqRoutingError::NoEligibleVcpu);
        }
        let load = load_of(target_vcpu).ok_or(FrameVmIrqRoutingError::NoEligibleVcpu)?;
        if !load.online {
            return Err(FrameVmIrqRoutingError::NoEligibleVcpu);
        }

        self.pending_by_target.lock().insert(
            (irq_line, target_vcpu),
            PendingIrq {
                coalesced_events: 0,
            },
        );

        Ok(FrameVmIrqNotification {
            irq_line,
            target_vcpu,
            coalesced: false,
        })
    }

    /// Routes a FrameV IRQ line notification.
    pub(crate) fn notify_irq_line(
        &self,
        irq_line: IrqLine,
        load_of: impl Fn(usize) -> Option<VcpuIrqLoad>,
    ) -> Result<FrameVmIrqNotification> {
        {
            let mut pending_by_target = self.pending_by_target.lock();
            if let Some((&(_, target_vcpu), pending)) = pending_by_target
                .iter_mut()
                .find(|((pending_line, _), _)| *pending_line == irq_line)
            {
                pending.coalesced_events = pending.coalesced_events.saturating_add(1);
                return Ok(FrameVmIrqNotification {
                    irq_line,
                    target_vcpu,
                    coalesced: true,
                });
            }
        }

        let route = self
            .routes
            .get(&irq_line)
            .ok_or(FrameVmIrqRoutingError::DeviceNotFound)?;
        let target_vcpu = self.select_target(route, load_of)?;

        self.pending_by_target.lock().insert(
            (irq_line, target_vcpu),
            PendingIrq {
                coalesced_events: 0,
            },
        );

        Ok(FrameVmIrqNotification {
            irq_line,
            target_vcpu,
            coalesced: false,
        })
    }

    /// Clears pending state for a routed IRQ request.
    pub(crate) fn clear_pending(
        &self,
        irq_line: IrqLine,
        expected_target_vcpu: usize,
    ) -> Result<()> {
        if self
            .pending_by_target
            .lock()
            .remove(&(irq_line, expected_target_vcpu))
            .is_none()
        {
            return Err(FrameVmIrqRoutingError::StaleIrqRequest);
        }

        Ok(())
    }

    #[cfg(ktest)]
    pub(crate) fn is_pending(&self, irq_line: IrqLine) -> bool {
        self.pending_by_target
            .lock()
            .keys()
            .any(|(pending_line, _)| *pending_line == irq_line)
    }

    /// Returns whether an IRQ line is pending for a target vCPU.
    #[cfg(ktest)]
    pub(crate) fn is_pending_on_vcpu(&self, irq_line: IrqLine, target_vcpu: usize) -> bool {
        self.pending_by_target
            .lock()
            .contains_key(&(irq_line, target_vcpu))
    }

    /// Clears all pending routing state for the owning VM.
    pub(crate) fn clear_pending_all(&self) {
        self.pending_by_target.lock().clear();
    }

    fn select_target(
        &self,
        route: &FrameVmIrqRoute,
        load_of: impl Fn(usize) -> Option<VcpuIrqLoad>,
    ) -> Result<usize> {
        self.select_lowest_pending(route, load_of)
    }

    fn select_lowest_pending(
        &self,
        route: &FrameVmIrqRoute,
        load_of: impl Fn(usize) -> Option<VcpuIrqLoad>,
    ) -> Result<usize> {
        let mut candidates = Vec::new();
        for vcpu_id in &route.affinity {
            let Some(load) = load_of(*vcpu_id) else {
                continue;
            };
            if load.online {
                candidates.push((*vcpu_id, load));
            }
        }

        if candidates.is_empty() {
            return Err(FrameVmIrqRoutingError::NoEligibleVcpu);
        }

        if candidates.iter().any(|(_, load)| load.runnable) {
            candidates.retain(|(_, load)| load.runnable);
        }

        if candidates
            .iter()
            .any(|(_, load)| load.virtual_interrupts_enabled)
        {
            candidates.retain(|(_, load)| load.virtual_interrupts_enabled);
        }

        let lowest_pending = candidates
            .iter()
            .map(|(_, load)| load.pending_work)
            .min()
            .ok_or(FrameVmIrqRoutingError::NoEligibleVcpu)?;
        candidates.retain(|(_, load)| load.pending_work == lowest_pending);

        let cursor = self.round_robin_cursor.fetch_add(1, Ordering::AcqRel);
        Ok(candidates[cursor % candidates.len()].0)
    }
}

type Result<T> = core::result::Result<T, FrameVmIrqRoutingError>;

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;
    fn default_devices() -> Vec<FrameVDeviceInfo> {
        alloc::vec![
            framev_console_common::default_device_info(),
            framev_sock_common::default_device_info(),
            framev_rng_common::default_device_info(),
        ]
    }

    fn runnable_load(_: usize) -> Option<VcpuIrqLoad> {
        Some(VcpuIrqLoad {
            online: true,
            runnable: true,
            virtual_interrupts_enabled: true,
            pending_work: 0,
        })
    }

    fn sleeping_online_load(_: usize) -> Option<VcpuIrqLoad> {
        Some(VcpuIrqLoad {
            online: true,
            runnable: false,
            virtual_interrupts_enabled: true,
            pending_work: 0,
        })
    }

    #[ktest]
    fn pending_irqs_are_scoped_to_one_routing_table() {
        let devices = default_devices();
        let first_vm_routing = FrameVmIrqRouting::new(&devices, 1).unwrap();
        let second_vm_routing = FrameVmIrqRouting::new(&devices, 1).unwrap();

        let notification = first_vm_routing
            .notify_irq_line(
                framev_console_common::default_device_info().irq_line,
                runnable_load,
            )
            .unwrap();

        assert!(first_vm_routing.is_pending(notification.irq_line));
        assert!(!second_vm_routing.is_pending(notification.irq_line));
    }

    #[ktest]
    fn clear_pending_all_removes_vm_scoped_routing_state() {
        let devices = default_devices();
        let routing = FrameVmIrqRouting::new(&devices, 1).unwrap();
        let notification = routing
            .notify_irq_line(
                framev_console_common::default_device_info().irq_line,
                runnable_load,
            )
            .unwrap();

        assert!(routing.is_pending(notification.irq_line));
        routing.clear_pending_all();
        assert!(!routing.is_pending(notification.irq_line));
        assert_eq!(
            routing.clear_pending(notification.irq_line, notification.target_vcpu),
            Err(FrameVmIrqRoutingError::StaleIrqRequest)
        );
    }

    #[ktest]
    fn targeted_device_notification_uses_requested_vcpu() {
        let devices = default_devices();
        let routing = FrameVmIrqRouting::new(&devices, 2).unwrap();
        let notification = routing
            .notify_irq_line_on_vcpu(
                framev_console_common::default_device_info().irq_line,
                1,
                runnable_load,
            )
            .unwrap();

        assert_eq!(notification.target_vcpu, 1);
        assert!(!notification.coalesced);
        assert!(routing.is_pending(notification.irq_line));
    }

    #[ktest]
    fn targeted_device_notifications_are_scoped_by_vcpu() {
        let devices = default_devices();
        let routing = FrameVmIrqRouting::new(&devices, 2).unwrap();
        let first_notification = routing
            .notify_irq_line_on_vcpu(
                framev_console_common::default_device_info().irq_line,
                0,
                runnable_load,
            )
            .unwrap();
        let second_notification = routing
            .notify_irq_line_on_vcpu(
                framev_console_common::default_device_info().irq_line,
                1,
                runnable_load,
            )
            .unwrap();

        assert!(!first_notification.coalesced);
        assert!(!second_notification.coalesced);
        assert!(routing.is_pending_on_vcpu(first_notification.irq_line, 0));
        assert!(routing.is_pending_on_vcpu(second_notification.irq_line, 1));
    }

    #[ktest]
    fn targeted_device_notification_rejects_unknown_vcpu() {
        let devices = default_devices();
        let routing = FrameVmIrqRouting::new(&devices, 1).unwrap();

        assert_eq!(
            routing.notify_irq_line_on_vcpu(
                framev_console_common::default_device_info().irq_line,
                1,
                runnable_load
            ),
            Err(FrameVmIrqRoutingError::NoEligibleVcpu)
        );
    }

    #[ktest]
    fn targeted_irq_can_wake_sleeping_online_vcpu() {
        let devices = default_devices();
        let routing = FrameVmIrqRouting::new(&devices, 1).unwrap();
        let irq_line = framev_sock_common::default_device_info().irq_line;

        let notification = routing
            .notify_irq_line_on_vcpu(irq_line, 0, sleeping_online_load)
            .unwrap();

        assert_eq!(notification.target_vcpu, 0);
        assert!(!notification.coalesced);
        assert!(routing.is_pending_on_vcpu(irq_line, 0));
    }

    #[ktest]
    fn untargeted_irq_can_wake_sleeping_online_vcpu() {
        let devices = default_devices();
        let routing = FrameVmIrqRouting::new(&devices, 1).unwrap();
        let irq_line = framev_console_common::default_device_info().irq_line;

        let notification = routing
            .notify_irq_line(irq_line, sleeping_online_load)
            .unwrap();

        assert_eq!(notification.target_vcpu, 0);
        assert!(!notification.coalesced);
        assert!(routing.is_pending_on_vcpu(irq_line, 0));
    }

    #[ktest]
    fn repeated_notification_is_coalesced_until_cleared() {
        let devices = default_devices();
        let routing = FrameVmIrqRouting::new(&devices, 1).unwrap();
        let irq_line = framev_console_common::default_device_info().irq_line;

        let first_notification = routing.notify_irq_line(irq_line, runnable_load).unwrap();
        let second_notification = routing.notify_irq_line(irq_line, runnable_load).unwrap();

        assert!(!first_notification.coalesced);
        assert!(second_notification.coalesced);
        assert_eq!(
            second_notification.target_vcpu,
            first_notification.target_vcpu
        );
        assert!(routing.is_pending_on_vcpu(irq_line, first_notification.target_vcpu));

        routing
            .clear_pending(irq_line, first_notification.target_vcpu)
            .unwrap();
        let third_notification = routing.notify_irq_line(irq_line, runnable_load).unwrap();
        assert!(!third_notification.coalesced);
    }
}
