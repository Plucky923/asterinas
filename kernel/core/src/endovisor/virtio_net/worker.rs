// SPDX-License-Identifier: MPL-2.0

//! Owns the adopted Host task and NAT backend for either frame transport.

use ostd::kernelet::control::Kernelet;

#[cfg(kernelet_nat_failure_diag_host)]
use super::endpoint;
use super::{NetEndpoint, VirtioNet, Work};
use crate::{endovisor::shared_net::SharedNetTransport, prelude::*};

enum Transport {
    Copy(Arc<VirtioNet>),
    Shared(Arc<SharedNetTransport>),
}

pub(in crate::endovisor) struct NetWorker {
    pub(super) kernelet: Arc<Kernelet>,
    pub(super) endpoint: Arc<NetEndpoint>,
    pub(super) mac: [u8; 6],
    transport: Transport,
}

impl NetWorker {
    pub(super) fn for_copy(device: Arc<VirtioNet>) -> Self {
        Self {
            kernelet: device.kernelet.clone(),
            endpoint: device.endpoint.clone(),
            mac: device.mac,
            transport: Transport::Copy(device),
        }
    }

    pub(in crate::endovisor) fn for_shared(
        kernelet: Arc<Kernelet>,
        endpoint: Arc<NetEndpoint>,
        mac: [u8; 6],
        transport: Arc<SharedNetTransport>,
    ) -> Self {
        Self {
            kernelet,
            endpoint,
            mac,
            transport: Transport::Shared(transport),
        }
    }

    pub(super) fn shared_transport(&self) -> Option<&Arc<SharedNetTransport>> {
        match &self.transport {
            Transport::Copy(_) => None,
            Transport::Shared(transport) => Some(transport),
        }
    }

    pub(super) fn take_work(&self) -> Option<Work> {
        match &self.transport {
            Transport::Copy(device) => device.take_work(),
            Transport::Shared(transport) => transport.take_work(),
        }
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn diagnostic_cancelled(&self) -> bool {
        match &self.transport {
            Transport::Copy(device) => device.registers.lock().cancelled,
            Transport::Shared(transport) => transport.is_cancelled(),
        }
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn record_diagnostic(
        &self,
        event: endpoint::NatEvent,
        context: endpoint::NatContext,
        errno: Option<Errno>,
    ) {
        let cancelled = self.diagnostic_cancelled();
        self.endpoint
            .record_diagnostic(event, context, errno, None, 0, None, cancelled);
    }

    pub(in crate::endovisor) fn run(&self) {
        let adopted = self.kernelet.adopt_current_task();
        if adopted.is_err() {
            #[cfg(kernelet_nat_failure_diag_host)]
            {
                self.endpoint.record_diagnostic(
                    endpoint::NatEvent::Adopt,
                    endpoint::NatContext::new("worker_adopt_failed"),
                    None,
                    adopted.err(),
                    0,
                    None,
                    self.diagnostic_cancelled(),
                );
                self.endpoint.emit_diagnostic_summary();
            }
            return;
        }
        if let Some((backend, reservation)) = self.endpoint.take_backend() {
            // Native listener observers retain the shared reservation until
            // the last backlog reference releases its buffers.
            let result = backend.run(self);
            #[cfg(kernelet_nat_failure_diag_host)]
            self.record_diagnostic(
                endpoint::NatEvent::BackendReturned,
                endpoint::NatContext::new(if result.is_ok() {
                    "backend_returned_ok"
                } else {
                    "backend_returned_error"
                }),
                result.as_ref().err().map(|error| error.error()),
            );
            drop(reservation);
            #[cfg(kernelet_nat_failure_diag_host)]
            {
                self.record_diagnostic(
                    endpoint::NatEvent::ReservationReleased,
                    endpoint::NatContext::new("backend_reservation_drop_returned"),
                    None,
                );
                self.endpoint.emit_diagnostic_summary();
            }
            if let Err(error) = result {
                error!("kernelet network backend failed: {:?}", error);
                let _ = self
                    .kernelet
                    .kill(ostd::kernelet::control::KillReason::HostPolicy(u32::MAX));
            }
        } else {
            #[cfg(kernelet_nat_failure_diag_host)]
            {
                self.record_diagnostic(
                    endpoint::NatEvent::BackendAbsent,
                    endpoint::NatContext::new("worker_take_backend_none"),
                    None,
                );
                self.endpoint.emit_diagnostic_summary();
            }
        }
        self.kernelet.disown_current_task();
    }
}
