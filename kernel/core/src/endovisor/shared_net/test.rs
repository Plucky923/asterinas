// SPDX-License-Identifier: MPL-2.0

//! NIC allocation lifetime through real pool transitions and UID admission.

use core::time::Duration;

use ostd::{
    cpu::{CpuId, CpuSet, PinCurrentCpu},
    kernelet::{
        abi::buffer,
        control::{
            CpuBudget, KerneletConfig, KerneletHooks, KerneletKind, KerneletPolicy, KerneletState,
            KillReason,
        },
    },
    prelude::ktest,
    task::{Task, TaskOptions},
};

use super::*;
use crate::{endovisor::policy, process::Uid};

#[ktest]
fn forwarded_nic_buffer_keeps_uid_charge_after_sender_destroy() {
    crate::time::clocks::init_for_ktest();
    crate::endovisor::reaper::init().unwrap();
    let kind = KerneletKind::register_dormant_fixture().unwrap();
    let owner = Uid::new(u32::MAX - 62);
    let peer_owner = Uid::new(u32::MAX - 63);
    let admission = Admission::reserve(owner, 1, 1, 0).unwrap();
    let peer_admission = Admission::reserve(peer_owner, 1, 1, 0).unwrap();
    let sender = instance(&kind);
    let receiver = instance(&kind);
    admission.mark_created();
    peer_admission.mark_created();
    let connection = sender.connect_shared_buffers(&receiver).unwrap();
    let endpoint = NetEndpoint::new(
        owner,
        #[cfg(kernelet_nat_failure_diag_host)]
        0x6f90_0000,
    );
    let nic = SharedNet::new(&admission, sender.clone(), endpoint, [2, 0, 0, 0, 0, 1], 32).unwrap();
    let nic_connection = nic.transport.local.connection();
    assert!(nic.transport.allocate_frame().unwrap().deliver(14));
    assert!(nic.transport.flush_transmit());
    // Use the real Image-side RECEIVE/REDEEM/HANDOFF protocol against OSTD's
    // actual pool. Only carrier execution is omitted by the kernel-test adapter.
    let delivery = sender.test_shared_buffer_service(buffer::RECEIVE, 0, [nic_connection, 0, 0]);
    assert_eq!(delivery.status, 0);
    assert_ne!(delivery.value, 0);
    let mapping = sender.test_shared_buffer_service(buffer::REDEEM, delivery.value, [0; 3]);
    assert!(mapping.status >= 0);
    let forwarded = sender.test_shared_buffer_service(
        buffer::HANDOFF,
        delivery.value,
        [connection, buffer::READ_WRITE, 26],
    );
    assert_eq!(forwarded.status, 0);
    let imported = receiver.test_shared_buffer_service(buffer::RECEIVE, 0, [connection, 0, 0]);
    assert_eq!(imported.status, 0);
    assert_ne!(imported.value, 0);
    assert!(
        receiver
            .test_shared_buffer_service(buffer::REDEEM, imported.value, [0; 3])
            .status
            >= 0
    );
    nic.cancel();
    drop(nic);
    assert_eq!(policy::endpoint_bytes_for_test(owner), CAPACITY * 2);
    destroy(&sender);
    admission.release_after_destroy();
    // The original per-instance reservation incorrectly made this zero.
    assert_eq!(policy::endpoint_bytes_for_test(owner), CAPACITY * 2);
    assert_eq!(
        receiver
            .test_shared_buffer_service(buffer::RELEASE, imported.value, [0; 3])
            .status,
        0
    );
    assert_eq!(policy::endpoint_bytes_for_test(owner), 0);
    destroy(&receiver);
    peer_admission.release_after_destroy();
    assert_eq!(policy::endpoint_bytes_for_test(peer_owner), 0);
}

fn instance(kind: &KerneletKind) -> Arc<Kernelet> {
    let mut cpus = CpuSet::new_empty();
    cpus.add(ostd::irq::disable_local().current_cpu());
    kind.create(
        &KerneletConfig {
            cmdline: "",
            initial_grains: 1,
            max_grains: 1,
            max_meta_sections: 1,
            budget: CpuBudget::default(),
            policy: KerneletPolicy::default(),
            max_tasks: 1,
            devices: &[],
            cpus,
        },
        Arc::new(DormantHooks),
    )
    .unwrap()
}

fn destroy(instance: &Kernelet) {
    instance.kill(KillReason::Requested).unwrap();
    let deadline = crate::time::read_monotonic_time() + Duration::from_secs(5);
    while instance.state() != KerneletState::Exited {
        assert!(
            crate::time::read_monotonic_time() < deadline,
            "dormant instance did not exit"
        );
        Task::yield_now();
    }
    instance.destroy().unwrap();
}

struct DormantHooks;

impl KerneletHooks for DormantHooks {
    fn create_vcpu_thread(
        &self,
        _: &Arc<Kernelet>,
        _: u16,
        _: CpuId,
        _: i8,
    ) -> ostd::Result<Arc<Task>> {
        TaskOptions::new(|| panic!("NIC quota fixture must remain dormant"))
            .data(())
            .build()
            .map(Arc::new)
    }

    fn realtime_now(&self) -> Duration {
        Duration::ZERO
    }
    fn mmio_read(&self, _: u16, _: u32, _: u32) -> MmioResult {
        panic!("NIC quota fixture must not execute MMIO")
    }
    fn mmio_write(&self, _: u16, _: u32, _: u32, _: u64) -> i64 {
        panic!("NIC quota fixture must not execute MMIO")
    }
    fn log(&self, _: u32, _: &str, _: &str) -> bool {
        panic!("NIC quota fixture must not execute logging")
    }
    fn set_vcpu_nice(&self, _: i8) -> ostd::Result<()> {
        panic!("NIC quota fixture must not change carrier policy")
    }
}
