// SPDX-License-Identifier: MPL-2.0

//! Real buffer transitions and physical queue contention with a test backend.

use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use aster_block::{
    BlockDeviceMeta,
    bio::{BioEnqueueError, SubmittedBio},
    request_queue::BioRequestSingleQueue,
};
use ostd::{
    cpu::{CpuId, CpuSet, PinCurrentCpu},
    kernelet::{
        abi::{MmioResult, buffer},
        control::{
            CpuBudget, KerneletConfig, KerneletHooks, KerneletKind, KerneletPolicy, KerneletState,
            KillReason,
        },
        shared_buffer::IoRequest,
    },
    prelude::ktest,
    task::{Task, TaskOptions},
};

use super::*;
use crate::process::Uid;

#[ktest]
fn atomic_submission_defers_contended_physical_queue_lock() {
    crate::time::clocks::init_for_ktest();
    crate::endovisor::reaper::init().unwrap();
    let kind = KerneletKind::register_dormant_fixture().unwrap();
    let mut cpus = CpuSet::new_empty();
    cpus.add(ostd::irq::disable_local().current_cpu());
    let instance = kind
        .create(
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
        .unwrap();
    let admission = Admission::reserve(Uid::new(u32::MAX - 64), 1, 1, 0).unwrap();
    admission.mark_created();
    let device = Arc::new(ContendedDevice {
        queue: BioRequestSingleQueue::new(),
        entered: AtomicBool::new(false),
        enqueued: AtomicBool::new(false),
    });
    let block = ZeroCopyBlock::new(&admission, instance.clone(), device.clone(), 8, false).unwrap();
    let link = instance.shared_buffer_host_endpoint().unwrap();
    let grant = link.allocate(PAGE_SIZE, Box::new(())).unwrap();
    grant
        .handoff(link.reserve_send(PAGE_SIZE).unwrap(), SECTOR_SIZE)
        .map_err(|(_, _, error)| error)
        .unwrap();
    let delivered =
        instance.test_shared_buffer_service(buffer::RECEIVE, 0, [link.connection(), 0, 0]);
    assert_eq!(delivered.status, 0);
    assert_ne!(delivered.value, 0);
    assert!(
        instance
            .test_shared_buffer_service(buffer::REDEEM, delivered.value, [0; 3])
            .status
            >= 0
    );
    let execution = ExecutionThreads::new(0, 1, 1).unwrap();
    let accepted = device.queue.with_locked_queue_for_test(|| {
        block.start_worker(&execution);
        let accepted = instance.test_shared_buffer_submit(
            delivered.value,
            block.info().unwrap(),
            IoRequest {
                device: 0,
                offset: 0,
                len: SECTOR_SIZE,
                device_writes: false,
            },
            |buffer, _| {
                // Match the hook's actual scheduling guards. The old direct
                // BIO submission panics on the queue mutex held by this Task.
                let _irq = ostd::irq::disable_local();
                let _preempt = ostd::task::disable_preempt();
                block.submit(buffer);
            },
        );
        assert_eq!(accepted.status, 0);
        assert_ne!(accepted.value, 0);
        wait_until(|| device.entered.load(Ordering::Acquire));
        assert!(!device.enqueued.load(Ordering::Acquire));
        assert_eq!(instance.state(), KerneletState::Created);
        accepted.value
    });
    wait_until(|| device.enqueued.load(Ordering::Acquire));
    for bio in device.queue.dequeue().into_bios() {
        bio.complete(BioStatus::Complete);
    }
    let mut completion = None;
    wait_until(|| {
        let reply = instance.test_shared_buffer_service(buffer::POLL, accepted, [0; 3]);
        assert_eq!(reply.status, 0);
        if reply.value == 0 {
            return false;
        }
        completion = Some(reply.value);
        true
    });
    assert_eq!(
        instance
            .test_shared_buffer_service(buffer::DISCARD, completion.unwrap(), [0; 3])
            .status,
        0
    );
    block.cancel();
    link.close();
    instance.kill(KillReason::Requested).unwrap();
    wait_until(|| instance.state() == KerneletState::Exited);
    wait_until(|| instance.destroy().is_ok());
    drop(block);
    admission.release_after_destroy();
}

fn wait_until(mut ready_fn: impl FnMut() -> bool) {
    let deadline = crate::time::read_monotonic_time() + Duration::from_secs(5);
    while !ready_fn() {
        assert!(
            crate::time::read_monotonic_time() < deadline,
            "shared block worker timed out"
        );
        Task::yield_now();
    }
}

/// Uses the exact request queue and sleeping mutex used by the VirtIO driver.
#[derive(Debug)]
struct ContendedDevice {
    queue: BioRequestSingleQueue,
    entered: AtomicBool,
    enqueued: AtomicBool,
}

impl BlockDevice for ContendedDevice {
    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        ostd::task::atomic_mode::might_sleep();
        self.entered.store(true, Ordering::Release);
        self.queue.enqueue(bio)?;
        self.enqueued.store(true, Ordering::Release);
        Ok(())
    }
    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: 1,
            nr_sectors: 8,
        }
    }
    fn name(&self) -> &str {
        "contended-shared-block-test"
    }
    fn id(&self) -> device_id::DeviceId {
        device_id::DeviceId::null()
    }
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
        TaskOptions::new(|| panic!("shared block fixture must remain dormant"))
            .data(())
            .build()
            .map(Arc::new)
    }
    fn realtime_now(&self) -> Duration {
        Duration::ZERO
    }
    fn mmio_read(&self, _: u16, _: u32, _: u32) -> MmioResult {
        unreachable!()
    }
    fn mmio_write(&self, _: u16, _: u32, _: u32, _: u64) -> i64 {
        unreachable!()
    }
    fn log(&self, _: u32, _: &str, _: &str) -> bool {
        unreachable!()
    }
    fn set_vcpu_nice(&self, _: i8) -> ostd::Result<()> {
        unreachable!()
    }
}
