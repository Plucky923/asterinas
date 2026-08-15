// SPDX-License-Identifier: MPL-2.0

//! The shared NVMe driver implementation built for FrameVM.

#![no_std]

extern crate alloc;
#[macro_use]
extern crate ostd_pod;

macro_rules! __log_prefix {
    () => {
        "nvme: "
    };
}

use alloc::sync::Arc;

use aster_block::{
    MajorIdOwner,
    request_queue::{BioRequestSingleQueue, RequestAdmission},
};
use component::{ComponentInitError, init_component};
use ostd::task::{self, TaskAdmission, TaskWorker};
use spin::Once;
use transport::pci::NVME_PCI_DRIVER;

pub use self::device::block_device::NvmeBlockDevice;

mod device;
mod msix;
mod nvme_cmd;
mod nvme_queue;
mod nvme_regs;
mod nvme_spec;
mod transport;

static NVME_BLOCK_MAJOR_ID: Once<MajorIdOwner> = Once::new();

struct NvmeRequestAdmission {
    admission: Arc<TaskAdmission>,
}

/// Holds one registered NVMe worker until it completes or fails.
pub struct NvmeWorker {
    admission: Arc<TaskAdmission>,
    worker: TaskWorker,
}

impl RequestAdmission for NvmeRequestAdmission {
    fn try_acquire(&self) -> bool {
        self.admission.try_enter_request()
    }

    fn release(&self) {
        self.admission.leave_request();
    }

    fn is_closed(&self) -> bool {
        self.admission.is_closed()
    }
}

#[init_component]
fn nvme_init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes the shared NVMe driver for the current FrameVM.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    let major = aster_block::allocate_major().map_err(|_| ComponentInitError::Unknown)?;
    NVME_BLOCK_MAJOR_ID.call_once(|| major);
    let admission = task::current_task_admission().map_err(|_| ComponentInitError::Unknown)?;

    transport::init();

    while let Some(transport) = NVME_PCI_DRIVER.get().unwrap().pop_device_transport() {
        let queue = BioRequestSingleQueue::with_request_admission(
            admission.wait_queue(),
            Arc::new(NvmeRequestAdmission {
                admission: admission.clone(),
            }),
        );
        if let Err(error) = NvmeBlockDevice::init(transport, queue) {
            ostd::error!("Device initialization error: {error:?}");
            admission.report_failure();
        }
    }

    Ok(())
}

/// Registers one NVMe request worker for this service.
pub fn register_worker() -> Option<NvmeWorker> {
    let admission = match task::current_task_admission() {
        Ok(admission) => admission,
        Err(error) => {
            ostd::error!("cannot register FrameVM NVMe worker without task admission: {error:?}");
            return None;
        }
    };
    let Some(worker) = admission.register_participant() else {
        if !admission.is_forced() {
            ostd::error!("cannot register FrameVM NVMe worker after service startup has ended");
            admission.report_failure();
        }
        return None;
    };

    Some(NvmeWorker { admission, worker })
}

impl NvmeWorker {
    /// Runs this registered NVMe worker.
    pub fn run(self, nvme_device: &NvmeBlockDevice) {
        let Self { admission, worker } = self;

        while nvme_device.handle_next_request_until_closed() {}

        if !admission.is_orderly_requested() {
            worker.fail();
            return;
        }

        match nvme_device.finish_orderly_shutdown() {
            Ok(()) => worker.complete(),
            Err(error) => {
                ostd::error!("FrameVM NVMe orderly shutdown failed: {error:?}");
                worker.fail();
            }
        }
    }
}
