// SPDX-License-Identifier: MPL-2.0

//! Explicit shared-buffer block attachments, separate from VirtIO MMIO.
//! Only audited whole-device VirtIO backends can import these allocations.

use aster_block::{
    BlockDevice, SECTOR_SIZE,
    bio::{Bio, BioSegment, BioStatus, BioType},
    id::Sid,
};
use aster_virtio::device::block::device::BlockDevice as VirtioBlockDriver;
use io_util::batch::IoBatch;
use ostd::{
    kernelet::{
        abi::{INVALID, LIMIT, STATE},
        control::{HostByteCharge, Kernelet},
        shared_buffer::{BackendBuffer, ZeroCopyBlockInfo},
    },
    sync::{LocalIrqDisabled, WaitQueue},
};

use super::{
    policy::{Admission, EndpointReservation},
    scheduling::ExecutionThreads,
    virtio_block::QUEUE_SIZE,
};
use crate::{fs::file::FileLike, prelude::*};

#[cfg(ktest)]
mod test;

/// One explicitly authorized backend. There is no guest descriptor queue,
/// staging buffer, or implicit route from a copying MMIO device.
pub(super) struct ZeroCopyBlock {
    kernelet: Arc<Kernelet>,
    device: Arc<dyn BlockDevice>,
    info: ZeroCopyBlockInfo,
    state: SpinLock<State, LocalIrqDisabled>,
    requests: WaitQueue,
    _host: HostByteCharge,
    _reservation: EndpointReservation,
}

struct State {
    cancelled: bool,
    pending: VecDeque<BackendBuffer>,
}

impl ZeroCopyBlock {
    /// Rejects incompatible backends during ATTACH, before buffer acceptance.
    pub(super) fn backend(file: &dyn FileLike) -> Result<Arc<dyn BlockDevice>> {
        crate::device::block_device_from_file(file)
            .filter(|device| device.downcast_ref::<VirtioBlockDriver>().is_some())
            .ok_or_else(|| {
                Error::with_message(
                    Errno::EOPNOTSUPP,
                    "backend cannot import shared DMA buffers",
                )
            })
    }

    pub(super) fn new(
        admission: &Arc<Admission>,
        kernelet: Arc<Kernelet>,
        device: Arc<dyn BlockDevice>,
        capacity_sectors: u64,
        read_only: bool,
    ) -> Result<Arc<Self>> {
        let capacity_bytes = capacity_sectors
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "block capacity overflow"))?;
        // Match the copying block device's bounded pending-request depth.
        // The worker stack is also reserved in the UID's instance memory budget.
        let metadata = size_of::<Self>() + QUEUE_SIZE * size_of::<BackendBuffer>();
        let host = kernelet.reserve_host_bytes(
            metadata + ostd::kernelet::control::host_worker_reservation_bytes(),
        )?;
        Ok(Arc::new(Self {
            kernelet,
            device,
            info: ZeroCopyBlockInfo {
                capacity_bytes,
                read_only,
            },
            state: SpinLock::new(State {
                cancelled: false,
                pending: VecDeque::with_capacity(QUEUE_SIZE),
            }),
            requests: WaitQueue::new(),
            _host: host,
            _reservation: admission.reserve_endpoint_bytes(metadata)?,
        }))
    }

    pub(super) fn info(&self) -> Option<ZeroCopyBlockInfo> {
        (!self.state.lock().cancelled).then_some(self.info)
    }

    pub(super) fn cancel(&self) {
        let pending = {
            let mut state = self.state.lock();
            state.cancelled = true;
            core::mem::take(&mut state.pending)
        };
        // Queued buffers have no driver access. In-flight BIOs retain their
        // independent holds until the physical driver releases them.
        for buffer in pending {
            let _ = buffer.complete(-STATE, 0);
        }
        self.requests.wake_all();
    }

    /// The non-scheduling hook only transfers an accepted buffer into this queue.
    pub(super) fn submit(&self, buffer: BackendBuffer) {
        let failure = {
            let mut state = self.state.lock();
            if state.cancelled {
                STATE
            } else if state.pending.len() == QUEUE_SIZE {
                LIMIT
            } else {
                state.pending.push_back(buffer);
                drop(state);
                self.requests.wake_all();
                return;
            }
        };
        let _ = buffer.complete(-failure, 0);
    }

    pub(super) fn start_worker(self: &Arc<Self>, execution: &ExecutionThreads) {
        let block = self.clone();
        execution.spawn_worker(move || block.worker());
    }

    fn worker(&self) {
        if self.kernelet.adopt_current_task().is_err() {
            self.cancel();
            return;
        }
        while let Some(buffer) = self.requests.wait_until(|| {
            let mut state = self.state.lock();
            if state.cancelled {
                Some(None)
            } else {
                state.pending.pop_front().map(Some)
            }
        }) {
            self.submit_io(buffer);
            if ostd::task::Task::need_yield() {
                ostd::task::Task::yield_now();
            }
        }
        self.kernelet.disown_current_task();
    }

    fn submit_io(&self, buffer: BackendBuffer) {
        let request = buffer.request();
        // Teardown can race the earlier service admission. An accepted request
        // gets a result, while its storage still follows the backend-hold rule.
        if self.info().is_none() || buffer.cancel_requested() {
            let _ = buffer.complete(-STATE, 0);
            return;
        }
        let buffer = Arc::new(buffer);
        let segment = match BioSegment::from_shared_buffer(buffer.clone()) {
            Ok(segment) => segment,
            Err(_) => {
                let _ = buffer.complete(-INVALID, 0);
                return;
            }
        };
        let completion = buffer.clone();
        let bio = Bio::new(
            if request.device_writes {
                BioType::Read
            } else {
                BioType::Write
            },
            Sid::from_offset(request.offset as usize),
            vec![segment],
            Some(Box::new(move |status| {
                let (status, transferred) = if status == BioStatus::Complete {
                    (0, request.len)
                } else {
                    (-STATE, 0)
                };
                let _ = completion.complete(status, transferred);
            })),
        );
        // Both the driver-owned segment and callback retain the original DMA
        // allocation. Dropping this local waiter cannot return buffer access.
        if bio
            .submit(self.device.as_ref(), &mut IoBatch::new())
            .is_err()
        {
            let _ = buffer.complete(-STATE, 0);
        }
    }
}
