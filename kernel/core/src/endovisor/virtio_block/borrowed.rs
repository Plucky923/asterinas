// SPDX-License-Identifier: MPL-2.0

//! Physical BIOs that retain the Image's registered DMA allocations directly.
//!
//! Control information comes from the existing validated VirtIO request. This
//! backend allocates metadata only; it neither stages nor copies payload bytes.
//! All DMA leases are acquired before the first physical BIO is published.

use core::sync::atomic::{AtomicU64, Ordering};

use aster_block::{
    BlockDevice,
    bio::{Bio, BioSegment, BioType, GuestBioSegmentCache},
    id::Sid,
};
use io_util::batch::IoBatch;
use ostd::{
    kernelet::{
        control::{HostByteCharge, Kernelet},
        guest_dma::{DeviceAccess, GuestDmaLease},
        guest_memory::GuestMemory,
    },
    mm::HasDaddr,
};
use smallvec::SmallVec;

use super::{
    BorrowedBlockStats, Buffer, MAX_REQUEST_BYTES, QUEUE_SIZE, REQUEST_READ, REQUEST_WRITE,
    SECTOR_BYTES, TailCounters, TailSnapshot,
};
use crate::{
    endovisor::policy::{Admission, EndpointReservation},
    prelude::*,
};

// Allow 512 bytes per descriptor for its retained DMA lease, BIO segment,
// reference-counted owners and vector/node overhead. The additional page
// per request covers BIO metadata and completion bookkeeping. This is a
// metadata allowance, independent of the block device sector size.
const DESCRIPTOR_METADATA_BYTES: usize = 512;
const METADATA_BYTES: usize =
    super::backing::IO_DEPTH * (QUEUE_SIZE * DESCRIPTOR_METADATA_BYTES + PAGE_SIZE);

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    bytes: AtomicU64,
    identity_checks: AtomicU64,
    /// Transfers drained by the worker, including rejected submissions.
    completions: AtomicU64,
    /// Bounded tail buckets of the physical BIO service time.
    wait_tail: TailCounters,
}

pub(super) struct BorrowedBackend {
    device: Arc<dyn BlockDevice>,
    max_segments: usize,
    counters: Counters,
    _host_charge: HostByteCharge,
    _reservation: EndpointReservation,
}

const MAX_CACHED_SEGMENTS: usize = super::backing::IO_DEPTH * (QUEUE_SIZE - 2);

/// Worker-owned metadata cache.
/// Entries never retain an Image DMA lease.
pub(super) struct BorrowedIo {
    backend: Arc<BorrowedBackend>,
    cache: Vec<GuestBioSegmentCache>,
}

impl BorrowedIo {
    pub(super) fn new(backend: Arc<BorrowedBackend>) -> Self {
        Self {
            backend,
            cache: Vec::with_capacity(MAX_CACHED_SEGMENTS),
        }
    }

    pub(super) fn submit(
        &mut self,
        memory: &GuestMemory,
        buffers: &[Buffer],
        offset: usize,
        len: usize,
        operation: u32,
    ) -> Result<PendingTransfer> {
        self.backend
            .submit(memory, buffers, offset, len, operation, &mut self.cache)
    }

    pub(super) fn finish(
        &mut self,
        transfer: PendingTransfer,
        publish_allowed_fn: impl FnOnce() -> bool,
    ) -> Result<u32, (Error, u32)> {
        transfer.finish(publish_allowed_fn, &mut self.cache, &self.backend.counters)
    }
}

impl BorrowedBackend {
    pub(super) fn new(
        device: Arc<dyn BlockDevice>,
        owner: &Arc<Kernelet>,
        admission: &Arc<Admission>,
    ) -> ostd::Result<Arc<Self>> {
        if !GuestDmaLease::is_supported() {
            return Err(ostd::Error::AccessDenied);
        }
        let reservation = admission
            .reserve_endpoint_bytes(METADATA_BYTES)
            .map_err(|_| ostd::Error::NotEnoughResources)?;
        let host_charge = owner.reserve_host_bytes(METADATA_BYTES)?;
        let max_segments = device
            .metadata()
            .max_nr_segments_per_bio
            .clamp(1, QUEUE_SIZE - 2);
        Ok(Arc::new(Self {
            device,
            max_segments,
            counters: Counters::default(),
            _host_charge: host_charge,
            _reservation: reservation,
        }))
    }

    pub(super) fn stats(&self, worker_tail: TailSnapshot) -> BorrowedBlockStats {
        BorrowedBlockStats {
            requests: self.counters.requests.load(Ordering::Relaxed),
            bytes: self.counters.bytes.load(Ordering::Relaxed),
            // There is no payload-copy operation or copying fallback here.
            copied_bytes: 0,
            identity_checks: self.counters.identity_checks.load(Ordering::Relaxed),
            completions: self.counters.completions.load(Ordering::Relaxed),
            wait_tail: self.counters.wait_tail.snapshot(),
            worker_tail,
        }
    }

    fn submit(
        self: &Arc<Self>,
        memory: &GuestMemory,
        buffers: &[Buffer],
        offset: usize,
        len: usize,
        operation: u32,
        cache: &mut Vec<GuestBioSegmentCache>,
    ) -> Result<PendingTransfer> {
        let (kind, access) = match operation {
            REQUEST_READ => (BioType::Read, DeviceAccess::Write),
            REQUEST_WRITE => (BioType::Write, DeviceAccess::Read),
            _ => return_errno_with_message!(Errno::EINVAL, "invalid borrowed block operation"),
        };
        if len == 0
            || len > MAX_REQUEST_BYTES
            || buffers.len() > QUEUE_SIZE - 2
            || !len.is_multiple_of(SECTOR_BYTES as usize)
            || !offset.is_multiple_of(SECTOR_BYTES as usize)
        {
            return_errno_with_message!(Errno::EINVAL, "invalid borrowed block range");
        }
        let metadata = self.device.metadata();
        if offset
            .checked_add(len)
            .is_none_or(|end| end / SECTOR_BYTES as usize > metadata.nr_sectors)
        {
            return_errno_with_message!(Errno::EINVAL, "borrowed block range exceeds device");
        }
        if let [buffer] = buffers {
            if buffer.len as usize != len {
                return_errno_with_message!(Errno::EINVAL, "borrowed block lengths differ");
            }
            let segment = self.borrow_segment(memory, buffer, access, cache)?;
            return Ok(submit_single_segment(
                self.device.as_ref(),
                &self.counters,
                segment,
                offset,
                len,
                kind,
            ));
        }
        let mut segments = Vec::with_capacity(buffers.len());
        let mut total = 0usize;
        for buffer in buffers {
            let size = buffer.len as usize;
            if size == 0 {
                continue;
            }
            if !size.is_multiple_of(SECTOR_BYTES as usize) {
                return_errno_with_message!(Errno::EINVAL, "borrowed block segment is unaligned");
            }
            total = total.checked_add(size).ok_or_else(|| {
                Error::with_message(Errno::EINVAL, "borrowed block length overflow")
            })?;
            if total > len {
                return_errno_with_message!(Errno::EINVAL, "borrowed block segments exceed request");
            }
            segments.push(self.borrow_segment(memory, buffer, access, cache)?);
        }
        if total != len || segments.is_empty() {
            return_errno_with_message!(Errno::EINVAL, "borrowed block lengths differ");
        }
        Ok(submit_segments(
            self.device.as_ref(),
            &self.counters,
            segments,
            offset,
            len,
            kind,
            self.max_segments,
        ))
    }

    fn borrow_segment(
        self: &Arc<Self>,
        memory: &GuestMemory,
        buffer: &Buffer,
        access: DeviceAccess,
        cache: &mut Vec<GuestBioSegmentCache>,
    ) -> Result<BioSegment> {
        let lease = memory.borrow_dma(buffer.paddr, buffer.len as usize, access)?;
        let segment = if let Some(cached) = cache.pop() {
            cached.bind(lease, self.clone())?
        } else {
            BioSegment::from_guest_dma(lease, self.clone())?
        };
        // Every physical descriptor retains its checked original allocation.
        if segment.dma_slice().daddr() as u64 != buffer.paddr {
            return_errno_with_message!(Errno::EIO, "borrowed DMA allocation identity differs");
        }
        Ok(segment)
    }
}

fn submit_single_segment(
    device: &dyn BlockDevice,
    counters: &Counters,
    segment: BioSegment,
    offset: usize,
    len: usize,
    kind: BioType,
) -> PendingTransfer {
    let mut retained = SmallVec::new();
    retained.push(segment.clone());
    let bio = Bio::new_single(kind, Sid::from_offset(offset), segment, None);
    submit_bio(device, counters, bio, len, kind, retained)
}

fn submit_bio(
    device: &dyn BlockDevice,
    counters: &Counters,
    bio: Bio,
    len: usize,
    kind: BioType,
    retained: SmallVec<[BioSegment; 1]>,
) -> PendingTransfer {
    let count = bio.segments().len();
    let mut batch = IoBatch::new();
    let failed = bio.submit(device, &mut batch).is_err();
    if !failed {
        counters.requests.fetch_add(1, Ordering::Relaxed);
        counters.bytes.fetch_add(len as u64, Ordering::Relaxed);
        counters
            .identity_checks
            .fetch_add(count as u64, Ordering::Relaxed);
    }
    PendingTransfer {
        batch,
        len,
        kind,
        failed,
        retained,
    }
}

fn submit_segments(
    device: &dyn BlockDevice,
    counters: &Counters,
    segments: Vec<BioSegment>,
    offset: usize,
    len: usize,
    kind: BioType,
    max_segments: usize,
) -> PendingTransfer {
    let retained = segments.iter().cloned().collect();
    if segments.len() <= max_segments {
        let bio = Bio::new(kind, Sid::from_offset(offset), segments, None);
        return submit_bio(device, counters, bio, len, kind, retained);
    }
    let mut batch = IoBatch::with_capacity(segments.len().div_ceil(max_segments));
    let mut segments = segments.into_iter();
    let mut disk_offset = offset;
    let mut failed = false;
    while segments.len() != 0 {
        let chunk: Vec<_> = segments.by_ref().take(max_segments).collect();
        let bytes = chunk.iter().map(BioSegment::nbytes).sum::<usize>();
        let count = chunk.len();
        let bio = Bio::new(kind, Sid::from_offset(disk_offset), chunk, None);
        if bio.submit(device, &mut batch).is_err() {
            // Earlier chunks may already be DMA-active. Return an accepted
            // transfer that drains them before reporting the error.
            failed = true;
            break;
        }
        counters.requests.fetch_add(1, Ordering::Relaxed);
        counters.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        counters
            .identity_checks
            .fetch_add(count as u64, Ordering::Relaxed);
        disk_offset += bytes;
    }
    // The worker retains every acquired lease, including the unsubmitted suffix,
    // until all accepted BIOs finish. The driver also retains its own references.
    PendingTransfer {
        batch,
        len,
        kind,
        failed,
        retained,
    }
}

pub(super) struct PendingTransfer {
    batch: IoBatch,
    len: usize,
    kind: BioType,
    failed: bool,
    // Keep the final segment reference in the worker, so ordinary completion
    // never releases the Image pin or frees its metadata in the physical IRQ.
    retained: SmallVec<[BioSegment; 1]>,
}

impl PendingTransfer {
    pub(super) fn finish(
        self,
        publish_allowed_fn: impl FnOnce() -> bool,
        cache: &mut Vec<GuestBioSegmentCache>,
        counters: &Counters,
    ) -> Result<u32, (Error, u32)> {
        // Device service time: the span of the physical BIOs, that is the Host
        // backend plus DMA. Image wake-up happens after this window, so a
        // mismatch against the worker span and the measured request latency
        // separates the two tail sources. The clock pair is the only added
        // fast-path cost; `record` writes no atomic below the floor.
        let wait_start = crate::time::read_monotonic_time();
        let result = self.batch.wait_all();
        counters
            .wait_tail
            .record(crate::time::read_monotonic_time().saturating_sub(wait_start));
        counters.completions.fetch_add(1, Ordering::Relaxed);
        // Each BIO has finished device synchronization and dropped its segment
        // references. Release all leases before the Image can observe completion,
        // including failures and stale/reset requests. Only empty metadata is cached.
        for segment in self.retained {
            if let Ok(cached) = segment.try_recycle_guest_dma()
                && cache.len() < MAX_CACHED_SEGMENTS
            {
                cache.push(cached);
            }
        }
        if self.failed || result.is_err() {
            return Err((
                Error::with_message(Errno::EIO, "borrowed block BIO failed"),
                0,
            ));
        }
        // The real driver synchronized device writes before BIO completion.
        // No CPU payload accessor or post-completion copyback is required.
        Ok(if self.kind == BioType::Read && publish_allowed_fn() {
            self.len as u32
        } else {
            0
        })
    }
}

#[cfg(ktest)]
mod test {
    use core::sync::atomic::{AtomicBool, AtomicUsize};

    use aster_block::{
        BlockDeviceMeta,
        bio::{BioDirection, BioEnqueueError, BioStatus, SubmittedBio},
    };
    use ostd::{
        prelude::*,
        task::{Task, TaskOptions},
    };

    use super::*;

    #[derive(Debug)]
    struct DeferredDevice {
        pending: SpinLock<Vec<SubmittedBio>>,
        attempts: AtomicUsize,
        reject_attempt: Option<usize>,
    }

    impl BlockDevice for DeferredDevice {
        fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
            let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
            if self.reject_attempt == Some(attempt) {
                return Err(BioEnqueueError::Refused);
            }
            assert_eq!(bio.segments().len(), 1);
            self.pending.lock().push(bio);
            Ok(())
        }

        fn metadata(&self) -> BlockDeviceMeta {
            BlockDeviceMeta {
                max_nr_segments_per_bio: 1,
                nr_sectors: 1 << 20,
            }
        }

        fn name(&self) -> &str {
            "borrowed-deferred-test"
        }
        fn id(&self) -> device_id::DeviceId {
            device_id::DeviceId::null()
        }
    }

    fn segments(count: usize) -> Vec<BioSegment> {
        (0..count)
            .map(|_| BioSegment::try_alloc(1, BioDirection::FromDevice).unwrap())
            .collect()
    }

    fn borrowed_segment(memory: &GuestMemory, address: u64, access: DeviceAccess) -> BioSegment {
        BioSegment::from_guest_dma(
            memory.borrow_dma(address, PAGE_SIZE, access).unwrap(),
            Arc::new(()),
        )
        .unwrap()
    }

    fn with_supported_dma_test(test_fn: impl FnOnce(&GuestMemory, u64)) {
        GuestMemory::with_test_registered_dma(|memory, address| {
            let supported = GuestDmaLease::is_supported();
            ostd::early_println!("borrowed_dma_test_supported={}", supported);
            if !supported {
                assert!(
                    memory
                        .borrow_dma(address, PAGE_SIZE, DeviceAccess::Write)
                        .is_err()
                );
                return;
            }
            test_fn(memory, address);
        });
    }

    #[ktest]
    fn recycled_segment_drops_lease_and_rebinds_fresh_dma_identity() {
        with_supported_dma_test(|memory, address| {
            let segment = borrowed_segment(memory, address, DeviceAccess::Write);
            let metadata_address = core::ptr::from_ref(segment.dma_slice());
            let other_view = segment.clone();
            let segment = segment.try_recycle_guest_dma().unwrap_err();
            assert!(memory.is_pinned_for_test());
            assert_eq!(other_view.dma_slice().daddr() as u64, address);
            drop(other_view);

            let cache = segment.try_recycle_guest_dma().unwrap();
            assert!(!memory.is_pinned_for_test());
            let next_address = address + PAGE_SIZE as u64;
            let lease = memory
                .borrow_dma(next_address, 512, DeviceAccess::Read)
                .unwrap();
            let segment = cache.bind(lease, Arc::new(())).unwrap();
            assert_eq!(core::ptr::from_ref(segment.dma_slice()), metadata_address);
            assert_eq!(segment.dma_slice().daddr() as u64, next_address);
            assert_eq!(segment.nbytes(), 512);
            assert_eq!(segment.dma_slice().mem_obj().sync_to_device(0..512), Ok(()));
            assert_eq!(
                segment.dma_slice().mem_obj().sync_from_device(0..512),
                Err(ostd::Error::AccessDenied)
            );
            let cache = segment.try_recycle_guest_dma().unwrap();
            assert!(!memory.is_pinned_for_test());
            memory.revoke_for_test();
            assert!(
                memory
                    .borrow_dma(address, PAGE_SIZE, DeviceAccess::Write)
                    .is_err()
            );
            drop(cache);
        });
    }

    #[ktest]
    fn borrowed_completion_keeps_pin_until_worker_recycles_before_publication() {
        with_supported_dma_test(|memory, address| {
            let device = DeferredDevice {
                pending: SpinLock::new(Vec::new()),
                attempts: AtomicUsize::new(0),
                reject_attempt: None,
            };
            let counters = Counters::default();
            let transfer = submit_single_segment(
                &device,
                &counters,
                borrowed_segment(memory, address, DeviceAccess::Write),
                0,
                PAGE_SIZE,
                BioType::Read,
            );
            let bio = device.pending.lock().pop().unwrap();
            bio.complete(BioStatus::Complete);
            // Simulates returning from the real physical completion handler.
            assert!(memory.is_pinned_for_test());
            let mut cache = Vec::new();
            assert_eq!(
                transfer
                    .finish(
                        || {
                            assert!(!memory.is_pinned_for_test());
                            true
                        },
                        &mut cache,
                        &counters
                    )
                    .unwrap(),
                PAGE_SIZE as u32
            );
            assert_eq!(cache.len(), 1);
            assert!(!memory.is_pinned_for_test());
        });
    }

    #[ktest]
    fn rejected_borrowed_submission_recycles_without_publishing() {
        with_supported_dma_test(|memory, address| {
            let device = DeferredDevice {
                pending: SpinLock::new(Vec::new()),
                attempts: AtomicUsize::new(0),
                reject_attempt: Some(0),
            };
            let counters = Counters::default();
            let transfer = submit_single_segment(
                &device,
                &counters,
                borrowed_segment(memory, address, DeviceAccess::Write),
                0,
                PAGE_SIZE,
                BioType::Read,
            );
            let mut cache = Vec::new();
            assert!(
                transfer
                    .finish(
                        || panic!("rejected BIO cannot publish"),
                        &mut cache,
                        &counters
                    )
                    .is_err()
            );
            assert_eq!(cache.len(), 1);
            assert!(!memory.is_pinned_for_test());
        });
    }

    #[ktest]
    fn single_segment_submission_preserves_dma_address_and_completion() {
        let device = DeferredDevice {
            pending: SpinLock::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            reject_attempt: None,
        };
        let segment = segments(1).pop().unwrap();
        let address = segment.dma_slice().daddr();
        let counters = Counters::default();
        let transfer = submit_single_segment(
            &device,
            &counters,
            segment,
            PAGE_SIZE,
            PAGE_SIZE,
            BioType::Read,
        );
        assert!(!transfer.failed);
        assert_eq!(transfer.batch.len(), 1);
        assert_eq!(counters.requests.load(Ordering::Relaxed), 1);
        assert_eq!(counters.bytes.load(Ordering::Relaxed), PAGE_SIZE as u64);
        assert_eq!(counters.identity_checks.load(Ordering::Relaxed), 1);
        let bio = device.pending.lock().pop().unwrap();
        assert_eq!(bio.segments()[0].dma_slice().daddr(), address);
        assert_eq!(bio.sid_range().start.to_raw(), PAGE_SIZE as u64 / 512);
        bio.complete(BioStatus::Complete);
        assert_eq!(
            transfer
                .finish(|| true, &mut Vec::new(), &counters)
                .unwrap(),
            PAGE_SIZE as u32
        );
    }

    #[ktest]
    fn single_segment_device_rejection_keeps_failure_and_zero_counters() {
        let device = DeferredDevice {
            pending: SpinLock::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            reject_attempt: Some(0),
        };
        let counters = Counters::default();
        let transfer = submit_single_segment(
            &device,
            &counters,
            segments(1).pop().unwrap(),
            0,
            PAGE_SIZE,
            BioType::Read,
        );
        assert!(transfer.failed);
        assert!(transfer.batch.is_empty());
        assert!(
            transfer
                .finish(
                    || panic!("rejected BIO cannot publish"),
                    &mut Vec::new(),
                    &counters
                )
                .is_err()
        );
        assert!(device.pending.lock().is_empty());
        assert_eq!(counters.requests.load(Ordering::Relaxed), 0);
        assert_eq!(counters.bytes.load(Ordering::Relaxed), 0);
        assert_eq!(counters.identity_checks.load(Ordering::Relaxed), 0);
    }

    #[ktest]
    fn stale_single_segment_read_waits_for_dma_before_suppressing_publication() {
        let device = DeferredDevice {
            pending: SpinLock::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            reject_attempt: None,
        };
        let counters = Arc::new(Counters::default());
        let transfer = submit_single_segment(
            &device,
            &counters,
            segments(1).pop().unwrap(),
            0,
            PAGE_SIZE,
            BioType::Read,
        );
        let bio = device.pending.lock().pop().unwrap();
        let started = Arc::new(AtomicBool::new(false));
        let result = Arc::new(Mutex::new(None));
        let waiter = {
            let started = started.clone();
            let result = result.clone();
            TaskOptions::new(move || {
                started.store(true, Ordering::Release);
                *result.lock() = Some(transfer.finish(|| false, &mut Vec::new(), &counters));
            })
            .spawn()
            .unwrap()
        };
        for _ in 0..100_000 {
            if started.load(Ordering::Acquire) {
                break;
            }
            Task::yield_now();
        }
        assert!(started.load(Ordering::Acquire));
        for _ in 0..10 {
            Task::yield_now();
        }
        assert!(result.lock().is_none());
        bio.complete(BioStatus::Complete);
        for _ in 0..100_000 {
            if result.lock().is_some() {
                break;
            }
            Task::yield_now();
        }
        assert_eq!(result.lock().take().unwrap().unwrap(), 0);
        drop(waiter);
    }

    #[ktest]
    fn physical_bios_respect_segment_limits_and_original_dma_addresses() {
        let device = DeferredDevice {
            pending: SpinLock::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            reject_attempt: None,
        };
        let segments = segments(3);
        let addresses: Vec<_> = segments
            .iter()
            .map(|segment| segment.dma_slice().daddr())
            .collect();
        let counters = Counters::default();
        let transfer = submit_segments(
            &device,
            &counters,
            segments,
            4096,
            3 * PAGE_SIZE,
            BioType::Read,
            1,
        );
        assert_eq!(transfer.batch.len(), 3);
        let pending = core::mem::take(&mut *device.pending.lock());
        for (index, bio) in pending.into_iter().enumerate() {
            assert_eq!(bio.segments()[0].dma_slice().daddr(), addresses[index]);
            assert_eq!(
                bio.sid_range().start.to_raw(),
                (4096 + index * PAGE_SIZE) as u64 / 512
            );
            bio.complete(BioStatus::Complete);
        }
        assert_eq!(
            counters.bytes.load(Ordering::Relaxed),
            (3 * PAGE_SIZE) as u64
        );
        assert_eq!(counters.identity_checks.load(Ordering::Relaxed), 3);
        assert_eq!(
            transfer
                .finish(|| true, &mut Vec::new(), &counters)
                .unwrap(),
            (3 * PAGE_SIZE) as u32
        );
    }

    #[ktest]
    fn partial_submission_drains_every_earlier_bio_even_after_a_completion_error() {
        let device = DeferredDevice {
            pending: SpinLock::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            reject_attempt: Some(2),
        };
        let counters = Arc::new(Counters::default());
        let transfer = submit_segments(
            &device,
            &counters,
            segments(3),
            0,
            3 * PAGE_SIZE,
            BioType::Read,
            1,
        );
        assert!(transfer.failed);
        assert_eq!(transfer.batch.len(), 2);
        let mut pending = core::mem::take(&mut *device.pending.lock()).into_iter();
        pending.next().unwrap().complete(BioStatus::IoError);
        let last = pending.next().unwrap();
        let started = Arc::new(AtomicBool::new(false));
        let result = Arc::new(Mutex::new(None));
        let waiter = {
            let started = started.clone();
            let result = result.clone();
            TaskOptions::new(move || {
                started.store(true, Ordering::Release);
                *result.lock() = Some(transfer.finish(|| true, &mut Vec::new(), &counters));
            })
            .spawn()
            .unwrap()
        };
        for _ in 0..100_000 {
            if started.load(Ordering::Acquire) {
                break;
            }
            Task::yield_now();
        }
        assert!(started.load(Ordering::Acquire));
        for _ in 0..10 {
            Task::yield_now();
        }
        assert!(result.lock().is_none());
        last.complete(BioStatus::Complete);
        for _ in 0..100_000 {
            if result.lock().is_some() {
                break;
            }
            Task::yield_now();
        }
        assert!(result.lock().take().unwrap().is_err());
        drop(waiter);
    }
}
