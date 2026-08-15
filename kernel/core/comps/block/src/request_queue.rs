// SPDX-License-Identifier: MPL-2.0

use ostd::sync::{Mutex, WaitQueue};

use super::{
    bio::{BioEnqueueError, BioType, SubmittedBio},
    id::Sid,
};
use crate::prelude::*;

/// A simple block I/O request queue backed by one internal FIFO queue.
///
/// It is a FIFO producer-consumer queue, where the producer (e.g., filesystem)
/// submits requests to the queue, and the consumer (e.g., block device driver)
/// continuously consumes and processes these requests from the queue.
///
/// It supports merging the new request with the front request if if the type
/// is same and the sector range is contiguous.
pub struct BioRequestSingleQueue {
    queue: Mutex<VecDeque<BioRequest>>,
    num_requests: AtomicUsize,
    wait_queue: Arc<WaitQueue>,
    request_admission: Option<Arc<dyn RequestAdmission>>,
    max_nr_segments_per_bio: usize,
}

impl BioRequestSingleQueue {
    /// Creates an empty queue.
    pub fn new() -> Self {
        Self::with_max_nr_segments_per_bio(usize::MAX)
    }

    /// Creates an empty queue with the upper bound for the number of segments in a bio.
    pub fn with_max_nr_segments_per_bio(max_nr_segments_per_bio: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            num_requests: AtomicUsize::new(0),
            wait_queue: Arc::new(WaitQueue::new()),
            request_admission: None,
            max_nr_segments_per_bio,
        }
    }

    /// Creates an empty queue controlled by external request admission.
    pub fn with_request_admission(
        wait_queue: Arc<WaitQueue>,
        request_admission: Arc<dyn RequestAdmission>,
    ) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            num_requests: AtomicUsize::new(0),
            wait_queue,
            request_admission: Some(request_admission),
            max_nr_segments_per_bio: usize::MAX,
        }
    }

    /// Returns the upper limit for the number of segments per bio.
    pub fn max_nr_segments_per_bio(&self) -> usize {
        self.max_nr_segments_per_bio
    }

    /// Returns the number of requests currently in this queue.
    pub fn num_requests(&self) -> usize {
        self.num_requests.load(Ordering::Relaxed)
    }

    /// Enqueues a `SubmittedBio` to this queue.
    ///
    /// When enqueueing the `SubmittedBio`, try to insert it into the last request if the
    /// type is same and the sector range is contiguous.
    /// Otherwise, creates and inserts a new request for the `SubmittedBio`.
    ///
    /// This method will wake up the waiter if a new `BioRequest` is enqueued.
    pub fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        if bio.segments().len() >= self.max_nr_segments_per_bio {
            return Err(BioEnqueueError::TooBig);
        }

        let request_admission = self.request_admission.as_deref();
        if let Some(request_admission) = request_admission
            && !request_admission.try_acquire()
        {
            return Err(BioEnqueueError::Refused);
        }
        let _admission = RequestAdmissionGuard { request_admission };

        let mut queue = self.queue.lock();
        if let Some(request) = queue.front_mut()
            && request.can_merge(&bio)
            && request.num_segments() + bio.segments().len() <= self.max_nr_segments_per_bio
        {
            request.merge_bio(bio);
            return Ok(());
        }

        let new_request = BioRequest::from(bio);
        queue.push_front(new_request);
        self.inc_num_requests();
        drop(queue);

        self.wait_queue.wake_all();
        Ok(())
    }

    /// Dequeues a `BioRequest` from this queue.
    ///
    /// This method will wait until one request can be retrieved.
    pub fn dequeue(&self) -> BioRequest {
        let mut num_requests = self.num_requests();

        loop {
            if num_requests > 0 {
                let mut queue = self.queue.lock();
                if let Some(request) = queue.pop_back() {
                    self.dec_num_requests();
                    return request;
                }
            }

            num_requests = self.wait_queue.wait_until(|| {
                let num_requests = self.num_requests();
                if num_requests > 0 {
                    Some(num_requests)
                } else {
                    None
                }
            });
        }
    }

    /// Dequeues a request or returns `None` after external admission closes.
    pub fn dequeue_until_closed(&self) -> Option<BioRequest> {
        loop {
            if let Some(request) = self.try_dequeue() {
                return Some(request);
            }

            if self.is_closed() {
                return self.try_dequeue();
            }

            self.wait_queue
                .wait_until(|| (self.num_requests() > 0 || self.is_closed()).then_some(()));
        }
    }

    fn try_dequeue(&self) -> Option<BioRequest> {
        let request = self.queue.lock().pop_back()?;
        self.dec_num_requests();
        Some(request)
    }

    fn is_closed(&self) -> bool {
        self.request_admission
            .as_deref()
            .is_some_and(|request_admission| request_admission.is_closed())
    }

    fn dec_num_requests(&self) {
        self.num_requests.fetch_sub(1, Ordering::Relaxed);
    }

    fn inc_num_requests(&self) {
        self.num_requests.fetch_add(1, Ordering::Relaxed);
    }
}

/// Controls request admission for a queue owned by an external lifecycle.
pub trait RequestAdmission: Send + Sync {
    /// Acquires admission before a request becomes accepted.
    fn try_acquire(&self) -> bool;

    /// Releases admission after an accepted request reaches the queue.
    fn release(&self);

    /// Returns whether a consumer may exit after draining the queue.
    ///
    /// Returning `true` guarantees that no later successful admission can add
    /// a request to the queue.
    fn is_closed(&self) -> bool;
}

struct RequestAdmissionGuard<'a> {
    request_admission: Option<&'a dyn RequestAdmission>,
}

impl Drop for RequestAdmissionGuard<'_> {
    fn drop(&mut self) {
        if let Some(request_admission) = self.request_admission {
            request_admission.release();
        }
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::{
        collections::VecDeque,
        sync::{Arc, Weak},
    };
    use core::sync::atomic::{AtomicBool, Ordering};

    use ostd::{
        prelude::ktest,
        sync::{Mutex, WaitQueue},
    };

    use super::{BioRequest, BioRequestSingleQueue, BioType, RequestAdmission, Sid};

    struct ClosingAdmission {
        queue: Mutex<Option<Weak<BioRequestSingleQueue>>>,
        injected: AtomicBool,
    }

    impl ClosingAdmission {
        fn inject_request(&self) {
            if self.injected.swap(true, Ordering::AcqRel) {
                return;
            }

            let Some(queue) = self.queue.lock().as_ref().and_then(|queue| queue.upgrade()) else {
                return;
            };
            queue.queue.lock().push_front(BioRequest {
                type_: BioType::Flush,
                sid_range: Sid::new(0)..Sid::new(0),
                num_segments: 0,
                bios: VecDeque::new(),
            });
            queue.inc_num_requests();
        }
    }

    impl RequestAdmission for ClosingAdmission {
        fn try_acquire(&self) -> bool {
            true
        }

        fn release(&self) {}

        fn is_closed(&self) -> bool {
            self.inject_request();
            true
        }
    }

    #[ktest]
    fn dequeue_until_closed_rechecks_the_queue_after_close() {
        let admission = Arc::new(ClosingAdmission {
            queue: Mutex::new(None),
            injected: AtomicBool::new(false),
        });
        let queue = Arc::new(BioRequestSingleQueue::with_request_admission(
            Arc::new(WaitQueue::new()),
            admission.clone(),
        ));
        *admission.queue.lock() = Some(Arc::downgrade(&queue));

        assert!(queue.dequeue_until_closed().is_some());
        assert!(queue.dequeue_until_closed().is_none());
    }
}

impl Default for BioRequestSingleQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for BioRequestSingleQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("BioRequestSingleQueue")
            .field("num_requests", &self.num_requests())
            .field("queue", &self.queue.lock())
            .finish()
    }
}

/// A block I/O request dequeued from [`BioRequestSingleQueue`].
///
/// This `BioRequest` type is more friendly to storage medium than `SubmittedBio` for two reasons.
///
/// First, a `BioRequest` can represent a merged request over multiple `SubmittedBio`s
/// that (1) are of the same request type and (2) are contiguous in terms of target sectors.
/// This helps reduce the number of I/O requests submitted to the underlying storage medium.
///
/// Second, a `BioRequest` provides the physical sector addresses suitable for storage medium.
/// The sector addresses returned from `SubmittedBio::sid_range()` are logical ones:
/// they need to be adjusted with `SubmittedBio::sid_offset()` to calculate the physical ones.
/// This calculation is handled internally by `BioRequest`.
/// One can simply call `BioRequest::sid_range()` to obtain the physical sector addresses.
#[derive(Debug)]
pub struct BioRequest {
    /// The type of the I/O
    type_: BioType,
    /// The physical range of target sectors on the device
    sid_range: Range<Sid>,
    /// The number of segments
    num_segments: usize,
    /// The submitted bios
    bios: VecDeque<SubmittedBio>,
}

impl BioRequest {
    /// Returns the type of the I/O.
    pub fn type_(&self) -> BioType {
        self.type_
    }

    /// Returns the range of sector id on device.
    pub fn sid_range(&self) -> &Range<Sid> {
        &self.sid_range
    }

    /// Returns an iterator to the `SubmittedBio`s.
    pub fn bios(&self) -> impl Iterator<Item = &SubmittedBio> {
        self.bios.iter()
    }

    /// Returns an iterator that consumes and yields the `SubmittedBio`s.
    pub fn into_bios(self) -> impl Iterator<Item = SubmittedBio> {
        self.bios.into_iter()
    }

    /// Returns the number of sectors of this request.
    pub fn num_sectors(&self) -> usize {
        (self.sid_range.end.to_raw() - self.sid_range.start.to_raw())
            .try_into()
            .unwrap()
    }

    /// Returns the number of segments.
    pub fn num_segments(&self) -> usize {
        self.num_segments
    }

    /// Returns `true` if can merge the `SubmittedBio`, `false` otherwise.
    pub fn can_merge(&self, rq_bio: &SubmittedBio) -> bool {
        if rq_bio.type_() != self.type_ {
            return false;
        }

        let sid_offset = rq_bio.sid_offset();

        rq_bio.sid_range().start + sid_offset == self.sid_range.end
            || rq_bio.sid_range().end + sid_offset == self.sid_range.start
    }

    /// Merges the `SubmittedBio` into this request.
    ///
    /// The merged `SubmittedBio` can only be placed at the front or back.
    ///
    /// # Panics
    ///
    /// If the `SubmittedBio` can not be merged, this method will panic.
    pub fn merge_bio(&mut self, rq_bio: SubmittedBio) {
        assert!(self.can_merge(&rq_bio));

        let rq_bio_nr_segments = rq_bio.segments().len();
        let sid_offset = rq_bio.sid_offset();

        if rq_bio.sid_range().start + sid_offset == self.sid_range.end {
            self.sid_range.end = rq_bio.sid_range().end + sid_offset;
            self.bios.push_back(rq_bio);
        } else {
            self.sid_range.start = rq_bio.sid_range().start + sid_offset;
            self.bios.push_front(rq_bio);
        }

        self.num_segments += rq_bio_nr_segments;
    }
}

impl From<SubmittedBio> for BioRequest {
    fn from(bio: SubmittedBio) -> Self {
        let mut sid_range = bio.sid_range().clone();
        sid_range.start = sid_range.start + bio.sid_offset();
        sid_range.end = sid_range.end + bio.sid_offset();

        Self {
            type_: bio.type_(),
            sid_range,
            num_segments: bio.segments().len(),
            bios: {
                let mut bios = VecDeque::with_capacity(1);
                bios.push_front(bio);
                bios
            },
        }
    }
}
