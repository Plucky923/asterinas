// SPDX-License-Identifier: MPL-2.0

//! Work queue mechanism.
//!
//! # Overview
//!
//! A `workqueue` is a kernel-level mechanism used to schedule and execute deferred work.
//! Deferred work refers to tasks that need to be executed at some point in the future,
//! but not necessarily immediately.
//!
//! The workqueue mechanism is implemented using a combination of kernel threads and data
//! structures such as `WorkItem`, `WorkQueue`, `Worker` and `WorkerPool`. The `WorkItem`
//! represents a task to be processed, while the `WorkQueue` maintains the queue of submitted
//! `WorkItems`. The `Worker` is responsible for processing these submitted tasks,
//! and the `WorkerPool` manages and schedules these workers.
//!
//! # Examples
//!
//! The system has a default work queue and worker pool,
//! and it also provides high-level APIs for users to use.
//! Here is a basic example to how to use those APIs.
//!
//! ```rust
//! use crate::thread::work_queue::{submit_work_func, submit_work_item, WorkItem};
//!
//! // Submit to high priority queue.
//! submit_work_func(||{ }, true);
//!
//! // Submit to low priority queue.
//! submit_work_func(||{ }, false);
//!
//! fn deferred_task(){
//!     // ...
//! }
//!
//! // Create a work item.
//! let work_item = Arc::new(WorkItem::new(Box::new(deferred_task)));
//!
//! // Submit to high priority queue.
//! submit_work_item(work_item, true);
//!
//! // Submit to low priority queue.
//! submit_work_item(work_item, false);
//! ```
//!
//! Certainly, users can also create a dedicated WorkQueue and WorkerPool.
//!
//! ```rust
//! use ostd::cpu::CpuSet;
//! use crate::thread::work_queue::{WorkQueue, WorkerPool, WorkItem};
//!
//! fn deferred_task(){
//!     // ...
//! }
//!
//! let cpu_set = CpuSet::new_full();
//! let high_pri_pool = WorkerPool::new(true, cpu_set);
//! let my_queue = WorkQueue::new(Arc::downgrade(high_pri_pool.get().unwrap()));
//!
//! let work_item = Arc::new(WorkItem::new(Box::new(deferred_task)));
//! my_queue.enqueue(work_item);
//!
//! ```

use intrusive_collections::linked_list::LinkedList;
use ostd::cpu::{CpuId, CpuSet};
use spin::Once;
use work_item::{WorkItem, WorkItemAdapter};
use worker_pool::WorkerPool;

use crate::prelude::*;

mod simple_scheduler;
pub mod work_item;
pub mod worker;
pub mod worker_pool;

static WORKERPOOL_NORMAL: Once<SpinLock<Option<Arc<WorkerPool>>>> = Once::new();
static WORKERPOOL_HIGH_PRI: Once<SpinLock<Option<Arc<WorkerPool>>>> = Once::new();
static WORKQUEUE_GLOBAL_NORMAL: Once<SpinLock<Option<Arc<WorkQueue>>>> = Once::new();
static WORKQUEUE_GLOBAL_HIGH_PRI: Once<SpinLock<Option<Arc<WorkQueue>>>> = Once::new();

/// Submit a function to a global work queue.
pub fn submit_work_func<F>(work_func: F, work_priority: WorkPriority)
where
    F: Fn() + Send + Sync + 'static,
{
    let work_item = WorkItem::new(Box::new(work_func));
    submit_work_item(work_item, work_priority);
}

/// Submit a work item to a global work queue.
pub fn submit_work_item(work_item: Arc<WorkItem>, work_priority: WorkPriority) -> bool {
    let work_queue = match work_priority {
        WorkPriority::High => WORKQUEUE_GLOBAL_HIGH_PRI
            .get()
            .and_then(|queue| queue.lock().clone()),
        WorkPriority::Normal => WORKQUEUE_GLOBAL_NORMAL
            .get()
            .and_then(|queue| queue.lock().clone()),
    };
    work_queue.is_some_and(|work_queue| work_queue.enqueue(work_item))
}

/// A work queue maintains a series of work items to be handled
/// asynchronously in a process context.
pub struct WorkQueue {
    _worker_pool: Weak<WorkerPool>,
    inner: SpinLock<WorkQueueInner>,
}

struct WorkQueueInner {
    pending_work_items: LinkedList<WorkItemAdapter>,
}

impl WorkQueue {
    /// Create a `WorkQueue` and specify a `WorkerPool` to
    /// process the submitted `WorkItems`.
    pub fn new(worker_pool: Weak<WorkerPool>) -> Arc<Self> {
        let queue = Arc::new(WorkQueue {
            _worker_pool: worker_pool.clone(),
            inner: SpinLock::new(WorkQueueInner {
                pending_work_items: LinkedList::new(WorkItemAdapter::NEW),
            }),
        });
        worker_pool
            .upgrade()
            .unwrap()
            .assign_work_queue(queue.clone());
        queue
    }

    /// Submit a work item. Return `false` if the work item is currently pending.
    pub fn enqueue(&self, work_item: Arc<WorkItem>) -> bool {
        if !work_item.try_pending() {
            return false;
        }
        self.inner
            .disable_irq()
            .lock()
            .pending_work_items
            .push_back(work_item);

        true
    }

    /// Request a pending work item. The `request_cpu` indicates the CPU where
    /// the calling worker is located.
    fn dequeue(&self, request_cpu: CpuId) -> Option<Arc<WorkItem>> {
        let mut inner = self.inner.disable_irq().lock();
        let mut cursor = inner.pending_work_items.front_mut();
        while let Some(item) = cursor.get() {
            if item.is_valid_cpu(request_cpu) {
                return cursor.remove();
            }

            cursor.move_next();
        }

        None
    }

    fn has_pending_work_items(&self, request_cpu: CpuId) -> bool {
        self.inner
            .disable_irq()
            .lock()
            .pending_work_items
            .iter()
            .any(|item| item.is_valid_cpu(request_cpu))
    }
}

/// Initialize global worker pools and work queues.
pub fn init_in_first_kthread() {
    let normal_pool_slot = WORKERPOOL_NORMAL.call_once(|| SpinLock::new(None));
    let high_priority_pool_slot = WORKERPOOL_HIGH_PRI.call_once(|| SpinLock::new(None));
    let normal_queue_slot = WORKQUEUE_GLOBAL_NORMAL.call_once(|| SpinLock::new(None));
    let high_priority_queue_slot = WORKQUEUE_GLOBAL_HIGH_PRI.call_once(|| SpinLock::new(None));

    let normal_pool = {
        let mut worker_pool = normal_pool_slot.lock();
        worker_pool
            .get_or_insert_with(|| WorkerPool::new(WorkPriority::Normal, CpuSet::new_full()))
            .clone()
    };
    normal_pool.run();

    let high_priority_pool = {
        let mut worker_pool = high_priority_pool_slot.lock();
        worker_pool
            .get_or_insert_with(|| WorkerPool::new(WorkPriority::High, CpuSet::new_full()))
            .clone()
    };
    high_priority_pool.run();

    let mut normal_queue = normal_queue_slot.lock();
    normal_queue.get_or_insert_with(|| WorkQueue::new(Arc::downgrade(&normal_pool)));
    drop(normal_queue);

    let mut high_priority_queue = high_priority_queue_slot.lock();
    high_priority_queue.get_or_insert_with(|| WorkQueue::new(Arc::downgrade(&high_priority_pool)));
}

/// Stops global worker pools during FrameVM service teardown.
///
/// The pools stay owned by their statics while shutdown is in progress, so a
/// monitor queued through a weak reference can finish safely. FrameVisor keeps
/// the service image mapped until those worker tasks have completed.
pub(crate) fn shutdown() {
    for worker_pool in worker_pools() {
        worker_pool.shutdown();
    }
}

fn worker_pools() -> Vec<Arc<WorkerPool>> {
    [WORKERPOOL_NORMAL.get(), WORKERPOOL_HIGH_PRI.get()]
        .into_iter()
        .flatten()
        .filter_map(|worker_pool| worker_pool.lock().as_ref().cloned())
        .collect()
}

impl Drop for WorkQueue {
    fn drop(&mut self) {
        //TODO: Handling non-empty queues.
    }
}

#[derive(PartialEq)]
pub enum WorkPriority {
    High,
    Normal,
}
