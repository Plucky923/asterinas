// SPDX-License-Identifier: MPL-2.0

//! Wait queues exposed through the OSTD-compatible surface.

use alloc::{collections::VecDeque, sync::Arc};
use core::{
    marker::PhantomData,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use host_ostd::sync as host_sync;

use super::{LocalIrqDisabled, SpinLock};
use crate::task::{Task, scheduler};

/// A wait queue.
///
/// The API follows `host_ostd::sync::WaitQueue`.
pub struct WaitQueue {
    num_wakers: AtomicU32,
    wakers: SpinLock<VecDeque<Arc<Waker>>, LocalIrqDisabled>,
}

impl WaitQueue {
    /// Creates a new, empty wait queue.
    pub const fn new() -> Self {
        Self {
            num_wakers: AtomicU32::new(0),
            wakers: SpinLock::new(VecDeque::new()),
        }
    }

    /// Waits until some condition is met.
    #[track_caller]
    pub fn wait_until<F, R>(&self, mut cond: F) -> R
    where
        F: FnMut() -> Option<R>,
    {
        if let Some(result) = cond() {
            return result;
        }

        let (waiter, _) = Waiter::new_pair();
        let cond = || {
            self.enqueue(waiter.waker());
            cond()
        };
        waiter
            .wait_until_or_cancelled(cond, || Ok::<(), ()>(()))
            .unwrap()
    }

    /// Wakes up one waiting task, if any.
    pub fn wake_one(&self) -> bool {
        if self.is_empty() {
            return false;
        }

        loop {
            let mut wakers = self.wakers.lock();
            let Some(waker) = wakers.pop_front() else {
                return false;
            };
            self.num_wakers.fetch_sub(1, Ordering::Release);
            drop(wakers);

            if waker.wake_up() {
                return true;
            }
        }
    }

    /// Wakes up all waiting tasks.
    pub fn wake_all(&self) -> usize {
        if self.is_empty() {
            return 0;
        }

        let mut num_woken = 0;
        loop {
            let mut wakers = self.wakers.lock();
            let Some(waker) = wakers.pop_front() else {
                break;
            };
            self.num_wakers.fetch_sub(1, Ordering::Release);
            drop(wakers);

            if waker.wake_up() {
                num_woken += 1;
            }
        }

        num_woken
    }

    fn is_empty(&self) -> bool {
        self.num_wakers.fetch_add(0, Ordering::Release) == 0
    }

    /// Enqueues a waker to this wait queue.
    #[doc(hidden)]
    pub fn enqueue(&self, waker: Arc<Waker>) {
        let mut wakers = self.wakers.lock();
        wakers.push_back(waker);
        self.num_wakers.fetch_add(1, Ordering::Acquire);
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A waiter that can put the current task to sleep.
pub struct Waiter {
    waker: Arc<Waker>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// A waker associated with a task.
pub struct Waker {
    has_woken: AtomicBool,
    host_wait_queue: host_sync::WaitQueue,
    task: Arc<Task>,
}

impl Waiter {
    /// Creates a waiter and its associated waker.
    pub fn new_pair() -> (Self, Arc<Waker>) {
        let task = Task::current().unwrap().cloned();
        let waker = Arc::new(Waker {
            has_woken: AtomicBool::new(false),
            host_wait_queue: host_sync::WaitQueue::new(),
            task,
        });
        let waiter = Self {
            waker: waker.clone(),
            _not_send_or_sync: PhantomData,
        };
        (waiter, waker)
    }

    /// Waits until the associated waker wakes this waiter.
    #[track_caller]
    pub fn wait(&self) {
        self.waker.do_wait();
    }

    /// Waits until `cond` is met or `cancel_cond` returns an error.
    #[track_caller]
    pub fn wait_until_or_cancelled<F, R, FCancel, E>(
        &self,
        mut cond: F,
        cancel_cond: FCancel,
    ) -> Result<R, E>
    where
        F: FnMut() -> Option<R>,
        FCancel: Fn() -> Result<(), E>,
    {
        loop {
            if let Some(result) = cond() {
                return Ok(result);
            }

            if let Err(error) = cancel_cond() {
                self.waker.close();
                return cond().ok_or(error);
            }

            self.wait();
        }
    }

    /// Returns the associated waker.
    pub fn waker(&self) -> Arc<Waker> {
        self.waker.clone()
    }

    /// Returns the task that the associated waker wakes.
    pub fn task(&self) -> &Arc<Task> {
        &self.waker.task
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.waker.close();
    }
}

impl Waker {
    /// Wakes up the associated task.
    pub fn wake_up(&self) -> bool {
        if self.has_woken.swap(true, Ordering::Release) {
            return false;
        }

        scheduler::unpark_target(self.task.clone());
        self.host_wait_queue.wake_all();
        true
    }

    #[track_caller]
    fn do_wait(&self) {
        while !self.has_woken.swap(false, Ordering::Acquire) {
            let _ = scheduler::park_current(|| self.has_woken.load(Ordering::Acquire));
            self.host_wait_queue
                .wait_until(|| self.has_woken.load(Ordering::Acquire).then_some(()));
        }
    }

    fn close(&self) {
        let _ = self.has_woken.swap(true, Ordering::Acquire);
        self.host_wait_queue.wake_all();
    }
}
