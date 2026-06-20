// SPDX-License-Identifier: MPL-2.0

//! Polling primitives copied in shape from the kernel `Poller`/`Pollee` model.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicBool, AtomicIsize, Ordering},
    time::Duration,
};

use ostd::{
    sync::{Waiter, Waker},
    task::Task,
};

use crate::{
    error::{Errno, Error, Result},
    events::{IoEvents, Observer, SyncSubject},
    time,
};

/// An I/O object that can be polled for readiness events.
#[derive(Clone)]
pub struct Pollee {
    inner: Arc<PolleeInner>,
}

struct PolleeInner {
    subject: SyncSubject<IoEvents, IoEvents>,
    state: AtomicIsize,
}

const INV_STATE: isize = -1;

impl Pollee {
    /// Creates a new pollee.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(PolleeInner {
                subject: SyncSubject::new(),
                state: AtomicIsize::new(INV_STATE),
            }),
        }
    }

    /// Registers `poller`, checks current readiness, and returns matching events.
    ///
    /// If readiness was cached and not invalidated, this returns the cached events.
    /// Otherwise it checks readiness after registration so a notification cannot be
    /// lost between polling and sleeping.
    pub fn poll_with(
        &self,
        mask: IoEvents,
        poller: Option<&mut PollHandle>,
        check: impl FnOnce() -> IoEvents,
    ) -> IoEvents {
        let mask = mask | IoEvents::ALWAYS_POLL;

        if let Some(poller) = poller {
            self.register_poller(poller, mask);
        }

        let events = self.inner.state.load(Ordering::Acquire);
        if events >= 0 {
            return IoEvents::from_bits_truncate(events as _) & mask;
        }

        if events != INV_STATE {
            return check() & mask;
        }

        const {
            use ostd::mm::KERNEL_VADDR_RANGE;
            assert!((KERNEL_VADDR_RANGE.start as isize) < 0);
        }
        let Some(current_task) = Task::current() else {
            return check() & mask;
        };
        let task_ptr = current_task.as_ref() as *const _ as isize;

        let _ = self.inner.state.swap(task_ptr, Ordering::Acquire);
        let new_events = check();

        let _ = self.inner.state.compare_exchange_weak(
            task_ptr,
            new_events.bits() as _,
            Ordering::Release,
            Ordering::Relaxed,
        );

        new_events & mask
    }

    /// Registers a poller without checking readiness.
    pub fn register_poller(&self, poller: &mut PollHandle, mask: IoEvents) {
        self.inner
            .subject
            .register_observer(poller.observer.clone(), mask);
        poller.pollees.push(Arc::downgrade(&self.inner));
    }

    /// Notifies pollers about readiness changes.
    pub fn notify(&self, events: IoEvents) {
        self.invalidate();
        self.inner.subject.notify_observers(&events);
    }

    /// Invalidates cached readiness when old events may have disappeared.
    pub fn invalidate(&self) {
        self.inner.state.store(INV_STATE, Ordering::Release);
    }
}

impl Default for Pollee {
    fn default() -> Self {
        Self::new()
    }
}

/// An opaque handle used by pollable objects to register wake interest.
pub struct PollHandle {
    observer: Weak<dyn Observer<IoEvents>>,
    pollees: Vec<Weak<PolleeInner>>,
}

impl PollHandle {
    /// Constructs a new handle with the observer.
    ///
    /// Note: It is a logic error to construct multiple handles with the same observer.
    pub fn new(observer: Weak<dyn Observer<IoEvents>>) -> Self {
        Self {
            observer,
            pollees: Vec::new(),
        }
    }

    fn reset(&mut self) {
        for pollee in self.pollees.iter().filter_map(Weak::upgrade) {
            pollee.subject.unregister_observer(&self.observer);
        }
        self.pollees.clear();
    }

    /// Returns whether this handle is registered on at least one pollee.
    pub fn has_registrations(&self) -> bool {
        !self.pollees.is_empty()
    }
}

impl Drop for PollHandle {
    fn drop(&mut self) {
        self.reset();
    }
}

/// An adaptor to make an [`Observer`] usable for [`Pollable::poll`].
pub struct PollAdaptor<O> {
    observer: Arc<O>,
    inner: PollHandle,
}

#[expect(
    dead_code,
    reason = "Keep the kernel poll API shape for copied modules"
)]
impl<O: Observer<IoEvents> + 'static> PollAdaptor<O> {
    /// Constructs a new adaptor with the specified observer.
    pub fn with_observer(observer: O) -> Self {
        let observer = Arc::new(observer);
        let inner = PollHandle::new(Arc::downgrade(&observer) as _);

        Self { observer, inner }
    }
}

impl<O> PollAdaptor<O> {
    /// Gets a reference to the observer.
    #[expect(dead_code, reason = "Keep this `Arc` to avoid dropping the observer")]
    pub fn observer(&self) -> &Arc<O> {
        &self.observer
    }

    /// Returns a mutable reference of [`PollHandle`].
    #[expect(
        dead_code,
        reason = "Keep the kernel poll API shape for copied modules"
    )]
    pub fn as_handle_mut(&mut self) -> &mut PollHandle {
        &mut self.inner
    }
}

/// A poller that waits until one of its registered pollees notifies events.
pub struct Poller {
    poller: PollHandle,
    waiter: Waiter,
    observer: Arc<PollWakeObserver>,
    deadline_ns: Option<u64>,
}

struct PollWakeObserver {
    waker: Arc<Waker>,
    has_events: AtomicBool,
}

impl Poller {
    /// Creates a new poller.
    pub fn new(timeout: Option<&Duration>) -> Result<Self> {
        let (waiter, waker) = Waiter::new_pair();
        let observer = Arc::new(PollWakeObserver {
            waker,
            has_events: AtomicBool::new(false),
        });
        Ok(Self {
            poller: PollHandle::new(Arc::downgrade(&observer) as Weak<dyn Observer<IoEvents>>),
            waiter,
            observer,
            deadline_ns: timeout.map(deadline_from_duration).transpose()?,
        })
    }

    /// Returns the mutable poll handle passed to pollable objects.
    pub fn as_handle_mut(&mut self) -> &mut PollHandle {
        &mut self.poller
    }

    /// Returns whether the poller was registered on at least one pollee.
    #[expect(dead_code, reason = "Keep the kernel poll API shape")]
    pub fn has_registrations(&self) -> bool {
        self.poller.has_registrations()
    }

    /// Waits until any registered event arrives.
    pub fn wait(&self) -> Result<()> {
        let Some(deadline_ns) = self.deadline_ns else {
            self.waiter.wait();
            return Ok(());
        };

        let timeout = time::TimeoutRegistration::new(deadline_ns, self.waiter.waker())?;
        loop {
            if self.observer.take_events() {
                return Ok(());
            }
            if timeout.has_expired() || time::is_deadline_elapsed(deadline_ns)? {
                return Err(Error::new(Errno::ETIME));
            }
            self.waiter.wait();
        }
    }
}

impl PollWakeObserver {
    fn take_events(&self) -> bool {
        self.has_events.swap(false, Ordering::Acquire)
    }
}

impl Observer<IoEvents> for PollWakeObserver {
    fn on_events(&self, _events: &IoEvents) {
        self.has_events.store(true, Ordering::Release);
        self.waker.wake_up();
    }
}

fn deadline_from_duration(timeout: &Duration) -> Result<u64> {
    time::deadline_after(timeout)
}

impl Observer<IoEvents> for Waker {
    fn on_events(&self, _events: &IoEvents) {
        self.wake_up();
    }
}

/// Allows waiting for events and performing event-based operations.
#[expect(
    dead_code,
    reason = "Keep the kernel poll API shape for copied modules"
)]
pub trait Pollable {
    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// poller is provided.
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents;

    /// Waits for events and performs event-based operations.
    #[track_caller]
    fn wait_events<F, R>(
        &self,
        mask: IoEvents,
        timeout: Option<&Duration>,
        mut try_op: F,
    ) -> Result<R>
    where
        Self: Sized,
        F: FnMut() -> Result<R>,
    {
        match try_op() {
            Err(error) if error.errno() == Errno::EAGAIN => (),
            result => return result,
        }

        if timeout.is_some_and(Duration::is_zero) {
            return Err(Error::new(Errno::ETIME));
        }

        let mut poller = Poller::new(timeout)?;
        if self.poll(mask, Some(poller.as_handle_mut())).is_empty() {
            poller.wait()?;
        }

        loop {
            match try_op() {
                Err(error) if error.errno() == Errno::EAGAIN => (),
                result => return result,
            }
            poller.wait()?;
        }
    }
}
