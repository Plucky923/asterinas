// SPDX-License-Identifier: MPL-2.0

//! Per-FrameVM physical-memory accounting.
//!
//! `MemoryDomain` is deliberately smaller than an allocator.  It owns the
//! admission counters for one VM and leaves object allocation to the
//! OSTD-shaped providers.  Keeping the accounting here gives every backing
//! path the same limit and rollback semantics without changing Host OSTD.

use alloc::sync::Arc;
#[cfg(ktest)]
use core::sync::atomic::{AtomicBool, AtomicUsize};
use core::sync::atomic::{AtomicU64, Ordering};

use host_ostd::sync::WaitQueue;

use crate::{Error, mm::PAGE_SIZE, prelude::Result, sync::SpinLock};

/// Lifecycle of a VM memory domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryDomainState {
    /// New backing may be granted.
    Accepting,
    /// New backing is rejected while existing references drain.
    Stopping,
    /// No further accounting transition is allowed.
    Closed,
}

#[derive(Debug)]
struct MemoryCounters {
    physical_committed: usize,
    host_committed: usize,
    rref_committed: usize,
    reserved: usize,
    reusable: usize,
    oom_count: u64,
    reclaim_count: u64,
}

/// Stable, read-only accounting snapshot for one VM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryStats {
    /// Configured page-rounded limit.
    pub limit: usize,
    /// Physical Frame/Segment backing granted to this domain.
    pub physical_committed: usize,
    /// Host-owned resources, such as service-task stacks, charged to this domain.
    pub host_committed: usize,
    /// Shared-heap payload charge currently attributed to this domain.
    pub shared_heap_committed: usize,
    /// Bytes currently charged to the domain, including physical cached
    /// extents and logical shared-heap payloads.
    pub committed: usize,
    /// Bytes reserved by an in-flight allocation transaction.
    pub reserved: usize,
    /// Physical bytes that no longer contain live VM objects.
    pub reusable: usize,
    /// Charged bytes that currently contain live VM state.
    pub active: usize,
    /// Number of domain-limit allocation failures.
    pub oom_count: u64,
    /// Number of cached extents returned to Host.
    pub reclaim_count: u64,
}

/// Per-FrameVM physical-memory admission and accounting state.
#[derive(Clone)]
pub(crate) struct MemoryDomain {
    inner: Arc<MemoryDomainInner>,
}

struct MemoryDomainInner {
    limit: usize,
    generation: AtomicU64,
    state: SpinLock<MemoryDomainState>,
    counters: SpinLock<MemoryCounters>,
    reservations_drained: WaitQueue,
    #[cfg(ktest)]
    reservation_delay: SpinLock<Option<Arc<ReservationDelay>>>,
}

/// Pauses successful test reservations after admission, without holding a
/// domain lock. The test releases this gate after observing the in-flight
/// counters, making concurrent admission deterministic.
#[cfg(ktest)]
pub(crate) struct ReservationDelay {
    entered: AtomicUsize,
    target: usize,
    released: AtomicBool,
    wait_queue: WaitQueue,
}

#[cfg(ktest)]
impl ReservationDelay {
    pub(crate) fn new(target: usize) -> Self {
        assert!(target != 0);
        Self {
            entered: AtomicUsize::new(0),
            target,
            released: AtomicBool::new(false),
            wait_queue: WaitQueue::new(),
        }
    }

    fn wait_after_admission(&self) {
        let entered = self.entered.fetch_add(1, Ordering::AcqRel) + 1;
        self.wait_queue.wake_all();
        if entered <= self.target {
            self.wait_queue
                .wait_until(|| self.released.load(Ordering::Acquire).then_some(()));
        }
    }

    pub(crate) fn wait_until_entered(&self) {
        self.wait_queue
            .wait_until(|| (self.entered.load(Ordering::Acquire) >= self.target).then_some(()));
    }

    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.wait_queue.wake_all();
    }
}

impl MemoryDomain {
    /// Creates a domain after validating a page-rounded startup minimum.
    ///
    /// The minimum is the conservative Host-owned charge required to build a
    /// `FrameVm`. Keeping this check beside limit rounding makes creation and
    /// restart use the same admission rule, before any VM-owned resource is
    /// published.
    pub(crate) fn new_with_minimum(limit_bytes: usize, minimum_bytes: usize) -> Result<Self> {
        let limit = validate_limit(limit_bytes, minimum_bytes)?;
        Ok(Self {
            inner: Arc::new(MemoryDomainInner {
                limit,
                generation: AtomicU64::new(0),
                state: SpinLock::new(MemoryDomainState::Accepting),
                counters: SpinLock::new(MemoryCounters {
                    physical_committed: 0,
                    host_committed: 0,
                    rref_committed: 0,
                    reserved: 0,
                    reusable: 0,
                    oom_count: 0,
                    reclaim_count: 0,
                }),
                reservations_drained: WaitQueue::new(),
                #[cfg(ktest)]
                reservation_delay: SpinLock::new(None),
            }),
        })
    }

    /// Creates a domain with a deterministic reservation gate for ktests.
    #[cfg(ktest)]
    pub(crate) fn new_with_reservation_delay(
        limit_bytes: usize,
        delay: Arc<ReservationDelay>,
    ) -> Result<Self> {
        let domain = Self::new_with_minimum(limit_bytes, 0)?;
        *domain.inner.reservation_delay.lock() = Some(delay);
        Ok(domain)
    }

    /// Validates a configured limit without creating a domain.
    ///
    /// This is used by the registry entry point before reserving a VM ID, so
    /// an invalid limit cannot leave a partially admitted creation attempt.
    pub(crate) fn validate_limit(limit_bytes: usize, minimum_bytes: usize) -> Result<usize> {
        validate_limit(limit_bytes, minimum_bytes)
    }

    /// Returns a consistent accounting snapshot.
    pub(crate) fn stats(&self) -> MemoryStats {
        let state = self.inner.state.lock();
        let counters = self.inner.counters.lock();
        let committed = total_committed(&counters);
        let active = committed.saturating_sub(counters.reusable);
        // Keep the state guard live until the counters have been copied.  The
        // state transition lock is intentionally separate so allocation paths
        // never hold it while touching OSTD.
        let _ = *state;
        MemoryStats {
            limit: self.inner.limit,
            physical_committed: counters.physical_committed,
            host_committed: counters.host_committed,
            shared_heap_committed: counters.rref_committed,
            committed,
            reserved: counters.reserved,
            reusable: counters.reusable,
            active,
            oom_count: counters.oom_count,
            reclaim_count: counters.reclaim_count,
        }
    }

    /// Returns whether two handles refer to the same VM memory domain.
    pub(crate) fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Returns the execution generation that owns new allocations.
    pub(crate) fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    #[cfg(ktest)]
    pub(crate) fn set_generation_for_test(&self, generation: u64) {
        self.inner.generation.store(generation, Ordering::Release);
    }

    /// Charges a Host-owned resource created specifically for this VM.
    ///
    /// Host task stacks and similar control-plane resources are not physical
    /// FrameVisor cache entries, so they use a small RAII charge instead of
    /// entering `FrameOwners`. The charge still participates in the same
    /// limit and is released only after the resource holder is dropped.
    pub(crate) fn charge_host(&self, bytes: usize) -> Result<MemoryCharge> {
        let reservation = self.reserve_host(bytes)?;
        reservation.commit()?;
        Ok(MemoryCharge {
            domain: self.clone(),
            bytes: round_to_page(bytes)?,
        })
    }

    /// Reserves bytes for a new physical backing transaction.
    pub(crate) fn reserve(&self, bytes: usize) -> Result<MemoryReservation<'_>> {
        self.reserve_committed(bytes, ReservationKind::Physical)
    }

    /// Reserves bytes for a Host-owned resource charged to this domain.
    fn reserve_host(&self, bytes: usize) -> Result<MemoryReservation<'_>> {
        self.reserve_committed(bytes, ReservationKind::Host)
    }

    fn reserve_committed(
        &self,
        bytes: usize,
        kind: ReservationKind,
    ) -> Result<MemoryReservation<'_>> {
        let bytes = round_to_page(bytes)?;
        if bytes == 0 {
            return Err(Error::InvalidArgs);
        }

        let state = self.inner.state.lock();
        if *state != MemoryDomainState::Accepting {
            return Err(Error::AccessDenied);
        }

        let mut counters = self.inner.counters.lock();
        let committed_and_reserved = total_committed(&counters)
            .checked_add(counters.reserved)
            .ok_or(Error::Overflow)?;
        if committed_and_reserved
            .checked_add(bytes)
            .ok_or(Error::Overflow)?
            > self.inner.limit
        {
            counters.oom_count = counters.oom_count.saturating_add(1);
            return Err(Error::NoMemory);
        }

        counters.reserved = counters
            .reserved
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        #[cfg(ktest)]
        {
            // The delay must not hold either accounting guard. In production
            // this block disappears with the entire test gate.
            drop(counters);
            drop(state);
            self.wait_after_test_admission();
        }
        Ok(MemoryReservation {
            domain: self,
            bytes,
            kind,
            committed: false,
        })
    }

    #[cfg(ktest)]
    fn wait_after_test_admission(&self) {
        let delay = self.inner.reservation_delay.lock().as_ref().cloned();
        if let Some(delay) = delay {
            delay.wait_after_admission();
        }
    }

    /// Reserves bytes that will consume already cached backing.
    pub(crate) fn reserve_reusable(&self, bytes: usize) -> Result<MemoryReservation<'_>> {
        let bytes = round_to_page(bytes)?;
        if bytes == 0 {
            return Err(Error::InvalidArgs);
        }

        let state = self.inner.state.lock();
        if *state != MemoryDomainState::Accepting {
            return Err(Error::AccessDenied);
        }

        let mut counters = self.inner.counters.lock();
        let active_and_reserved = total_committed(&counters)
            .checked_sub(counters.reusable)
            .ok_or(Error::InvalidArgs)?
            .checked_add(counters.reserved)
            .ok_or(Error::Overflow)?;
        if bytes > counters.reusable {
            return Err(Error::InvalidArgs);
        }
        if active_and_reserved
            .checked_add(bytes)
            .ok_or(Error::Overflow)?
            > self.inner.limit
        {
            counters.oom_count = counters.oom_count.saturating_add(1);
            return Err(Error::NoMemory);
        }

        let physical_committed = counters
            .physical_committed
            .checked_sub(bytes)
            .ok_or(Error::InvalidArgs)?;
        let reusable = counters
            .reusable
            .checked_sub(bytes)
            .ok_or(Error::InvalidArgs)?;
        counters.reserved = counters
            .reserved
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        // Reserve the cached bytes themselves as part of the transaction.
        // Otherwise two concurrent callers could both observe the same cached
        // page and one of their commits would fail after taking ownership.
        counters.physical_committed = physical_committed;
        counters.reusable = reusable;
        Ok(MemoryReservation {
            domain: self,
            bytes,
            kind: ReservationKind::Reusable,
            committed: false,
        })
    }

    /// Reserves logical charge for one shared-heap `RRef` payload.
    pub(crate) fn reserve_rref(&self, bytes: usize) -> Result<MemoryReservation<'_>> {
        let bytes = round_to_page(bytes.max(1))?;
        let state = self.inner.state.lock();
        if *state != MemoryDomainState::Accepting {
            return Err(Error::AccessDenied);
        }

        let mut counters = self.inner.counters.lock();
        let committed_and_reserved = total_committed(&counters)
            .checked_add(counters.reserved)
            .and_then(|value| value.checked_add(bytes))
            .ok_or(Error::Overflow)?;
        if committed_and_reserved > self.inner.limit {
            counters.oom_count = counters.oom_count.saturating_add(1);
            return Err(Error::NoMemory);
        }

        counters.reserved = counters
            .reserved
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        Ok(MemoryReservation {
            domain: self,
            bytes,
            kind: ReservationKind::Logical,
            committed: false,
        })
    }

    /// Marks bytes as reusable after the final VM-visible reference is gone.
    pub(crate) fn cache(&self, bytes: usize) -> Result<()> {
        let bytes = round_to_page(bytes)?;
        let state = self.inner.state.lock();
        if *state != MemoryDomainState::Accepting {
            return Err(Error::AccessDenied);
        }
        let mut counters = self.inner.counters.lock();
        let active = counters
            .physical_committed
            .checked_sub(counters.reusable)
            .ok_or(Error::InvalidArgs)?;
        if bytes > active {
            return Err(Error::InvalidArgs);
        }
        counters.reusable = counters
            .reusable
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Drops committed bytes after Host OSTD has received the physical extent.
    pub(crate) fn release(&self, bytes: usize, cached: bool) -> Result<()> {
        let bytes = round_to_page(bytes)?;
        let mut counters = self.inner.counters.lock();
        if bytes > counters.physical_committed {
            return Err(Error::InvalidArgs);
        }
        let active = counters
            .physical_committed
            .checked_sub(counters.reusable)
            .ok_or(Error::InvalidArgs)?;
        if !cached && bytes > active {
            return Err(Error::InvalidArgs);
        }
        if cached && bytes > counters.reusable {
            return Err(Error::InvalidArgs);
        }
        if cached {
            counters.reusable -= bytes;
        }
        counters.physical_committed -= bytes;
        Ok(())
    }

    /// Releases a Host-owned resource charge after its holder is dropped.
    fn release_host(&self, bytes: usize) -> Result<()> {
        let bytes = round_to_page(bytes)?;
        let mut counters = self.inner.counters.lock();
        if bytes > counters.host_committed {
            return Err(Error::InvalidArgs);
        }
        counters.host_committed -= bytes;
        Ok(())
    }

    /// Releases a previously charged shared-heap `RRef` payload.
    pub(crate) fn release_rref(&self, bytes: usize) -> Result<()> {
        let bytes = round_to_page(bytes.max(1))?;
        let mut counters = self.inner.counters.lock();
        if bytes > counters.rref_committed {
            return Err(Error::InvalidArgs);
        }
        counters.rref_committed -= bytes;
        Ok(())
    }

    /// Starts teardown and rejects all new reservations.
    pub(crate) fn begin_stopping(&self) -> bool {
        let mut state = self.inner.state.lock();
        if *state != MemoryDomainState::Accepting {
            return false;
        }
        *state = MemoryDomainState::Stopping;
        true
    }

    /// Waits until allocations admitted before stopping finish their
    /// commit/rollback transaction.
    pub(crate) fn wait_for_reservations(&self) {
        self.inner
            .reservations_drained
            .wait_until(|| (self.inner.counters.lock().reserved == 0).then_some(()));
    }

    /// Reopens an empty domain for a new execution generation.
    pub(crate) fn resume(&self) -> Result<()> {
        let mut state = self.inner.state.lock();
        if *state == MemoryDomainState::Accepting {
            return Ok(());
        }
        if *state != MemoryDomainState::Stopping {
            return Err(Error::AccessDenied);
        }

        let counters = self.inner.counters.lock();
        if total_committed(&counters) != 0
            || counters.reserved != 0
            || crate::mm::ownership::has_domain_records(self)
        {
            return Err(Error::AccessDenied);
        }
        drop(counters);
        if self
            .inner
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .is_err()
        {
            return Err(Error::Overflow);
        }
        *state = MemoryDomainState::Accepting;
        Ok(())
    }

    /// Closes an already-stopping domain after all owner references drain.
    pub(crate) fn close(&self) -> Result<()> {
        let mut state = self.inner.state.lock();
        if *state != MemoryDomainState::Stopping {
            return Err(Error::InvalidArgs);
        }
        let counters = self.inner.counters.lock();
        if total_committed(&counters) != 0
            || counters.reserved != 0
            || crate::mm::ownership::has_domain_records(self)
        {
            return Err(Error::AccessDenied);
        }
        drop(counters);
        *state = MemoryDomainState::Closed;
        Ok(())
    }

    fn commit_reservation(&self, bytes: usize, kind: ReservationKind) -> Result<()> {
        let mut counters = self.inner.counters.lock();
        if counters.reserved < bytes {
            return Err(Error::InvalidArgs);
        }

        match kind {
            ReservationKind::Physical => {
                let committed = counters
                    .physical_committed
                    .checked_add(bytes)
                    .ok_or(Error::Overflow)?;
                counters.reserved -= bytes;
                counters.physical_committed = committed;
            }
            ReservationKind::Host => {
                let committed = counters
                    .host_committed
                    .checked_add(bytes)
                    .ok_or(Error::Overflow)?;
                counters.reserved -= bytes;
                counters.host_committed = committed;
            }
            ReservationKind::Reusable => {
                let committed = counters
                    .physical_committed
                    .checked_add(bytes)
                    .ok_or(Error::Overflow)?;
                counters.reserved -= bytes;
                counters.physical_committed = committed;
            }
            ReservationKind::Logical => {
                let committed = counters
                    .rref_committed
                    .checked_add(bytes)
                    .ok_or(Error::Overflow)?;
                counters.reserved -= bytes;
                counters.rref_committed = committed;
            }
        }
        let drained = counters.reserved == 0;
        drop(counters);
        if drained {
            self.inner.reservations_drained.wake_all();
        }
        Ok(())
    }

    fn rollback_reservation(&self, bytes: usize, kind: ReservationKind) {
        let mut counters = self.inner.counters.lock();
        counters.reserved = counters.reserved.saturating_sub(bytes);
        if matches!(kind, ReservationKind::Reusable) {
            counters.physical_committed = counters.physical_committed.saturating_add(bytes);
            counters.reusable = counters.reusable.saturating_add(bytes);
        }
        let drained = counters.reserved == 0;
        drop(counters);
        if drained {
            self.inner.reservations_drained.wake_all();
        }
    }

    pub(crate) fn record_reclaim(&self) {
        let mut counters = self.inner.counters.lock();
        counters.reclaim_count = counters.reclaim_count.saturating_add(1);
    }
}

/// A fallible reservation that automatically rolls back when not committed.
pub(crate) struct MemoryReservation<'a> {
    domain: &'a MemoryDomain,
    bytes: usize,
    kind: ReservationKind,
    committed: bool,
}

/// RAII charge for a Host-owned per-FrameVM resource.
pub(crate) struct MemoryCharge {
    domain: MemoryDomain,
    bytes: usize,
}

impl Drop for MemoryCharge {
    fn drop(&mut self) {
        if self.domain.release_host(self.bytes).is_err() {
            ::log::error!("[framevisor] failed to release a Host-owned FrameVM charge");
        }
    }
}

#[derive(Clone, Copy)]
enum ReservationKind {
    Physical,
    Host,
    Logical,
    Reusable,
}

impl MemoryReservation<'_> {
    /// Commits the reservation after its backing has been acquired.
    pub(crate) fn commit(mut self) -> Result<()> {
        self.domain.commit_reservation(self.bytes, self.kind)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for MemoryReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.domain.rollback_reservation(self.bytes, self.kind);
        }
    }
}

fn round_to_page(bytes: usize) -> Result<usize> {
    if bytes == 0 {
        return Ok(0);
    }
    let mask = PAGE_SIZE.checked_sub(1).ok_or(Error::Overflow)?;
    bytes
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(Error::Overflow)
}

fn validate_limit(limit_bytes: usize, minimum_bytes: usize) -> Result<usize> {
    if limit_bytes == 0 {
        return Err(Error::InvalidArgs);
    }
    let limit = round_to_page(limit_bytes)?;
    let minimum = round_to_page(minimum_bytes)?;
    if limit < minimum {
        return Err(Error::NoMemory);
    }
    Ok(limit)
}

fn total_committed(counters: &MemoryCounters) -> usize {
    counters
        .physical_committed
        .saturating_add(counters.host_committed)
        .saturating_add(counters.rref_committed)
}

#[cfg(ktest)]
mod tests {
    use host_ostd::task::TaskOptions;
    use ostd::prelude::ktest;

    use super::*;

    struct TestBarrier {
        arrived: AtomicUsize,
        participants: usize,
        wait_queue: WaitQueue,
    }

    impl TestBarrier {
        fn new(participants: usize) -> Self {
            assert!(participants != 0);
            Self {
                arrived: AtomicUsize::new(0),
                participants,
                wait_queue: WaitQueue::new(),
            }
        }

        fn wait(&self) {
            self.arrived.fetch_add(1, Ordering::AcqRel);
            self.wait_queue.wake_all();
            self.wait_queue.wait_until(|| {
                (self.arrived.load(Ordering::Acquire) >= self.participants).then_some(())
            });
        }
    }

    #[ktest]
    fn rounds_limit_and_tracks_active_and_reusable_bytes() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE + 1, 0).unwrap();
        assert_eq!(domain.stats().limit, PAGE_SIZE * 2);

        let reservation = domain.reserve(PAGE_SIZE).unwrap();
        reservation.commit().unwrap();
        assert_eq!(domain.stats().active, PAGE_SIZE);

        domain.cache(PAGE_SIZE).unwrap();
        assert_eq!(domain.stats().reusable, PAGE_SIZE);
        assert_eq!(domain.stats().active, 0);
        domain.release(PAGE_SIZE, true).unwrap();
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn validates_startup_floor_before_domain_creation() {
        assert!(matches!(
            MemoryDomain::validate_limit(PAGE_SIZE, PAGE_SIZE * 2),
            Err(Error::NoMemory)
        ));
        assert_eq!(
            MemoryDomain::validate_limit(PAGE_SIZE + 1, PAGE_SIZE).unwrap(),
            PAGE_SIZE * 2
        );
    }

    #[ktest]
    fn rejects_limit_rounding_overflow() {
        assert!(matches!(
            MemoryDomain::validate_limit(usize::MAX, 0),
            Err(Error::Overflow)
        ));
    }

    #[ktest]
    fn combines_physical_host_and_shared_heap_charges() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE * 4, 0).unwrap();

        let physical = domain.reserve(PAGE_SIZE).unwrap();
        physical.commit().unwrap();
        let host = domain.charge_host(PAGE_SIZE).unwrap();
        let shared = domain.reserve_rref(1).unwrap();
        shared.commit().unwrap();

        let stats = domain.stats();
        assert_eq!(stats.physical_committed, PAGE_SIZE);
        assert_eq!(stats.host_committed, PAGE_SIZE);
        assert_eq!(stats.shared_heap_committed, PAGE_SIZE);
        assert_eq!(stats.committed, PAGE_SIZE * 3);
        assert_eq!(stats.active, PAGE_SIZE * 3);
        assert!(stats.committed + stats.reserved <= stats.limit);

        domain.release(PAGE_SIZE, false).unwrap();
        domain.release_rref(1).unwrap();
        drop(host);
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn uncommitted_reservation_rolls_back() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let reservation = domain.reserve(PAGE_SIZE).unwrap();
        assert_eq!(domain.stats().reserved, PAGE_SIZE);
        drop(reservation);
        assert_eq!(domain.stats().reserved, 0);
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn limit_rejects_active_and_reserved_bytes() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let reservation = domain.reserve(PAGE_SIZE).unwrap();
        assert!(matches!(domain.reserve(PAGE_SIZE), Err(Error::NoMemory)));
        reservation.commit().unwrap();
        assert!(matches!(domain.reserve(PAGE_SIZE), Err(Error::NoMemory)));
        assert_eq!(domain.stats().oom_count, 2);
    }

    #[ktest]
    fn host_charge_obeys_limit_and_releases_with_owner() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let charge = domain.charge_host(PAGE_SIZE).unwrap();
        assert_eq!(domain.stats().active, PAGE_SIZE);
        assert!(matches!(
            domain.charge_host(PAGE_SIZE),
            Err(Error::NoMemory)
        ));
        drop(charge);
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn rref_charge_uses_page_granularity() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let reservation = domain.reserve_rref(1).unwrap();
        reservation.commit().unwrap();
        assert_eq!(domain.stats().committed, PAGE_SIZE);
        domain.release_rref(1).unwrap();
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn rref_reservation_rolls_back_without_a_live_payload() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let reservation = domain.reserve_rref(1).unwrap();
        assert_eq!(domain.stats().reserved, PAGE_SIZE);
        drop(reservation);

        let stats = domain.stats();
        assert_eq!(stats.committed, 0);
        assert_eq!(stats.reserved, 0);
        assert_eq!(stats.shared_heap_committed, 0);
    }

    #[ktest]
    fn stopping_rejects_new_reservations_and_close_waits_for_release() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let reservation = domain.reserve(PAGE_SIZE).unwrap();
        reservation.commit().unwrap();
        assert!(domain.begin_stopping());
        assert!(matches!(
            domain.reserve(PAGE_SIZE),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            domain.charge_host(PAGE_SIZE),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            domain.reserve_rref(PAGE_SIZE),
            Err(Error::AccessDenied)
        ));
        assert_eq!(domain.cache(PAGE_SIZE), Err(Error::AccessDenied));
        assert!(!domain.begin_stopping());
        assert_eq!(domain.close().unwrap_err(), Error::AccessDenied);
        domain.release(PAGE_SIZE, false).unwrap();
        assert!(domain.close().is_ok());
        assert_eq!(domain.close(), Err(Error::InvalidArgs));
    }

    #[ktest]
    fn reusable_reservation_is_exclusive_and_rolls_back() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let reservation = domain.reserve(PAGE_SIZE).unwrap();
        reservation.commit().unwrap();
        domain.cache(PAGE_SIZE).unwrap();

        let reservation = domain.reserve_reusable(PAGE_SIZE).unwrap();
        assert_eq!(domain.stats().reusable, 0);
        assert_eq!(
            domain.stats().committed + domain.stats().reserved,
            PAGE_SIZE
        );
        assert!(matches!(
            domain.reserve_reusable(PAGE_SIZE),
            Err(Error::InvalidArgs | Error::NoMemory)
        ));
        drop(reservation);
        assert_eq!(domain.stats().reusable, PAGE_SIZE);
        assert_eq!(
            domain.stats().committed + domain.stats().reserved,
            PAGE_SIZE
        );
    }

    #[ktest]
    fn reusable_reservation_commit_moves_cached_bytes_to_active() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        domain.reserve(PAGE_SIZE).unwrap().commit().unwrap();
        domain.cache(PAGE_SIZE).unwrap();

        let reservation = domain.reserve_reusable(PAGE_SIZE).unwrap();
        let pending = domain.stats();
        assert_eq!(pending.committed + pending.reserved, pending.limit);
        assert_eq!(pending.active + pending.reusable, pending.committed);

        reservation.commit().unwrap();
        let committed = domain.stats();
        assert_eq!(committed.active, PAGE_SIZE);
        assert_eq!(committed.reusable, 0);
        assert_eq!(committed.committed + committed.reserved, committed.limit);
        domain.release(PAGE_SIZE, false).unwrap();
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn active_release_cannot_discard_cached_bytes() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        domain.reserve(PAGE_SIZE).unwrap().commit().unwrap();
        domain.cache(PAGE_SIZE).unwrap();

        assert_eq!(domain.release(PAGE_SIZE, false), Err(Error::InvalidArgs));
        assert_eq!(domain.stats().committed, PAGE_SIZE);
        assert_eq!(domain.stats().reusable, PAGE_SIZE);
        domain.release(PAGE_SIZE, true).unwrap();
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn concurrent_reservations_with_delay_never_cross_limit() {
        const WORKERS: usize = 4;
        const WINNERS: usize = 2;

        let delay = Arc::new(ReservationDelay::new(WINNERS));
        let domain =
            MemoryDomain::new_with_reservation_delay(PAGE_SIZE * WINNERS, delay.clone()).unwrap();
        let baseline = domain.stats();
        let start_barrier = Arc::new(TestBarrier::new(WORKERS));
        let finished = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(baseline.committed + baseline.reserved));
        let finished_wait = Arc::new(WaitQueue::new());

        for _ in 0..WORKERS {
            let domain = domain.clone();
            let start_barrier = start_barrier.clone();
            let finished = finished.clone();
            let peak = peak.clone();
            let finished_wait = finished_wait.clone();
            TaskOptions::new(move || {
                start_barrier.wait();

                let reservation = domain.reserve(PAGE_SIZE).ok();
                if let Some(reservation) = reservation {
                    let stats = domain.stats();
                    peak.fetch_max(stats.committed + stats.reserved, Ordering::AcqRel);
                    reservation.commit().unwrap();
                    let stats = domain.stats();
                    peak.fetch_max(stats.committed + stats.reserved, Ordering::AcqRel);
                    domain.release(PAGE_SIZE, false).unwrap();
                }

                finished.fetch_add(1, Ordering::Release);
                finished_wait.wake_all();
            })
            .data(())
            .spawn()
            .unwrap();
        }

        // The injected gate holds every admitted winner after it has charged
        // `reserved`, while the start barrier guarantees all workers contend
        // in the same generation. This observation occurs without any domain
        // lock held by the delayed workers.
        delay.wait_until_entered();
        let pending = domain.stats();
        let pending_invariant = pending.committed + pending.reserved <= pending.limit;
        let pending_reservations = pending.reserved;
        delay.release();

        finished_wait.wait_until(|| (finished.load(Ordering::Acquire) == WORKERS).then_some(()));
        let final_stats = domain.stats();
        assert!(pending_invariant);
        assert_eq!(pending_reservations, PAGE_SIZE * WINNERS);
        assert!(peak.load(Ordering::Acquire) <= baseline.limit);
        assert_eq!(final_stats.limit, baseline.limit);
        assert_eq!(final_stats.physical_committed, baseline.physical_committed);
        assert_eq!(final_stats.host_committed, baseline.host_committed);
        assert_eq!(
            final_stats.shared_heap_committed,
            baseline.shared_heap_committed
        );
        assert_eq!(final_stats.committed, baseline.committed);
        assert_eq!(final_stats.reserved, baseline.reserved);
        assert_eq!(final_stats.reusable, baseline.reusable);
        assert_eq!(final_stats.active, baseline.active);
        assert_eq!(final_stats.reclaim_count, baseline.reclaim_count);
        assert_eq!(
            final_stats.oom_count,
            baseline.oom_count + (WORKERS - WINNERS) as u64
        );
    }

    #[ktest]
    fn stopped_empty_domain_can_resume() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        assert_eq!(domain.generation(), 0);
        assert!(domain.begin_stopping());
        assert!(domain.resume().is_ok());
        assert_eq!(domain.generation(), 1);
        assert!(domain.reserve(PAGE_SIZE).is_ok());
    }

    #[ktest]
    fn repeated_stop_resume_cycles_preserve_generation_and_accounting() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE * 2, 0).unwrap();
        let baseline = domain.stats();

        let first = domain.reserve(PAGE_SIZE).unwrap();
        first.commit().unwrap();
        assert!(domain.begin_stopping());
        assert!(!domain.begin_stopping());
        assert_eq!(domain.generation(), 0);
        assert!(matches!(
            domain.reserve(PAGE_SIZE),
            Err(Error::AccessDenied)
        ));
        assert_eq!(domain.resume(), Err(Error::AccessDenied));

        domain.release(PAGE_SIZE, false).unwrap();
        assert!(domain.resume().is_ok());
        assert_eq!(domain.generation(), 1);
        assert!(domain.resume().is_ok());
        assert_eq!(domain.generation(), 1);

        let second = domain.reserve(PAGE_SIZE).unwrap();
        second.commit().unwrap();
        domain.release(PAGE_SIZE, false).unwrap();
        assert!(domain.begin_stopping());
        assert!(domain.resume().is_ok());
        assert_eq!(domain.generation(), 2);

        assert!(domain.begin_stopping());
        assert!(domain.close().is_ok());
        assert_eq!(domain.generation(), 2);
        assert!(matches!(
            domain.reserve(PAGE_SIZE),
            Err(Error::AccessDenied)
        ));
        assert_eq!(domain.resume(), Err(Error::AccessDenied));
        assert!(!domain.begin_stopping());
        assert_eq!(domain.stats(), baseline);
    }

    #[ktest]
    fn generation_overflow_keeps_domain_stopped() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        domain.inner.generation.store(u64::MAX, Ordering::Release);
        assert!(domain.begin_stopping());
        assert_eq!(domain.resume(), Err(Error::Overflow));
        assert_eq!(domain.generation(), u64::MAX);
    }
}
