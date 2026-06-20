// SPDX-License-Identifier: MPL-2.0

//! Kernel-local time helpers.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use ostd::{
    boot,
    cpu::{self, CpuSet},
    sync::{Once, SpinLock, Waiter, Waker},
    timer,
};

use crate::error::{Errno, Error, Result};

const NANOS_PER_SEC: u64 = 1_000_000_000;
const TIMEOUT_WAITING: u8 = 0;
const TIMEOUT_EXPIRED: u8 = 1;
const TIMEOUT_CANCELLED: u8 = 2;

/// Initializes timer-driven timeout handling on the current CPU.
pub fn init() {
    let cpu_id = cpu::CpuId::current_racy();
    let should_register = {
        let registered_cpus =
            TIMEOUT_TIMER_REGISTERED_CPUS.call_once(|| SpinLock::new(CpuSet::new_empty()));
        let mut registered_cpus = registered_cpus.lock();
        if registered_cpus.contains(cpu_id) {
            false
        } else {
            registered_cpus.add(cpu_id);
            true
        }
    };

    if should_register {
        timer::register_callback_on_cpu(wake_expired_timeouts);
    }
}

/// Returns a monotonic timestamp in nanoseconds.
pub fn monotonic_ns() -> Option<u64> {
    let freq = ostd::arch::tsc_freq();
    if freq == 0 {
        return None;
    }

    let tsc = ostd::arch::read_tsc();
    let sec = tsc / freq;
    let nsec = (tsc % freq).checked_mul(NANOS_PER_SEC)?.checked_div(freq)?;
    sec.checked_mul(NANOS_PER_SEC)?.checked_add(nsec)
}

/// Returns a realtime timestamp in nanoseconds since the Unix epoch.
pub fn realtime_ns() -> Option<u64> {
    let monotonic_ns = monotonic_ns()?;
    let base = realtime_base();
    Some(
        base.realtime_ns
            .saturating_add(monotonic_ns.saturating_sub(base.monotonic_ns)),
    )
}

/// Converts an absolute realtime deadline to the monotonic deadline used internally.
pub fn monotonic_deadline_from_realtime_ns(realtime_deadline_ns: u64) -> Option<u64> {
    let base = realtime_base();
    if realtime_deadline_ns >= base.realtime_ns {
        return Some(
            base.monotonic_ns
                .saturating_add(realtime_deadline_ns - base.realtime_ns),
        );
    }

    Some(
        base.monotonic_ns
            .saturating_sub(base.realtime_ns - realtime_deadline_ns),
    )
}

/// Returns a deadline `timeout` after the current monotonic time.
pub fn deadline_after(timeout: &Duration) -> Result<u64> {
    let timeout_ns = timeout
        .as_secs()
        .saturating_mul(NANOS_PER_SEC)
        .saturating_add(u64::from(timeout.subsec_nanos()));
    deadline_after_ns(timeout_ns)
}

/// Returns a deadline `timeout_ns` after the current monotonic time.
pub fn deadline_after_ns(timeout_ns: u64) -> Result<u64> {
    let now_ns = monotonic_ns().ok_or(Error::new(Errno::EINVAL))?;
    Ok(now_ns.saturating_add(timeout_ns))
}

/// Sleeps until the monotonic deadline expires.
pub fn sleep_until_ns(deadline_ns: u64) -> Result<()> {
    if is_deadline_elapsed(deadline_ns)? {
        return Ok(());
    }

    let (waiter, waker) = Waiter::new_pair();
    let timeout = TimeoutRegistration::new(deadline_ns, waker)?;
    loop {
        if timeout.has_expired() || is_deadline_elapsed(deadline_ns)? {
            return Ok(());
        }
        waiter.wait();
    }
}

/// Returns whether the monotonic deadline has expired.
pub fn is_deadline_elapsed(deadline_ns: u64) -> Result<bool> {
    Ok(monotonic_ns()
        .ok_or(Error::new(Errno::EINVAL))?
        .ge(&deadline_ns))
}

/// A timeout registration that wakes a waiter when the deadline expires.
pub struct TimeoutRegistration {
    item: Arc<TimeoutItem>,
}

impl TimeoutRegistration {
    /// Registers `waker` for a deadline-driven wakeup.
    pub fn new(deadline_ns: u64, waker: Arc<Waker>) -> Result<Self> {
        init();

        let item = Arc::new(TimeoutItem {
            deadline_ns,
            waker,
            state: AtomicU8::new(TIMEOUT_WAITING),
        });
        if is_deadline_elapsed(deadline_ns)? {
            item.try_complete(TIMEOUT_EXPIRED);
            return Ok(Self { item });
        }

        timeout_table().bucket.lock().push_back(item.clone());
        Ok(Self { item })
    }

    /// Returns whether the timeout has expired.
    pub fn has_expired(&self) -> bool {
        self.item.state.load(Ordering::Acquire) == TIMEOUT_EXPIRED
    }
}

impl Drop for TimeoutRegistration {
    fn drop(&mut self) {
        if self.item.try_complete(TIMEOUT_CANCELLED) {
            remove_timeout_item(&self.item);
        }
    }
}

struct TimeoutItem {
    deadline_ns: u64,
    waker: Arc<Waker>,
    state: AtomicU8,
}

impl TimeoutItem {
    fn try_complete(&self, state: u8) -> bool {
        self.state
            .compare_exchange(TIMEOUT_WAITING, state, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn is_expired_at(&self, now_ns: u64) -> bool {
        now_ns >= self.deadline_ns
    }
}

struct TimeoutTable {
    bucket: SpinLock<VecDeque<Arc<TimeoutItem>>>,
}

static TIMEOUT_TABLE: Once<TimeoutTable> = Once::new();
static TIMEOUT_TIMER_REGISTERED_CPUS: Once<SpinLock<CpuSet>> = Once::new();
static REALTIME_BASE: Once<RealtimeBase> = Once::new();

#[derive(Clone, Copy)]
struct RealtimeBase {
    realtime_ns: u64,
    monotonic_ns: u64,
}

fn timeout_table() -> &'static TimeoutTable {
    TIMEOUT_TABLE.call_once(|| TimeoutTable {
        bucket: SpinLock::new(VecDeque::new()),
    })
}

fn realtime_base() -> RealtimeBase {
    *REALTIME_BASE.call_once(|| {
        parse_realtime_base_from_cmdline().unwrap_or_else(|| {
            let monotonic_ns = monotonic_ns().unwrap_or(0);
            RealtimeBase {
                realtime_ns: monotonic_ns,
                monotonic_ns,
            }
        })
    })
}

fn parse_realtime_base_from_cmdline() -> Option<RealtimeBase> {
    let cmdline = &boot::boot_info().kernel_cmdline;
    Some(RealtimeBase {
        realtime_ns: parse_cmdline_u64(cmdline, "kernel.realtime_base_ns")?,
        monotonic_ns: parse_cmdline_u64(cmdline, "kernel.monotonic_base_ns")?,
    })
}

fn parse_cmdline_u64(cmdline: &str, key: &str) -> Option<u64> {
    for arg in cmdline.split_ascii_whitespace() {
        let Some(value) = arg
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        else {
            continue;
        };
        return value.parse().ok();
    }
    None
}

fn remove_timeout_item(item: &Arc<TimeoutItem>) -> bool {
    let mut bucket = timeout_table().bucket.lock();
    let Some(idx) = bucket
        .iter()
        .position(|candidate| Arc::ptr_eq(candidate, item))
    else {
        return false;
    };
    bucket.remove(idx);
    true
}

fn wake_expired_timeouts() {
    let Some(now_ns) = monotonic_ns() else {
        return;
    };

    let mut expired_items = Vec::new();
    {
        let mut bucket = timeout_table().bucket.lock();
        let mut idx = 0usize;
        while idx < bucket.len() {
            if bucket[idx].is_expired_at(now_ns) && bucket[idx].try_complete(TIMEOUT_EXPIRED) {
                let Some(item) = bucket.remove(idx) else {
                    break;
                };
                expired_items.push(item);
            } else {
                idx += 1;
            }
        }
    }

    for item in expired_items {
        let _ = item.waker.wake_up();
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn realtime_base_cmdline_parser_reads_exact_keys() {
        let cmdline = "kernel.mode=busybox-smoke kernel.realtime_base_ns=1700000000123456789 \
             kernel.monotonic_base_ns=123456";

        assert_eq!(
            parse_cmdline_u64(cmdline, "kernel.realtime_base_ns"),
            Some(1_700_000_000_123_456_789)
        );
        assert_eq!(
            parse_cmdline_u64(cmdline, "kernel.monotonic_base_ns"),
            Some(123_456)
        );
        assert_eq!(parse_cmdline_u64(cmdline, "kernel.realtime"), None);
    }

    #[ktest]
    fn realtime_base_cmdline_parser_rejects_invalid_numbers() {
        assert_eq!(
            parse_cmdline_u64(
                "kernel.realtime_base_ns=not-a-number",
                "kernel.realtime_base_ns"
            ),
            None
        );
    }
}
