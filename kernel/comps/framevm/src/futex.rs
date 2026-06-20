// SPDX-License-Identifier: MPL-2.0

//! Futex wait/wake support for user tasks.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};

use ostd::{
    cpu::{self, CpuSet},
    sync::{Once, SpinLock, Waiter, Waker},
    timer,
};

use crate::{
    error::{Errno, Error, Result},
    time,
};

const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;
const FUTEX_WORD_ALIGN: usize = 4;
const FUTEX_WAITING: u8 = 0;
const FUTEX_WOKEN: u8 = 1;
const FUTEX_TIMED_OUT: u8 = 2;

/// A futex operation from Linux UAPI.
#[expect(non_camel_case_types)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexOp {
    FUTEX_WAIT = 0,
    FUTEX_WAKE = 1,
    FUTEX_FD = 2,
    FUTEX_REQUEUE = 3,
    FUTEX_CMP_REQUEUE = 4,
    FUTEX_WAKE_OP = 5,
    FUTEX_LOCK_PI = 6,
    FUTEX_UNLOCK_PI = 7,
    FUTEX_TRYLOCK_PI = 8,
    FUTEX_WAIT_BITSET = 9,
    FUTEX_WAKE_BITSET = 10,
}

impl TryFrom<u32> for FutexOp {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::FUTEX_WAIT),
            1 => Ok(Self::FUTEX_WAKE),
            2 => Ok(Self::FUTEX_FD),
            3 => Ok(Self::FUTEX_REQUEUE),
            4 => Ok(Self::FUTEX_CMP_REQUEUE),
            5 => Ok(Self::FUTEX_WAKE_OP),
            6 => Ok(Self::FUTEX_LOCK_PI),
            7 => Ok(Self::FUTEX_UNLOCK_PI),
            8 => Ok(Self::FUTEX_TRYLOCK_PI),
            9 => Ok(Self::FUTEX_WAIT_BITSET),
            10 => Ok(Self::FUTEX_WAKE_BITSET),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FutexFlags {
    private: bool,
    clock_realtime: bool,
}

impl FutexFlags {
    /// Returns whether this futex operation requested private visibility.
    pub const fn is_private(self) -> bool {
        self.private
    }

    /// Returns whether this futex operation requested realtime-clock timeout semantics.
    pub const fn uses_clock_realtime(self) -> bool {
        self.clock_realtime
    }
}

/// Decodes a Linux futex operation word into an operation and flags.
pub fn futex_op_and_flags_from_u32(bits: u32) -> Result<(FutexOp, FutexFlags)> {
    const FUTEX_OP_MASK: u32 = 0x0000_000F;
    const FUTEX_PRIVATE_FLAG: u32 = 128;
    const FUTEX_CLOCK_REALTIME: u32 = 256;
    const FUTEX_FLAGS_MASK: u32 = FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME;

    let unknown_flags = bits & !(FUTEX_OP_MASK | FUTEX_FLAGS_MASK);
    if unknown_flags != 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let futex_op = FutexOp::try_from(bits & FUTEX_OP_MASK)?;
    let futex_flags = FutexFlags {
        private: bits & FUTEX_PRIVATE_FLAG != 0,
        clock_realtime: bits & FUTEX_CLOCK_REALTIME != 0,
    };
    Ok((futex_op, futex_flags))
}

/// Converts the Linux `val` argument to a maximum wake count.
pub fn futex_val_to_max_count(futex_val: u32) -> usize {
    // Keep the same behavior as `kernel/src/syscall/futex.rs`.
    (futex_val as i32).max(1) as usize
}

/// Initializes futex timer handling on the current CPU.
pub fn init() {
    let cpu_id = cpu::CpuId::current_racy();
    let should_register = {
        let registered_cpus =
            FUTEX_TIMER_REGISTERED_CPUS.call_once(|| SpinLock::new(CpuSet::new_empty()));
        let mut registered_cpus = registered_cpus.lock();
        if registered_cpus.contains(cpu_id) {
            false
        } else {
            registered_cpus.add(cpu_id);
            true
        }
    };

    if should_register {
        timer::register_callback_on_cpu(wake_expired_waiters);
    }
}

/// Waits while the futex word still contains `expected`.
pub fn futex_wait(
    futex_addr: usize,
    expected: u32,
    deadline_ns: Option<u64>,
    read_futex_word: impl FnMut() -> Result<u32>,
) -> Result<()> {
    futex_wait_bitset(
        futex_addr,
        expected,
        FUTEX_BITSET_MATCH_ANY,
        deadline_ns,
        read_futex_word,
    )
}

/// Waits while the futex word still contains `expected` for the given bitset.
pub fn futex_wait_bitset(
    futex_addr: usize,
    expected: u32,
    bitset: u32,
    deadline_ns: Option<u64>,
    mut read_futex_word: impl FnMut() -> Result<u32>,
) -> Result<()> {
    validate_futex_addr(futex_addr)?;
    validate_bitset(bitset)?;

    let futex_key = FutexKey::new(futex_addr, bitset);
    let (futex_item, waiter) = FutexItem::create(futex_key, deadline_ns);
    {
        let mut bucket = futex_table().bucket.lock();
        let futex_value = read_futex_word()?;
        if futex_value != expected {
            return Err(Error::new(Errno::EAGAIN));
        }
        if is_deadline_elapsed(deadline_ns)? {
            return Err(Error::new(Errno::ETIMEDOUT));
        }
        bucket.push_back(futex_item.clone());
    }

    let result = waiter.wait_until_or_cancelled(
        || futex_item.wait_result(),
        || {
            if is_deadline_elapsed(deadline_ns)? && futex_item.try_complete(FUTEX_TIMED_OUT) {
                remove_futex_item(&futex_item);
                return Err(Error::new(Errno::ETIMEDOUT));
            }
            Ok(())
        },
    );

    match result {
        Ok(result) => result,
        Err(error) => {
            remove_futex_item(&futex_item);
            Err(error)
        }
    }
}

/// Wakes up to `max_count` waiters for a futex word.
pub fn futex_wake(futex_addr: usize, max_count: usize) -> Result<usize> {
    futex_wake_bitset(futex_addr, max_count, FUTEX_BITSET_MATCH_ANY)
}

/// Wakes up to `max_count` waiters matching the bitset.
pub fn futex_wake_bitset(futex_addr: usize, max_count: usize, bitset: u32) -> Result<usize> {
    validate_futex_addr(futex_addr)?;
    validate_bitset(bitset)?;

    let mut bucket = futex_table().bucket.lock();
    Ok(wake_items_locked(
        &mut bucket,
        futex_addr,
        bitset,
        max_count,
    ))
}

/// Wakes waiters from one futex and requeues remaining waiters onto another.
pub fn futex_requeue(
    futex_addr: usize,
    max_nwakes: usize,
    max_nrequeues: usize,
    futex_new_addr: usize,
) -> Result<usize> {
    validate_futex_addr(futex_addr)?;
    validate_futex_addr(futex_new_addr)?;

    if futex_new_addr == futex_addr {
        return futex_wake(futex_addr, max_nwakes);
    }

    let mut bucket = futex_table().bucket.lock();
    let num_woken = wake_items_locked(&mut bucket, futex_addr, FUTEX_BITSET_MATCH_ANY, max_nwakes);
    requeue_items_locked(&mut bucket, futex_addr, futex_new_addr, max_nrequeues);
    Ok(num_woken)
}

/// Applies `FUTEX_WAKE_OP` and wakes matching waiters.
pub fn futex_wake_op(
    futex_addr_1: usize,
    futex_addr_2: usize,
    max_count_1: usize,
    max_count_2: usize,
    wake_op_bits: u32,
    mut atomic_fetch_update_futex_2: impl FnMut(&mut dyn FnMut(u32) -> u32) -> Result<u32>,
) -> Result<usize> {
    validate_futex_addr(futex_addr_1)?;
    validate_futex_addr(futex_addr_2)?;

    let wake_op = FutexWakeOpEncode::from_u32(wake_op_bits)?;
    let mut bucket = futex_table().bucket.lock();
    let old_val = atomic_fetch_update_futex_2(&mut |old_val| wake_op.calculate_new_val(old_val))?;

    let mut num_woken = wake_items_locked(
        &mut bucket,
        futex_addr_1,
        FUTEX_BITSET_MATCH_ANY,
        max_count_1,
    );
    if wake_op.should_wake(old_val) {
        num_woken = num_woken.saturating_add(wake_items_locked(
            &mut bucket,
            futex_addr_2,
            FUTEX_BITSET_MATCH_ANY,
            max_count_2,
        ));
    }

    Ok(num_woken)
}

fn validate_futex_addr(futex_addr: usize) -> Result<()> {
    if !futex_addr.is_multiple_of(FUTEX_WORD_ALIGN) {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

fn validate_bitset(bitset: u32) -> Result<()> {
    if bitset == 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FutexKey {
    addr: usize,
    bitset: u32,
}

impl FutexKey {
    const fn new(addr: usize, bitset: u32) -> Self {
        Self { addr, bitset }
    }

    fn matches_wake(&self, addr: usize, bitset: u32) -> bool {
        self.addr == addr && self.bitset & bitset != 0
    }

    fn requeue_to(&mut self, addr: usize) {
        self.addr = addr;
        self.bitset = FUTEX_BITSET_MATCH_ANY;
    }
}

struct FutexItem {
    key: SpinLock<FutexKey>,
    waker: Arc<Waker>,
    state: AtomicU8,
    deadline_ns: Option<u64>,
}

impl FutexItem {
    fn create(key: FutexKey, deadline_ns: Option<u64>) -> (Arc<Self>, Waiter) {
        let (waiter, waker) = Waiter::new_pair();
        let item = Arc::new(Self {
            key: SpinLock::new(key),
            waker,
            state: AtomicU8::new(FUTEX_WAITING),
            deadline_ns,
        });
        (item, waiter)
    }

    fn matches_wake(&self, addr: usize, bitset: u32) -> bool {
        self.key.lock().matches_wake(addr, bitset)
    }

    fn requeue_to(&self, addr: usize) {
        self.key.lock().requeue_to(addr);
    }

    fn waker(&self) -> &Waker {
        self.waker.as_ref()
    }

    fn try_complete(&self, state: u8) -> bool {
        self.state
            .compare_exchange(FUTEX_WAITING, state, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn wait_result(&self) -> Option<Result<()>> {
        match self.state.load(Ordering::Acquire) {
            FUTEX_WOKEN => Some(Ok(())),
            FUTEX_TIMED_OUT => Some(Err(Error::new(Errno::ETIMEDOUT))),
            _ => None,
        }
    }

    fn is_expired_at(&self, now_ns: u64) -> bool {
        self.deadline_ns
            .is_some_and(|deadline_ns| now_ns >= deadline_ns)
    }
}

struct FutexTable {
    bucket: SpinLock<VecDeque<Arc<FutexItem>>>,
}

static FUTEX_TABLE: Once<FutexTable> = Once::new();
static FUTEX_TIMER_REGISTERED_CPUS: Once<SpinLock<CpuSet>> = Once::new();

fn futex_table() -> &'static FutexTable {
    FUTEX_TABLE.call_once(|| FutexTable {
        bucket: SpinLock::new(VecDeque::new()),
    })
}

fn remove_futex_item(item: &Arc<FutexItem>) -> bool {
    let mut bucket = futex_table().bucket.lock();
    let Some(idx) = bucket
        .iter()
        .position(|candidate| Arc::ptr_eq(candidate, item))
    else {
        return false;
    };
    bucket.remove(idx);
    true
}

fn wake_items_locked(
    bucket: &mut VecDeque<Arc<FutexItem>>,
    futex_addr: usize,
    bitset: u32,
    max_count: usize,
) -> usize {
    let mut num_woken = 0usize;
    let mut idx = 0usize;
    while idx < bucket.len() && num_woken < max_count {
        if bucket[idx].matches_wake(futex_addr, bitset) && bucket[idx].try_complete(FUTEX_WOKEN) {
            let Some(item) = bucket.remove(idx) else {
                break;
            };
            if item.waker().wake_up() {
                num_woken += 1;
            }
        } else {
            idx += 1;
        }
    }
    num_woken
}

fn requeue_items_locked(
    bucket: &mut VecDeque<Arc<FutexItem>>,
    futex_addr: usize,
    futex_new_addr: usize,
    max_nrequeues: usize,
) -> usize {
    let mut num_requeued = 0usize;
    for item in bucket.iter() {
        if num_requeued >= max_nrequeues {
            break;
        }
        if item.matches_wake(futex_addr, FUTEX_BITSET_MATCH_ANY) {
            item.requeue_to(futex_new_addr);
            num_requeued += 1;
        }
    }
    num_requeued
}

fn wake_expired_waiters() {
    let Some(now_ns) = time::monotonic_ns() else {
        return;
    };

    let mut expired_items = Vec::new();
    {
        let mut bucket = futex_table().bucket.lock();
        let mut idx = 0usize;
        while idx < bucket.len() {
            if bucket[idx].is_expired_at(now_ns) && bucket[idx].try_complete(FUTEX_TIMED_OUT) {
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
        let _ = item.waker().wake_up();
    }
}

fn is_deadline_elapsed(deadline_ns: Option<u64>) -> Result<bool> {
    let Some(deadline_ns) = deadline_ns else {
        return Ok(false);
    };

    Ok(time::monotonic_ns()
        .ok_or(Error::new(Errno::EINVAL))?
        .ge(&deadline_ns))
}

/// Encoded operation/comparison used by `FUTEX_WAKE_OP`.
struct FutexWakeOpEncode {
    op: FutexWakeOp,
    is_oparg_shift: bool,
    cmp: FutexWakeCmp,
    oparg: u32,
    cmparg: u32,
}

#[expect(non_camel_case_types)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FutexWakeOp {
    FUTEX_OP_SET = 0,
    FUTEX_OP_ADD = 1,
    FUTEX_OP_OR = 2,
    FUTEX_OP_ANDN = 3,
    FUTEX_OP_XOR = 4,
}

impl TryFrom<u32> for FutexWakeOp {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::FUTEX_OP_SET),
            1 => Ok(Self::FUTEX_OP_ADD),
            2 => Ok(Self::FUTEX_OP_OR),
            3 => Ok(Self::FUTEX_OP_ANDN),
            4 => Ok(Self::FUTEX_OP_XOR),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }
}

#[expect(non_camel_case_types)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FutexWakeCmp {
    FUTEX_OP_CMP_EQ = 0,
    FUTEX_OP_CMP_NE = 1,
    FUTEX_OP_CMP_LT = 2,
    FUTEX_OP_CMP_LE = 3,
    FUTEX_OP_CMP_GT = 4,
    FUTEX_OP_CMP_GE = 5,
}

impl TryFrom<u32> for FutexWakeCmp {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::FUTEX_OP_CMP_EQ),
            1 => Ok(Self::FUTEX_OP_CMP_NE),
            2 => Ok(Self::FUTEX_OP_CMP_LT),
            3 => Ok(Self::FUTEX_OP_CMP_LE),
            4 => Ok(Self::FUTEX_OP_CMP_GT),
            5 => Ok(Self::FUTEX_OP_CMP_GE),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }
}

impl FutexWakeOpEncode {
    fn from_u32(bits: u32) -> Result<Self> {
        Ok(Self {
            op: FutexWakeOp::try_from((bits >> 28) & 0x7)?,
            is_oparg_shift: (bits >> 31) & 1 == 1,
            cmp: FutexWakeCmp::try_from((bits >> 24) & 0xf)?,
            oparg: (bits >> 12) & 0xfff,
            cmparg: bits & 0xfff,
        })
    }

    fn calculate_new_val(&self, old_val: u32) -> u32 {
        let oparg = if self.is_oparg_shift {
            1u32 << (self.oparg & 31)
        } else {
            self.oparg
        };

        match self.op {
            FutexWakeOp::FUTEX_OP_SET => oparg,
            FutexWakeOp::FUTEX_OP_ADD => old_val.wrapping_add(oparg),
            FutexWakeOp::FUTEX_OP_OR => old_val | oparg,
            FutexWakeOp::FUTEX_OP_ANDN => old_val & !oparg,
            FutexWakeOp::FUTEX_OP_XOR => old_val ^ oparg,
        }
    }

    fn should_wake(&self, old_val: u32) -> bool {
        match self.cmp {
            FutexWakeCmp::FUTEX_OP_CMP_EQ => old_val == self.cmparg,
            FutexWakeCmp::FUTEX_OP_CMP_NE => old_val != self.cmparg,
            FutexWakeCmp::FUTEX_OP_CMP_LT => old_val < self.cmparg,
            FutexWakeCmp::FUTEX_OP_CMP_LE => old_val <= self.cmparg,
            FutexWakeCmp::FUTEX_OP_CMP_GT => old_val > self.cmparg,
            FutexWakeCmp::FUTEX_OP_CMP_GE => old_val >= self.cmparg,
        }
    }
}

#[cfg(ktest)]
mod tests {
    use core::cell::Cell;

    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn futex_requeue_updates_waiter_key() {
        let source_addr = 0x1000_0000usize;
        let target_addr = 0x1000_1000usize;
        let (item, _waiter) =
            FutexItem::create(FutexKey::new(source_addr, FUTEX_BITSET_MATCH_ANY), None);

        futex_table().bucket.lock().push_back(item.clone());

        assert_eq!(futex_requeue(source_addr, 0, 1, target_addr).unwrap(), 0);
        assert!(item.matches_wake(target_addr, FUTEX_BITSET_MATCH_ANY));
        assert!(!item.matches_wake(source_addr, FUTEX_BITSET_MATCH_ANY));

        assert!(remove_futex_item(&item));
    }

    #[ktest]
    fn futex_wake_op_updates_second_word_and_wakes_first() {
        let first_addr = 0x1000_2000usize;
        let second_addr = 0x1000_3000usize;
        let (item, _waiter) =
            FutexItem::create(FutexKey::new(first_addr, FUTEX_BITSET_MATCH_ANY), None);
        futex_table().bucket.lock().push_back(item);

        let second_word = Cell::new(5u32);
        let wake_op_bits = ((FutexWakeOp::FUTEX_OP_ADD as u32) << 28)
            | ((FutexWakeCmp::FUTEX_OP_CMP_EQ as u32) << 24)
            | (7 << 12)
            | 5;
        let num_woken = futex_wake_op(
            first_addr,
            second_addr,
            1,
            1,
            wake_op_bits,
            |calculate_new_value| {
                let old_value = second_word.get();
                let new_value = calculate_new_value(old_value);
                second_word.set(new_value);
                Ok(old_value)
            },
        )
        .unwrap();

        assert_eq!(second_word.get(), 12);
        assert_eq!(num_woken, 1);
    }
}
