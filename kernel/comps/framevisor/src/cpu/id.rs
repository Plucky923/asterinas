//! CPU identification numbers.

use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use host_ostd::early_println;

/// The error type returned when converting an out-of-range integer to [`CpuId`].
#[derive(Clone, Copy, Debug)]
pub struct CpuIdFromIntError;

/// The ID of a CPU in the system.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct CpuId(u32);

impl CpuId {
    /// Creates a new CPU ID.
    ///
    /// # Panics
    ///
    /// The given number must be smaller than `host_ostd::cpu::num_cpus()`.
    pub fn new(raw_id: u32) -> Self {
        assert!(raw_id < crate::cpu::num_cpus() as u32);
        Self(raw_id)
    }

    pub(crate) const fn from_raw(raw_id: u32) -> Self {
        Self(raw_id)
    }

    /// Returns the CPU ID of the bootstrap processor.
    pub const fn bsp() -> Self {
        Self(0)
    }

    /// Returns the current CPU ID.
    pub fn current_racy() -> Self {
        crate::task::scheduler::current_cpu().unwrap_or_else(Self::bsp)
    }

    /// Returns this CPU ID as `usize`.
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for CpuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CpuId").field(&self.0).finish()
    }
}

impl From<CpuId> for u32 {
    fn from(cpu_id: CpuId) -> Self {
        cpu_id.0
    }
}

impl TryFrom<usize> for CpuId {
    type Error = CpuIdFromIntError;

    fn try_from(raw_id: usize) -> Result<Self, Self::Error> {
        if raw_id < crate::cpu::num_cpus() {
            Ok(Self(raw_id as u32))
        } else {
            Err(CpuIdFromIntError)
        }
    }
}

/// Returns an iterator over all CPUs.
pub fn all_cpus() -> impl Iterator<Item = CpuId> {
    (0..crate::cpu::num_cpus()).map(|raw_id| CpuId(raw_id as u32))
}

/// A set of CPU IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuSet {
    bits: u64,
}

impl CpuSet {
    /// Creates a set containing all CPUs.
    pub fn new_full() -> Self {
        let bits = valid_cpu_bits();
        Self { bits }
    }

    /// Creates an empty CPU set.
    pub fn new_empty() -> Self {
        Self { bits: 0 }
    }

    /// Adds a CPU ID to the set.
    pub fn add(&mut self, cpu_id: CpuId) {
        self.bits |= bit_for(cpu_id);
    }

    /// Removes a CPU ID from the set.
    pub fn remove(&mut self, cpu_id: CpuId) {
        self.bits &= !bit_for(cpu_id);
    }

    /// Returns whether the set contains a CPU ID.
    pub fn contains(&self, cpu_id: CpuId) -> bool {
        self.bits & bit_for(cpu_id) != 0
    }

    /// Iterates over CPU IDs in the set.
    pub fn iter(&self) -> CpuSetIter {
        CpuSetIter {
            bits: self.bits,
            next_raw_id: 0,
        }
    }

    /// Returns the number of CPU IDs in the set.
    pub fn count(&self) -> usize {
        (self.bits & valid_cpu_bits()).count_ones() as usize
    }

    /// Returns whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.bits & valid_cpu_bits() == 0
    }

    /// Returns whether the set contains all CPUs.
    pub fn is_full(&self) -> bool {
        (self.bits & valid_cpu_bits()) == valid_cpu_bits()
    }

    /// Adds all CPUs to the set.
    pub fn add_all(&mut self) {
        self.bits = valid_cpu_bits();
    }

    /// Removes all CPUs from the set.
    pub fn clear(&mut self) {
        self.bits = 0;
    }
}

impl Default for CpuSet {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl From<CpuId> for CpuSet {
    fn from(cpu_id: CpuId) -> Self {
        let mut cpu_set = Self::new_empty();
        cpu_set.add(cpu_id);
        cpu_set
    }
}

/// A set of CPU IDs that may be accessed concurrently.
#[derive(Debug)]
pub struct AtomicCpuSet {
    bits: AtomicU64,
}

impl AtomicCpuSet {
    /// Creates a new atomic CPU set from a CPU set.
    pub fn new(value: CpuSet) -> Self {
        Self {
            bits: AtomicU64::new(value.bits & valid_cpu_bits()),
        }
    }

    /// Loads the value of the set with the given ordering.
    pub fn load(&self, ordering: Ordering) -> CpuSet {
        let bits = match ordering {
            Ordering::Release => self.bits.fetch_or(0, ordering),
            _ => self.bits.load(ordering),
        };
        CpuSet {
            bits: bits & valid_cpu_bits(),
        }
    }

    /// Stores a new value to the set with the given ordering.
    pub fn store(&self, value: &CpuSet, ordering: Ordering) {
        self.bits.store(value.bits & valid_cpu_bits(), ordering);
    }

    /// Atomically adds a CPU ID with the given ordering.
    pub fn add(&self, cpu_id: CpuId, ordering: Ordering) {
        self.bits.fetch_or(bit_for(cpu_id), ordering);
    }

    /// Atomically removes a CPU ID with the given ordering.
    pub fn remove(&self, cpu_id: CpuId, ordering: Ordering) {
        self.bits.fetch_and(!bit_for(cpu_id), ordering);
    }

    /// Atomically checks whether the set contains a CPU ID.
    pub fn contains(&self, cpu_id: CpuId, ordering: Ordering) -> bool {
        self.bits.load(ordering) & bit_for(cpu_id) != 0
    }
}

/// A marker trait for guard types that pin the current task to the current CPU.
pub trait PinCurrentCpu {
    /// Returns the ID of the current CPU.
    fn current_cpu(&self) -> CpuId {
        CpuId::current_racy()
    }
}

impl PinCurrentCpu for crate::irq::DisabledLocalIrqGuard {}

impl PinCurrentCpu for crate::task::DisabledPreemptGuard {}

fn valid_cpu_bits() -> u64 {
    let cpu_count = crate::cpu::num_cpus().min(u64::BITS as usize);
    if cpu_count == u64::BITS as usize {
        u64::MAX
    } else {
        (1u64 << cpu_count) - 1
    }
}

fn bit_for(cpu_id: CpuId) -> u64 {
    1u64 << cpu_id.as_usize()
}

/// Iterator over [`CpuSet`].
pub struct CpuSetIter {
    bits: u64,
    next_raw_id: usize,
}

impl Iterator for CpuSetIter {
    type Item = CpuId;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_raw_id < crate::cpu::num_cpus().min(u64::BITS as usize) {
            let raw_id = self.next_raw_id;
            self.next_raw_id += 1;
            let cpu_id = CpuId::from_raw(raw_id as u32);
            if self.bits & bit_for(cpu_id) != 0 {
                return Some(cpu_id);
            }
        }
        None
    }
}

pub(super) fn init_cpu_id() {
    early_println!("[framevisor] Initializing CPU ID...");
    CpuId::bsp();
    CpuSet::new_full();
    early_println!("[framevisor] CPU ID initialized");
}
