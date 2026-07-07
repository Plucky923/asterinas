// SPDX-License-Identifier: MPL-2.0

//! Safe FrameVM CPU-local storage.
//!
//! This module is an OSTD-shaped provider substitution for FrameVM service
//! code. Host OSTD implements static CPU-local storage with `.cpu_local`
//! linker sections and raw CPU-local pointers. FrameVisor cannot expose that
//! implementation to FrameVM services because service CPU identity is a
//! FrameVM vCPU identity and slot ownership must follow the owning `FrameVm`.
//!
//! The implementation below is deliberately safe Rust. Each static CPU-local
//! object receives a metadata-only object id, and each `FrameVm` owns the
//! actual slot values in its `CpuLocalDomain`. A future lock-free provider
//! would need a separate lower-half design; it must not be smuggled into this
//! safe facade with raw pointers or leaked VM-owned slots.

extern crate alloc;

use alloc::{collections::BTreeMap, rc::Rc, sync::Arc, vec::Vec};
use core::{
    any::Any,
    marker::PhantomData,
    ops::{Add, BitAnd, BitOr, BitXor, Deref, Sub},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    cpu::CpuId,
    irq::DisabledLocalIrqGuard,
    sync::{Once, SpinLock},
    vm,
};

/// A metadata-only id for one static CPU-local object.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CpuLocalObjectId(u64);

impl CpuLocalObjectId {
    /// Creates an object id from facade-owned allocator metadata.
    #[doc(hidden)]
    #[inline(always)]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

/// Per-VM owner for FrameVM CPU-local slot values.
pub struct CpuLocalDomain {
    entries: SpinLock<BTreeMap<CpuLocalObjectId, Arc<dyn Any + Send + Sync>>>,
    active: AtomicBool,
}

impl CpuLocalDomain {
    /// Creates an empty CPU-local domain.
    pub fn new() -> Self {
        Self {
            entries: SpinLock::new(BTreeMap::new()),
            active: AtomicBool::new(true),
        }
    }

    /// Allows CPU-local access after a VM start boundary.
    pub(crate) fn activate(&self) {
        self.active.store(true, Ordering::Release);
    }

    /// Rejects new CPU-local access during VM teardown.
    pub(crate) fn start_teardown(&self) {
        self.active.store(false, Ordering::Release);
    }

    #[inline]
    pub(crate) fn typed_entry<E>(
        &self,
        object_id: CpuLocalObjectId,
        create: impl FnOnce() -> E,
    ) -> Arc<E>
    where
        E: Any + Send + Sync,
    {
        assert!(
            self.active.load(Ordering::Acquire),
            "FrameVM CPU-local access after VM teardown started"
        );

        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get(&object_id) {
            return entry
                .clone()
                .downcast::<E>()
                .expect("FrameVM CPU-local object id reused with incompatible type");
        }

        let entry = Arc::new(create());
        entries.insert(object_id, entry.clone());
        entry
    }
}

impl Default for CpuLocalDomain {
    fn default() -> Self {
        Self::new()
    }
}

/// A statically declared FrameVM CPU-local object.
pub struct StaticCpuLocal<T: 'static> {
    object_id: Once<CpuLocalObjectId>,
    init: fn() -> T,
    allocate_object_id: fn() -> CpuLocalObjectId,
    _marker: PhantomData<fn() -> T>,
}

impl<T: 'static> StaticCpuLocal<T> {
    /// Creates a static CPU-local object descriptor.
    pub const fn new(init: fn() -> T, allocate_object_id: fn() -> CpuLocalObjectId) -> Self {
        Self {
            object_id: Once::new(),
            init,
            allocate_object_id,
            _marker: PhantomData,
        }
    }

    #[inline]
    fn object_id(&'static self) -> CpuLocalObjectId {
        *self.object_id.call_once(self.allocate_object_id)
    }
}

impl<T> StaticCpuLocal<T>
where
    T: Send + Sync + 'static,
{
    /// Gets the slot on the current FrameVM CPU.
    #[inline]
    pub fn get_with<'a>(&'static self, _guard: &'a DisabledLocalIrqGuard) -> CpuLocalGuard<'a, T> {
        let cpu = crate::cpu::try_current_cpu()
            .expect("FrameVM CPU-local access requires a FrameVM CPU context");
        let slot = self.slot_on_cpu(cpu);
        CpuLocalGuard {
            slot,
            _guard: PhantomData,
            _not_send_sync: PhantomData,
        }
    }

    /// Gets the slot on a target FrameVM CPU.
    #[inline]
    pub fn get_on_cpu(&'static self, cpu: CpuId) -> CpuLocalRemoteGuard<T> {
        let slot = self.slot_on_cpu(cpu);
        CpuLocalRemoteGuard {
            slot,
            _not_send_sync: PhantomData,
        }
    }

    #[inline]
    fn slot_on_cpu(&'static self, cpu: CpuId) -> Arc<T> {
        let frame_vcpu_id = crate::current_frame_vcpu_id()
            .expect("FrameVM CPU-local access requires a FrameVM context");
        let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id())
            .expect("FrameVM CPU-local access requires a live owning FrameVM");
        let entry = vm
            .cpu_local_domain()
            .typed_entry(self.object_id(), || StaticCpuLocalSlots {
                init: self.init,
                slots: SpinLock::new(Vec::new()),
            });
        entry.slot(cpu)
    }
}

struct StaticCpuLocalSlots<T: Send + Sync + 'static> {
    init: fn() -> T,
    slots: SpinLock<Vec<Option<Arc<T>>>>,
}

impl<T> StaticCpuLocalSlots<T>
where
    T: Send + Sync + 'static,
{
    #[inline]
    fn slot(&self, cpu: CpuId) -> Arc<T> {
        let slot_index = cpu.as_usize();
        let mut slots = self.slots.lock();
        if slots.len() <= slot_index {
            slots.resize_with(slot_index + 1, || None);
        }

        slots[slot_index]
            .get_or_insert_with(|| Arc::new((self.init)()))
            .clone()
    }
}

/// Guard for a current-CPU static CPU-local slot.
#[must_use]
pub struct CpuLocalGuard<'a, T: Send + Sync + 'static> {
    slot: Arc<T>,
    _guard: PhantomData<&'a DisabledLocalIrqGuard>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<T: Send + Sync + 'static> Deref for CpuLocalGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.slot.as_ref()
    }
}

/// Guard for a remote static CPU-local slot.
#[must_use]
pub struct CpuLocalRemoteGuard<T: Send + Sync + 'static> {
    slot: Arc<T>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<T: Send + Sync + 'static> Deref for CpuLocalRemoteGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.slot.as_ref()
    }
}

/// An OSTD-shaped current-CPU value-operation cell.
pub struct CpuLocalCell<T: 'static> {
    object_id: Once<CpuLocalObjectId>,
    init: fn() -> T,
    allocate_object_id: fn() -> CpuLocalObjectId,
    _marker: PhantomData<fn() -> T>,
}

impl<T: 'static> CpuLocalCell<T> {
    /// Creates a CPU-local cell descriptor.
    pub const fn new(init: fn() -> T, allocate_object_id: fn() -> CpuLocalObjectId) -> Self {
        Self {
            object_id: Once::new(),
            init,
            allocate_object_id,
            _marker: PhantomData,
        }
    }

    #[inline]
    fn object_id(&'static self) -> CpuLocalObjectId {
        *self.object_id.call_once(self.allocate_object_id)
    }
}

impl<T> CpuLocalCell<T>
where
    T: Send + 'static,
{
    #[inline]
    fn with_current<R>(&'static self, operation: impl FnOnce(&mut T) -> R) -> R {
        let frame_vcpu_id = crate::current_frame_vcpu_id()
            .expect("FrameVM CPU-local access requires a FrameVM context");
        let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id())
            .expect("FrameVM CPU-local access requires a live owning FrameVM");
        let entry = vm
            .cpu_local_domain()
            .typed_entry(self.object_id(), || CpuLocalCellSlots {
                init: self.init,
                slots: SpinLock::new(Vec::new()),
            });
        let cpu = crate::cpu::try_current_cpu()
            .expect("FrameVM CPU-local access requires a FrameVM CPU context");
        let slot = entry.slot(cpu);
        let mut slot = slot.lock();
        operation(&mut slot)
    }

    /// Writes the value on the current FrameVM CPU.
    pub fn store(&'static self, value: T) {
        self.with_current(|slot| *slot = value);
    }
}

impl<T> CpuLocalCell<T>
where
    T: Copy + Send + 'static,
{
    /// Gets the value on the current FrameVM CPU.
    pub fn load(&'static self) -> T {
        self.with_current(|value| *value)
    }
}

impl<T> CpuLocalCell<T>
where
    T: Add<Output = T> + Copy + Send + 'static,
{
    /// Adds to the value on the current FrameVM CPU.
    pub fn add_assign(&'static self, value: T) {
        self.with_current(|slot| *slot = *slot + value);
    }
}

impl<T> CpuLocalCell<T>
where
    T: Copy + Send + Sub<Output = T> + 'static,
{
    /// Subtracts from the value on the current FrameVM CPU.
    pub fn sub_assign(&'static self, value: T) {
        self.with_current(|slot| *slot = *slot - value);
    }
}

impl<T> CpuLocalCell<T>
where
    T: BitAnd<Output = T> + Copy + Send + 'static,
{
    /// Bitwise ANDs into the value on the current FrameVM CPU.
    pub fn bitand_assign(&'static self, value: T) {
        self.with_current(|slot| *slot = *slot & value);
    }
}

impl<T> CpuLocalCell<T>
where
    T: BitOr<Output = T> + Copy + Send + 'static,
{
    /// Bitwise ORs into the value on the current FrameVM CPU.
    pub fn bitor_assign(&'static self, value: T) {
        self.with_current(|slot| *slot = *slot | value);
    }
}

impl<T> CpuLocalCell<T>
where
    T: BitXor<Output = T> + Copy + Send + 'static,
{
    /// Bitwise XORs into the value on the current FrameVM CPU.
    pub fn bitxor_assign(&'static self, value: T) {
        self.with_current(|slot| *slot = *slot ^ value);
    }
}

struct CpuLocalCellSlots<T: Send + 'static> {
    init: fn() -> T,
    slots: SpinLock<Vec<Option<Arc<SpinLock<T>>>>>,
}

impl<T> CpuLocalCellSlots<T>
where
    T: Send + 'static,
{
    #[inline]
    fn slot(&self, cpu: CpuId) -> Arc<SpinLock<T>> {
        let slot_index = cpu.as_usize();
        let mut slots = self.slots.lock();
        if slots.len() <= slot_index {
            slots.resize_with(slot_index + 1, || None);
        }

        slots[slot_index]
            .get_or_insert_with(|| Arc::new(SpinLock::new((self.init)())))
            .clone()
    }
}
