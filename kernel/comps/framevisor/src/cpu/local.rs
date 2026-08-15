// SPDX-License-Identifier: MPL-2.0

//! Safe FrameVM CPU-local storage.
//!
//! Host OSTD implements CPU-local storage with linker sections and raw CPU
//! pointers. FrameVM services instead use a safe, VM-owned provider: each
//! declaration has a static source key, and each VM owns one fixed slot for
//! every vCPU.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    any::Any,
    marker::PhantomData,
    ops::{Add, BitAnd, BitOr, BitXor, Deref, Sub},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    cpu::CpuId,
    irq::DisabledLocalIrqGuard,
    sync::SpinLock,
    task,
    vm::{self, FrameVcpuId},
};

/// Per-VM owner for FrameVM CPU-local slot values.
pub(crate) struct CpuLocalDomain {
    entries: SpinLock<BTreeMap<&'static str, Arc<dyn Any + Send + Sync>>>,
    vcpu_count: usize,
    active: AtomicBool,
}

impl CpuLocalDomain {
    /// Creates a closed CPU-local domain with fixed vCPU capacity.
    pub(crate) fn new(vcpu_count: usize) -> Self {
        assert!(
            vcpu_count != 0,
            "a CPU-local domain needs at least one vCPU"
        );
        Self {
            entries: SpinLock::new(BTreeMap::new()),
            vcpu_count,
            active: AtomicBool::new(false),
        }
    }

    /// Opens CPU-local access for the active VM service image.
    pub(crate) fn activate(&self) {
        self.active.store(true, Ordering::Release);
    }

    /// Rejects new CPU-local access during VM teardown.
    pub(crate) fn start_teardown(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// Drops all per-VM CPU-local values while the owning service image is
    /// still the current address space.
    pub(crate) fn clear(&self) {
        let entries = {
            let mut stored = self.entries.lock();
            assert!(
                !self.active.load(Ordering::Acquire),
                "FrameVM CPU-local domain must be closed before clear"
            );
            core::mem::take(&mut *stored)
        };
        drop(entries);
    }

    #[inline]
    pub(crate) fn typed_entry<E>(
        &self,
        key: &'static str,
        vcpu_index: usize,
        create: impl FnOnce() -> E,
    ) -> Arc<E>
    where
        E: Any + Send + Sync,
    {
        assert!(
            vcpu_index < self.vcpu_count,
            "FrameVM vCPU index is out of range"
        );

        let mut entries = self.entries.lock();
        assert!(
            self.active.load(Ordering::Acquire),
            "FrameVM CPU-local access after VM teardown started"
        );
        if let Some(entry) = entries.get(key) {
            return entry
                .clone()
                .downcast::<E>()
                .expect("FrameVM CPU-local declaration key reused with incompatible type");
        }

        let entry = Arc::new(create());
        entries.insert(key, entry.clone());
        entry
    }
}

/// A statically declared FrameVM CPU-local object.
pub struct StaticCpuLocal<T: 'static> {
    init: fn() -> T,
    key: &'static str,
}

impl<T: 'static> StaticCpuLocal<T> {
    /// Creates a static CPU-local object descriptor.
    pub const fn new(init: fn() -> T, key: &'static str) -> Self {
        Self { init, key }
    }
}

impl<T> StaticCpuLocal<T>
where
    T: Send + Sync + 'static,
{
    /// Gets the slot on the current FrameVM CPU.
    #[inline]
    pub fn get_with<'a>(&'static self, guard: &'a DisabledLocalIrqGuard) -> CpuLocalGuard<'a, T> {
        let (frame_vm, frame_vcpu_id) = current_frame_vcpu();
        assert_eq!(
            guard.current_cpu().as_usize(),
            frame_vcpu_id.vcpu_index(),
            "FrameVM CPU-local guard and scope refer to different vCPUs"
        );
        let slot = self.slot_on_vcpu(&frame_vm, frame_vcpu_id, frame_vcpu_id.vcpu_index());
        CpuLocalGuard {
            slot,
            _guard: guard,
            _not_send_sync: PhantomData,
        }
    }

    /// Gets the slot on a target FrameVM CPU.
    #[inline]
    pub fn get_on_cpu(&'static self, cpu: CpuId) -> CpuLocalRemoteGuard<T> {
        let (frame_vm, frame_vcpu_id) = current_frame_vcpu();
        let slot = self.slot_on_vcpu(&frame_vm, frame_vcpu_id, cpu.as_usize());
        CpuLocalRemoteGuard {
            slot,
            _not_send_sync: PhantomData,
        }
    }

    #[inline]
    fn slot_on_vcpu(
        &'static self,
        frame_vm: &vm::FrameVm,
        frame_vcpu_id: FrameVcpuId,
        target_vcpu_index: usize,
    ) -> Arc<T> {
        debug_assert_eq!(frame_vcpu_id.vm_id(), frame_vm.id());
        let entry = frame_vm
            .cpu_local_domain()
            .typed_entry(self.key, target_vcpu_index, || {
                CpuLocalSlots::<Arc<T>>::new(frame_vm.vcpu_count())
            });
        entry.slot(target_vcpu_index, || Arc::new((self.init)()))
    }
}

/// The one typed storage implementation used by both CPU-local declarations.
/// The mode is represented by the slot type: static declarations hold shared
/// immutable values, while cell declarations hold individually locked values.
struct CpuLocalSlots<S> {
    // The vector length is fixed at declaration-entry creation. `None` keeps
    // payload construction lazy for each individual vCPU.
    slots: SpinLock<Vec<Option<S>>>,
}

impl<S> CpuLocalSlots<S> {
    fn new(vcpu_count: usize) -> Self {
        let mut slots = Vec::with_capacity(vcpu_count);
        slots.resize_with(vcpu_count, || None);
        Self {
            slots: SpinLock::new(slots),
        }
    }
}

impl<S: Clone> CpuLocalSlots<S> {
    #[inline]
    fn slot(&self, cpu: usize, init: impl FnOnce() -> S) -> S {
        let mut slots = self.slots.lock();
        slots
            .get_mut(cpu)
            .expect("FrameVM CPU-local slot is out of range")
            .get_or_insert_with(init)
            .clone()
    }
}

/// Guard for a current-CPU static CPU-local slot.
#[must_use]
pub struct CpuLocalGuard<'a, T: Send + Sync + 'static> {
    slot: Arc<T>,
    _guard: &'a DisabledLocalIrqGuard,
    _not_send_sync: PhantomData<*mut ()>,
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
    _not_send_sync: PhantomData<*mut ()>,
}

impl<T: Send + Sync + 'static> Deref for CpuLocalRemoteGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.slot.as_ref()
    }
}

/// An OSTD-shaped current-CPU value-operation cell.
pub struct CpuLocalCell<T: 'static> {
    init: fn() -> T,
    key: &'static str,
}

impl<T: 'static> CpuLocalCell<T> {
    /// Creates a CPU-local cell descriptor.
    pub const fn new(init: fn() -> T, key: &'static str) -> Self {
        Self { init, key }
    }
}

impl<T> CpuLocalCell<T>
where
    T: Send + 'static,
{
    #[inline]
    fn with_current<R>(&'static self, operation: impl FnOnce(&mut T) -> R) -> R {
        let (frame_vm, frame_vcpu_id) = current_frame_vcpu();
        let entry =
            frame_vm
                .cpu_local_domain()
                .typed_entry(self.key, frame_vcpu_id.vcpu_index(), || {
                    CpuLocalSlots::<Arc<SpinLock<T>>>::new(frame_vm.vcpu_count())
                });
        let slot = entry.slot(frame_vcpu_id.vcpu_index(), || {
            Arc::new(SpinLock::new((self.init)()))
        });
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

fn current_frame_vcpu() -> (Arc<vm::FrameVm>, FrameVcpuId) {
    let frame_vcpu_id = task::current_frame_vcpu_id()
        .expect("FrameVM CPU-local access requires a FrameVM vCPU context");
    let frame_vm = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        .expect("FrameVM CPU-local access requires a live owning FrameVM");
    assert!(
        frame_vcpu_id.vcpu_index() < frame_vm.vcpu_count(),
        "FrameVM CPU-local context has an invalid vCPU index"
    );
    (frame_vm, frame_vcpu_id)
}
