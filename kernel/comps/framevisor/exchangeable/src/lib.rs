// SPDX-License-Identifier: MPL-2.0

//! Exchangeable values and their cross-domain ownership carrier.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(feature = "ostd-domain")]
use ostd::{
    cpu::PinCurrentCpu,
    irq::{self, DisabledLocalIrqGuard},
};
use spin::Once;

/// The identity of the domain that owns an exchangeable value.
///
/// `Host` is the root kernel. `Guest(n)` is the FrameVM whose registry ID is
/// `n`; guest zero is deliberately distinct from the Host sentinel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VmId {
    /// The root kernel domain.
    #[default]
    Host,
    /// A FrameVM domain.
    Guest(u32),
}

impl VmId {
    /// Creates a guest VM identity from its registry number.
    pub const fn new(raw_id: u32) -> Self {
        Self::Guest(raw_id)
    }

    /// Returns the numeric guest ID, if this is a guest.
    pub const fn guest_id(self) -> Option<u32> {
        match self {
            Self::Host => None,
            Self::Guest(id) => Some(id),
        }
    }

    /// Returns whether this is the Host identity.
    pub const fn is_host(self) -> bool {
        matches!(self, Self::Host)
    }

    /// Returns whether this is a guest identity.
    pub const fn is_guest(self) -> bool {
        matches!(self, Self::Guest(_))
    }

    /// Adds an offset to a guest identity.
    pub const fn checked_add(self, offset: u32) -> Option<Self> {
        match self {
            Self::Host => None,
            Self::Guest(id) => match id.checked_add(offset) {
                Some(id) => Some(Self::Guest(id)),
                None => None,
            },
        }
    }

    #[inline]
    const fn encode(self) -> u64 {
        match self {
            Self::Host => 0,
            Self::Guest(id) => id as u64 + 1,
        }
    }

    #[inline]
    const fn decode(value: u64) -> Self {
        if value == 0 {
            return Self::Host;
        }

        // Only values produced by `encode` are stored. Keeping the assertion
        // here makes an invalid atomic value fail at the ownership boundary
        // instead of silently aliasing another VM.
        assert!(value <= u32::MAX as u64 + 1);
        Self::Guest((value - 1) as u32)
    }
}

impl From<u32> for VmId {
    fn from(raw_id: u32) -> Self {
        Self::new(raw_id)
    }
}

impl fmt::Display for VmId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => formatter.write_str("host"),
            Self::Guest(id) => id.fmt(formatter),
        }
    }
}

/// The accounting boundary for shared exchangeable payloads.
///
/// The provider owns no RRef table and receives no object identity. It only
/// moves the logical payload charge between the canonical VM identities.
pub trait RRefAccounting: Send + Sync {
    /// Reserves charge for a newly created payload.
    fn reserve(&self, owner: VmId, bytes: usize) -> bool;

    /// Moves charge after a successful ownership transfer.
    fn transfer(&self, source: VmId, target: VmId, bytes: usize) -> bool;

    /// Releases charge after the payload leaves the exchange heap.
    fn release(&self, owner: VmId, bytes: usize);
}

static ACCOUNTING: Once<Arc<dyn RRefAccounting>> = Once::new();

/// Installs the process-wide shared-payload accounting provider.
pub fn install_accounting(accounting: Arc<dyn RRefAccounting>) {
    ACCOUNTING.call_once(|| accounting);
}

fn accounting() -> Option<&'static Arc<dyn RRefAccounting>> {
    ACCOUNTING.get()
}

const VM_OVERRIDE_NONE: u64 = u64::MAX;
pub const MAX_VM_OVERRIDE_CPUS: usize = 256;

static CURRENT_VM_PROVIDER: Once<fn() -> VmId> = Once::new();
static VM_OVERRIDES: [AtomicU64; MAX_VM_OVERRIDE_CPUS] =
    [const { AtomicU64::new(VM_OVERRIDE_NONE) }; MAX_VM_OVERRIDE_CPUS];

/// Installs the runtime provider for the current FrameVM context.
pub fn init_current_vm_provider(provider: fn() -> VmId) {
    CURRENT_VM_PROVIDER.call_once(|| provider);
}

fn current_vm() -> VmId {
    current_vm_override()
        .or_else(|| CURRENT_VM_PROVIDER.get().map(|provider| provider()))
        .unwrap_or(VmId::Host)
}

/// Temporarily enters a VM ownership context.
#[derive(Debug)]
#[must_use]
pub struct VmContextGuard {
    cpu_index: usize,
    previous_override: u64,
    #[cfg(feature = "ostd-domain")]
    _irq_guard: DisabledLocalIrqGuard,
}

impl Drop for VmContextGuard {
    fn drop(&mut self) {
        VM_OVERRIDES[self.cpu_index].store(self.previous_override, Ordering::Release);
    }
}

/// Enters `vm_id` until the returned guard is dropped.
pub fn enter_vm(vm_id: VmId) -> VmContextGuard {
    #[cfg(feature = "ostd-domain")]
    {
        let irq_guard = irq::disable_local();
        let cpu_index = vm_override_cpu_index(irq_guard.current_cpu());
        let previous_override = VM_OVERRIDES[cpu_index].swap(vm_id.encode(), Ordering::AcqRel);
        return VmContextGuard {
            cpu_index,
            previous_override,
            _irq_guard: irq_guard,
        };
    }

    #[cfg(not(feature = "ostd-domain"))]
    {
        let previous_override = VM_OVERRIDES[0].swap(vm_id.encode(), Ordering::AcqRel);
        VmContextGuard {
            cpu_index: 0,
            previous_override,
        }
    }
}

#[cfg(feature = "ostd-domain")]
fn current_vm_override() -> Option<VmId> {
    let irq_guard = irq::disable_local();
    load_vm_override(vm_override_cpu_index(irq_guard.current_cpu()))
}

#[cfg(not(feature = "ostd-domain"))]
fn current_vm_override() -> Option<VmId> {
    load_vm_override(0)
}

fn load_vm_override(cpu_index: usize) -> Option<VmId> {
    let raw_vm = VM_OVERRIDES[cpu_index].load(Ordering::Acquire);
    (raw_vm != VM_OVERRIDE_NONE).then(|| VmId::decode(raw_vm))
}

#[cfg(feature = "ostd-domain")]
fn vm_override_cpu_index(cpu_id: ostd::cpu::CpuId) -> usize {
    let cpu_index = u32::from(cpu_id) as usize;
    assert!(
        cpu_index < MAX_VM_OVERRIDE_CPUS,
        "CPU ID {cpu_index} exceeds VM context capacity {MAX_VM_OVERRIDE_CPUS}"
    );
    cpu_index
}

/// Marks a type whose value may cross a FrameVM boundary.
pub trait Exchangeable: Send {
    /// Returns the logical bytes charged to the owning VM.
    fn allocation_size(&self) -> usize {
        size_of_val(self).max(1)
    }
}

impl Exchangeable for () {}

macro_rules! impl_exchangeable_for_copy_values {
    ($($ty:ty),* $(,)?) => {
        $(impl Exchangeable for $ty {})*
    };
}

impl_exchangeable_for_copy_values!(bool, u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);
impl Exchangeable for Vec<u8> {}

impl<T: Exchangeable + 'static> Exchangeable for RRef<T> {}

/// A typed, move-only reference to a shared exchange allocation.
pub struct RRef<T: Exchangeable + 'static> {
    owner: AtomicU64,
    allocation_size: usize,
    value: Option<Vec<T>>,
}

/// Error returned when a transfer cannot consume the original token.
pub struct RRefTransferError<T: Exchangeable + 'static> {
    rref: RRef<T>,
    error: RRefError,
}

impl<T: Exchangeable + 'static> RRefTransferError<T> {
    /// Returns the original token.
    pub fn into_rref(self) -> RRef<T> {
        self.rref
    }

    /// Returns the transfer failure reason.
    pub const fn error(&self) -> RRefError {
        self.error
    }
}

impl<T: Exchangeable + 'static> RRef<T> {
    /// Creates a token owned by the current VM context.
    pub fn new(value: T) -> Self {
        Self::try_new(value).expect("RRef accounting must be installed before creation")
    }

    /// Creates a token with an explicit owner.
    pub fn new_with_owner(value: T, owner: VmId) -> Self {
        Self::try_new_with_owner(value, owner)
            .expect("RRef accounting must be installed before creation")
    }

    /// Tries to create a token owned by the current VM context.
    pub fn try_new(value: T) -> Result<Self, RRefError> {
        Self::try_new_with_owner(value, current_vm())
    }

    /// Tries to create a token with an explicit owner.
    pub fn try_new_with_owner(value: T, owner: VmId) -> Result<Self, RRefError> {
        Self::try_new_with_owner_recoverable(value, owner).map_err(|(error, _)| error)
    }

    /// Tries to create a token and returns the payload on failure.
    pub fn try_new_with_owner_recoverable(value: T, owner: VmId) -> Result<Self, (RRefError, T)> {
        let Some(accounting) = accounting() else {
            return Err((RRefError::NotInitialized, value));
        };
        let allocation_size = value.allocation_size().max(1);
        if !accounting.reserve(owner, allocation_size) {
            return Err((RRefError::OutOfMemory, value));
        }

        let mut storage = Vec::new();
        if storage.try_reserve(1).is_err() {
            accounting.release(owner, allocation_size);
            return Err((RRefError::OutOfMemory, value));
        }
        storage.push(value);

        Ok(Self {
            owner: AtomicU64::new(owner.encode()),
            allocation_size,
            value: Some(storage),
        })
    }

    /// Returns the current owner.
    pub fn owner(&self) -> VmId {
        VmId::decode(self.owner.load(Ordering::Acquire))
    }

    /// Transfers ownership to another VM context.
    pub fn try_transfer_to(self, new_owner: VmId) -> Result<Self, RRefTransferError<T>> {
        let current_owner = self.owner();
        if current_owner != current_vm() {
            return Err(RRefTransferError {
                rref: self,
                error: RRefError::NotOwner,
            });
        }

        if current_owner != new_owner {
            let Some(accounting) = accounting() else {
                return Err(RRefTransferError {
                    rref: self,
                    error: RRefError::NotInitialized,
                });
            };
            if !accounting.transfer(current_owner, new_owner, self.allocation_size) {
                return Err(RRefTransferError {
                    rref: self,
                    error: RRefError::TransferRejected,
                });
            }
            self.owner.store(new_owner.encode(), Ordering::Release);
        }

        Ok(self)
    }

    /// Returns whether the current VM owns this token.
    pub fn is_owned_by_current(&self) -> bool {
        self.owner() == current_vm()
    }

    /// Returns the value, asserting current ownership.
    pub fn get(&self) -> &T {
        assert!(
            self.is_owned_by_current(),
            "current VM does not own this RRef"
        );
        self.value
            .as_ref()
            .and_then(|value| value.first())
            .expect("RRef value is missing")
    }

    /// Returns mutable access, asserting current ownership.
    pub fn get_mut(&mut self) -> &mut T {
        assert!(
            self.is_owned_by_current(),
            "current VM does not own this RRef"
        );
        self.value
            .as_mut()
            .and_then(|value| value.first_mut())
            .expect("RRef value is missing")
    }

    /// Returns a value reference only when the current VM owns the token.
    pub fn try_get(&self) -> Option<&T> {
        if !self.is_owned_by_current() {
            return None;
        }
        self.value.as_ref().and_then(|value| value.first())
    }

    /// Returns mutable value access only when the current VM owns the token.
    pub fn try_get_mut(&mut self) -> Option<&mut T> {
        if !self.is_owned_by_current() {
            return None;
        }
        self.value.as_mut().and_then(|value| value.first_mut())
    }

    /// Consumes the token and returns its value to the owning VM.
    pub fn try_into_inner(mut self) -> Result<T, Self> {
        if !self.is_owned_by_current() || self.value.is_none() {
            return Err(self);
        }
        let Some(accounting) = accounting() else {
            return Err(self);
        };

        let owner = self.owner();
        accounting.release(owner, self.allocation_size);
        Ok(self
            .value
            .take()
            .expect("RRef value was checked before release")
            .into_iter()
            .next()
            .expect("RRef allocation must contain its payload"))
    }
}

impl<T: Exchangeable + 'static> Drop for RRef<T> {
    fn drop(&mut self) {
        if self.value.is_some()
            && let Some(accounting) = accounting()
        {
            accounting.release(self.owner(), self.allocation_size);
        }
    }
}

impl<T: Exchangeable + 'static> core::ops::Deref for RRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T: Exchangeable + 'static> core::ops::DerefMut for RRef<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

/// Errors returned by an exchange ownership operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RRefError {
    /// The accounting provider has not been installed.
    NotInitialized,
    /// The current VM does not own the token.
    NotOwner,
    /// The owning VM rejected the logical payload charge.
    OutOfMemory,
    /// The ownership charge could not be moved to the target VM.
    TransferRejected,
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicUsize;

    use super::*;

    struct TestAccounting;

    impl RRefAccounting for TestAccounting {
        fn reserve(&self, _owner: VmId, _bytes: usize) -> bool {
            true
        }

        fn transfer(&self, _source: VmId, _target: VmId, _bytes: usize) -> bool {
            true
        }

        fn release(&self, _owner: VmId, _bytes: usize) {}
    }

    fn init_test_runtime() {
        install_accounting(Arc::new(TestAccounting));
    }

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Exchangeable for DropCounter {}

    #[test]
    fn vm_identity_keeps_host_separate_from_guest_zero() {
        assert_ne!(VmId::Host, VmId::new(0));
        assert_eq!(VmId::new(0).guest_id(), Some(0));

        let outer = enter_vm(VmId::new(0));
        assert_eq!(current_vm(), VmId::Guest(0));
        let inner = enter_vm(VmId::new(1));
        assert_eq!(current_vm(), VmId::Guest(1));
        drop(inner);
        assert_eq!(current_vm(), VmId::Guest(0));
        drop(outer);
        assert_eq!(current_vm(), VmId::Host);
    }

    #[test]
    fn transfer_requires_current_owner_and_preserves_token_on_failure() {
        init_test_runtime();
        let host = enter_vm(VmId::Host);
        let token = RRef::new_with_owner(7_u64, VmId::new(1));

        let token = match token.try_transfer_to(VmId::Host) {
            Ok(_) => panic!("a non-owner must not transfer a token"),
            Err(error) => {
                assert_eq!(error.error(), RRefError::NotOwner);
                error.into_rref()
            }
        };
        assert_eq!(token.owner(), VmId::new(1));
        assert!(token.try_get().is_none());
        drop(host);

        let guest = enter_vm(VmId::new(1));
        assert_eq!(*token.get(), 7);
        drop(guest);
    }

    #[test]
    fn dropping_from_another_context_releases_the_payload_once() {
        init_test_runtime();
        let drops = Arc::new(AtomicUsize::new(0));
        let host = enter_vm(VmId::Host);
        drop(RRef::new_with_owner(
            DropCounter(drops.clone()),
            VmId::new(2),
        ));
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        drop(host);
    }
}
