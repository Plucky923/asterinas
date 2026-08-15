//! Frame allocator wrappers exposed through the OSTD-compatible surface.

use alloc::sync::Arc;
#[cfg(ktest)]
use core::sync::atomic::{AtomicBool, Ordering};

use host_ostd::mm::{
    FrameAllocOptions as OstdFrameAllocOptions, frame::meta::AnyFrameMeta, io::VmIo,
};

use crate::{
    mm::{
        Frame,
        frame::segment::{Segment, SegmentLease},
        ownership,
    },
    prelude::Result,
    vm::{MemoryDomain, MemoryReservation, VmId},
};

pub struct FrameAllocOptions {
    inner: OstdFrameAllocOptions,
    zeroed: bool,
    #[cfg(ktest)]
    fail_next_host_allocation: AtomicBool,
    #[cfg(ktest)]
    fail_next_metadata_validation: AtomicBool,
}

impl Default for FrameAllocOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAllocOptions {
    pub fn new() -> Self {
        Self {
            inner: OstdFrameAllocOptions::new(),
            zeroed: true,
            #[cfg(ktest)]
            fail_next_host_allocation: AtomicBool::new(false),
            #[cfg(ktest)]
            fail_next_metadata_validation: AtomicBool::new(false),
        }
    }

    /// Forces the next Host backing request to fail in a ktest.
    #[cfg(ktest)]
    pub(crate) fn fail_next_host_allocation_for_test(&self) {
        self.fail_next_host_allocation
            .store(true, Ordering::Release);
    }

    /// Forces the next typed metadata construction to fail in a ktest.
    #[cfg(ktest)]
    pub(crate) fn fail_next_metadata_validation_for_test(&self) {
        self.fail_next_metadata_validation
            .store(true, Ordering::Release);
    }

    #[cfg(ktest)]
    fn should_fail_host_allocation(&self) -> bool {
        self.fail_next_host_allocation.swap(false, Ordering::AcqRel)
    }

    #[cfg(ktest)]
    fn should_fail_metadata_validation(&self) -> bool {
        self.fail_next_metadata_validation
            .swap(false, Ordering::AcqRel)
    }

    pub fn zeroed(&mut self, zeroed: bool) -> &mut Self {
        self.inner.zeroed(zeroed);
        self.zeroed = zeroed;
        self
    }

    pub fn alloc_frame(&self) -> Result<Frame<()>> {
        if let Some(frame_vcpu_id) = crate::task::current_frame_vcpu_id() {
            let frame_vm =
                crate::vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(crate::Error::AccessDenied)?;
            return self.alloc_frame_for_vm(frame_vm.memory(), frame_vm.id());
        }
        let frame = self.inner.alloc_frame()?;
        Ok(Frame::new_with_inner(frame))
    }

    /// Allocates an OSTD frame for the service-facing compatibility facade.
    ///
    /// The public value deliberately remains an OSTD frame so existing service
    /// code keeps its type identity. FrameVisor retains a hidden owner handle
    /// in `FrameOwners`; an allocation that has no external OSTD references is
    /// discovered by the next domain allocation or by VM teardown.
    #[doc(hidden)]
    pub fn alloc_frame_for_service(&self) -> Result<host_ostd::mm::Frame<()>> {
        let (domain, vm_id) = current_vm_domain().ok_or(crate::Error::AccessDenied)?;
        self.alloc_service_frame_for_vm(&domain, vm_id)
    }

    #[doc(hidden)]
    pub fn alloc_frame_with_for_service<M: AnyFrameMeta>(
        &self,
        metadata: M,
    ) -> Result<host_ostd::mm::Frame<M>> {
        let (domain, vm_id) = current_vm_domain().ok_or(crate::Error::AccessDenied)?;
        self.alloc_service_frame_with_for_vm(&domain, vm_id, metadata)
    }

    /// Allocates one frame charged to a specific FrameVM domain.
    ///
    /// Host OSTD remains responsible for the physical allocation.  FrameVisor
    /// admits the page first, records its provenance, and keeps one hidden
    /// owner reference before publishing the service-shaped value.
    pub(crate) fn alloc_frame_for_vm(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
    ) -> Result<Frame<()>> {
        if let Some((frame, owner)) = ownership::reserve_cached_frame(vm_id, domain) {
            let paddr = host_ostd::mm::HasPaddr::paddr(&frame);
            let Ok(reservation) = domain.reserve_reusable(crate::mm::PAGE_SIZE) else {
                let _ = ownership::restore_cached_frame(paddr, vm_id, domain);
                drop(frame);
                drop(owner);
                // The cache reservation was not admitted. Continue with a
                // fresh Host backing request, just as the no-cache path does
                // when the domain is full or stopping.
                return self.alloc_new_frame_for_vm(domain, vm_id);
            };
            if let Err(error) = reservation.commit() {
                let _ = ownership::restore_cached_frame(paddr, vm_id, domain);
                drop(frame);
                drop(owner);
                return Err(error);
            }
            ownership::commit_cached_frame(paddr, vm_id, domain);
            if self.zeroed {
                zero_frame(&frame)?;
            }
            return Ok(Frame::new_with_owner(frame, owner));
        }
        self.alloc_new_frame_for_vm(domain, vm_id)
    }

    fn alloc_new_frame_for_vm(&self, domain: &MemoryDomain, vm_id: VmId) -> Result<Frame<()>> {
        let (frame, reservation) = self.alloc_frame_backing(domain, vm_id)?;
        let (frame, owner) = ownership::adopt_frame(frame, vm_id, domain)?;
        if let Err(error) = reservation.commit() {
            let paddr = host_ostd::mm::HasPaddr::paddr(&frame);
            match ownership::discard_adopted_frame(paddr, vm_id, domain) {
                Ok(hidden) => {
                    drop(owner);
                    drop(frame);
                    drop(hidden);
                }
                Err(rollback_error) => {
                    ::log::error!(
                        "[framevisor] failed to roll back frame admission for VM {}: {:?}",
                        vm_id,
                        rollback_error
                    );
                }
            }
            return Err(error);
        }
        Ok(Frame::new_with_owner(frame, owner))
    }

    pub fn alloc_frame_with<M: AnyFrameMeta>(&self, metadata: M) -> Result<Frame<M>> {
        if let Some(frame_vcpu_id) = crate::task::current_frame_vcpu_id() {
            let frame_vm =
                crate::vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(crate::Error::AccessDenied)?;
            return self.alloc_frame_with_for_vm(frame_vm.memory(), frame_vm.id(), metadata);
        }
        let frame = self.inner.alloc_frame_with(metadata)?;
        Ok(Frame::new_with_inner(frame))
    }

    fn alloc_frame_with_for_vm<M: AnyFrameMeta>(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
        metadata: M,
    ) -> Result<Frame<M>> {
        let (frame, reservation) = self.alloc_frame_with_backing(domain, vm_id, metadata)?;
        let (frame, owner) = ownership::adopt_frame(frame, vm_id, domain)?;
        if let Err(error) = reservation.commit() {
            let paddr = host_ostd::mm::HasPaddr::paddr(&frame);
            match ownership::discard_adopted_frame(paddr, vm_id, domain) {
                Ok(hidden) => {
                    drop(owner);
                    drop(frame);
                    drop(hidden);
                }
                Err(rollback_error) => {
                    ::log::error!(
                        "[framevisor] failed to roll back typed frame admission for VM {}: {:?}",
                        vm_id,
                        rollback_error
                    );
                }
            }
            return Err(error);
        }
        Ok(Frame::new_with_owner(frame, owner))
    }

    pub fn alloc_segment(&self, nframes: usize) -> Result<Segment<()>> {
        if let Some(frame_vcpu_id) = crate::task::current_frame_vcpu_id() {
            let frame_vm =
                crate::vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(crate::Error::AccessDenied)?;
            return self.alloc_segment_for_vm(frame_vm.memory(), frame_vm.id(), nframes);
        }
        let ostd_segment = self.inner.alloc_segment(nframes)?;
        Ok(Segment::new_with_inner(ostd_segment))
    }

    #[doc(hidden)]
    pub fn alloc_segment_for_service(&self, nframes: usize) -> Result<host_ostd::mm::Segment<()>> {
        let (domain, vm_id) = current_vm_domain().ok_or(crate::Error::AccessDenied)?;
        self.alloc_service_segment_for_vm(&domain, vm_id, nframes)
    }

    /// Allocates one contiguous untyped segment charged to a FrameVM domain.
    pub(crate) fn alloc_segment_for_vm(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
        nframes: usize,
    ) -> Result<Segment<()>> {
        if nframes == 0 {
            return Err(crate::Error::InvalidArgs);
        }
        let (segment, reservation) = self.alloc_segment_backing(domain, vm_id, nframes)?;
        let start = host_ostd::mm::HasPaddr::paddr(&segment);
        if let Err(error) = ownership::adopt_segment(&segment, vm_id, domain) {
            drop(segment);
            drop(reservation);
            return Err(error);
        }
        if let Err(error) = reservation.commit() {
            if let Err(rollback_error) = ownership::discard_adopted_segment(&segment, vm_id, domain)
            {
                ::log::error!(
                    "[framevisor] failed to roll back segment admission for VM {}: {:?}",
                    vm_id,
                    rollback_error
                );
            }
            drop(segment);
            return Err(error);
        }
        Ok(Segment::new_with_owner(
            segment,
            Arc::new(SegmentLease::new(start)),
        ))
    }

    pub fn alloc_segment_with<M: AnyFrameMeta, F>(
        &self,
        nframes: usize,
        metadata_fn: F,
    ) -> Result<Segment<M>>
    where
        F: FnMut(crate::mm::Paddr) -> M,
    {
        if let Some(frame_vcpu_id) = crate::task::current_frame_vcpu_id() {
            let frame_vm =
                crate::vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(crate::Error::AccessDenied)?;
            return self.alloc_segment_with_for_vm(
                frame_vm.memory(),
                frame_vm.id(),
                nframes,
                metadata_fn,
            );
        }
        let segment = self.inner.alloc_segment_with(nframes, metadata_fn)?;
        Ok(Segment::new_with_inner(segment))
    }

    fn alloc_segment_with_for_vm<M: AnyFrameMeta, F>(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
        nframes: usize,
        metadata_fn: F,
    ) -> Result<Segment<M>>
    where
        F: FnMut(crate::mm::Paddr) -> M,
    {
        if nframes == 0 {
            return Err(crate::Error::InvalidArgs);
        }
        let (segment, reservation) =
            self.alloc_segment_with_backing(domain, vm_id, nframes, metadata_fn)?;
        let start = host_ostd::mm::HasPaddr::paddr(&segment);
        if let Err(error) = ownership::adopt_segment(&segment, vm_id, domain) {
            drop(segment);
            drop(reservation);
            return Err(error);
        }
        if let Err(error) = reservation.commit() {
            if let Err(rollback_error) = ownership::discard_adopted_segment(&segment, vm_id, domain)
            {
                ::log::error!(
                    "[framevisor] failed to roll back typed segment admission for VM {}: {:?}",
                    vm_id,
                    rollback_error
                );
            }
            drop(segment);
            return Err(error);
        }
        Ok(Segment::new_with_owner(
            segment,
            Arc::new(SegmentLease::new(start)),
        ))
    }

    fn alloc_frame_backing<'a>(
        &self,
        domain: &'a MemoryDomain,
        vm_id: VmId,
    ) -> Result<(host_ostd::mm::Frame<()>, MemoryReservation<'a>)> {
        loop {
            let reservation = domain.reserve(crate::mm::PAGE_SIZE)?;
            #[cfg(ktest)]
            if self.should_fail_host_allocation() {
                drop(reservation);
                return Err(crate::Error::NoMemory);
            }
            match self.inner.alloc_frame() {
                Ok(frame) => {
                    // A fresh Host grant is scrubbed regardless of the
                    // caller's `zeroed` preference.  That preference only
                    // controls same-domain cache reuse; it must not expose
                    // stale Host data to a FrameVM.
                    frame.zero();
                    return Ok((frame, reservation));
                }
                Err(host_ostd::Error::NoMemory) => {
                    drop(reservation);
                    if !crate::mm::provider::reclaim_after_oom(vm_id)? {
                        return Err(crate::Error::NoMemory);
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn alloc_frame_with_backing<'a, M: AnyFrameMeta>(
        &self,
        domain: &'a MemoryDomain,
        vm_id: VmId,
        metadata: M,
    ) -> Result<(host_ostd::mm::Frame<M>, MemoryReservation<'a>)> {
        let reservation = domain.reserve(crate::mm::PAGE_SIZE)?;
        match self.inner.alloc_frame_with(metadata) {
            Ok(frame) => {
                #[cfg(ktest)]
                if self.should_fail_metadata_validation() {
                    drop(frame);
                    drop(reservation);
                    return Err(crate::Error::InvalidArgs);
                }
                frame.zero();
                Ok((frame, reservation))
            }
            Err(host_ostd::Error::NoMemory) => {
                drop(reservation);
                // A typed metadata value is consumed by OSTD before the
                // physical frame is constructed, so it cannot be retried
                // safely without changing OSTD's API. Untyped and segment
                // paths perform the reclaim-and-retry loop below.
                let _ = crate::mm::provider::reclaim_after_oom(vm_id)?;
                Err(crate::Error::NoMemory)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn alloc_segment_backing<'a>(
        &self,
        domain: &'a MemoryDomain,
        vm_id: VmId,
        nframes: usize,
    ) -> Result<(host_ostd::mm::Segment<()>, MemoryReservation<'a>)> {
        let bytes = nframes
            .checked_mul(crate::mm::PAGE_SIZE)
            .ok_or(crate::Error::Overflow)?;
        loop {
            let reservation = domain.reserve(bytes)?;
            #[cfg(ktest)]
            if self.should_fail_host_allocation() {
                drop(reservation);
                return Err(crate::Error::NoMemory);
            }
            match self.inner.alloc_segment(nframes) {
                Ok(segment) => {
                    segment.zero();
                    return Ok((segment, reservation));
                }
                Err(host_ostd::Error::NoMemory) => {
                    drop(reservation);
                    if !crate::mm::provider::reclaim_after_oom(vm_id)? {
                        return Err(crate::Error::NoMemory);
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Allocates an untyped segment for a provider that must let Host OSTD
    /// construct the public `Segment` value itself.
    pub(crate) fn alloc_provider_segment_for_vm(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
        nframes: usize,
    ) -> Result<host_ostd::mm::Segment<()>> {
        if nframes == 0 {
            return Err(crate::Error::InvalidArgs);
        }
        ownership::cache_idle_for_vm(vm_id)?;
        let (segment, reservation) = self.alloc_segment_backing(domain, vm_id, nframes)?;
        if let Err(error) = ownership::adopt_segment(&segment, vm_id, domain) {
            drop(segment);
            drop(reservation);
            return Err(error);
        }
        if let Err(error) = reservation.commit() {
            if let Err(rollback_error) = ownership::discard_adopted_segment(&segment, vm_id, domain)
            {
                ::log::error!(
                    "[framevisor] failed to roll back provider segment admission for VM {}: {:?}",
                    vm_id,
                    rollback_error
                );
            }
            drop(segment);
            return Err(error);
        }
        Ok(segment)
    }

    fn alloc_segment_with_backing<'a, M: AnyFrameMeta, F>(
        &self,
        domain: &'a MemoryDomain,
        vm_id: VmId,
        nframes: usize,
        mut metadata_fn: F,
    ) -> Result<(host_ostd::mm::Segment<M>, MemoryReservation<'a>)>
    where
        F: FnMut(crate::mm::Paddr) -> M,
    {
        let bytes = nframes
            .checked_mul(crate::mm::PAGE_SIZE)
            .ok_or(crate::Error::Overflow)?;
        loop {
            let reservation = domain.reserve(bytes)?;
            match self.inner.alloc_segment_with(nframes, &mut metadata_fn) {
                Ok(segment) => {
                    #[cfg(ktest)]
                    if self.should_fail_metadata_validation() {
                        drop(segment);
                        drop(reservation);
                        return Err(crate::Error::InvalidArgs);
                    }
                    segment.zero();
                    return Ok((segment, reservation));
                }
                Err(host_ostd::Error::NoMemory) => {
                    drop(reservation);
                    if !crate::mm::provider::reclaim_after_oom(vm_id)? {
                        return Err(crate::Error::NoMemory);
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    #[doc(hidden)]
    pub fn alloc_segment_with_for_service<M: AnyFrameMeta, F>(
        &self,
        nframes: usize,
        metadata_fn: F,
    ) -> Result<host_ostd::mm::Segment<M>>
    where
        F: FnMut(crate::mm::Paddr) -> M,
    {
        let (domain, vm_id) = current_vm_domain().ok_or(crate::Error::AccessDenied)?;
        self.alloc_service_segment_with_for_vm(&domain, vm_id, nframes, metadata_fn)
    }

    fn alloc_service_frame_for_vm(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
    ) -> Result<host_ostd::mm::Frame<()>> {
        if let Some(frame_vm) = crate::vm::get_vm_by_id(vm_id)
            && frame_vm.memory().is_same(domain)
        {
            return frame_vm
                .allocator()
                .alloc_service_untyped_frame(self.zeroed);
        }
        ownership::cache_idle_for_vm(vm_id)?;
        if let Some((frame, lease)) = ownership::reserve_cached_frame(vm_id, domain) {
            let paddr = host_ostd::mm::HasPaddr::paddr(&frame);
            if let Ok(reservation) = domain.reserve_reusable(crate::mm::PAGE_SIZE) {
                if let Err(error) = reservation.commit() {
                    let _ = ownership::restore_cached_frame(paddr, vm_id, domain);
                    drop(frame);
                    drop(lease);
                    return Err(error);
                }
                ownership::commit_cached_frame(paddr, vm_id, domain);
                if self.zeroed {
                    zero_frame(&frame)?;
                }
                // The OSTD frame is the service-side reference. Once it is
                // dropped, the lease can put the hidden owner back into the
                // domain cache without returning it to Host.
                drop(lease);
                return Ok(frame);
            } else {
                let _ = ownership::restore_cached_frame(paddr, vm_id, domain);
                drop(frame);
                drop(lease);
            }
        }

        let (frame, reservation) = self.alloc_frame_backing(domain, vm_id)?;
        let (frame, owner) = match ownership::adopt_frame(frame, vm_id, domain) {
            Ok(result) => result,
            Err(error) => {
                drop(reservation);
                return Err(error);
            }
        };
        if let Err(error) = reservation.commit() {
            let paddr = host_ostd::mm::HasPaddr::paddr(&frame);
            match ownership::discard_adopted_frame(paddr, vm_id, domain) {
                Ok(hidden) => {
                    drop(owner);
                    drop(frame);
                    drop(hidden);
                }
                Err(rollback_error) => {
                    ::log::error!(
                        "[framevisor] failed to roll back service frame admission for VM {}: {:?}",
                        vm_id,
                        rollback_error
                    );
                }
            }
            return Err(error);
        }
        drop(owner);
        Ok(frame)
    }

    fn alloc_service_frame_with_for_vm<M: AnyFrameMeta>(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
        metadata: M,
    ) -> Result<host_ostd::mm::Frame<M>> {
        if let Some(frame_vm) = crate::vm::get_vm_by_id(vm_id)
            && frame_vm.memory().is_same(domain)
        {
            return frame_vm
                .allocator()
                .alloc_service_frame(metadata, self.zeroed);
        }
        ownership::cache_idle_for_vm(vm_id)?;
        let (frame, reservation) = self.alloc_frame_with_backing(domain, vm_id, metadata)?;
        let (frame, owner) = match ownership::adopt_frame(frame, vm_id, domain) {
            Ok(result) => result,
            Err(error) => {
                drop(reservation);
                return Err(error);
            }
        };
        if let Err(error) = reservation.commit() {
            let paddr = host_ostd::mm::HasPaddr::paddr(&frame);
            match ownership::discard_adopted_frame(paddr, vm_id, domain) {
                Ok(hidden) => {
                    drop(owner);
                    drop(frame);
                    drop(hidden);
                }
                Err(rollback_error) => {
                    ::log::error!(
                        "[framevisor] failed to roll back typed service frame admission for VM {}: {:?}",
                        vm_id,
                        rollback_error
                    );
                }
            }
            return Err(error);
        }
        drop(owner);
        Ok(frame)
    }

    pub(crate) fn alloc_service_segment_for_vm(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
        nframes: usize,
    ) -> Result<host_ostd::mm::Segment<()>> {
        if let Some(frame_vm) = crate::vm::get_vm_by_id(vm_id)
            && frame_vm.memory().is_same(domain)
        {
            return frame_vm
                .allocator()
                .alloc_service_segment(nframes, |_| (), self.zeroed);
        }
        ownership::cache_idle_for_vm(vm_id)?;
        if nframes == 0 {
            return Err(crate::Error::InvalidArgs);
        }
        let (segment, reservation) = self.alloc_segment_backing(domain, vm_id, nframes)?;
        if let Err(error) = ownership::adopt_segment(&segment, vm_id, domain) {
            drop(segment);
            drop(reservation);
            return Err(error);
        }
        if let Err(error) = reservation.commit() {
            if let Err(rollback_error) = ownership::discard_adopted_segment(&segment, vm_id, domain)
            {
                ::log::error!(
                    "[framevisor] failed to roll back service segment admission for VM {}: {:?}",
                    vm_id,
                    rollback_error
                );
            }
            drop(segment);
            return Err(error);
        }
        Ok(segment)
    }

    fn alloc_service_segment_with_for_vm<M: AnyFrameMeta, F>(
        &self,
        domain: &MemoryDomain,
        vm_id: VmId,
        nframes: usize,
        metadata_fn: F,
    ) -> Result<host_ostd::mm::Segment<M>>
    where
        F: FnMut(crate::mm::Paddr) -> M,
    {
        if let Some(frame_vm) = crate::vm::get_vm_by_id(vm_id)
            && frame_vm.memory().is_same(domain)
        {
            return frame_vm
                .allocator()
                .alloc_service_segment(nframes, metadata_fn, self.zeroed);
        }
        ownership::cache_idle_for_vm(vm_id)?;
        if nframes == 0 {
            return Err(crate::Error::InvalidArgs);
        }
        let (segment, reservation) =
            self.alloc_segment_with_backing(domain, vm_id, nframes, metadata_fn)?;
        if let Err(error) = ownership::adopt_segment(&segment, vm_id, domain) {
            drop(segment);
            drop(reservation);
            return Err(error);
        }
        if let Err(error) = reservation.commit() {
            if let Err(rollback_error) = ownership::discard_adopted_segment(&segment, vm_id, domain)
            {
                ::log::error!(
                    "[framevisor] failed to roll back typed service segment admission for VM {}: {:?}",
                    vm_id,
                    rollback_error
                );
            }
            drop(segment);
            return Err(error);
        }
        Ok(segment)
    }
}

fn current_vm_domain() -> Option<(MemoryDomain, VmId)> {
    let frame_vcpu_id = crate::task::current_frame_vcpu_id()?;
    let frame_vm = crate::vm::get_vm_by_id(frame_vcpu_id.vm_id())?;
    Some((frame_vm.memory().clone(), frame_vm.id()))
}

fn zero_frame(frame: &host_ostd::mm::Frame<()>) -> Result<()> {
    let zero_page = [0u8; crate::mm::PAGE_SIZE];
    frame.write_bytes(0, &zero_page).map_err(Into::into)
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;
    use crate::mm::HasPaddr;

    #[ktest]
    fn domain_frame_path_charges_and_caches_one_page() {
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        let frame = FrameAllocOptions::new()
            .alloc_frame_for_vm(&domain, crate::vm::VmId::new(23))
            .unwrap();
        assert_eq!(domain.stats().active, crate::mm::PAGE_SIZE);
        let paddr = frame.paddr();
        assert_ne!(paddr, 0);
        drop(frame);
        assert_eq!(domain.stats().reusable, crate::mm::PAGE_SIZE);
        let reused = FrameAllocOptions::new()
            .alloc_frame_for_vm(&domain, crate::vm::VmId::new(23))
            .unwrap();
        assert_eq!(reused.paddr(), paddr);
        assert_eq!(domain.stats().active, crate::mm::PAGE_SIZE);
        drop(reused);
        ownership::release_cached_page(paddr, crate::vm::VmId::new(23)).unwrap();
    }

    #[ktest]
    fn domain_segment_path_keeps_every_member_page_owned() {
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE * 2, 0).unwrap();
        let segment = FrameAllocOptions::new()
            .alloc_segment_for_vm(&domain, crate::vm::VmId::new(24), 2)
            .unwrap();
        assert_eq!(domain.stats().active, crate::mm::PAGE_SIZE * 2);
        let start = segment.paddr();
        drop(segment);
        // The last SegmentLease clears the extent-level marker atomically;
        // every detached member is now reusable without reconstructing OSTD
        // metadata.
        assert_eq!(domain.stats().reusable, crate::mm::PAGE_SIZE * 2);
        assert_eq!(
            ownership::release_quiesced_for_vm(crate::vm::VmId::new(24)).unwrap(),
            2
        );
        assert_eq!(domain.stats().committed, 0);
        assert_eq!(ownership::owner_of(start), None);
    }

    #[ktest]
    fn host_pressure_reclaims_only_cached_pages() {
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        let frame = FrameAllocOptions::new()
            .alloc_frame_for_vm(&domain, crate::vm::VmId::new(25))
            .unwrap();
        let paddr = frame.paddr();
        assert_eq!(
            ownership::owner_of(paddr),
            Some(ownership::FrameOwner::FrameVm(crate::vm::VmId::new(25)))
        );
        drop(frame);
        assert_eq!(domain.stats().reusable, crate::mm::PAGE_SIZE);
        while ownership::owner_of(paddr).is_some() {
            assert!(ownership::reclaim_one_cached().unwrap());
        }
        assert_eq!(domain.stats().committed, 0);
        assert_eq!(ownership::owner_of(paddr), None);
    }

    #[ktest]
    fn host_allocation_failure_rolls_back_domain_and_owner_state() {
        let vm_id = crate::vm::VmId::new(26);
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        let options = FrameAllocOptions::new();
        let before = domain.stats();
        let owners_before = ownership::owner_count_for_vm(vm_id, &domain);

        options.fail_next_host_allocation_for_test();
        assert!(matches!(
            options.alloc_frame_for_vm(&domain, vm_id),
            Err(crate::Error::NoMemory)
        ));

        assert_eq!(domain.stats(), before);
        assert_eq!(ownership::owner_count_for_vm(vm_id, &domain), owners_before);
    }

    #[ktest]
    fn metadata_validation_failure_releases_host_frame_and_charge() {
        let vm_id = crate::vm::VmId::new(27);
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        let options = FrameAllocOptions::new();
        let before = domain.stats();
        let owners_before = ownership::owner_count_for_vm(vm_id, &domain);

        options.fail_next_metadata_validation_for_test();
        assert!(matches!(
            options.alloc_frame_with_for_vm(&domain, vm_id, ()),
            Err(crate::Error::InvalidArgs)
        ));

        assert_eq!(domain.stats(), before);
        assert_eq!(ownership::owner_count_for_vm(vm_id, &domain), owners_before);
    }

    #[ktest]
    fn local_oom_returns_allocation_error_without_closing_domain() {
        let vm_id = crate::vm::VmId::new(28);
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE * 2, 0).unwrap();
        let options = FrameAllocOptions::new();
        let first = options.alloc_frame_for_vm(&domain, vm_id).unwrap();
        let second = options.alloc_frame_for_vm(&domain, vm_id).unwrap();
        let full = domain.stats();
        assert_eq!(full.active, crate::mm::PAGE_SIZE * 2);

        assert!(matches!(
            options.alloc_frame_for_vm(&domain, vm_id),
            Err(crate::Error::NoMemory)
        ));
        let oom = domain.stats();
        assert_eq!(oom.committed, full.committed);
        assert_eq!(oom.reserved, full.reserved);
        assert_eq!(oom.oom_count, full.oom_count + 1);

        drop(first);
        drop(second);
        assert_eq!(ownership::release_quiesced_for_vm(vm_id).unwrap(), 2);
        assert_eq!(domain.stats().committed, 0);
    }
}
