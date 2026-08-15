// SPDX-License-Identifier: MPL-2.0

//! Physical-frame provenance retained by FrameVisor.
//!
//! OSTD owns the allocator and the metadata embedded in each physical frame.
//! This table is deliberately a side table: it records which FrameVisor
//! domain was granted a page and retains one hidden OSTD handle so a service
//! value cannot return the page to the Host merely by being dropped.

use alloc::{collections::BTreeMap, sync::Arc};

use host_ostd::mm::{
    Frame as OstdFrame, HasPaddr, HasSize, Segment as OstdSegment, UFrame as OstdUFrame,
    frame::meta::AnyFrameMeta, io::VmIo,
};

use crate::{
    Error, Result,
    mm::Paddr,
    sync::{Once, SpinLock},
    vm::{MemoryDomain, VmId},
};

/// The physical owner recorded for one page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameOwner {
    /// The page is available to Host OSTD.
    #[expect(
        dead_code,
        reason = "Host provenance is retained for the transfer protocol"
    )]
    Host,
    /// The page is retained by one FrameVM domain.
    FrameVm(VmId),
    /// The page is being scrubbed before returning to Host OSTD.
    Releasing(VmId),
}

struct OwnerRecord {
    owner: FrameOwner,
    /// Execution generation that admitted this physical extent.
    generation: u64,
    /// The only FrameVisor-owned OSTD reference.  Service and mapping
    /// references are separate OSTD clones and are observed through the
    /// reference count when the lease is dropped.
    hidden: OstdFrame<dyn AnyFrameMeta>,
    domain: MemoryDomain,
    cached: bool,
    /// Whether an image-defined provider retains opaque cache state for this
    /// page. Provider-managed pages are never guessed to be reclaimable.
    provider_managed: bool,
    /// Whether the metadata permits byte access through an OSTD untyped view.
    /// This is captured while the allocating image is mapped so teardown does
    /// not call `AnyFrameMeta::is_untyped` through an unloaded service vtable.
    untyped: bool,
    /// Whether the page was created through the service image's OSTD
    /// allocator. The Host keeps these pages isolated until a service-specific
    /// teardown protocol can release their opaque metadata safely.
    service_owned: bool,
    /// Whether this page belongs to a contiguous OSTD segment. OSTD may
    /// return segment members one at a time, so segment members are never
    /// entered into the page cache independently.
    segment_owned: bool,
    /// The complete extent recorded by a native OSTD segment callback. A
    /// service `Segment` has no FrameVisor wrapper lease, so idle callbacks
    /// use this range to detach all members atomically once every member is
    /// hidden-owner-only.
    segment_start: Option<Paddr>,
    segment_end: Option<Paddr>,
    /// Whether an allocator has selected this cached page for a reusable
    /// allocation but has not committed the matching domain reservation yet.
    /// Keeping this transition in the owner table closes the race where Host
    /// reclaim could otherwise start releasing the page between the domain
    /// counter update and the ownership lookup.
    reusable_reserved: bool,
    /// Temporary OSTD views used while a raw provider pointer is active.
    busy: usize,
}

/// A handle carried by FrameVisor-shaped values.
pub(crate) struct FrameLease {
    paddr: Paddr,
}

impl Drop for FrameLease {
    fn drop(&mut self) {
        // A mapping or DMA reference may still exist after the service value
        // is gone.  In that case the owner record remains until the explicit
        // FrameVisor reclaim/teardown scan observes the hidden-owner-only
        // state.  The check is intentionally non-allocating.
        let _ = cache_if_idle(self.paddr);
    }
}

static OWNERS: Once<SpinLock<BTreeMap<Paddr, OwnerRecord>>> = Once::new();

fn owners() -> &'static SpinLock<BTreeMap<Paddr, OwnerRecord>> {
    OWNERS.call_once(|| SpinLock::new(BTreeMap::new()))
}

/// Adopts a freshly allocated Host OSTD frame for one FrameVM.
pub(crate) fn adopt_frame<M>(
    frame: OstdFrame<M>,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> Result<(OstdFrame<M>, Arc<FrameLease>)>
where
    M: AnyFrameMeta + ?Sized,
{
    adopt_frame_with_policy(frame, vm_id, domain, false, false, false)
}

fn adopt_frame_with_policy<M>(
    frame: OstdFrame<M>,
    vm_id: VmId,
    domain: &MemoryDomain,
    provider_managed: bool,
    service_owned: bool,
    segment_owned: bool,
) -> Result<(OstdFrame<M>, Arc<FrameLease>)>
where
    M: AnyFrameMeta + ?Sized,
{
    let paddr = frame.paddr();
    let untyped = frame.dyn_meta().is_untyped();
    let hidden = OstdFrame::<dyn AnyFrameMeta>::from_unsized(frame.clone());
    let mut table = owners().lock();
    if table.contains_key(&paddr) {
        drop(table);
        return Err(Error::AccessDenied);
    }
    table.insert(
        paddr,
        OwnerRecord {
            owner: FrameOwner::FrameVm(vm_id),
            generation: domain.generation(),
            hidden,
            domain: domain.clone(),
            cached: false,
            provider_managed,
            untyped,
            service_owned,
            segment_owned,
            segment_start: None,
            segment_end: None,
            reusable_reserved: false,
            busy: 0,
        },
    );
    drop(table);
    Ok((frame, Arc::new(FrameLease { paddr })))
}

/// Removes one provisional owner after its admission transaction failed.
///
/// The caller still owns the public OSTD frame, so removing the hidden handle
/// here leaves the final public drop responsible for the normal allocator
/// return.  This is used only before a newly-admitted value is published.
pub(crate) fn discard_adopted_frame(
    paddr: Paddr,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> Result<OstdFrame<dyn AnyFrameMeta>> {
    let mut table = owners().lock();
    let record = table.get(&paddr).ok_or(Error::AccessDenied)?;
    if record.owner != FrameOwner::FrameVm(vm_id)
        || record.generation != domain.generation()
        || !record.domain.is_same(domain)
        || record.cached
        || record.busy != 0
        || record.hidden.reference_count() != 2
    {
        return Err(Error::AccessDenied);
    }
    table
        .remove(&paddr)
        .map(|record| record.hidden)
        .ok_or(Error::AccessDenied)
}

/// Records a frame allocated through the current service image's OSTD
/// provider.
pub(crate) fn adopt_existing_frame_for_service(
    hidden: OstdFrame<dyn AnyFrameMeta>,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> bool {
    adopt_existing_frame_with_policy(hidden, vm_id, domain, false, true, false)
}

/// Records a frame whose cache policy is retained by an image-defined
/// provider. The page remains charged until that provider is quiesced.
pub(crate) fn adopt_existing_frame_with_provider(
    hidden: OstdFrame<dyn AnyFrameMeta>,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> bool {
    adopt_existing_frame_with_policy(hidden, vm_id, domain, true, true, false)
}

fn adopt_existing_frame_with_policy(
    hidden: OstdFrame<dyn AnyFrameMeta>,
    vm_id: VmId,
    domain: &MemoryDomain,
    provider_managed: bool,
    service_owned: bool,
    segment_owned: bool,
) -> bool {
    let paddr = hidden.paddr();
    let untyped = hidden.dyn_meta().is_untyped();
    let mut table = owners().lock();
    if table.contains_key(&paddr) {
        return false;
    }
    table.insert(
        paddr,
        OwnerRecord {
            owner: FrameOwner::FrameVm(vm_id),
            generation: domain.generation(),
            hidden,
            domain: domain.clone(),
            cached: false,
            provider_managed,
            untyped,
            service_owned,
            segment_owned,
            segment_start: None,
            segment_end: None,
            reusable_reserved: false,
            busy: 0,
        },
    );
    true
}

/// Records a segment allocated through the current service image's OSTD
/// provider.
pub(crate) fn adopt_existing_segment_for_service(
    segment: OstdSegment<dyn AnyFrameMeta>,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> bool {
    adopt_existing_segment_with_policy(segment, vm_id, domain, false, true)
}

/// Records a segment whose cache policy remains opaque to FrameVisor.
pub(crate) fn adopt_existing_segment_with_provider(
    segment: OstdSegment<dyn AnyFrameMeta>,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> bool {
    adopt_existing_segment_with_policy(segment, vm_id, domain, true, true)
}

fn adopt_existing_segment_with_policy(
    mut segment: OstdSegment<dyn AnyFrameMeta>,
    vm_id: VmId,
    domain: &MemoryDomain,
    provider_managed: bool,
    service_owned: bool,
) -> bool {
    let start = segment.paddr();
    let size = segment.size();
    if size == 0 || !start.is_multiple_of(crate::mm::PAGE_SIZE) {
        return false;
    }
    let Some(end) = start.checked_add(size) else {
        return false;
    };
    if !size.is_multiple_of(crate::mm::PAGE_SIZE) {
        return false;
    }
    let expected_pages = size / crate::mm::PAGE_SIZE;
    let mut adopted = 0;
    for frame in &mut segment {
        if !adopt_existing_frame_with_policy(
            frame,
            vm_id,
            domain,
            provider_managed,
            service_owned,
            true,
        ) {
            remove_adopted_segment_pages(start, adopted, vm_id, domain);
            return false;
        }
        let Some(next_adopted) = adopted.checked_add(1) else {
            remove_adopted_segment_pages(start, adopted, vm_id, domain);
            return false;
        };
        adopted = next_adopted;
    }
    if adopted == expected_pages && mark_segment_range(start, end, vm_id, domain) {
        return true;
    }

    remove_adopted_segment_pages(start, adopted, vm_id, domain);
    false
}

fn remove_adopted_segment_pages(start: Paddr, pages: usize, vm_id: VmId, domain: &MemoryDomain) {
    let Some(bytes) = pages.checked_mul(crate::mm::PAGE_SIZE) else {
        return;
    };
    let Some(end) = start.checked_add(bytes) else {
        return;
    };
    for paddr in (start..end).step_by(crate::mm::PAGE_SIZE) {
        remove_owner_without_release(paddr, vm_id, domain);
    }
}

fn remove_owner_without_release(paddr: Paddr, vm_id: VmId, domain: &MemoryDomain) {
    let record = {
        let mut table = owners().lock();
        let Some(record) = table.get(&paddr) else {
            return;
        };
        if record.owner != FrameOwner::FrameVm(vm_id)
            || record.generation != domain.generation()
            || !record.domain.is_same(domain)
        {
            return;
        }
        table.remove(&paddr)
    };
    let Some(record) = record else {
        return;
    };
    drop_hidden_owner(record);
}

/// Returns whether FrameVisor still tracks one physical page.
pub(crate) fn has_owner(paddr: Paddr) -> bool {
    owners().lock().contains_key(&paddr)
}

/// Returns the FrameVM recorded for one owned page.
pub(crate) fn owner_vm(paddr: Paddr) -> Option<VmId> {
    let table = owners().lock();
    let record = table.get(&paddr)?;
    if record.generation != record.domain.generation() {
        return None;
    }
    match record.owner {
        FrameOwner::FrameVm(vm_id) | FrameOwner::Releasing(vm_id) => Some(vm_id),
        FrameOwner::Host => None,
    }
}

/// Returns whether an image-defined provider controls this page's cache
/// policy. FrameVisor must not reclaim opaque provider state by inference.
pub(crate) fn provider_managed(paddr: Paddr) -> bool {
    owners()
        .lock()
        .get(&paddr)
        .is_some_and(|record| record.provider_managed)
}

/// Returns whether a VM still has an opaque provider-owned frame record.
///
/// A provider may keep additional OSTD references in image code after the
/// service-facing reference has drained.  FrameVisor cannot infer that cache's
/// contents, so the allocator image must remain mapped while any such record
/// is present.
pub(crate) fn has_provider_managed_for_vm(vm_id: VmId) -> bool {
    owners().lock().values().any(|record| {
        record.owner == FrameOwner::FrameVm(vm_id)
            && record.provider_managed
            && record.generation == record.domain.generation()
    })
}

/// Returns whether a service-owned frame still anchors the loaded image.
///
/// Typed OSTD metadata may contain a destructor or vtable from the service
/// image. A public reference can outlive every service task, so the image
/// must remain mapped until the corresponding owner record has drained. This
/// predicate deliberately includes records with extra public references;
/// the release pass handles only hidden-owner-only records.
pub(crate) fn has_service_owned_for_vm(vm_id: VmId) -> bool {
    owners().lock().values().any(|record| {
        record.owner == FrameOwner::FrameVm(vm_id)
            && record.service_owned
            && record.generation == record.domain.generation()
    })
}

/// Zeroes a raw provider allocation while retaining its VM provenance.
pub(crate) fn zero_heap_range(
    start: Paddr,
    bytes: usize,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> Result<()> {
    if !raw_range_belongs_to_vm(start, bytes, vm_id, domain) {
        return Err(Error::AccessDenied);
    }
    let zero_page = [0u8; crate::mm::PAGE_SIZE];
    let end = start.checked_add(bytes).ok_or(Error::Overflow)?;
    let mut cursor = start;
    while cursor < end {
        let page = cursor - (cursor % crate::mm::PAGE_SIZE);
        let page_offset = cursor - page;
        let chunk = (crate::mm::PAGE_SIZE - page_offset).min(end - cursor);
        with_untyped_frame(page, vm_id, domain, |frame| {
            frame
                .write_bytes(page_offset, &zero_page[..chunk])
                .map_err(Error::from)
        })?;
        cursor += chunk;
    }
    Ok(())
}

/// Copies bytes between two active raw provider allocations.
pub(crate) fn copy_heap_range(
    source: Paddr,
    destination: Paddr,
    bytes: usize,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> Result<()> {
    if bytes == 0 {
        return Ok(());
    }
    if !raw_range_belongs_to_vm(source, bytes, vm_id, domain)
        || !raw_range_belongs_to_vm(destination, bytes, vm_id, domain)
    {
        return Err(Error::AccessDenied);
    }

    let mut offset = 0;
    let mut buffer = [0u8; crate::mm::PAGE_SIZE];
    while offset < bytes {
        let source_address = source.checked_add(offset).ok_or(Error::Overflow)?;
        let destination_address = destination.checked_add(offset).ok_or(Error::Overflow)?;
        let source_offset = source_address % crate::mm::PAGE_SIZE;
        let destination_offset = destination_address % crate::mm::PAGE_SIZE;
        let chunk = (crate::mm::PAGE_SIZE - source_offset)
            .min(crate::mm::PAGE_SIZE - destination_offset)
            .min(bytes - offset);
        let source_page = source_address - source_offset;
        let destination_page = destination_address - destination_offset;

        with_untyped_frame(source_page, vm_id, domain, |frame| {
            frame
                .read_bytes(source_offset, &mut buffer[..chunk])
                .map_err(Error::from)
        })?;
        with_untyped_frame(destination_page, vm_id, domain, |frame| {
            frame
                .write_bytes(destination_offset, &buffer[..chunk])
                .map_err(Error::from)
        })?;
        offset += chunk;
    }
    Ok(())
}

pub(crate) fn raw_range_belongs_to_vm(
    start: Paddr,
    bytes: usize,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> bool {
    let Some(end) = start.checked_add(bytes) else {
        return false;
    };
    let page_start = start - (start % crate::mm::PAGE_SIZE);
    let Some(page_end) = end
        .checked_add(crate::mm::PAGE_SIZE - 1)
        .map(|end| end - (end % crate::mm::PAGE_SIZE))
    else {
        return false;
    };
    page_end > page_start && range_belongs_to_vm(page_start, page_end - page_start, vm_id, domain)
}

/// Returns whether no FrameVisor owner record covers the requested range.
///
/// Custom OSTD providers may return a subrange of a larger grant. Check every
/// member page before OSTD constructs a `Segment`; otherwise a provider that
/// overlaps an existing owner can make `Segment::from_unused` drop a prefix
/// and leave the caller's whole-range rollback pointing at already-free pages.
pub(crate) fn range_is_unowned(start: Paddr, bytes: usize) -> bool {
    if bytes == 0 || !start.is_multiple_of(crate::mm::PAGE_SIZE) {
        return false;
    }
    let Some(end) = start.checked_add(bytes) else {
        return false;
    };
    if !end.is_multiple_of(crate::mm::PAGE_SIZE) {
        return false;
    }

    let table = owners().lock();
    (start..end)
        .step_by(crate::mm::PAGE_SIZE)
        .all(|paddr| !table.contains_key(&paddr))
}

/// Finds the unique FrameVM that owns every page touched by a raw range.
///
/// This is used only by a late deallocation path when the original service
/// task context is no longer available.  It never grants access by itself;
/// the owning provider still validates the slot shape and lifecycle state.
pub(crate) fn vm_for_range(start: Paddr, bytes: usize) -> Option<VmId> {
    if bytes == 0 {
        return None;
    }
    let end = start.checked_add(bytes)?;
    let page_start = start - (start % crate::mm::PAGE_SIZE);
    let page_end = end
        .checked_add(crate::mm::PAGE_SIZE - 1)
        .map(|end| end - (end % crate::mm::PAGE_SIZE))?;
    let table = owners().lock();
    let mut owner = None;
    for paddr in (page_start..page_end).step_by(crate::mm::PAGE_SIZE) {
        let record = table.get(&paddr)?;
        if record.generation != record.domain.generation() {
            return None;
        }
        let FrameOwner::FrameVm(vm_id) = record.owner else {
            return None;
        };
        if owner.is_some_and(|current| current != vm_id) {
            return None;
        }
        owner = Some(vm_id);
    }
    owner
}

fn with_untyped_frame<T>(
    paddr: Paddr,
    vm_id: VmId,
    domain: &MemoryDomain,
    operation: impl FnOnce(&OstdUFrame) -> Result<T>,
) -> Result<T> {
    let dynamic = {
        let mut table = owners().lock();
        let record = table.get_mut(&paddr).ok_or(Error::AccessDenied)?;
        if record.owner != FrameOwner::FrameVm(vm_id)
            || record.cached
            || record.generation != domain.generation()
            || !record.domain.is_same(domain)
            || !record.untyped
        {
            return Err(Error::AccessDenied);
        }
        record.busy = record.busy.checked_add(1).ok_or(Error::Overflow)?;
        record.hidden.clone()
    };

    let frame: OstdUFrame = match dynamic.try_into() {
        Ok(frame) => frame,
        Err(_) => {
            end_untyped_view(paddr);
            return Err(Error::AccessDenied);
        }
    };
    let result = operation(&frame);
    drop(frame);
    end_untyped_view(paddr);
    result
}

fn end_untyped_view(paddr: Paddr) {
    if let Some(record) = owners().lock().get_mut(&paddr) {
        record.busy = record.busy.saturating_sub(1);
    }
}

/// Returns the recorded owner without exposing the hidden OSTD handle.
#[cfg(ktest)]
pub(crate) fn owner_of(paddr: Paddr) -> Option<FrameOwner> {
    owners().lock().get(&paddr).map(|record| record.owner)
}

/// Counts owner records for one VM/domain fixture.
#[cfg(ktest)]
pub(crate) fn owner_count_for_vm(vm_id: VmId, domain: &MemoryDomain) -> usize {
    owners()
        .lock()
        .values()
        .filter(|record| {
            record.domain.is_same(domain)
                && match record.owner {
                    FrameOwner::FrameVm(owner) | FrameOwner::Releasing(owner) => owner == vm_id,
                    FrameOwner::Host => false,
                }
        })
        .count()
}

/// Returns whether any physical owner record still anchors a domain.
pub(crate) fn has_domain_records(domain: &MemoryDomain) -> bool {
    let table = owners().lock();
    table.values().any(|record| record.domain.is_same(domain))
}

/// Reserves one cached page for same-domain reuse.
///
/// The owner-table transition is made before the caller reserves accounting
/// bytes in `MemoryDomain`. Host reclaim therefore cannot start releasing the
/// page in the small interval between those two operations. The caller must
/// call [`commit_cached_frame`] after its domain reservation commits, or
/// [`restore_cached_frame`] when the allocation transaction rolls back.
pub(crate) fn reserve_cached_frame(
    vm_id: VmId,
    domain: &MemoryDomain,
) -> Option<(OstdFrame<()>, Arc<FrameLease>)> {
    let mut table = owners().lock();
    let (paddr, record) = table.iter_mut().find(|(_, record)| {
        record.owner == FrameOwner::FrameVm(vm_id)
            && record.cached
            && !record.segment_owned
            && record.generation == domain.generation()
            && record.domain.is_same(domain)
            && record.busy == 0
            && !record.reusable_reserved
            && record.hidden.reference_count() == 1
            && record.untyped
    })?;
    let dynamic: OstdFrame<dyn AnyFrameMeta> = record.hidden.clone();
    let frame = dynamic.try_into().ok()?;
    record.reusable_reserved = true;
    Some((frame, Arc::new(FrameLease { paddr: *paddr })))
}

/// Commits the owner-table half of a reusable-page allocation.
pub(crate) fn commit_cached_frame(paddr: Paddr, vm_id: VmId, domain: &MemoryDomain) {
    let mut table = owners().lock();
    let Some(record) = table.get_mut(&paddr) else {
        ::log::error!(
            "[framevisor] cached frame owner disappeared while committing VM {} reuse",
            vm_id
        );
        return;
    };
    if record.owner == FrameOwner::FrameVm(vm_id)
        && record.cached
        && record.reusable_reserved
        && record.generation == domain.generation()
        && record.domain.is_same(domain)
    {
        record.cached = false;
        record.reusable_reserved = false;
    } else {
        ::log::error!(
            "[framevisor] cached frame owner state invalid while committing VM {} reuse",
            vm_id
        );
    }
}

/// Restores a cached page when its replacement reservation could not commit.
pub(crate) fn restore_cached_frame(paddr: Paddr, vm_id: VmId, domain: &MemoryDomain) -> Result<()> {
    let mut table = owners().lock();
    let record = table.get_mut(&paddr).ok_or(Error::AccessDenied)?;
    if record.owner != FrameOwner::FrameVm(vm_id)
        || !record.cached
        || !record.reusable_reserved
        || record.generation != domain.generation()
        || !record.domain.is_same(domain)
        || record.busy != 0
        || record.hidden.reference_count() != 2
    {
        return Err(Error::AccessDenied);
    }
    record.reusable_reserved = false;
    Ok(())
}

/// Creates a lease for an already-recorded page.
pub(crate) fn lease_for(paddr: Paddr) -> Option<Arc<FrameLease>> {
    owners()
        .lock()
        .contains_key(&paddr)
        .then(|| Arc::new(FrameLease { paddr }))
}

/// Marks one FrameVM-owned page as a member of a newly-created OSTD segment.
///
/// `Segment::from(Frame)` consumes the public frame reference without going
/// through the allocator admission callback.  Promote the existing owner
/// record before publishing the segment lease so the complete extent remains
/// out of the reusable cache until the segment is gone.
pub(crate) fn promote_frame_to_segment(paddr: Paddr) -> bool {
    let Some(end) = paddr.checked_add(crate::mm::PAGE_SIZE) else {
        return false;
    };
    let mut table = owners().lock();
    let Some(record) = table.get_mut(&paddr) else {
        return false;
    };
    if !matches!(record.owner, FrameOwner::FrameVm(_))
        || record.cached
        || record.busy != 0
        || record.segment_owned
        || record.generation != record.domain.generation()
    {
        return false;
    }
    record.segment_owned = true;
    record.segment_start = Some(paddr);
    record.segment_end = Some(end);
    true
}

/// Checks that every page in an externally supplied contiguous range belongs
/// to the selected VM and is still an active, un-cached grant.
pub(crate) fn range_belongs_to_vm(
    start: Paddr,
    bytes: usize,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> bool {
    if bytes == 0 || !start.is_multiple_of(crate::mm::PAGE_SIZE) {
        return false;
    }
    let Some(end) = start.checked_add(bytes) else {
        return false;
    };
    if !end.is_multiple_of(crate::mm::PAGE_SIZE) {
        return false;
    }

    let table = owners().lock();
    (start..end).step_by(crate::mm::PAGE_SIZE).all(|paddr| {
        table.get(&paddr).is_some_and(|record| {
            record.owner == FrameOwner::FrameVm(vm_id)
                && !record.cached
                && record.generation == domain.generation()
                && record.domain.is_same(domain)
        })
    })
}

/// Records every member page of a newly allocated untyped segment.
pub(crate) fn adopt_segment<M>(
    segment: &OstdSegment<M>,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> Result<()>
where
    M: AnyFrameMeta + ?Sized,
{
    let start = segment.paddr();
    let size = segment.size();
    if size == 0
        || !start.is_multiple_of(crate::mm::PAGE_SIZE)
        || !size.is_multiple_of(crate::mm::PAGE_SIZE)
        || start.checked_add(size).is_none()
    {
        return Err(Error::InvalidArgs);
    }
    let expected_pages = size / crate::mm::PAGE_SIZE;
    let pages = segment.clone();
    let mut adopted_pages = 0;
    for frame in pages {
        let (frame, lease) = match adopt_frame_with_policy(frame, vm_id, domain, false, false, true)
        {
            Ok(result) => result,
            Err(error) => {
                abandon_adopted_segment(segment.paddr(), adopted_pages, vm_id, domain);
                return Err(error);
            }
        };
        drop(frame);
        drop(lease);
        adopted_pages = adopted_pages.checked_add(1).ok_or_else(|| {
            abandon_adopted_segment(segment.paddr(), adopted_pages, vm_id, domain);
            Error::Overflow
        })?;
        if adopted_pages > expected_pages {
            abandon_adopted_segment(segment.paddr(), adopted_pages, vm_id, domain);
            return Err(Error::InvalidArgs);
        }
    }
    if adopted_pages != expected_pages {
        abandon_adopted_segment(segment.paddr(), adopted_pages, vm_id, domain);
        return Err(Error::InvalidArgs);
    }
    let end = segment
        .paddr()
        .checked_add(segment.size())
        .ok_or(Error::Overflow)?;
    if !mark_segment_range(segment.paddr(), end, vm_id, domain) {
        abandon_adopted_segment(segment.paddr(), adopted_pages, vm_id, domain);
        return Err(Error::AccessDenied);
    }
    Ok(())
}

fn mark_segment_range(start: Paddr, end: Paddr, vm_id: VmId, domain: &MemoryDomain) -> bool {
    let mut table = owners().lock();
    for paddr in (start..end).step_by(crate::mm::PAGE_SIZE) {
        let Some(record) = table.get(&paddr) else {
            return false;
        };
        if record.owner != FrameOwner::FrameVm(vm_id)
            || record.generation != domain.generation()
            || !record.domain.is_same(domain)
            || !record.segment_owned
            || record.segment_start.is_some()
        {
            return false;
        }
    }
    for paddr in (start..end).step_by(crate::mm::PAGE_SIZE) {
        if let Some(record) = table.get_mut(&paddr) {
            record.segment_start = Some(start);
            record.segment_end = Some(end);
        }
    }
    true
}

/// Detaches a native service segment after its idle callbacks drain every
/// member page.
///
/// A service-facing OSTD `Segment` is not wrapped in FrameVisor's
/// `SegmentLease`, so its final lifetime signal is one `on_frame_idle` call
/// per member page. The complete range is cleared in one provenance-lock
/// transaction to preserve whole-extent reuse semantics.
pub(crate) fn detach_segment_if_idle(paddr: Paddr) -> Result<usize> {
    let (start, end) = {
        let mut table = owners().lock();
        let record = table.get(&paddr).ok_or(Error::AccessDenied)?;
        let FrameOwner::FrameVm(vm_id) = record.owner else {
            return Err(Error::AccessDenied);
        };
        let (Some(start), Some(end)) = (record.segment_start, record.segment_end) else {
            return Ok(0);
        };
        if !record.segment_owned
            || record.provider_managed
            || record.generation != record.domain.generation()
            || record.busy != 0
            || record.hidden.reference_count() != 1
        {
            return Ok(0);
        }
        let domain = record.domain.clone();
        for member in (start..end).step_by(crate::mm::PAGE_SIZE) {
            let Some(member_record) = table.get(&member) else {
                return Err(Error::AccessDenied);
            };
            if member_record.owner != FrameOwner::FrameVm(vm_id)
                || member_record.generation != domain.generation()
                || !member_record.domain.is_same(&domain)
                || !member_record.segment_owned
                || member_record.segment_start != Some(start)
                || member_record.segment_end != Some(end)
                || member_record.provider_managed
                || member_record.busy != 0
                || member_record.hidden.reference_count() != 1
            {
                return Ok(0);
            }
        }
        for member in (start..end).step_by(crate::mm::PAGE_SIZE) {
            if let Some(member_record) = table.get_mut(&member) {
                member_record.segment_owned = false;
                member_record.segment_start = None;
                member_record.segment_end = None;
            }
        }
        (start, end)
    };

    for member in (start..end).step_by(crate::mm::PAGE_SIZE) {
        let _ = cache_if_idle(member);
    }
    Ok((end - start) / crate::mm::PAGE_SIZE)
}

/// Removes all provisional owners for a segment after admission failed.
pub(crate) fn discard_adopted_segment<M>(
    segment: &OstdSegment<M>,
    vm_id: VmId,
    domain: &MemoryDomain,
) -> Result<()>
where
    M: AnyFrameMeta + ?Sized,
{
    let start = segment.paddr();
    let end = start.checked_add(segment.size()).ok_or(Error::Overflow)?;
    if !start.is_multiple_of(crate::mm::PAGE_SIZE) || !end.is_multiple_of(crate::mm::PAGE_SIZE) {
        return Err(Error::InvalidArgs);
    }

    for paddr in (start..end).step_by(crate::mm::PAGE_SIZE) {
        let hidden = discard_adopted_frame(paddr, vm_id, domain)?;
        drop_hidden_frame(hidden);
    }
    Ok(())
}

/// Removes owner records created for a segment whose admission failed.
///
/// The segment is still held by the caller, so each successfully-adopted page
/// has exactly two references here: the segment's forgotten handle and the
/// hidden owner handle.  No service value has been published yet.
fn abandon_adopted_segment(start: Paddr, pages: usize, vm_id: VmId, domain: &MemoryDomain) {
    remove_adopted_segment_pages(start, pages, vm_id, domain);
}

/// Completes a release after the caller has scrubbed the page.
pub(crate) fn finish_release(paddr: Paddr, vm_id: VmId, cached: bool) -> Result<()> {
    let record = {
        let mut table = owners().lock();
        let record = table.get(&paddr).ok_or(Error::InvalidArgs)?;
        if record.owner != FrameOwner::Releasing(vm_id) || record.cached != cached {
            return Err(Error::AccessDenied);
        }
        table.remove(&paddr).ok_or(Error::InvalidArgs)?
    };
    let domain = record.domain.clone();
    if let Err(error) = domain.release(crate::mm::PAGE_SIZE, cached) {
        // Keep both provenance and the hidden OSTD owner intact if accounting
        // rejects the final release. Dropping the owner before restoring the
        // record would return the physical page to Host while its charge was
        // still live.
        owners().lock().insert(paddr, record);
        return Err(error);
    }
    // The hidden handle is a Host OSTD value. Its native drop path returns the
    // physical page to the Host allocator exactly once, after any typed
    // metadata destructor has run. The service-facing drop path is separate
    // and has already drained before this function is called.
    drop_hidden_owner(record);
    domain.record_reclaim();
    Ok(())
}

fn drop_hidden_owner(record: OwnerRecord) {
    let OwnerRecord { hidden, .. } = record;
    drop_hidden_frame(hidden);
}

fn drop_hidden_frame(hidden: OstdFrame<dyn AnyFrameMeta>) {
    drop(hidden);
}

/// Scrubs and releases one cached page back to Host OSTD.
pub(crate) fn release_cached_page(paddr: Paddr, vm_id: VmId) -> Result<()> {
    let cached = begin_release_page(paddr, vm_id, true, false)?;
    scrub_and_finish(paddr, vm_id, cached)
}

/// Reclaims one cached page from any FrameVM.
///
/// This is the Host-pressure path.  It deliberately considers only entries
/// that have already entered the domain cache; an active page is never made
/// reclaimable merely because another allocation is under pressure.
pub(crate) fn reclaim_one_cached() -> Result<bool> {
    let candidate = owners().lock().iter().find_map(|(paddr, record)| {
        let FrameOwner::FrameVm(vm_id) = record.owner else {
            return None;
        };
        (record.cached
            && record.generation == record.domain.generation()
            && !record.service_owned
            && !record.segment_owned
            && !record.reusable_reserved
            && record.hidden.reference_count() == 1
            && record.busy == 0
            && record.untyped)
            .then_some((*paddr, vm_id))
    });
    let Some((paddr, vm_id)) = candidate else {
        return Ok(false);
    };

    release_cached_page(paddr, vm_id)?;
    Ok(true)
}

fn release_idle_page(paddr: Paddr, vm_id: VmId, service_owned: bool) -> Result<()> {
    let cached = begin_release_page(paddr, vm_id, false, service_owned)?;
    scrub_and_finish(paddr, vm_id, cached)
}

fn begin_release_page(
    paddr: Paddr,
    vm_id: VmId,
    require_cached: bool,
    service_owned: bool,
) -> Result<bool> {
    let cached = {
        let mut table = owners().lock();
        let record = table.get_mut(&paddr).ok_or(Error::InvalidArgs)?;
        if record.owner != FrameOwner::FrameVm(vm_id)
            || (require_cached && !record.cached)
            || record.generation != record.domain.generation()
            || record.service_owned != service_owned
            || record.segment_owned
            || record.reusable_reserved
            || record.busy != 0
            || record.hidden.reference_count() != 1
        {
            return Err(Error::AccessDenied);
        }
        record.owner = FrameOwner::Releasing(vm_id);
        record.cached
    };
    Ok(cached)
}

fn scrub_and_finish(paddr: Paddr, vm_id: VmId, cached: bool) -> Result<()> {
    let is_untyped = owners()
        .lock()
        .get(&paddr)
        .is_some_and(|record| record.untyped);
    if !is_untyped {
        // A typed metadata object does not promise that its backing page can
        // be accessed as bytes.  Keeping it owned is safer than returning
        // potentially stale data to the Host allocator.  Such pages remain
        // part of a stopping domain until a future metadata-specific release
        // protocol is available.
        restore_releasing_page(paddr, vm_id);
        return Err(Error::AccessDenied);
    }

    // The owner table has verified that the hidden OSTD reference is the last
    // live reference.  Scrub through the Host raw-memory seam instead of
    // cloning that reference: a clone would run inside an allocator/drop
    // callback and could re-enter the same frame's idle path.
    if host_ostd::mm::frame::zero_raw(paddr, crate::mm::PAGE_SIZE).is_err() {
        restore_releasing_page(paddr, vm_id);
        return Err(Error::IoError);
    }
    finish_release(paddr, vm_id, cached)
}

/// Releases non-service-owned pages after a VM allocator has quiesced.
///
/// Service-owned pages are handled by `release_service_owned_for_vm` while the
/// image is mapped. Any provider cache that still has extra references remains
/// isolated because the Host cannot destroy its opaque OSTD metadata safely.
pub(crate) fn release_quiesced_for_vm(vm_id: VmId) -> Result<usize> {
    // Provider-managed records remain behind the image-defined allocator
    // until that allocator supplies its own teardown protocol. Dropping the
    // hidden handle here would release the logical charge without returning
    // the opaque backing through the provider, which both leaks the page and
    // breaks the provider's ownership contract.
    release_owned_for_vm(vm_id, false, false)
}

/// Releases service-owned pages after all service tasks have exited but while
/// the loaded image remains mapped. Typed metadata destructors may point into
/// that image, so this explicit phase must precede provider deactivation and
/// program unload. Provider-managed entries are deliberately excluded: OSTD
/// has no generic provider-cache teardown callback, and dropping their hidden
/// handle here would bypass the provider's deallocation path.
pub(crate) fn release_service_owned_for_vm(vm_id: VmId) -> Result<usize> {
    release_owned_for_vm(vm_id, false, true)
}

fn release_owned_for_vm(
    vm_id: VmId,
    include_provider_managed: bool,
    service_owned: bool,
) -> Result<usize> {
    let mut released = 0;
    loop {
        let paddr = owners().lock().iter().find_map(|(paddr, record)| {
            (record.owner == FrameOwner::FrameVm(vm_id)
                && record.generation == record.domain.generation()
                && record.service_owned == service_owned
                && (include_provider_managed || !record.provider_managed)
                && record.busy == 0
                && record.hidden.reference_count() == 1)
                .then_some(*paddr)
        });
        let Some(paddr) = paddr else {
            return Ok(released);
        };
        let is_untyped = owners()
            .lock()
            .get(&paddr)
            .is_some_and(|record| record.untyped);
        if is_untyped {
            release_idle_page(paddr, vm_id, service_owned)?;
        } else {
            release_typed_page(paddr, vm_id, include_provider_managed, service_owned)?;
        }
        released += 1;
    }
}

fn release_typed_page(
    paddr: Paddr,
    vm_id: VmId,
    include_provider_managed: bool,
    service_owned: bool,
) -> Result<()> {
    let record = {
        let mut table = owners().lock();
        let record = table.get(&paddr).ok_or(Error::InvalidArgs)?;
        if record.owner != FrameOwner::FrameVm(vm_id)
            || record.cached
            || record.generation != record.domain.generation()
            || record.service_owned != service_owned
            || record.segment_owned
            || (!include_provider_managed && record.provider_managed)
            || record.reusable_reserved
            || record.busy != 0
            || record.hidden.reference_count() != 1
            || record.untyped
        {
            return Err(Error::AccessDenied);
        }
        table.remove(&paddr).ok_or(Error::InvalidArgs)?
    };

    let domain = record.domain.clone();
    if let Err(error) = domain.release(crate::mm::PAGE_SIZE, false) {
        let mut table = owners().lock();
        table.insert(paddr, record);
        return Err(error);
    }

    // The hidden handle is dropped while the service image remains mapped, so
    // a typed metadata destructor can still call image code. Its Host OSTD
    // drop path then returns the page to the Host allocator once; FrameVisor
    // must not issue a second raw deallocation.
    drop_hidden_owner(record);
    Ok(())
}

pub(crate) fn cache_if_idle(paddr: Paddr) -> Result<()> {
    // Allocation reserves cached bytes before consulting this table.  Never
    // call into `MemoryDomain` while holding `FrameOwners`; doing so would
    // invert the domain -> owners order used by allocation and could deadlock
    // a concurrent final-drop path.
    let (domain, vm_id) = {
        let mut table = owners().lock();
        let Some(record) = table.get_mut(&paddr) else {
            return Ok(());
        };
        let FrameOwner::FrameVm(vm_id) = record.owner else {
            return Ok(());
        };
        if record.cached
            || record.provider_managed
            || record.segment_owned
            || record.reusable_reserved
            || record.generation != record.domain.generation()
            || record.busy != 0
            || record.hidden.reference_count() != 1
            || !record.untyped
        {
            return Ok(());
        }
        record.busy = record.busy.checked_add(1).ok_or(Error::Overflow)?;
        (record.domain.clone(), vm_id)
    };

    let cache_result = domain.cache(crate::mm::PAGE_SIZE);
    let mut release_cached_charge = false;
    let mut marked_cached = false;
    {
        let mut table = owners().lock();
        if let Some(record) = table.get_mut(&paddr) {
            record.busy = record.busy.saturating_sub(1);
            if cache_result.is_ok()
                && record.owner == FrameOwner::FrameVm(vm_id)
                && !record.cached
                && !record.provider_managed
                && !record.segment_owned
                && record.generation == record.domain.generation()
                && record.hidden.reference_count() == 1
                && record.untyped
            {
                record.cached = true;
                marked_cached = true;
            } else if cache_result.is_ok() {
                // The busy marker prevents this in normal operation, but keep
                // the accounting conservative if a future path changes that
                // rule.
                release_cached_charge = true;
            }
        } else {
            // The owner may have been removed by a teardown path while this
            // operation was outside the table lock. Undo the cache charge
            // instead of leaving an unowned physical byte accounted forever.
            release_cached_charge = cache_result.is_ok();
        }
    }

    if release_cached_charge {
        domain.release(crate::mm::PAGE_SIZE, true)?;
    }
    if marked_cached {
        return Ok(());
    }
    // A failed cache transition usually means the domain is stopping.  Do not
    // release the hidden owner from this callback: `cache_if_idle` is invoked
    // by OSTD while the last public `Frame` is still executing its `Drop`.
    // Releasing the hidden handle here would make that in-flight frame point
    // at metadata that has already been destroyed.  The VM teardown pass
    // retries the release after all public handles and their drop callbacks
    // have returned.
    cache_result
}

fn restore_releasing_page(paddr: Paddr, vm_id: VmId) {
    let mut table = owners().lock();
    if let Some(record) = table.get_mut(&paddr)
        && record.owner == FrameOwner::Releasing(vm_id)
    {
        record.owner = FrameOwner::FrameVm(vm_id);
    }
}

/// Promotes hidden-owner-only pages to the VM cache.
pub(crate) fn cache_idle_for_vm(vm_id: VmId) -> Result<usize> {
    let mut cached = 0;
    loop {
        let paddr = owners().lock().iter().find_map(|(paddr, record)| {
            (record.owner == FrameOwner::FrameVm(vm_id)
                && !record.cached
                && record.generation == record.domain.generation()
                && !record.provider_managed
                && !record.segment_owned
                && !record.reusable_reserved
                && record.hidden.reference_count() == 1
                && record.busy == 0
                && record.untyped)
                .then_some(*paddr)
        });
        let Some(paddr) = paddr else {
            return Ok(cached);
        };
        cache_if_idle(paddr)?;
        cached += 1;
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;
    use crate::mm::FrameAllocOptions;

    struct TypedMeta;

    host_ostd::impl_frame_meta_for!(TypedMeta);

    #[ktest]
    fn adopted_frame_retains_hidden_owner_until_service_drop() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let (frame, lease) = adopt_frame(frame, crate::vm::VmId::new(0), &domain).unwrap();
        assert_eq!(
            owner_of(paddr),
            Some(FrameOwner::FrameVm(crate::vm::VmId::new(0)))
        );
        drop(frame);
        assert_eq!(
            owner_of(paddr),
            Some(FrameOwner::FrameVm(crate::vm::VmId::new(0)))
        );
        drop(lease);
        assert_eq!(
            owner_of(paddr),
            Some(FrameOwner::FrameVm(crate::vm::VmId::new(0)))
        );
        assert_eq!(domain.stats().reusable, crate::mm::PAGE_SIZE);
        assert!(release_cached_page(paddr, crate::vm::VmId::new(0)).is_ok());
    }

    #[ktest]
    fn wrong_domain_cannot_begin_release() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let (frame, _lease) = adopt_frame(frame, crate::vm::VmId::new(7), &domain).unwrap();
        assert_eq!(
            release_cached_page(paddr, crate::vm::VmId::new(8)).unwrap_err(),
            Error::AccessDenied
        );
        drop(frame);
        // The owner is not cache-eligible until the service handle is gone.
        assert!(release_cached_page(paddr, crate::vm::VmId::new(7)).is_err());
        drop(_lease);
        assert!(release_cached_page(paddr, crate::vm::VmId::new(7)).is_ok());
    }

    #[ktest]
    fn framevisor_wrapper_path_can_still_allocate_host_frames() {
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        assert_ne!(frame.paddr(), 0);
    }

    #[ktest]
    fn cached_page_is_scrubbed_before_host_release() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let (frame, lease) = adopt_frame(frame, crate::vm::VmId::new(11), &domain).unwrap();
        drop(frame);
        drop(lease);
        let (cached, lease) = reserve_cached_frame(crate::vm::VmId::new(11), &domain).unwrap();
        // A pending owner-table reservation must hide the page from Host
        // reclaim until the matching domain reservation is committed.
        assert!(!reclaim_one_cached().unwrap());
        let reservation = domain.reserve_reusable(crate::mm::PAGE_SIZE).unwrap();
        reservation.commit().unwrap();
        commit_cached_frame(paddr, crate::vm::VmId::new(11), &domain);
        cached
            .write_bytes(0, &[0xa5; crate::mm::PAGE_SIZE])
            .unwrap();
        drop(cached);
        drop(lease);
        release_cached_page(paddr, crate::vm::VmId::new(11)).unwrap();
        assert_eq!(owner_of(paddr), None);
        assert_eq!(domain.stats().committed, 0);
        assert_eq!(domain.stats().reclaim_count, 1);
    }

    #[ktest]
    fn typed_page_releases_after_final_owner_drains() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame_with(TypedMeta)
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let (frame, lease) = adopt_frame(frame, VmId::new(12), &domain).unwrap();
        drop(frame);
        drop(lease);

        assert_eq!(domain.stats().active, crate::mm::PAGE_SIZE);
        assert_eq!(release_quiesced_for_vm(VmId::new(12)).unwrap(), 1);
        assert_eq!(domain.stats().committed, 0);
        assert_eq!(owner_of(paddr), None);
    }

    #[ktest]
    fn quiesced_provider_page_remains_isolated_without_service_teardown() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let hidden = OstdFrame::<dyn AnyFrameMeta>::from_unsized(frame.clone());
        assert!(adopt_existing_frame_with_provider(
            hidden,
            VmId::new(15),
            &domain,
        ));
        drop(frame);

        assert_eq!(release_quiesced_for_vm(VmId::new(15)).unwrap(), 0);
        assert_eq!(domain.stats().committed, crate::mm::PAGE_SIZE);
        assert_eq!(owner_of(paddr), Some(FrameOwner::FrameVm(VmId::new(15))));
    }

    #[ktest]
    fn explicit_service_teardown_releases_hidden_only_page() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let hidden = OstdFrame::<dyn AnyFrameMeta>::from_unsized(frame.clone());
        // This fixture starts with a Host-allocated frame. Exercise the
        // service-owned teardown policy without claiming that its final drop
        // must use the FrameVM allocator dispatch; production provider
        // callbacks use `adopt_existing_frame_for_service`, which records the
        // opposite provenance.
        assert!(adopt_existing_frame_with_policy(
            hidden,
            VmId::new(16),
            &domain,
            false,
            true,
            false,
        ));
        drop(frame);

        assert_eq!(release_service_owned_for_vm(VmId::new(16)).unwrap(), 1);
        assert_eq!(owner_of(paddr), None);
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn service_teardown_skips_ordinary_pages() {
        let ordinary = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let ordinary_paddr = ordinary.paddr();
        let service = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let service_paddr = service.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE * 2, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE * 2)
            .unwrap()
            .commit()
            .unwrap();

        let (ordinary, ordinary_lease) = adopt_frame(ordinary, VmId::new(17), &domain).unwrap();
        let service_hidden = OstdFrame::<dyn AnyFrameMeta>::from_unsized(service.clone());
        assert!(adopt_existing_frame_for_service(
            service_hidden,
            VmId::new(17),
            &domain,
        ));
        drop(service);
        drop(ordinary);
        drop(ordinary_lease);

        assert_eq!(release_service_owned_for_vm(VmId::new(17)).unwrap(), 1);
        assert_eq!(owner_of(service_paddr), None);
        assert_eq!(
            owner_of(ordinary_paddr),
            Some(FrameOwner::FrameVm(VmId::new(17)))
        );
        assert_eq!(release_quiesced_for_vm(VmId::new(17)).unwrap(), 1);
        assert_eq!(owner_of(ordinary_paddr), None);
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn externally_supplied_range_must_have_matching_vm_provenance() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let (frame, lease) = adopt_frame(frame, VmId::new(13), &domain).unwrap();
        assert!(range_belongs_to_vm(
            paddr,
            crate::mm::PAGE_SIZE,
            VmId::new(13),
            &domain,
        ));
        assert!(!range_belongs_to_vm(
            paddr,
            crate::mm::PAGE_SIZE,
            VmId::new(14),
            &domain,
        ));
        drop(frame);
        drop(lease);
        release_cached_page(paddr, VmId::new(13)).unwrap();
    }

    #[ktest]
    fn stale_generation_cannot_reuse_or_release_owner() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let (frame, lease) = adopt_frame(frame, VmId::new(16), &domain).unwrap();
        let generation = domain.generation();

        domain.set_generation_for_test(generation + 1);
        assert!(!range_belongs_to_vm(
            paddr,
            crate::mm::PAGE_SIZE,
            VmId::new(16),
            &domain,
        ));
        assert_eq!(owner_vm(paddr), None);
        drop(frame);
        drop(lease);
        assert_eq!(
            release_cached_page(paddr, VmId::new(16)),
            Err(Error::AccessDenied)
        );

        domain.set_generation_for_test(generation);
        cache_if_idle(paddr).unwrap();
        release_cached_page(paddr, VmId::new(16)).unwrap();
    }

    #[ktest]
    fn wrong_domain_cannot_reuse_or_mutate_cached_owner() {
        let frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = frame.paddr();
        let owner_domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        let wrong_domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        owner_domain
            .reserve(crate::mm::PAGE_SIZE)
            .unwrap()
            .commit()
            .unwrap();
        let (frame, lease) = adopt_frame(frame, VmId::new(16), &owner_domain).unwrap();
        drop(frame);
        drop(lease);

        let owner_stats = owner_domain.stats();
        assert_eq!(owner_stats.reusable, crate::mm::PAGE_SIZE);
        assert!(!range_belongs_to_vm(
            paddr,
            crate::mm::PAGE_SIZE,
            VmId::new(16),
            &wrong_domain,
        ));
        assert!(reserve_cached_frame(VmId::new(16), &wrong_domain).is_none());
        assert_eq!(owner_domain.stats(), owner_stats);
        assert_eq!(wrong_domain.stats().committed, 0);

        release_cached_page(paddr, VmId::new(16)).unwrap();
        assert_eq!(owner_domain.stats().committed, 0);
    }

    #[ktest]
    fn service_release_does_not_consume_ordinary_pages() {
        let vm_id = VmId::new(70);
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE * 2, 0).unwrap();
        domain
            .reserve(crate::mm::PAGE_SIZE * 2)
            .unwrap()
            .commit()
            .unwrap();

        let ordinary = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let ordinary_paddr = ordinary.paddr();
        let typed = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame_with(TypedMeta)
            .unwrap();
        let (ordinary, ordinary_lease) = adopt_frame(ordinary, vm_id, &domain).unwrap();
        let (typed, typed_lease) =
            adopt_frame_with_policy(typed, vm_id, &domain, false, true, false).unwrap();
        drop(ordinary);
        drop(ordinary_lease);
        drop(typed);
        drop(typed_lease);

        assert_eq!(release_service_owned_for_vm(vm_id).unwrap(), 1);
        assert!(has_owner(ordinary_paddr));
        assert_eq!(domain.stats().committed, crate::mm::PAGE_SIZE);

        assert_eq!(release_quiesced_for_vm(vm_id).unwrap(), 1);
        assert_eq!(domain.stats().committed, 0);
    }
}
