use alloc::{boxed::Box, format, vec, vec::Vec};
use core::any::Any;

use xmas_elf::{
    ElfFile,
    sections::{SHF_ALLOC, SHF_COMPRESSED, SHF_EXECINSTR, SHF_TLS, SHF_WRITE},
};

use super::invalid_args;
use crate::{
    Result,
    mm::{
        PAGE_SIZE,
        kspace::kvirt_area::KVirtArea,
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SectionMemoryType {
    Text,
    RoData,
    RwData,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SectionPlacement {
    memory_type: SectionMemoryType,
    offset: usize,
    size: usize,
}

impl SectionPlacement {
    pub(super) fn memory_type(self) -> SectionMemoryType {
        self.memory_type
    }

    pub(super) fn offset(self) -> usize {
        self.offset
    }

    pub(super) fn size(self) -> usize {
        self.size
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LoadedSection {
    base: usize,
    size: usize,
    memory_type: SectionMemoryType,
}

impl LoadedSection {
    pub(super) fn new(base: usize, placement: SectionPlacement) -> Self {
        Self {
            base,
            size: placement.size,
            memory_type: placement.memory_type,
        }
    }

    pub(super) fn base(self) -> usize {
        self.base
    }

    pub(super) fn size(self) -> usize {
        self.size
    }

    pub(super) fn memory_type(self) -> SectionMemoryType {
        self.memory_type
    }

    pub(super) fn contains_range(self, offset: usize, size: usize) -> bool {
        offset <= self.size && size <= self.size - offset
    }

    pub(super) fn contains_address(self, offset: usize) -> bool {
        offset < self.size
    }
}

pub(super) struct SectionLayout {
    pub(super) exec_bytes: usize,
    pub(super) ro_bytes: usize,
    pub(super) rw_bytes: usize,
    pub(super) placements: Vec<Option<SectionPlacement>>,
}

impl SectionLayout {
    pub(super) fn plan(elf_file: &ElfFile) -> Result<Self> {
        log::info!("[Loader] Analyzing service sections...");

        let mut layout = Self {
            exec_bytes: 0,
            ro_bytes: 0,
            rw_bytes: 0,
            placements: vec![None; elf_file.section_iter().count()],
        };

        for (section_index, section) in elf_file.section_iter().enumerate() {
            let flags = section.flags();
            if (flags & SHF_ALLOC) == 0 {
                continue;
            }
            let name = section.get_name(elf_file).map_err(|_| {
                invalid_args(format!("section {section_index} has an invalid name"))
            })?;
            if name.starts_with(".debug") {
                continue;
            }
            if flags & (SHF_TLS | SHF_COMPRESSED) != 0 {
                return Err(invalid_args(format!(
                    "allocated section `{name}` uses unsupported TLS or compressed storage"
                )));
            }

            let memory_type = section_memory_type(flags, name)?;
            let size = usize::try_from(section.size())
                .map_err(|_| invalid_args(format!("section `{name}` size exceeds usize")))?;
            if size == 0 {
                return Err(invalid_args(format!(
                    "allocated section `{name}` has zero size"
                )));
            }

            let align = usize::try_from(section.align())
                .map_err(|_| invalid_args(format!("section `{name}` alignment exceeds usize")))?
                .max(1);
            if !align.is_power_of_two() || align > PAGE_SIZE {
                return Err(invalid_args(format!(
                    "section `{name}` alignment {} is unsupported",
                    align
                )));
            }
            let cursor = match memory_type {
                SectionMemoryType::Text => &mut layout.exec_bytes,
                SectionMemoryType::RoData => &mut layout.ro_bytes,
                SectionMemoryType::RwData => &mut layout.rw_bytes,
            };
            let offset = align_up_checked(*cursor, align)?;
            let end = offset
                .checked_add(size)
                .ok_or_else(|| invalid_args(format!("section `{name}` size overflows")))?;
            *cursor = end;
            layout.placements[section_index] = Some(SectionPlacement {
                memory_type,
                offset,
                size,
            });
        }

        Ok(layout)
    }
}

fn section_memory_type(flags: u64, name: &str) -> Result<SectionMemoryType> {
    match (flags & SHF_EXECINSTR != 0, flags & SHF_WRITE != 0) {
        (true, true) => Err(invalid_args(format!(
            "section `{name}` is both writable and executable"
        ))),
        (true, false) => Ok(SectionMemoryType::Text),
        (false, true) => Ok(SectionMemoryType::RwData),
        (false, false) => Ok(SectionMemoryType::RoData),
    }
}

/// Stores the mapped service-section areas.
pub(super) struct SectionMemory {
    pub(super) exec_kvirt: Option<KVirtArea>,
    pub(super) ro_kvirt: Option<KVirtArea>,
    pub(super) rw_kvirt: Option<KVirtArea>,
    // Mappings are declared before owner guards so Rust drops mappings first.
    _owner_guards: Vec<Box<dyn Any + Send + Sync>>,
}

/// Keeps a mapping alive until its physical-segment owner has been released.
///
/// The field order is deliberate: Rust drops `mapping` before `owner_guard`,
/// including when a later allocation fails and this value is dropped as a
/// local temporary.
struct MappedSection {
    mapping: Option<KVirtArea>,
    owner_guard: Option<Box<dyn Any + Send + Sync>>,
}

/// Physical section backing plus an optional caller-owned release guard.
///
/// The loader only consumes the segment and retains the opaque guard until
/// all section mappings are dropped. OSTD does not interpret the guard or
/// depend on FrameVisor; this is a narrow lifetime handoff for allocators that
/// retain provenance outside the native `Segment` value.
pub struct SectionBacking {
    segment: crate::mm::Segment<()>,
    owner_guard: Option<Box<dyn Any + Send + Sync>>,
}

impl SectionBacking {
    /// Creates section backing without an additional owner guard.
    pub fn from_segment(segment: crate::mm::Segment<()>) -> Self {
        Self {
            segment,
            owner_guard: None,
        }
    }

    /// Creates section backing with an opaque caller-owned guard.
    pub fn with_owner(
        segment: crate::mm::Segment<()>,
        owner_guard: Box<dyn Any + Send + Sync>,
    ) -> Self {
        Self {
            segment,
            owner_guard: Some(owner_guard),
        }
    }
}

impl SectionMemory {
    pub(super) fn contains_executable_address(&self, address: usize) -> bool {
        self.exec_kvirt
            .as_ref()
            .is_some_and(|area| address >= area.start() && address < area.end())
    }

    pub(super) fn contains_range(&self, start: usize, size: usize) -> bool {
        let Some(end) = start.checked_add(size) else {
            return false;
        };
        [
            self.exec_kvirt.as_ref(),
            self.ro_kvirt.as_ref(),
            self.rw_kvirt.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|area| start >= area.start() && end <= area.end())
    }

    pub(super) fn protect_final_permissions(&self) -> Result<()> {
        if let Some(exec_kvirt) = &self.exec_kvirt {
            exec_kvirt.protect(section_prop(PageFlags::RX))?;
        }
        if let Some(ro_kvirt) = &self.ro_kvirt {
            ro_kvirt.protect(section_prop(PageFlags::R))?;
        }
        if let Some(rw_kvirt) = &self.rw_kvirt {
            rw_kvirt.protect(section_prop(PageFlags::RW))?;
        }
        Ok(())
    }
}

/// Allocates service sections through a caller-provided segment source.
///
/// The loader owns the virtual mapping and permission transition, while the
/// caller owns the decision about where the physical segment comes from. This
/// is intentionally a narrow loading seam: it does not alter OSTD frame
/// ownership or expose a loader API to FrameVM service code.
pub(super) fn alloc_section_memory_with<F>(
    layout: &SectionLayout,
    alloc_segment_fn: F,
) -> Result<SectionMemory>
where
    F: Fn(usize) -> Result<SectionBacking>,
{
    log::info!(
        "[Loader] Allocating memory: Text={} bytes, RoData={} bytes, RwData={} bytes",
        layout.exec_bytes,
        layout.ro_bytes,
        layout.rw_bytes
    );

    let exec_pages = layout.exec_bytes.div_ceil(PAGE_SIZE);
    let ro_pages = layout.ro_bytes.div_ceil(PAGE_SIZE);
    let rw_pages = layout.rw_bytes.div_ceil(PAGE_SIZE);

    let exec = alloc_pages(exec_pages, &alloc_segment_fn)?;
    let ro = alloc_pages(ro_pages, &alloc_segment_fn)?;
    let rw = alloc_pages(rw_pages, &alloc_segment_fn)?;

    let owner_guards = [exec.owner_guard, ro.owner_guard, rw.owner_guard]
        .into_iter()
        .flatten()
        .collect();

    Ok(SectionMemory {
        exec_kvirt: exec.mapping,
        ro_kvirt: ro.mapping,
        rw_kvirt: rw.mapping,
        _owner_guards: owner_guards,
    })
}

fn alloc_pages<F>(pages: usize, alloc_segment_fn: &F) -> Result<MappedSection>
where
    F: Fn(usize) -> Result<SectionBacking>,
{
    if pages == 0 {
        return Ok(MappedSection {
            mapping: None,
            owner_guard: None,
        });
    }

    let area_size = pages.checked_mul(PAGE_SIZE).ok_or(crate::Error::Overflow)?;
    let backing = alloc_segment_fn(pages)?;
    if crate::mm::HasSize::size(&backing.segment) != area_size {
        return Err(invalid_args(format!(
            "section backing has {} bytes, expected {}",
            crate::mm::HasSize::size(&backing.segment),
            area_size
        )));
    }
    let kvirt_area =
        KVirtArea::map_module_frames(area_size, 0, backing.segment, section_prop(PageFlags::RW))?;
    Ok(MappedSection {
        mapping: Some(kvirt_area),
        owner_guard: backing.owner_guard,
    })
}

fn section_prop(flags: PageFlags) -> PageProperty {
    PageProperty {
        flags,
        cache: CachePolicy::Writeback,
        priv_flags: PrivilegedPageFlags::empty(),
    }
}

fn align_up_checked(value: usize, align: usize) -> Result<usize> {
    if align <= 1 {
        return Ok(value);
    }
    let rem = value % align;
    if rem == 0 {
        return Ok(value);
    }
    value
        .checked_add(align - rem)
        .ok_or_else(|| invalid_args("section alignment overflows"))
}

#[cfg(ktest)]
mod tests {
    use ostd_macros::ktest;

    use super::*;

    #[ktest]
    fn rejects_writable_executable_sections() {
        assert!(section_memory_type(SHF_EXECINSTR | SHF_WRITE, ".text").is_err());
        assert_eq!(
            section_memory_type(SHF_EXECINSTR, ".text").unwrap(),
            SectionMemoryType::Text
        );
        assert_eq!(
            section_memory_type(SHF_WRITE, ".data").unwrap(),
            SectionMemoryType::RwData
        );
    }

    #[ktest]
    fn rejects_section_alignment_overflow() {
        assert!(align_up_checked(usize::MAX - 1, 4).is_err());
        assert_eq!(align_up_checked(3, 4).unwrap(), 4);
    }
}
