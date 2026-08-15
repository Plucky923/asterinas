use alloc::{sync::Arc, vec, vec::Vec};
use core::slice;

use crate::{Result, early_println};

mod memory;
mod metadata;
mod parser;
mod relocation;
mod service_object;
mod symbol;

pub use memory::SectionBacking;
use memory::{LoadedSection, SectionLayout, SectionMemory, alloc_section_memory_with};
use metadata::validate_framevm_metadata;
use parser::load_section_data;
use relocation::relocate_sections_with;
use service_object::ServiceObject;
use symbol::{EntryPoint, find_entry_point};

pub(super) fn invalid_args(message: impl core::fmt::Display) -> crate::Error {
    early_println!("[Loader] ERROR: {}", message);
    crate::Error::InvalidArgs
}

/// Owns one loaded service program and its mapped image.
pub struct Program {
    _section_memory: Arc<SectionMemory>,
    entry_point: EntryPoint,
}

/// Copies an ELF payload into storage whose base is aligned for xmas-elf's
/// zero-copy array views. The copy is only used when the caller supplied an
/// unaligned byte slice; normal boot modules remain borrowed.
fn aligned_elf_copy(data: &[u8]) -> Vec<u64> {
    let word_count = data.len().div_ceil(size_of::<u64>());
    let mut storage = vec![0; word_count];
    // SAFETY: `storage` has at least `data.len()` bytes and is aligned to
    // `u64`; the regions do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            storage.as_mut_ptr().cast::<u8>(),
            data.len(),
        );
    }
    storage
}

fn aligned_elf_bytes<'a>(data: &'a [u8], storage: &'a Vec<u64>) -> &'a [u8] {
    // SAFETY: `storage` is a live `Vec<u64>` and therefore has a u64-aligned
    // base. Its allocation contains at least the requested byte length.
    unsafe { slice::from_raw_parts(storage.as_ptr().cast::<u8>(), data.len()) }
}

/// Describes one image-defined symbol after its section has been mapped.
///
/// This value is created only by the loader.  Capability owners may ask it for
/// one of the validated OSTD provider-cell handles; arbitrary physical or
/// virtual addresses are never accepted by those constructors.
pub struct DefinedSymbol<'a> {
    name: &'a [u8],
    address: usize,
    size: usize,
    section_memory: Arc<SectionMemory>,
}

impl DefinedSymbol<'_> {
    /// Returns the raw symbol name used by the service object.
    pub fn name(&self) -> &[u8] {
        self.name
    }

    /// Returns the relocated address of the symbol.
    pub fn address(&self) -> usize {
        self.address
    }

    /// Returns the symbol's declared size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns a handle for a defined global frame-allocator cell.
    pub fn frame_allocator_cell(&self) -> Option<FrameAllocatorCell> {
        (self.name == b"__GLOBAL_FRAME_ALLOCATOR_REF")
            .then(|| FrameAllocatorCell::new(self.address, self.size, &self.section_memory))
            .flatten()
    }

    /// Returns a handle for a defined global heap-allocator cell.
    pub fn heap_allocator_cell(&self) -> Option<HeapAllocatorCell> {
        (self.name == b"__GLOBAL_HEAP_ALLOCATOR_REF")
            .then(|| HeapAllocatorCell::new(self.address, self.size, &self.section_memory))
            .flatten()
    }
}

/// A validated cell containing an OSTD global frame allocator reference.
#[derive(Clone)]
pub struct FrameAllocatorCell {
    address: usize,
    section_memory: Arc<SectionMemory>,
}

impl FrameAllocatorCell {
    fn new(address: usize, size: usize, section_memory: &Arc<SectionMemory>) -> Option<Self> {
        (size == size_of::<&'static dyn crate::mm::frame::GlobalFrameAllocator>()
            && address.is_multiple_of(align_of::<usize>()))
        .then(|| Self {
            address,
            section_memory: Arc::clone(section_memory),
        })
    }

    fn raw_parts(&self) -> (usize, usize) {
        // SAFETY: The loader checked that the cell is a complete, aligned
        // trait-object-sized range before constructing this handle.
        unsafe {
            let pointer = self.address as *const usize;
            (
                core::ptr::read_unaligned(pointer),
                core::ptr::read_unaligned(pointer.add(1)),
            )
        }
    }

    /// Returns whether the cell contains a valid image-local trait object.
    pub fn is_image_trait_object(&self) -> bool {
        let (data, vtable) = self.raw_parts();
        let vtable_words = 3 + 6;
        let vtable_size = vtable_words * size_of::<usize>();
        if data == 0
            || vtable == 0
            || !vtable.is_multiple_of(align_of::<usize>())
            || !self.section_memory.contains_range(data, 1)
            || !self.section_memory.contains_range(vtable, vtable_size)
        {
            return false;
        }

        // Rust trait-object vtables begin with drop glue, object size, and
        // object alignment. All image-defined code and metadata must remain
        // inside the image mapping before the object is materialized.
        // SAFETY: The vtable range was checked above and contains all three
        // metadata words.
        let (drop_fn, object_size, object_align) = unsafe {
            (
                core::ptr::read_unaligned(vtable as *const usize),
                core::ptr::read_unaligned((vtable as *const usize).add(1)),
                core::ptr::read_unaligned((vtable as *const usize).add(2)),
            )
        };
        let methods_are_executable = (3..vtable_words).all(|index| {
            // SAFETY: The vtable range was checked above for every method
            // entry read by this loop.
            let method = unsafe { core::ptr::read_unaligned((vtable as *const usize).add(index)) };
            self.section_memory.contains_executable_address(method)
        });
        (drop_fn == 0 || self.section_memory.contains_executable_address(drop_fn))
            && methods_are_executable
            && object_align.is_power_of_two()
            && data.is_multiple_of(object_align)
            && (object_size == 0 || self.section_memory.contains_range(data, object_size))
    }

    /// Returns whether the cell has the same raw trait-object value as a
    /// trusted host provider.
    pub fn matches(&self, provider: &dyn crate::mm::frame::GlobalFrameAllocator) -> bool {
        self.raw_parts() == frame_trait_object_parts(provider)
    }

    /// Reads an image-defined provider while retaining its image mapping.
    pub fn get(&self) -> Option<&dyn crate::mm::frame::GlobalFrameAllocator> {
        if !self.is_image_trait_object() {
            return None;
        }
        // SAFETY: `is_image_trait_object` checked the data pointer, vtable,
        // vtable fields, and their containment in the live image mapping.
        // The handle owns an `Arc` clone of that mapping.
        let _mapping = &self.section_memory;
        Some(unsafe {
            *(self.address as *const &'static dyn crate::mm::frame::GlobalFrameAllocator)
        })
    }
}

fn frame_trait_object_parts(
    provider: &dyn crate::mm::frame::GlobalFrameAllocator,
) -> (usize, usize) {
    // SAFETY: A Rust trait object is represented by its data and vtable
    // pointers. The source and destination have the same size.
    unsafe {
        core::mem::transmute::<*const dyn crate::mm::frame::GlobalFrameAllocator, (usize, usize)>(
            provider as *const _,
        )
    }
}

/// A validated cell containing an OSTD global heap allocator reference.
#[derive(Clone)]
pub struct HeapAllocatorCell {
    address: usize,
    section_memory: Arc<SectionMemory>,
}

impl HeapAllocatorCell {
    fn new(address: usize, size: usize, section_memory: &Arc<SectionMemory>) -> Option<Self> {
        (size == size_of::<&'static dyn crate::mm::heap::GlobalHeapAllocator>()
            && address.is_multiple_of(align_of::<usize>()))
        .then(|| Self {
            address,
            section_memory: Arc::clone(section_memory),
        })
    }

    fn raw_parts(&self) -> (usize, usize) {
        // SAFETY: The loader checked that the cell is a complete, aligned
        // trait-object-sized range before constructing this handle.
        unsafe {
            let pointer = self.address as *const usize;
            (
                core::ptr::read_unaligned(pointer),
                core::ptr::read_unaligned(pointer.add(1)),
            )
        }
    }

    /// Returns whether the cell contains a valid image-local trait object.
    pub fn is_image_trait_object(&self) -> bool {
        let (data, vtable) = self.raw_parts();
        let vtable_words = 3 + 2;
        let vtable_size = vtable_words * size_of::<usize>();
        if data == 0
            || vtable == 0
            || !vtable.is_multiple_of(align_of::<usize>())
            || !self.section_memory.contains_range(data, 1)
            || !self.section_memory.contains_range(vtable, vtable_size)
        {
            return false;
        }

        // SAFETY: The vtable range was checked above and contains all three
        // metadata words.
        let (drop_fn, object_size, object_align) = unsafe {
            (
                core::ptr::read_unaligned(vtable as *const usize),
                core::ptr::read_unaligned((vtable as *const usize).add(1)),
                core::ptr::read_unaligned((vtable as *const usize).add(2)),
            )
        };
        let methods_are_executable = (3..vtable_words).all(|index| {
            // SAFETY: The vtable range was checked above for every method
            // entry read by this loop.
            let method = unsafe { core::ptr::read_unaligned((vtable as *const usize).add(index)) };
            self.section_memory.contains_executable_address(method)
        });
        (drop_fn == 0 || self.section_memory.contains_executable_address(drop_fn))
            && methods_are_executable
            && object_align.is_power_of_two()
            && data.is_multiple_of(object_align)
            && (object_size == 0 || self.section_memory.contains_range(data, object_size))
    }

    /// Returns whether the cell has the same raw trait-object value as a
    /// trusted host provider.
    pub fn matches(&self, provider: &dyn crate::mm::heap::GlobalHeapAllocator) -> bool {
        self.raw_parts() == heap_trait_object_parts(provider)
    }

    /// Reads an image-defined provider while retaining its image mapping.
    pub fn get(&self) -> Option<&dyn crate::mm::heap::GlobalHeapAllocator> {
        if !self.is_image_trait_object() {
            return None;
        }
        // SAFETY: `is_image_trait_object` checked the data pointer, vtable,
        // vtable fields, and their containment in the live image mapping.
        let _mapping = &self.section_memory;
        Some(unsafe { *(self.address as *const &'static dyn crate::mm::heap::GlobalHeapAllocator) })
    }
}

fn heap_trait_object_parts(provider: &dyn crate::mm::heap::GlobalHeapAllocator) -> (usize, usize) {
    // SAFETY: A Rust trait object is represented by its data and vtable
    // pointers. The source and destination have the same size.
    unsafe {
        core::mem::transmute::<*const dyn crate::mm::heap::GlobalHeapAllocator, (usize, usize)>(
            provider as *const _,
        )
    }
}

/// Observes one image-defined symbol after its section has been mapped.
pub type DefinedSymbolObserver<'a> =
    dyn for<'symbol> Fn(&DefinedSymbol<'symbol>) -> Result<()> + 'a;

/// Supplies the policy hooks for loading one FrameVM service image.
///
/// Keeping the hooks in one value makes the loader boundary explicit: the
/// caller owns allocation, symbol resolution, deferred-symbol policy, and
/// defined-symbol observation for the whole load transaction.
pub struct FrameVmLoadContext<'a> {
    allocate_segment: &'a dyn Fn(usize) -> Result<SectionBacking>,
    resolve_symbol: &'a dyn Fn(&[u8]) -> Option<u64>,
    defer_symbol: &'a dyn Fn(&[u8]) -> bool,
    observe_symbol: &'a DefinedSymbolObserver<'a>,
}

impl<'a> FrameVmLoadContext<'a> {
    /// Creates a load context from the policy hooks for one service image.
    pub fn new(
        allocate_segment: &'a dyn Fn(usize) -> Result<SectionBacking>,
        resolve_symbol: &'a dyn Fn(&[u8]) -> Option<u64>,
        defer_symbol: &'a dyn Fn(&[u8]) -> bool,
        observe_symbol: &'a DefinedSymbolObserver<'a>,
    ) -> Self {
        Self {
            allocate_segment,
            resolve_symbol,
            defer_symbol,
            observe_symbol,
        }
    }
}

impl Program {
    /// Starts the loaded service module by invoking its entry point.
    pub fn start(&self) -> Result<()> {
        start_service(self.entry_point)
    }

    /// Loads a service program using one explicit load-policy context.
    ///
    /// This is intentionally narrower than a general loader callback: it is
    /// invoked after section backing and initial contents are complete. The
    /// loader has applied every non-deferred relocation before the callback so
    /// a capability owner can inspect provider cells, then applies deferred
    /// relocations and final permissions. This lets the owner select a
    /// provider-dependent symbol policy without exposing loader internals to
    /// the service API.
    pub fn load_with_context(elf_data: &[u8], context: &FrameVmLoadContext<'_>) -> Result<Self> {
        log::info!("[Loader] Loading service module...");
        let aligned_storage;
        let elf_data = if (elf_data.as_ptr() as usize).is_multiple_of(align_of::<u64>()) {
            elf_data
        } else {
            aligned_storage = aligned_elf_copy(elf_data);
            aligned_elf_bytes(elf_data, &aligned_storage)
        };
        let service_object = ServiceObject::parse(elf_data)?;
        let elf_file = service_object.elf_file();
        validate_framevm_metadata(&service_object)?;

        let layout = SectionLayout::plan(elf_file)?;
        let section_memory = Arc::new(alloc_section_memory_with(
            &layout,
            context.allocate_segment,
        )?);
        let loaded_sections: Vec<Option<LoadedSection>> =
            load_section_data(elf_file, &layout, &section_memory)?;
        let deferred_relocations = relocate_sections_with(
            &service_object,
            &loaded_sections,
            context.resolve_symbol,
            context.defer_symbol,
        )?;
        symbol::observe_defined_symbols(
            &service_object,
            &loaded_sections,
            &section_memory,
            context.observe_symbol,
        )?;
        deferred_relocations.resolve_and_apply(context.resolve_symbol)?;
        section_memory
            .protect_final_permissions()
            .map_err(|_| invalid_args("failed to protect service module section permissions"))?;

        let entry_point = find_entry_point(&service_object, &loaded_sections)?
            .ok_or_else(|| invalid_args("service program entry point is missing"))?;
        let addr = entry_point.addr();
        log::info!("[Loader] Entry point found at: 0x{:x}", addr);

        Ok(Self {
            _section_memory: section_memory,
            entry_point,
        })
    }
}

fn start_service(entry_point: EntryPoint) -> Result<()> {
    let start = entry_point.addr();
    log::info!(
        "[Loader] Entry point called directly, entry point: 0x{:x}",
        start
    );

    if start == 0 {
        return Err(invalid_args("entry point is 0, cannot proceed"));
    }

    log::info!("[Loader] About to call entry point at 0x{:x}", start);

    // SAFETY: `start` is resolved from a relocated entry symbol that was
    // checked to lie inside the executable section of this loaded module.
    if entry_point.returns_to_loader() {
        let entry: extern "Rust" fn() = unsafe { core::mem::transmute(start) };
        entry();
    } else {
        let entry: extern "Rust" fn() -> ! = unsafe { core::mem::transmute(start) };
        entry();
    }

    log::info!("[Loader] Service module execution finished");
    Ok(())
}
