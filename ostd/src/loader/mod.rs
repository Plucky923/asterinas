use alloc::{format, string::String};

use spin::Once;
use xmas_elf::program::ProgramHeader;

use crate::{Result, early_println, sync::SpinLock};

mod memory;
mod metadata;
mod parser;
mod relocation;
mod service_object;
mod symbol;

use memory::{SectionMemory, alloc_section_memory, caculate_section_size};
use metadata::validate_framevm_metadata;
use parser::load_section_data;
use relocation::relocate_sections;
use service_object::ServiceObject;
use symbol::{EntryPoint, find_entry_point};

static LOADER_LAST_ERROR: Once<SpinLock<Option<String>>> = Once::new();

fn loader_last_error_slot() -> &'static SpinLock<Option<String>> {
    LOADER_LAST_ERROR.call_once(|| SpinLock::new(None))
}

fn remember_loader_error(message: impl Into<String>) {
    let message = message.into();
    log::error!("[Loader] ERROR: {}", message);
    *loader_last_error_slot().lock() = Some(message);
}

pub fn clear_last_error() {
    *loader_last_error_slot().lock() = None;
}

pub fn last_error() -> Option<String> {
    loader_last_error_slot().lock().clone()
}

pub(super) fn invalid_args(message: impl Into<String>) -> crate::Error {
    remember_loader_error(message);
    crate::Error::InvalidArgs
}

/// A relocatable Rust service module loaded into kernel memory.
pub struct ServiceModuleInfo<'a> {
    service_object: ServiceObject<'a>,
    entry_point: Option<EntryPoint>,
    section_memory: Option<SectionMemory>,
}

impl<'a> ServiceModuleInfo<'a> {
    fn entry_point(&self) -> Option<EntryPoint> {
        self.entry_point
    }

    /// Starts the loaded service module by invoking its entry point.
    pub fn start(&self) -> Result<()> {
        let Some(entry_point) = self.entry_point() else {
            return Err(invalid_args("entry point is missing, cannot proceed"));
        };
        let start = entry_point.addr();
        early_println!(
            "[Loader] Calling entry point: 0x{:x}, returns={}",
            start,
            entry_point.returns_to_loader()
        );
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

    /// Loads a relocatable Rust service module from an ELF object.
    pub fn load_service_module(elf_data: &'a [u8]) -> Result<Self> {
        clear_last_error();
        log::info!("[Loader] Loading service module...");
        let service_object = ServiceObject::parse(elf_data)?;
        let elf_file = service_object.elf_file();
        if !crate::symbols::framevm_symbol_table_available() {
            return Err(invalid_args(
                "framevm symbol table is unavailable before service relocation",
            ));
        }
        validate_framevm_metadata(&service_object)?;

        for (i, ph) in elf_file.program_iter().enumerate() {
            match ph {
                ProgramHeader::Ph64(ph64) => {
                    if let Ok(ph_type) = ph64.get_type() {
                        // Only non-empty program headers are relevant here.
                        if ph64.mem_size > 0 {
                            early_println!(
                                "[Loader] Program header {}: type={:?}, offset=0x{:x}, vaddr=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
                                i,
                                ph_type,
                                ph64.offset,
                                ph64.virtual_addr,
                                ph64.file_size,
                                ph64.mem_size
                            );
                        }
                    }
                }
                ProgramHeader::Ph32(_) => {
                    early_println!("[Loader] Program header {}: 32-bit (not supported)", i);
                }
            }
        }

        let (exec_bytes, ro_bytes, rw_bytes) = caculate_section_size(&elf_file)?;
        let section_memory = alloc_section_memory(exec_bytes, ro_bytes, rw_bytes)?;
        let sections_metadata = load_section_data(&elf_file, &section_memory)?;
        relocate_sections(&service_object, &sections_metadata)?;
        section_memory.protect_final_permissions()?;

        let entry_point = find_entry_point(&service_object, &sections_metadata)?;
        if let Some(entry_point) = entry_point {
            let addr = entry_point.addr();
            early_println!(
                "[Loader] Entry point found: 0x{:x}, returns={}",
                addr,
                entry_point.returns_to_loader()
            );
            log::info!("[Loader] Entry point found at: 0x{:x}", addr);
            if let Some(ref exec_kvirt) = section_memory.exec_kvirt {
                if addr < exec_kvirt.start() || addr >= exec_kvirt.end() {
                    return Err(invalid_args(format!(
                        "entry point 0x{:x} is outside executable segment [0x{:x}, 0x{:x})",
                        addr,
                        exec_kvirt.start(),
                        exec_kvirt.end()
                    )));
                }
            }
        } else {
            log::warn!("[Loader] Warning: service module entry point not found");
        }

        Ok(Self {
            service_object,
            entry_point,
            section_memory: Some(section_memory),
        })
    }
}
