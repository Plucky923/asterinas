use alloc::{format, string::String};

use spin::Once;
use xmas_elf::{header::Type, program::ProgramHeader, ElfFile};

use crate::{early_println, sync::SpinLock, Result};

mod memory;
mod parser;
mod relocation;
mod symbol;

use memory::{alloc_section_memory, caculate_section_size, SectionMemory};
use parser::load_section_data;
use relocation::relocate_sections;
use symbol::find_entry_point;

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

pub struct FrameVmInfo<'a> {
    elf_file: ElfFile<'a>,
    entry_point: Option<usize>,
    section_memory: Option<SectionMemory>,
}

impl<'a> FrameVmInfo<'a> {
    fn entry_point(&self) -> Option<usize> {
        self.entry_point
    }

    pub fn start_framevm(&self) -> Result<()> {
        // 直接在当前 CPU 上调用，不创建新 Task
        let start = self.entry_point().unwrap_or(0);
        log::info!(
            "[Loader] Entry point called directly, entry point: 0x{:x}",
            start
        );

        if start == 0 {
            return Err(invalid_args("entry point is 0, cannot proceed"));
        }

        // 移除 Hex dump
        /*
        unsafe {
            early_println!("[Loader] Dumping code at entry point (first 128 bytes):");
            let code_ptr = start as *const u8;
            let mut line_buffer = alloc::string::String::new();
            for i in 0..128 {
                if i % 16 == 0 {
                    if !line_buffer.is_empty() {
                        early_println!("{}", line_buffer);
                        line_buffer.clear();
                    }
                    line_buffer = alloc::format!("[Loader] 0x{:x}: ", start + i);
                }
                let mut byte = [0u8; 1];
                let mut reader = VmReader::from_kernel_space(code_ptr.add(i), 1);
                if reader.read(&mut VmWriter::from(&mut byte[..])) == 1 {
                    line_buffer.push_str(&alloc::format!("{:02x} ", byte[0]));
                } else {
                    line_buffer.push_str("?? ");
                }
            }
            if !line_buffer.is_empty() {
                early_println!("{}", line_buffer);
            }

            // 尝试解析前几条指令
            early_println!("[Loader] Attempting to disassemble first few instructions:");
            let mut hex_buffer = alloc::string::String::new();
            for i in 0..32.min(128) {
                let mut byte = [0u8; 1];
                let mut reader = VmReader::from_kernel_space(code_ptr.add(i), 1);
                if reader.read(&mut VmWriter::from(&mut byte[..])) == 1 {
                    hex_buffer.push_str(&alloc::format!("{:02x}", byte[0]));
                } else {
                    hex_buffer.push_str("??");
                }
            }
            early_println!("{}", hex_buffer);
        }
        */

        // 打印入口点函数的反汇编信息（前几条指令）
        log::info!("[Loader] About to call entry point at 0x{:x}", start);

        let entry: extern "Rust" fn() = unsafe { core::mem::transmute(start) };
        unsafe { entry() };

        log::info!("[Loader] FrameVM execution finished");
        Ok(())
    }

    pub fn load_framevm_file(elf_data: &'a [u8]) -> Result<FrameVmInfo<'a>> {
        clear_last_error();
        log::info!("[Loader] Loading FrameVM module...");
        let elf_file = ElfFile::new(elf_data)
            .map_err(|_| invalid_args("failed to parse FrameVM object as ELF"))?;

        // 简化日志
        // early_println!("[Loader] ELF header: {:?}", elf_file.header);

        // 检查是否是重定位文件
        let typ = elf_file.header.pt2.type_().as_type();
        if typ != Type::Relocatable {
            return Err(invalid_args(format!(
                "FrameVM object is not relocatable: {:?}",
                typ
            )));
        }

        for (i, ph) in elf_file.program_iter().enumerate() {
            match ph {
                ProgramHeader::Ph64(ph64) => {
                    if let Ok(ph_type) = ph64.get_type() {
                        // 仅当 Program Header 非空时打印
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

        let (exec_bytes, ro_bytes, rw_bytes) = caculate_section_size(&elf_file);
        let section_memory = alloc_section_memory(exec_bytes, ro_bytes, rw_bytes)?;
        let sections_metadata = load_section_data(&elf_file, &section_memory)?;
        relocate_sections(&elf_file, &sections_metadata)?;

        // 打印代码段边界信息
        /*
        if let Some(ref exec_kvirt) = section_memory.exec_kvirt {
            early_println!(
                "[Loader] Executable code segment: start=0x{:x}, end=0x{:x}, size=0x{:x} bytes",
                exec_kvirt.start(),
                exec_kvirt.end(),
                exec_kvirt.end() - exec_kvirt.start()
            );
        }
        */

        // 查找并记录入口点地址 (_start)
        let entry_point = find_entry_point(&elf_file, &sections_metadata)?;
        if let Some(addr) = entry_point {
            log::info!("[Loader] Entry point found at: 0x{:x}", addr);
            // 检查入口点是否在代码段内
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
            log::warn!("[Loader] Warning: Entry point (_start) not found");
        }

        Ok(FrameVmInfo {
            elf_file,
            entry_point,
            section_memory: Some(section_memory),
        })
    }
}
