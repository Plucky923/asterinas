// SPDX-License-Identifier: MPL-2.0

use xmas_elf::program::{ProgramHeader, SegmentData};
use core::mem::MaybeUninit;

use xmas_elf::{
    program::{ProgramHeader, SegmentData},
    sections::{SectionData, ShType},
};

/// Load the kernel ELF payload to memory.
pub fn load_elf(file: &[u8]) -> usize {
    let elf = xmas_elf::ElfFile::new(file).unwrap();

    for ph in elf.program_iter() {
        let ProgramHeader::Ph64(program) = ph else {
            panic!(
                "[setup] Unexpected program header type! Asterinas should be 64-bit ELF binary."
            );
        };

        if program.get_type().unwrap() == xmas_elf::program::Type::Load {
            load_segment(&elf, program);
        }
    }

    let total_symbols = parse_symbols_from_elf_file(&elf);
    total_symbols
}

fn load_segment(file: &xmas_elf::ElfFile, program: &xmas_elf::program::ProgramHeader64) {
    let SegmentData::Undefined(segment_data) = program.get_data(file).unwrap() else {
        panic!("[setup] Unexpected segment data type!");
    };

    let dst_slice = crate::x86::alloc_at(program.physical_addr as usize, program.mem_size as usize);

    #[cfg(feature = "debug_print")]
    crate::println!(
        "[setup] Loading an ELF segment: addr={:#x}, size={:#x}",
        program.physical_addr,
        program.mem_size,
    );

    let (left, right) = dst_slice.split_at_mut(program.file_size as usize);
    left.write_copy_of_slice(segment_data);
    right.write_filled(0);
}

fn parse_symbols_from_elf_file(elf: &xmas_elf::ElfFile) -> usize {
    // Try to find either a full symbol table (.symtab) or a dynamic symbol table (.dynsym).
    let mut total = 0usize;

    for sec in elf.section_iter() {
        match sec.get_type() {
            Ok(ShType::SymTab) => match sec.get_data(elf) {
                Ok(SectionData::SymbolTable64(syms)) => total += syms.len(),
                Ok(SectionData::SymbolTable32(syms)) => total += syms.len(),
                _ => {}
            },
            Ok(ShType::DynSym) => match sec.get_data(elf) {
                Ok(SectionData::SymbolTable64(syms)) => total += syms.len(),
                Ok(SectionData::SymbolTable32(syms)) => total += syms.len(),
                _ => {}
            },
            _ => {}
        }
    }

    if total > 0 {
        crate::println!("[setup] Parsed {} symbols from sections.", total);
        crate::println!("[setup] DEBUG: This message proves your code was executed!");
    } else {
        crate::println!("[setup] No symbol table found (kernel image may be stripped).");
    }
    total
}
