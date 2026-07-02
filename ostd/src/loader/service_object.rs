use alloc::{format, vec::Vec};

use xmas_elf::{
    ElfFile,
    header::Type,
    sections::{SHF_ALLOC, ShType},
};

use super::{invalid_args, symbol::get_symbol_table};
use crate::Result;

pub(super) struct ServiceObject<'a> {
    elf_file: ElfFile<'a>,
    relocation_sections: Vec<ServiceRelocationSection>,
}

impl<'a> ServiceObject<'a> {
    pub(super) fn parse(elf_data: &'a [u8]) -> Result<Self> {
        let elf_file = ElfFile::new(elf_data)
            .map_err(|_| invalid_args("failed to parse service module object as ELF"))?;

        let typ = elf_file.header.pt2.type_().as_type();
        if typ != Type::Relocatable {
            return Err(invalid_args(format!(
                "service module object is not relocatable: {:?}",
                typ
            )));
        }

        let _ = get_symbol_table(&elf_file)?;
        let relocation_sections = collect_relocation_sections(&elf_file)?;
        Ok(Self {
            elf_file,
            relocation_sections,
        })
    }

    pub(super) fn elf_file(&self) -> &ElfFile<'a> {
        &self.elf_file
    }

    pub(super) fn relocation_sections(&self) -> &[ServiceRelocationSection] {
        &self.relocation_sections
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ServiceRelocationSection {
    section_index: usize,
    target_section_index: usize,
    target_section_size: u64,
}

impl ServiceRelocationSection {
    fn new(section_index: usize, target_section_index: usize, target_section_size: u64) -> Self {
        Self {
            section_index,
            target_section_index,
            target_section_size,
        }
    }

    pub(super) fn section_index(self) -> usize {
        self.section_index
    }

    pub(super) fn target_section_index(self) -> usize {
        self.target_section_index
    }

    pub(super) fn target_section_size(self) -> u64 {
        self.target_section_size
    }
}

fn collect_relocation_sections(elf_file: &ElfFile) -> Result<Vec<ServiceRelocationSection>> {
    let mut relocation_sections = Vec::new();
    for (section_index, section) in elf_file.section_iter().enumerate() {
        let Ok(section_type) = section.get_type() else {
            continue;
        };
        if !matches!(section_type, ShType::Rela | ShType::Rel) {
            continue;
        }

        let target_section_index = section.info() as usize;
        if target_section_index == 0 {
            continue;
        }
        let target_section = elf_file
            .section_header(target_section_index as u16)
            .map_err(|_| {
                invalid_args(format!(
                    "relocation section {} references invalid target section {}",
                    section_index, target_section_index
                ))
            })?;
        if (target_section.flags() & SHF_ALLOC) == 0 {
            continue;
        }

        relocation_sections.push(ServiceRelocationSection::new(
            section_index,
            target_section_index,
            target_section.size(),
        ));
    }
    Ok(relocation_sections)
}
