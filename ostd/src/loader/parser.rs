use alloc::{format, vec, vec::Vec};

use xmas_elf::{ElfFile, sections::ShType};

use super::{
    invalid_args,
    memory::{LoadedSection, SectionLayout, SectionMemory, SectionMemoryType},
};
use crate::{
    Result,
    mm::io::{VmReader, VmWriter},
};

pub(super) fn load_section_data(
    elf_file: &ElfFile,
    layout: &SectionLayout,
    section_memory: &SectionMemory,
) -> Result<Vec<Option<LoadedSection>>> {
    log::info!("[Loader] Loading service sections...");

    let mut loaded_bases = vec![None; layout.placements.len()];
    for (section_index, section) in elf_file.section_iter().enumerate() {
        let Some(placement) = layout
            .placements
            .get(section_index)
            .and_then(|placement| *placement)
        else {
            continue;
        };

        let name = section
            .get_name(elf_file)
            .map_err(|_| invalid_args(format!("section {section_index} has an invalid name")))?;
        let section_type = section
            .get_type()
            .map_err(|_| invalid_args(format!("section `{name}` has an invalid type")))?;
        let size = usize::try_from(section.size())
            .map_err(|_| invalid_args(format!("section `{name}` size exceeds usize")))?;
        if size != placement.size() {
            return Err(invalid_args(format!(
                "section `{name}` changed size after layout: planned={}, actual={}",
                placement.size(),
                size
            )));
        }

        let kvirt = match placement.memory_type() {
            SectionMemoryType::Text => section_memory.exec_kvirt.as_ref().ok_or_else(|| {
                invalid_args(format!("missing executable area for section `{name}`"))
            })?,
            SectionMemoryType::RoData => section_memory.ro_kvirt.as_ref().ok_or_else(|| {
                invalid_args(format!("missing read-only area for section `{name}`"))
            })?,
            SectionMemoryType::RwData => section_memory.rw_kvirt.as_ref().ok_or_else(|| {
                invalid_args(format!("missing writable area for section `{name}`"))
            })?,
        };
        let end = placement
            .offset()
            .checked_add(size)
            .ok_or_else(|| invalid_args(format!("section `{name}` range overflows")))?;
        let area_len = kvirt
            .end()
            .checked_sub(kvirt.start())
            .ok_or_else(|| invalid_args(format!("section `{name}` area range is invalid")))?;
        if end > area_len {
            return Err(invalid_args(format!(
                "section `{name}` exceeds allocated area: end=0x{end:x}, area_len=0x{area_len:x}"
            )));
        }
        let base_addr = kvirt
            .start()
            .checked_add(placement.offset())
            .ok_or_else(|| invalid_args(format!("section `{name}` address overflows")))?;

        let section_data = (section_type != ShType::NoBits).then(|| section.raw_data(elf_file));
        // SAFETY: The layout pass assigned this section a non-overlapping range
        // in the selected module mapping. The bounds check above proves the
        // complete destination range is mapped and writable during loading.
        unsafe {
            let mut writer = VmWriter::from_kernel_space(base_addr as *mut u8, size);
            if let Some(data) = section_data {
                if data.len() != size {
                    return Err(invalid_args(format!(
                        "section `{name}` size mismatch: section header={size}, raw_data={}",
                        data.len()
                    )));
                }
                let written = writer.write(&mut VmReader::from(data));
                if written != data.len() {
                    return Err(invalid_args(format!(
                        "failed to copy section `{name}`: expected {}, wrote {written}",
                        data.len()
                    )));
                }
            } else {
                let filled = writer.fill_zeros(size);
                if filled != size {
                    return Err(invalid_args(format!(
                        "failed to zero-fill section `{name}`: expected {size}, wrote {filled}"
                    )));
                }
            }
        }

        loaded_bases[section_index] = Some(LoadedSection::new(base_addr, placement));
    }

    log::info!(
        "[Loader] Loaded service sections: Text={} bytes, RoData={} bytes, RwData={} bytes",
        layout.exec_bytes,
        layout.ro_bytes,
        layout.rw_bytes
    );
    Ok(loaded_bases)
}
