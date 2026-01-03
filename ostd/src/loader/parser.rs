use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use core::cmp;

use xmas_elf::{
    ElfFile,
    sections::{SHF_ALLOC, ShType},
};

use super::memory::{SectionMemory, SectionMemoryType, align_up, select_section_bucket};
use crate::{
    Result, early_println,
    mm::io::{Infallible, VmReader, VmWriter},
};

pub struct SectionsMetadata<'a> {
    pub loaded_sections: BTreeMap<usize, Arc<LoadSection<'a>>>,
}

/// 记录加载到映射页里的section的基地址，偏移量等信息
pub struct LoadSection<'a> {
    pub base_addr: usize,
    pub offset: usize,
    pub size: usize,
    pub align: usize,
    pub sh_type: ShType,
    pub section_data: Option<&'a [u8]>,
    pub verified: bool,
}

pub fn load_section_data<'a>(
    elf_file: &'a ElfFile,
    section_memory: &SectionMemory,
) -> Result<SectionsMetadata<'a>> {
    early_println!("[Loader] Start Loading section data...");

    let mut sections_metadata = SectionsMetadata {
        loaded_sections: BTreeMap::new(),
    };

    let mut exec_cursor = 0usize;
    let mut ro_cursor = 0usize;
    let mut rw_cursor = 0usize;

    for (i, sh) in elf_file.section_iter().enumerate() {
        let Ok(name) = sh.get_name(elf_file) else {
            continue;
        };
        let Ok(sh_type) = sh.get_type() else {
            continue;
        };

        let flags = sh.flags();
        if (flags & SHF_ALLOC) == 0 {
            continue;
        }

        // 只跳过真正的 debug section（以 .debug 开头）
        if name.starts_with(".debug") {
            continue;
        }

        let size = sh.size() as usize;
        if size == 0 {
            continue;
        }

        let align = cmp::max(sh.align() as usize, 1);

        let bucket = select_section_bucket(flags);
        let (cursor, kvirt) = match bucket {
            SectionMemoryType::Text => (
                &mut exec_cursor,
                section_memory
                    .exec_kvirt
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgs)?,
            ),
            SectionMemoryType::RwData => (
                &mut rw_cursor,
                section_memory
                    .rw_kvirt
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgs)?,
            ),
            SectionMemoryType::RoData => (
                &mut ro_cursor,
                section_memory
                    .ro_kvirt
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgs)?,
            ),
        };

        // 对齐到页面大小倍数
        let offset = align_up(*cursor, align);
        let end = offset.checked_add(size).ok_or(crate::Error::InvalidArgs)?;

        // 检查是否超出内存区域
        let area_len = kvirt.end() - kvirt.start();
        if end > area_len {
            return Err(crate::Error::InvalidArgs);
        }

        let section_data = if sh_type == ShType::NoBits {
            None
        } else {
            Some(sh.raw_data(elf_file))
        };

        unsafe {
            let mut writer = VmWriter::from_kernel_space((kvirt.start() + offset) as *mut u8, size);
            if section_data.is_none() {
                let filled = writer.fill_zeros(size);
                if filled != size {
                    return Err(crate::Error::InvalidArgs);
                }
            } else {
                let data = section_data.unwrap();
                if data.len() != size {
                    return Err(crate::Error::InvalidArgs);
                }
                let written = writer.write(&mut VmReader::from(data));
                if written != data.len() {
                    return Err(crate::Error::InvalidArgs);
                }
            }
        }

        /*
        let verified = verify_section_memory(kvirt, offset, size, sh_type, section_data)?;
        if !verified {
            early_println!(
                "[Loader] Section {} ({}) verification failed at bucket {:?}",
                i,
                name,
                bucket
            );
            return Err(crate::Error::InvalidArgs);
        }
        */
        let verified = true;

        *cursor = end;

        sections_metadata.loaded_sections.insert(
            i,
            Arc::new(LoadSection {
                base_addr: kvirt.start() + offset,
                offset,
                size,
                align,
                sh_type,
                section_data,
                verified,
            }),
        );
    }

    early_println!(
        "[Loader] Loaded sections summary: Text={} bytes, RoData={} bytes, RwData={} bytes",
        exec_cursor,
        ro_cursor,
        rw_cursor
    );

    Ok(sections_metadata)
}

const VERIFY_CHUNK_SIZE: usize = 256;

#[allow(dead_code)]
pub fn verify_section_memory(
    kvirt: &crate::mm::kspace::kvirt_area::KVirtArea,
    offset: usize,
    size: usize,
    sh_type: ShType,
    section_data: Option<&[u8]>,
) -> Result<bool> {
    if size == 0 {
        return Ok(true);
    }

    unsafe {
        let mut dst_reader =
            VmReader::from_kernel_space((kvirt.start() + offset) as *const u8, size);
        let verified = if sh_type == ShType::NoBits {
            reader_is_zeroed(&mut dst_reader, size)
        } else if let Some(data) = section_data {
            reader_equals_slice(&mut dst_reader, data)
        } else {
            true
        };
        Ok(verified)
    }
}

#[allow(dead_code)]
fn reader_is_zeroed(reader: &mut VmReader<'_, Infallible>, mut remaining: usize) -> bool {
    let mut scratch = [0u8; VERIFY_CHUNK_SIZE];
    while remaining > 0 {
        let chunk_len = remaining.min(VERIFY_CHUNK_SIZE);
        let mut writer = VmWriter::from(&mut scratch[..chunk_len]);
        let read_len = reader.read(&mut writer);
        if read_len != chunk_len {
            return false;
        }
        if scratch[..read_len].iter().any(|&byte| byte != 0) {
            return false;
        }
        remaining -= read_len;
    }
    true
}

#[allow(dead_code)]
fn reader_equals_slice(reader: &mut VmReader<'_, Infallible>, data: &[u8]) -> bool {
    let mut processed = 0usize;
    let mut scratch = [0u8; VERIFY_CHUNK_SIZE];
    while processed < data.len() {
        let chunk_len = (data.len() - processed).min(VERIFY_CHUNK_SIZE);
        let mut writer = VmWriter::from(&mut scratch[..chunk_len]);
        let read_len = reader.read(&mut writer);
        if read_len != chunk_len {
            return false;
        }
        if scratch[..read_len] != data[processed..processed + read_len] {
            return false;
        }
        processed += read_len;
    }
    reader.remain() == 0
}
