use core::cmp;

use xmas_elf::{
    ElfFile,
    sections::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE},
};

use crate::{
    Result, early_println,
    mm::{
        PAGE_SIZE,
        frame::allocator::FrameAllocOptions,
        kspace::kvirt_area::KVirtArea,
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
    },
};

/// 决定后续分配为 section 分配的内存应该是什么类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SectionMemoryType {
    Text,
    RoData,
    RwData,
}

pub fn select_section_bucket(sh_type: u64) -> SectionMemoryType {
    let is_text = sh_type & SHF_EXECINSTR != 0;
    let is_rodata = sh_type & SHF_WRITE == 0;
    let is_rwdata = sh_type & SHF_WRITE != 0;

    if is_text {
        SectionMemoryType::Text
    } else if is_rwdata {
        SectionMemoryType::RwData
    } else if is_rodata {
        SectionMemoryType::RoData
    } else {
        early_println!("Invalid section type: {:?}", sh_type);
        SectionMemoryType::RoData
    }
}

/// 存储已分配的内存区域
pub struct SectionMemory {
    pub exec_kvirt: Option<KVirtArea>,
    pub ro_kvirt: Option<KVirtArea>,
    pub rw_kvirt: Option<KVirtArea>,
}

pub fn caculate_section_size(elf_file: &ElfFile) -> (usize, usize, usize) {
    early_println!("[Loader] Analyzing sections...");

    let mut exec_cursor = 0;
    let mut ro_cursor = 0;
    let mut rw_cursor = 0;

    for (i, sh) in elf_file.section_iter().enumerate() {
        let Ok(name) = sh.get_name(elf_file) else {
            continue;
        };

        let flags = sh.flags();
        let should_alloc = (SHF_ALLOC & flags) != 0;
        let size = sh.size() as usize;

        // 只跳过真正的 debug section（以 .debug 开头），而不是名称中包含 "debug" 的所有 section
        // 因为代码 section 的名称可能包含 "debug" 字符串（如函数名）
        if !should_alloc || name.starts_with(".debug") {
            continue;
        }

        let align = cmp::max(sh.align() as usize, 1);

        // 判断需要分配什么样的内存
        let bucket = select_section_bucket(flags);
        match bucket {
            SectionMemoryType::Text => {
                exec_cursor = align_up(exec_cursor, align);
                exec_cursor += size;
            }
            SectionMemoryType::RoData => {
                ro_cursor = align_up(ro_cursor, align);
                ro_cursor += size;
            }
            SectionMemoryType::RwData => {
                rw_cursor = align_up(rw_cursor, align);
                rw_cursor += size;
            }
        }
    }

    (exec_cursor, ro_cursor, rw_cursor)
}

pub fn alloc_section_memory(
    exec_bytes: usize,
    ro_bytes: usize,
    rw_bytes: usize,
) -> Result<SectionMemory> {
    early_println!(
        "[Loader] Allocating memory: Text={} bytes, RoData={} bytes, RwData={} bytes",
        exec_bytes,
        ro_bytes,
        rw_bytes
    );

    // 将size对齐到页面大小倍数
    let align_to_page = |size: usize| -> usize {
        if size == 0 {
            0
        } else {
            (size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE
        }
    };

    let exec_pages = align_to_page(exec_bytes) / PAGE_SIZE;
    let ro_pages = align_to_page(ro_bytes) / PAGE_SIZE;
    let rw_pages = align_to_page(rw_bytes) / PAGE_SIZE;

    let exec_kvirt = alloc_pages(exec_pages, PageFlags::RWX)?;
    let ro_kvirt = alloc_pages(ro_pages, PageFlags::RWX)?; // Temporarily RWX for loading
    let rw_kvirt = alloc_pages(rw_pages, PageFlags::RWX)?;

    // 简化内存分配日志，改为表格形式或单行汇总（此处用单行汇总）
    if let Some(ref kvirt) = exec_kvirt {
        early_println!(
            "[Loader] Text segment: 0x{:x} - 0x{:x} ({} pages)",
            kvirt.start(),
            kvirt.end(),
            exec_pages
        );
    }
    if let Some(ref kvirt) = ro_kvirt {
        early_println!(
            "[Loader] RoData segment: 0x{:x} - 0x{:x} ({} pages)",
            kvirt.start(),
            kvirt.end(),
            ro_pages
        );
    }
    if let Some(ref kvirt) = rw_kvirt {
        early_println!(
            "[Loader] RwData segment: 0x{:x} - 0x{:x} ({} pages)",
            kvirt.start(),
            kvirt.end(),
            rw_pages
        );
    }

    Ok(SectionMemory {
        exec_kvirt,
        ro_kvirt,
        rw_kvirt,
    })
}

fn alloc_pages(pages: usize, flags: PageFlags) -> Result<Option<KVirtArea>> {
    if pages == 0 {
        return Ok(None);
    }
    let segment = FrameAllocOptions::new()
        .zeroed(true)
        .alloc_segment(pages)
        .map_err(|_| crate::Error::NoMemory)?;

    let prop = PageProperty {
        flags,
        cache: CachePolicy::Writeback,
        priv_flags: PrivilegedPageFlags::empty(),
    };

    // area_size 需要是字节数，map_offset 应该从 0 开始
    let kvirt_area = KVirtArea::map_module_frames(pages * PAGE_SIZE, 0, segment.into_iter(), prop);
    Ok(Some(kvirt_area))
}

pub fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}
