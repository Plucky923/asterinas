// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use ostd::mm::PageFlags;

use super::{
    ExistingMapping, PAGE_SIZE, Result, map_anonymous, unmap_range, with_current_user_task_data,
};

const USER_MMAP_BASE_LIMIT: usize = 0x7000_0000_0000;

/// Expands the user heap to a new heap end.
pub(super) fn sys_brk(requested: usize) -> Result<isize> {
    with_current_user_task_data(|task_data| {
        let current = task_data.brk.load(Ordering::SeqCst);
        let heap_base = task_data.heap_base();
        if requested == 0 {
            return Ok(current as isize);
        }
        if requested < heap_base || requested >= USER_MMAP_BASE_LIMIT {
            return Ok(current as isize);
        }

        let old_mapped_end = current.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let new_mapped_end = requested.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        if new_mapped_end > old_mapped_end {
            let vm_space = task_data.vm_space();
            map_anonymous(
                vm_space.as_ref(),
                old_mapped_end,
                new_mapped_end - old_mapped_end,
                PageFlags::R | PageFlags::W,
                ExistingMapping::Skip,
            )?;
        } else if new_mapped_end < old_mapped_end {
            let vm_space = task_data.vm_space();
            unmap_range(
                vm_space.as_ref(),
                new_mapped_end,
                old_mapped_end - new_mapped_end,
            )?;
        }
        task_data.brk.store(requested, Ordering::SeqCst);
        Ok(requested as isize)
    })
}
