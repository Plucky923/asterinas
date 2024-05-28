// SPDX-License-Identifier: MPL-2.0

use core::mem;

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{process_table, Pid},
    util::write_val_to_user,
};

pub fn sys_sched_getaffinity(
    pid: Pid,
    cpuset_size: usize,
    user_mask_ptr: Vaddr,
) -> Result<SyscallReturn> {
    // Ensure cpuset_size is sufficient to store a cpu_set_t.
    if cpuset_size < core::mem::size_of::<cpu_set_t>() {
        return Err(Error::with_message(Errno::EINVAL, "invalid cpuset size"));
    }

    // Use match statement for clearer control flow especially when pid == 0 logic is implemented.
    match pid {
        0 => {
            // TODO: Get the current thread's CPU affinity
            // Placeholder for future implementation.
        }
        _ => {
            // Check if the process exists, in a Rust idiomatic way using match for clarity.
            match process_table::get_process(&pid) {
                Some(_process) => { /* Placeholder if process-specific logic needed */ }
                None => return Err(Error::with_message(Errno::ESRCH, "process does not exist")),
            }
        }
    }

    // Assuming all CPUs are available; construct the cpu_set_t accordingly.
    let result = cpu_set_t {
        __bits: [usize::MAX; CPU_SETSIZE / __NCPUBITS],
    };

    // Write the CPU mask to user space.
    write_val_to_user(user_mask_ptr, &result)?;

    Ok(SyscallReturn::Return(0))
}

const CPU_SETSIZE: usize = 1024;
const __NCPUBITS: usize = 8 * mem::size_of::<usize>();

#[derive(Debug, Clone, Copy, Pod)]
#[repr(C, packed)]
struct cpu_set_t {
    __bits: [usize; CPU_SETSIZE / __NCPUBITS],
}
