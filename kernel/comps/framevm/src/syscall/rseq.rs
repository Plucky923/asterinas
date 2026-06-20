// SPDX-License-Identifier: MPL-2.0

//! `rseq(2)` implementation placeholder.

use super::{Errno, Error, Result};

pub(super) fn sys_rseq() -> Result<isize> {
    // Linux userspace enables restartable sequences only if the syscall
    // succeeds. The trimmed kernel image does not yet update per-task rseq CPU state on
    // migration or preemption, so report the feature as unavailable.
    Err(Error::new(Errno::ENOSYS))
}
