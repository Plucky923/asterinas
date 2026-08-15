// SPDX-License-Identifier: MPL-2.0

#[expect(
    unused_imports,
    reason = "Keep the copied kernel prelude shape for service modules"
)]
pub use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, LinkedList, VecDeque},
    ffi::CString,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
#[expect(
    unused_imports,
    reason = "Keep the copied kernel prelude shape for service modules"
)]
pub use core::{any::Any, ffi::CStr, fmt::Debug};

#[expect(
    unused_imports,
    reason = "Keep the copied kernel prelude shape for service modules"
)]
pub use bitflags::bitflags;
pub use int_to_c_enum::TryFromInt;
pub use ostd::{
    alert, crit, debug, emerg, error, info,
    mm::{FallibleVmRead, FallibleVmWrite, PAGE_SIZE, Vaddr, VmReader, VmWriter},
    notice,
    sync::{Mutex, MutexGuard, RwLock, RwMutex, SpinLock, SpinLockGuard},
    warn,
};
pub use ostd_pod::{FromBytes, FromZeros, IntoBytes, Pod};

pub(crate) use crate::context::{CurrentUserSpace, current, current_thread};
pub use crate::{
    context::Context,
    error::{Errno, Error},
    process::{
        posix_thread::{AsPosixThread, AsThreadLocal},
        signal::Pause,
    },
    time::{Clock, wait::WaitTimeout},
    util::ReadCString,
};
#[expect(
    unused_imports,
    reason = "Keep syscall compatibility macros available through the prelude"
)]
pub(crate) use crate::{context::current_userspace, return_errno, return_errno_with_message};

pub type Result<T, E = Error> = core::result::Result<T, E>;
