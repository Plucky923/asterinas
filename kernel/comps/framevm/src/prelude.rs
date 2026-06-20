// SPDX-License-Identifier: MPL-2.0

#![expect(unused)]

pub use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::CString,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
pub use core::{any::Any, ffi::CStr, fmt::Debug};

pub use bitflags::bitflags;
pub use ostd::mm::{FallibleVmRead, FallibleVmWrite, PAGE_SIZE, Vaddr, VmReader, VmWriter};

pub use crate::{
    context::Context,
    error::{Errno, Error, Result},
};
pub(crate) use crate::{return_errno, return_errno_with_message};

macro_rules! debug {
    ($($arg:tt)+) => {{
        let _ = core::format_args!($($arg)+);
    }};
}
pub(crate) use debug;
