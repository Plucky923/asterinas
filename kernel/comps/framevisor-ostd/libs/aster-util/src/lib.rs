// SPDX-License-Identifier: MPL-2.0

//! FrameVM's provider for the kernel-shaped `aster_util` namespace.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub use host_aster_util::{
    coeff, dup, field_ptr, fixed_point, mem_obj_slice, printer, ranged_integer, safe_ptr, slot_vec,
};

pub mod per_cpu_counter;
