// SPDX-License-Identifier: MPL-2.0

//! Service stack management for secure cross-domain calls.
//!
//! This module provides service stacks that are used when the caller's stack
//! has insufficient space. Each CPU has its own service stack to avoid
//! contention.
//!
//! # Security Model
//!
//! Service stacks provide isolation between untrusted callers (e.g., FrameVM)
//! and trusted callees (e.g., FrameVisor). When a caller has exhausted its
//! stack (either legitimately or maliciously), the callee can safely execute
//! on the service stack.

use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Once;

use crate::{
    cpu_local_cell,
    mm::{
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
        FrameAllocOptions, PAGE_SIZE,
        kspace::kvirt_area::KVirtArea,
    },
    prelude::*,
};

/// Service stack size (64KB by default).
const SERVICE_STACK_SIZE: usize = 64 * 1024;

/// Service stack for executing code when the caller's stack is insufficient.
pub struct ServiceStack {
    /// The virtual memory area for the stack.
    kvirt_area: KVirtArea,
    /// Stack top address (high address, initial RSP value).
    top: Vaddr,
    /// Stack bottom address (low address).
    bottom: Vaddr,
    /// Nesting depth (0 = not in use).
    nesting_depth: AtomicU32,
}

// SAFETY: ServiceStack is thread-safe. The kvirt_area is not modified after
// creation, and nesting_depth uses atomic operations.
unsafe impl Send for ServiceStack {}
unsafe impl Sync for ServiceStack {}

/// Metadata for service stack frames.
#[derive(Debug, Default)]
struct ServiceStackMeta;

crate::impl_frame_meta_for!(ServiceStackMeta);

impl ServiceStack {
    /// Creates a new service stack.
    pub fn new() -> Result<Self> {
        let num_pages = SERVICE_STACK_SIZE / PAGE_SIZE;

        // Allocate physical frames for the stack
        let pages = FrameAllocOptions::new()
            .zeroed(true)
            .alloc_segment_with(num_pages, |_| ServiceStackMeta)?;

        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::empty(),
        };

        // Map with guard pages (1 page before, 1 page after)
        let kvirt_area = KVirtArea::map_frames(
            SERVICE_STACK_SIZE + 2 * PAGE_SIZE,  // Total size including guards
            PAGE_SIZE,                            // Offset (1 guard page before)
            pages.into_iter(),
            prop,
        );

        let bottom = kvirt_area.range().start + PAGE_SIZE;
        let top = bottom + SERVICE_STACK_SIZE;

        Ok(Self {
            kvirt_area,
            top,
            bottom,
            nesting_depth: AtomicU32::new(0),
        })
    }

    /// Returns the stack top address (high address).
    #[inline]
    pub fn top(&self) -> Vaddr {
        self.top
    }

    /// Returns the stack bottom address (low address).
    #[inline]
    pub fn bottom(&self) -> Vaddr {
        self.bottom
    }

    /// Checks if the given stack pointer is within this service stack.
    #[inline]
    pub fn contains(&self, rsp: usize) -> bool {
        rsp >= self.bottom && rsp < self.top
    }

    /// Increments the nesting depth.
    #[inline]
    pub fn enter(&self) {
        self.nesting_depth.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrements the nesting depth.
    #[inline]
    pub fn leave(&self) {
        self.nesting_depth.fetch_sub(1, Ordering::AcqRel);
    }

    /// Returns the current nesting depth.
    #[inline]
    pub fn nesting_depth(&self) -> u32 {
        self.nesting_depth.load(Ordering::Acquire)
    }
}

cpu_local_cell! {
    /// Pointer to the current CPU's service stack.
    static CPU_SERVICE_STACK_PTR: usize = 0;
}

/// Global storage for service stacks (one per CPU).
static SERVICE_STACKS: Once<Vec<ServiceStack>> = Once::new();

/// Initializes the service stack system.
///
/// This must be called during system initialization before any stack switching
/// can occur.
///
/// # Arguments
///
/// * `cpu_count` - The number of CPUs in the system.
pub fn init(cpu_count: usize) {
    SERVICE_STACKS.call_once(|| {
        let mut stacks = Vec::with_capacity(cpu_count);
        for _ in 0..cpu_count {
            stacks.push(
                ServiceStack::new().expect("Failed to allocate service stack")
            );
        }
        stacks
    });
}

/// Sets up the service stack for the current CPU.
///
/// This must be called on each CPU after `init()`.
///
/// # Arguments
///
/// * `cpu_id` - The ID of the current CPU.
pub fn init_on_cpu(cpu_id: usize) {
    if let Some(stacks) = SERVICE_STACKS.get() {
        if let Some(stack) = stacks.get(cpu_id) {
            CPU_SERVICE_STACK_PTR.store(stack as *const _ as usize);
        }
    }
}

/// Gets the service stack for the current CPU.
fn get_current_service_stack() -> Option<&'static ServiceStack> {
    let ptr = CPU_SERVICE_STACK_PTR.load();
    if ptr == 0 {
        None
    } else {
        // SAFETY: The pointer was set by init_on_cpu and points to a valid
        // ServiceStack that lives for the duration of the system.
        Some(unsafe { &*(ptr as *const ServiceStack) })
    }
}

/// Checks if the current execution is on a service stack.
#[inline]
pub fn is_on_service_stack() -> bool {
    let current_rsp = super::stack::current_stack_pointer();

    if let Some(stack) = get_current_service_stack() {
        stack.contains(current_rsp)
    } else {
        false
    }
}

// Import the assembly stack switching function from arch layer.
use crate::arch::task::call_on_stack;

/// Executes a closure on the service stack.
///
/// If already on the service stack (nested call), the closure is executed
/// directly without switching.
///
/// # Arguments
///
/// * `f` - The closure to execute.
///
/// # Returns
///
/// The return value of the closure.
///
/// # Panics
///
/// Panics if the service stack is not initialized.
pub fn with_service_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let service_stack = get_current_service_stack()
        .expect("Service stack not initialized for this CPU");

    // Check if we're already on the service stack (nested call)
    let current_rsp = super::stack::current_stack_pointer();
    if service_stack.contains(current_rsp) {
        // Already on service stack, execute directly
        return f();
    }

    // Track nesting
    service_stack.enter();

    // Prepare closure data
    struct ClosureData<F, R> {
        func: Option<F>,
        result: Option<R>,
    }

    let mut data = ClosureData {
        func: Some(f),
        result: None,
    };

    // Wrapper function that will be called on the service stack
    extern "C" fn wrapper<F, R>(data_ptr: usize)
    where
        F: FnOnce() -> R,
    {
        let data = unsafe { &mut *(data_ptr as *mut ClosureData<F, R>) };
        if let Some(func) = data.func.take() {
            data.result = Some(func());
        }
    }

    // Perform the stack switch
    // SAFETY:
    // - service_stack.top() is a valid stack address
    // - wrapper::<F, R> is a valid function pointer
    // - &mut data is a valid pointer that outlives the call
    unsafe {
        call_on_stack(
            service_stack.top(),
            wrapper::<F, R> as usize,
            &mut data as *mut _ as usize,
        );
    }

    // Track nesting
    service_stack.leave();

    // Return the result
    data.result.expect("Closure did not produce a result")
}

#[cfg(ktest)]
mod test {
    use super::*;

    #[ktest]
    fn test_service_stack_creation() {
        let stack = ServiceStack::new().unwrap();
        assert!(stack.top() > stack.bottom());
        assert_eq!(stack.top() - stack.bottom(), SERVICE_STACK_SIZE);
        assert_eq!(stack.nesting_depth(), 0);
    }

    #[ktest]
    fn test_is_on_service_stack() {
        // Before initialization, should return false
        assert!(!is_on_service_stack());
    }
}
