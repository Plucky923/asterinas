// SPDX-License-Identifier: MPL-2.0

//! Task scheduler injection and FrameVM scheduler bridges.

mod cpu_scope;
pub mod info;
mod interrupt;
mod queue;
mod registry;
mod timer;
mod types;

pub(crate) use cpu_scope::{current_cpu, enter_frame_cpu_scope, try_current_cpu};
pub(crate) use interrupt::{
    VirtualInterruptToken, enter_virtual_interrupt_disabled_section,
    exit_virtual_interrupt_disabled_section, frame_vcpu_current_ostd_task,
    frame_vcpu_needs_resched, frame_vcpu_virtual_interrupts_enabled,
};
pub(crate) use queue::{enqueue_task, exit_current_task, park_current, unpark_target};
pub use registry::inject_scheduler;
pub(crate) use registry::{clear_scheduler, clear_scheduler_for_vm};
pub use timer::enable_preemption_on_cpu;
pub(crate) use timer::{dispatch_timer_ticks, init_virtual_timer_on_current_cpu};
pub use types::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags};
