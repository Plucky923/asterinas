// SPDX-License-Identifier: MPL-2.0

//! FrameVM instance and registry management.
//!
//! This module declares the per-VM implementation and management registry,
//! then re-exports their existing public and crate-visible interfaces.

mod clock;
mod frame_group;
mod instance;
mod memory;
mod registry;
mod service_entry_points;
mod task_admission;
mod vcpu;

pub use aster_framevisor_exchangeable::VmId;
pub(crate) use clock::VmClock;
pub use frame_group::{FrameSchedGroup, FrameVcpuId};
pub use instance::{FrameVm, FrameVmConfig, FrameVmEventSink, MAX_VCPU_COUNT, VmStatus};
pub use memory::MemoryStats;
pub(crate) use memory::{MemoryCharge, MemoryDomain, MemoryReservation};
pub use registry::{
    create_vm, destroy_vm, get_sched_group_by_id, get_sched_groups_by_vm_id, get_vm_by_id, list_vms,
};
pub(crate) use service_entry_points::{ServiceEntryPoints, UserPageFaultEntryPoint};
/// Admission state for ordinary tasks owned by one FrameVM.
pub use task_admission::TaskAdmission;
pub(crate) use task_admission::TaskAdmissionOutcome;
pub use task_admission::TaskStartup;
/// Completion token held by one FrameVM worker task.
pub use task_admission::TaskWorker;
pub use vcpu::Vcpu;

pub(crate) use crate::mm::provider::FrameVmAllocator;
