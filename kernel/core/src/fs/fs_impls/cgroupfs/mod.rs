// SPDX-License-Identifier: MPL-2.0

pub(crate) use cgroup_ns::CgroupNamespace;
pub(crate) use controller::{
    cpu::{CpuStatKind, charge_cpu_time},
    cpuset::CpuPlacement,
};
use fs::CgroupFsType;
pub(in crate::fs) use systree_node::CgroupSystem;
pub(crate) use systree_node::{CgroupMembership, CgroupNode, CgroupSysNode};

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "cgroup: "
    };
}

mod cgroup_ns;
mod controller;
mod fs;
mod inode;
mod systree_node;

// This method should be called during kernel file system initialization,
// _after_ `aster_systree::init`.
pub(super) fn init() {
    crate::fs::vfs::registry::register(&CgroupFsType).unwrap();
}

/// Returns the root cgroup's stable CPU-placement domain.
pub(crate) fn root_cpu_placement() -> alloc::sync::Arc<CpuPlacement> {
    CgroupSystem::singleton().controller().cpu_placement()
}
