// SPDX-License-Identifier: MPL-2.0

//! Host-task commands owned by FrameVisor.

use alloc::{boxed::Box, sync::Arc};

use host_ostd::task::Task as OstdTask;

use super::{FrameTaskLocalData, FrameTaskState};
use crate::{prelude::Result, sync::Once};

/// The one Host-owned construction operation for an existing OSTD carrier.
/// Scheduler transitions never cross this boundary.
#[doc(hidden)]
pub type BuildHostTask =
    fn(Box<dyn FnOnce() + Send>, Arc<FrameTaskState>, FrameTaskLocalData) -> Result<Arc<OstdTask>>;

pub(super) static BUILD_HOST_TASK: Once<BuildHostTask> = Once::new();

/// Installs the immutable Host task command set.
pub fn inject_build_host_task(build_host_task: BuildHostTask) {
    BUILD_HOST_TASK.call_once(|| build_host_task);
}

pub(crate) fn build_host_task(
    func: Box<dyn FnOnce() + Send>,
    state: Arc<FrameTaskState>,
    local_data: FrameTaskLocalData,
) -> Result<Arc<OstdTask>> {
    let build_host_task = BUILD_HOST_TASK
        .get()
        .ok_or(crate::error::Error::InvalidArgs)?;
    build_host_task(func, state, local_data)
}
