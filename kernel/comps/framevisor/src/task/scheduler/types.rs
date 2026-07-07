// SPDX-License-Identifier: MPL-2.0

//! Scheduler and local runqueue abstractions.

use alloc::sync::Arc;

use crate::{cpu::CpuId, task::Task};

/// Flags that explain why a task is enqueued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueFlags {
    /// A task became runnable after creation.
    Spawn,
    /// A task became runnable after a wake operation.
    Wake,
}

/// Flags that explain why the current task is being updated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateFlags {
    /// The current task voluntarily yielded.
    Yield,
    /// The current task is about to wait.
    Wait,
    /// A timer tick arrived.
    Tick,
    /// The current task is exiting.
    Exit,
}

/// A SMP-aware task scheduler.
pub trait Scheduler<T = Task>: Send + Sync {
    /// Enqueues a runnable task.
    fn enqueue(&self, runnable: Arc<T>, flags: EnqueueFlags) -> Option<CpuId>;

    /// Gives immutable access to the local runqueue of the current CPU.
    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<T>));

    /// Gives mutable access to the local runqueue of the current CPU.
    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<T>));

    /// Gives immutable access to the local runqueue of a specific FrameVM CPU.
    fn local_rq_on_cpu_with(&self, cpu_id: CpuId, f: &mut dyn FnMut(&dyn LocalRunQueue<T>));

    /// Gives mutable access to the local runqueue of a specific FrameVM CPU.
    fn mut_local_rq_on_cpu_with(&self, cpu_id: CpuId, f: &mut dyn FnMut(&mut dyn LocalRunQueue<T>));
}

/// A per-CPU local runqueue.
pub trait LocalRunQueue<T = Task> {
    /// Returns the current task, if any.
    fn current(&self) -> Option<&Arc<T>>;

    /// Returns whether this runqueue has runnable service work.
    fn has_runnable(&self) -> bool;

    /// Updates the current task and returns whether another task should run.
    fn update_current(&mut self, flags: UpdateFlags) -> bool;

    /// Picks the next task to run.
    fn pick_next(&mut self) -> &Arc<T> {
        self.try_pick_next().unwrap()
    }

    /// Tries to pick the next task to run.
    fn try_pick_next(&mut self) -> Option<&Arc<T>>;

    /// Removes the current task from this runqueue.
    fn dequeue_current(&mut self) -> Option<Arc<T>>;
}
