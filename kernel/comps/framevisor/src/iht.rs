// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::DataPacket;
use ostd::{
    sync::{SpinLock, WaitQueue},
    task::Task,
};
use spin::Once;

use crate::vsock;

/// Context for Per-vCPU Interrupt Handler Task
pub struct IhtContext {
    /// Queue of pending packets
    pub packet_queue: SpinLock<VecDeque<RRef<DataPacket>>>,
    /// WaitQueue for the IHT to sleep on
    pub wait_queue: WaitQueue,
    /// Handle to the IHT task itself (optional, for reference)
    pub task: SpinLock<Option<Arc<Task>>>,
    /// Exit flag
    pub should_exit: AtomicBool,
}

impl IhtContext {
    pub fn new() -> Self {
        Self {
            packet_queue: SpinLock::new(VecDeque::new()),
            wait_queue: WaitQueue::new(),
            task: SpinLock::new(None),
            should_exit: AtomicBool::new(false),
        }
    }

    pub fn set_task(&self, task: Arc<Task>) {
        *self.task.lock() = Some(task);
    }
}

/// Global Manager for IHTs
pub struct IhtManager {
    contexts: Vec<Arc<IhtContext>>,
}

impl IhtManager {
    pub fn new(vcpu_count: usize) -> Self {
        let mut contexts = Vec::with_capacity(vcpu_count);
        for _ in 0..vcpu_count {
            contexts.push(Arc::new(IhtContext::new()));
        }
        Self { contexts }
    }

    pub fn get_context(&self, vcpu_id: usize) -> Option<Arc<IhtContext>> {
        self.contexts.get(vcpu_id).cloned()
    }
}

pub static IHT_MANAGER: Once<IhtManager> = Once::new();

/// Initialize the global IHT manager
pub fn init_iht_manager(vcpu_count: usize) {
    IHT_MANAGER.call_once(|| IhtManager::new(vcpu_count));
}

/// IHT Creator function type
pub type IhtCreator = fn(Arc<IhtContext>) -> Arc<Task>;
static IHT_CREATOR: Once<IhtCreator> = Once::new();

/// Register the IHT creator (called by kernel)
#[ostd::ensure_stack(4096)]
pub fn inject_iht_creator(creator: IhtCreator) {
    IHT_CREATOR.call_once(|| creator);
}

/// Start all IHTs (called after init_iht_manager)
pub fn start_ihts() {
    if let Some(manager) = IHT_MANAGER.get() {
        if let Some(creator) = IHT_CREATOR.get() {
            for ctx in manager.contexts.iter() {
                let task = creator(ctx.clone());
                ctx.set_task(task.clone());
            }
        }
    }
}

/// The main loop for the Interrupt Handler Task
pub fn iht_main_loop(ctx: Arc<IhtContext>) {
    loop {
        // Wait for packets or exit signal
        ctx.wait_queue.wait_until(|| {
            if ctx.should_exit.load(Ordering::Acquire) {
                return Some(());
            }
            let queue = ctx.packet_queue.lock();
            if !queue.is_empty() {
                return Some(());
            }
            None
        });

        if ctx.should_exit.load(Ordering::Acquire) {
            break;
        }

        // Process all pending packets
        loop {
            let packet = {
                let mut queue = ctx.packet_queue.lock();
                queue.pop_front()
            };

            match packet {
                Some(packet) => {
                    // Dispatch the packet using the handler in vsock
                    let _result = vsock::invoke_direct_dispatch(packet);
                }
                None => {
                    break;
                }
            }
        }
    }
}
