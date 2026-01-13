// SPDX-License-Identifier: MPL-2.0

//! Interrupt Handler Task (IHT) for FrameVM
//!
//! # Architecture
//!
//! Each vCPU has a dedicated IHT that processes packets from the shared Per-vCPU queue.
//! The IHT is a real-time priority kernel task that:
//! - Sleeps when there are no packets to process (removed from ready queue)
//! - Wakes up when packets arrive (via interrupt injection)
//! - Processes all pending packets before going back to sleep
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Per-vCPU Architecture                     │
//! │                                                              │
//! │   Host Thread                    IHT Task (RT Priority)      │
//! │       │                               ▲                      │
//! │       │ deliver_packet()              │ wake_iht()           │
//! │       ▼                               │                      │
//! │   ┌───────────────────────────────────┴───────────────┐     │
//! │   │              Per-vCPU Queue                        │     │
//! │   │  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │     │
//! │   │  │ data_queue  │  │control_queue│  │ wait_queue│  │     │
//! │   │  └─────────────┘  └─────────────┘  └───────────┘  │     │
//! │   └────────────────────────────────────────────────────┘     │
//! │                          │                                   │
//! │                          ▼                                   │
//! │                  ┌───────────────┐                          │
//! │                  │ IHT processes │                          │
//! │                  │ and dispatches│                          │
//! │                  └───────────────┘                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::notify::{InterruptStrategy, NotifyController};
use aster_framevsock::{ControlPacket, DataPacket};
use ostd::{
    sync::{SpinLock, WaitQueue},
    task::Task,
};
use spin::Once;

use crate::vsock;

/// Per-vCPU context that is shared between Host delivery and IHT processing.
///
/// This is the single source of truth for packet queues per vCPU.
/// Both Host (delivery) and IHT (processing) access the same queues.
pub struct PerVcpuContext {
    /// Data packet queue
    pub data_queue: SpinLock<VecDeque<RRef<DataPacket>>>,
    /// Control packet queue
    pub control_queue: SpinLock<VecDeque<RRef<ControlPacket>>>,
    /// WaitQueue for the IHT to sleep on - Host wakes this when delivering packets
    pub wait_queue: WaitQueue,
    /// Notification controller for race-free wait/notify
    pub notify_ctrl: NotifyController,
    /// Interrupt strategy for coalescing wakeups
    pub interrupt_strategy: InterruptStrategy,
    /// Handle to the IHT task itself
    pub task: SpinLock<Option<Arc<Task>>>,
    /// Exit flag for graceful shutdown
    pub should_exit: AtomicBool,
    /// vCPU ID for this context
    pub vcpu_id: usize,
}

impl PerVcpuContext {
    pub fn new(vcpu_id: usize) -> Self {
        Self {
            data_queue: SpinLock::new(VecDeque::with_capacity(1024)),
            control_queue: SpinLock::new(VecDeque::with_capacity(256)),
            wait_queue: WaitQueue::new(),
            notify_ctrl: NotifyController::new(),
            // Interrupt coalescing: wake after 8 packets or 50μs, whichever comes first
            interrupt_strategy: InterruptStrategy::with_time_threshold(8, 50),
            task: SpinLock::new(None),
            should_exit: AtomicBool::new(false),
            vcpu_id,
        }
    }

    /// Push a data packet to this vCPU's queue
    /// Returns Ok(()) on success, Err(packet) if queue is full
    #[inline]
    pub fn push_data(&self, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        let mut queue = self.data_queue.lock();
        if queue.len() >= 8192 {
            return Err(packet);
        }
        queue.push_back(packet);
        Ok(())
    }

    /// Push a control packet to this vCPU's queue
    /// Returns Ok(()) on success, Err(packet) if queue is full
    #[inline]
    pub fn push_control(&self, packet: RRef<ControlPacket>) -> Result<(), RRef<ControlPacket>> {
        let mut queue = self.control_queue.lock();
        if queue.len() >= 1024 {
            return Err(packet);
        }
        queue.push_back(packet);
        Ok(())
    }

    /// Pop a data packet from this vCPU's queue
    #[inline]
    pub fn pop_data(&self) -> Option<RRef<DataPacket>> {
        self.data_queue.lock().pop_front()
    }

    /// Pop a control packet from this vCPU's queue
    #[inline]
    pub fn pop_control(&self) -> Option<RRef<ControlPacket>> {
        self.control_queue.lock().pop_front()
    }

    /// Check if data queue has pending packets
    #[inline]
    pub fn has_pending_data(&self) -> bool {
        !self.data_queue.lock().is_empty()
    }

    /// Check if control queue has pending packets
    #[inline]
    pub fn has_pending_control(&self) -> bool {
        !self.control_queue.lock().is_empty()
    }

    /// Check if any queue has pending packets
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.has_pending_data() || self.has_pending_control()
    }

    /// Wake the IHT to process packets
    #[inline]
    pub fn wake_iht(&self) {
        self.wait_queue.wake_one();
    }

    /// Set the IHT task handle
    pub fn set_task(&self, task: Arc<Task>) {
        *self.task.lock() = Some(task);
    }
}

/// Global Manager for Per-vCPU contexts and IHTs
pub struct IhtManager {
    contexts: Vec<Arc<PerVcpuContext>>,
}

impl IhtManager {
    pub fn new(vcpu_count: usize) -> Self {
        let mut contexts = Vec::with_capacity(vcpu_count);
        for i in 0..vcpu_count {
            contexts.push(Arc::new(PerVcpuContext::new(i)));
        }
        Self { contexts }
    }

    /// Get the Per-vCPU context for a specific vCPU
    pub fn get_context(&self, vcpu_id: usize) -> Option<Arc<PerVcpuContext>> {
        self.contexts.get(vcpu_id).cloned()
    }

    /// Get number of vCPUs
    pub fn vcpu_count(&self) -> usize {
        self.contexts.len()
    }

    /// Iterate over all contexts
    pub fn iter_contexts(&self) -> impl Iterator<Item = &Arc<PerVcpuContext>> {
        self.contexts.iter()
    }
}

pub static IHT_MANAGER: Once<IhtManager> = Once::new();

/// Cached vCPU count for lock-free access
static VCPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// Initialize the global IHT manager
pub fn init_iht_manager(vcpu_count: usize) {
    VCPU_COUNT.store(vcpu_count, Ordering::Release);
    IHT_MANAGER.call_once(|| IhtManager::new(vcpu_count));
}

/// Get the vCPU count (lock-free)
#[inline]
pub fn get_vcpu_count() -> usize {
    VCPU_COUNT.load(Ordering::Relaxed)
}

/// IHT Creator function type
pub type IhtCreator = fn(Arc<PerVcpuContext>) -> Arc<Task>;
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
///
/// This function runs in a dedicated kernel task with real-time priority.
/// It continuously:
/// 1. Waits for packets to arrive (sleeping when idle)
/// 2. Processes all pending control packets first (connection management)
/// 3. Processes all pending data packets
/// 4. Goes back to sleep
pub fn iht_main_loop(ctx: Arc<PerVcpuContext>) {
    loop {
        // Wait for packets or exit signal
        // IHT sleeps here when there's nothing to do,
        // effectively removing itself from the ready queue
        ctx.wait_queue.wait_until(|| {
            if ctx.should_exit.load(Ordering::Acquire) {
                return Some(());
            }
            if ctx.has_pending() {
                return Some(());
            }
            None
        });

        if ctx.should_exit.load(Ordering::Acquire) {
            break;
        }

        // Process all pending packets
        // Control packets first (higher priority for connection management)
        loop {
            let packet = ctx.pop_control();
            match packet {
                Some(packet) => {
                    // Dispatch control packet
                    vsock::dispatch_control_packet_to_guest(packet);
                }
                None => break,
            }
        }

        // Then data packets
        loop {
            let packet = ctx.pop_data();
            match packet {
                Some(packet) => {
                    // Dispatch data packet
                    vsock::dispatch_data_packet_to_guest(packet);
                }
                None => break,
            }
        }
    }
}

// ========== Helper functions for external access ==========

/// Deliver a data packet to a specific vCPU's queue with interrupt coalescing
///
/// This is the main entry point for Host -> Guest data delivery.
/// Uses interrupt coalescing to reduce wakeup overhead:
/// - Always wakes on first packet (when queue was empty) - ensures low latency
/// - Subsequent packets use batching - wakes after batch_threshold packets
/// - This balances latency (first packet fast) and throughput (batching for bursts)
///
/// Returns Ok(()) if packet was queued, Err(packet) if queue is full.
pub fn deliver_data_to_vcpu(
    vcpu_id: usize,
    packet: RRef<DataPacket>,
) -> Result<(), RRef<DataPacket>> {
    if let Some(manager) = IHT_MANAGER.get() {
        if let Some(ctx) = manager.get_context(vcpu_id) {
            // Check if queue was empty before pushing (first packet should wake immediately)
            let was_empty = !ctx.has_pending_data();

            ctx.push_data(packet)?;

            // Wake IHT if:
            // 1. Queue was empty (first packet - ensures low latency for ping-pong patterns)
            // 2. Or batch threshold reached (for high throughput scenarios)
            if was_empty {
                // First packet: wake immediately to ensure low latency
                ctx.interrupt_strategy.reset();
                ctx.wake_iht();
            } else if ctx.interrupt_strategy.should_inject(
                false, // is_urgent: data packets are not urgent
                true,  // has_waiters: IHT is always waiting
            ) {
                // Batch threshold reached: wake for high throughput
                ctx.wake_iht();
            }

            return Ok(());
        }
    }
    Err(packet)
}

/// Deliver a control packet to a specific vCPU's queue and wake IHT immediately
///
/// Control packets are always urgent (connection management), so IHT is always woken.
/// This bypasses interrupt coalescing to ensure low latency for control operations.
pub fn deliver_control_to_vcpu(
    vcpu_id: usize,
    packet: RRef<ControlPacket>,
) -> Result<(), RRef<ControlPacket>> {
    if let Some(manager) = IHT_MANAGER.get() {
        if let Some(ctx) = manager.get_context(vcpu_id) {
            ctx.push_control(packet)?;

            // Control packets are urgent - reset coalescing counter and wake immediately
            ctx.interrupt_strategy.reset();
            ctx.wake_iht();

            return Ok(());
        }
    }
    Err(packet)
}

/// Check if a vCPU has pending packets
pub fn vcpu_has_pending(vcpu_id: usize) -> bool {
    if let Some(manager) = IHT_MANAGER.get() {
        if let Some(ctx) = manager.get_context(vcpu_id) {
            return ctx.has_pending();
        }
    }
    false
}

/// Pop a data packet from a vCPU's queue (for direct processing)
pub fn pop_data_from_vcpu(vcpu_id: usize) -> Option<RRef<DataPacket>> {
    if let Some(manager) = IHT_MANAGER.get() {
        if let Some(ctx) = manager.get_context(vcpu_id) {
            return ctx.pop_data();
        }
    }
    None
}

/// Pop a control packet from a vCPU's queue (for direct processing)
pub fn pop_control_from_vcpu(vcpu_id: usize) -> Option<RRef<ControlPacket>> {
    if let Some(manager) = IHT_MANAGER.get() {
        if let Some(ctx) = manager.get_context(vcpu_id) {
            return ctx.pop_control();
        }
    }
    None
}
