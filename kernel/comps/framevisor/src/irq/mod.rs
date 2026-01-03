// SPDX-License-Identifier: MPL-2.0

//! FrameVisor IRQ (Interrupt ReQuest) handling module.
//!
//! This module provides virtualized interrupt handling for FrameVM.
//! The API signatures are designed to be consistent with `ostd::irq`,
//! but the implementation is virtualized.
//!
//! # Design Principles
//!
//! - API signatures match `ostd::irq` for seamless code reuse in FrameVM
//! - Implementation is based on a virtual interrupt table in memory
//! - No actual hardware interrupt allocation is needed

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::ops::Deref;

use ostd::arch::trap::TrapFrame;
use spin::RwLock;

use crate::prelude::*;

/// FrameVsock dedicated virtual IRQ number
pub const FRAMEVSOCK_IRQ_NUM: u8 = 0x80;

/// Virtual IRQ number range for FrameVisor
const IRQ_NUM_MIN: u8 = 0x80;
const IRQ_NUM_MAX: u8 = 0x8F;
const NUMBER_OF_IRQS: usize = (IRQ_NUM_MAX - IRQ_NUM_MIN + 1) as usize;

/// Type alias for IRQ callback function.
/// Signature matches `ostd::irq::IrqCallbackFunction`.
pub type IrqCallbackFunction = dyn Fn(&TrapFrame) + Sync + Send + 'static;

/// Inner state for a single IRQ line
struct IrqInner {
    callbacks: RwLock<Vec<Box<IrqCallbackFunction>>>,
}

impl IrqInner {
    const fn new() -> Self {
        Self {
            callbacks: RwLock::new(Vec::new()),
        }
    }
}

/// Global virtual IRQ table
static FRAMEVISOR_IRQS: [IrqInner; NUMBER_OF_IRQS] = [const { IrqInner::new() }; NUMBER_OF_IRQS];

/// Virtual IRQ line handle.
///
/// This structure provides the same API as `ostd::irq::IrqLine`,
/// but manages virtual interrupts for FrameVM.
#[derive(Debug)]
#[must_use]
pub struct IrqLine {
    inner: Arc<InnerHandle>,
    callbacks: Vec<CallbackHandle>,
}

#[derive(Debug)]
struct InnerHandle {
    index: u8,
}

impl Deref for InnerHandle {
    type Target = IrqInner;

    fn deref(&self) -> &Self::Target {
        &FRAMEVISOR_IRQS[self.index as usize]
    }
}

#[derive(Debug)]
struct CallbackHandle {
    irq_index: u8,
    callback_addr: usize,
}

impl Drop for CallbackHandle {
    fn drop(&mut self) {
        let mut callbacks = FRAMEVISOR_IRQS[self.irq_index as usize].callbacks.write();
        if let Some(pos) = callbacks
            .iter()
            .position(|cb| core::ptr::from_ref(&**cb).addr() == self.callback_addr)
        {
            callbacks.swap_remove(pos);
        }
    }
}

impl IrqLine {
    /// Allocates an available IRQ line.
    ///
    /// Signature matches `ostd::irq::IrqLine::alloc()`.
    pub fn alloc() -> Result<Self> {
        // For virtual IRQs, we simply use the first available slot
        // In practice, we may need an allocator
        Self::alloc_specific(IRQ_NUM_MIN)
    }

    /// Allocates a specific IRQ line.
    ///
    /// Signature matches `ostd::irq::IrqLine::alloc_specific()`.
    pub fn alloc_specific(irq_num: u8) -> Result<Self> {
        if irq_num < IRQ_NUM_MIN || irq_num > IRQ_NUM_MAX {
            return Err(crate::error::Error::InvalidArgs);
        }
        Ok(Self::new(irq_num - IRQ_NUM_MIN))
    }

    fn new(index: u8) -> Self {
        Self {
            inner: Arc::new(InnerHandle { index }),
            callbacks: Vec::new(),
        }
    }

    /// Gets the IRQ number.
    ///
    /// Signature matches `ostd::irq::IrqLine::num()`.
    pub fn num(&self) -> u8 {
        self.inner.index + IRQ_NUM_MIN
    }

    /// Registers a callback that will be invoked when the IRQ is active.
    ///
    /// Signature matches `ostd::irq::IrqLine::on_active()`.
    pub fn on_active<F>(&mut self, callback: F)
    where
        F: Fn(&TrapFrame) + Sync + Send + 'static,
    {
        let callback_handle = {
            let callback_box = Box::new(callback);
            let callback_addr = core::ptr::from_ref(&*callback_box).addr();

            let mut callbacks = self.inner.callbacks.write();
            callbacks.push(callback_box);

            CallbackHandle {
                irq_index: self.inner.index,
                callback_addr,
            }
        };

        self.callbacks.push(callback_handle);
    }

    /// Checks if there are no registered callbacks.
    ///
    /// Signature matches `ostd::irq::IrqLine::is_empty()`.
    pub fn is_empty(&self) -> bool {
        self.callbacks.is_empty()
    }
}

impl Clone for IrqLine {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            callbacks: Vec::new(),
        }
    }
}

/// Calls all registered callbacks for the given IRQ.
///
/// This is the core dispatch function, similar to `ostd::irq::call_irq_callback_functions`.
pub fn call_irq_callbacks(trap_frame: &TrapFrame, irq_num: u8) {
    if irq_num < IRQ_NUM_MIN || irq_num > IRQ_NUM_MAX {
        return;
    }

    let index = (irq_num - IRQ_NUM_MIN) as usize;
    let callbacks = FRAMEVISOR_IRQS[index].callbacks.read();

    for callback in callbacks.iter() {
        callback(trap_frame);
    }
}

/// Injects a virtual interrupt into FrameVM.
///
/// This is a FrameVisor-specific API for injecting interrupts from Host to Guest.
///
/// # Arguments
/// - `irq_num`: Virtual IRQ number
/// - `trap_frame`: CPU state at interrupt time
///   - User mode: obtained from `UserContext.as_trap_frame()`
///   - Kernel mode: use `make_synthetic_trapframe()`
pub fn inject_irq(irq_num: u8, trap_frame: &TrapFrame) {
    call_irq_callbacks(trap_frame, irq_num);
}

/// Creates a synthetic TrapFrame for kernel-mode interrupt injection.
///
/// When injecting interrupts in kernel mode, we don't have real register state.
/// For virtual devices like FrameVsock, callbacks typically don't need these values.
pub fn make_synthetic_trapframe(irq_num: u8) -> TrapFrame {
    TrapFrame {
        trap_num: irq_num as usize,
        error_code: 0,
        ..Default::default()
    }
}

/// Injects a FrameVsock RX ready interrupt.
pub fn inject_vsock_rx_interrupt() {
    let trap_frame = make_synthetic_trapframe(FRAMEVSOCK_IRQ_NUM);
    inject_irq(FRAMEVSOCK_IRQ_NUM, &trap_frame);
}

/// Initialize the IRQ subsystem
pub fn init() {
    ostd::early_println!("[framevisor] IRQ subsystem initialized");
}
