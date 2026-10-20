// SPDX-License-Identifier: MPL-2.0

//! Authenticated entry to the shared-buffer pool.

use super::{CarrierState, RETURNING, current_carrier_state};
use crate::kernelet::{
    abi::{MmioResult, STATE},
    shared_buffer,
};

impl CarrierState<'_> {
    fn call_buffer_hook<R>(&self, hook_fn: impl FnOnce() -> R) -> Option<R> {
        // Buffer allocation runs with IRQs enabled. Only the bounded callback
        // uses the existing private hook stack and panic containment.
        let _irq_guard = crate::irq::disable_local();
        self.call_hook(hook_fn)
    }
}

// SAFETY: The fixed stub validates the live image stack and installs the
// carrier Host stack before calling. Buffer operations validate any Image DMA
// address before accessing it or changing grant ownership.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_buffer_impl(
    operation: u32,
    token: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
) -> MmioResult {
    let failure = MmioResult {
        status: -STATE,
        value: 0,
    };
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return failure;
    };
    let Some(()) = state.admit_service() else {
        return failure;
    };
    // Pool storage allocation and DMA mapping can wait for TLB publication.
    // They run on this carrier's Host stack, preserving image virtual guards.
    state.enter_schedulable_service();
    crate::arch::irq::enable_local();
    let result = if operation == crate::kernelet::abi::buffer::SHARED_NET_INFO {
        if token != 0
            || arg0 > u32::MAX as u64
            || arg1 > crate::kernelet::abi::buffer::NET_QUERY_IRQ as u64
            || arg2 != 0
        {
            MmioResult {
                status: -crate::kernelet::abi::INVALID,
                value: 0,
            }
        } else {
            state
                .call_buffer_hook(|| state.hooks.shared_net_info(arg0 as u32, arg1 as u32))
                .unwrap_or(failure)
        }
    } else if operation == crate::kernelet::abi::buffer::SHARED_NET_KICK {
        let accepted = token == 0
            && arg0 <= u32::MAX as u64
            && arg1 == 0
            && arg2 == 0
            && state
                .call_buffer_hook(|| state.hooks.shared_net_kick(arg0 as u32))
                .unwrap_or(false);
        MmioResult {
            status: if accepted {
                0
            } else {
                -crate::kernelet::abi::INVALID
            },
            value: 0,
        }
    } else if operation == crate::kernelet::abi::buffer::SHARED_NET_TRANSMIT {
        shared_buffer::dispatch_net_transmit(
            &state.control.shared_buffers,
            &state.guest_memory,
            token,
            [arg0, arg1, arg2],
        )
    } else if operation == crate::kernelet::abi::buffer::SHARED_NET_EXCHANGE {
        shared_buffer::dispatch_net_exchange(
            &state.control.shared_buffers,
            &state.guest_memory,
            token,
            [arg0, arg1, arg2],
        )
    } else {
        shared_buffer::dispatch_device(
            &state.control.shared_buffers,
            operation,
            token,
            [arg0, arg1, arg2],
            |id| {
                state
                    .call_buffer_hook(|| state.hooks.shared_block_info(id))
                    .flatten()
            },
            |bytes| {
                state
                    .call_buffer_hook(|| state.hooks.reserve_shared_buffer(bytes))
                    .unwrap_or(Err(crate::Error::AccessDenied))
            },
            |buffer, request| {
                state.call_buffer_hook(|| state.hooks.submit_buffer(buffer, request));
            },
        )
    };
    crate::arch::irq::disable_local();
    state.set_phase(RETURNING);
    result
}
