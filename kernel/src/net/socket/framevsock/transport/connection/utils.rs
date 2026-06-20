// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use aster_framevsock::ConnectionId;

use super::Connected;
use crate::{net::socket::framevsock::backend, prelude::*};

impl Connected {
    pub(super) fn set_error_if_empty(&self, error: Error) {
        let mut pending_error = self.error.disable_irq().lock();
        if pending_error.is_none() {
            *pending_error = Some(error);
        }
    }

    pub(super) fn set_reset_error_if_empty(&self) {
        self.set_error_if_empty(Error::with_message(
            Errno::ECONNRESET,
            "the connection is reset",
        ));
    }

    /// Calculates available credit to send to peer.
    pub(super) fn available_credit(&self, tx_cnt: u64) -> u32 {
        let peer_fwd_cnt = self.peer_credit.peer_fwd_cnt.load(Ordering::Acquire);
        let peer_buf_alloc = self.peer_credit.peer_buf_alloc.load(Ordering::Acquire);
        Self::calc_available_credit(tx_cnt, peer_buf_alloc, peer_fwd_cnt)
    }

    #[inline]
    pub(super) fn calc_available_credit(
        tx_cnt: u64,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u64,
    ) -> u32 {
        if peer_fwd_cnt >= tx_cnt {
            return peer_buf_alloc;
        }
        let in_flight = tx_cnt - peer_fwd_cnt;
        if in_flight > peer_buf_alloc as u64 {
            0
        } else {
            (peer_buf_alloc as u64 - in_flight) as u32
        }
    }

    /// Updates `peer_fwd_cnt`, reconstructing the full u64 from the u32 wire value.
    pub(super) fn update_peer_fwd_cnt(&self, new_low: u32, tx_cnt: u64) {
        loop {
            let prev = self.peer_credit.peer_fwd_cnt.load(Ordering::Acquire);
            let prev_high = prev & !0xFFFF_FFFF_u64;
            let candidate = prev_high | (new_low as u64);

            let new_full = if candidate > tx_cnt {
                if prev_high == 0 {
                    return;
                }
                (prev_high - (1u64 << 32)) | (new_low as u64)
            } else if candidate < prev {
                let wrapped = prev_high.wrapping_add(1u64 << 32) | (new_low as u64);
                if wrapped <= tx_cnt {
                    wrapped
                } else {
                    return;
                }
            } else {
                candidate
            };

            if new_full > tx_cnt || new_full < prev {
                return;
            }

            if self
                .peer_credit
                .peer_fwd_cnt
                .compare_exchange_weak(prev, new_full, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Selects vCPU for this connection.
    #[inline]
    pub(super) fn select_vcpu(&self) -> usize {
        self.cached_vcpu_id
    }

    /// Computes vCPU ID using local and peer addresses for distribution.
    pub(super) fn compute_vcpu_id(id: &ConnectionId) -> usize {
        let mut hash: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        for byte in id.local_addr.cid.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in id.local_addr.port.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in id.peer_addr.cid.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in id.peer_addr.port.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        let vcpu_count = backend::vcpu_count();
        (hash as usize) % vcpu_count
    }
}
