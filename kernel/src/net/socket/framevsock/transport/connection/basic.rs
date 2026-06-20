// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use aster_framevsock::ConnectionId;

use super::Connected;
use crate::{
    events::IoEvents, net::socket::framevsock::addr::FrameVsockAddr, prelude::*,
    process::signal::PollHandle,
};

impl Connected {
    pub fn peer_addr(&self) -> FrameVsockAddr {
        self.id.peer_addr
    }

    pub fn local_addr(&self) -> FrameVsockAddr {
        self.id.local_addr
    }

    /// Returns and clears the pending socket error, if any.
    pub fn test_and_clear_error(&self) -> Option<Error> {
        let error = self.error.disable_irq().lock().take();
        if error.is_some() {
            self.pollee.invalidate();
        }
        error
    }

    /// Snapshot current TX progress epoch.
    #[inline]
    pub fn tx_progress_epoch(&self) -> u64 {
        self.tx_state.disable_irq().lock().tx_progress_epoch
    }

    /// Whether TX is currently blocked by backend queue pressure.
    #[inline]
    pub fn is_tx_blocked_on_queue(&self) -> bool {
        self.tx_state.disable_irq().lock().tx_blocked_on_queue
    }

    pub fn id(&self) -> ConnectionId {
        self.id
    }

    pub fn owns_local_port(&self) -> bool {
        self.owns_local_port
    }

    /// Cached vCPU mapping for this connection.
    #[inline]
    pub fn cached_vcpu_id(&self) -> usize {
        self.cached_vcpu_id
    }

    /// Gets our buffer allocation for credit info in packets.
    pub fn buf_alloc(&self) -> u32 {
        self.buf_alloc.load(Ordering::Acquire)
    }

    /// Gets our forward count for credit info in packets.
    pub fn fwd_cnt(&self) -> u32 {
        self.fwd_cnt.load(Ordering::Acquire) as u32
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }

    fn check_io_events(&self) -> IoEvents {
        let has_pending_error = self.error.disable_irq().lock().is_some();
        let rx = self.rx_state.disable_irq().lock();
        let tx = self.tx_state.disable_irq().lock();
        let mut events = IoEvents::empty();

        let local_read_shutdown = self.local_read_shutdown.load(Ordering::Acquire);
        let local_write_shutdown = self.local_write_shutdown.load(Ordering::Acquire);
        let peer_send_shutdown = self.peer_send_shutdown.load(Ordering::Acquire);
        let peer_recv_shutdown = self.peer_recv_shutdown.load(Ordering::Acquire);
        let connection_reset = self.connection_reset.load(Ordering::Acquire);
        let local_fully_closed = local_read_shutdown && local_write_shutdown;
        let peer_fully_closed = peer_send_shutdown && peer_recv_shutdown;

        if !rx.pending_packets.is_empty() || rx.partial_read.is_some() || peer_send_shutdown {
            events |= IoEvents::IN;
        }

        if peer_send_shutdown || local_read_shutdown {
            events |= IoEvents::IN | IoEvents::RDHUP;
        }

        let available = self.available_credit(tx.tx_cnt);
        if !local_write_shutdown {
            if available > 0 && !peer_recv_shutdown && !tx.tx_blocked_on_queue {
                events |= IoEvents::OUT;
            }

            if peer_fully_closed {
                events |= IoEvents::OUT;
            }
        }

        if local_fully_closed || (peer_send_shutdown && local_write_shutdown) {
            events |= IoEvents::HUP;
        }

        if connection_reset || has_pending_error {
            events |= IoEvents::ERR;
        }

        events
    }
}
