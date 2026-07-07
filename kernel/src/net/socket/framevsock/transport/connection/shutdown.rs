// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use framev_sock_common::{FrameVsockPacket, SHUTDOWN_FLAG_RECV, SHUTDOWN_FLAG_SEND};

use super::Connected;
use crate::{
    events::IoEvents,
    net::socket::{framevsock::backend, util::SockShutdownCmd},
    prelude::*,
    thread::Thread,
};

const CONTROL_SEND_RETRIES: usize = 1024;

impl Connected {
    pub fn should_close(&self) -> bool {
        let rx = self.rx_state.disable_irq().lock();
        self.peer_send_shutdown.load(Ordering::Acquire)
            && self.peer_recv_shutdown.load(Ordering::Acquire)
            && rx.pending_packets.is_empty()
            && rx.partial_read.is_none()
    }

    pub fn is_closed(&self) -> bool {
        self.local_read_shutdown.load(Ordering::Acquire)
            && self.local_write_shutdown.load(Ordering::Acquire)
    }

    pub fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        let mut shutdown_flags = 0;
        let mut notify_events = IoEvents::empty();

        if cmd.shut_read() && !self.local_read_shutdown.swap(true, Ordering::AcqRel) {
            shutdown_flags |= SHUTDOWN_FLAG_RECV;
            notify_events |= IoEvents::IN | IoEvents::RDHUP | IoEvents::HUP;
        }

        if cmd.shut_write() && !self.local_write_shutdown.swap(true, Ordering::AcqRel) {
            shutdown_flags |= SHUTDOWN_FLAG_SEND;
            notify_events |= IoEvents::HUP;
        }

        let peer_fully_closed = self.peer_send_shutdown.load(Ordering::Acquire)
            && self.peer_recv_shutdown.load(Ordering::Acquire);

        if !peer_fully_closed && shutdown_flags != 0 {
            let packet =
                FrameVsockPacket::shutdown(self.local_addr(), self.peer_addr(), shutdown_flags);

            let vcpu_id = self.select_vcpu();
            let mut packet = backend::PacketCarrier::from_owned(packet);
            let mut retries = 0usize;
            loop {
                match backend::send_packet(vcpu_id, packet) {
                    Ok(()) => break,
                    Err(returned_packet) => {
                        retries = retries.saturating_add(1);
                        if retries >= CONTROL_SEND_RETRIES {
                            return_errno_with_message!(
                                Errno::EAGAIN,
                                "the FrameVsock control queue is full"
                            );
                        }
                        packet = returned_packet;
                        Thread::yield_now();
                    }
                }
            }
        }

        self.pollee.notify(notify_events);
        Ok(())
    }

    /// Handles shutdown from peer.
    pub fn on_shutdown_received(&self, flags: u32) -> Result<bool> {
        let mut notify_events = IoEvents::empty();

        if flags & SHUTDOWN_FLAG_SEND != 0 && !self.peer_send_shutdown.swap(true, Ordering::AcqRel)
        {
            notify_events |= IoEvents::IN | IoEvents::OUT | IoEvents::RDHUP | IoEvents::HUP;
        }
        if flags & SHUTDOWN_FLAG_RECV != 0 && !self.peer_recv_shutdown.swap(true, Ordering::AcqRel)
        {
            notify_events |= IoEvents::OUT;
        }

        if !notify_events.is_empty() {
            self.pollee.notify(notify_events);
        }

        let peer_fully_closed = self.peer_send_shutdown.load(Ordering::Acquire)
            && self.peer_recv_shutdown.load(Ordering::Acquire);
        Ok(peer_fully_closed && !notify_events.is_empty())
    }

    /// Handles reset from peer.
    pub fn on_rst_received(&self) -> Result<()> {
        self.set_reset_error_if_empty();
        self.connection_reset.store(true, Ordering::Release);
        self.peer_send_shutdown.store(true, Ordering::Release);
        self.peer_recv_shutdown.store(true, Ordering::Release);
        self.local_read_shutdown.store(true, Ordering::Release);
        self.local_write_shutdown.store(true, Ordering::Release);

        {
            let mut rx = self.rx_state.disable_irq().lock();
            rx.pending_packets.clear();
            rx.partial_read = None;
        }
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);
        Ok(())
    }
}
