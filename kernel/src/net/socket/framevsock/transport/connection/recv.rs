// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{
    DataPacket, create_credit_update, create_rst,
    flow_control::{self, MAX_PENDING_PACKETS},
    trace,
};

use super::{Connected, RxState};
use crate::{events::IoEvents, net::socket::framevsock::backend, prelude::*, util::MultiWrite};

/// Partial read state - tracks remaining data from a partially consumed packet.
pub(super) struct PartialRead {
    packet: RRef<DataPacket>,
    offset: usize,
}

enum PendingRead {
    Partial(PartialRead),
    Packet(RRef<DataPacket>),
}

impl PendingRead {
    fn remaining_data(&self) -> &[u8] {
        match self {
            Self::Partial(partial) => &partial.packet.data.as_slice()[partial.offset..],
            Self::Packet(packet) => packet.data.as_slice(),
        }
    }

    fn total_packet_len(&self) -> usize {
        match self {
            Self::Partial(partial) => partial.packet.data.len(),
            Self::Packet(packet) => packet.data.len(),
        }
    }

    fn into_partial_read(self, bytes_written: usize) -> PartialRead {
        match self {
            Self::Partial(mut partial) => {
                partial.offset += bytes_written;
                partial
            }
            Self::Packet(packet) => PartialRead {
                packet,
                offset: bytes_written,
            },
        }
    }

    fn restore_no_progress(self, rx: &mut RxState) {
        match self {
            Self::Partial(partial) => rx.partial_read = Some(partial),
            Self::Packet(packet) => rx.pending_packets.push_front(packet),
        }
    }
}

impl Connected {
    /// Receive data to a MultiWrite (user buffer).
    ///
    /// Zero-copy path:
    /// 1. Get packet from pending queue (RRef<DataPacket>)
    /// 2. Copy data directly from packet to user buffer (ONE copy)
    pub fn try_recv(&self, writer: &mut dyn MultiWrite) -> Result<usize> {
        let _trace = trace::TraceGuard::new(&trace::HOST_TRY_RECV);
        let mut total_written = 0usize;
        let mut terminal_result = None;

        loop {
            let Some(pending_read) = ({
                let mut rx = self.rx_state.disable_irq().lock();
                if let Some(partial) = rx.partial_read.take() {
                    Some(PendingRead::Partial(partial))
                } else {
                    rx.pending_packets.pop_front().map(PendingRead::Packet)
                }
            }) else {
                break;
            };

            let remaining = pending_read.remaining_data();
            let remaining_len = remaining.len();
            let mut vm_reader = VmReader::from(remaining);
            let before = writer.sum_lens();
            let bytes_written = match writer.write(&mut vm_reader) {
                Ok(n) => n,
                Err(e) => {
                    let after = writer.sum_lens();
                    let progressed = before.saturating_sub(after).min(remaining_len);
                    let mut rx = self.rx_state.disable_irq().lock();

                    if progressed > 0 {
                        total_written += progressed;
                        if progressed < remaining_len {
                            rx.partial_read = Some(pending_read.into_partial_read(progressed));
                        } else {
                            let packet_len = pending_read.total_packet_len() as u32;
                            self.fwd_cnt.fetch_add(packet_len as u64, Ordering::Relaxed);
                            rx.buf_used = rx.buf_used.saturating_sub(packet_len);
                        }
                        terminal_result = Some(Ok(total_written));
                        break;
                    }

                    pending_read.restore_no_progress(&mut rx);
                    terminal_result = Some(if total_written > 0 {
                        Ok(total_written)
                    } else {
                        Err(e.into())
                    });
                    break;
                }
            };

            total_written += bytes_written;
            let mut rx = self.rx_state.disable_irq().lock();

            if bytes_written < remaining_len {
                rx.partial_read = Some(pending_read.into_partial_read(bytes_written));
                break;
            } else {
                let packet_len = pending_read.total_packet_len() as u32;
                self.fwd_cnt.fetch_add(packet_len as u64, Ordering::Relaxed);
                rx.buf_used = rx.buf_used.saturating_sub(packet_len);
            }
        }

        if total_written > 0 {
            let mut rx = self.rx_state.disable_irq().lock();
            let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
            self.send_credit_update_internal(&mut rx, buf_alloc);
        }

        if let Some(result) = terminal_result {
            return result;
        }

        let is_connection_reset = self.connection_reset.load(Ordering::Acquire);
        let is_peer_send_shutdown = self.peer_send_shutdown.load(Ordering::Acquire);
        let is_local_read_shutdown = self.local_read_shutdown.load(Ordering::Acquire);
        self.pollee.invalidate();

        if total_written > 0 {
            return Ok(total_written);
        }

        if is_connection_reset {
            return_errno_with_message!(Errno::ECONNRESET, "the connection is reset");
        }
        if is_peer_send_shutdown || is_local_read_shutdown {
            return Ok(0);
        }
        return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty");
    }

    /// Handle incoming data packet (zero-copy: packet ownership transferred).
    ///
    /// All checks (buf_used, queue capacity) are done atomically under the same
    /// lock to prevent race conditions. Stream sockets must not silently drop
    /// data; on RX overflow, reset the connection so peers fail fast instead of
    /// stalling forever.
    pub fn on_data_packet_received(&self, packet: RRef<DataPacket>) -> Result<()> {
        let _trace = trace::TraceGuard::new(&trace::HOST_ON_DATA);
        let src_port = packet.header.src_port;

        let tx_cnt = {
            let tx = self.tx_state.disable_irq().lock();
            tx.tx_cnt
        };

        self.peer_credit
            .peer_buf_alloc
            .store(packet.header.buf_alloc, Ordering::Release);
        self.update_peer_fwd_cnt(packet.header.fwd_cnt, tx_cnt);

        let mut rx = self.rx_state.disable_irq().lock();
        let packet_size = packet.data.len() as u32;

        if rx.pending_packets.len() >= MAX_PENDING_PACKETS {
            drop(rx);

            error!(
                "[FrameVsock] FATAL: RX pending queue overflow from port {} (len={}, queue_len={}). Reset connection.",
                src_port, packet_size, MAX_PENDING_PACKETS
            );

            let rst_packet = create_rst(
                self.local_addr().cid,
                self.local_addr().port,
                self.peer_addr().cid,
                self.peer_addr().port,
            );
            let vcpu_id = self.select_vcpu();
            let _ = backend::send_control(vcpu_id, rst_packet);

            self.set_reset_error_if_empty();
            self.connection_reset.store(true, Ordering::Release);
            self.peer_send_shutdown.store(true, Ordering::Release);
            self.peer_recv_shutdown.store(true, Ordering::Release);
            self.local_read_shutdown.store(true, Ordering::Release);
            self.local_write_shutdown.store(true, Ordering::Release);
            self.pollee
                .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);

            return_errno_with_message!(Errno::ENOBUFS, "receiver queue overflow");
        }

        let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
        if rx.buf_used.saturating_add(packet_size) > buf_alloc {
            let buf_used = rx.buf_used;
            drop(rx);

            error!(
                "[FrameVsock] FATAL: RX buffer overflow from port {} (buf_used={} + {} > {}). Reset connection.",
                src_port, buf_used, packet_size, buf_alloc
            );

            let rst_packet = create_rst(
                self.local_addr().cid,
                self.local_addr().port,
                self.peer_addr().cid,
                self.peer_addr().port,
            );
            let vcpu_id = self.select_vcpu();
            let _ = backend::send_control(vcpu_id, rst_packet);

            self.set_reset_error_if_empty();
            self.connection_reset.store(true, Ordering::Release);
            self.peer_send_shutdown.store(true, Ordering::Release);
            self.peer_recv_shutdown.store(true, Ordering::Release);
            self.local_read_shutdown.store(true, Ordering::Release);
            self.local_write_shutdown.store(true, Ordering::Release);
            self.pollee
                .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);

            return_errno_with_message!(Errno::ENOBUFS, "receiver buffer overflow");
        }

        rx.buf_used = rx.buf_used.saturating_add(packet_size);
        rx.pending_packets.push_back(packet);

        if self.should_send_credit_update_rx(&mut rx) {
            let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
            self.send_credit_update_internal(&mut rx, buf_alloc);
        }

        drop(rx);

        self.pollee.notify(IoEvents::IN | IoEvents::OUT);
        Ok(())
    }

    /// Send credit update to peer.
    pub fn send_credit_update(&self) {
        let mut rx = self.rx_state.disable_irq().lock();
        let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
        self.send_credit_update_internal(&mut rx, buf_alloc);
    }

    /// Checks if we should send a credit update with the Linux-style heuristic.
    fn should_send_credit_update_rx(&self, rx: &mut RxState) -> bool {
        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed) as u32;

        flow_control::should_send_credit_update(
            buf_alloc,
            rx.buf_used,
            fwd_cnt,
            rx.last_credit_update_fwd_cnt as u32,
        )
    }

    /// Sends credit update with `rx` locked.
    fn send_credit_update_internal(&self, rx: &mut RxState, buf_alloc: u32) {
        let _trace = trace::TraceGuard::new(&trace::HOST_SEND_CREDIT_UPDATE);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Acquire);
        rx.last_credit_update_fwd_cnt = fwd_cnt;
        let packet = create_credit_update(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
            buf_alloc,
            fwd_cnt as u32,
        );
        let vcpu_id = self.select_vcpu();
        let _ = backend::send_control(vcpu_id, packet);
    }
}
