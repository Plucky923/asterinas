// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{
    DataPacket, create_credit_request, create_data_packet_with_credit,
    flow_control::MAX_PKT_BUF_SIZE, trace,
};

use super::{Connected, TxState};
use crate::{
    events::IoEvents,
    net::socket::{framevsock::backend, util::SendRecvFlags},
    prelude::*,
    util::MultiRead,
};

/// Retry interval for credit requests when no credit update is received.
///
/// Keep this conservative to avoid control-plane storms under single-vCPU
/// contention. Linux virtio-vsock relies on reliable transport delivery and
/// does not aggressively resend credit requests in tight loops.
const CREDIT_REQUEST_RETRY_NS: u64 = 5_000_000; // 5ms

impl Connected {
    /// Send data from a MultiRead (user buffer).
    ///
    /// Zero-copy path:
    /// 1. Read from user buffer into Vec<u8> (ONE copy)
    /// 2. Create DataPacket with the Vec
    /// 3. Send via FrameVisor (zero-copy RRef transfer)
    pub fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        _flags: SendRecvFlags,
        pending_packet: &mut Option<RRef<DataPacket>>,
    ) -> Result<usize> {
        let _trace = trace::TraceGuard::new(&trace::HOST_TRY_SEND);

        self.check_send_allowed()?;

        if let Some(packet) = pending_packet.take() {
            if let Err(error) = self.check_send_allowed() {
                *pending_packet = Some(packet);
                return Err(error);
            }

            let mut tx = self.tx_state.disable_irq().lock();
            let pending_len = packet.data.len();
            let available_credit = self.available_credit(tx.tx_cnt) as usize;

            if available_credit < pending_len {
                *pending_packet = Some(packet);
                tx.tx_blocked_on_queue = false;

                let now_tsc = ostd::arch::read_tsc();
                if Self::should_send_credit_request(&tx, now_tsc) {
                    if self.send_credit_request() {
                        tx.credit_request_pending = true;
                        tx.last_credit_request_tsc = now_tsc;
                        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
                    } else {
                        tx.credit_request_pending = false;
                    }
                }

                drop(tx);
                return_errno_with_message!(Errno::EAGAIN, "no credit available");
            }

            let was_blocked = tx.tx_blocked_on_queue;
            tx.tx_cnt = tx.tx_cnt.saturating_add(pending_len as u64);
            tx.tx_blocked_on_queue = false;
            drop(tx);

            let vcpu_id = self.select_vcpu();
            if let Err(packet) = backend::send_data(vcpu_id, packet) {
                let mut tx = self.tx_state.disable_irq().lock();
                tx.tx_cnt = tx.tx_cnt.saturating_sub(pending_len as u64);
                if !was_blocked {
                    tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
                }
                tx.tx_blocked_on_queue = true;

                *pending_packet = Some(packet);
                drop(tx);
                return_errno_with_message!(Errno::EAGAIN, "guest queue full, retry later");
            }

            if was_blocked {
                let mut tx = self.tx_state.disable_irq().lock();
                tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
            }

            return Ok(pending_len);
        }

        let buf_len = reader.sum_lens();
        if buf_len == 0 {
            return Ok(0);
        }

        let to_send = {
            let mut tx = self.tx_state.disable_irq().lock();

            let available_credit = self.available_credit(tx.tx_cnt) as usize;
            if available_credit == 0 {
                tx.tx_blocked_on_queue = false;

                let now_tsc = ostd::arch::read_tsc();
                if Self::should_send_credit_request(&tx, now_tsc) {
                    if self.send_credit_request() {
                        tx.credit_request_pending = true;
                        tx.last_credit_request_tsc = now_tsc;
                        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
                    } else {
                        tx.credit_request_pending = false;
                    }
                }

                drop(tx);
                return_errno_with_message!(Errno::EAGAIN, "no credit available");
            }

            let to_send = buf_len.min(available_credit).min(MAX_PKT_BUF_SIZE as usize);
            tx.tx_cnt = tx.tx_cnt.saturating_add(to_send as u64);
            to_send
        };

        let mut data = Vec::with_capacity(to_send);
        data.resize(to_send, 0u8);

        let mut vm_writer = VmWriter::from(data.as_mut_slice());
        let bytes_read = match reader.read(&mut vm_writer) {
            Ok(n) => n,
            Err(e) => {
                let mut tx = self.tx_state.disable_irq().lock();
                tx.tx_cnt = tx.tx_cnt.saturating_sub(to_send as u64);
                return Err(e.into());
            }
        };

        if bytes_read < to_send {
            let mut tx = self.tx_state.disable_irq().lock();
            tx.tx_cnt = tx.tx_cnt.saturating_sub((to_send - bytes_read) as u64);
        }

        data.truncate(bytes_read);

        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);

        let packet = create_data_packet_with_credit(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
            data,
            buf_alloc,
            fwd_cnt as u32,
        );

        let vcpu_id = self.select_vcpu();
        if let Err(packet) = backend::send_data(vcpu_id, packet) {
            let mut tx = self.tx_state.disable_irq().lock();
            tx.tx_cnt = tx.tx_cnt.saturating_sub(bytes_read as u64);
            if !tx.tx_blocked_on_queue {
                tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
            }
            tx.tx_blocked_on_queue = true;

            *pending_packet = Some(packet);

            drop(tx);
            return_errno_with_message!(Errno::EAGAIN, "guest queue full, retry later");
        }

        let mut tx = self.tx_state.disable_irq().lock();
        tx.tx_blocked_on_queue = false;
        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);

        Ok(bytes_read)
    }

    fn check_send_allowed(&self) -> Result<()> {
        if self.connection_reset.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ECONNRESET, "connection reset");
        }

        if self.local_write_shutdown.load(Ordering::Acquire)
            || self.peer_recv_shutdown.load(Ordering::Acquire)
        {
            return_errno_with_message!(Errno::EPIPE, "connection closed for writing");
        }

        Ok(())
    }

    /// Handles backend Host->Guest queue drain notification.
    pub fn on_tx_queue_drained(&self, _queue_reserved_len_before_pop: usize) {
        let mut tx = self.tx_state.disable_irq().lock();
        if tx.tx_blocked_on_queue {
            tx.tx_blocked_on_queue = false;
            tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
            drop(tx);

            self.pollee.notify(IoEvents::OUT);
        }
    }

    /// Handles credit update from peer.
    pub fn on_credit_update(&self, buf_alloc: u32, fwd_cnt: u32) {
        let _trace = trace::TraceGuard::new(&trace::HOST_ON_CREDIT_UPDATE);

        let prev_peer_buf_alloc = self.peer_credit.peer_buf_alloc.load(Ordering::Acquire);
        let prev_peer_fwd_cnt = self.peer_credit.peer_fwd_cnt.load(Ordering::Acquire);

        let mut tx = self.tx_state.disable_irq().lock();
        let prev_available_credit =
            Self::calc_available_credit(tx.tx_cnt, prev_peer_buf_alloc, prev_peer_fwd_cnt);

        self.peer_credit
            .peer_buf_alloc
            .store(buf_alloc, Ordering::Release);
        self.update_peer_fwd_cnt(fwd_cnt, tx.tx_cnt);

        let available_credit = self.available_credit(tx.tx_cnt);
        let credit_advanced = available_credit > prev_available_credit;

        if credit_advanced {
            tx.credit_request_pending = false;
            tx.last_credit_request_tsc = 0;
        }

        let unblocked_by_credit = tx.tx_blocked_on_queue && credit_advanced;
        if unblocked_by_credit {
            tx.tx_blocked_on_queue = false;
        }
        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);

        let can_send_now = available_credit > 0 && !tx.tx_blocked_on_queue;
        drop(tx);

        if can_send_now {
            self.pollee.notify(IoEvents::OUT);
        }
    }

    #[inline]
    fn should_send_credit_request(tx: &TxState, now_tsc: u64) -> bool {
        if !tx.credit_request_pending {
            return true;
        }

        let retry_cycles = Self::credit_request_retry_cycles();
        if retry_cycles == 0 {
            return true;
        }

        now_tsc.wrapping_sub(tx.last_credit_request_tsc) >= retry_cycles
    }

    #[inline]
    fn credit_request_retry_cycles() -> u64 {
        let freq = ostd::arch::tsc_freq();
        if freq == 0 {
            return 0;
        }

        (((freq as u128) * (CREDIT_REQUEST_RETRY_NS as u128)) / 1_000_000_000u128).max(1) as u64
    }

    /// Sends credit request to peer to get their credit info.
    fn send_credit_request(&self) -> bool {
        let _trace = trace::TraceGuard::new(&trace::HOST_SEND_CREDIT_REQUEST);
        let mut packet = create_credit_request(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
        );
        packet.header.buf_alloc = self.buf_alloc.load(Ordering::Acquire);
        packet.header.fwd_cnt = self.fwd_cnt.load(Ordering::Acquire) as u32;
        let vcpu_id = self.select_vcpu();
        backend::send_control(vcpu_id, packet).is_ok()
    }
}
