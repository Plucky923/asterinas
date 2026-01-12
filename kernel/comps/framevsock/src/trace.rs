// SPDX-License-Identifier: MPL-2.0

//! FrameVsock timing trace points (safe, always-on).
//!
//! This module provides lightweight, no-unsafe timing statistics for
//! hot paths across the FrameVsock stack. Statistics are aggregated
//! globally and can be exported via procfs.

#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ostd::arch::{read_tsc, tsc_freq};

#[derive(Debug)]
pub struct TracePoint {
    name: &'static str,
    count: AtomicU64,
    total_cycles: AtomicU64,
    min_cycles: AtomicU64,
    max_cycles: AtomicU64,
}

impl TracePoint {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            count: AtomicU64::new(0),
            total_cycles: AtomicU64::new(0),
            min_cycles: AtomicU64::new(u64::MAX),
            max_cycles: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_elapsed(&self, start_cycles: u64) {
        let end = now_cycles();
        let elapsed = end.wrapping_sub(start_cycles);
        self.record_cycles(elapsed);
    }

    #[inline]
    pub fn record_cycles(&self, cycles: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_cycles.fetch_add(cycles, Ordering::Relaxed);
        update_min(&self.min_cycles, cycles);
        update_max(&self.max_cycles, cycles);
    }

    #[inline]
    pub fn snapshot(&self) -> TraceSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let total = self.total_cycles.load(Ordering::Relaxed);
        let mut min = self.min_cycles.load(Ordering::Relaxed);
        let max = self.max_cycles.load(Ordering::Relaxed);

        if count == 0 || min == u64::MAX {
            min = 0;
        }
        let avg = if count == 0 { 0 } else { total / count };

        TraceSnapshot {
            name: self.name,
            count,
            total_cycles: total,
            min_cycles: min,
            max_cycles: max,
            avg_cycles: avg,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    pub name: &'static str,
    pub count: u64,
    pub total_cycles: u64,
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub avg_cycles: u64,
}

pub struct TraceGuard {
    start_cycles: u64,
    point: &'static TracePoint,
    enabled: bool,
}

impl TraceGuard {
    #[inline]
    pub fn new(point: &'static TracePoint) -> Self {
        let rate = TRACE_SAMPLE_RATE.load(Ordering::Relaxed);
        if rate == 0 {
            return Self {
                start_cycles: 0,
                point,
                enabled: false,
            };
        }

        let seq = TRACE_SAMPLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let enabled = rate == 1 || (seq % rate as u64) == 0;
        let start_cycles = if enabled { now_cycles() } else { 0 };

        Self {
            start_cycles,
            point,
            enabled,
        }
    }
}

impl Drop for TraceGuard {
    #[inline]
    fn drop(&mut self) {
        if self.enabled {
            self.point.record_elapsed(self.start_cycles);
        }
    }
}

static TRACE_SAMPLE_RATE: AtomicU32 = AtomicU32::new(1);
static TRACE_SAMPLE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Set trace sampling rate.
/// 0 = disabled, 1 = sample all, N = 1/N sampling.
pub fn set_sample_rate(rate: u32) {
    TRACE_SAMPLE_RATE.store(rate, Ordering::Relaxed);
}

/// Get current trace sampling rate.
pub fn sample_rate() -> u32 {
    TRACE_SAMPLE_RATE.load(Ordering::Relaxed)
}

#[inline]
pub fn now_cycles() -> u64 {
    read_tsc()
}

#[inline]
pub fn tsc_freq_hz() -> u64 {
    tsc_freq()
}

#[inline]
pub fn cycles_to_ns(cycles: u64, freq_hz: u64) -> Option<u64> {
    if freq_hz == 0 {
        None
    } else {
        Some((cycles as u128 * 1_000_000_000u128 / freq_hz as u128) as u64)
    }
}

pub fn snapshot_all() -> Vec<TraceSnapshot> {
    TRACE_POINTS.iter().map(|tp| tp.snapshot()).collect()
}

#[inline]
fn update_min(cell: &AtomicU64, value: u64) {
    let mut current = cell.load(Ordering::Relaxed);
    while value < current {
        match cell.compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(updated) => current = updated,
        }
    }
}

#[inline]
fn update_max(cell: &AtomicU64, value: u64) {
    let mut current = cell.load(Ordering::Relaxed);
    while value > current {
        match cell.compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(updated) => current = updated,
        }
    }
}

// ===== Trace points =====

// Guest (FrameVM) syscall and socket layer
pub static GUEST_SYS_SENDTO: TracePoint = TracePoint::new("guest.sys_sendto");
pub static GUEST_SYS_RECVFROM: TracePoint = TracePoint::new("guest.sys_recvfrom");
pub static GUEST_SOCKET_SEND_PACKET: TracePoint = TracePoint::new("guest.socket.send_packet");
pub static GUEST_SOCKET_RECV_PACKET: TracePoint = TracePoint::new("guest.socket.recv_packet");
pub static GUEST_SOCKET_RECV_TO_USER: TracePoint = TracePoint::new("guest.socket.recv_to_user");
pub static GUEST_SOCKET_RECV_LOCK: TracePoint = TracePoint::new("guest.socket.recv_lock");
pub static GUEST_SOCKET_RECV_EXTRACT: TracePoint = TracePoint::new("guest.socket.recv_extract");
pub static GUEST_SOCKET_RECV_COPY: TracePoint = TracePoint::new("guest.socket.recv_copy");
pub static GUEST_SOCKET_ON_DATA: TracePoint = TracePoint::new("guest.socket.on_data_packet");
pub static GUEST_SOCKET_ON_CONTROL: TracePoint = TracePoint::new("guest.socket.on_control_packet");
pub static GUEST_VSOCK_IRQ: TracePoint = TracePoint::new("guest.vsock_irq_handler");
pub static GUEST_DISPATCH_DATA: TracePoint = TracePoint::new("guest.dispatch_data_packet");
pub static GUEST_DISPATCH_CONTROL: TracePoint = TracePoint::new("guest.dispatch_control_packet");
pub static GUEST_SUBMIT_DATA: TracePoint = TracePoint::new("guest.submit_data_packet");
pub static GUEST_SUBMIT_CONTROL: TracePoint = TracePoint::new("guest.submit_control_packet");

// FrameVisor backend
pub static FRAMEVISOR_SEND_TO_HOST_DATA: TracePoint =
    TracePoint::new("framevisor.send_to_host_data");
pub static FRAMEVISOR_SEND_TO_HOST_CONTROL: TracePoint =
    TracePoint::new("framevisor.send_to_host_control");
pub static FRAMEVISOR_SEND_TO_GUEST_DATA: TracePoint =
    TracePoint::new("framevisor.send_to_guest_data");
pub static FRAMEVISOR_SEND_TO_GUEST_CONTROL: TracePoint =
    TracePoint::new("framevisor.send_to_guest_control");

// FrameVisor vCPU queues
pub static FRAMEVISOR_QUEUE_PUSH_DATA: TracePoint = TracePoint::new("framevisor.queue.push_data");
pub static FRAMEVISOR_QUEUE_POP_DATA: TracePoint = TracePoint::new("framevisor.queue.pop_data");
pub static FRAMEVISOR_QUEUE_PUSH_CONTROL: TracePoint =
    TracePoint::new("framevisor.queue.push_control");
pub static FRAMEVISOR_QUEUE_POP_CONTROL: TracePoint =
    TracePoint::new("framevisor.queue.pop_control");
pub static FRAMEVISOR_QUEUE_SHOULD_INJECT_IRQ: TracePoint =
    TracePoint::new("framevisor.queue.should_inject_irq");

// Shared ring buffer
pub static RING_PUSH: TracePoint = TracePoint::new("ring.push");
pub static RING_POP: TracePoint = TracePoint::new("ring.pop");
pub static RING_POP_CAS: TracePoint = TracePoint::new("ring.pop.cas");
pub static RING_POP_LOCK: TracePoint = TracePoint::new("ring.pop.lock");
pub static RING_PUSH_BATCH: TracePoint = TracePoint::new("ring.push_batch");
pub static RING_POP_BATCH: TracePoint = TracePoint::new("ring.pop_batch");

// Host socket layer
pub static HOST_TRY_SEND: TracePoint = TracePoint::new("host.connected.try_send");
pub static HOST_TRY_SEND_LOCK: TracePoint = TracePoint::new("host.try_send.lock");
pub static HOST_TRY_SEND_ALLOC: TracePoint = TracePoint::new("host.try_send.alloc");
pub static HOST_TRY_SEND_READ: TracePoint = TracePoint::new("host.try_send.read_user");
pub static HOST_TRY_SEND_CREATE_PKT: TracePoint = TracePoint::new("host.try_send.create_pkt");
pub static HOST_TRY_SEND_DELIVER: TracePoint = TracePoint::new("host.try_send.deliver");
pub static HOST_TRY_RECV: TracePoint = TracePoint::new("host.connected.try_recv");
pub static HOST_ON_DATA: TracePoint = TracePoint::new("host.connected.on_data_packet");
pub static HOST_ON_CREDIT_UPDATE: TracePoint = TracePoint::new("host.connected.on_credit_update");
pub static HOST_SEND_CREDIT_UPDATE: TracePoint =
    TracePoint::new("host.connected.send_credit_update");
pub static HOST_SEND_CREDIT_REQUEST: TracePoint =
    TracePoint::new("host.connected.send_credit_request");
pub static HOST_SHUTDOWN: TracePoint = TracePoint::new("host.connected.shutdown");
pub static HOST_RESET: TracePoint = TracePoint::new("host.connected.reset");

pub static TRACE_POINTS: [&TracePoint; 43] = [
    &GUEST_SYS_SENDTO,
    &GUEST_SYS_RECVFROM,
    &GUEST_SOCKET_SEND_PACKET,
    &GUEST_SOCKET_RECV_PACKET,
    &GUEST_SOCKET_RECV_TO_USER,
    &GUEST_SOCKET_RECV_LOCK,
    &GUEST_SOCKET_RECV_EXTRACT,
    &GUEST_SOCKET_RECV_COPY,
    &GUEST_SOCKET_ON_DATA,
    &GUEST_SOCKET_ON_CONTROL,
    &GUEST_VSOCK_IRQ,
    &GUEST_DISPATCH_DATA,
    &GUEST_DISPATCH_CONTROL,
    &GUEST_SUBMIT_DATA,
    &GUEST_SUBMIT_CONTROL,
    &FRAMEVISOR_SEND_TO_HOST_DATA,
    &FRAMEVISOR_SEND_TO_HOST_CONTROL,
    &FRAMEVISOR_SEND_TO_GUEST_DATA,
    &FRAMEVISOR_SEND_TO_GUEST_CONTROL,
    &FRAMEVISOR_QUEUE_PUSH_DATA,
    &FRAMEVISOR_QUEUE_POP_DATA,
    &FRAMEVISOR_QUEUE_PUSH_CONTROL,
    &FRAMEVISOR_QUEUE_POP_CONTROL,
    &FRAMEVISOR_QUEUE_SHOULD_INJECT_IRQ,
    &RING_PUSH,
    &RING_POP,
    &RING_POP_CAS,
    &RING_POP_LOCK,
    &RING_PUSH_BATCH,
    &RING_POP_BATCH,
    &HOST_TRY_SEND,
    &HOST_TRY_SEND_LOCK,
    &HOST_TRY_SEND_ALLOC,
    &HOST_TRY_SEND_READ,
    &HOST_TRY_SEND_CREATE_PKT,
    &HOST_TRY_SEND_DELIVER,
    &HOST_TRY_RECV,
    &HOST_ON_DATA,
    &HOST_ON_CREDIT_UPDATE,
    &HOST_SEND_CREDIT_UPDATE,
    &HOST_SEND_CREDIT_REQUEST,
    &HOST_SHUTDOWN,
    &HOST_RESET,
];
