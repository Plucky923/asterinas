// SPDX-License-Identifier: MPL-2.0

//! Procfs view for FrameVsock runtime statistics and tuning knobs.

use alloc::{string::String, vec::Vec};
use core::fmt::{Arguments, Write};

use aster_framevisor::{irq, vsock};
use aster_framevsock::{
    ring::{RingDebugSnapshot, get_debug_stats},
    trace::{cycles_to_ns, sample_rate, set_sample_rate, snapshot_all, tsc_freq_hz},
    tuning,
};

use crate::{
    fs::{
        procfs::template::{FileOps, ProcFileBuilder},
        utils::{Inode, mkmod},
    },
    prelude::*,
};

/// Represents the inode at `/proc/sys/kernel/framevsock`.
pub struct FrameVsockFileOps;

impl FrameVsockFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFileBuilder::new(Self, mkmod!(a+r))
            .parent(parent)
            .build()
            .unwrap()
    }
}

fn write_line(output: &mut String, args: Arguments<'_>) {
    let _ = output.write_fmt(args);
    let _ = output.write_char('\n');
}

fn format_ring_stats(output: &mut String, name: &str, stats: &RingDebugSnapshot) {
    write_line(output, format_args!("\n{} Ring Buffer Statistics:", name));
    write_line(
        output,
        format_args!("  push_count:        {:>12}", stats.push_count),
    );
    write_line(
        output,
        format_args!("  pop_count:         {:>12}", stats.pop_count),
    );
    write_line(
        output,
        format_args!("  push_cas_retries:  {:>12}", stats.push_cas_retries),
    );
    write_line(
        output,
        format_args!("  pop_cas_retries:   {:>12}", stats.pop_cas_retries),
    );
    write_line(
        output,
        format_args!("  pop_wait_producer: {:>12}", stats.pop_wait_producer),
    );
    write_line(
        output,
        format_args!(
            "  pop_slot_empty:    {:>12} (BUG if non-zero!)",
            stats.pop_slot_empty
        ),
    );
    write_line(
        output,
        format_args!("  push_full:         {:>12}", stats.push_full),
    );
    write_line(
        output,
        format_args!("  pop_empty:         {:>12}", stats.pop_empty),
    );

    // Calculate loss ratio
    if stats.push_count > 0 {
        let loss = stats.push_count.saturating_sub(stats.pop_count);
        // Keep this path integer-only to avoid floating-point formatting in kernel context.
        let loss_bps = ((loss as u128) * 10_000u128) / (stats.push_count as u128);
        let loss_pct_int = (loss_bps / 100) as u64;
        let loss_pct_frac = (loss_bps % 100) as u64;
        write_line(
            output,
            format_args!(
                "  packet_loss:       {:>12} ({}.{:02}%)",
                loss, loss_pct_int, loss_pct_frac
            ),
        );
    }
}

impl FileOps for FrameVsockFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        // Generate trace output
        let mut output = String::new();
        let freq_hz = tsc_freq_hz();

        write_line(&mut output, format_args!("FrameVsock Debug Statistics"));
        write_line(&mut output, format_args!("==========================="));
        write_line(&mut output, format_args!("TSC Frequency: {} Hz", freq_hz));
        write_line(
            &mut output,
            format_args!(
                "IRQ Coalescing: batch={} time_us={}",
                tuning::irq_config().batch_threshold(),
                tuning::irq_config().time_threshold_us()
            ),
        );
        write_line(
            &mut output,
            format_args!(
                "Guest RX IRQ: work_budget_pkts={} cross_sweep={} urgent_first_packet={} credit_headroom_bytes={}",
                vsock::irq_work_budget_pkts(),
                u8::from(vsock::irq_cross_sweep_enabled()),
                u8::from(vsock::irq_urgent_first_packet()),
                vsock::rx_credit_headroom_bytes()
            ),
        );
        let backend_stats = vsock::backend_tx_debug_stats();
        write_line(
            &mut output,
            format_args!(
                "Backend TX(data): attempts={} success={} err_bad_cid={} err_vm_inactive={} err_vm_missing={} err_queue_missing={} err_queue_full={} irq_full={} irq_policy={}",
                backend_stats.data_send_attempts,
                backend_stats.data_send_success,
                backend_stats.data_send_err_bad_cid,
                backend_stats.data_send_err_vm_inactive,
                backend_stats.data_send_err_vm_missing,
                backend_stats.data_send_err_queue_missing,
                backend_stats.data_send_err_queue_full,
                backend_stats.data_irq_forced_on_full,
                backend_stats.data_irq_policy_inject
            ),
        );
        write_line(
            &mut output,
            format_args!(
                "Backend TX(ctrl): attempts={} success={} err_bad_cid={} err_vm_inactive={} err_vm_missing={} err_queue_missing={} err_queue_full={} irq_full={} irq_policy={} queue_drain_notifies={}",
                backend_stats.control_send_attempts,
                backend_stats.control_send_success,
                backend_stats.control_send_err_bad_cid,
                backend_stats.control_send_err_vm_inactive,
                backend_stats.control_send_err_vm_missing,
                backend_stats.control_send_err_queue_missing,
                backend_stats.control_send_err_queue_full,
                backend_stats.control_irq_forced_on_full,
                backend_stats.control_irq_policy_inject,
                backend_stats.host_queue_drain_notifies
            ),
        );
        let irq_stats = irq::vsock_irq_debug_stats();
        write_line(
            &mut output,
            format_args!(
                "Backend IRQ(vsock): attempts={} dedup_skips={} enqueue_ok={} fail_no_vm={} fail_no_ctx={} callbacks={} cb_vcpu_unknown={}",
                irq_stats.inject_attempts,
                irq_stats.dedup_skips,
                irq_stats.enqueue_success,
                irq_stats.enqueue_fail_no_vm,
                irq_stats.enqueue_fail_no_ctx,
                irq_stats.callback_runs,
                irq_stats.callback_vcpu_unknown
            ),
        );
        write_line(
            &mut output,
            format_args!("Trace Sample Rate: {}", sample_rate()),
        );

        // Ring buffer debug stats
        let (data_stats, control_stats) = get_debug_stats();
        format_ring_stats(&mut output, "Data", &data_stats);
        format_ring_stats(&mut output, "Control", &control_stats);

        // Per-vCPU queue stats (FrameVisor)
        let vcpu_stats = vsock::get_vcpu_queue_stats();
        if !vcpu_stats.is_empty() {
            write_line(&mut output, format_args!("\nPer-vCPU Queue Stats:"));
            write_line(&mut output, format_args!("----------------------"));
            for (vcpu_id, stats) in vcpu_stats {
                write_line(
                    &mut output,
                    format_args!(
                        "  vCPU {}: data_push={} data_pop={} control_push={} control_pop={}",
                        vcpu_id,
                        stats.data_push_count,
                        stats.data_pop_count,
                        stats.control_push_count,
                        stats.control_pop_count
                    ),
                );
            }
        }

        // Trace timing stats
        write_line(&mut output, format_args!("\nTrace Timing Statistics:"));
        write_line(&mut output, format_args!("------------------------"));
        write_line(
            &mut output,
            format_args!(
                "{:<45} {:>12} {:>12} {:>12} {:>12} {:>12}",
                "Trace Point", "Count", "Avg(ns)", "Min(ns)", "Max(ns)", "Total(ns)"
            ),
        );
        write_line(&mut output, format_args!("{}", "-".repeat(105)));

        for snap in snapshot_all() {
            let avg_ns = cycles_to_ns(snap.avg_cycles, freq_hz).unwrap_or(0);
            let min_ns = cycles_to_ns(snap.min_cycles, freq_hz).unwrap_or(0);
            let max_ns = cycles_to_ns(snap.max_cycles, freq_hz).unwrap_or(0);
            let total_ns = cycles_to_ns(snap.total_cycles, freq_hz).unwrap_or(0);

            write_line(
                &mut output,
                format_args!(
                    "{:<45} {:>12} {:>12} {:>12} {:>12} {:>12}",
                    snap.name, snap.count, avg_ns, min_ns, max_ns, total_ns
                ),
            );
        }

        let bytes = output.as_bytes();
        if offset >= bytes.len() {
            return Ok(0);
        }

        let remaining = &bytes[offset..];
        let to_write = remaining.len().min(writer.avail());
        writer.write_fallible(&mut ostd::mm::VmReader::from(&remaining[..to_write]))?;
        Ok(to_write)
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let len = reader.remain();
        if len == 0 {
            return Ok(0);
        }

        let max_len = 256usize;
        let read_len = len.min(max_len);
        let mut buf = Vec::with_capacity(read_len);
        buf.resize(read_len, 0u8);
        for i in 0..read_len {
            buf[i] = reader.read_val::<u8>()?;
        }
        if len > read_len {
            reader.skip(len - read_len);
        }

        let input = core::str::from_utf8(&buf)
            .map_err(|_| Error::new(Errno::EINVAL))?
            .trim();
        if input.is_empty() {
            return Ok(len);
        }

        let mut updated = false;
        for token in input.split_whitespace() {
            if let Some(value) = token.strip_prefix("batch=") {
                let v: u32 = value.parse().map_err(|_| Error::new(Errno::EINVAL))?;
                tuning::irq_config().set_batch_threshold(v);
                updated = true;
                continue;
            }
            if let Some(value) = token.strip_prefix("time_us=") {
                let v: u64 = value.parse().map_err(|_| Error::new(Errno::EINVAL))?;
                tuning::irq_config().set_time_threshold_us(v);
                updated = true;
                continue;
            }
            if let Some(value) = token.strip_prefix("trace_sample=") {
                let v: u32 = value.parse().map_err(|_| Error::new(Errno::EINVAL))?;
                set_sample_rate(v);
                updated = true;
                continue;
            }
            if let Some(value) = token.strip_prefix("irq_work_budget_pkts=") {
                let v: u32 = value.parse().map_err(|_| Error::new(Errno::EINVAL))?;
                vsock::set_irq_work_budget_pkts(v.max(1));
                updated = true;
                continue;
            }
            if let Some(value) = token.strip_prefix("irq_cross_sweep=") {
                let enabled = match value {
                    "1" | "true" => true,
                    "0" | "false" => false,
                    _ => return Err(Error::new(Errno::EINVAL)),
                };
                vsock::set_irq_cross_sweep_enabled(enabled);
                updated = true;
                continue;
            }
            if let Some(value) = token.strip_prefix("irq_urgent_first_packet=") {
                let enabled = match value {
                    "1" | "true" => true,
                    "0" | "false" => false,
                    _ => return Err(Error::new(Errno::EINVAL)),
                };
                vsock::set_irq_urgent_first_packet(enabled);
                updated = true;
                continue;
            }
            if let Some(value) = token.strip_prefix("rx_credit_headroom_bytes=") {
                let bytes: u32 = value.parse().map_err(|_| Error::new(Errno::EINVAL))?;
                vsock::set_rx_credit_headroom_bytes(bytes);
                updated = true;
                continue;
            }
            if let Some(value) = token.strip_prefix("stats_reset=") {
                let enabled = match value {
                    "1" | "true" => true,
                    "0" | "false" => false,
                    _ => return Err(Error::new(Errno::EINVAL)),
                };
                if enabled {
                    vsock::reset_backend_tx_debug_stats();
                    irq::reset_vsock_irq_debug_stats();
                }
                updated = true;
                continue;
            }
            return Err(Error::with_message(Errno::EINVAL, "unknown key"));
        }

        if !updated {
            return Err(Error::with_message(Errno::EINVAL, "no valid key"));
        }

        Ok(len)
    }
}
