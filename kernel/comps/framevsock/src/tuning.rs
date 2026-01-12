// SPDX-License-Identifier: MPL-2.0

//! FrameVsock runtime tuning knobs (IRQ coalescing).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Default interrupt batch threshold.
/// For high-throughput scenarios with small packets (2KB), we need
/// a balance between batching efficiency and latency.
/// 16 packets provides good balance for 2KB packets.
pub const DEFAULT_IRQ_BATCH_THRESHOLD: u32 = 16;

/// Default interrupt time threshold in microseconds.
/// 20μs provides low latency while still allowing some batching.
/// Too low (e.g., 10μs) causes excessive IRQ overhead.
/// Too high (e.g., 100μs) causes Guest to wait too long.
pub const DEFAULT_IRQ_TIME_THRESHOLD_US: u64 = 20;

/// IRQ coalescing configuration (shared across VMs).
pub struct IrqCoalesceConfig {
    batch_threshold: AtomicU32,
    time_threshold_us: AtomicU64,
    config_epoch: AtomicU64,
}

impl IrqCoalesceConfig {
    pub const fn new(batch_threshold: u32, time_threshold_us: u64) -> Self {
        Self {
            batch_threshold: AtomicU32::new(batch_threshold),
            time_threshold_us: AtomicU64::new(time_threshold_us),
            config_epoch: AtomicU64::new(1),
        }
    }

    #[inline]
    pub fn batch_threshold(&self) -> u32 {
        self.batch_threshold.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn time_threshold_us(&self) -> u64 {
        self.time_threshold_us.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn epoch(&self) -> u64 {
        self.config_epoch.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn set_batch_threshold(&self, batch_threshold: u32) {
        let batch_threshold = batch_threshold.max(1);
        let old = self
            .batch_threshold
            .swap(batch_threshold, Ordering::Relaxed);
        if old != batch_threshold {
            self.config_epoch.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn set_time_threshold_us(&self, time_threshold_us: u64) {
        let old = self
            .time_threshold_us
            .swap(time_threshold_us, Ordering::Relaxed);
        if old != time_threshold_us {
            self.config_epoch.fetch_add(1, Ordering::Relaxed);
        }
    }
}

static IRQ_COALESCE_CONFIG: IrqCoalesceConfig =
    IrqCoalesceConfig::new(DEFAULT_IRQ_BATCH_THRESHOLD, DEFAULT_IRQ_TIME_THRESHOLD_US);

#[inline]
pub fn irq_config() -> &'static IrqCoalesceConfig {
    &IRQ_COALESCE_CONFIG
}
