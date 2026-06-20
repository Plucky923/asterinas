// SPDX-License-Identifier: MPL-2.0

//! Kernel-local resource limits.
//!
//! This is the trimmed counterpart of `kernel/src/process/rlimit.rs`.

use core::{
    array,
    sync::atomic::{AtomicU64, Ordering},
};

use ostd::sync::SpinLock;

use crate::{
    error::{Errno, Error, Result},
    return_errno_with_message,
    vm::USER_STACK_SIZE,
};

const RLIM_INFINITY: u64 = u64::MAX;
const INIT_RLIMIT_NPROC: u64 = 0;
const INIT_RLIMIT_NICE: u64 = 0;
const INIT_RLIMIT_SIGPENDING: u64 = 0;
const INIT_RLIMIT_RTPRIO: u64 = 0;
pub const INIT_RLIMIT_NOFILE_CUR: u64 = 1024;
const INIT_RLIMIT_NOFILE_MAX: u64 = 4096;
const INIT_RLIMIT_MEMLOCK: u64 = 8 * 1024 * 1024;
const INIT_RLIMIT_MSGQUEUE: u64 = 819200;
pub const SYSCTL_NR_OPEN: u64 = 1024 * 1024;
const RLIMIT_COUNT: usize = 16;

/// Per-process resource limits.
#[derive(Clone)]
pub struct ResourceLimits {
    rlimits: [RLimit64; RLIMIT_COUNT],
}

impl ResourceLimits {
    /// Returns a reference to a specific resource limit.
    pub fn get_rlimit(&self, resource: ResourceType) -> &RLimit64 {
        &self.rlimits[resource as usize]
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        let mut rlimits: [RLimit64; RLIMIT_COUNT] = array::from_fn(|_| RLimit64::default());

        rlimits[ResourceType::Cpu as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::FileSize as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::Data as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::Stack as usize] =
            RLimit64::new(USER_STACK_SIZE as u64, RLIM_INFINITY);
        rlimits[ResourceType::Core as usize] = RLimit64::new(0, RLIM_INFINITY);
        rlimits[ResourceType::Rss as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::Process as usize] =
            RLimit64::new(INIT_RLIMIT_NPROC, INIT_RLIMIT_NPROC);
        rlimits[ResourceType::NoFile as usize] =
            RLimit64::new(INIT_RLIMIT_NOFILE_CUR, INIT_RLIMIT_NOFILE_MAX);
        rlimits[ResourceType::MemLock as usize] =
            RLimit64::new(INIT_RLIMIT_MEMLOCK, INIT_RLIMIT_MEMLOCK);
        rlimits[ResourceType::AddressSpace as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::Locks as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);
        rlimits[ResourceType::SigPending as usize] =
            RLimit64::new(INIT_RLIMIT_SIGPENDING, INIT_RLIMIT_SIGPENDING);
        rlimits[ResourceType::MessageQueue as usize] =
            RLimit64::new(INIT_RLIMIT_MSGQUEUE, INIT_RLIMIT_MSGQUEUE);
        rlimits[ResourceType::Nice as usize] = RLimit64::new(INIT_RLIMIT_NICE, INIT_RLIMIT_NICE);
        rlimits[ResourceType::RtPrio as usize] =
            RLimit64::new(INIT_RLIMIT_RTPRIO, INIT_RLIMIT_RTPRIO);
        rlimits[ResourceType::RtTime as usize] = RLimit64::new(RLIM_INFINITY, RLIM_INFINITY);

        Self { rlimits }
    }
}

/// Linux resource-limit identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ResourceType {
    Cpu = 0,
    FileSize = 1,
    Data = 2,
    Stack = 3,
    Core = 4,
    Rss = 5,
    Process = 6,
    NoFile = 7,
    MemLock = 8,
    AddressSpace = 9,
    Locks = 10,
    SigPending = 11,
    MessageQueue = 12,
    Nice = 13,
    RtPrio = 14,
    RtTime = 15,
}

impl TryFrom<u32> for ResourceType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        let resource = match value {
            0 => Self::Cpu,
            1 => Self::FileSize,
            2 => Self::Data,
            3 => Self::Stack,
            4 => Self::Core,
            5 => Self::Rss,
            6 => Self::Process,
            7 => Self::NoFile,
            8 => Self::MemLock,
            9 => Self::AddressSpace,
            10 => Self::Locks,
            11 => Self::SigPending,
            12 => Self::MessageQueue,
            13 => Self::Nice,
            14 => Self::RtPrio,
            15 => Self::RtTime,
            _ => return Err(Error::new(Errno::EINVAL)),
        };
        Ok(resource)
    }
}

/// User ABI shape for `struct rlimit64`.
#[derive(Clone, Copy, Debug)]
pub struct RawRLimit64 {
    pub cur: u64,
    pub max: u64,
}

#[derive(Debug)]
pub struct RLimit64 {
    cur: AtomicU64,
    max: AtomicU64,
    lock: SpinLock<()>,
}

impl RLimit64 {
    const fn new(cur: u64, max: u64) -> Self {
        assert!(cur <= max, "the current rlimit exceeds the max rlimit");
        Self {
            cur: AtomicU64::new(cur),
            max: AtomicU64::new(max),
            lock: SpinLock::new(()),
        }
    }

    /// Returns the current rlimit without synchronization.
    pub fn get_cur(&self) -> u64 {
        self.cur.load(Ordering::Relaxed)
    }

    fn get_max(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    /// Returns the synchronized user ABI value.
    pub fn get_raw_rlimit(&self) -> RawRLimit64 {
        let _guard = self.lock.lock();
        RawRLimit64 {
            cur: self.cur.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
        }
    }

    /// Sets the limit and returns the previous value.
    pub fn set_raw_rlimit(
        &self,
        new: RawRLimit64,
        can_raise_hard_limit: bool,
    ) -> Result<RawRLimit64> {
        if new.cur > new.max {
            return_errno_with_message!(Errno::EINVAL, "the current rlimit exceeds the max rlimit");
        }

        let _guard = self.lock.lock();
        if new.max > self.get_max() && !can_raise_hard_limit {
            return_errno_with_message!(
                Errno::EPERM,
                "raising hard resource limits requires CAP_SYS_RESOURCE"
            );
        }

        let old = RawRLimit64 {
            cur: self.cur.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
        };
        self.cur.store(new.cur, Ordering::Relaxed);
        self.max.store(new.max, Ordering::Relaxed);
        Ok(old)
    }
}

impl Default for RLimit64 {
    fn default() -> Self {
        Self {
            cur: AtomicU64::new(RLIM_INFINITY),
            max: AtomicU64::new(RLIM_INFINITY),
            lock: SpinLock::new(()),
        }
    }
}

impl Clone for RLimit64 {
    fn clone(&self) -> Self {
        let raw = self.get_raw_rlimit();
        Self {
            cur: AtomicU64::new(raw.cur),
            max: AtomicU64::new(raw.max),
            lock: SpinLock::new(()),
        }
    }
}
