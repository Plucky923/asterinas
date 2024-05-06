// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicU64, Ordering};

use crate::prelude::*;

pub type CapMask = u64;

// Capabilities defined by Linux. Taken from the kernel's include/uapi/linux/capability.h.
// See capabilities(7) or that file for more detailed capability descriptions.
#[repr(u8)]
pub enum CapabilityPrivilegeList {
    Chown = 0,
    DacOverride = 1,
    DacReadSearch = 2,
    Fowner = 3,
    Fsetid = 4,
    Kill = 5,
    Setgid = 6,
    Setuid = 7,
    Setpcap = 8,
    LinuxImmutable = 9,
    NetBindService = 10,
    NetBroadcast = 11,
    NetAdmin = 12,
    NetRaw = 13,
    IpcLock = 14,
    IpcOwner = 15,
    SysModule = 16,
    SysRawio = 17,
    SysChroot = 18,
    SysPtrace = 19,
    SysPacct = 20,
    SysAdmin = 21,
    SysBoot = 22,
    SysNice = 23,
    SysResource = 24,
    SysTime = 25,
    SysTtyConfig = 26,
    Mknod = 27,
    Lease = 28,
    AuditWrite = 29,
    AuditControl = 30,
    Setfcap = 31,
    MacOverride = 32,
    MacAdmin = 33,
    Syslog = 34,
    WakeAlarm = 35,
    BlockSuspend = 36,
    AuditRead = 37,
    Perfmon = 38,
    Bpf = 39,
    CheckpointRestore = 40,
    // some variants might be omitted
}

const CAP_LAST_CAP: u64 = 40; // Number of the last capability
pub const CAP_VALID_MASK: u64 = (1u64 << (CAP_LAST_CAP + 1)) - 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct Capability(pub u64);

impl Capability {
    pub const fn new(cap: u64) -> Self {
        Self(cap)
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const fn new_root() -> Self {
        // Give CAP_SYS_ADMIN for the root.
        Self(1u64 << CapabilityPrivilegeList::SysAdmin as u64)
    }

    // Provided for prctl(PR_SET_KEEPCAPS), prctl(PR_CAP_AMBIENT_RAISE)
    // Sets (raises) a particular capability bit in a capability set, identified by the `flag` index.
    pub fn raise(cap_set: &mut CapMask, flag: u64) {
        *cap_set |= 1 << flag;
    }

    // Provided for prctl(PR_CAPBSET_DROP), prctl(PR_CAP_AMBIENT_LOWER)
    // Clears (lowers) a particular capability bit in a capability set, identified by the `flag` index.
    pub fn lower(cap_set: &mut CapMask, flag: u64) {
        *cap_set &= !(1 << flag);
    }

    // Provided for prctl(PR_CAP_AMBIENT_IS_SET)
    // Checks for whether a particular capability bit in a capability set is set (raised) or not.
    pub fn is_raised(cap_set: &CapMask, flag: u64) -> bool {
        (*cap_set & (1 << flag)) != 0
    }

    // Provided for prctl(PR_CAP_AMBIENT_CLEAR_ALL)
    // Clears (sets to 0) all capability bits of a particular capability set identified by `cap_set`.
    pub fn clear(cap_set: &mut CapMask) {
        *cap_set = 0;
    }
}

#[derive(Debug)]
pub(super) struct AtomicCapability(AtomicU64);

impl AtomicCapability {
    pub const fn new(cap: Capability) -> Self {
        Self(AtomicU64::new(cap.as_u64()))
    }

    pub fn set(&self, cap: Capability) {
        self.0.store(cap.as_u64(), Ordering::Relaxed)
    }

    pub fn get(&self) -> Capability {
        Capability(self.0.load(Ordering::Relaxed))
    }
}

impl Clone for AtomicCapability {
    fn clone(&self) -> Self {
        Self(AtomicU64::new(self.0.load(Ordering::Relaxed)))
    }
}

// Structure that represents the different capability sets used by the Linux capability model.
pub struct CapabilitySets {
    // Capabilities that can be inherited by child processes.
    pub inheritablecap: Capability,
    // Capabilities that the process is permitted to use.
    pub permittedcap: Capability,
    // Capabilities that the process can actually use.
    pub effectivecap: Capability,
    // The capability bounding set that limits the capabilities for new processes.
    pub bset: CapMask,
    // The ambient capability set which is automatically inherited by execve-ed processes.
    pub ambient: CapMask,
}
