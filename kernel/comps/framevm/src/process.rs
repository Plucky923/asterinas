// SPDX-License-Identifier: MPL-2.0

//! Process group and session state for the kernel image.
//!
//! This module keeps the same object relationship as the kernel process model:
//! a process belongs to one process group, and each process group belongs to one
//! session. The implementation is trimmed to the syscall-visible state needed by
//! the current kernel image.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use ostd::sync::{Once, SpinLock as Mutex};

use crate::error::{Errno, Error, Result};

pub type Pid = u32;
pub type Pgid = u32;
pub type Sid = u32;

/// A Linux user ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uid(u32);

impl Uid {
    /// Creates the root user ID.
    pub const fn new_root() -> Self {
        Self(0)
    }

    /// Creates a user ID from a raw value.
    pub const fn new(uid: u32) -> Self {
        Self(uid)
    }

    /// Returns whether this is the root user ID.
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }
}

impl From<Uid> for u32 {
    fn from(value: Uid) -> Self {
        value.0
    }
}

/// A Linux group ID.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Gid(u32);

impl Gid {
    /// Creates the root group ID.
    pub const fn new_root() -> Self {
        Self(0)
    }

    /// Creates a group ID from a raw value.
    pub const fn new(gid: u32) -> Self {
        Self(gid)
    }
}

impl From<Gid> for u32 {
    fn from(value: Gid) -> Self {
        value.0
    }
}

const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SETPCAP: u32 = 8;
const CAP_SYS_RESOURCE: u32 = 24;
const CAP_LAST_CAP: u32 = 40;
const SECUREBITS_LOCK_MASK: u16 = 0b1010_1010;
const SECUREBITS_VALID_MASK: u16 = SECUREBITS_LOCK_MASK | (SECUREBITS_LOCK_MASK >> 1);
const SECUREBIT_NO_SETUID_FIXUP: u16 = 1 << 2;
const SECUREBIT_KEEP_CAPS: u16 = 1 << 4;

/// Linux capability set stored as the kernel ABI's 64-bit bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    /// Returns an empty capability set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns all capabilities known to this kernel image.
    pub const fn all() -> Self {
        Self((1_u64 << (CAP_LAST_CAP + 1)) - 1)
    }

    /// Creates a capability set from Linux's low/high 32-bit ABI fields.
    pub const fn from_lo_hi(lo: u32, hi: u32) -> Self {
        Self((lo as u64 | ((hi as u64) << 32)) & Self::all().0)
    }

    /// Splits the set into Linux's low/high 32-bit ABI fields.
    pub const fn to_lo_hi(self) -> (u32, u32) {
        (self.0 as u32, (self.0 >> 32) as u32)
    }

    /// Creates a one-bit set for a Linux capability number.
    pub fn from_capability_number(capability: u32) -> Option<Self> {
        if capability > CAP_LAST_CAP {
            return None;
        }
        Some(Self(1_u64 << capability))
    }

    /// Returns whether all `other` capabilities are present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn remove(&mut self, capability: Self) {
        self.0 &= !capability.0;
    }
}

/// Numeric credentials associated with a POSIX thread.
#[derive(Clone, Debug)]
pub struct Credentials {
    ruid: Uid,
    euid: Uid,
    suid: Uid,
    rgid: Gid,
    egid: Gid,
    sgid: Gid,
    groups: Vec<Gid>,
    permitted_capset: CapabilitySet,
    effective_capset: CapabilitySet,
    inheritable_capset: CapabilitySet,
    bounding_capset: CapabilitySet,
    securebits: u16,
}

impl Credentials {
    /// Creates root credentials for the current initial kernel image.
    pub fn new_root() -> Self {
        Self {
            ruid: Uid::new_root(),
            euid: Uid::new_root(),
            suid: Uid::new_root(),
            rgid: Gid::new_root(),
            egid: Gid::new_root(),
            sgid: Gid::new_root(),
            groups: Vec::new(),
            permitted_capset: CapabilitySet::all(),
            effective_capset: CapabilitySet::all(),
            inheritable_capset: CapabilitySet::empty(),
            bounding_capset: CapabilitySet::all(),
            securebits: 0,
        }
    }

    /// Returns the real user ID.
    pub const fn ruid(&self) -> Uid {
        self.ruid
    }

    /// Returns the effective user ID.
    pub const fn euid(&self) -> Uid {
        self.euid
    }

    /// Returns the saved-set user ID.
    pub const fn suid(&self) -> Uid {
        self.suid
    }

    /// Returns the real group ID.
    pub const fn rgid(&self) -> Gid {
        self.rgid
    }

    /// Returns the effective group ID.
    pub const fn egid(&self) -> Gid {
        self.egid
    }

    /// Returns the saved-set group ID.
    pub const fn sgid(&self) -> Gid {
        self.sgid
    }

    /// Returns supplementary group IDs.
    pub fn groups(&self) -> &[Gid] {
        &self.groups
    }

    /// Replaces supplementary groups.
    pub fn set_groups(&mut self, mut groups: Vec<Gid>) {
        groups.sort();
        groups.dedup();
        self.groups = groups;
    }

    /// Returns the permitted capability set.
    pub const fn permitted_capset(&self) -> CapabilitySet {
        self.permitted_capset
    }

    /// Returns the effective capability set.
    pub const fn effective_capset(&self) -> CapabilitySet {
        self.effective_capset
    }

    /// Returns the inheritable capability set.
    pub const fn inheritable_capset(&self) -> CapabilitySet {
        self.inheritable_capset
    }

    /// Returns the capability bounding set.
    pub const fn bounding_capset(&self) -> CapabilitySet {
        self.bounding_capset
    }

    /// Returns whether `CAP_SYS_RESOURCE` is effective.
    pub fn has_sys_resource(&self) -> bool {
        self.effective_capset.contains(capability(CAP_SYS_RESOURCE))
    }

    /// Sets capability sets after validating Linux capability containment rules.
    pub fn set_capsets(
        &mut self,
        permitted: CapabilitySet,
        effective: CapabilitySet,
        inheritable: CapabilitySet,
    ) -> Result<()> {
        if !self.permitted_capset.contains(permitted) {
            return Err(Error::new(Errno::EPERM));
        }
        if !permitted.contains(effective) {
            return Err(Error::new(Errno::EPERM));
        }
        if !self
            .inheritable_capset
            .union(self.permitted_capset)
            .contains(inheritable)
            && !self.effective_capset.contains(capability(CAP_SETPCAP))
        {
            return Err(Error::new(Errno::EPERM));
        }
        if !self
            .inheritable_capset
            .union(self.bounding_capset)
            .contains(inheritable)
        {
            return Err(Error::new(Errno::EPERM));
        }
        self.permitted_capset = permitted;
        self.effective_capset = effective;
        self.inheritable_capset = inheritable;
        Ok(())
    }

    /// Returns whether capabilities are kept across UID changes.
    pub const fn keep_capabilities(&self) -> bool {
        self.securebits & SECUREBIT_KEEP_CAPS != 0
    }

    const fn no_setuid_fixup(&self) -> bool {
        self.securebits & SECUREBIT_NO_SETUID_FIXUP != 0
    }

    /// Sets the keep-capabilities flag.
    pub fn set_keep_capabilities(&mut self, keep_capabilities: bool) -> Result<()> {
        let securebits = if keep_capabilities {
            self.securebits | SECUREBIT_KEEP_CAPS
        } else {
            self.securebits & !SECUREBIT_KEEP_CAPS
        };
        self.try_store_securebits(securebits)
    }

    /// Returns securebits.
    pub const fn securebits(&self) -> u16 {
        self.securebits
    }

    /// Sets securebits.
    pub fn set_securebits(&mut self, securebits: u16) -> Result<()> {
        if !self.effective_capset.contains(capability(CAP_SETPCAP)) {
            return Err(Error::new(Errno::EPERM));
        }
        self.try_store_securebits(securebits)
    }

    fn try_store_securebits(&mut self, securebits: u16) -> Result<()> {
        if securebits & !SECUREBITS_VALID_MASK != 0 {
            return Err(Error::new(Errno::EINVAL));
        }

        let locked_bits = (self.securebits & SECUREBITS_LOCK_MASK) >> 1;
        if locked_bits & self.securebits != locked_bits & securebits {
            return Err(Error::new(Errno::EPERM));
        }
        if SECUREBITS_LOCK_MASK & self.securebits & !securebits != 0 {
            return Err(Error::new(Errno::EPERM));
        }

        self.securebits = securebits;
        Ok(())
    }

    /// Drops a capability from the bounding set.
    pub fn drop_bounding_capability(&mut self, cap: CapabilitySet) -> Result<()> {
        if !self.effective_capset.contains(capability(CAP_SETPCAP)) {
            return Err(Error::new(Errno::EPERM));
        }
        self.bounding_capset.remove(cap);
        Ok(())
    }

    /// Sets the user ID following the root-capable `setuid` rule.
    pub fn set_uid(&mut self, uid: Uid) -> Result<()> {
        if self.effective_capset.contains(capability(CAP_SETUID)) {
            return self.set_resuid(Some(uid), Some(uid), Some(uid));
        }
        self.set_resuid(None, Some(uid), None)
    }

    /// Sets the group ID following the root-capable `setgid` rule.
    pub fn set_gid(&mut self, gid: Gid) -> Result<()> {
        if self.effective_capset.contains(capability(CAP_SETGID)) {
            return self.set_resgid(Some(gid), Some(gid), Some(gid));
        }
        self.set_resgid(None, Some(gid), None)
    }

    /// Sets real and effective user IDs following `setreuid` rules.
    pub fn set_reuid(&mut self, ruid: Option<Uid>, euid: Option<Uid>) -> Result<()> {
        self.check_uid_perm(ruid, euid, None, false)?;
        let old_ruid = self.ruid;
        let old_euid = self.euid;
        let suid = if ruid.is_some() || euid.is_some_and(|euid| euid != old_ruid) {
            Some(euid.unwrap_or(old_euid))
        } else {
            None
        };
        self.set_resuid_unchecked(ruid, euid, suid);
        Ok(())
    }

    /// Sets real, effective, and saved-set user IDs.
    pub fn set_resuid(
        &mut self,
        ruid: Option<Uid>,
        euid: Option<Uid>,
        suid: Option<Uid>,
    ) -> Result<()> {
        self.check_uid_perm(ruid, euid, suid, true)?;
        self.set_resuid_unchecked(ruid, euid, suid);
        Ok(())
    }

    /// Sets real and effective group IDs following `setregid` rules.
    pub fn set_regid(&mut self, rgid: Option<Gid>, egid: Option<Gid>) -> Result<()> {
        self.check_gid_perm(rgid, egid, None, false)?;
        let old_rgid = self.rgid;
        let old_egid = self.egid;
        let sgid = if rgid.is_some() || egid.is_some_and(|egid| egid != old_rgid) {
            Some(egid.unwrap_or(old_egid))
        } else {
            None
        };
        self.set_resgid_unchecked(rgid, egid, sgid);
        Ok(())
    }

    /// Sets real, effective, and saved-set group IDs.
    pub fn set_resgid(
        &mut self,
        rgid: Option<Gid>,
        egid: Option<Gid>,
        sgid: Option<Gid>,
    ) -> Result<()> {
        self.check_gid_perm(rgid, egid, sgid, true)?;
        self.set_resgid_unchecked(rgid, egid, sgid);
        Ok(())
    }

    fn check_uid_perm(
        &self,
        ruid: Option<Uid>,
        euid: Option<Uid>,
        suid: Option<Uid>,
        ruid_may_be_old_suid: bool,
    ) -> Result<()> {
        if self.effective_capset.contains(capability(CAP_SETUID)) {
            return Ok(());
        }

        if let Some(ruid) = ruid
            && ruid != self.ruid
            && ruid != self.euid
            && (!ruid_may_be_old_suid || ruid != self.suid)
        {
            return Err(Error::new(Errno::EPERM));
        }

        if let Some(euid) = euid
            && euid != self.ruid
            && euid != self.euid
            && euid != self.suid
        {
            return Err(Error::new(Errno::EPERM));
        }

        if let Some(suid) = suid
            && suid != self.ruid
            && suid != self.euid
            && suid != self.suid
        {
            return Err(Error::new(Errno::EPERM));
        }

        Ok(())
    }

    fn check_gid_perm(
        &self,
        rgid: Option<Gid>,
        egid: Option<Gid>,
        sgid: Option<Gid>,
        rgid_may_be_old_sgid: bool,
    ) -> Result<()> {
        if self.effective_capset.contains(capability(CAP_SETGID)) {
            return Ok(());
        }

        if let Some(rgid) = rgid
            && rgid != self.rgid
            && rgid != self.egid
            && (!rgid_may_be_old_sgid || rgid != self.sgid)
        {
            return Err(Error::new(Errno::EPERM));
        }

        if let Some(egid) = egid
            && egid != self.rgid
            && egid != self.egid
            && egid != self.sgid
        {
            return Err(Error::new(Errno::EPERM));
        }

        if let Some(sgid) = sgid
            && sgid != self.rgid
            && sgid != self.egid
            && sgid != self.sgid
        {
            return Err(Error::new(Errno::EPERM));
        }

        Ok(())
    }

    fn set_resuid_unchecked(&mut self, ruid: Option<Uid>, euid: Option<Uid>, suid: Option<Uid>) {
        let old_ruid = self.ruid;
        let old_euid = self.euid;
        let old_suid = self.suid;

        if let Some(ruid) = ruid {
            self.ruid = ruid;
        }
        if let Some(euid) = euid {
            self.euid = euid;
        }
        if let Some(suid) = suid {
            self.suid = suid;
        }

        self.update_capsets_after_uid_change(old_ruid, old_euid, old_suid);
    }

    fn update_capsets_after_uid_change(&mut self, old_ruid: Uid, old_euid: Uid, old_suid: Uid) {
        if self.no_setuid_fixup() {
            return;
        }

        let had_root = old_ruid.is_root() || old_euid.is_root() || old_suid.is_root();
        let has_root = self.ruid.is_root() || self.euid.is_root() || self.suid.is_root();
        if had_root && !has_root && !self.keep_capabilities() {
            self.permitted_capset = CapabilitySet::empty();
            self.effective_capset = CapabilitySet::empty();
            self.inheritable_capset = CapabilitySet::empty();
            return;
        }

        if old_euid.is_root() && !self.euid.is_root() {
            self.effective_capset = CapabilitySet::empty();
        } else if !old_euid.is_root() && self.euid.is_root() {
            self.effective_capset = self.permitted_capset;
        }
    }

    fn set_resgid_unchecked(&mut self, rgid: Option<Gid>, egid: Option<Gid>, sgid: Option<Gid>) {
        if let Some(rgid) = rgid {
            self.rgid = rgid;
        }
        if let Some(egid) = egid {
            self.egid = egid;
        }
        if let Some(sgid) = sgid {
            self.sgid = sgid;
        }
    }
}

const fn capability(capability: u32) -> CapabilitySet {
    CapabilitySet(1_u64 << capability)
}

#[cfg(ktest)]
mod tests {
    use alloc::vec;

    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn capability_from_abi_truncates_unknown_bits() {
        let capset = CapabilitySet::from_lo_hi(u32::MAX, u32::MAX);

        assert_eq!(capset, CapabilitySet::all());
    }

    #[ktest]
    fn setuid_permission_depends_on_capability_not_root_euid() {
        let mut credentials = Credentials::new_root();
        let mut effective = CapabilitySet::all();
        effective.remove(capability(CAP_SETUID));
        credentials.effective_capset = effective;

        assert_eq!(
            credentials.set_uid(Uid::new(1000)).unwrap_err().errno(),
            Errno::EPERM
        );
    }

    #[ktest]
    fn setuid_capability_allows_full_id_change() {
        let mut credentials = Credentials::new_root();
        credentials.ruid = Uid::new(1000);
        credentials.euid = Uid::new(1000);
        credentials.suid = Uid::new(1000);
        credentials.permitted_capset = capability(CAP_SETUID);
        credentials.effective_capset = capability(CAP_SETUID);

        credentials.set_uid(Uid::new(1001)).unwrap();

        assert_eq!(credentials.ruid(), Uid::new(1001));
        assert_eq!(credentials.euid(), Uid::new(1001));
        assert_eq!(credentials.suid(), Uid::new(1001));
    }

    #[ktest]
    fn no_setuid_fixup_securebit_preserves_capsets() {
        let mut credentials = Credentials::new_root();
        credentials
            .set_securebits(SECUREBIT_NO_SETUID_FIXUP)
            .unwrap();

        credentials
            .set_resuid(
                Some(Uid::new(1000)),
                Some(Uid::new(1000)),
                Some(Uid::new(1000)),
            )
            .unwrap();

        assert_eq!(credentials.permitted_capset(), CapabilitySet::all());
        assert_eq!(credentials.effective_capset(), CapabilitySet::all());
        assert_eq!(credentials.inheritable_capset(), CapabilitySet::empty());
    }

    #[ktest]
    fn setgroups_matches_kernel_collection_semantics() {
        let mut credentials = Credentials::new_root();
        credentials.effective_capset = CapabilitySet::empty();

        credentials.set_groups(vec![Gid::new(3), Gid::new(2), Gid::new(3)]);

        assert_eq!(credentials.groups(), &[Gid::new(2), Gid::new(3)]);
    }

    #[ktest]
    fn capset_rejects_permitted_capability_growth() {
        let mut credentials = Credentials::new_root();
        let reduced = capability(CAP_SETUID);
        credentials
            .set_capsets(reduced, reduced, CapabilitySet::empty())
            .unwrap();

        assert_eq!(
            credentials
                .set_capsets(
                    reduced.union(capability(CAP_SETGID)),
                    reduced,
                    CapabilitySet::empty()
                )
                .unwrap_err()
                .errno(),
            Errno::EPERM
        );
    }

    #[ktest]
    fn capset_rejects_effective_capabilities_outside_new_permitted() {
        let mut credentials = Credentials::new_root();

        assert_eq!(
            credentials
                .set_capsets(
                    capability(CAP_SETUID),
                    capability(CAP_SETUID).union(capability(CAP_SETGID)),
                    CapabilitySet::empty()
                )
                .unwrap_err()
                .errno(),
            Errno::EPERM
        );
    }

    #[ktest]
    fn capset_requires_setpcap_for_new_inheritable_capabilities() {
        let mut credentials = Credentials::new_root();
        credentials.permitted_capset = CapabilitySet::empty();
        credentials.effective_capset = CapabilitySet::empty();

        assert_eq!(
            credentials
                .set_capsets(
                    CapabilitySet::empty(),
                    CapabilitySet::empty(),
                    capability(CAP_SETUID)
                )
                .unwrap_err()
                .errno(),
            Errno::EPERM
        );
    }

    #[ktest]
    fn capset_rejects_inheritable_capabilities_outside_bounding_set() {
        let mut credentials = Credentials::new_root();
        credentials.bounding_capset = CapabilitySet::empty();

        assert_eq!(
            credentials
                .set_capsets(
                    CapabilitySet::all(),
                    CapabilitySet::empty(),
                    capability(CAP_SETUID)
                )
                .unwrap_err()
                .errno(),
            Errno::EPERM
        );
    }

    #[ktest]
    fn set_process_group_creates_kernel_shaped_process_group() {
        let parent = new_init_process(10_100);
        let child = new_child_process(10_101, &parent);

        set_process_group(&parent, child.pid() as i32, 0).unwrap();

        assert_eq!(child.pgid(), child.pid());
        assert_eq!(child.sid(), parent.sid());
    }

    #[ktest]
    fn create_session_rejects_process_group_leader() {
        let process = new_init_process(10_200);

        set_process_group(&process, 0, 0).unwrap();

        assert_eq!(create_session(&process).unwrap_err().errno(), Errno::EPERM);
    }

    #[ktest]
    fn set_process_group_rejects_child_in_different_session() {
        let parent = new_init_process(10_300);
        let child = new_child_process(10_301, &parent);

        create_session(&child).unwrap();

        assert_eq!(
            set_process_group(&parent, child.pid() as i32, parent.pgid() as i32)
                .unwrap_err()
                .errno(),
            Errno::EPERM
        );
    }
}

/// POSIX-thread identity exposed to copied syscall handlers.
#[derive(Clone, Debug)]
pub struct PosixThread {
    tid: Pid,
    credentials: Credentials,
}

impl PosixThread {
    /// Creates a POSIX thread identity with a credentials snapshot.
    pub fn new(tid: Pid, credentials: Credentials) -> Self {
        Self { tid, credentials }
    }

    /// Returns the thread ID.
    pub const fn tid(&self) -> Pid {
        self.tid
    }

    /// Returns the read-only credentials of the thread.
    pub fn credentials(&self) -> Credentials {
        self.credentials.clone()
    }
}

const BOOTSTRAP_GROUP: Pgid = 0;
const BOOTSTRAP_SESSION: Sid = 0;
static CONSOLE_FOREGROUND_PGID: AtomicU32 = AtomicU32::new(BOOTSTRAP_GROUP);

/// Process-level identity visible through Linux process syscalls.
pub struct ProcessIdentity {
    pid: Pid,
    parent_pid: Option<Pid>,
    credentials: Mutex<Credentials>,
    process_group: Mutex<Option<Arc<ProcessGroup>>>,
    parent_death_signal: AtomicU32,
    cpu_time_cycles: AtomicU64,
    child_subreaper: AtomicBool,
}

/// Parent process identity visible through `getppid`.
pub struct ParentProcess {
    pid: Pid,
}

impl ParentProcess {
    /// Returns the parent process ID.
    pub const fn pid(&self) -> Pid {
        self.pid
    }
}

impl ProcessIdentity {
    fn new(pid: Pid, parent_pid: Option<Pid>, credentials: Credentials) -> Self {
        Self {
            pid,
            parent_pid,
            credentials: Mutex::new(credentials),
            process_group: Mutex::new(None),
            parent_death_signal: AtomicU32::new(0),
            cpu_time_cycles: AtomicU64::new(0),
            child_subreaper: AtomicBool::new(false),
        }
    }

    pub const fn pid(&self) -> Pid {
        self.pid
    }

    pub const fn parent_pid(&self) -> Option<Pid> {
        self.parent_pid
    }

    /// Returns the syscall-visible parent process identity.
    pub fn parent(&self) -> ParentProcess {
        ParentProcess {
            pid: self.parent_pid.unwrap_or(0),
        }
    }

    /// Returns a credentials snapshot.
    pub fn credentials(&self) -> Credentials {
        self.credentials.lock().clone()
    }

    /// Updates process credentials.
    pub fn update_credentials<T>(
        &self,
        f: impl FnOnce(&mut Credentials) -> Result<T>,
    ) -> Result<T> {
        let mut credentials = self.credentials.lock();
        f(&mut credentials)
    }

    /// Sets the process user IDs.
    pub fn set_uid(&self, uid: Uid) -> Result<()> {
        self.credentials.lock().set_uid(uid)
    }

    /// Sets the process group IDs.
    pub fn set_gid(&self, gid: Gid) -> Result<()> {
        self.credentials.lock().set_gid(gid)
    }

    /// Sets real and effective user IDs.
    pub fn set_reuid(&self, ruid: Option<Uid>, euid: Option<Uid>) -> Result<()> {
        self.credentials.lock().set_reuid(ruid, euid)
    }

    /// Sets real, effective, and saved-set user IDs.
    pub fn set_resuid(
        &self,
        ruid: Option<Uid>,
        euid: Option<Uid>,
        suid: Option<Uid>,
    ) -> Result<()> {
        self.credentials.lock().set_resuid(ruid, euid, suid)
    }

    /// Sets real and effective group IDs.
    pub fn set_regid(&self, rgid: Option<Gid>, egid: Option<Gid>) -> Result<()> {
        self.credentials.lock().set_regid(rgid, egid)
    }

    /// Sets real, effective, and saved-set group IDs.
    pub fn set_resgid(
        &self,
        rgid: Option<Gid>,
        egid: Option<Gid>,
        sgid: Option<Gid>,
    ) -> Result<()> {
        self.credentials.lock().set_resgid(rgid, egid, sgid)
    }

    /// Replaces supplementary groups.
    pub fn set_groups(&self, groups: Vec<Gid>) {
        self.credentials.lock().set_groups(groups)
    }

    /// Sets the signal sent when the parent process exits.
    pub fn set_parent_death_signal(&self, signal: u32) -> Result<()> {
        if !(1..=64).contains(&signal) {
            return Err(Error::new(Errno::EINVAL));
        }
        self.parent_death_signal.store(signal, Ordering::Release);
        Ok(())
    }

    /// Returns the parent-death signal number, or zero when unset.
    pub fn parent_death_signal(&self) -> u32 {
        self.parent_death_signal.load(Ordering::Acquire)
    }

    /// Charges CPU runtime to the process.
    pub fn record_cpu_time_cycles(&self, cycles: u64) {
        self.cpu_time_cycles.fetch_add(cycles, Ordering::Relaxed);
    }

    /// Returns accumulated process CPU runtime in TSC cycles.
    pub fn cpu_time_cycles(&self) -> u64 {
        self.cpu_time_cycles.load(Ordering::Acquire)
    }

    /// Sets child-subreaper state.
    pub fn set_child_subreaper(&self, is_set: bool) {
        self.child_subreaper.store(is_set, Ordering::Release);
    }

    /// Returns child-subreaper state.
    pub fn is_child_subreaper(&self) -> bool {
        self.child_subreaper.load(Ordering::Acquire)
    }

    pub fn pgid(&self) -> Pgid {
        self.process_group
            .lock()
            .as_ref()
            .map_or(0, |group| group.pgid())
    }

    pub fn sid(&self) -> Sid {
        self.session().map_or(0, |session| session.sid())
    }

    fn session(&self) -> Option<Arc<Session>> {
        self.process_group
            .lock()
            .as_ref()
            .map(|group| group.session().clone())
    }

    fn set_process_group(&self, process_group: Option<Arc<ProcessGroup>>) {
        *self.process_group.lock() = process_group;
    }
}

struct ProcessGroup {
    pgid: Pgid,
    session: Arc<Session>,
    processes: Mutex<BTreeMap<Pid, Weak<ProcessIdentity>>>,
}

impl ProcessGroup {
    fn new(process: &Arc<ProcessIdentity>, session: Arc<Session>) -> Arc<Self> {
        Self::new_with(process.pid(), process, session)
    }

    fn new_bootstrap(process: &Arc<ProcessIdentity>, session: Arc<Session>) -> Arc<Self> {
        Self::new_with(BOOTSTRAP_GROUP, process, session)
    }

    fn new_with(pgid: Pgid, process: &Arc<ProcessIdentity>, session: Arc<Session>) -> Arc<Self> {
        let mut processes = BTreeMap::new();
        processes.insert(process.pid(), Arc::downgrade(process));
        Arc::new(Self {
            pgid,
            session,
            processes: Mutex::new(processes),
        })
    }

    const fn pgid(&self) -> Pgid {
        self.pgid
    }

    fn session(&self) -> &Arc<Session> {
        &self.session
    }

    fn insert_process(&self, process: &Arc<ProcessIdentity>) {
        self.processes
            .lock()
            .insert(process.pid(), Arc::downgrade(process));
    }

    fn remove_process(&self, pid: Pid) {
        self.processes.lock().remove(&pid);
    }

    fn purge_dead_processes(&self) {
        self.processes
            .lock()
            .retain(|_, process| process.upgrade().is_some());
    }

    fn is_empty(&self) -> bool {
        self.processes
            .lock()
            .values()
            .all(|process| process.upgrade().is_none())
    }
}

struct Session {
    sid: Sid,
    process_groups: Mutex<BTreeMap<Pgid, Weak<ProcessGroup>>>,
}

impl Session {
    fn new_pair(process: &Arc<ProcessIdentity>) -> (Arc<Self>, Arc<ProcessGroup>) {
        let session = Self::new_empty(process.pid());
        let process_group = ProcessGroup::new(process, session.clone());
        session.insert_process_group(&process_group);
        (session, process_group)
    }

    fn new_bootstrap_pair(process: &Arc<ProcessIdentity>) -> (Arc<Self>, Arc<ProcessGroup>) {
        let session = Self::new_empty(BOOTSTRAP_SESSION);
        let process_group = ProcessGroup::new_bootstrap(process, session.clone());
        session.insert_process_group(&process_group);
        (session, process_group)
    }

    fn new_empty(sid: Sid) -> Arc<Self> {
        Arc::new(Self {
            sid,
            process_groups: Mutex::new(BTreeMap::new()),
        })
    }

    const fn sid(&self) -> Sid {
        self.sid
    }

    fn insert_process_group(&self, process_group: &Arc<ProcessGroup>) {
        self.process_groups
            .lock()
            .insert(process_group.pgid(), Arc::downgrade(process_group));
    }

    fn remove_process_group(&self, pgid: Pgid) {
        self.process_groups.lock().remove(&pgid);
    }

    fn purge_dead_process_groups(&self) {
        self.process_groups.lock().retain(|pgid, group| {
            *pgid == BOOTSTRAP_GROUP || group.upgrade().is_some_and(|group| !group.is_empty())
        });
    }

    fn is_empty(&self) -> bool {
        self.process_groups
            .lock()
            .values()
            .all(|group| group.upgrade().is_none_or(|group| group.is_empty()))
    }
}

struct ProcessTable {
    inner: Mutex<ProcessTableInner>,
}

struct ProcessTableInner {
    processes: BTreeMap<Pid, Weak<ProcessIdentity>>,
    process_groups: BTreeMap<Pgid, Arc<ProcessGroup>>,
    sessions: BTreeMap<Sid, Arc<Session>>,
}

static PROCESS_TABLE: Once<ProcessTable> = Once::new();

fn process_table() -> &'static ProcessTable {
    PROCESS_TABLE.call_once(|| ProcessTable {
        inner: Mutex::new(ProcessTableInner {
            processes: BTreeMap::new(),
            process_groups: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }),
    })
}

/// PID table APIs used by copied syscall handlers.
pub mod pid_table {
    use alloc::sync::Arc;

    use super::{Pid, ProcessIdentity, lookup_process_locked, process_table, purge_dead_processes};

    /// A mutable PID-table view.
    pub struct PidTableMut;

    /// Returns a mutable PID-table view.
    pub fn pid_table_mut() -> PidTableMut {
        PidTableMut
    }

    impl PidTableMut {
        /// Gets a process by PID.
        pub fn get_process(&self, pid: Pid) -> Option<Arc<ProcessIdentity>> {
            let mut inner = process_table().inner.lock();
            purge_dead_processes(&mut inner);
            lookup_process_locked(&inner, pid).ok()
        }
    }
}

/// Creates the initial process identity for a top-level task.
pub fn new_init_process(pid: Pid) -> Arc<ProcessIdentity> {
    let process = Arc::new(ProcessIdentity::new(pid, None, Credentials::new_root()));
    let mut inner = process_table().inner.lock();
    insert_process_locked(&mut inner, &process);

    if let Some(process_group) = lookup_group_locked(&inner, BOOTSTRAP_GROUP) {
        process_group.insert_process(&process);
        process.set_process_group(Some(process_group));
        return process;
    }

    let (session, process_group) = Session::new_bootstrap_pair(&process);
    process.set_process_group(Some(process_group.clone()));
    insert_group_locked(&mut inner, &process_group);
    insert_session_locked(&mut inner, &session);
    process
}

/// Creates a child process identity with inherited group/session state.
pub fn new_child_process(pid: Pid, parent: &Arc<ProcessIdentity>) -> Arc<ProcessIdentity> {
    let process = Arc::new(ProcessIdentity::new(
        pid,
        Some(parent.pid()),
        parent.credentials(),
    ));
    let parent_group = parent.process_group.lock().as_ref().cloned();

    let mut inner = process_table().inner.lock();
    insert_process_locked(&mut inner, &process);
    if let Some(parent_group) = parent_group {
        parent_group.insert_process(&process);
        process.set_process_group(Some(parent_group));
    }
    process
}

/// Removes a process identity after its last thread exits.
pub fn unregister_process_if_last_reference(process: &Arc<ProcessIdentity>) {
    if Arc::strong_count(process) != 1 {
        return;
    }

    let mut inner = process_table().inner.lock();
    inner.processes.remove(&process.pid());
    clear_group_and_session_locked(&mut inner, process);
    purge_dead_processes(&mut inner);
}

pub fn set_process_group(
    current: &Arc<ProcessIdentity>,
    raw_pid: i32,
    raw_pgid: i32,
) -> Result<()> {
    if raw_pid < 0 || raw_pgid < 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let pid = if raw_pid == 0 {
        current.pid()
    } else {
        raw_pid as Pid
    };
    let pgid = if raw_pgid == 0 { pid } else { raw_pgid as Pgid };

    let mut inner = process_table().inner.lock();
    purge_dead_processes(&mut inner);

    let target = lookup_process_locked(&inner, pid)?;
    let target_is_current = target.pid() == current.pid();
    let target_is_child = target.parent_pid() == Some(current.pid());
    if !target_is_current && !target_is_child {
        return Err(Error::new(Errno::ESRCH));
    }

    let current_session = if target_is_current {
        None
    } else {
        Some(current.session().ok_or(Error::new(Errno::EPERM))?)
    };

    if let Some(process_group) = lookup_group_locked(&inner, pgid) {
        move_to_existing_group_locked(&mut inner, &target, current_session, process_group)
    } else if pgid == target.pid() {
        move_to_new_group_locked(&mut inner, &target, current_session)
    } else {
        Err(Error::new(Errno::EPERM))
    }
}

pub fn create_session(process: &Arc<ProcessIdentity>) -> Result<Sid> {
    let mut inner = process_table().inner.lock();
    purge_dead_processes(&mut inner);

    if lookup_group_locked(&inner, process.pid()).is_some() {
        return Err(Error::new(Errno::EPERM));
    }

    clear_group_and_session_locked(&mut inner, process);
    let (session, process_group) = Session::new_pair(process);
    let sid = session.sid();
    process.set_process_group(Some(process_group.clone()));
    insert_session_locked(&mut inner, &session);
    insert_group_locked(&mut inner, &process_group);
    Ok(sid)
}

pub fn foreground_process_group() -> Pgid {
    CONSOLE_FOREGROUND_PGID.load(Ordering::Acquire)
}

pub fn set_controlling_terminal(process: &Arc<ProcessIdentity>) {
    CONSOLE_FOREGROUND_PGID.store(process.pgid(), Ordering::Release);
}

pub fn set_foreground_process_group(current: &Arc<ProcessIdentity>, raw_pgid: i32) -> Result<()> {
    if raw_pgid < 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let pgid = raw_pgid as Pgid;
    let mut inner = process_table().inner.lock();
    purge_dead_processes(&mut inner);

    let process_group = lookup_group_locked(&inner, pgid).ok_or(Error::new(Errno::ESRCH))?;
    if process_group.session().sid() != current.sid() {
        return Err(Error::new(Errno::EPERM));
    }

    CONSOLE_FOREGROUND_PGID.store(pgid, Ordering::Release);
    Ok(())
}

fn move_to_existing_group_locked(
    inner: &mut ProcessTableInner,
    process: &Arc<ProcessIdentity>,
    current_session: Option<Arc<Session>>,
    new_process_group: Arc<ProcessGroup>,
) -> Result<()> {
    let old_process_group = process
        .process_group
        .lock()
        .as_ref()
        .cloned()
        .ok_or(Error::new(Errno::EPERM))?;
    let old_session = old_process_group.session();

    if old_session.sid() == process.pid() {
        return Err(Error::new(Errno::EPERM));
    }
    if old_session.sid() != new_process_group.session().sid() {
        return Err(Error::new(Errno::EPERM));
    }
    if current_session
        .as_ref()
        .is_some_and(|current| current.sid() != old_session.sid())
    {
        return Err(Error::new(Errno::EPERM));
    }
    if old_process_group.pgid() == new_process_group.pgid() {
        return Ok(());
    }

    remove_from_old_group_locked(inner, process, &old_process_group);
    new_process_group.insert_process(process);
    process.set_process_group(Some(new_process_group));
    Ok(())
}

fn move_to_new_group_locked(
    inner: &mut ProcessTableInner,
    process: &Arc<ProcessIdentity>,
    current_session: Option<Arc<Session>>,
) -> Result<()> {
    let old_process_group = process
        .process_group
        .lock()
        .as_ref()
        .cloned()
        .ok_or(Error::new(Errno::EPERM))?;
    let session = old_process_group.session().clone();

    if current_session
        .as_ref()
        .is_some_and(|current| current.sid() != session.sid())
    {
        return Err(Error::new(Errno::EPERM));
    }
    if old_process_group.pgid() == process.pid() {
        return Ok(());
    }

    remove_from_old_group_locked(inner, process, &old_process_group);
    let new_process_group = ProcessGroup::new(process, session.clone());
    session.insert_process_group(&new_process_group);
    insert_group_locked(inner, &new_process_group);
    process.set_process_group(Some(new_process_group));
    Ok(())
}

fn clear_group_and_session_locked(inner: &mut ProcessTableInner, process: &Arc<ProcessIdentity>) {
    let old_process_group = process.process_group.lock().take();
    if let Some(old_process_group) = old_process_group {
        remove_from_old_group_locked(inner, process, &old_process_group);
    }
}

fn remove_from_old_group_locked(
    inner: &mut ProcessTableInner,
    process: &Arc<ProcessIdentity>,
    process_group: &Arc<ProcessGroup>,
) {
    process_group.remove_process(process.pid());
    if !process_group.is_empty() {
        return;
    }
    if process_group.pgid() == BOOTSTRAP_GROUP {
        return;
    }

    inner.process_groups.remove(&process_group.pgid());
    let session = process_group.session();
    session.remove_process_group(process_group.pgid());
    if session.sid() != BOOTSTRAP_SESSION && session.is_empty() {
        inner.sessions.remove(&session.sid());
    }
}

fn lookup_process_locked(inner: &ProcessTableInner, pid: Pid) -> Result<Arc<ProcessIdentity>> {
    inner
        .processes
        .get(&pid)
        .and_then(Weak::upgrade)
        .ok_or(Error::new(Errno::ESRCH))
}

fn lookup_group_locked(inner: &ProcessTableInner, pgid: Pgid) -> Option<Arc<ProcessGroup>> {
    inner.process_groups.get(&pgid).cloned()
}

fn insert_process_locked(inner: &mut ProcessTableInner, process: &Arc<ProcessIdentity>) {
    inner
        .processes
        .insert(process.pid(), Arc::downgrade(process));
}

fn insert_group_locked(inner: &mut ProcessTableInner, process_group: &Arc<ProcessGroup>) {
    inner
        .process_groups
        .insert(process_group.pgid(), process_group.clone());
}

fn insert_session_locked(inner: &mut ProcessTableInner, session: &Arc<Session>) {
    inner.sessions.insert(session.sid(), session.clone());
}

fn purge_dead_processes(inner: &mut ProcessTableInner) {
    let dead_pids = inner
        .processes
        .iter()
        .filter_map(|(pid, process)| process.upgrade().is_none().then_some(*pid))
        .collect::<Vec<_>>();

    for pid in dead_pids {
        inner.processes.remove(&pid);
    }

    let process_group_ids = inner.process_groups.keys().copied().collect::<Vec<_>>();
    let mut dead_groups = Vec::new();
    for pgid in process_group_ids {
        let process_group = inner.process_groups.get(&pgid).cloned();
        let Some(process_group) = process_group else {
            dead_groups.push(pgid);
            continue;
        };
        process_group.purge_dead_processes();
        if pgid != BOOTSTRAP_GROUP && process_group.is_empty() {
            dead_groups.push(pgid);
        }
    }
    for pgid in dead_groups {
        if let Some(process_group) = lookup_group_locked(inner, pgid) {
            process_group.session().remove_process_group(pgid);
            if process_group.session().sid() != BOOTSTRAP_SESSION
                && process_group.session().is_empty()
            {
                inner.sessions.remove(&process_group.session().sid());
            }
        }
        inner.process_groups.remove(&pgid);
    }

    for session in inner.sessions.values() {
        session.purge_dead_process_groups();
    }
    inner
        .sessions
        .retain(|sid, session| *sid == BOOTSTRAP_SESSION || !session.is_empty());
}
