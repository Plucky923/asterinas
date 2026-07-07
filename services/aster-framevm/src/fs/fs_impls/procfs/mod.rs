// SPDX-License-Identifier: MPL-2.0

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use template::{
    ListedEntry, ProcDir, ProcDirOps, ReaddirEntry, StaticDirEntry, keyed_readdir_entries,
    listed_entries_from_table, lookup_child_from_table, sequential_readdir_entries,
    visit_readdir_entries,
};

use self::{pid::PidDirOps, self_::SelfSymOps};
use crate::{
    fs::{
        file::{InodeType, mkmod},
        pseudofs::AnonDeviceId,
        utils::NAME_MAX,
        vfs::{
            file_system::{FileSystem, FsEventSubscriberStats, SuperBlock},
            inode::{Inode, RevalidationPolicy},
            registry::{FsCreationCtx, FsProperties, FsType},
        },
    },
    prelude::*,
    process::{Pid, pid_table},
};

mod pid;
mod self_;
mod template;

pub(super) fn init() {
    crate::fs::vfs::registry::register(&ProcFsType).unwrap();
}

/// Magic number.
const PROC_MAGIC: u64 = 0x9fa0;
/// Root Inode ID.
const PROC_ROOT_INO: u64 = 1;
/// Block size.
const BLOCK_SIZE: usize = 1024;

struct ProcFs {
    _anon_device_id: AnonDeviceId,
    sb: SuperBlock,
    root: Arc<dyn Inode>,
    inode_allocator: AtomicU64,
    fs_event_subscriber_stats: FsEventSubscriberStats,
}

impl ProcFs {
    pub(self) fn new() -> Arc<Self> {
        let anon_device_id = AnonDeviceId::acquire().expect("no device ID is available for procfs");
        let sb = SuperBlock::new(PROC_MAGIC, BLOCK_SIZE, NAME_MAX, anon_device_id.id());
        Arc::new_cyclic(|weak_fs| Self {
            _anon_device_id: anon_device_id,
            sb: sb.clone(),
            root: ProcRootOps::new_inode(weak_fs.clone(), &sb),
            inode_allocator: AtomicU64::new(PROC_ROOT_INO + 1),
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
        })
    }

    pub(self) fn alloc_id(&self) -> u64 {
        self.inode_allocator.fetch_add(1, Ordering::Relaxed)
    }
}

impl FileSystem for ProcFs {
    fn name(&self) -> &'static str {
        "proc"
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn sb(&self) -> SuperBlock {
        self.sb.clone()
    }

    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        &self.fs_event_subscriber_stats
    }
}

struct ProcFsType;

impl FsType for ProcFsType {
    fn name(&self) -> &'static str {
        "proc"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::empty()
    }

    fn create(&self, _fs_creation_ctx: &FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        Ok(ProcFs::new())
    }

    fn sysnode(&self) -> Option<Arc<dyn aster_systree::SysNode>> {
        None
    }
}

/// Represents the inode at `/proc`.
struct ProcRootOps;

impl ProcRootOps {
    pub fn new_inode(fs: Weak<ProcFs>, sb: &SuperBlock) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/root.c#L368>
        let fs: Weak<dyn FileSystem> = fs;
        ProcDir::new_root(Self, fs, PROC_ROOT_INO, sb, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] =
        &[("self", InodeType::SymLink, SelfSymOps::new_inode)];
}

impl ProcDirOps for ProcRootOps {
    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if let Ok(pid) = name.parse::<Pid>() {
            let process = {
                let pid_table = pid_table::pid_table_mut();
                pid_table.get_process(pid)
            };
            if let Some(process) = process {
                return Ok(PidDirOps::new_inode(process, this_dir.this_weak().clone()));
            }
        }

        if let Some(child) = lookup_child_from_table(name, Self::STATIC_ENTRIES, |f| {
            (f)(this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the file does not exist");
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, mut visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        const FIRST_PID_OFFSET: usize = 2 + ProcRootOps::STATIC_ENTRIES.len();
        visit_readdir_entries(
            sequential_readdir_entries(offset, 2, listed_entries_from_table(Self::STATIC_ENTRIES)),
            &mut visit_fn,
        )?;

        let process_pids = {
            let pid_table = pid_table::pid_table_mut();
            pid_table
                .iter_processes()
                .filter_map(|process| usize::try_from(process.pid()).ok())
                .collect::<Vec<_>>()
        };

        visit_readdir_entries(
            keyed_readdir_entries(offset, FIRST_PID_OFFSET, process_pids, |process_pid| {
                ListedEntry::new(decimal_string(process_pid as u64), InodeType::Dir)
            }),
            visit_fn,
        )
    }

    fn revalidation_policy(&self) -> RevalidationPolicy {
        RevalidationPolicy::REVALIDATE_EXISTS | RevalidationPolicy::REVALIDATE_ABSENT
    }

    fn revalidate_exists(&self, name: &str, child: &dyn Inode) -> bool {
        if name.parse::<Pid>().is_err() {
            return true;
        };

        child
            .downcast_ref::<ProcDir<PidDirOps>>()
            .is_some_and(|child| child.inner().process().is_some())
    }

    fn revalidate_absent(&self, name: &str) -> bool {
        let Ok(pid) = name.parse::<Pid>() else {
            return true;
        };

        let process = {
            let pid_table = pid_table::pid_table_mut();
            pid_table.get_process(pid)
        };

        process.is_none()
    }
}

type StaticEntry = StaticDirEntry<fn(Weak<dyn Inode>) -> Arc<dyn Inode>>;

fn decimal_string(mut value: u64) -> String {
    if value == 0 {
        return String::from("0");
    }

    let mut digits = [0u8; 20];
    let mut pos = digits.len();
    while value != 0 {
        pos -= 1;
        digits[pos] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    let mut string = String::new();
    for digit in &digits[pos..] {
        string.push(char::from(*digit));
    }
    string
}

fn signed_decimal_string(value: i64) -> String {
    if value < 0 {
        let mut string = String::from("-");
        string.push_str(&decimal_string(value.unsigned_abs()));
        return string;
    }

    decimal_string(value as u64)
}
