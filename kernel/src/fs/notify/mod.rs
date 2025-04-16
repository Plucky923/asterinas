use alloc::{sync::Arc, vec::Vec};
use core::{any::Any, ptr};

use bitflags::bitflags;
use ostd::{
    mm::VmWriter,
    sync::{Mutex, RwLock},
};

use crate::{fs::path::Dentry, prelude::*};

pub mod inotify;
pub use inotify::{InotifyFile, InotifyFlags, InotifyMask};

use super::file_handle::FileLike;

pub struct FsnotifyCommon {
    fsnotify_mask: u32,
    fsnotify_marks: RwLock<Vec<Arc<dyn FsnotifyMark>>>,
}

pub struct FsnotifyGroup {
    notifications: RwLock<Vec<Arc<dyn FsnotifyEvent>>>,
    marks: RwLock<Vec<Arc<Mutex<dyn FsnotifyMark>>>>,
}

impl FsnotifyGroup {
    pub fn new() -> Self {
        Self {
            notifications: RwLock::new(Vec::new()),
            marks: RwLock::new(Vec::new()),
        }
    }

    pub fn add_event(&mut self, event: Arc<dyn FsnotifyEvent>) {
        self.notifications.write().push(event);
    }

    pub fn pop_event(&self) -> Option<Arc<dyn FsnotifyEvent>> {
        let mut notifications = self.notifications.write();
        if notifications.is_empty() {
            None
        } else {
            Some(notifications.remove(0))
        }
    }

    pub fn get_all_event_size(&self) -> usize {
        self.notifications.read().iter().map(|event| event.get_size()).sum()
    }

    fn add_mark(&self, mark: Arc<Mutex<dyn FsnotifyMark>>) {
        self.marks.write().push(mark);
    }

    fn remove_mark(&self, mark: &Arc<Mutex<dyn FsnotifyMark>>) {
        self.marks.write().retain(|m| !ptr::eq(m, mark));
    }
}

pub trait FsnotifyEvent: Send + Sync {
    fn copy_to_user(&self, writer: &mut VmWriter) -> Result<usize>;
    fn get_size(&self) -> usize;
}

pub trait FsnotifyMark: Any + Send + Sync {
    fn fsnotify_group(&self) -> &Arc<Mutex<FsnotifyGroup>>;
    fn update_mark(&mut self, dentry: &Dentry, mask: u32) -> Result<i32>;
    fn mask(&self) -> u32;
    fn flags(&self) -> u32;
    fn set_mask(&mut self, mask: u32);
    fn set_flags(&mut self, flags: u32);
    fn send_fsnotify(&self, mask: u32);
}

impl dyn FsnotifyMark {
    pub fn downcast_mut<T: FsnotifyMark>(&mut self) -> Option<&mut T> {
        (self as &mut dyn Any).downcast_mut::<T>()
    }
}

bitflags! {
    pub struct FsnotifyMarkFlags: u32 {
        // General fsnotify mark flags
        const FSNOTIFY_MARK_FLAG_ALIVE               = 0x0001;
        const FSNOTIFY_MARK_FLAG_ATTACHED            = 0x0002;
        // inotify mark flags
        const FSNOTIFY_MARK_FLAG_EXCL_UNLINK         = 0x0010;
        const FSNOTIFY_MARK_FLAG_IN_ONESHOT          = 0x0020;
        // fanotify mark flags
        const FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY = 0x0100;
        const FSNOTIFY_MARK_FLAG_NO_IREF             = 0x0200;
        const FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS    = 0x0400;
    }
}

bitflags! {
    pub struct FsnotifyFlags: u32 {
        const FS_ACCESS        = 0x00000001; // File was accessed
        const FS_MODIFY        = 0x00000002; // File was modified
        const FS_ATTRIB        = 0x00000004; // Metadata changed
        const FS_CLOSE_WRITE   = 0x00000008; // Writtable file was closed
        const FS_CLOSE_NOWRITE = 0x00000010; // Unwrittable file closed
        const FS_OPEN          = 0x00000020; // File was opened
        const FS_MOVED_FROM    = 0x00000040; // File was moved from X
        const FS_MOVED_TO      = 0x00000080; // File was moved to Y
        const FS_CREATE        = 0x00000100; // Subfile was created
        const FS_DELETE        = 0x00000200; // Subfile was deleted
        const FS_DELETE_SELF   = 0x00000400; // Self was deleted
        const FS_MOVE_SELF     = 0x00000800; // Self was moved
        const FS_OPEN_EXEC     = 0x00001000; // File was opened for exec

        const FS_UNMOUNT       = 0x00002000; // inode on umount fs
        const FS_Q_OVERFLOW    = 0x00004000; // Event queued overflowed
        const FS_ERROR         = 0x00008000; // Filesystem Error (fanotify)
        // FS_IN_IGNORED overloads FS_ERROR. It is only used internally by inotify
        // which does not support FS_ERROR.
        const FS_IN_IGNORED      = 0x00008000; // last inotify event here

        const FS_OPEN_PERM       = 0x00010000; // open event in a permission hook
        const FS_ACCESS_PERM     = 0x00020000; // access event in a permissions hook
        const FS_OPEN_EXEC_PERM  = 0x00040000; // open/exec event in a permission hook

        // Set on inode mark that cares about things that happen to its children.
        // Always set for dnotify and inotify.
        // Set on inode/sb/mount marks that care about parent/name info.
        const FS_EVENT_ON_CHILD  = 0x08000000;

        const FS_RENAME          = 0x10000000; // File was renamed
        const FS_DN_MULTISHOT    = 0x20000000; // dnotify multishot
        const FS_ISDIR           = 0x40000000; // event occurred against dir
    }
}

pub fn fsnotify_access(dentry: &Dentry) -> Result<()> {
    fsnotify(dentry, FsnotifyFlags::FS_ACCESS)
}

fn fsnotify(dentry: &Dentry, data_type: FsnotifyFlags) -> Result<()> {
    // traverse all the marks and send to the group
    dentry.send_fsnotify(data_type.bits());
    Ok(())
}
