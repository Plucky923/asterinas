use alloc::{string::String, sync::Arc};
use core::{any::Any, sync::atomic::{AtomicU32, Ordering}};

use bitflags::bitflags;
use hashbrown::HashMap;
use ostd::{mm::VmWriter, sync::Mutex};

use crate::{
    current_userspace,
    events::IoEvents,
    fs::{
        file_handle::FileLike,
        notify::{
            FsnotifyEvent, FsnotifyFlags, FsnotifyGroup, FsnotifyMark, FsnotifyMarkFlags,
        },
        path::Dentry,
        utils::{InodeMode, IoctlCmd, Metadata},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    return_errno_with_message, util::MultiWrite,
};

pub struct InotifyFile {
    fsnotify_group: Arc<Mutex<FsnotifyGroup>>,
    wd_allocator: AtomicU32,
    wd_map: Mutex<HashMap<i32, (Dentry, Arc<Mutex<dyn FsnotifyMark>>)>>,
    flags: InotifyFlags,
    this: Weak<InotifyFile>,
}

impl InotifyFile {
    pub fn new(flags: InotifyFlags) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| Self {
            fsnotify_group: Arc::new(Mutex::new(FsnotifyGroup::new())),
            wd_allocator: AtomicU32::new(0),
            wd_map: Mutex::new(HashMap::new()),
            this: weak_self.clone(),
            flags,
        })
    }

    fn alloc_wd(&self) -> i32 {
        self.wd_allocator.fetch_add(1, Ordering::SeqCst) as i32
    }

    fn free_wd(&self) {
        self.wd_allocator.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn update_watch(&self, dentry: &Dentry, mask: u32) -> Result<i32> {
        let ret = self.inotify_update_existing_watch(dentry, mask);
        match ret {
            Ok(wd) => Ok(wd),
            Err(e) => {
                if e.error() == Errno::ENOENT {
                    let wd = self.inotify_new_watch(dentry, mask)?;
                    Ok(wd)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn remove_watch(&self, wd: i32) -> Result<()> {
        println!("remove_watch wd = {}", wd);
        let mut wd_map = self.wd_map.lock();

        // Clone the values we need before removing from the map
        let dentry_and_mark = wd_map.get(&wd).cloned();

        if let Some((dentry, mark)) = dentry_and_mark {
            // Send the IN_IGNORED event to the mark
            println!("Sending IN_IGNORED event to mark");
            self.fsnotify_group.lock().remove_mark(&mark);
            dentry.remove_fsnotify_mark(&mark);
            let mut mark = mark.lock();
            mark.send_fsnotify(InotifyMask::IN_IGNORED.bits());
            wd_map.remove(&wd);
            self.free_wd();
        } else {
            return_errno_with_message!(Errno::EINVAL, "watch not found");
        }
        Ok(())
    }

    fn inotify_update_existing_watch(&self, dentry: &Dentry, mask: u32) -> Result<i32> {
        let mark = dentry.find_fsnotify_mark(&self.fsnotify_group);
        if let Some(mark) = mark {
            let mut mark = mark.lock();
            mark.update_mark(dentry, mask)
        } else {
            return_errno_with_message!(Errno::ENOENT, "watch not found");
        }
    }

    fn inotify_new_watch(&self, dentry: &Dentry, arg: u32) -> Result<i32> {
        let mask = inotify_arg_to_mask(arg);
        let flags = inotify_arg_to_flags(arg);
        let inotify_mark = InotifyMark::new(self.this(), mask, flags);
        let fsnotify_mark = inotify_mark.clone() as Arc<Mutex<dyn FsnotifyMark>>;
        dentry.add_fsnotify_mark(fsnotify_mark.clone(), 0);
        let wd = self.alloc_wd();
        let mut inotify_mark = inotify_mark.lock();
        inotify_mark.wd = wd;
        let mut wd_map = self.wd_map.lock();
        wd_map.insert(wd, (dentry.clone(), fsnotify_mark.clone()));
        self.fsnotify_group.lock().add_mark(fsnotify_mark.clone());
        Ok(wd)
    }

    fn this(&self) -> Arc<Self> {
        self.this.upgrade().unwrap()
    }
}

impl Pollable for InotifyFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        todo!()
    }
}

impl FileLike for InotifyFile {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        let fsnotify_group = self.fsnotify_group.lock();
        if self.flags.contains(InotifyFlags::IN_NONBLOCK)
            && fsnotify_group.get_all_event_size() == 0
        {
            return_errno_with_message!(Errno::EAGAIN, "non-blocking read");
        }

        let mut size = 0;
        while let Some(event) = fsnotify_group.pop_event() {
            size += event.copy_to_user(writer)?;
        }
        Ok(size)
    }

    fn ioctl(&self, cmd: IoctlCmd, arg: usize) -> Result<i32> {
        match cmd {
            IoctlCmd::FIONREAD => {
                let fsnotify_group = self.fsnotify_group.lock();
                let size = fsnotify_group.get_all_event_size();
                current_userspace!().write_val(arg, &size)?;
                Ok(0)
            }
            _ => return_errno_with_message!(Errno::EINVAL, "ioctl is not supported"),
        }
    }

    fn metadata(&self) -> Metadata {
        // This is a dummy implementation.
        // TODO: Add "anonymous inode fs" and link `InotifyFile` to it.
        Metadata::new_file(
            0,
            InodeMode::from_bits_truncate(0o600),
            aster_block::BLOCK_SIZE,
        )
    }
}

fn inotify_arg_to_mask(arg: u32) -> u32 {
    let mut mask = FsnotifyFlags::FS_UNMOUNT.bits();

    mask |= arg & InotifyMask::IN_ALL_EVENTS.bits();
    mask
}

fn inotify_arg_to_flags(arg: u32) -> u32 {
    let mut flag = 0;
    if arg & InotifyMask::IN_EXCL_UNLINK.bits() != 0 {
        flag |= FsnotifyMarkFlags::FSNOTIFY_MARK_FLAG_EXCL_UNLINK.bits();
    }

    if arg & InotifyMask::IN_ONESHOT.bits() != 0 {
        flag |= FsnotifyMarkFlags::FSNOTIFY_MARK_FLAG_IN_ONESHOT.bits();
    }

    flag
}

bitflags! {
    pub struct InotifyMask: u32 {
        // Core events that user-space can watch for
        const IN_ACCESS        = 1 << 0;  // File was accessed
        const IN_MODIFY        = 1 << 1;  // File was modified
        const IN_ATTRIB        = 1 << 2;  // Metadata changed
        const IN_CLOSE_WRITE   = 1 << 3;  // Writable file was closed
        const IN_CLOSE_NOWRITE = 1 << 4;  // Unwritable file closed
        const IN_OPEN          = 1 << 5;  // File was opened
        const IN_MOVED_FROM    = 1 << 6;  // File was moved from X
        const IN_MOVED_TO      = 1 << 7;  // File was moved to Y
        const IN_CREATE        = 1 << 8;  // Subfile was created
        const IN_DELETE        = 1 << 9;  // Subfile was deleted
        const IN_DELETE_SELF   = 1 << 10; // Self was deleted
        const IN_MOVE_SELF     = 1 << 11; // Self was moved

        // Additional events sent as needed
        const IN_UNMOUNT       = 1 << 13; // Backing fs was unmounted
        const IN_Q_OVERFLOW    = 1 << 14; // Event queue overflowed
        const IN_IGNORED       = 1 << 15; // File was ignored

        // Helper events
        const IN_CLOSE         = Self::IN_CLOSE_WRITE.bits() | Self::IN_CLOSE_NOWRITE.bits(); // Close events
        const IN_MOVE          = Self::IN_MOVED_FROM.bits() | Self::IN_MOVED_TO.bits();       // Move events

        // Special flags
        const IN_ONLYDIR       = 1 << 24; // Only watch directories
        const IN_DONT_FOLLOW   = 1 << 25; // Don't follow symlinks
        const IN_EXCL_UNLINK   = 1 << 26; // Exclude events on unlinked objects
        const IN_MASK_CREATE   = 1 << 28; // Only create watches
        const IN_MASK_ADD      = 1 << 29; // Add to existing watch mask
        const IN_ISDIR         = 1 << 30; // Event occurred on a directory
        const IN_ONESHOT       = 1 << 31; // Send event once
        const IN_ALL_EVENTS    = Self::IN_ACCESS.bits() | Self::IN_MODIFY.bits() | Self::IN_ATTRIB.bits() |
                                 Self::IN_CLOSE_WRITE.bits() | Self::IN_CLOSE_NOWRITE.bits() | Self::IN_OPEN.bits() |
                                 Self::IN_MOVED_FROM.bits() | Self::IN_MOVED_TO.bits() | Self::IN_DELETE.bits() |
                                 Self::IN_CREATE.bits() | Self::IN_DELETE_SELF.bits() | Self::IN_MOVE_SELF.bits();
    }
}

pub struct InotifyMark {
    inotify_file: Arc<InotifyFile>,
    mask: u32,
    flags: u32,
    wd: i32,
}

impl InotifyMark {
    pub fn new(inotify_file: Arc<InotifyFile>, mask: u32, flags: u32) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            inotify_file,
            mask,
            flags,
            wd: -1,
        }))
    }

    pub fn wd(&self) -> i32 {
        self.wd
    }
}

impl FsnotifyMark for InotifyMark {
    fn fsnotify_group(&self) -> &Arc<Mutex<FsnotifyGroup>> {
        &self.inotify_file.fsnotify_group
    }

    fn update_mark(&mut self, dentry: &Dentry, mask: u32) -> Result<i32> {
        if mask & InotifyMask::IN_MASK_CREATE.bits() != 0 {
            return_errno_with_message!(Errno::EEXIST, "watch already exists");
        }

        if mask & InotifyMask::IN_MASK_ADD.bits() == 0 {
            self.set_mask(0);
            self.set_flags(
                self.flags()
                    & !(FsnotifyMarkFlags::FSNOTIFY_MARK_FLAG_ATTACHED.bits()
                        | FsnotifyMarkFlags::FSNOTIFY_MARK_FLAG_IN_ONESHOT.bits()),
            );
        }

        self.set_mask(self.mask() | inotify_arg_to_mask(mask));
        self.set_flags(self.flags() | inotify_arg_to_flags(mask));

        if self.mask() != mask {
            dentry.update_fsnotify_mask(mask, self.mask());
        }

        Ok(self.wd())
    }

    fn mask(&self) -> u32 {
        self.mask
    }

    fn flags(&self) -> u32 {
        self.flags
    }

    fn set_mask(&mut self, mask: u32) {
        self.mask = mask;
    }

    fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    fn send_fsnotify(&self, mask: u32) {
        let wd = self.wd();
        if wd == -1 {
            return;
        }
        let event = Arc::new(InotifyEvent::new(mask, wd, 0, 0, String::new())) as Arc<dyn FsnotifyEvent>;
        let mut fsnotify_group = self.fsnotify_group().lock();
        fsnotify_group.add_event(event);
    }
}

#[repr(C)]
struct InotifyEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    name_len: u32,
    name: String,
}

impl InotifyEvent {
    pub fn new(mask: u32, wd: i32, cookie: u32, name_len: u32, name: String) -> Self {
        Self {
            mask,
            wd,
            cookie,
            name_len,
            name,
        }
    }
}

impl FsnotifyEvent for InotifyEvent {
    fn copy_to_user(&self, writer: &mut VmWriter) -> Result<usize> {
        let mut total_size = 0;

        println!(
            "InotifyEvent::copy_to_user: wd={}, mask={:#x}, cookie={}, name_len={}, name='{}'",
            self.wd, self.mask, self.cookie, self.name_len, self.name
        );

        // Write the event header
        writer.write_val(&self.wd)?;
        writer.write_val(&self.mask)?;
        writer.write_val(&self.cookie)?;
        writer.write_val(&self.name_len)?;
        total_size += core::mem::size_of::<i32>() * 4;
        println!("  Total bytes written: {}", total_size);
        Ok(total_size)
    }

    fn get_size(&self) -> usize {
        core::mem::size_of::<i32>() * 4 + self.name.len()
    }
}

bitflags! {
    pub struct InotifyFlags: u32 {
        const IN_NONBLOCK = 1 << 11; // Non-blocking
        const IN_CLOEXEC = 1 << 19; // Close on exec
    }
}
