// SPDX-License-Identifier: MPL-2.0

use bitflags::bitflags;

use crate::fs::file::AccessMode;

bitflags! {
    pub struct FileMode: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const LSEEK = 1 << 2;
        const PREAD = 1 << 3;
        const PWRITE = 1 << 4;
        const PATH = 1 << 14;
        const ATOMIC_POS = 1 << 15;
        const CAN_READ = 1 << 17;
        const CAN_WRITE = 1 << 18;
        const STREAM = 1 << 21;
        const NONOTIFY = 1 << 25;
        const NONOTIFY_PERM = 1 << 26;
    }
}

impl FileMode {
    pub const fn is_readable_open(self) -> bool {
        self.contains(Self::READ)
    }

    pub const fn is_writable_open(self) -> bool {
        self.contains(Self::WRITE)
    }

    pub const fn can_pread(self) -> bool {
        self.contains(Self::PREAD)
    }

    pub const fn can_pwrite(self) -> bool {
        self.contains(Self::PWRITE)
    }

    pub const fn can_seek(self) -> bool {
        self.contains(Self::LSEEK)
    }

    pub const fn uses_atomic_pos(self) -> bool {
        self.contains(Self::ATOMIC_POS)
    }

    pub const fn is_path(self) -> bool {
        self.contains(Self::PATH)
    }
}

impl From<AccessMode> for FileMode {
    fn from(access_mode: AccessMode) -> Self {
        match access_mode {
            AccessMode::O_RDONLY => Self::READ,
            AccessMode::O_WRONLY => Self::WRITE,
            AccessMode::O_RDWR => Self::READ | Self::WRITE,
        }
    }
}
