// SPDX-License-Identifier: MPL-2.0

//! Error types for FrameVM.

/// POSIX-compatible error numbers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    EIO = 5,
    EBADF = 9,
    EAGAIN = 11,
    ENOMEM = 12,
    EFAULT = 14,
    EBUSY = 16,
    EINVAL = 22,
    EPIPE = 32,
    ENOSYS = 38,
    ENOTSOCK = 88,
    ESOCKTNOSUPPORT = 94,
    EAFNOSUPPORT = 97,
    EADDRINUSE = 98,
    ECONNRESET = 104,
    EISCONN = 106,
    ENOTCONN = 107,
    ETIMEDOUT = 110,
    ECONNREFUSED = 111,
    EINPROGRESS = 115,
}

/// Error type for FrameVM operations.
#[derive(Debug, Clone, Copy)]
pub struct Error {
    errno: Errno,
    msg: Option<&'static str>,
}

impl Error {
    pub const fn new(errno: Errno) -> Self {
        Self { errno, msg: None }
    }

    pub const fn with_message(errno: Errno, msg: &'static str) -> Self {
        Self {
            errno,
            msg: Some(msg),
        }
    }

    pub const fn errno(&self) -> Errno {
        self.errno
    }
}

impl From<Errno> for Error {
    fn from(errno: Errno) -> Self {
        Self::new(errno)
    }
}

/// Convert from aster_framevisor::Error (re-exported from ostd::Error)
impl From<aster_framevisor::Error> for Error {
    fn from(e: aster_framevisor::Error) -> Self {
        let errno = match e {
            aster_framevisor::Error::InvalidArgs => Errno::EINVAL,
            aster_framevisor::Error::NoMemory => Errno::ENOMEM,
            aster_framevisor::Error::PageFault => Errno::EFAULT,
            aster_framevisor::Error::AccessDenied => Errno::EPERM,
            aster_framevisor::Error::IoError => Errno::EIO,
            aster_framevisor::Error::NotEnoughResources => Errno::EBUSY,
            aster_framevisor::Error::Overflow => Errno::EINVAL,
        };
        Self::new(errno)
    }
}

impl From<(aster_framevisor::Error, usize)> for Error {
    fn from((e, _): (aster_framevisor::Error, usize)) -> Self {
        Self::from(e)
    }
}

/// Convert from aster_framevisor::error::Error (the framevisor-local error type)
impl From<aster_framevisor::error::Error> for Error {
    fn from(e: aster_framevisor::error::Error) -> Self {
        let errno = match e {
            aster_framevisor::error::Error::InvalidArgs => Errno::EINVAL,
            aster_framevisor::error::Error::NoMemory => Errno::ENOMEM,
            aster_framevisor::error::Error::PageFault => Errno::EFAULT,
            aster_framevisor::error::Error::AccessDenied => Errno::EPERM,
            aster_framevisor::error::Error::IoError => Errno::EIO,
            aster_framevisor::error::Error::NotEnoughResources => Errno::EBUSY,
            aster_framevisor::error::Error::Overflow => Errno::EINVAL,
        };
        Self::new(errno)
    }
}

/// Result type for FrameVM operations.
pub type Result<T> = core::result::Result<T, Error>;

#[macro_export]
macro_rules! return_errno {
    ($errno:expr) => {
        return Err($crate::error::Error::new($errno))
    };
}

#[macro_export]
macro_rules! return_errno_with_message {
    ($errno:expr, $msg:expr) => {
        return Err($crate::error::Error::with_message($errno, $msg))
    };
}
