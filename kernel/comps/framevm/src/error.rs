// SPDX-License-Identifier: MPL-2.0

//! Error types for the kernel image.

/// POSIX-compatible error numbers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    ESRCH = 3,
    EIO = 5,
    EBADF = 9,
    ECHILD = 10,
    EACCES = 13,
    EAGAIN = 11,
    ENOMEM = 12,
    EFAULT = 14,
    EBUSY = 16,
    EEXIST = 17,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    EMFILE = 24,
    ENOTTY = 25,
    EFBIG = 27,
    ESPIPE = 29,
    EPIPE = 32,
    ERANGE = 34,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
    ETIME = 62,
    EOVERFLOW = 75,
    ENOTSOCK = 88,
    EMSGSIZE = 90,
    ENOPROTOOPT = 92,
    ESOCKTNOSUPPORT = 94,
    EOPNOTSUPP = 95,
    EAFNOSUPPORT = 97,
    EADDRINUSE = 98,
    EADDRNOTAVAIL = 99,
    ENETUNREACH = 101,
    ECONNRESET = 104,
    EISCONN = 106,
    ENOTCONN = 107,
    ETIMEDOUT = 110,
    ECONNREFUSED = 111,
    EALREADY = 114,
    EINPROGRESS = 115,
}

/// Error type for kernel-image operations.
#[derive(Debug, Clone, Copy)]
pub struct Error {
    errno: Errno,
    #[expect(dead_code)]
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

/// Convert from `ostd::Error`.
impl From<ostd::Error> for Error {
    fn from(e: ostd::Error) -> Self {
        let errno = match e {
            ostd::Error::InvalidArgs => Errno::EINVAL,
            ostd::Error::NoMemory => Errno::ENOMEM,
            ostd::Error::PageFault => Errno::EFAULT,
            ostd::Error::AccessDenied => Errno::EPERM,
            ostd::Error::IoError => Errno::EIO,
            ostd::Error::NotEnoughResources => Errno::EBUSY,
            ostd::Error::Overflow => Errno::EOVERFLOW,
        };
        Self::new(errno)
    }
}

impl From<(ostd::Error, usize)> for Error {
    fn from((e, _): (ostd::Error, usize)) -> Self {
        Self::from(e)
    }
}

/// Result type for kernel-image operations.
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
