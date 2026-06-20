// SPDX-License-Identifier: MPL-2.0

//! Linux `AF_UNIX` socket support.

mod stream;

pub use stream::UnixStreamSocket;

/// `AF_UNIX`.
pub const AF_UNIX: i32 = 1;

/// A Unix-domain socket address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixSocketAddr {
    Unnamed,
}
