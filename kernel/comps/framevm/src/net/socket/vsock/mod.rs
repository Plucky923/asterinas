// SPDX-License-Identifier: MPL-2.0

//! Linux `AF_VSOCK` socket support.

mod addr;
mod port;
mod stream;

pub use addr::{
    AF_VSOCK, CSocketAddrVm, VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_LOCAL, VMADDR_PORT_ANY,
    VsockSocketAddr,
};
pub use stream::VsockStreamSocket;
