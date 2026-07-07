// SPDX-License-Identifier: MPL-2.0

//! Linux `AF_VSOCK` socket support.

mod addr;
mod stream;
mod transport;

pub use addr::{
    AF_VSOCK, CSocketAddrVm, VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_LOCAL, VMADDR_PORT_ANY,
    VsockSocketAddr,
};
pub use stream::VsockStreamSocket;

use crate::error::{Errno, Error, Result};

/// Initializes the default `framev-sock` frontend.
pub fn init() -> Result<()> {
    let sock = framev_bus::sock().map_err(map_frontend_error)?;
    framev_sock_frontend::activate().map_err(map_frontend_error)?;
    stream::init_rx_taskless();
    framev_sock_frontend::install_rx_callback(stream::schedule_rx_notification)
        .map_err(map_frontend_error)?;
    ostd::early_println!("use sockets provided by FrameV device {:?}", sock.id());
    Ok(())
}

fn map_frontend_error(error: framev_bus::FrameVBusError) -> Error {
    Error::with_message(Errno::EINVAL, error.message())
}
