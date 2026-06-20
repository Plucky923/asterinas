//! Address conversions for host-side FrameVsock sockets.

pub use aster_framevsock::FrameVsockAddr;

use crate::{
    net::socket::{util::SocketAddr, vsock::VsockSocketAddr},
    prelude::*,
};

pub fn try_from_socketaddr(value: SocketAddr) -> Result<FrameVsockAddr> {
    let SocketAddr::Vsock(addr) = value else {
        return_errno_with_message!(Errno::EINVAL, "invalid vsock socket addr");
    };
    Ok(addr.into())
}

pub fn to_socketaddr(value: FrameVsockAddr) -> Result<SocketAddr> {
    Ok(SocketAddr::Vsock(to_vsock_addr(value)?))
}

fn to_vsock_addr(value: FrameVsockAddr) -> Result<VsockSocketAddr> {
    let cid = if value.cid == VMADDR_CID_ANY {
        u32::MAX
    } else {
        u32::try_from(value.cid)
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid vsock cid"))?
    };
    Ok(VsockSocketAddr {
        cid,
        port: value.port,
    })
}

impl From<VsockSocketAddr> for FrameVsockAddr {
    fn from(value: VsockSocketAddr) -> Self {
        Self {
            cid: value.cid.into(),
            port: value.port,
        }
    }
}

/// The vSocket equivalent of INADDR_ANY.
pub const VMADDR_CID_ANY: u64 = u64::MAX;
/// Use this as the destination CID in an address when referring to the host (any process other than the hypervisor).
pub const VMADDR_CID_HOST: u64 = 2;
/// Bind to any available port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn converts_carrier_addr_to_linux_vsock_addr() {
        let socket_addr = to_socketaddr(FrameVsockAddr::new(3, 1024)).unwrap();
        let SocketAddr::Vsock(vsock_addr) = socket_addr else {
            panic!("expected vsock socket address");
        };

        assert_eq!(vsock_addr.cid, 3);
        assert_eq!(vsock_addr.port, 1024);
    }

    #[ktest]
    fn converts_any_carrier_cid_to_linux_any_cid() {
        let socket_addr = to_socketaddr(FrameVsockAddr::any()).unwrap();
        let SocketAddr::Vsock(vsock_addr) = socket_addr else {
            panic!("expected vsock socket address");
        };

        assert_eq!(vsock_addr.cid, u32::MAX);
        assert_eq!(vsock_addr.port, VMADDR_PORT_ANY);
    }

    #[ktest]
    fn rejects_non_linux_visible_carrier_cid() {
        let error = to_socketaddr(FrameVsockAddr::new(u64::from(u32::MAX) + 1, 1024)).unwrap_err();

        assert_eq!(error.error(), Errno::EINVAL);
    }
}
