// SPDX-License-Identifier: MPL-2.0

//! Fixed-layout types for the versioned `/dev/framevm` management ABI.

#![no_std]
#![deny(unsafe_code)]

#[macro_use]
extern crate ostd_pod;

/// Identifies the memory-domain creation ABI.
pub const FRAMEVM_API_VERSION: u32 = 2;

/// Identifies the FrameVM ioctl family.
pub const FRAMEVM_IOCTL_MAGIC: u8 = b'F';

/// Identifies `FRAMEVM_CREATE_VM`.
pub const FRAMEVM_CREATE_VM_NR: u8 = 0x01;
/// Identifies `FRAMEVM_START`.
pub const FRAMEVM_START_NR: u8 = 0x02;
/// Identifies `FRAMEVM_STOP`.
pub const FRAMEVM_STOP_NR: u8 = 0x03;
/// Identifies `FRAMEVM_GET_CONSOLE_FD`.
pub const FRAMEVM_GET_CONSOLE_FD_NR: u8 = 0x04;
/// Identifies `FRAMEVM_GET_STATUS`.
pub const FRAMEVM_GET_STATUS_NR: u8 = 0x06;
/// Identifies `FRAMEVM_SET_CMDLINE`.
pub const FRAMEVM_SET_CMDLINE_NR: u8 = 0x07;
/// Identifies `FRAMEVM_SET_ARTIFACT`.
pub const FRAMEVM_SET_ARTIFACT_NR: u8 = 0x08;
/// Identifies `FRAMEVM_ADD_CONSOLE`.
pub const FRAMEVM_ADD_CONSOLE_NR: u8 = 0x09;
/// Identifies `FRAMEVM_ADD_RNG`.
pub const FRAMEVM_ADD_RNG_NR: u8 = 0x0a;
/// Identifies `FRAMEVM_ADD_BLOCK`.
pub const FRAMEVM_ADD_BLOCK_NR: u8 = 0x0b;
/// Identifies `FRAMEVM_ADD_SOCK`.
pub const FRAMEVM_ADD_SOCK_NR: u8 = 0x0c;
/// Identifies `FRAMEVM_ADD_NET`.
pub const FRAMEVM_ADD_NET_NR: u8 = 0x0d;
/// Identifies `FRAMEVM_ASSIGN_PCI`.
pub const FRAMEVM_ASSIGN_PCI_NR: u8 = 0x0e;
/// Identifies `FRAMEVM_GET_MEMORY_STATUS`.
pub const FRAMEVM_GET_MEMORY_STATUS_NR: u8 = 0x0f;

/// Marks a block device as read-only.
pub const FRAMEVM_BLOCK_READ_ONLY: u32 = 1 << 0;

/// Limits each immutable FrameV Sock port allowlist.
pub const FRAMEVM_SOCK_MAX_PORTS_PER_DIRECTION: u32 = 16;

/// Identifies a draft that has not started.
pub const FRAMEVM_STATE_CREATED: u32 = 0;
/// Identifies a start transaction in progress.
pub const FRAMEVM_STATE_STARTING: u32 = 1;
/// Identifies a running VM.
pub const FRAMEVM_STATE_RUNNING: u32 = 2;
/// Identifies a terminal VM and its exit code is stored in `code`.
pub const FRAMEVM_STATE_EXITED: u32 = 3;

/// Creates a bare FrameVM configuration draft.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmCreateVm {
    api_version: u32,
    vcpu_count: u32,
    share: u32,
    flags: u32,
    memory_limit_bytes: [u32; 2],
}

impl FrameVmCreateVm {
    /// Creates a request with an explicit memory limit.
    pub const fn new_with_memory_limit(
        vcpu_count: u32,
        share: u32,
        memory_limit_bytes: u64,
    ) -> Self {
        Self {
            api_version: FRAMEVM_API_VERSION,
            vcpu_count,
            share,
            flags: 0,
            memory_limit_bytes: [memory_limit_bytes as u32, (memory_limit_bytes >> 32) as u32],
        }
    }

    /// Returns the requested ABI version.
    pub const fn api_version(self) -> u32 {
        self.api_version
    }

    /// Returns the requested vCPU count.
    pub const fn vcpu_count(self) -> u32 {
        self.vcpu_count
    }

    /// Returns the requested scheduler share.
    pub const fn share(self) -> u32 {
        self.share
    }

    /// Returns the requested page-backed memory limit in bytes.
    pub const fn memory_limit_bytes(self) -> u64 {
        self.memory_limit_bytes[0] as u64 | ((self.memory_limit_bytes[1] as u64) << 32)
    }

    /// Returns creation flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Returns whether this request carries no unsupported flags.
    pub const fn flags_are_zero(self) -> bool {
        self.flags == 0
    }
}

/// Describes a bounded userspace byte string copied at ioctl entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmBytes {
    ptr: u64,
    len: u32,
    flags: u32,
}

impl FrameVmBytes {
    /// Creates a byte-string request.
    pub const fn new(ptr: u64, len: u32) -> Self {
        Self { ptr, len, flags: 0 }
    }

    /// Returns the userspace address.
    pub const fn ptr(self) -> u64 {
        self.ptr
    }

    /// Returns the byte length.
    pub const fn len(self) -> u32 {
        self.len
    }

    /// Returns whether the byte string is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns request flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }
}

/// Captures one resource file descriptor into a VM draft.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmResourceFd {
    fd: i32,
    flags: u32,
    reserved: u64,
}

impl FrameVmResourceFd {
    /// Creates a resource request.
    pub const fn new(fd: i32, flags: u32) -> Self {
        Self {
            fd,
            flags,
            reserved: 0,
        }
    }

    /// Returns the resource file descriptor.
    pub const fn fd(self) -> i32 {
        self.fd
    }

    /// Returns resource flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Returns whether every reserved field is zero.
    pub const fn reserved_is_zero(self) -> bool {
        self.reserved == 0
    }
}

/// Adds one block resource with a stable draft-local identifier.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmBlock {
    fd: i32,
    device_id: u32,
    flags: u32,
    reserved: u32,
}

impl FrameVmBlock {
    /// Creates a block-resource request.
    pub const fn new(fd: i32, device_id: u32, flags: u32) -> Self {
        Self {
            fd,
            device_id,
            flags,
            reserved: 0,
        }
    }

    /// Returns the block image file descriptor.
    pub const fn fd(self) -> i32 {
        self.fd
    }

    /// Returns the draft-local block identifier.
    pub const fn device_id(self) -> u32 {
        self.device_id
    }

    /// Returns block flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Returns whether every reserved field is zero.
    pub const fn reserved_is_zero(self) -> bool {
        self.reserved == 0
    }
}

/// Adds one connected Unix datagram network endpoint.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmNet {
    fd: i32,
    mac_address: [u8; 6],
    mtu: u16,
    flags: u32,
    reserved: u32,
}

/// Adds one FrameV Sock function with an immutable CID and port policy.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmSock {
    guest_cid: u32,
    flags: u32,
    guest_connect_host_ports_ptr: u64,
    host_connect_guest_ports_ptr: u64,
    guest_connect_host_ports_len: u32,
    host_connect_guest_ports_len: u32,
    reserved: [u64; 2],
}

impl FrameVmSock {
    /// Creates a socket-function request borrowing both policy lists.
    ///
    /// Returns `None` when either list exceeds the revision-1 policy limit or
    /// cannot be represented by the fixed-width ABI length fields.
    pub fn new(
        guest_cid: u32,
        guest_connect_host_ports: &[u32],
        host_connect_guest_ports: &[u32],
    ) -> Option<Self> {
        let max_ports = usize::try_from(FRAMEVM_SOCK_MAX_PORTS_PER_DIRECTION).ok()?;
        if guest_connect_host_ports.len() > max_ports || host_connect_guest_ports.len() > max_ports
        {
            return None;
        }

        let guest_connect_host_ports_len = u32::try_from(guest_connect_host_ports.len()).ok()?;
        let host_connect_guest_ports_len = u32::try_from(host_connect_guest_ports.len()).ok()?;

        Some(Self {
            guest_cid,
            flags: 0,
            guest_connect_host_ports_ptr: slice_ptr(guest_connect_host_ports),
            host_connect_guest_ports_ptr: slice_ptr(host_connect_guest_ports),
            guest_connect_host_ports_len,
            host_connect_guest_ports_len,
            reserved: [0; 2],
        })
    }

    /// Returns the requested guest CID.
    pub const fn guest_cid(self) -> u32 {
        self.guest_cid
    }

    /// Returns socket-function flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Returns the userspace address of Guest-to-Host allowed ports.
    pub const fn guest_connect_host_ports_ptr(self) -> u64 {
        self.guest_connect_host_ports_ptr
    }

    /// Returns the number of Guest-to-Host allowed ports.
    pub const fn guest_connect_host_ports_len(self) -> u32 {
        self.guest_connect_host_ports_len
    }

    /// Returns the userspace address of Host-to-Guest allowed ports.
    pub const fn host_connect_guest_ports_ptr(self) -> u64 {
        self.host_connect_guest_ports_ptr
    }

    /// Returns the number of Host-to-Guest allowed ports.
    pub const fn host_connect_guest_ports_len(self) -> u32 {
        self.host_connect_guest_ports_len
    }

    /// Returns whether every reserved field is zero.
    pub const fn reserved_is_zero(self) -> bool {
        self.reserved[0] == 0 && self.reserved[1] == 0
    }
}

fn slice_ptr(values: &[u32]) -> u64 {
    if values.is_empty() {
        0
    } else {
        values.as_ptr() as u64
    }
}

impl FrameVmNet {
    /// Creates a network-endpoint request with no flags.
    pub const fn new(fd: i32, mac_address: [u8; 6], mtu: u16) -> Self {
        Self {
            fd,
            mac_address,
            mtu,
            flags: 0,
            reserved: 0,
        }
    }

    /// Returns the connected endpoint file descriptor.
    pub const fn fd(self) -> i32 {
        self.fd
    }

    /// Returns the immutable guest Ethernet address.
    pub const fn mac_address(self) -> [u8; 6] {
        self.mac_address
    }

    /// Returns the requested Ethernet MTU.
    pub const fn mtu(self) -> u16 {
        self.mtu
    }

    /// Returns network endpoint flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Returns whether every reserved field is zero.
    pub const fn reserved_is_zero(self) -> bool {
        self.reserved == 0
    }
}

/// Requests assignment of one boot-reserved physical PCI function.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmAssignedPci {
    segment: u16,
    bus: u8,
    device_function: u8,
    flags: u32,
    reserved: u64,
}

impl FrameVmAssignedPci {
    /// Creates a PCI assignment request.
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Option<Self> {
        if device >= 32 || function >= 8 {
            return None;
        }
        Some(Self {
            segment,
            bus,
            device_function: device << 3 | function,
            flags: 0,
            reserved: 0,
        })
    }

    /// Returns the PCI segment.
    pub const fn segment(self) -> u16 {
        self.segment
    }

    /// Returns the PCI bus.
    pub const fn bus(self) -> u8 {
        self.bus
    }

    /// Returns the PCI device number.
    pub const fn device(self) -> u8 {
        self.device_function >> 3
    }

    /// Returns the PCI function number.
    pub const fn function(self) -> u8 {
        self.device_function & 0x07
    }

    /// Returns assignment flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Returns whether every reserved field is zero.
    pub const fn reserved_is_zero(self) -> bool {
        self.reserved == 0
    }
}

/// Reports one FrameVM control snapshot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmStatus {
    state: u32,
    code: i32,
}

/// Reports the memory-domain counters for one FrameVM.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FrameVmMemoryStatus {
    limit_bytes: u64,
    committed_bytes: u64,
    reserved_bytes: u64,
    reusable_bytes: u64,
    active_bytes: u64,
    oom_count: u64,
    reclaim_count: u64,
}

impl FrameVmMemoryStatus {
    /// Creates a memory status snapshot from validated counters.
    pub const fn new(
        limit_bytes: u64,
        committed_bytes: u64,
        reserved_bytes: u64,
        reusable_bytes: u64,
        active_bytes: u64,
        oom_count: u64,
        reclaim_count: u64,
    ) -> Self {
        Self {
            limit_bytes,
            committed_bytes,
            reserved_bytes,
            reusable_bytes,
            active_bytes,
            oom_count,
            reclaim_count,
        }
    }

    /// Returns the configured memory limit.
    pub const fn limit_bytes(self) -> u64 {
        self.limit_bytes
    }

    /// Returns committed physical bytes.
    pub const fn committed_bytes(self) -> u64 {
        self.committed_bytes
    }

    /// Returns in-flight reserved bytes.
    pub const fn reserved_bytes(self) -> u64 {
        self.reserved_bytes
    }

    /// Returns reusable cached bytes.
    pub const fn reusable_bytes(self) -> u64 {
        self.reusable_bytes
    }

    /// Returns active bytes.
    pub const fn active_bytes(self) -> u64 {
        self.active_bytes
    }

    /// Returns the cumulative OOM count.
    pub const fn oom_count(self) -> u64 {
        self.oom_count
    }

    /// Returns the cumulative reclaim count.
    pub const fn reclaim_count(self) -> u64 {
        self.reclaim_count
    }
}

impl FrameVmStatus {
    /// Creates a status snapshot from validated kernel values.
    pub const fn new(state: u32, code: i32) -> Self {
        Self { state, code }
    }

    /// Returns the lifecycle-state discriminator.
    pub const fn state(self) -> u32 {
        self.state
    }

    /// Returns the guest or Host exit code.
    pub const fn code(self) -> i32 {
        self.code
    }
}

const _: () = assert!(size_of::<FrameVmCreateVm>() == 24);
const _: () = assert!(align_of::<FrameVmCreateVm>() == 4);
const _: () = assert!(size_of::<FrameVmBytes>() == 16);
const _: () = assert!(align_of::<FrameVmBytes>() == 8);
const _: () = assert!(size_of::<FrameVmResourceFd>() == 16);
const _: () = assert!(align_of::<FrameVmResourceFd>() == 8);
const _: () = assert!(size_of::<FrameVmBlock>() == 16);
const _: () = assert!(align_of::<FrameVmBlock>() == 4);
const _: () = assert!(size_of::<FrameVmNet>() == 20);
const _: () = assert!(align_of::<FrameVmNet>() == 4);
const _: () = assert!(size_of::<FrameVmSock>() == 48);
const _: () = assert!(align_of::<FrameVmSock>() == 8);
const _: () = assert!(size_of::<FrameVmAssignedPci>() == 16);
const _: () = assert!(align_of::<FrameVmAssignedPci>() == 8);
const _: () = assert!(size_of::<FrameVmStatus>() == 8);
const _: () = assert!(align_of::<FrameVmStatus>() == 4);
const _: () = assert!(size_of::<FrameVmMemoryStatus>() == 56);
const _: () = assert!(align_of::<FrameVmMemoryStatus>() == 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_pci_rejects_invalid_device_or_function() {
        assert!(FrameVmAssignedPci::new(0, 0, 31, 7).is_some());
        assert!(FrameVmAssignedPci::new(0, 0, 32, 0).is_none());
        assert!(FrameVmAssignedPci::new(0, 0, 0, 8).is_none());
    }

    #[test]
    fn assigned_pci_round_trips_bdf() {
        let request = FrameVmAssignedPci::new(3, 0x81, 0x1f, 7).unwrap();
        assert_eq!(request.segment(), 3);
        assert_eq!(request.bus(), 0x81);
        assert_eq!(request.device(), 0x1f);
        assert_eq!(request.function(), 7);
    }

    #[test]
    fn network_request_preserves_the_endpoint_and_configuration() {
        let request = FrameVmNet::new(17, [0x02, 0, 0, 0, 0, 1], 1_500);

        assert_eq!(request.fd(), 17);
        assert_eq!(request.mac_address(), [0x02, 0, 0, 0, 0, 1]);
        assert_eq!(request.mtu(), 1_500);
        assert_eq!(request.flags(), 0);
        assert!(request.reserved_is_zero());
    }

    #[test]
    fn sock_request_checks_policy_lengths_before_encoding() {
        let guest_ports = [1024, 2048];
        let host_ports = [4096];
        let request = FrameVmSock::new(3, &guest_ports, &host_ports).unwrap();

        assert_eq!(request.guest_cid(), 3);
        assert_eq!(request.guest_connect_host_ports_len(), 2);
        assert_eq!(request.host_connect_guest_ports_len(), 1);
        assert_eq!(
            request.guest_connect_host_ports_ptr(),
            guest_ports.as_ptr() as u64
        );
        assert_eq!(
            request.host_connect_guest_ports_ptr(),
            host_ports.as_ptr() as u64
        );
        assert!(request.reserved_is_zero());

        let too_many_ports = [0_u32; FRAMEVM_SOCK_MAX_PORTS_PER_DIRECTION as usize + 1];
        assert!(FrameVmSock::new(3, &too_many_ports, &[]).is_none());
        assert!(FrameVmSock::new(3, &[], &too_many_ports).is_none());
    }

    #[test]
    fn create_request_round_trips_memory_limit_without_changing_layout() {
        let request = FrameVmCreateVm::new_with_memory_limit(2, 128, 8 * 1024 * 1024);
        assert_eq!(request.api_version(), FRAMEVM_API_VERSION);
        assert_eq!(request.memory_limit_bytes(), 8 * 1024 * 1024);
        assert!(request.flags_are_zero());
    }
}
