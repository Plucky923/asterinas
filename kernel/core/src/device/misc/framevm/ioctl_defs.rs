// SPDX-License-Identifier: MPL-2.0

use core::str;

pub(super) use framevm_abi::{
    FRAMEVM_API_VERSION, FRAMEVM_BLOCK_READ_ONLY, FRAMEVM_SOCK_MAX_PORTS_PER_DIRECTION,
    FrameVmAssignedPci, FrameVmBlock, FrameVmBytes as FrameVmCmdline, FrameVmCreateVm,
    FrameVmMemoryStatus, FrameVmNet, FrameVmResourceFd, FrameVmSock, FrameVmStatus,
};
use ostd::mm::VmIo;

use crate::{
    context::current_userspace,
    prelude::*,
    util::ioctl::{InData, NoData, OutData, ioc},
};

const MIN_VCPU_COUNT: u32 = 1;
const MAX_VCPU_COUNT: u32 = 4;
const MIN_SHARE: u32 = 2;
const MAX_SHARE: u32 = 262_144;
const MAX_CMDLINE_APPEND_LEN: usize = 4096;
const FRAMEVM_CREATE_KNOWN_FLAGS: u32 = 0;
const FRAMEVM_CMDLINE_KNOWN_FLAGS: u32 = 0;
const FRAMEVM_RESOURCE_KNOWN_FLAGS: u32 = 0;
const FRAMEVM_BLOCK_KNOWN_FLAGS: u32 = FRAMEVM_BLOCK_READ_ONLY;
const FRAMEVM_NET_KNOWN_FLAGS: u32 = 0;
const FRAMEVM_SOCK_KNOWN_FLAGS: u32 = 0;
const FRAMEVM_ASSIGN_PCI_KNOWN_FLAGS: u32 = 0;
const RESERVED_CMDLINE_KEYS: [&str; 3] = [
    "kernel.realtime_base_ns",
    "kernel.monotonic_base_ns",
    "ostd.vcpu_count",
];

pub(super) fn validate_create(request: FrameVmCreateVm) -> Result<()> {
    if request.api_version() != FRAMEVM_API_VERSION {
        return_errno_with_message!(Errno::EINVAL, "unsupported FrameVM API version");
    }
    if !(MIN_VCPU_COUNT..=MAX_VCPU_COUNT).contains(&request.vcpu_count()) {
        return_errno_with_message!(Errno::EINVAL, "invalid FrameVM vCPU count");
    }
    if !(MIN_SHARE..=MAX_SHARE).contains(&request.share()) {
        return_errno_with_message!(Errno::EINVAL, "invalid FrameVM share");
    }
    let memory_limit = request.memory_limit_bytes();
    let page_size = u64::try_from(PAGE_SIZE).map_err(|_| {
        Error::with_message(Errno::EINVAL, "FrameVM page size does not fit the ABI")
    })?;
    if memory_limit == 0 || !memory_limit.is_multiple_of(page_size) {
        return_errno_with_message!(Errno::EINVAL, "invalid FrameVM memory limit");
    }
    if usize::try_from(memory_limit).is_err() {
        return_errno_with_message!(Errno::EINVAL, "FrameVM memory limit overflows usize");
    }
    if request.flags() & !FRAMEVM_CREATE_KNOWN_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM create flags");
    }
    if !request.flags_are_zero() {
        return_errno_with_message!(Errno::EINVAL, "nonzero FrameVM create flags");
    }
    Ok(())
}

pub(super) fn read_cmdline(request: FrameVmCmdline) -> Result<Option<String>> {
    if request.flags() & !FRAMEVM_CMDLINE_KNOWN_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM cmdline flags");
    }

    let len = request.len() as usize;
    if request.is_empty() {
        return Ok(None);
    }
    if len > MAX_CMDLINE_APPEND_LEN {
        return_errno_with_message!(Errno::EINVAL, "FrameVM cmdline append is too long");
    }

    let ptr = usize::try_from(request.ptr()).map_err(|_| {
        Error::with_message(
            Errno::EFAULT,
            "FrameVM cmdline pointer is outside usize range",
        )
    })?;
    let mut bytes = vec![0u8; len];
    current_userspace!().read_bytes(ptr, &mut bytes)?;

    if bytes.contains(&0) {
        return_errno_with_message!(Errno::EINVAL, "FrameVM cmdline contains NUL");
    }

    let append = str::from_utf8(&bytes)
        .map_err(|_| Error::with_message(Errno::EINVAL, "FrameVM cmdline is not UTF-8"))?;
    if !append.is_ascii() {
        return_errno_with_message!(Errno::EINVAL, "FrameVM cmdline is not ASCII");
    }
    reject_reserved_cmdline_keys(append)?;

    Ok(Some(String::from(append)))
}

pub(super) fn validate_block(request: FrameVmBlock) -> Result<()> {
    if request.flags() & !FRAMEVM_BLOCK_KNOWN_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM block flags");
    }
    if !request.reserved_is_zero() {
        return_errno_with_message!(Errno::EINVAL, "nonzero FrameVM block reserved field");
    }
    Ok(())
}

pub(super) fn validate_resource_fd(request: FrameVmResourceFd) -> Result<()> {
    if request.flags() & !FRAMEVM_RESOURCE_KNOWN_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM resource flags");
    }
    if !request.reserved_is_zero() {
        return_errno_with_message!(Errno::EINVAL, "nonzero FrameVM resource reserved field");
    }
    Ok(())
}

pub(super) fn validate_net(request: FrameVmNet) -> Result<()> {
    if request.flags() & !FRAMEVM_NET_KNOWN_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM network flags");
    }
    if !request.reserved_is_zero() {
        return_errno_with_message!(Errno::EINVAL, "nonzero FrameVM network reserved field");
    }
    Ok(())
}

pub(super) fn validate_sock(request: FrameVmSock) -> Result<()> {
    if request.flags() & !FRAMEVM_SOCK_KNOWN_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM Sock flags");
    }
    if !request.reserved_is_zero() {
        return_errno_with_message!(Errno::EINVAL, "nonzero FrameVM Sock reserved field");
    }
    Ok(())
}

pub(super) fn validate_assigned_pci(request: FrameVmAssignedPci) -> Result<()> {
    if request.flags() & !FRAMEVM_ASSIGN_PCI_KNOWN_FLAGS != 0 {
        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM PCI assignment flags");
    }
    if !request.reserved_is_zero() {
        return_errno_with_message!(
            Errno::EINVAL,
            "nonzero FrameVM PCI assignment reserved field"
        );
    }
    if request.segment() != 0 || request.function() != 0 {
        return_errno_with_message!(
            Errno::EINVAL,
            "FrameVM PCI assignment currently requires segment and function zero"
        );
    }
    Ok(())
}

fn reject_reserved_cmdline_keys(append: &str) -> Result<()> {
    for token in append.split_ascii_whitespace() {
        let key = token.split_once('=').map(|(key, _)| key).unwrap_or(token);
        if RESERVED_CMDLINE_KEYS.contains(&key) {
            return_errno_with_message!(
                Errno::EINVAL,
                "FrameVM cmdline append overrides a reserved key"
            );
        }
    }
    Ok(())
}

pub(super) type CreateVm = ioc!(
    FRAMEVM_CREATE_VM,
    b'F',
    0x01,
    InData<FrameVmCreateVm>
);
pub(super) type StartVm = ioc!(
    FRAMEVM_START,
    b'F',
    0x02,
    NoData
);
pub(super) type StopVm = ioc!(
    FRAMEVM_STOP,
    b'F',
    0x03,
    NoData
);
pub(super) type GetConsoleFd = ioc!(
    FRAMEVM_GET_CONSOLE_FD,
    b'F',
    0x04,
    NoData
);
pub(super) type GetStatus = ioc!(
    FRAMEVM_GET_STATUS,
    b'F',
    0x06,
    OutData<FrameVmStatus>
);
pub(super) type GetMemoryStatus = ioc!(
    FRAMEVM_GET_MEMORY_STATUS,
    b'F',
    0x0f,
    OutData<FrameVmMemoryStatus>
);
pub(super) type SetCmdline = ioc!(
    FRAMEVM_SET_CMDLINE,
    b'F',
    0x07,
    InData<FrameVmCmdline>
);
pub(super) type SetArtifact = ioc!(
    FRAMEVM_SET_ARTIFACT,
    b'F',
    0x08,
    InData<FrameVmResourceFd>
);
pub(super) type AddConsole = ioc!(
    FRAMEVM_ADD_CONSOLE,
    b'F',
    0x09,
    NoData
);
pub(super) type AddRng = ioc!(
    FRAMEVM_ADD_RNG,
    b'F',
    0x0a,
    NoData
);
pub(super) type AddBlock = ioc!(
    FRAMEVM_ADD_BLOCK,
    b'F',
    0x0b,
    InData<FrameVmBlock>
);
pub(super) type AddSock = ioc!(
    FRAMEVM_ADD_SOCK,
    b'F',
    0x0c,
    InData<FrameVmSock>
);
pub(super) type AddNet = ioc!(
    FRAMEVM_ADD_NET,
    b'F',
    0x0d,
    InData<FrameVmNet>
);
pub(super) type AssignPci = ioc!(
    FRAMEVM_ASSIGN_PCI,
    b'F',
    0x0e,
    InData<FrameVmAssignedPci>
);
