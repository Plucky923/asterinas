// SPDX-License-Identifier: MPL-2.0

use alloc::vec;
use core::str;

use ostd::mm::VmIo;

use crate::{
    context::current_userspace,
    fs::file::file_table::FileDesc,
    prelude::*,
    util::ioctl::{InData, NoData, OutData, ioc},
    vmm::{
        FrameVmFailureClass, FrameVmLifecycleState, FrameVmLifecycleStatus, FrameVmTerminalReason,
    },
};

const _: () = assert!(size_of::<FrameVmCreateVm>() == 16);
const _: () = assert!(align_of::<FrameVmCreateVm>() == 4);
const _: () = assert!(size_of::<FrameVmCmdline>() == 16);
const _: () = assert!(align_of::<FrameVmCmdline>() == 8);
const _: () = assert!(size_of::<FrameVmStatus>() == 32);
const _: () = assert!(align_of::<FrameVmStatus>() == 8);

const MIN_VCPU_COUNT: u32 = 1;
const MAX_VCPU_COUNT: u32 = 4;
const MIN_SHARE: u32 = 2;
const MAX_SHARE: u32 = 262_144;
const MAX_CMDLINE_APPEND_LEN: usize = 4096;
const FRAMEVM_CMDLINE_KNOWN_FLAGS: u32 = 0;
const RESERVED_CMDLINE_KEYS: [&str; 4] = [
    "kernel.realtime_base_ns",
    "kernel.monotonic_base_ns",
    "ostd.vcpu_count",
    "framev.devices",
];

pub(super) const FRAMEVM_CREATE_HAS_DRIVE: u32 = 1 << 0;
pub(super) const FRAMEVM_CREATE_DRIVE_READONLY: u32 = 1 << 1;
const FRAMEVM_CREATE_KNOWN_FLAGS: u32 = FRAMEVM_CREATE_HAS_DRIVE | FRAMEVM_CREATE_DRIVE_READONLY;

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct FrameVmCreateVm {
    vcpu_count: u32,
    share: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct FrameVmCmdline {
    ptr: u64,
    len: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct FrameVmStatus {
    state: u32,
    terminal_reason: u32,
    status_code: i32,
    failure_class: u32,
    vm_id: u64,
    reserved: u64,
}

impl From<FrameVmLifecycleStatus> for FrameVmStatus {
    fn from(status: FrameVmLifecycleStatus) -> Self {
        Self {
            state: status.state() as u32,
            terminal_reason: status.terminal_reason() as u32,
            status_code: status.status_code(),
            failure_class: status.failure_class() as u32,
            vm_id: status.vm_id().map(u64::from).unwrap_or(u64::MAX),
            reserved: 0,
        }
    }
}

const _: () = assert!(FrameVmLifecycleState::Created as u32 == 0);
const _: () = assert!(FrameVmLifecycleState::Starting as u32 == 1);
const _: () = assert!(FrameVmLifecycleState::Running as u32 == 2);
const _: () = assert!(FrameVmLifecycleState::ExitedSuccess as u32 == 3);
const _: () = assert!(FrameVmLifecycleState::ExitedFailure as u32 == 4);
const _: () = assert!(FrameVmLifecycleState::RestartRequested as u32 == 5);
const _: () = assert!(FrameVmLifecycleState::StoppedByHost as u32 == 6);
const _: () = assert!(FrameVmLifecycleState::PanicFailure as u32 == 7);
const _: () = assert!(FrameVmLifecycleState::Destroyed as u32 == 8);

const _: () = assert!(FrameVmTerminalReason::None as u32 == 0);
const _: () = assert!(FrameVmTerminalReason::GuestExit as u32 == 1);
const _: () = assert!(FrameVmTerminalReason::Poweroff as u32 == 2);
const _: () = assert!(FrameVmTerminalReason::Restart as u32 == 3);
const _: () = assert!(FrameVmTerminalReason::HostStop as u32 == 4);
const _: () = assert!(FrameVmTerminalReason::FdClose as u32 == 5);
const _: () = assert!(FrameVmTerminalReason::Panic as u32 == 6);
const _: () = assert!(FrameVmTerminalReason::SetupFailed as u32 == 7);

const _: () = assert!(FrameVmFailureClass::None as u32 == 0);
const _: () = assert!(FrameVmFailureClass::GuestExitCode as u32 == 1);
const _: () = assert!(FrameVmFailureClass::Panic as u32 == 2);
const _: () = assert!(FrameVmFailureClass::Setup as u32 == 3);
const _: () = assert!(FrameVmFailureClass::HostStop as u32 == 4);

impl FrameVmCreateVm {
    pub(super) const fn vcpu_count(self) -> usize {
        self.vcpu_count as usize
    }

    pub(super) const fn share(self) -> u32 {
        self.share
    }

    pub(super) const fn has_drive(self) -> bool {
        self.flags & FRAMEVM_CREATE_HAS_DRIVE != 0
    }

    pub(super) const fn drive_readonly(self) -> bool {
        self.flags & FRAMEVM_CREATE_DRIVE_READONLY != 0
    }

    pub(super) fn drive_fd(self) -> Result<Option<FileDesc>> {
        if !self.has_drive() {
            return Ok(None);
        }
        let raw_fd = i32::try_from(self.reserved).map_err(|_| {
            Error::with_message(Errno::EINVAL, "FrameVM drive fd is outside int range")
        })?;
        FileDesc::try_from(raw_fd).map(Some)
    }

    pub(super) fn validate(&self) -> Result<()> {
        if !(MIN_VCPU_COUNT..=MAX_VCPU_COUNT).contains(&self.vcpu_count) {
            return_errno_with_message!(Errno::EINVAL, "invalid FrameVM vCPU count");
        }
        if !(MIN_SHARE..=MAX_SHARE).contains(&self.share) {
            return_errno_with_message!(Errno::EINVAL, "invalid FrameVM share");
        }
        if self.flags & !FRAMEVM_CREATE_KNOWN_FLAGS != 0 {
            return_errno_with_message!(Errno::EINVAL, "unknown FrameVM create flags");
        }
        if self.drive_readonly() && !self.has_drive() {
            return_errno_with_message!(
                Errno::EINVAL,
                "readonly FrameVM drive flag requires a drive"
            );
        }
        if !self.has_drive() && self.reserved != 0 {
            return_errno_with_message!(Errno::EINVAL, "nonzero FrameVM create reserved field");
        }
        self.drive_fd()?;
        Ok(())
    }
}

impl FrameVmCmdline {
    pub(super) fn read_append(self) -> Result<Option<String>> {
        if self.flags & !FRAMEVM_CMDLINE_KNOWN_FLAGS != 0 {
            return_errno_with_message!(Errno::EINVAL, "unknown FrameVM cmdline flags");
        }

        let len = self.len as usize;
        if len == 0 {
            return Ok(None);
        }
        if len > MAX_CMDLINE_APPEND_LEN {
            return_errno_with_message!(Errno::EINVAL, "FrameVM cmdline append is too long");
        }

        let ptr = usize::try_from(self.ptr).map_err(|_| {
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

// Reference: OpenSpec `refactor-framevm-task-group-scheduling` FrameVM ioctl ABI.

pub(super) type CreateVm     = ioc!(FRAMEVM_CREATE_VM,      b'F', 0x01, InData<FrameVmCreateVm>);
pub(super) type StartVm      = ioc!(FRAMEVM_START,          b'F', 0x02, NoData);
pub(super) type StopVm       = ioc!(FRAMEVM_STOP,           b'F', 0x03, NoData);
pub(super) type GetConsoleFd = ioc!(FRAMEVM_GET_CONSOLE_FD, b'F', 0x04, NoData);
pub(super) type SetCmdline   = ioc!(FRAMEVM_SET_CMDLINE,    b'F', 0x07, InData<FrameVmCmdline>);
pub(super) type GetStatus    = ioc!(FRAMEVM_GET_STATUS,     b'F', 0x06, OutData<FrameVmStatus>);
