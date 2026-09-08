//! Safe ownership wrapper for the versioned `/dev/framevm` ABI.

use std::{
    fs::{File, OpenOptions},
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::Path,
    sync::atomic::{AtomicI32, Ordering},
};

use framevm_abi::{
    FRAMEVM_ADD_BLOCK_NR, FRAMEVM_ADD_CONSOLE_NR, FRAMEVM_ADD_NET_NR, FRAMEVM_ADD_RNG_NR,
    FRAMEVM_ADD_SOCK_NR, FRAMEVM_ASSIGN_PCI_NR, FRAMEVM_BLOCK_READ_ONLY, FRAMEVM_CREATE_VM_NR,
    FRAMEVM_GET_CONSOLE_FD_NR, FRAMEVM_GET_STATUS_NR, FRAMEVM_IOCTL_MAGIC, FRAMEVM_SET_ARTIFACT_NR,
    FRAMEVM_SET_CMDLINE_NR, FRAMEVM_START_NR, FRAMEVM_STOP_NR, FrameVmAssignedPci, FrameVmBlock,
    FrameVmBytes, FrameVmCreateVm, FrameVmNet, FrameVmResourceFd, FrameVmSock, FrameVmStatus,
};

const FRAMEVM_DEVICE: &str = "/dev/framevm";
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioctl_command<T>(direction: u32, number: u8) -> libc::c_ulong {
    ((direction << IOC_DIRSHIFT)
        | ((FRAMEVM_IOCTL_MAGIC as u32) << IOC_TYPESHIFT)
        | ((number as u32) << IOC_NRSHIFT)
        | ((mem::size_of::<T>() as u32) << IOC_SIZESHIFT)) as libc::c_ulong
}

const fn no_data_command(number: u8) -> libc::c_ulong {
    ioctl_command::<()>(IOC_NONE, number)
}

const CREATE_VM: libc::c_ulong = ioctl_command::<FrameVmCreateVm>(IOC_WRITE, FRAMEVM_CREATE_VM_NR);
const START: libc::c_ulong = no_data_command(FRAMEVM_START_NR);
const STOP: libc::c_ulong = no_data_command(FRAMEVM_STOP_NR);
const GET_CONSOLE_FD: libc::c_ulong = no_data_command(FRAMEVM_GET_CONSOLE_FD_NR);
const GET_STATUS: libc::c_ulong = ioctl_command::<FrameVmStatus>(IOC_READ, FRAMEVM_GET_STATUS_NR);
const SET_CMDLINE: libc::c_ulong = ioctl_command::<FrameVmBytes>(IOC_WRITE, FRAMEVM_SET_CMDLINE_NR);
const SET_ARTIFACT: libc::c_ulong =
    ioctl_command::<FrameVmResourceFd>(IOC_WRITE, FRAMEVM_SET_ARTIFACT_NR);
const ADD_CONSOLE: libc::c_ulong = no_data_command(FRAMEVM_ADD_CONSOLE_NR);
const ADD_RNG: libc::c_ulong = no_data_command(FRAMEVM_ADD_RNG_NR);
const ADD_BLOCK: libc::c_ulong = ioctl_command::<FrameVmBlock>(IOC_WRITE, FRAMEVM_ADD_BLOCK_NR);
const ADD_SOCK: libc::c_ulong = ioctl_command::<FrameVmSock>(IOC_WRITE, FRAMEVM_ADD_SOCK_NR);
const ADD_NET: libc::c_ulong = ioctl_command::<FrameVmNet>(IOC_WRITE, FRAMEVM_ADD_NET_NR);
const ASSIGN_PCI: libc::c_ulong =
    ioctl_command::<FrameVmAssignedPci>(IOC_WRITE, FRAMEVM_ASSIGN_PCI_NR);

static TERMINATION_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_termination_signal(signal: libc::c_int) {
    TERMINATION_SIGNAL.store(signal, Ordering::Relaxed);
}

pub(crate) struct FrameVmController {
    file: File,
}

impl FrameVmController {
    pub(crate) fn open() -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(FRAMEVM_DEVICE)
            .map(|file| Self { file })
    }

    pub(crate) fn create(
        &self,
        vcpu_count: u32,
        share: u32,
        memory_limit_bytes: u64,
    ) -> io::Result<VmDraft> {
        let request = FrameVmCreateVm::new_with_memory_limit(vcpu_count, share, memory_limit_bytes);
        let fd = ioctl_with_input(self.file.as_raw_fd(), CREATE_VM, &request)?;
        owned_fd(fd).map(|fd| VmDraft { fd })
    }
}

pub(crate) struct VmDraft {
    fd: OwnedFd,
}

impl VmDraft {
    pub(crate) fn set_artifact(&mut self, artifact: &File) -> io::Result<()> {
        let request = FrameVmResourceFd::new(artifact.as_raw_fd(), 0);
        ioctl_with_input(self.fd.as_raw_fd(), SET_ARTIFACT, &request).map(drop)
    }

    pub(crate) fn set_cmdline(&mut self, command_line: Option<&str>) -> io::Result<()> {
        let bytes = command_line.unwrap_or_default().as_bytes();
        let len = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "command line is too long"))?;
        let request = FrameVmBytes::new(bytes.as_ptr() as u64, len);
        ioctl_with_input(self.fd.as_raw_fd(), SET_CMDLINE, &request).map(drop)
    }

    pub(crate) fn add_console(&mut self) -> io::Result<()> {
        ioctl_no_data(self.fd.as_raw_fd(), ADD_CONSOLE).map(drop)
    }

    pub(crate) fn add_rng(&mut self) -> io::Result<()> {
        ioctl_no_data(self.fd.as_raw_fd(), ADD_RNG).map(drop)
    }

    pub(crate) fn add_block(
        &mut self,
        image: &File,
        device_id: u32,
        is_read_only: bool,
    ) -> io::Result<()> {
        let flags = if is_read_only {
            FRAMEVM_BLOCK_READ_ONLY
        } else {
            0
        };
        let request = FrameVmBlock::new(image.as_raw_fd(), device_id, flags);
        ioctl_with_input(self.fd.as_raw_fd(), ADD_BLOCK, &request).map(drop)
    }

    pub(crate) fn add_sock(
        &mut self,
        guest_cid: u32,
        guest_connect_host_ports: &[u32],
        host_connect_guest_ports: &[u32],
    ) -> io::Result<()> {
        let request = FrameVmSock::new(
            guest_cid,
            guest_connect_host_ports,
            host_connect_guest_ports,
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "FrameVM Sock port policy exceeds the ABI limit",
            )
        })?;
        ioctl_with_input(self.fd.as_raw_fd(), ADD_SOCK, &request).map(drop)
    }

    pub(crate) fn add_net(
        &mut self,
        endpoint: &OwnedFd,
        mac_address: [u8; 6],
        mtu: u16,
    ) -> io::Result<()> {
        let request = FrameVmNet::new(endpoint.as_raw_fd(), mac_address, mtu);
        ioctl_with_input(self.fd.as_raw_fd(), ADD_NET, &request).map(drop)
    }

    pub(crate) fn assign_pci(&mut self, request: FrameVmAssignedPci) -> io::Result<()> {
        ioctl_with_input(self.fd.as_raw_fd(), ASSIGN_PCI, &request).map(drop)
    }

    pub(crate) fn console(&self) -> io::Result<OwnedFd> {
        owned_fd(ioctl_no_data(self.fd.as_raw_fd(), GET_CONSOLE_FD)?)
    }

    pub(crate) fn start(self) -> io::Result<RunningVm> {
        ioctl_no_data(self.fd.as_raw_fd(), START)?;
        Ok(RunningVm { fd: self.fd })
    }
}

pub(crate) struct RunningVm {
    fd: OwnedFd,
}

impl RunningVm {
    pub(crate) fn status(&self) -> io::Result<FrameVmStatus> {
        let mut status = FrameVmStatus::new(0, 0);
        ioctl_with_output(self.fd.as_raw_fd(), GET_STATUS, &mut status)?;
        Ok(status)
    }

    pub(crate) fn stop(&self) -> io::Result<()> {
        ioctl_no_data(self.fd.as_raw_fd(), STOP).map(drop)
    }

    pub(crate) fn event_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub(crate) fn install_termination_handlers() -> io::Result<()> {
    let action = libc::sigaction {
        sa_sigaction: record_termination_signal as *const () as usize,
        sa_mask: unsafe {
            // SAFETY: an all-zero `sigset_t` is a valid empty signal mask on Linux targets.
            mem::zeroed()
        },
        sa_flags: 0,
        sa_restorer: None,
    };
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: `action` is initialized, its handler has the required C ABI, and no old action is requested.
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn termination_signal() -> Option<i32> {
    match TERMINATION_SIGNAL.load(Ordering::Relaxed) {
        0 => None,
        signal => Some(signal),
    }
}

pub(crate) fn duplicate_fd(raw_fd: RawFd) -> io::Result<OwnedFd> {
    if raw_fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "network fd must be nonnegative",
        ));
    }
    // SAFETY: `fcntl` does not borrow the source fd; success returns a new owned descriptor.
    let duplicated = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 0) };
    owned_fd(duplicated)
}

fn owned_fd(raw_fd: RawFd) -> io::Result<OwnedFd> {
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fd-returning syscalls transfer one new descriptor to the caller.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

fn ioctl_no_data(fd: RawFd, command: libc::c_ulong) -> io::Result<RawFd> {
    // SAFETY: the command encoding declares no third argument, and `fd` remains borrowed.
    let result = unsafe { libc::ioctl(fd, command) };
    ioctl_result(result)
}

fn ioctl_with_input<T>(fd: RawFd, command: libc::c_ulong, input: &T) -> io::Result<RawFd> {
    // SAFETY: the typed request remains initialized and borrowed for the complete ioctl call.
    let result = unsafe { libc::ioctl(fd, command, input as *const T) };
    ioctl_result(result)
}

fn ioctl_with_output<T>(fd: RawFd, command: libc::c_ulong, output: &mut T) -> io::Result<RawFd> {
    // SAFETY: the typed output points to writable storage for the complete ioctl call.
    let result = unsafe { libc::ioctl(fd, command, output as *mut T) };
    ioctl_result(result)
}

fn ioctl_result(result: RawFd) -> io::Result<RawFd> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub(crate) fn open_read_only(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_layout_matches_linux_ioc_encoding() {
        assert_eq!(CREATE_VM, 0x4018_4601);
        assert_eq!(GET_STATUS, 0x8008_4606);
        assert_eq!(SET_ARTIFACT, 0x4010_4608);
        assert_eq!(ADD_SOCK, 0x4030_460c);
        assert_eq!(ADD_NET, 0x4014_460d);
    }
}
