// SPDX-License-Identifier: MPL-2.0

use core::fmt::Display;

use aster_framevisor::{
    device::{NetworkConfiguration, NetworkEndpoint as FramevisorNetworkEndpoint},
    vsock::SockConfiguration,
};
use aster_pci::{PciDeviceLocation, PciReservationError, ReservedPciGroup};
use framev_net_common::{
    FRAMEV_NET_DEFAULT_MAX_POSTED_RECEIVE_BUFFERS, FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES,
    FrameVNetConfig, NetworkEndpointError, OwnedNetworkBuffer,
};
use ostd::{mm::VmIo, task::Task};

use super::{artifact, console_file::FrameVmConsoleFile, ioctl_defs};
use crate::{
    context::current_userspace,
    events::{IoEvents, Observer},
    fs::{
        cgroupfs::{CgroupSysNode, root_cpu_placement},
        file::{
            AccessMode, CreationFlags, FileLike, StatusFlags,
            file_table::{FdFlags, FileDesc},
        },
        pseudofs::AnonInodeFs,
        vfs::path::Path,
    },
    net::socket::{
        Socket,
        unix::UnixDatagramSocket,
        util::{MessageHeader, SendRecvFlags},
    },
    prelude::*,
    process::{
        posix_thread::AsPosixThread,
        signal::{PollAdaptor, PollHandle, Pollable},
    },
    sched::TaskGroup,
    thread::{
        AsThread,
        work_queue::{self, WorkPriority},
    },
    util::ioctl::{RawIoctl, dispatch_ioctl},
    vmm::{FrameVmControl, FrameVmRawImage, FrameVmState},
};

const FRAMEVM_DRIVE_SECTOR_SIZE: usize = 512;
const FRAMEVM_MAX_BLOCK_DEVICES: u32 = 16;

struct VmInner {
    vcpu_count: usize,
    share: u32,
    memory_limit_bytes: usize,
    artifact: Option<Arc<[u8]>>,
    console_configured: bool,
    rng_configured: bool,
    sock_configuration: Option<SockConfiguration>,
    drive_files: BTreeMap<u32, FrameVmDriveFile>,
    network_file: Option<FrameVmNetworkFile>,
    cmdline_append: Option<String>,
    cmdline_configured: bool,
    assigned_pci: Vec<ioctl_defs::FrameVmAssignedPci>,
}

#[derive(Clone, Copy)]
enum FrameVmStopMode {
    Orderly,
    Forced,
}

#[derive(Clone)]
pub(super) struct FrameVmDriveFile {
    file: Arc<dyn FileLike>,
    readonly: bool,
    capacity_bytes: usize,
}

impl FrameVmDriveFile {
    pub(super) fn new(file: Arc<dyn FileLike>, readonly: bool) -> Result<Self> {
        if !file.path().metadata().type_.is_regular_file() {
            return_errno_with_message!(Errno::EINVAL, "FrameVM drive must be a regular file");
        }

        let access_mode = file.access_mode();
        if !access_mode.is_readable() || (!readonly && !access_mode.is_writable()) {
            return_errno_with_message!(
                Errno::EBADF,
                "FrameVM drive fd access mode does not match requested mode"
            );
        }
        let capacity_bytes = file.path().size();
        if capacity_bytes == 0 || !capacity_bytes.is_multiple_of(FRAMEVM_DRIVE_SECTOR_SIZE) {
            return_errno_with_message!(
                Errno::EINVAL,
                "FrameVM drive capacity must be nonzero and 512-byte aligned"
            );
        }

        Ok(Self {
            file,
            readonly,
            capacity_bytes,
        })
    }

    fn readonly(&self) -> bool {
        self.readonly
    }

    fn access_mode(&self) -> AccessMode {
        self.file.access_mode()
    }

    fn raw_image(&self) -> Arc<dyn aster_framevisor::device::BlockImage> {
        Arc::new(FrameVmRawImage::new(
            self.file.clone(),
            self.readonly,
            self.capacity_bytes as u64,
        ))
    }
}

#[derive(Clone)]
struct FrameVmNetworkFile {
    file: Arc<dyn FileLike>,
    config: FrameVNetConfig,
}

impl FrameVmNetworkFile {
    fn new(file: Arc<dyn FileLike>, request: ioctl_defs::FrameVmNet) -> Result<Self> {
        if !file.status_flags().contains(StatusFlags::O_NONBLOCK) {
            return_errno_with_message!(Errno::EINVAL, "FrameVM network fd must be nonblocking");
        }
        let Some(socket) = file.downcast_ref::<UnixDatagramSocket>() else {
            return_errno_with_message!(
                Errno::EINVAL,
                "FrameVM network fd must be a Unix datagram socket"
            );
        };
        socket.peer_addr().map_err(|error| {
            Error::with_message(
                error.error(),
                "FrameVM network fd must be a connected Unix datagram socket",
            )
        })?;

        let config = FrameVNetConfig::new(
            request.mac_address(),
            request.mtu(),
            FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES,
            FRAMEV_NET_DEFAULT_MAX_POSTED_RECEIVE_BUFFERS,
        )
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid FrameVM network configuration"))?;

        Ok(Self { file, config })
    }

    fn network_configuration(&self) -> NetworkConfiguration {
        NetworkConfiguration::new(
            self.config,
            Arc::new(CapturedNetworkEndpoint {
                file: self.file.clone(),
                receive_readiness: Mutex::new(None),
            }),
        )
    }
}

/// Adapts the captured FrameVM Unix datagram fd to the FrameVisor endpoint.
struct CapturedNetworkEndpoint {
    file: Arc<dyn FileLike>,
    receive_readiness: Mutex<Option<PollAdaptor<NetworkReadinessObserver>>>,
}

/// Defers endpoint I/O out of the socket queue's notification context.
struct NetworkReadinessObserver {
    callback: Arc<dyn Fn() + Send + Sync>,
}

impl FramevisorNetworkEndpoint for CapturedNetworkEndpoint {
    fn send(&self, ethernet_frame: &[u8]) -> core::result::Result<(), NetworkEndpointError> {
        let Some(socket) = self.file.downcast_ref::<UnixDatagramSocket>() else {
            return Err(NetworkEndpointError::Lost);
        };
        let mut reader = VmReader::from(ethernet_frame).to_fallible();
        match socket.sendmsg(
            &mut reader,
            MessageHeader::new(None, Vec::new()),
            SendRecvFlags::MSG_DONTWAIT,
        ) {
            Ok(written_len) if written_len == ethernet_frame.len() => Ok(()),
            Ok(_) => Err(NetworkEndpointError::Lost),
            Err(error) if error.error() == Errno::EAGAIN => Err(NetworkEndpointError::NotReady),
            Err(_) => Err(NetworkEndpointError::Lost),
        }
    }

    fn receive(
        &self,
        receive_buffer: &mut OwnedNetworkBuffer,
    ) -> core::result::Result<Option<usize>, NetworkEndpointError> {
        let Some(socket) = self.file.downcast_ref::<UnixDatagramSocket>() else {
            return Err(NetworkEndpointError::Lost);
        };
        let mut writer = VmWriter::from(receive_buffer.as_mut_bytes()).to_fallible();
        match socket.recvmsg(&mut writer, SendRecvFlags::MSG_DONTWAIT) {
            Ok((frame_len, _)) if frame_len <= receive_buffer.len() => Ok(Some(frame_len)),
            Ok(_) => Err(NetworkEndpointError::Lost),
            Err(error) if error.error() == Errno::EAGAIN => Err(NetworkEndpointError::NotReady),
            Err(_) => Err(NetworkEndpointError::Lost),
        }
    }

    fn install_receive_callback(&self, callback: Arc<dyn Fn() + Send + Sync>) {
        let mut receive_readiness = self.receive_readiness.lock();
        if receive_readiness.is_some() {
            return;
        }

        let mut poll_adaptor = PollAdaptor::with_observer(NetworkReadinessObserver {
            callback: callback.clone(),
        });
        let read_events = IoEvents::IN | IoEvents::RDHUP | IoEvents::HUP;
        let current_events = self
            .file
            .poll(read_events, Some(poll_adaptor.as_handle_mut()));
        *receive_readiness = Some(poll_adaptor);
        drop(receive_readiness);

        if current_events.intersects(read_events) {
            callback();
        }
    }
}

impl Observer<IoEvents> for NetworkReadinessObserver {
    fn on_events(&self, events: &IoEvents) {
        if events.intersects(IoEvents::IN | IoEvents::RDHUP | IoEvents::HUP) {
            let callback = self.callback.clone();
            work_queue::submit_work_func(move || callback(), WorkPriority::High);
        }
    }
}

pub(super) struct FrameVmFile {
    inner: Mutex<VmInner>,
    control: Arc<FrameVmControl>,
    pseudo_path: Path,
    task_group: Arc<TaskGroup>,
}

impl FrameVmFile {
    pub(super) fn new(
        vcpu_count: usize,
        share: u32,
        memory_limit_bytes: usize,
        creator_task: &Task,
    ) -> Arc<Self> {
        let creator_thread = creator_task.as_thread();
        let task_group = creator_thread
            .map(|thread| thread.task_group())
            .unwrap_or_else(|| crate::sched::root_task_group().clone());
        let cpu_placement = creator_thread
            .and_then(|thread| thread.as_posix_thread())
            .and_then(|thread| {
                thread
                    .process()
                    .cgroup()
                    .get()
                    .map(|cgroup| cgroup.controller().cpu_placement())
            })
            .unwrap_or_else(root_cpu_placement);

        Arc::new(Self {
            inner: Mutex::new(VmInner {
                vcpu_count,
                share,
                memory_limit_bytes,
                artifact: None,
                console_configured: false,
                rng_configured: false,
                sock_configuration: None,
                drive_files: BTreeMap::new(),
                network_file: None,
                cmdline_append: None,
                cmdline_configured: false,
                assigned_pci: Vec::new(),
            }),
            control: FrameVmControl::new(cpu_placement.clone()),
            pseudo_path: AnonInodeFs::new_path(|_| "anon_inode:[framevm-vm]".to_string()),
            task_group,
        })
    }

    fn try_lock_inner(&self) -> Result<MutexGuard<'_, VmInner>> {
        self.inner.try_lock().ok_or_else(|| {
            error!("[FrameVM] VM fd operation lock is already held");
            Error::with_message(Errno::EBUSY, "a FrameVM operation is in progress")
        })
    }

    fn start(&self) -> Result<i32> {
        let mut inner = self.try_lock_inner()?;
        match self.control.state() {
            FrameVmState::Created => {}
            FrameVmState::Starting => {
                error!("[FrameVM] VM fd start rejected because a state transition is active");
                return_errno_with_message!(Errno::EBUSY, "FrameVM state transition is active")
            }
            FrameVmState::Running => {
                return_errno_with_message!(Errno::EALREADY, "FrameVM is running")
            }
            FrameVmState::Exited { .. } => {
                return_errno_with_message!(Errno::EINVAL, "FrameVM is already terminal")
            }
        }

        let Some(artifact) = &inner.artifact else {
            return_errno_with_message!(Errno::EINVAL, "FrameVM start requires an artifact");
        };
        if !inner.console_configured || !inner.rng_configured {
            return_errno_with_message!(
                Errno::EINVAL,
                "FrameVM start requires console and RNG functions"
            );
        }
        let Some(sock_configuration) = inner.sock_configuration.clone() else {
            return_errno_with_message!(Errno::EINVAL, "FrameVM start requires a Sock function");
        };
        if inner.drive_files.is_empty() {
            return_errno_with_message!(Errno::EINVAL, "FrameVM start requires a drive image");
        }
        if inner
            .drive_files
            .keys()
            .copied()
            .ne(0..inner.drive_files.len() as u32)
        {
            return_errno_with_message!(
                Errno::EINVAL,
                "FrameVM block device IDs must be contiguous"
            );
        }
        let drive_images = inner
            .drive_files
            .values()
            .map(FrameVmDriveFile::raw_image)
            .collect();
        let assigned_pci = claim_assigned_pci(&inner.assigned_pci)?;
        let network_configuration = inner
            .network_file
            .as_ref()
            .map(FrameVmNetworkFile::network_configuration);

        let config = aster_framevisor::FrameVmConfig::new(
            inner.vcpu_count,
            inner.share,
            inner.memory_limit_bytes,
            artifact.clone(),
            inner.cmdline_append.clone(),
            drive_images,
            sock_configuration,
            network_configuration,
            assigned_pci,
        );
        match crate::vmm::start_framevm(config, self.control.clone(), self.task_group.clone()) {
            Ok(()) => {
                ostd::early_println!("[FrameVM] START ioctl setup returned");
                if self
                    .control
                    .vm_id()
                    .and_then(aster_framevisor::get_framevm)
                    .is_none()
                {
                    return_errno_with_message!(
                        Errno::EIO,
                        "FrameVM started without a live instance"
                    );
                }
                inner.artifact = None;
                inner.sock_configuration = None;
                inner.drive_files.clear();
                inner.network_file = None;
                inner.cmdline_append = None;
                inner.assigned_pci.clear();
                Ok(0)
            }
            Err(error) => {
                error!("[FrameVM] VM fd start failed: {:?}", error);
                Err(error)
            }
        }
    }

    fn set_cmdline(&self, request: ioctl_defs::FrameVmCmdline) -> Result<i32> {
        let append = ioctl_defs::read_cmdline(request)?;
        let mut inner = self.try_lock_inner()?;
        match self.control.state() {
            FrameVmState::Created => {}
            FrameVmState::Starting => {
                return_errno_with_message!(Errno::EBUSY, "FrameVM state transition is active")
            }
            FrameVmState::Running => {
                return_errno_with_message!(Errno::EBUSY, "FrameVM is already running")
            }
            FrameVmState::Exited { .. } => {
                return_errno_with_message!(Errno::EINVAL, "FrameVM is already terminal")
            }
        }

        if inner.cmdline_configured {
            return_errno_with_message!(Errno::EEXIST, "FrameVM cmdline is already configured");
        }
        inner.cmdline_append = append;
        inner.cmdline_configured = true;
        Ok(0)
    }

    fn set_artifact(&self, request: ioctl_defs::FrameVmResourceFd) -> Result<i32> {
        ioctl_defs::validate_resource_fd(request)?;
        let raw_fd = FileDesc::try_from(request.fd())?;
        let artifact = artifact::capture_authorized_artifact(current_file(raw_fd)?)?;

        let mut inner = self.try_lock_inner()?;
        ensure_configuring(&self.control)?;
        if inner.artifact.is_some() {
            return_errno_with_message!(Errno::EEXIST, "FrameVM artifact is already configured");
        }
        inner.artifact = Some(artifact);
        Ok(0)
    }

    fn add_console(&self) -> Result<i32> {
        let mut inner = self.try_lock_inner()?;
        ensure_configuring(&self.control)?;
        if inner.console_configured {
            return_errno_with_message!(Errno::EEXIST, "FrameVM console is already configured");
        }
        inner.console_configured = true;
        Ok(0)
    }

    fn add_rng(&self) -> Result<i32> {
        let mut inner = self.try_lock_inner()?;
        ensure_configuring(&self.control)?;
        if inner.rng_configured {
            return_errno_with_message!(Errno::EEXIST, "FrameVM RNG is already configured");
        }
        inner.rng_configured = true;
        Ok(0)
    }

    fn add_sock(&self, request: ioctl_defs::FrameVmSock) -> Result<i32> {
        ioctl_defs::validate_sock(request)?;
        let guest_connect_host_ports = read_port_list(
            request.guest_connect_host_ports_ptr(),
            request.guest_connect_host_ports_len(),
        )?;
        let host_connect_guest_ports = read_port_list(
            request.host_connect_guest_ports_ptr(),
            request.host_connect_guest_ports_len(),
        )?;

        let mut configuration = SockConfiguration::new(request.guest_cid())
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid FrameVM guest CID"))?;
        for port in guest_connect_host_ports {
            configuration = configuration
                .allow_guest_connect_host_port(port)
                .map_err(|_| {
                    Error::with_message(Errno::EINVAL, "invalid Guest-to-Host Sock port")
                })?;
        }
        for port in host_connect_guest_ports {
            configuration = configuration
                .allow_host_connect_guest_port(port)
                .map_err(|_| {
                    Error::with_message(Errno::EINVAL, "invalid Host-to-Guest Sock port")
                })?;
        }

        let mut inner = self.try_lock_inner()?;
        ensure_configuring(&self.control)?;
        if inner.sock_configuration.is_some() {
            return_errno_with_message!(Errno::EEXIST, "FrameVM Sock is already configured");
        }
        inner.sock_configuration = Some(configuration);
        Ok(0)
    }

    fn add_block(&self, request: ioctl_defs::FrameVmBlock) -> Result<i32> {
        ioctl_defs::validate_block(request)?;
        if request.device_id() >= FRAMEVM_MAX_BLOCK_DEVICES {
            return_errno_with_message!(Errno::EINVAL, "FrameVM block device ID is out of range");
        }
        let raw_fd = FileDesc::try_from(request.fd())?;
        let readonly = request.flags() & ioctl_defs::FRAMEVM_BLOCK_READ_ONLY != 0;
        let drive_file = FrameVmDriveFile::new(current_file(raw_fd)?, readonly)?;

        let mut inner = self.try_lock_inner()?;
        ensure_configuring(&self.control)?;
        if inner.drive_files.contains_key(&request.device_id()) {
            return_errno_with_message!(
                Errno::EEXIST,
                "FrameVM block device ID is already configured"
            );
        }
        inner.drive_files.insert(request.device_id(), drive_file);
        Ok(0)
    }

    fn add_net(&self, request: ioctl_defs::FrameVmNet) -> Result<i32> {
        ioctl_defs::validate_net(request)?;
        let raw_fd = FileDesc::try_from(request.fd())?;
        let network_file = FrameVmNetworkFile::new(current_file(raw_fd)?, request)?;

        let mut inner = self.try_lock_inner()?;
        ensure_configuring(&self.control)?;
        if inner.network_file.is_some() {
            return_errno_with_message!(
                Errno::EEXIST,
                "FrameVM network endpoint is already configured"
            );
        }
        inner.network_file = Some(network_file);
        Ok(0)
    }

    fn assign_pci(&self, request: ioctl_defs::FrameVmAssignedPci) -> Result<i32> {
        ioctl_defs::validate_assigned_pci(request)?;
        let mut inner = self.try_lock_inner()?;
        ensure_configuring(&self.control)?;
        if inner.assigned_pci.iter().any(|existing| {
            existing.segment() == request.segment()
                && existing.bus() == request.bus()
                && existing.device() == request.device()
                && existing.function() == request.function()
        }) {
            return_errno_with_message!(Errno::EEXIST, "FrameVM PCI function is already requested");
        }
        inner.assigned_pci.push(request);
        Ok(0)
    }

    fn stop(&self, mode: FrameVmStopMode) -> Result<i32> {
        let control = {
            let _operation_guard = match mode {
                FrameVmStopMode::Orderly => self.try_lock_inner()?,
                FrameVmStopMode::Forced => self.inner.lock(),
            };
            match self.control.state() {
                FrameVmState::Created => {
                    self.control.publish_terminal(0);
                    return Ok(0);
                }
                FrameVmState::Running => self.control.clone(),
                FrameVmState::Starting => {
                    if matches!(mode, FrameVmStopMode::Orderly) {
                        return_errno_with_message!(
                            Errno::EBUSY,
                            "FrameVM state transition is active"
                        )
                    }
                    self.control.clone()
                }
                FrameVmState::Exited { .. } => return Ok(0),
            }
        };

        let vm_id = control.vm_id().ok_or_else(|| {
            Error::with_message(Errno::EINVAL, "running FrameVM has no VM identifier")
        })?;
        if let Some(frame_vm) = aster_framevisor::get_framevm(vm_id) {
            control.retain_console_output(&frame_vm);
        }
        let assigned_pci_failed = match mode {
            FrameVmStopMode::Orderly => crate::vmm::stop_framevm_orderly(vm_id, &control),
            FrameVmStopMode::Forced => crate::vmm::stop_framevm_forced(vm_id, &control),
        };
        let exit_code = if assigned_pci_failed { -5 } else { 0 };
        control.publish_terminal(exit_code);
        Ok(0)
    }

    fn status(&self) -> ioctl_defs::FrameVmStatus {
        self.control.status()
    }

    fn memory_status(&self) -> ioctl_defs::FrameVmMemoryStatus {
        let inner = self.inner.lock();
        let stats = self
            .control
            .vm_id()
            .and_then(aster_framevisor::get_framevm)
            .map(|vm| vm.memory_stats());
        match stats {
            Some(stats) => ioctl_defs::FrameVmMemoryStatus::new(
                stats.limit as u64,
                stats.committed as u64,
                stats.reserved as u64,
                stats.reusable as u64,
                stats.active as u64,
                stats.oom_count,
                stats.reclaim_count,
            ),
            None => ioctl_defs::FrameVmMemoryStatus::new(
                inner.memory_limit_bytes as u64,
                0,
                0,
                0,
                0,
                0,
                0,
            ),
        }
    }

    fn get_console_fd(&self) -> Result<i32> {
        let _operation_guard = self.try_lock_inner()?;
        match self.control.state() {
            FrameVmState::Created | FrameVmState::Running => {
                let current_task = Task::current().ok_or_else(|| {
                    Error::with_message(Errno::ESRCH, "FrameVM console fd requires a task")
                })?;
                let thread_local = current_task.as_thread_local().ok_or_else(|| {
                    Error::with_message(
                        Errno::EINVAL,
                        "FrameVM console fd requires a process-backed task",
                    )
                })?;

                let cursor = self
                    .control
                    .vm_id()
                    .and_then(aster_framevisor::get_framevm)
                    .map(|vm| vm.devices().console().output_tail_offset())
                    .unwrap_or(0);
                let console_file = FrameVmConsoleFile::new(cursor, self.control.clone());
                let fd = {
                    let file_table = thread_local.borrow_file_table();
                    let file_table = file_table.as_ref().ok_or_else(|| {
                        Error::with_message(
                            Errno::EINVAL,
                            "FrameVM console fd requires a file table",
                        )
                    })?;
                    let mut file_table_locked = file_table.write();
                    file_table_locked.insert(console_file, FdFlags::empty())
                };
                Ok(fd.into())
            }
            FrameVmState::Starting => {
                return_errno_with_message!(Errno::EBUSY, "FrameVM state transition is active")
            }
            FrameVmState::Exited { .. } => {
                return_errno_with_message!(Errno::EINVAL, "FrameVM is already terminal")
            }
        }
    }

    fn stop_on_close(&self) {
        if self.control.state().is_terminal() {
            return;
        }
        let _ = self.stop(FrameVmStopMode::Forced);
    }
}

fn claim_assigned_pci(
    requests: &[ioctl_defs::FrameVmAssignedPci],
) -> Result<Option<ReservedPciGroup>> {
    let Some(request) = requests.first() else {
        return Ok(None);
    };
    if requests.len() != 1 {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "only one FrameVM PCI assignment is currently supported"
        );
    }

    let location = PciDeviceLocation {
        bus: request.bus(),
        device: request.device(),
        function: request.function(),
    };
    aster_pci::claim_reserved_group(request.segment(), location)
        .map(Some)
        .map_err(map_pci_reservation_error)
}

fn map_pci_reservation_error(error: PciReservationError) -> Error {
    match error {
        PciReservationError::Busy => Error::with_message(
            Errno::EBUSY,
            "FrameVM PCI function is already being assigned",
        ),
        PciReservationError::NotFound => {
            Error::with_message(Errno::ENODEV, "reserved FrameVM PCI function was not found")
        }
        PciReservationError::NotReserved => Error::with_message(
            Errno::EPERM,
            "FrameVM PCI function was not reserved at boot",
        ),
        PciReservationError::UnsupportedGroup => Error::with_message(
            Errno::EOPNOTSUPP,
            "FrameVM PCI requester group is not supported",
        ),
        PciReservationError::Quarantined | PciReservationError::StaleAssignment => {
            Error::with_message(Errno::EIO, "FrameVM PCI function is quarantined")
        }
    }
}

impl Drop for FrameVmFile {
    fn drop(&mut self) {
        self.stop_on_close();
    }
}

impl Pollable for FrameVmFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.control.poll_terminal(mask, poller)
    }
}

impl FileLike for FrameVmFile {
    fn read(&self, _writer: &mut VmWriter) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the FrameVM VM fd is not readable")
    }

    fn write(&self, _reader: &mut VmReader) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the FrameVM VM fd is not writable")
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            StartVm => {
                self.start()
            }
            StopVm => {
                self.stop(FrameVmStopMode::Orderly)
            }
            GetConsoleFd => {
                self.get_console_fd()
            }
            cmd @ SetCmdline => {
                self.set_cmdline(cmd.read()?)
            }
            cmd @ SetArtifact => {
                self.set_artifact(cmd.read()?)
            }
            AddConsole => {
                self.add_console()
            }
            AddRng => {
                self.add_rng()
            }
            cmd @ AddBlock => {
                self.add_block(cmd.read()?)
            }
            cmd @ AddNet => {
                self.add_net(cmd.read()?)
            }
            cmd @ AddSock => {
                self.add_sock(cmd.read()?)
            }
            cmd @ AssignPci => {
                self.assign_pci(cmd.read()?)
            }
            cmd @ GetStatus => {
                let status = self.status();
                cmd.write(&status)?;
                Ok(0)
            }
            cmd @ GetMemoryStatus => {
                cmd.write(&self.memory_status())?;
                Ok(0)
            }
            CreateVm => {
                return_errno_with_message!(
                    Errno::ENOTTY,
                    "the ioctl command is invalid for this fd"
                )
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "the ioctl command is unknown"),
        })
    }

    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn path(&self) -> &Path {
        &self.pseudo_path
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            inner: Arc<FrameVmFile>,
            fd_flags: FdFlags,
        }

        impl Display for FdInfo {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let inner = self.inner.inner.lock();
                let mut flags = self.inner.access_mode() as u32;
                if self.fd_flags.contains(FdFlags::CLOEXEC) {
                    flags |= CreationFlags::O_CLOEXEC.bits();
                }
                let status = self.inner.control.status();

                writeln!(formatter, "pos:\t{}", 0)?;
                writeln!(formatter, "flags:\t0{:o}", flags)?;
                writeln!(formatter, "state:\t{}", status.state())?;
                writeln!(formatter, "code:\t{}", status.code())?;
                writeln!(formatter, "vcpu_count:\t{}", inner.vcpu_count)?;
                writeln!(formatter, "share:\t{}", inner.share)?;
                match &inner.artifact {
                    Some(artifact) => writeln!(formatter, "artifact:\t{} bytes", artifact.len()),
                    None => writeln!(formatter, "artifact:\tnone"),
                }?;
                writeln!(formatter, "console:\t{}", inner.console_configured)?;
                writeln!(formatter, "rng:\t{}", inner.rng_configured)?;
                match &inner.sock_configuration {
                    Some(configuration) => {
                        writeln!(formatter, "sock:\tcid={}", configuration.guest_cid())
                    }
                    None => writeln!(formatter, "sock:\tnone"),
                }?;
                if inner.drive_files.is_empty() {
                    writeln!(formatter, "drives:\tnone")?;
                }
                for (device_id, drive_file) in &inner.drive_files {
                    writeln!(
                        formatter,
                        "drive[{device_id}]:\t{},access={:?}",
                        if drive_file.readonly() {
                            "readonly"
                        } else {
                            "writable"
                        },
                        drive_file.access_mode()
                    )?;
                }
                match &inner.network_file {
                    Some(network_file) => writeln!(
                        formatter,
                        "network:\tmac={:02x?},mtu={}",
                        network_file.config.mac_address(),
                        network_file.config.mtu()
                    ),
                    None => writeln!(formatter, "network:\tnone"),
                }?;
                Ok(())
            }
        }

        Box::new(FdInfo {
            inner: self,
            fd_flags,
        })
    }
}

fn read_port_list(ptr: u64, len: u32) -> Result<Vec<u32>> {
    if len > ioctl_defs::FRAMEVM_SOCK_MAX_PORTS_PER_DIRECTION {
        return_errno_with_message!(Errno::EINVAL, "FrameVM Sock port list is too long");
    }
    if len == 0 {
        if ptr != 0 {
            return_errno_with_message!(Errno::EINVAL, "empty FrameVM Sock port list has a pointer");
        }
        return Ok(Vec::new());
    }

    let base = usize::try_from(ptr)
        .map_err(|_| Error::with_message(Errno::EFAULT, "FrameVM Sock port pointer is invalid"))?;
    let mut ports = Vec::with_capacity(len as usize);
    let mut unique_ports = BTreeSet::new();
    for index in 0..len as usize {
        let offset = index.checked_mul(size_of::<u32>()).ok_or_else(|| {
            Error::with_message(Errno::EFAULT, "FrameVM Sock port pointer overflows")
        })?;
        let address = base.checked_add(offset).ok_or_else(|| {
            Error::with_message(Errno::EFAULT, "FrameVM Sock port pointer overflows")
        })?;
        let port = current_userspace!().read_val::<u32>(address)?;
        if !unique_ports.insert(port) {
            return_errno_with_message!(Errno::EINVAL, "duplicate FrameVM Sock port");
        }
        ports.push(port);
    }
    Ok(ports)
}

fn ensure_configuring(control: &FrameVmControl) -> Result<()> {
    match control.state() {
        FrameVmState::Created => Ok(()),
        FrameVmState::Starting | FrameVmState::Running => {
            return_errno_with_message!(Errno::EBUSY, "FrameVM is no longer configurable")
        }
        FrameVmState::Exited { .. } => {
            return_errno_with_message!(Errno::EINVAL, "FrameVM is already terminal")
        }
    }
}

fn current_file(fd: FileDesc) -> Result<Arc<dyn FileLike>> {
    let current_task = Task::current()
        .ok_or_else(|| Error::with_message(Errno::ESRCH, "FrameVM resource requires a task"))?;
    let thread_local = current_task.as_thread_local().ok_or_else(|| {
        Error::with_message(
            Errno::EINVAL,
            "FrameVM resource requires a process-backed task",
        )
    })?;
    let file_table = thread_local.borrow_file_table();
    let file_table = file_table.as_ref().ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "FrameVM resource requires a file table")
    })?;
    Ok(file_table.read().get_file(fd)?.clone())
}
