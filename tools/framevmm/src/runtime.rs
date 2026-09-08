//! FrameVM resource transaction and process lifecycle.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, OwnedFd},
    process::ExitCode,
};

use framevm_abi::{
    FRAMEVM_STATE_CREATED, FRAMEVM_STATE_EXITED, FRAMEVM_STATE_RUNNING, FRAMEVM_STATE_STARTING,
    FrameVmAssignedPci, FrameVmStatus,
};

use crate::{
    framevm_api::{
        FrameVmController, RunningVm, duplicate_fd, install_termination_handlers, open_read_only,
        termination_signal,
    },
    qemu_compat::{DriveConfig, VmConfig},
};

const FRAMEV_NET_MTU: u16 = 1_500;
const EXT2_SUPERBLOCK_OFFSET: u64 = 1_024;
const EXT2_LOG_BLOCK_SIZE_OFFSET: u64 = EXT2_SUPERBLOCK_OFFSET + 24;
const EXT2_MAGIC_OFFSET: u64 = EXT2_SUPERBLOCK_OFFSET + 56;
const EXT2_MAGIC: u16 = 0xef53;
const REQUIRED_EXT2_BLOCK_SIZE: u32 = 4_096;
const EVENT_POLL_INTERVAL_MS: libc::c_int = 100;
const CONSOLE_BUFFER_SIZE: usize = 4_096;

pub(crate) fn run(configuration: VmConfig) -> Result<ExitCode, RuntimeError> {
    let resources = PreparedResources::open(&configuration)?;
    install_termination_handlers().map_err(|error| RuntimeError::io("install signals", error))?;

    let controller =
        FrameVmController::open().map_err(|error| RuntimeError::io("open /dev/framevm", error))?;
    let mut draft = controller
        .create(
            u32::from(configuration.vcpu_count().get()),
            configuration.scheduler_share(),
            configuration.memory_limit_bytes(),
        )
        .map_err(|error| RuntimeError::io("create FrameVM draft", error))?;

    draft
        .set_artifact(&resources.artifact)
        .map_err(|error| RuntimeError::io("stage FrameVM artifact", error))?;
    draft
        .set_cmdline(configuration.cmdline())
        .map_err(|error| RuntimeError::io("stage FrameVM command line", error))?;
    draft
        .add_console()
        .map_err(|error| RuntimeError::io("stage FrameV console", error))?;
    draft
        .add_rng()
        .map_err(|error| RuntimeError::io("stage FrameV RNG", error))?;
    draft
        .add_block(&resources.root.file, 0, false)
        .map_err(|error| RuntimeError::io("stage FrameVM root drive", error))?;
    for (index, drive) in resources.secondary.iter().enumerate() {
        let device_id = u32::try_from(index + 1)
            .map_err(|_| RuntimeError::new("too many FrameVM block devices"))?;
        draft
            .add_block(&drive.file, device_id, drive.is_read_only)
            .map_err(|error| RuntimeError::io("stage FrameVM secondary drive", error))?;
    }
    let socket = configuration.socket();
    draft
        .add_sock(
            socket.guest_cid(),
            socket.guest_connect_host_ports(),
            socket.host_connect_guest_ports(),
        )
        .map_err(|error| RuntimeError::io("stage FrameV Sock", error))?;
    if let Some(network) = &resources.network {
        draft
            .add_net(
                network,
                configuration.network().unwrap().mac_address(),
                FRAMEV_NET_MTU,
            )
            .map_err(|error| RuntimeError::io("stage FrameV-net endpoint", error))?;
    }
    if let Some(address) = configuration.assigned_pci() {
        let request = FrameVmAssignedPci::new(
            address.segment(),
            address.bus(),
            address.device(),
            address.function(),
        )
        .ok_or_else(|| RuntimeError::new("invalid assigned PCI address"))?;
        draft
            .assign_pci(request)
            .map_err(|error| RuntimeError::io("stage assigned PCI function", error))?;
    }

    let console = draft
        .console()
        .map_err(|error| RuntimeError::io("open FrameVM console", error))?;
    let running = draft
        .start()
        .map_err(|error| RuntimeError::io("start FrameVM", error))?;
    let exit_status = relay_console_until_terminal(&running, console)?;
    Ok(ExitCode::from(exit_status as u8))
}

struct PreparedResources {
    artifact: File,
    root: PreparedDrive,
    secondary: Vec<PreparedDrive>,
    network: Option<OwnedFd>,
}

impl PreparedResources {
    fn open(configuration: &VmConfig) -> Result<Self, RuntimeError> {
        let artifact = open_read_only(configuration.kernel_path())
            .map_err(|error| RuntimeError::io("open FrameVM artifact", error))?;
        validate_regular_nonempty(&artifact, "FrameVM artifact")?;
        let root = PreparedDrive::open(configuration.root_drive())?;
        validate_ext2_root(&root.file)?;
        let secondary = configuration
            .secondary_drives()
            .iter()
            .map(PreparedDrive::open)
            .collect::<Result<Vec<_>, _>>()?;
        let network = configuration
            .network()
            .map(|network| duplicate_fd(network.endpoint_fd()))
            .transpose()
            .map_err(|error| RuntimeError::io("duplicate inherited FrameV-net fd", error))?;
        Ok(Self {
            artifact,
            root,
            secondary,
            network,
        })
    }
}

struct PreparedDrive {
    file: File,
    is_read_only: bool,
}

impl PreparedDrive {
    fn open(configuration: &DriveConfig) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new()
            .read(true)
            .write(!configuration.is_read_only())
            .open(configuration.path())
            .map_err(|error| {
                RuntimeError::io(&format!("open drive '{}'", configuration.id()), error)
            })?;
        validate_regular_nonempty(&file, &format!("drive '{}'", configuration.id()))?;
        let drive_len = file
            .metadata()
            .map_err(|error| RuntimeError::io("read drive metadata", error))?
            .len();
        if drive_len % 512 != 0 {
            return Err(RuntimeError::new(format!(
                "drive '{}' size must be 512-byte aligned",
                configuration.id()
            )));
        }
        Ok(Self {
            file,
            is_read_only: configuration.is_read_only(),
        })
    }
}

fn validate_regular_nonempty(file: &File, resource: &str) -> Result<(), RuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError::io(&format!("read {resource} metadata"), error))?;
    if !metadata.is_file() {
        return Err(RuntimeError::new(format!(
            "{resource} must be a regular file"
        )));
    }
    if metadata.len() == 0 {
        return Err(RuntimeError::new(format!("{resource} must not be empty")));
    }
    Ok(())
}

fn validate_ext2_root(file: &File) -> Result<(), RuntimeError> {
    let mut file = file
        .try_clone()
        .map_err(|error| RuntimeError::io("clone root drive fd", error))?;
    let magic = read_exact_at::<2>(&mut file, EXT2_MAGIC_OFFSET)?;
    if u16::from_le_bytes(magic) != EXT2_MAGIC {
        return Err(RuntimeError::new("FrameVM root drive must contain Ext2"));
    }
    let log_block_size =
        u32::from_le_bytes(read_exact_at::<4>(&mut file, EXT2_LOG_BLOCK_SIZE_OFFSET)?);
    let block_size = 1_024u32
        .checked_shl(log_block_size)
        .ok_or_else(|| RuntimeError::new("invalid Ext2 block size"))?;
    if block_size != REQUIRED_EXT2_BLOCK_SIZE {
        return Err(RuntimeError::new(format!(
            "FrameVM root Ext2 block size must be {REQUIRED_EXT2_BLOCK_SIZE}"
        )));
    }
    Ok(())
}

fn read_exact_at<const N: usize>(file: &mut File, offset: u64) -> Result<[u8; N], RuntimeError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| RuntimeError::io("seek root drive", error))?;
    let mut bytes = [0; N];
    file.read_exact(&mut bytes)
        .map_err(|error| RuntimeError::io("read Ext2 superblock", error))?;
    Ok(bytes)
}

fn relay_console_until_terminal(
    running: &RunningVm,
    console: OwnedFd,
) -> Result<i32, RuntimeError> {
    let mut console = File::from(console);
    let mut stdout = File::from(
        duplicate_fd(io::stdout().as_raw_fd())
            .map_err(|error| RuntimeError::io("duplicate console output fd", error))?,
    );
    let mut stdin = File::from(
        duplicate_fd(io::stdin().as_raw_fd())
            .map_err(|error| RuntimeError::io("duplicate console input fd", error))?,
    );
    relay_loop(running, &mut console, &mut stdout, &mut stdin)
}

fn relay_loop(
    running: &RunningVm,
    console: &mut File,
    stdout: &mut File,
    stdin: &mut File,
) -> Result<i32, RuntimeError> {
    let mut stdin_open = true;
    loop {
        let status = running
            .status()
            .map_err(|error| RuntimeError::io("query FrameVM status", error))?;
        if is_terminal(status.state()) {
            eprintln!(
                "FrameVM terminal status: {} code={}",
                state_name(status.state()),
                status.code(),
            );
            return Ok(normalize_exit_status(status.code()));
        }
        if let Some(signal) = termination_signal() {
            // `SIGHUP` abandons the owner fd so the kernel performs its
            // forced-stop path. Other termination signals request an orderly stop.
            if signal != libc::SIGHUP {
                running
                    .stop()
                    .map_err(|error| RuntimeError::io("stop FrameVM", error))?;
            }
            return Ok((128 + signal).min(255));
        }

        let mut poll_fds = [
            libc::pollfd {
                fd: running.event_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: console.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if stdin_open { stdin.as_raw_fd() } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `poll_fds` contains three initialized descriptors for the
        // duration of the call; a negative descriptor is intentionally ignored.
        let poll_result = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                EVENT_POLL_INTERVAL_MS,
            )
        };
        if poll_result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(RuntimeError::io("wait for FrameVM or console input", error));
            }
            continue;
        }
        if poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            forward_console_output(console, stdout)?;
        }
        if stdin_open && poll_fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            stdin_open = forward_console_input(stdin, console)?;
        }
    }
}

fn forward_console_output(console: &mut File, stdout: &mut File) -> Result<(), RuntimeError> {
    let mut bytes = [0; CONSOLE_BUFFER_SIZE];
    let count = console
        .read(&mut bytes)
        .map_err(|error| RuntimeError::io("read FrameVM console output", error))?;
    if count != 0 {
        stdout
            .write_all(&bytes[..count])
            .map_err(|error| RuntimeError::io("forward FrameVM console output", error))?;
    }
    Ok(())
}

fn forward_console_input(stdin: &mut File, console: &mut File) -> Result<bool, RuntimeError> {
    let mut bytes = [0; CONSOLE_BUFFER_SIZE];
    let count = stdin
        .read(&mut bytes)
        .map_err(|error| RuntimeError::io("read FrameVM console input", error))?;
    if count == 0 {
        return Ok(false);
    }
    console
        .write_all(&bytes[..count])
        .map_err(|error| RuntimeError::io("forward FrameVM console input", error))?;
    Ok(true)
}

fn is_terminal(state: u32) -> bool {
    state == FRAMEVM_STATE_EXITED
}

fn state_name(state: u32) -> &'static str {
    match state {
        FRAMEVM_STATE_CREATED => "created",
        FRAMEVM_STATE_STARTING => "starting",
        FRAMEVM_STATE_RUNNING => "running",
        FRAMEVM_STATE_EXITED => "exited",
        _ => "unknown",
    }
}

fn normalize_exit_status(status: i32) -> i32 {
    if status == 0 {
        return 0;
    }
    if (1..=255).contains(&status) {
        status
    } else {
        1
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeError {
    message: String,
}

impl RuntimeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn io(operation: &str, error: io::Error) -> Self {
        Self::new(format!("{operation}: {error}"))
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states_are_closed() {
        assert!(!is_terminal(FRAMEVM_STATE_CREATED));
        assert!(!is_terminal(FRAMEVM_STATE_STARTING));
        assert!(!is_terminal(FRAMEVM_STATE_RUNNING));
        assert!(is_terminal(FRAMEVM_STATE_EXITED));
    }

    #[test]
    fn terminal_statuses_map_to_process_exit_codes() {
        let success = FrameVmStatus::new(FRAMEVM_STATE_EXITED, 0);
        let guest_failure = FrameVmStatus::new(FRAMEVM_STATE_EXITED, 7);
        let invalid_failure = FrameVmStatus::new(FRAMEVM_STATE_EXITED, -1);

        assert_eq!(normalize_exit_status(success.code()), 0);
        assert_eq!(normalize_exit_status(guest_failure.code()), 7);
        assert_eq!(normalize_exit_status(invalid_failure.code()), 1);
    }
}
