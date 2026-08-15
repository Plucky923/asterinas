//! FrameVM resource transaction and process lifecycle.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::fd::{AsRawFd, OwnedFd},
    process::ExitCode,
    thread,
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
    let console_output = forward_console(console)?;
    let exit_code = wait_for_terminal(&running)?;
    drop(running);
    console_output.finish()?;
    Ok(exit_code)
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

struct ConsoleOutput {
    output: thread::JoinHandle<io::Result<u64>>,
}

impl ConsoleOutput {
    fn finish(self) -> Result<(), RuntimeError> {
        self.output
            .join()
            .map_err(|_| RuntimeError::new("FrameVM console output thread panicked"))?
            .map_err(|error| RuntimeError::io("forward FrameVM console output", error))?;
        Ok(())
    }
}

fn forward_console(console: OwnedFd) -> Result<ConsoleOutput, RuntimeError> {
    let output = File::from(
        console
            .try_clone()
            .map_err(|error| RuntimeError::io("clone console output fd", error))?,
    );
    let input = File::from(console);
    let stdout = File::from(
        duplicate_fd(io::stdout().as_raw_fd())
            .map_err(|error| RuntimeError::io("duplicate console output fd", error))?,
    );
    let stdin = File::from(
        duplicate_fd(io::stdin().as_raw_fd())
            .map_err(|error| RuntimeError::io("duplicate console input fd", error))?,
    );
    let output_thread = thread::Builder::new()
        .name("framevmm-console-output".into())
        .spawn(move || {
            let mut output = output;
            let mut stdout = stdout;
            io::copy(&mut output, &mut stdout)
        })
        .map_err(|error| RuntimeError::io("start console output forwarding", error))?;
    thread::Builder::new()
        .name("framevmm-console-input".into())
        .spawn(move || {
            let mut input = input;
            let mut stdin = stdin;
            let _ = io::copy(&mut stdin, &mut input);
        })
        .map_err(|error| RuntimeError::io("start console input forwarding", error))?;
    Ok(ConsoleOutput {
        output: output_thread,
    })
}

fn wait_for_terminal(running: &RunningVm) -> Result<ExitCode, RuntimeError> {
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
            return Ok(exit_code(status));
        }
        if let Some(signal) = termination_signal() {
            // `SIGHUP` abandons the owner fd so the kernel performs its
            // forced-stop path. Other termination signals request an orderly stop.
            if signal != libc::SIGHUP {
                running
                    .stop()
                    .map_err(|error| RuntimeError::io("stop FrameVM", error))?;
            }
            return Ok(ExitCode::from((128 + signal).min(255) as u8));
        }
        match running.wait_for_event() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(RuntimeError::io("wait for FrameVM status", error)),
        }
    }
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

fn exit_code(status: FrameVmStatus) -> ExitCode {
    if status.code() == 0 {
        return ExitCode::SUCCESS;
    }
    if (1..=255).contains(&status.code()) {
        ExitCode::from(status.code() as u8)
    } else {
        ExitCode::FAILURE
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

        assert_eq!(exit_code(success), ExitCode::SUCCESS);
        assert_eq!(exit_code(guest_failure), ExitCode::from(7));
        assert_eq!(exit_code(invalid_failure), ExitCode::FAILURE);
    }
}
