//! Strict parsing of the supported QEMU-shaped FrameVM command line.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt,
    num::NonZeroU8,
    path::PathBuf,
};

const MIN_VCPU_COUNT: u8 = 1;
const MAX_VCPU_COUNT: u8 = 4;
const DEFAULT_SCHEDULER_SHARE: u32 = 1_024;
const MIN_SCHEDULER_SHARE: u32 = 2;
const MAX_SCHEDULER_SHARE: u32 = 262_144;
const FRAMEVM_PAGE_SIZE_BYTES: u64 = 4 * 1024;
const FRAMEV_NET_MTU: u16 = 1_500;

/// A normalized FrameVM configuration that has not acquired any resources.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VmConfig {
    vcpu_count: NonZeroU8,
    scheduler_share: u32,
    memory_limit_bytes: u64,
    kernel_path: PathBuf,
    cmdline: Option<String>,
    uses_stdio_console: bool,
    root_drive: DriveConfig,
    secondary_drives: Vec<DriveConfig>,
    socket: SockConfig,
    network: Option<NetworkConfig>,
    assigned_pci: Option<PciAddress>,
}

impl VmConfig {
    /// Returns the configured virtual CPU count.
    pub(crate) fn vcpu_count(&self) -> NonZeroU8 {
        self.vcpu_count
    }

    /// Returns the configured Host scheduler share.
    pub(crate) const fn scheduler_share(&self) -> u32 {
        self.scheduler_share
    }

    /// Returns the configured FrameVM memory limit in bytes.
    pub(crate) const fn memory_limit_bytes(&self) -> u64 {
        self.memory_limit_bytes
    }

    /// Returns the configured kernel artifact path.
    pub(crate) fn kernel_path(&self) -> &PathBuf {
        &self.kernel_path
    }

    /// Returns the configured root-drive path.
    pub(crate) fn root_drive(&self) -> &DriveConfig {
        &self.root_drive
    }

    /// Returns the configured secondary drives.
    pub(crate) fn secondary_drives(&self) -> &[DriveConfig] {
        &self.secondary_drives
    }

    /// Returns the configured physical PCI request.
    pub(crate) fn assigned_pci(&self) -> Option<PciAddress> {
        self.assigned_pci
    }

    pub(crate) fn cmdline(&self) -> Option<&str> {
        self.cmdline.as_deref()
    }

    pub(crate) fn socket(&self) -> &SockConfig {
        &self.socket
    }

    pub(crate) fn network(&self) -> Option<&NetworkConfig> {
        self.network.as_ref()
    }
}

/// A typed raw-drive definition.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DriveConfig {
    id: String,
    path: PathBuf,
    is_read_only: bool,
}

impl DriveConfig {
    /// Returns the QEMU-local drive identifier.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Returns whether the drive is read-only.
    pub(crate) fn is_read_only(&self) -> bool {
        self.is_read_only
    }

    pub(crate) fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// A typed FrameV Sock definition.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SockConfig {
    guest_cid: u32,
    guest_connect_host_ports: Vec<u32>,
    host_connect_guest_ports: Vec<u32>,
}

impl SockConfig {
    pub(crate) const fn guest_cid(&self) -> u32 {
        self.guest_cid
    }

    pub(crate) fn guest_connect_host_ports(&self) -> &[u32] {
        &self.guest_connect_host_ports
    }

    pub(crate) fn host_connect_guest_ports(&self) -> &[u32] {
        &self.host_connect_guest_ports
    }
}

/// A typed FrameV-net definition.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NetworkConfig {
    endpoint_fd: i32,
    mac_address: [u8; 6],
}

impl NetworkConfig {
    pub(crate) const fn endpoint_fd(&self) -> i32 {
        self.endpoint_fd
    }

    pub(crate) const fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }
}

/// A complete physical PCI address validated from vfio-pci host syntax.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PciAddress {
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
}

impl PciAddress {
    pub(crate) const fn segment(self) -> u16 {
        self.segment
    }

    pub(crate) const fn bus(self) -> u8 {
        self.bus
    }

    pub(crate) const fn device(self) -> u8 {
        self.device
    }

    pub(crate) const fn function(self) -> u8 {
        self.function
    }
}

/// Describes one invalid QEMU-shaped command line.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ParseError {
    message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for ParseError {}

/// Parses a supported QEMU-shaped FrameVM invocation without opening resources.
pub(crate) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<VmConfig, ParseError> {
    let mut arguments = arguments.into_iter();
    let _program_name = arguments.next();
    let mut parser = ArgumentParser::default();

    while let Some(argument) = arguments.next() {
        let argument = os_string_to_string(argument, "option")?;
        match argument.as_str() {
            "-m" => parser.set_memory_limit(next_value(&mut arguments, "-m")?)?,
            "-smp" => parser.set_smp(next_value(&mut arguments, "-smp")?)?,
            "-share" => parser.set_share(next_value(&mut arguments, "-share")?)?,
            "-kernel" => parser.set_kernel(next_value(&mut arguments, "-kernel")?)?,
            "-append" => parser.set_cmdline(next_value(&mut arguments, "-append")?)?,
            "-nographic" => parser.enable_stdio_console()?,
            "-drive" => parser.add_drive(next_value(&mut arguments, "-drive")?)?,
            "-device" => parser.add_device(next_value(&mut arguments, "-device")?)?,
            "-netdev" => parser.add_netdev(next_value(&mut arguments, "-netdev")?)?,
            unsupported if unsupported.starts_with('-') => {
                return Err(ParseError::new(format!(
                    "unsupported option '{unsupported}'"
                )));
            }
            positional => {
                return Err(ParseError::new(format!(
                    "unexpected positional argument '{positional}'"
                )));
            }
        }
    }

    parser.finish()
}

#[derive(Default)]
struct ArgumentParser {
    vcpu_count: Option<NonZeroU8>,
    scheduler_share: Option<u32>,
    memory_limit_bytes: Option<u64>,
    kernel_path: Option<PathBuf>,
    cmdline: Option<String>,
    uses_stdio_console: bool,
    drives: BTreeMap<String, DriveConfig>,
    block_drive_ids: BTreeSet<String>,
    root_drive_id: Option<String>,
    socket: Option<SockConfig>,
    netdevs: BTreeMap<String, i32>,
    network: Option<PendingNetworkConfig>,
    assigned_pci: Option<PciAddress>,
}

struct PendingNetworkConfig {
    netdev_id: String,
    mac_address: [u8; 6],
}

impl ArgumentParser {
    fn set_smp(&mut self, value: String) -> Result<(), ParseError> {
        set_once(&mut self.vcpu_count, parse_smp(&value)?, "-smp")
    }

    fn set_share(&mut self, value: String) -> Result<(), ParseError> {
        let share = value
            .parse::<u32>()
            .map_err(|_| ParseError::new("-share requires an unsigned integer"))?;
        if !(MIN_SCHEDULER_SHARE..=MAX_SCHEDULER_SHARE).contains(&share) {
            return Err(ParseError::new(format!(
                "-share requires a value in {MIN_SCHEDULER_SHARE}..={MAX_SCHEDULER_SHARE}"
            )));
        }
        set_once(&mut self.scheduler_share, share, "-share")
    }

    fn set_memory_limit(&mut self, value: String) -> Result<(), ParseError> {
        let memory_limit_bytes = parse_memory_limit(&value)?;
        set_once(&mut self.memory_limit_bytes, memory_limit_bytes, "-m")
    }

    fn set_kernel(&mut self, value: String) -> Result<(), ParseError> {
        if value.is_empty() {
            return Err(ParseError::new("-kernel requires a path"));
        }
        set_once(&mut self.kernel_path, PathBuf::from(value), "-kernel")
    }

    fn set_cmdline(&mut self, value: String) -> Result<(), ParseError> {
        set_once(&mut self.cmdline, value, "-append")
    }

    fn enable_stdio_console(&mut self) -> Result<(), ParseError> {
        if self.uses_stdio_console {
            return Err(ParseError::new("duplicate option '-nographic'"));
        }
        self.uses_stdio_console = true;
        Ok(())
    }

    fn add_drive(&mut self, value: String) -> Result<(), ParseError> {
        let mut properties = Properties::parse("-drive", value)?;
        let id = properties.required("id")?;
        let path = properties.required("file")?;
        let format = properties.required("format")?;
        if format != "raw" {
            return Err(ParseError::new(format!(
                "-drive '{id}' requires format=raw"
            )));
        }
        let is_read_only = properties.optional_bool("readonly")?.unwrap_or(false);
        properties.reject_unknown()?;

        if self.drives.contains_key(&id) {
            return Err(ParseError::new(format!("duplicate -drive id '{id}'")));
        }
        self.drives.insert(
            id.clone(),
            DriveConfig {
                id,
                path: PathBuf::from(path),
                is_read_only,
            },
        );
        Ok(())
    }

    fn add_device(&mut self, value: String) -> Result<(), ParseError> {
        let (device_name, properties) = Properties::parse_named("-device", value)?;
        match device_name.as_str() {
            "framev-blk" => self.add_block_device(properties),
            "framev-sock" => self.add_sock_device(properties),
            "framev-net" => self.add_network_device(properties),
            "vfio-pci" => self.add_vfio_device(properties),
            unsupported => Err(ParseError::new(format!(
                "unsupported -device '{unsupported}'"
            ))),
        }
    }

    fn add_block_device(&mut self, mut properties: Properties) -> Result<(), ParseError> {
        let drive_id = properties.required("drive")?;
        let is_root = properties.required_bool("root")?;
        properties.reject_unknown()?;
        if !self.block_drive_ids.insert(drive_id.clone()) {
            return Err(ParseError::new(format!(
                "duplicate framev-blk drive '{drive_id}'"
            )));
        }
        if is_root {
            set_once(&mut self.root_drive_id, drive_id, "root framev-blk")?;
        }
        Ok(())
    }

    fn add_sock_device(&mut self, mut properties: Properties) -> Result<(), ParseError> {
        let guest_cid = properties.required_u32("guest-cid")?;
        let guest_connect_host_ports = properties.optional_port_list("guest-connect-host-ports")?;
        let host_connect_guest_ports = properties.optional_port_list("host-connect-guest-ports")?;
        properties.reject_unknown()?;
        if guest_cid < 3 || guest_cid == u32::MAX {
            return Err(ParseError::new(
                "framev-sock guest-cid must be in 3..u32::MAX",
            ));
        }
        set_once(
            &mut self.socket,
            SockConfig {
                guest_cid,
                guest_connect_host_ports,
                host_connect_guest_ports,
            },
            "framev-sock",
        )
    }

    fn add_network_device(&mut self, mut properties: Properties) -> Result<(), ParseError> {
        let netdev_id = properties.required("netdev")?;
        let mac_address = parse_mac_address(&properties.required("mac")?)?;
        let mtu = properties.required_u16("mtu")?;
        if mtu != FRAMEV_NET_MTU {
            return Err(ParseError::new(format!(
                "framev-net requires mtu={FRAMEV_NET_MTU}"
            )));
        }
        properties.reject_unknown()?;
        set_once(
            &mut self.network,
            PendingNetworkConfig {
                netdev_id,
                mac_address,
            },
            "framev-net",
        )
    }

    fn add_vfio_device(&mut self, mut properties: Properties) -> Result<(), ParseError> {
        let host = properties.required("host")?;
        properties.reject_unknown()?;
        set_once(
            &mut self.assigned_pci,
            parse_pci_address(&host)?,
            "vfio-pci",
        )
    }

    fn add_netdev(&mut self, value: String) -> Result<(), ParseError> {
        let (netdev_name, mut properties) = Properties::parse_named("-netdev", value)?;
        if netdev_name != "socket" {
            return Err(ParseError::new(format!(
                "unsupported -netdev '{netdev_name}'"
            )));
        }
        let id = properties.required("id")?;
        let endpoint_fd = properties.required_i32("fd")?;
        if endpoint_fd < 0 {
            return Err(ParseError::new("-netdev socket requires a nonnegative fd"));
        }
        properties.reject_unknown()?;
        if self.netdevs.insert(id.clone(), endpoint_fd).is_some() {
            return Err(ParseError::new(format!("duplicate -netdev id '{id}'")));
        }
        Ok(())
    }

    fn finish(mut self) -> Result<VmConfig, ParseError> {
        let vcpu_count = self
            .vcpu_count
            .ok_or_else(|| ParseError::new("missing required option '-smp'"))?;
        let memory_limit_bytes = self
            .memory_limit_bytes
            .ok_or_else(|| ParseError::new("missing required option '-m'"))?;
        let kernel_path = self
            .kernel_path
            .ok_or_else(|| ParseError::new("missing required option '-kernel'"))?;
        if !self.uses_stdio_console {
            return Err(ParseError::new("missing required option '-nographic'"));
        }
        let root_drive_id = self
            .root_drive_id
            .ok_or_else(|| ParseError::new("missing required device 'framev-blk'"))?;
        let root_drive = self.drives.remove(&root_drive_id).ok_or_else(|| {
            ParseError::new(format!(
                "framev-blk references unknown drive '{root_drive_id}'"
            ))
        })?;
        if root_drive.is_read_only {
            return Err(ParseError::new("FrameVM root drive must be writable"));
        }
        let mut secondary_drives = Vec::new();
        for drive_id in self.block_drive_ids {
            if drive_id == root_drive_id {
                continue;
            }
            let drive = self.drives.remove(&drive_id).ok_or_else(|| {
                ParseError::new(format!("framev-blk references unknown drive '{drive_id}'"))
            })?;
            secondary_drives.push(drive);
        }
        let network = self
            .network
            .take()
            .map(|pending| {
                let endpoint_fd = self.netdevs.remove(&pending.netdev_id).ok_or_else(|| {
                    ParseError::new(format!(
                        "framev-net references unknown netdev '{}'",
                        pending.netdev_id
                    ))
                })?;
                Ok(NetworkConfig {
                    endpoint_fd,
                    mac_address: pending.mac_address,
                })
            })
            .transpose()?;
        let socket = self
            .socket
            .ok_or_else(|| ParseError::new("missing required device 'framev-sock'"))?;
        if let Some((id, _)) = self.drives.into_iter().next() {
            return Err(ParseError::new(format!("unused -drive id '{id}'")));
        }
        if let Some((id, _)) = self.netdevs.into_iter().next() {
            return Err(ParseError::new(format!("unused -netdev id '{id}'")));
        }

        Ok(VmConfig {
            vcpu_count,
            scheduler_share: self.scheduler_share.unwrap_or(DEFAULT_SCHEDULER_SHARE),
            memory_limit_bytes,
            kernel_path,
            cmdline: self.cmdline,
            uses_stdio_console: self.uses_stdio_console,
            root_drive,
            secondary_drives,
            socket,
            network,
            assigned_pci: self.assigned_pci,
        })
    }
}

struct Properties {
    owner: String,
    values: BTreeMap<String, String>,
}

impl Properties {
    fn parse(owner: impl Into<String>, value: String) -> Result<Self, ParseError> {
        let owner = owner.into();
        let mut values = BTreeMap::new();
        for property in value.split(',') {
            let (key, property_value) = property.split_once('=').ok_or_else(|| {
                ParseError::new(format!("{owner} property '{property}' requires '='"))
            })?;
            if key.is_empty() || property_value.is_empty() {
                return Err(ParseError::new(format!("{owner} has an empty property")));
            }
            if values
                .insert(key.to_string(), property_value.to_string())
                .is_some()
            {
                return Err(ParseError::new(format!("{owner} repeats property '{key}'")));
            }
        }
        Ok(Self { owner, values })
    }

    fn parse_named(owner: &'static str, value: String) -> Result<(String, Self), ParseError> {
        let (device_name, properties) = value.split_once(',').ok_or_else(|| {
            ParseError::new(format!("{owner} requires a device name and properties"))
        })?;
        if device_name.is_empty() {
            return Err(ParseError::new(format!("{owner} requires a device name")));
        }
        Ok((
            device_name.to_string(),
            Self::parse(device_name, properties.to_string())?,
        ))
    }

    fn required(&mut self, key: &str) -> Result<String, ParseError> {
        self.values
            .remove(key)
            .ok_or_else(|| ParseError::new(format!("{} requires property '{key}'", self.owner)))
    }

    fn required_bool(&mut self, key: &str) -> Result<bool, ParseError> {
        let value = self.required(key)?;
        parse_boolean(&self.owner, key, &value)
    }

    fn optional_bool(&mut self, key: &str) -> Result<Option<bool>, ParseError> {
        self.values
            .remove(key)
            .map(|value| parse_boolean(&self.owner, key, &value))
            .transpose()
    }

    fn required_i32(&mut self, key: &str) -> Result<i32, ParseError> {
        let value = self.required(key)?;
        value.parse::<i32>().map_err(|_| {
            ParseError::new(format!(
                "{} property '{key}' requires an integer",
                self.owner
            ))
        })
    }

    fn required_u16(&mut self, key: &str) -> Result<u16, ParseError> {
        let value = self.required(key)?;
        value.parse::<u16>().map_err(|_| {
            ParseError::new(format!(
                "{} property '{key}' requires an unsigned integer",
                self.owner
            ))
        })
    }

    fn required_u32(&mut self, key: &str) -> Result<u32, ParseError> {
        let value = self.required(key)?;
        value.parse::<u32>().map_err(|_| {
            ParseError::new(format!(
                "{} property '{key}' requires an unsigned integer",
                self.owner
            ))
        })
    }

    fn optional_port_list(&mut self, key: &str) -> Result<Vec<u32>, ParseError> {
        let Some(value) = self.values.remove(key) else {
            return Ok(Vec::new());
        };
        let mut ports = BTreeSet::new();
        for item in value.split(':') {
            let port = item.parse::<u32>().map_err(|_| {
                ParseError::new(format!(
                    "{} property '{key}' requires colon-separated unsigned ports",
                    self.owner
                ))
            })?;
            if port == u32::MAX {
                return Err(ParseError::new(format!(
                    "{} property '{key}' contains a reserved port",
                    self.owner
                )));
            }
            if !ports.insert(port) {
                return Err(ParseError::new(format!(
                    "{} property '{key}' repeats port '{port}'",
                    self.owner
                )));
            }
        }
        if ports.len() > framevm_abi::FRAMEVM_SOCK_MAX_PORTS_PER_DIRECTION as usize {
            return Err(ParseError::new(format!(
                "{} property '{key}' contains too many ports",
                self.owner
            )));
        }
        Ok(ports.into_iter().collect())
    }

    fn reject_unknown(&self) -> Result<(), ParseError> {
        if let Some((key, _)) = self.values.first_key_value() {
            return Err(ParseError::new(format!(
                "{} has unsupported property '{key}'",
                self.owner
            )));
        }
        Ok(())
    }
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<String, ParseError> {
    let value = arguments
        .next()
        .ok_or_else(|| ParseError::new(format!("{option} requires a value")))?;
    os_string_to_string(value, option)
}

fn os_string_to_string(value: OsString, context: &str) -> Result<String, ParseError> {
    value
        .into_string()
        .map_err(|_| ParseError::new(format!("{context} must be valid UTF-8")))
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), ParseError> {
    if slot.replace(value).is_some() {
        return Err(ParseError::new(format!("duplicate {name}")));
    }
    Ok(())
}

fn parse_smp(value: &str) -> Result<NonZeroU8, ParseError> {
    let value = value.strip_prefix("cpus=").unwrap_or(value);
    let count = value
        .parse::<u8>()
        .map_err(|_| ParseError::new("-smp requires an integer CPU count"))?;
    if !(MIN_VCPU_COUNT..=MAX_VCPU_COUNT).contains(&count) {
        return Err(ParseError::new(format!(
            "-smp requires a CPU count in {MIN_VCPU_COUNT}..={MAX_VCPU_COUNT}"
        )));
    }
    NonZeroU8::new(count).ok_or_else(|| ParseError::new("-smp requires a nonzero CPU count"))
}

fn parse_memory_limit(value: &str) -> Result<u64, ParseError> {
    let (digits, multiplier) = match value.as_bytes().last().copied() {
        Some(b'b' | b'B') => (&value[..value.len() - 1], 1),
        Some(b'k' | b'K') => (&value[..value.len() - 1], 1 << 10),
        Some(b'm' | b'M') => (&value[..value.len() - 1], 1 << 20),
        Some(b'g' | b'G') => (&value[..value.len() - 1], 1 << 30),
        Some(b't' | b'T') => (&value[..value.len() - 1], 1 << 40),
        _ => (value, 1),
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|_| ParseError::new("-m requires a byte size such as 8G"))?;
    let memory_limit_bytes = amount
        .checked_mul(multiplier)
        .ok_or_else(|| ParseError::new("-m memory limit overflows bytes"))?;
    if memory_limit_bytes == 0 || memory_limit_bytes % FRAMEVM_PAGE_SIZE_BYTES != 0 {
        return Err(ParseError::new(
            "-m requires a nonzero page-aligned memory limit",
        ));
    }
    Ok(memory_limit_bytes)
}

fn parse_boolean(owner: &str, key: &str, value: &str) -> Result<bool, ParseError> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(ParseError::new(format!(
            "{owner} property '{key}' requires on or off"
        ))),
    }
}

fn parse_mac_address(value: &str) -> Result<[u8; 6], ParseError> {
    let mut address = [0; 6];
    let mut octets = value.split(':');
    for octet in &mut address {
        let value = octets
            .next()
            .ok_or_else(|| ParseError::new("framev-net mac requires six octets"))?;
        if value.len() != 2 {
            return Err(ParseError::new(
                "framev-net mac octets require two hex digits",
            ));
        }
        *octet = u8::from_str_radix(value, 16)
            .map_err(|_| ParseError::new("framev-net mac contains invalid hex digits"))?;
    }
    if octets.next().is_some() {
        return Err(ParseError::new("framev-net mac requires six octets"));
    }
    Ok(address)
}

fn parse_pci_address(value: &str) -> Result<PciAddress, ParseError> {
    if value.len() != 12
        || value.as_bytes()[4] != b':'
        || value.as_bytes()[7] != b':'
        || value.as_bytes()[10] != b'.'
    {
        return Err(ParseError::new("vfio-pci host requires dddd:bb:ss.f"));
    }
    let segment = u16::from_str_radix(&value[0..4], 16)
        .map_err(|_| ParseError::new("vfio-pci host contains invalid segment"))?;
    let bus = u8::from_str_radix(&value[5..7], 16)
        .map_err(|_| ParseError::new("vfio-pci host contains invalid bus"))?;
    let device = u8::from_str_radix(&value[8..10], 16)
        .map_err(|_| ParseError::new("vfio-pci host contains invalid device"))?;
    let function = u8::from_str_radix(&value[11..12], 16)
        .map_err(|_| ParseError::new("vfio-pci host contains invalid function"))?;
    if device >= 32 || function >= 8 {
        return Err(ParseError::new(
            "vfio-pci host has an out-of-range BDF field",
        ));
    }
    Ok(PciAddress {
        segment,
        bus,
        device,
        function,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn parse_fixture(arguments: &[&str]) -> Result<VmConfig, ParseError> {
        parse(arguments.iter().map(OsString::from))
    }

    fn fixture_arguments() -> Vec<&'static str> {
        vec![
            "framevmm",
            "-smp",
            "cpus=2",
            "-m",
            "8G",
            "-share",
            "4096",
            "-kernel",
            "/framevm/framevm.o",
            "-append",
            "init=/bin/framevm-test-runner FRAMEVM_TEST=boot",
            "-nographic",
            "-drive",
            "file=/framevm/rootfs.ext2,id=root,format=raw,readonly=off",
            "-device",
            "framev-blk,drive=root,root=on",
            "-device",
            "framev-sock,guest-cid=3,guest-connect-host-ports=1234:65530,host-connect-guest-ports=4321:65531",
            "-netdev",
            "socket,id=peer,fd=7",
            "-device",
            "framev-net,netdev=peer,mac=02:00:00:00:00:01,mtu=1500",
            "-device",
            "vfio-pci,host=0000:00:0b.0",
        ]
    }

    #[test]
    fn fixture_normalizes_into_typed_configuration() {
        let configuration = parse_fixture(&fixture_arguments()).unwrap();

        assert_eq!(configuration.vcpu_count(), NonZeroU8::new(2).unwrap());
        assert_eq!(configuration.scheduler_share(), 4_096);
        assert_eq!(configuration.memory_limit_bytes(), 8 * 1024 * 1024 * 1024);
        assert_eq!(
            configuration.kernel_path(),
            &PathBuf::from("/framevm/framevm.o")
        );
        assert_eq!(configuration.root_drive().id(), "root");
        assert!(!configuration.root_drive().is_read_only());
        assert_eq!(
            configuration.assigned_pci(),
            Some(PciAddress {
                segment: 0,
                bus: 0,
                device: 0x0b,
                function: 0,
            })
        );
        assert_eq!(
            configuration.socket,
            SockConfig {
                guest_cid: 3,
                guest_connect_host_ports: vec![1234, 65_530],
                host_connect_guest_ports: vec![4321, 65_531],
            }
        );
        assert_eq!(
            configuration.network,
            Some(NetworkConfig {
                endpoint_fd: 7,
                mac_address: [0x02, 0, 0, 0, 0, 1],
            })
        );
    }

    #[test]
    fn framev_net_can_precede_its_netdev() {
        let arguments = [
            "framevmm",
            "-smp",
            "2",
            "-m",
            "8G",
            "-kernel",
            "/framevm/framevm.o",
            "-nographic",
            "-drive",
            "file=/framevm/rootfs.ext2,id=root,format=raw",
            "-device",
            "framev-blk,drive=root,root=on",
            "-device",
            "framev-sock,guest-cid=3",
            "-device",
            "framev-net,netdev=peer,mac=02:00:00:00:00:01,mtu=1500",
            "-netdev",
            "socket,id=peer,fd=7",
        ];

        let configuration = parse_fixture(&arguments).unwrap();

        assert_eq!(
            configuration.network,
            Some(NetworkConfig {
                endpoint_fd: 7,
                mac_address: [0x02, 0, 0, 0, 0, 1],
            })
        );
    }

    #[test]
    fn secondary_drive_is_normalized_after_the_root_drive() {
        let mut arguments = fixture_arguments();
        arguments.extend([
            "-drive",
            "file=/framevm/data.ext2,id=data,format=raw,readonly=on",
            "-device",
            "framev-blk,drive=data,root=off",
        ]);

        let configuration = parse_fixture(&arguments).unwrap();

        assert_eq!(configuration.secondary_drives().len(), 1);
        assert_eq!(configuration.secondary_drives()[0].id(), "data");
        assert!(configuration.secondary_drives()[0].is_read_only());
    }

    #[test]
    fn memory_limit_requires_page_alignment() {
        let error = parse_fixture(&["framevmm", "-m", "1K"]).unwrap_err();

        assert_eq!(
            error.to_string(),
            "-m requires a nonzero page-aligned memory limit"
        );
    }

    #[test]
    fn memory_limit_is_required_before_resource_validation() {
        let mut arguments = fixture_arguments();
        let memory_option = arguments
            .iter()
            .position(|argument| *argument == "-m")
            .unwrap();
        arguments.drain(memory_option..=memory_option + 1);

        let error = parse_fixture(&arguments).unwrap_err();
        assert_eq!(error.to_string(), "missing required option '-m'");
    }

    #[test]
    fn memory_limit_rejects_overflow() {
        let error = parse_fixture(&["framevmm", "-m", "18446744073709551615T"]).unwrap_err();

        assert_eq!(error.to_string(), "-m memory limit overflows bytes");
    }

    #[test]
    fn scheduler_share_defaults_and_validates() {
        let mut arguments = fixture_arguments();
        let share_option = arguments
            .iter()
            .position(|argument| *argument == "-share")
            .unwrap();
        arguments.drain(share_option..=share_option + 1);
        assert_eq!(
            parse_fixture(&arguments).unwrap().scheduler_share(),
            DEFAULT_SCHEDULER_SHARE
        );

        arguments.extend(["-share", "1"]);
        let error = parse_fixture(&arguments).unwrap_err();
        assert_eq!(error.to_string(), "-share requires a value in 2..=262144");
    }

    #[test]
    fn duplicate_property_names_the_property() {
        let error = parse_fixture(&[
            "framevmm",
            "-drive",
            "file=/root,id=root,id=second,format=raw",
        ])
        .unwrap_err();

        assert_eq!(error.to_string(), "-drive repeats property 'id'");
    }

    #[test]
    fn network_rejects_unknown_reference() {
        let mut arguments = fixture_arguments();
        let netdev = arguments
            .iter()
            .position(|argument| *argument == "socket,id=peer,fd=7")
            .unwrap();
        arguments[netdev] = "socket,id=other,fd=7";

        let error = parse_fixture(&arguments).unwrap_err();

        assert_eq!(
            error.to_string(),
            "framev-net references unknown netdev 'peer'"
        );
    }

    #[test]
    fn reserved_sock_cid_is_rejected() {
        let error = parse_fixture(&["framevmm", "-device", "framev-sock,guest-cid=2"]).unwrap_err();

        assert_eq!(
            error.to_string(),
            "framev-sock guest-cid must be in 3..u32::MAX"
        );
    }

    #[test]
    fn duplicate_sock_policy_port_is_rejected() {
        let mut arguments = fixture_arguments();
        let sock = arguments
            .iter()
            .position(|argument| argument.starts_with("framev-sock,"))
            .unwrap();
        arguments[sock] = "framev-sock,guest-cid=3,guest-connect-host-ports=80:80";

        let error = parse_fixture(&arguments).unwrap_err();

        assert_eq!(
            error.to_string(),
            "framev-sock property 'guest-connect-host-ports' repeats port '80'"
        );
    }

    #[test]
    fn oversized_sock_policy_is_rejected() {
        let mut arguments = fixture_arguments();
        let sock = arguments
            .iter()
            .position(|argument| argument.starts_with("framev-sock,"))
            .unwrap();
        arguments[sock] = "framev-sock,guest-cid=3,host-connect-guest-ports=1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16:17";

        let error = parse_fixture(&arguments).unwrap_err();

        assert_eq!(
            error.to_string(),
            "framev-sock property 'host-connect-guest-ports' contains too many ports"
        );
    }

    #[test]
    fn missing_sock_device_is_rejected() {
        let mut arguments = fixture_arguments();
        let option = arguments
            .iter()
            .position(|argument| argument.starts_with("framev-sock,"))
            .unwrap();
        arguments.drain(option - 1..=option);

        let error = parse_fixture(&arguments).unwrap_err();

        assert_eq!(error.to_string(), "missing required device 'framev-sock'");
    }

    #[test]
    fn vfio_requires_complete_pci_address() {
        let error = parse_fixture(&["framevmm", "-device", "vfio-pci,host=00:0b.0"]).unwrap_err();

        assert_eq!(error.to_string(), "vfio-pci host requires dddd:bb:ss.f");
    }
}
