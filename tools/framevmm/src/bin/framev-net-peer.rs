//! Deterministic smoltcp peer for the FrameV-net integration test.

use std::{
    cell::Cell,
    env, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixDatagram, process::CommandExt},
    },
    process::{Child, Command, ExitCode, ExitStatus},
    thread,
    time::{Duration as StdDuration, Instant as StdInstant},
};

use sha2::{Digest, Sha256};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::tcp,
    time::Instant,
    wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr},
};

const PEER_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 2]);
const GUEST_MAC: &str = "02:00:00:00:00:01";
const HTTP_PORT: u16 = 80;
const HTTP_BODY: &[u8] = b"FrameV-net HTTP OK\n";
const TEST_TIMEOUT: StdDuration = StdDuration::from_secs(45);
const APPLICATION_HTTP_PORT: u16 = 8_080;
const APPLICATION_SOURCE_PORT: u16 = 49_152;
const APPLICATION_BODY_LEN: usize = 16_384;
const APPLICATION_BODY_SHA256: [u8; 32] = [
    0xc6, 0x02, 0xe7, 0xc4, 0x00, 0x4d, 0x0d, 0x12, 0x95, 0x07, 0x33, 0xb8, 0x9c, 0x1a, 0xbd, 0x6c,
    0xe4, 0xf6, 0x67, 0xcd, 0x9d, 0x4a, 0xf4, 0x47, 0x54, 0x47, 0xcd, 0x36, 0xdf, 0xf6, 0x48, 0xf1,
];
const APPLICATION_TIMEOUT: StdDuration = StdDuration::from_secs(180);
const CONNECT_RETRY_INTERVAL: StdDuration = StdDuration::from_millis(250);
const MAX_HTTP_HEADERS: usize = 16 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PeerMode {
    FixtureServer,
    ApplicationClient,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("framev-net-peer: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    if env::args().nth(1).as_deref() == Some("--shell") {
        return run_demo_shell();
    }

    let mode = match env::var("FRAMEV_NET_PEER_MODE").as_deref() {
        Ok("application") => PeerMode::ApplicationClient,
        Ok(value) => return Err(format!("unknown FRAMEV_NET_PEER_MODE={value}")),
        Err(env::VarError::NotPresent) => PeerMode::FixtureServer,
        Err(error) => return Err(format!("read FRAMEV_NET_PEER_MODE: {error}")),
    };
    let command = parse_command()?;
    let (peer_socket, guest_socket) =
        UnixDatagram::pair().map_err(io_error("create socketpair"))?;
    peer_socket
        .set_nonblocking(true)
        .map_err(io_error("set peer socket nonblocking"))?;
    guest_socket
        .set_nonblocking(true)
        .map_err(io_error("set guest socket nonblocking"))?;
    let inherited_guest = inheritable_duplicate(&guest_socket)
        .map_err(io_error("duplicate inherited network endpoint"))?;
    let mut child = spawn_framevmm(command, inherited_guest.as_raw_fd())?;
    drop(inherited_guest);
    drop(guest_socket);

    match mode {
        PeerMode::FixtureServer => {
            let (served, status) = serve_http(peer_socket, &mut child)?;
            require_success(status, served)
        }
        PeerMode::ApplicationClient => run_application_client(peer_socket, &mut child),
    }
}

/// Runs an interactive Host shell with a FrameV-net endpoint on file descriptor 3.
fn run_demo_shell() -> Result<(), String> {
    let (peer_socket, guest_socket) =
        UnixDatagram::pair().map_err(io_error("create socketpair"))?;
    peer_socket
        .set_nonblocking(true)
        .map_err(io_error("set peer socket nonblocking"))?;
    guest_socket
        .set_nonblocking(true)
        .map_err(io_error("set guest socket nonblocking"))?;
    let inherited_guest = inheritable_duplicate(&guest_socket)
        .map_err(io_error("duplicate inherited network endpoint"))?;
    let endpoint_fd = inherited_guest.as_raw_fd();

    let mut shell = Command::new("script");
    shell.args(["/dev/null", "-q", "-c", "/bin/sh -i"]);
    // SAFETY: the closure only invokes async-signal-safe libc operations before `exec`.
    unsafe {
        shell.pre_exec(move || {
            if libc::dup2(endpoint_fd, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut shell = shell.spawn().map_err(io_error("start interactive shell"))?;
    drop(inherited_guest);
    drop(guest_socket);

    run_demo_application_peer(peer_socket, &mut shell)
}

fn parse_command() -> Result<Vec<String>, String> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("--") {
        return Err(String::from("expected '--' followed by a framevmm command"));
    }
    let command = arguments.collect::<Vec<_>>();
    if command.is_empty() {
        return Err(String::from("missing framevmm command after '--'"));
    }
    Ok(command)
}

fn spawn_framevmm(command: Vec<String>, endpoint_fd: i32) -> Result<Child, String> {
    let mut command = command.into_iter();
    let Some(program) = command.next() else {
        return Err(String::from("missing framevmm executable"));
    };
    let peer_pid = std::process::id();
    let mut child = Command::new(program);
    child.args(command).args([
        "-netdev".to_string(),
        format!("socket,id=framev-peer,fd={endpoint_fd}"),
        "-device".to_string(),
        format!("framev-net,netdev=framev-peer,mac={GUEST_MAC},mtu=1500"),
    ]);
    // SAFETY: the closure only invokes async-signal-safe libc operations before `exec`.
    unsafe {
        child.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() as u32 != peer_pid {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    child.spawn().map_err(io_error("spawn framevmm"))
}

fn serve_http(socket: UnixDatagram, child: &mut Child) -> Result<(bool, ExitStatus), String> {
    let mut device = DatagramDevice {
        fatal_error: Cell::new(None),
        received_bytes: 0,
        received_frames: 0,
        sent_bytes: Cell::new(0),
        sent_frames: Cell::new(0),
        tx_backpressure: Cell::new(0),
        socket,
    };
    let mut config = Config::new(HardwareAddress::Ethernet(PEER_MAC));
    config.random_seed = 0x4652_414d_4556_4e45;
    let started = StdInstant::now();
    let mut interface = Interface::new(config, &mut device, Instant::ZERO);
    interface.update_ip_addrs(|addresses| {
        let _ = addresses.push(IpCidr::new(IpAddress::v4(192, 0, 2, 1), 24));
    });

    let rx_buffer = tcp::SocketBuffer::new(vec![0; 4_096]);
    let tx_buffer = tcp::SocketBuffer::new(vec![0; 4_096]);
    let mut http_socket = tcp::Socket::new(rx_buffer, tx_buffer);
    http_socket
        .listen(HTTP_PORT)
        .map_err(|error| error.to_string())?;
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(http_socket);
    let mut request = Vec::new();
    let mut served = false;

    loop {
        let elapsed_millis = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let timestamp = Instant::from_millis(elapsed_millis);
        interface.poll(timestamp, &mut device, &mut sockets);
        device.check_error()?;
        let http = sockets.get_mut::<tcp::Socket>(handle);
        if http.may_recv() {
            http.recv(|bytes| {
                request.extend_from_slice(bytes);
                (bytes.len(), ())
            })
            .map_err(|error| error.to_string())?;
        }
        if !served && request.windows(4).any(|window| window == b"\r\n\r\n") && http.can_send() {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                HTTP_BODY.len(),
                String::from_utf8_lossy(HTTP_BODY)
            );
            http.send_slice(response.as_bytes())
                .map_err(|error| error.to_string())?;
            http.close();
            served = true;
            println!("FRAMEV_NET_HTTP_SERVED");
        }

        if let Some(status) = child.try_wait().map_err(io_error("query framevmm"))? {
            device.require_endpoint_copies()?;
            device.report_endpoint_copies();
            return Ok((served, status));
        }
        if started.elapsed() >= TEST_TIMEOUT {
            let received_frames = device.received_frames;
            let sent_frames = device.sent_frames.get();
            child
                .kill()
                .map_err(io_error("terminate timed-out framevmm"))?;
            return Err(format!(
                "HTTP exchange timed out after {TEST_TIMEOUT:?} (received_frames={received_frames}, sent_frames={sent_frames})"
            ));
        }
        thread::sleep(StdDuration::from_millis(1));
    }
}

fn run_application_client(socket: UnixDatagram, child: &mut Child) -> Result<(), String> {
    let mut device = DatagramDevice {
        fatal_error: Cell::new(None),
        received_bytes: 0,
        received_frames: 0,
        sent_bytes: Cell::new(0),
        sent_frames: Cell::new(0),
        tx_backpressure: Cell::new(0),
        socket,
    };
    let mut config = Config::new(HardwareAddress::Ethernet(PEER_MAC));
    config.random_seed = 0x4652_414d_4556_4150;
    let started = StdInstant::now();
    let mut interface = Interface::new(config, &mut device, Instant::ZERO);
    interface.update_ip_addrs(|addresses| {
        let _ = addresses.push(IpCidr::new(IpAddress::v4(192, 0, 2, 1), 24));
    });

    let rx_buffer = tcp::SocketBuffer::new(vec![0; 65_536]);
    let tx_buffer = tcp::SocketBuffer::new(vec![0; 65_536]);
    let handle = {
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(30)));
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        (sockets, handle)
    };
    let (mut sockets, handle) = handle;
    let request = b"GET /index.html HTTP/1.1\r\nHost: framevm.test\r\nConnection: close\r\n\r\n";
    let mut response = Vec::new();
    let mut request_queued = false;
    let mut attempted_connect = false;
    let mut next_connect = started;

    loop {
        let elapsed_millis = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let timestamp = Instant::from_millis(elapsed_millis);
        interface.poll(timestamp, &mut device, &mut sockets);
        device.check_error()?;

        let now = StdInstant::now();
        let http = sockets.get_mut::<tcp::Socket>(handle);
        if !http.is_open() && response.is_empty() && now >= next_connect {
            http.connect(
                interface.context(),
                (IpAddress::v4(192, 0, 2, 2), APPLICATION_HTTP_PORT),
                APPLICATION_SOURCE_PORT,
            )
            .map_err(|error| format!("start application TCP connection: {error}"))?;
            attempted_connect = true;
            request_queued = false;
            next_connect = now + CONNECT_RETRY_INTERVAL;
            println!("FRAMEVM_NGINX_TCP_ATTEMPT");
        }

        if http.can_send() && !request_queued {
            http.send_slice(request)
                .map_err(|error| format!("queue HTTP request: {error}"))?;
            request_queued = true;
        }
        while http.can_recv() {
            http.recv(|bytes| {
                response.extend_from_slice(bytes);
                (bytes.len(), ())
            })
            .map_err(|error| format!("receive HTTP response: {error}"))?;
            if response.len() > MAX_HTTP_HEADERS + APPLICATION_BODY_LEN {
                return Err(String::from("HTTP response exceeds the manifest bounds"));
            }
        }

        if !http.is_open() && request_queued {
            if response.is_empty() {
                request_queued = false;
                next_connect = now + CONNECT_RETRY_INTERVAL;
            } else {
                validate_application_response(&response)?;
                println!("FRAMEVM_NGINX_HTTP_OK");
                break;
            }
        }

        if let Some(status) = child.try_wait().map_err(io_error("query framevmm"))? {
            if request_queued && !response.is_empty() {
                // The guest stops Nginx immediately after its access log
                // records the request. It can therefore publish the FrameVM
                // terminal state before smoltcp observes the peer's final TCP
                // close. A complete response remains sufficient evidence of
                // the exchange; `validate_application_response` rejects a
                // partial final segment.
                validate_application_response(&response)?;
                if !status.success() {
                    return Err(format!("framevmm exited with {status}"));
                }
                device.require_endpoint_copies()?;
                device.report_endpoint_copies();
                println!("FRAMEVM_NGINX_HTTP_OK");
                println!("FRAMEVM_NGINX_PEER_OK");
                return Ok(());
            }
            return Err(format!(
                "framevmm exited before application HTTP validation with {status}"
            ));
        }
        if attempted_connect
            && device.received_frames == 0
            && started.elapsed() >= StdDuration::from_secs(10)
        {
            return Err(String::from("ARP stage timed out after 10s"));
        }
        if started.elapsed() >= APPLICATION_TIMEOUT {
            return Err(format!(
                "application HTTP stage timed out after {APPLICATION_TIMEOUT:?} (received_frames={}, sent_frames={}, tx_backpressure={})",
                device.received_frames,
                device.sent_frames.get(),
                device.tx_backpressure.get()
            ));
        }
        thread::sleep(StdDuration::from_millis(1));
    }

    let shutdown_deadline = StdInstant::now() + StdDuration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().map_err(io_error("query framevmm"))? {
            if !status.success() {
                return Err(format!("framevmm exited with {status}"));
            }
            device.require_endpoint_copies()?;
            device.report_endpoint_copies();
            println!("FRAMEVM_NGINX_PEER_OK");
            return Ok(());
        }
        if StdInstant::now() >= shutdown_deadline {
            return Err(String::from(
                "Nginx/FrameVM clean shutdown timed out after 30s",
            ));
        }
        thread::sleep(StdDuration::from_millis(10));
    }
}

/// Keeps a Host-side HTTP client available for an interactive FrameVM demo.
fn run_demo_application_peer(socket: UnixDatagram, shell: &mut Child) -> Result<(), String> {
    let mut device = DatagramDevice {
        fatal_error: Cell::new(None),
        received_bytes: 0,
        received_frames: 0,
        sent_bytes: Cell::new(0),
        sent_frames: Cell::new(0),
        tx_backpressure: Cell::new(0),
        socket,
    };
    let mut config = Config::new(HardwareAddress::Ethernet(PEER_MAC));
    config.random_seed = 0x4652_414d_4556_444d;
    let started = StdInstant::now();
    let mut interface = Interface::new(config, &mut device, Instant::ZERO);
    interface.update_ip_addrs(|addresses| {
        let _ = addresses.push(IpCidr::new(IpAddress::v4(192, 0, 2, 1), 24));
    });

    let rx_buffer = tcp::SocketBuffer::new(vec![0; 65_536]);
    let tx_buffer = tcp::SocketBuffer::new(vec![0; 65_536]);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(tcp::Socket::new(rx_buffer, tx_buffer));
    let request = b"GET /index.html HTTP/1.1\r\nHost: framevm.test\r\nConnection: close\r\n\r\n";
    let mut response = Vec::new();
    let mut request_queued = false;
    let mut next_connect = started;
    let mut validated = false;

    loop {
        let elapsed_millis = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let timestamp = Instant::from_millis(elapsed_millis);
        interface.poll(timestamp, &mut device, &mut sockets);
        device.check_error()?;

        let now = StdInstant::now();
        let http = sockets.get_mut::<tcp::Socket>(handle);
        if !validated && !http.is_open() && response.is_empty() && now >= next_connect {
            http.connect(
                interface.context(),
                (IpAddress::v4(192, 0, 2, 2), APPLICATION_HTTP_PORT),
                APPLICATION_SOURCE_PORT,
            )
            .map_err(|error| format!("start demo TCP connection: {error}"))?;
            request_queued = false;
            next_connect = now + CONNECT_RETRY_INTERVAL;
        }
        if !validated && http.can_send() && !request_queued {
            http.send_slice(request)
                .map_err(|error| format!("queue demo HTTP request: {error}"))?;
            request_queued = true;
        }
        while http.can_recv() {
            http.recv(|bytes| {
                response.extend_from_slice(bytes);
                (bytes.len(), ())
            })
            .map_err(|error| format!("receive demo HTTP response: {error}"))?;
            if response.len() > MAX_HTTP_HEADERS + APPLICATION_BODY_LEN {
                return Err(String::from(
                    "demo HTTP response exceeds the manifest bounds",
                ));
            }
        }
        if !validated && !http.is_open() && request_queued {
            if response.is_empty() {
                request_queued = false;
                next_connect = now + CONNECT_RETRY_INTERVAL;
            } else {
                validate_application_response(&response)?;
                print_demo_application_response(&response)?;
                println!("FRAMEVM_NGINX_HTTP_OK");
                validated = true;
            }
        }

        if let Some(status) = shell
            .try_wait()
            .map_err(io_error("query interactive shell"))?
        {
            if status.success() {
                return Ok(());
            }
            return Err(format!("interactive shell exited with {status}"));
        }
        thread::sleep(StdDuration::from_millis(1));
    }
}

/// Prints the visible portion of the response that completed the Nginx demo.
fn print_demo_application_response(response: &[u8]) -> Result<(), String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| String::from("HTTP response closed before complete headers"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| String::from("HTTP response headers are not UTF-8"))?;
    let body_start = header_end + 4;
    let body = std::str::from_utf8(&response[body_start..])
        .map_err(|_| String::from("HTTP response body is not UTF-8"))?;

    println!("\n===== FrameVM Nginx HTTP response =====");
    println!("{}", headers.lines().next().unwrap_or_default());
    for line in body.lines().take(3) {
        println!("{line}");
    }
    println!("[16 KiB response verified over FrameV-net]");
    println!("========================================\n");
    Ok(())
}

fn validate_application_response(response: &[u8]) -> Result<(), String> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(String::from("HTTP response closed before complete headers"));
    };
    let body_start = header_end + 4;
    if body_start > MAX_HTTP_HEADERS {
        return Err(String::from("HTTP response headers exceed 16 KiB"));
    }
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| String::from("HTTP response headers are not UTF-8"))?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(String::from("HTTP response status is not 200"));
    }
    let content_length = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| String::from("HTTP response lacks a valid Content-Length"))?;
    if content_length != APPLICATION_BODY_LEN {
        return Err(format!(
            "HTTP Content-Length is {content_length}, expected {APPLICATION_BODY_LEN}"
        ));
    }
    let body = &response[body_start..];
    if body.len() != APPLICATION_BODY_LEN {
        return Err(format!(
            "HTTP body length is {}, expected {APPLICATION_BODY_LEN}",
            body.len()
        ));
    }
    let digest: [u8; 32] = Sha256::digest(body).into();
    if digest != APPLICATION_BODY_SHA256 {
        return Err(format!("HTTP body SHA-256 mismatch: {digest:x?}"));
    }
    Ok(())
}

fn require_success(status: ExitStatus, served: bool) -> Result<(), String> {
    if !served {
        return Err(String::from(
            "framevmm exited before the HTTP exchange completed",
        ));
    }
    if !status.success() {
        return Err(format!("framevmm exited with {status}"));
    }
    println!("FRAMEV_NET_PEER_OK");
    Ok(())
}

fn inheritable_duplicate(socket: &UnixDatagram) -> io::Result<OwnedFd> {
    // SAFETY: `dup` borrows a valid fd and returns a new descriptor without `FD_CLOEXEC`.
    let fd = unsafe { libc::dup(socket.as_raw_fd()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `dup` transfers ownership of one new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn io_error(operation: &'static str) -> impl FnOnce(io::Error) -> String {
    move |error| format!("{operation}: {error}")
}

struct DatagramDevice {
    fatal_error: Cell<Option<io::ErrorKind>>,
    received_bytes: usize,
    received_frames: usize,
    sent_bytes: Cell<usize>,
    sent_frames: Cell<usize>,
    tx_backpressure: Cell<usize>,
    socket: UnixDatagram,
}

impl DatagramDevice {
    fn check_error(&self) -> Result<(), String> {
        let Some(kind) = self.fatal_error.take() else {
            return Ok(());
        };
        Err(format!("FrameV-net endpoint failed: {kind:?}"))
    }

    fn report_endpoint_copies(&self) {
        println!(
            "FRAMEV_NET_ENDPOINT_COPIES received_bytes={} sent_bytes={}",
            self.received_bytes,
            self.sent_bytes.get()
        );
    }

    fn require_endpoint_copies(&self) -> Result<(), String> {
        if self.received_bytes == 0 || self.sent_bytes.get() == 0 {
            return Err(String::from(
                "FrameV-net endpoint did not copy traffic in both directions",
            ));
        }
        Ok(())
    }
}

impl Device for DatagramDevice {
    type RxToken<'a> = DatagramRxToken;
    type TxToken<'a> = DatagramTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut frame = vec![0; 1_515];
        match self.socket.recv(&mut frame) {
            Ok(length) if length > 1_514 => {
                self.fatal_error.set(Some(io::ErrorKind::InvalidData));
                None
            }
            Ok(length) => {
                self.received_bytes = self.received_bytes.saturating_add(length);
                self.received_frames = self.received_frames.saturating_add(1);
                frame.truncate(length);
                Some((
                    DatagramRxToken { frame },
                    DatagramTxToken {
                        sent_frames: &self.sent_frames,
                        sent_bytes: &self.sent_bytes,
                        socket: &self.socket,
                        fatal_error: &self.fatal_error,
                        tx_backpressure: &self.tx_backpressure,
                    },
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(error) => {
                self.fatal_error.set(Some(error.kind()));
                None
            }
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(DatagramTxToken {
            sent_frames: &self.sent_frames,
            sent_bytes: &self.sent_bytes,
            socket: &self.socket,
            fatal_error: &self.fatal_error,
            tx_backpressure: &self.tx_backpressure,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = 1_514;
        capabilities
    }
}

struct DatagramRxToken {
    frame: Vec<u8>,
}

impl phy::RxToken for DatagramRxToken {
    fn consume<R, F>(self, consume_fn: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        consume_fn(&self.frame)
    }
}

struct DatagramTxToken<'a> {
    fatal_error: &'a Cell<Option<io::ErrorKind>>,
    sent_frames: &'a Cell<usize>,
    sent_bytes: &'a Cell<usize>,
    socket: &'a UnixDatagram,
    tx_backpressure: &'a Cell<usize>,
}

impl phy::TxToken for DatagramTxToken<'_> {
    fn consume<R, F>(self, length: usize, consume_fn: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0; length];
        let result = consume_fn(&mut frame);
        if length > 1_514 {
            self.fatal_error.set(Some(io::ErrorKind::InvalidInput));
            return result;
        }
        match self.socket.send(&frame) {
            Ok(sent_len) => {
                self.sent_bytes
                    .set(self.sent_bytes.get().saturating_add(sent_len));
                self.sent_frames
                    .set(self.sent_frames.get().saturating_add(1));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => self
                .tx_backpressure
                .set(self.tx_backpressure.get().saturating_add(1)),
            Err(error) => self.fatal_error.set(Some(error.kind())),
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_response() -> Vec<u8> {
        let mut body = b"FrameVM Nginx demo\nserved by Nginx inside an isolated FrameVM\nrequest completed over FrameV-net\n".to_vec();
        body.resize(APPLICATION_BODY_LEN, b'F');
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        response
    }

    #[test]
    fn accepts_manifest_bounded_application_response() {
        validate_application_response(&valid_response()).unwrap();
    }

    #[test]
    fn rejects_malformed_application_status() {
        let mut response = valid_response();
        response[..15].copy_from_slice(b"HTTP/1.1 500 OK");
        assert!(validate_application_response(&response).is_err());
    }

    #[test]
    fn rejects_application_body_hash_mismatch() {
        let mut response = valid_response();
        *response.last_mut().unwrap() = b'X';
        assert!(validate_application_response(&response).is_err());
    }

    #[test]
    fn rejects_application_body_length_mismatch() {
        let mut response = valid_response();
        response.pop();
        assert!(validate_application_response(&response).is_err());
    }
}
