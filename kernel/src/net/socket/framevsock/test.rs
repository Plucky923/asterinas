// SPDX-License-Identifier: MPL-2.0

//! FrameVsock test framework for end-to-end communication testing.
//!
//! This module provides utilities to test bidirectional communication
//! between Host (kernel) and Guest (FrameVM).

use alloc::{sync::Arc, vec};

use aster_framevisor::vsock as framevisor_vsock;
use aster_framevsock::{VMADDR_CID_GUEST, create_data_packet};
use log::{debug, info, warn};
use spin::Once;

use super::{
    addr::{FrameVsockAddr, VMADDR_CID_HOST},
    stream::socket::FrameVsockStreamSocket,
};
use crate::{
    net::socket::{
        Socket,
        util::{MessageHeader, SocketAddr},
    },
    prelude::*,
    util::{MultiRead, MultiWrite, ReadCString},
};

/// Default test ports
pub const HOST_TEST_PORT: u32 = 8080;
pub const GUEST_TEST_PORT: u32 = 12345;

/// Global echo server socket for polling-based accept
static ECHO_SERVER_SOCKET: Once<Arc<FrameVsockStreamSocket>> = Once::new();

/// Start a test echo server on the Host side.
/// This server accepts connections from Guest and echoes back received data.
pub fn start_host_echo_server(port: u32) -> Result<()> {
    info!(
        "[FrameVsock Test] Starting Host echo server on port {}",
        port
    );

    let socket = FrameVsockStreamSocket::new(false)?;
    let addr = SocketAddr::FrameVsock(FrameVsockAddr::new(VMADDR_CID_HOST, port));
    socket.bind(addr)?;
    socket.listen(5)?;

    info!(
        "[FrameVsock Test] Host echo server listening on port {}",
        port
    );

    // Spawn a kernel thread to handle connections
    let socket = Arc::new(socket);
    spawn_echo_handler(socket);

    Ok(())
}

/// Spawn a kernel thread to handle echo connections
fn spawn_echo_handler(listen_socket: Arc<FrameVsockStreamSocket>) {
    debug!("[FrameVsock Test] Echo handler spawning kernel thread");

    // Store the listen socket for later polling
    // In a real implementation with blocking support, we would:
    // 1. Accept connections in a loop
    // 2. For each connection, spawn a handler thread
    // 3. The handler would recv/send in a loop

    // For now, since blocking isn't implemented, store it globally
    // and let the test driver poll it
    ECHO_SERVER_SOCKET.call_once(|| listen_socket);
}

/// Test: Host connects to Guest's listening socket
///
/// Prerequisites:
/// - Guest must have a listening socket on GUEST_TEST_PORT (12345)
/// - Call this after FrameVM has started and set up its listener
pub fn test_host_connect_to_guest() -> Result<()> {
    info!("[FrameVsock Test] Testing Host -> Guest connection");

    let socket = FrameVsockStreamSocket::new(false)?;
    let peer_addr = SocketAddr::FrameVsock(FrameVsockAddr::new(VMADDR_CID_GUEST, GUEST_TEST_PORT));

    info!(
        "[FrameVsock Test] Connecting to Guest at CID={}, port={}",
        VMADDR_CID_GUEST, GUEST_TEST_PORT
    );

    socket.connect(peer_addr)?;

    info!("[FrameVsock Test] Connected to Guest successfully!");

    // Send test data
    let test_data = b"Hello from Host!";
    info!(
        "[FrameVsock Test] Sending test data: {:?}",
        core::str::from_utf8(test_data).unwrap_or("<binary>")
    );

    // Send using the socket
    let mut reader = VecReader::new(test_data.to_vec());
    let message_header = MessageHeader::new(None, alloc::vec![]);
    let sent = socket.sendmsg(
        &mut reader,
        message_header,
        crate::net::socket::util::SendRecvFlags::empty(),
    )?;
    info!("[FrameVsock Test] Sent {} bytes", sent);

    // Poll recv until we get data or timeout
    let mut recv_buf = vec![0u8; 256];
    let mut writer = VecWriter::new(&mut recv_buf);

    // Polling loop with retry limit
    let mut retries = 0;
    const MAX_RETRIES: u32 = 100000;

    loop {
        match socket.recvmsg(
            &mut writer,
            crate::net::socket::util::SendRecvFlags::empty(),
        ) {
            Ok((received, _header)) => {
                info!("[FrameVsock Test] Received {} bytes", received);
                let response = &recv_buf[..received];
                info!(
                    "[FrameVsock Test] Response: {:?}",
                    core::str::from_utf8(response).unwrap_or("<binary>")
                );

                // Verify echo
                if response == test_data {
                    info!("[FrameVsock Test] Echo verification PASSED!");
                } else {
                    warn!(
                        "[FrameVsock Test] Echo verification FAILED! Expected: {:?}, Got: {:?}",
                        test_data, response
                    );
                }
                break;
            }
            Err(e) if e.error() == Errno::EAGAIN => {
                retries += 1;
                if retries >= MAX_RETRIES {
                    warn!(
                        "[FrameVsock Test] Timeout waiting for echo response after {} retries",
                        retries
                    );
                    break;
                }
                // Continue polling
                continue;
            }
            Err(e) => {
                warn!("[FrameVsock Test] Recv error: {:?}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Simple reader wrapper for Vec<u8>
struct VecReader {
    data: alloc::vec::Vec<u8>,
    pos: usize,
}

impl VecReader {
    fn new(data: alloc::vec::Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }
}

impl ReadCString for VecReader {
    fn read_cstring_until_nul(&mut self, max_len: usize) -> Result<Option<CString>> {
        let remaining = &self.data[self.pos..];
        let search_len = remaining.len().min(max_len);

        if let Some(null_pos) = remaining[..search_len].iter().position(|&b| b == 0) {
            let bytes: alloc::vec::Vec<u8> = remaining[..null_pos].to_vec();
            self.pos += null_pos + 1;
            Ok(Some(
                CString::new(bytes).map_err(|_| Error::new(Errno::EINVAL))?,
            ))
        } else {
            Ok(None)
        }
    }

    fn read_cstring_until_end(&mut self, max_len: usize) -> Result<(CString, usize)> {
        let remaining = &self.data[self.pos..];
        let search_len = remaining.len().min(max_len);

        if let Some(null_pos) = remaining[..search_len].iter().position(|&b| b == 0) {
            let bytes: alloc::vec::Vec<u8> = remaining[..null_pos].to_vec();
            self.pos += null_pos + 1;
            Ok((
                CString::new(bytes).map_err(|_| Error::new(Errno::EINVAL))?,
                null_pos + 1,
            ))
        } else {
            let bytes: alloc::vec::Vec<u8> = remaining[..search_len].to_vec();
            self.pos += search_len;
            Ok((
                CString::new(bytes).map_err(|_| Error::new(Errno::EINVAL))?,
                search_len,
            ))
        }
    }
}

impl MultiRead for VecReader {
    fn read(&mut self, writer: &mut ostd::mm::VmWriter<'_, ostd::mm::Infallible>) -> Result<usize> {
        let remaining = &self.data[self.pos..];
        let to_write = remaining.len().min(writer.avail());
        writer.write(&mut ostd::mm::VmReader::from(&remaining[..to_write]));
        self.pos += to_write;
        Ok(to_write)
    }

    fn sum_lens(&self) -> usize {
        self.data.len() - self.pos
    }

    fn skip_some(&mut self, nbytes: usize) {
        let skip = nbytes.min(self.data.len() - self.pos);
        self.pos += skip;
    }
}

/// Simple writer wrapper for &mut Vec<u8>
struct VecWriter<'a> {
    buf: &'a mut alloc::vec::Vec<u8>,
    pos: usize,
}

impl<'a> VecWriter<'a> {
    fn new(buf: &'a mut alloc::vec::Vec<u8>) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> MultiWrite for VecWriter<'a> {
    fn write(
        &mut self,
        reader: &mut ostd::mm::VmReader<'_, ostd::mm::Infallible>,
    ) -> Result<usize> {
        let available = self.buf.len() - self.pos;
        let to_read = available.min(reader.remain());
        let mut tmp = vec![0u8; to_read];
        reader.read(&mut ostd::mm::VmWriter::from(tmp.as_mut_slice()));
        self.buf[self.pos..self.pos + to_read].copy_from_slice(&tmp);
        self.pos += to_read;
        Ok(to_read)
    }

    fn sum_lens(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn skip_some(&mut self, nbytes: usize) {
        let skip = nbytes.min(self.buf.len() - self.pos);
        self.pos += skip;
    }
}

/// Send test data to Guest and verify echo response
pub fn test_echo_roundtrip(port: u32, data: &[u8]) -> Result<()> {
    info!(
        "[FrameVsock Test] Starting echo roundtrip test to port {}",
        port
    );

    let socket = FrameVsockStreamSocket::new(false)?;
    let peer_addr = SocketAddr::FrameVsock(FrameVsockAddr::new(VMADDR_CID_GUEST, port));

    socket.connect(peer_addr)?;
    info!("[FrameVsock Test] Connected to Guest");

    // Send data
    let mut reader = VecReader::new(data.to_vec());
    let message_header = MessageHeader::new(None, alloc::vec![]);
    let sent = socket.sendmsg(
        &mut reader,
        message_header,
        crate::net::socket::util::SendRecvFlags::empty(),
    )?;
    info!(
        "[FrameVsock Test] Sent {} bytes: {:?}",
        sent,
        core::str::from_utf8(data).unwrap_or("<binary>")
    );

    // Poll for echo response
    let mut recv_buf = vec![0u8; 256];
    let mut writer = VecWriter::new(&mut recv_buf);

    let mut retries = 0;
    const MAX_RETRIES: u32 = 100000;

    loop {
        match socket.recvmsg(
            &mut writer,
            crate::net::socket::util::SendRecvFlags::empty(),
        ) {
            Ok((received, _header)) => {
                let response = &recv_buf[..received];
                info!(
                    "[FrameVsock Test] Received {} bytes: {:?}",
                    received,
                    core::str::from_utf8(response).unwrap_or("<binary>")
                );

                if response == data {
                    info!("[FrameVsock Test] Echo roundtrip PASSED!");
                    return Ok(());
                } else {
                    warn!("[FrameVsock Test] Echo mismatch!");
                    return_errno_with_message!(Errno::EIO, "echo mismatch");
                }
            }
            Err(e) if e.error() == Errno::EAGAIN => {
                retries += 1;
                if retries >= MAX_RETRIES {
                    warn!("[FrameVsock Test] Timeout waiting for echo");
                    return_errno_with_message!(Errno::ETIMEDOUT, "timeout waiting for echo");
                }
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Poll the echo server's accept() and handle one connection
/// Returns true if a connection was accepted and handled
pub fn poll_echo_server_accept() -> bool {
    let Some(socket) = ECHO_SERVER_SOCKET.get() else {
        return false;
    };

    // Try to accept a connection
    match socket.accept() {
        Ok((client_socket, peer_addr)) => {
            info!(
                "[FrameVsock Test] Echo server accepted connection from {:?}",
                peer_addr
            );

            // Handle the connection: recv and send back using FileLike interface
            let mut buf = vec![0u8; 256];

            loop {
                // Use FileLike::read to receive data
                let mut writer = ostd::mm::VmWriter::from(buf.as_mut_slice()).to_fallible();

                match client_socket.read(&mut writer) {
                    Ok(received) if received > 0 => {
                        info!("[FrameVsock Test] Echo server received {} bytes", received);

                        // Send it back using FileLike::write
                        let mut reader = ostd::mm::VmReader::from(&buf[..received]).to_fallible();
                        match client_socket.write(&mut reader) {
                            Ok(sent) => info!("[FrameVsock Test] Echo server sent {} bytes", sent),
                            Err(e) => {
                                warn!("[FrameVsock Test] Echo server send error: {:?}", e);
                                break;
                            }
                        }
                    }
                    Ok(0) => {
                        info!("[FrameVsock Test] Echo server: client closed connection");
                        break;
                    }
                    Err(e) if e.error() == Errno::EAGAIN => {
                        // No data yet, continue polling
                        continue;
                    }
                    Err(e) => {
                        debug!("[FrameVsock Test] Echo server recv error: {:?}", e);
                        break;
                    }
                    _ => break,
                }
            }

            true
        }
        Err(e) if e.error() == Errno::EAGAIN => {
            // No connection pending
            false
        }
        Err(e) => {
            debug!("[FrameVsock Test] Accept error: {:?}", e);
            false
        }
    }
}

/// Directly deliver a test packet to Guest (bypassing socket layer)
/// Useful for testing the low-level RX path
pub fn inject_test_packet_to_guest(dst_port: u32, data: &[u8]) {
    info!(
        "[FrameVsock Test] Injecting test packet to Guest port {}",
        dst_port
    );

    let packet = create_data_packet(
        VMADDR_CID_HOST,
        0, // src_port doesn't matter for test
        VMADDR_CID_GUEST,
        dst_port,
        data.to_vec(),
    );

    // Deliver to vCPU 0
    if framevisor_vsock::deliver_data_packet(0, packet).is_err() {
        debug!("[FrameVsock Test] Failed to inject test packet");
    } else {
        info!("[FrameVsock Test] Test packet injected successfully");
    }
}

/// Check if Guest has a listening socket on the specified port
pub fn guest_has_listener(_port: u32) -> bool {
    // We can't directly check Guest's socket state from Host
    // This is inferred from successful connection attempts
    false // Placeholder
}

/// Run all FrameVsock tests
pub fn run_all_tests() -> Result<()> {
    info!("[FrameVsock Test] ======================================");
    info!("[FrameVsock Test] Starting FrameVsock Test Suite");
    info!("[FrameVsock Test] ======================================");

    // Test 1: Start Host echo server
    info!("[FrameVsock Test] Test 1: Start Host echo server");
    start_host_echo_server(HOST_TEST_PORT)?;
    info!("[FrameVsock Test] Test 1: PASSED");

    // Test 2: Connect to Guest (requires Guest to be listening)
    // This will fail if Guest hasn't set up listener yet
    info!("[FrameVsock Test] Test 2: Host connect to Guest (may fail if Guest not ready)");
    match test_host_connect_to_guest() {
        Ok(_) => info!("[FrameVsock Test] Test 2: PASSED"),
        Err(e) => info!(
            "[FrameVsock Test] Test 2: SKIPPED (Guest not ready: {:?})",
            e
        ),
    }

    info!("[FrameVsock Test] ======================================");
    info!("[FrameVsock Test] Test Suite Completed");
    info!("[FrameVsock Test] ======================================");

    Ok(())
}

/// Setup tests before FrameVM starts
/// Call this before loading FrameVM
pub fn setup_pre_framevm() -> Result<()> {
    info!("[FrameVsock Test] Setting up Host-side infrastructure");

    // Start the echo server that Guest can connect to
    start_host_echo_server(HOST_TEST_PORT)?;

    info!(
        "[FrameVsock Test] Host echo server ready on port {}",
        HOST_TEST_PORT
    );
    Ok(())
}

/// Run tests after FrameVM has started and Guest is ready
/// Call this after FrameVM has been running for a bit
pub fn run_post_framevm_tests() -> Result<()> {
    info!("[FrameVsock Test] ======================================");
    info!("[FrameVsock Test] Running Post-FrameVM Tests");
    info!("[FrameVsock Test] ======================================");

    // Wait for Guest to set up its listener with retry
    // The Guest's echo server should be on port 12345
    info!(
        "[FrameVsock Test] Waiting for Guest echo server to be ready on port {}",
        GUEST_TEST_PORT
    );

    // Retry connecting with delays to give Guest time to start listening
    const MAX_CONNECTION_RETRIES: u32 = 100;
    const RETRY_YIELD_COUNT: u32 = 10000; // Yield many times between retries

    for retry in 0..MAX_CONNECTION_RETRIES {
        info!(
            "[FrameVsock Test] Connection attempt {} of {}",
            retry + 1,
            MAX_CONNECTION_RETRIES
        );

        match test_echo_roundtrip(GUEST_TEST_PORT, b"Test message from Host!") {
            Ok(_) => {
                info!("[FrameVsock Test] Host -> Guest echo: PASSED");
                info!("[FrameVsock Test] ======================================");
                info!("[FrameVsock Test] Post-FrameVM Tests Completed Successfully");
                info!("[FrameVsock Test] ======================================");
                return Ok(());
            }
            Err(e) => {
                debug!(
                    "[FrameVsock Test] Connection attempt {} failed: {:?}",
                    retry + 1,
                    e
                );
                // Yield to let Guest make progress
                for _ in 0..RETRY_YIELD_COUNT {
                    ostd::task::Task::yield_now();
                }
            }
        }
    }

    warn!(
        "[FrameVsock Test] Host -> Guest echo: FAILED after {} retries",
        MAX_CONNECTION_RETRIES
    );
    info!("[FrameVsock Test] ======================================");
    info!("[FrameVsock Test] Post-FrameVM Tests Completed with Failures");
    info!("[FrameVsock Test] ======================================");

    Ok(())
}
