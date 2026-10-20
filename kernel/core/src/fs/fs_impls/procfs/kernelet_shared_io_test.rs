// SPDX-License-Identifier: MPL-2.0

//! Opt-in functional checks using real image APIs and configured backends.
//! This entry is absent unless KERNELET_SHARED_IO_TEST=1 at build time.

use alloc::format;

use aster_util::printer::VmPrinter;
use ostd::{
    kernelet::shared_buffer::{Buffer, PendingIo, ReadWriteBuffer, Received, ZeroCopyBlock},
    mm::Infallible,
    task::Task,
};

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    net::socket::zero_copy::DatagramSocket,
    prelude::*,
};

const FIXTURE_MAGIC: &[u8] = b"KerneletSharedIOv1";
const TIMEOUT: core::time::Duration = core::time::Duration::from_secs(30);
static RESULT: Mutex<String> = Mutex::new(String::new());

pub(super) struct SharedIoTestFileOps;

impl SharedIoTestFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u+rw))
    }
}

impl ProcFileOps for SharedIoTestFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        if offset != 0 {
            return Ok(0);
        }
        let result = RESULT.lock();
        let mut printer = VmPrinter::from(writer);
        writeln!(printer, "{}", *result)?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _: usize, reader: &mut VmReader) -> Result<usize> {
        let len = reader.remain();
        if len == 0 || len > 16 {
            return_errno_with_message!(Errno::EINVAL, "invalid shared I/O test command");
        }
        let mut command = [0; 16];
        reader.read_fallible(&mut VmWriter::from(&mut command[..len]))?;
        let result = match &command[..len] {
            b"block" => block_check(),
            b"send" => network_check(NetworkRole::Sender),
            b"receive" => network_check(NetworkRole::Receiver),
            b"paths" => image_path_check(),
            _ => return_errno_with_message!(Errno::EINVAL, "unknown shared I/O test command"),
        };
        *RESULT.lock() = match result {
            Ok(result) => result,
            Err(error) => {
                return Err(error);
            }
        };
        Ok(len)
    }
}

fn image_path_check() -> Result<String> {
    let packets = aster_bigtcp::packet::shared_packet_statistics();
    let net = crate::net::device::shared::statistics();
    if packets.native_to_shared_packets != 0 || packets.shared_to_native_packets != 0 {
        return_errno_with_message!(Errno::EIO, "ordinary socket traffic copied packet storage");
    }
    if net.tx_packets != 0
        && (net.exchanges == 0
            || net.exchange_received == 0
            || net.exchange_returned == 0
            || net.rejected_packets != 0)
    {
        return_errno_with_message!(
            Errno::EIO,
            "shared Ethernet exchange was not exercised cleanly"
        );
    }
    Ok(format!(
        "packet paths shared_tx={} native_to_shared_bytes={} shared_to_native_bytes={} tx={} rx={} rejected={} exchanges={} received={} returned={} max_batch={}",
        packets.shared_tx_packets,
        packets.native_to_shared_bytes,
        packets.shared_to_native_bytes,
        net.tx_packets,
        net.rx_packets,
        net.rejected_packets,
        net.exchanges,
        net.exchange_received,
        net.exchange_returned,
        net.exchange_max_received,
    ))
}

fn abi_error(status: i64) -> Error {
    ostd::error!("shared I/O test service returned {}", status);
    Error::with_message(Errno::EIO, "shared I/O test service failed")
}

fn wait_io(mut request: PendingIo) -> Result<ReadWriteBuffer> {
    let start = crate::time::read_monotonic_time();
    loop {
        if let Some(Received { status, buffer }) = request.poll().map_err(abi_error)? {
            if status != 0 {
                return Err(abi_error(status));
            }
            return match buffer {
                Buffer::ReadWrite(buffer) => Ok(buffer),
                Buffer::ReadOnly(_) => Err(abi_error(-1)),
            };
        }
        if crate::time::read_monotonic_time().saturating_sub(start) > TIMEOUT {
            return_errno_with_message!(Errno::ETIME, "shared block completion timed out");
        }
        Task::yield_now();
    }
}

fn block_check() -> Result<String> {
    let disk = ZeroCopyBlock::open(0)
        .map_err(abi_error)?
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "shared block device missing"))?;
    let buffer = ReadWriteBuffer::allocate(4096).map_err(abi_error)?;
    let original = buffer.reader().cursor().addr();
    let mut buffer = wait_io(
        disk.read(buffer, 0, 512)
            .map_err(|(_, status)| abi_error(status))?,
    )?;
    let mut header = [0; 512];
    buffer.reader().read(&mut VmWriter::from(&mut header[..]));
    if &header[..FIXTURE_MAGIC.len()] != FIXTURE_MAGIC
        || buffer.reader().cursor().addr() != original
    {
        return_errno_with_message!(
            Errno::EIO,
            "shared block fixture or storage identity differs"
        );
    }
    let pattern = [0xa5; 512];
    buffer.writer().write(&mut VmReader::from(&pattern[..]));
    buffer.set_payload_len(512).map_err(abi_error)?;
    let mut buffer = wait_io(
        disk.write(buffer, 4096, 512)
            .map_err(|(_, status)| abi_error(status))?,
    )?;
    // The read must replace different bytes; a no-op completion cannot pass.
    buffer.writer().write(&mut VmReader::from(&[0x3c; 512][..]));
    let buffer = wait_io(
        disk.read(buffer, 4096, 512)
            .map_err(|(_, status)| abi_error(status))?,
    )?;
    let mut actual = [0; 512];
    buffer.reader().read(&mut VmWriter::from(&mut actual[..]));
    if actual != pattern || buffer.reader().cursor().addr() != original {
        return_errno_with_message!(
            Errno::EIO,
            "shared block readback or storage identity differs"
        );
    }
    Ok(format!(
        "block ok original={original:#x} returned={:#x} bytes=512",
        buffer.reader().cursor().addr()
    ))
}

fn check_payload(mut reader: VmReader<'_, Infallible>, len: usize) -> Result<()> {
    if reader.remain() != len {
        return_errno_with_message!(Errno::EIO, "shared packet length differs");
    }
    let mut bytes = [0; 256];
    while reader.remain() != 0 {
        let count = reader.remain().min(bytes.len());
        reader.read(&mut VmWriter::from(&mut bytes[..count]));
        if bytes[..count].iter().any(|&byte| byte != 0x5a) {
            return_errno_with_message!(Errno::EIO, "shared packet contents differ");
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum NetworkRole {
    Sender,
    Receiver,
}

fn network_check(role: NetworkRole) -> Result<String> {
    let start = crate::time::read_monotonic_time();
    let socket = loop {
        match DatagramSocket::open(0) {
            Ok(socket) => break socket,
            Err(error) if error.error() == Errno::ENODEV => {}
            Err(error) => return Err(error),
        }
        if crate::time::read_monotonic_time().saturating_sub(start) > TIMEOUT {
            return_errno_with_message!(Errno::ETIME, "shared network connection timed out");
        }
        Task::yield_now();
    };
    let mut last_address = 0;
    for len in [0usize, 1, 512, 65535] {
        let mut original = None;
        if role == NetworkRole::Sender {
            let mut buffer = socket.allocate(len)?;
            original = Some(buffer.reader().cursor().addr());
            let mut writer = buffer.writer();
            let bytes = [0x5a; 256];
            let mut remaining = len;
            while remaining != 0 {
                let count = remaining.min(bytes.len());
                writer.write(&mut VmReader::from(&bytes[..count]));
                remaining -= count;
            }
            drop(writer);
            socket.send_buffer(buffer).map_err(|(_, error)| error)?;
        }
        let packet = loop {
            match socket.recv() {
                Ok(packet) => break packet,
                Err(error) if error.error() == Errno::EAGAIN => {}
                Err(error) => return Err(error),
            }
            if crate::time::read_monotonic_time().saturating_sub(start) > TIMEOUT {
                return_errno_with_message!(Errno::ETIME, "shared network receive timed out");
            }
            Task::yield_now();
        };
        check_payload(packet.reader(), len)?;
        last_address = packet.reader().cursor().addr();
        if original.is_some_and(|address| address != last_address) {
            return_errno_with_message!(Errno::EIO, "shared round trip changed the allocation");
        }
        if role == NetworkRole::Receiver {
            let packet =
                DatagramSocket::import(packet.into_buffer()).map_err(|(_, error)| error)?;
            socket.send(packet).map_err(|(_, error)| error)?;
        }
    }
    Ok(format!(
        "network ok role={} connection={} rounds=4 last_address={last_address:#x}",
        match role {
            NetworkRole::Sender => "send",
            NetworkRole::Receiver => "receive",
        },
        socket.info().connection
    ))
}
