#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Check real vOSTD buffer permissions and borrows with compile-fail consumers.

Run inside the development container with the pinned nightly. No model API or
test double replaces the dependency under test.
"""

from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "device_read_requires_write_grant": ("E0308", "fn check(d: ZeroCopyBlock, b: ReadBuffer) { let _ = d.read(b, 0, 512); }"),
    "read_only_writer": ("E0599", "fn check(mut b: ReadBuffer) { b.writer(); }"),
    "live_reader_handoff": ("E0505", "fn check(b: ReadWriteBuffer) { let r = b.reader(); let _ = b.handoff(1, GrantAccess::ReadOnly, 1); let _ = r.cursor(); }"),
    "reader_and_writer": ("E0502", "fn check(mut b: ReadWriteBuffer) { let r = b.reader(); let _w = b.writer(); let _ = r.cursor(); }"),
    "duplicate_owner": ("E0599", "fn check(b: ReadWriteBuffer) { let _ = b.clone(); }"),
    "datagram_live_reader_forward": ("E0505", "fn check(s: ZeroCopyDatagramSocket, p: ZeroCopyDatagram) { let r = p.reader(); let _ = s.try_send_datagram(p); let _ = r.cursor(); }"),
    "datagram_live_reader_extract": ("E0505", "fn check(p: ZeroCopyDatagram) { let r = p.reader(); let _ = p.into_buffer(); let _ = r.cursor(); }"),
    "datagram_has_no_writer": ("E0599", "fn check(mut p: ZeroCopyDatagram) { let _ = p.writer(); }"),
    "datagram_duplicate_owner": ("E0599", "fn check(p: ZeroCopyDatagram) { let _ = p.clone(); }"),
    "datagram_has_no_token_constructor": ("E0599", "fn check() { let _ = ZeroCopyDatagram::from_token(1); }"),
    "packet_live_reader_extract": ("E0505", "fn check(p: TxPacket<LinkLayer>) { let r = p.reader(); let _ = p.into_shared_frame(|_| Err(ostd::Error::NoMemory)); let _ = r.cursor(); }"),
    "packet_reader_and_writer": ("E0502", "fn check(mut p: TxPacket<LinkLayer>) { let r = p.reader(); let _ = p.prepend_writer(0); let _ = r.cursor(); }"),
    "packet_builder_live_writer": ("E0505", "fn check(mut p: TxPacketBuilder<LinkLayer>) { let w = p.append_writer(); let _ = p.build(); let _ = w.avail(); }"),
    "rx_packet_has_no_writer": ("E0599", "fn check(mut p: RxPacket<LinkLayer>) { let _ = p.writer(); }"),
}


def main():
    cache = ROOT / "target/shared-buffer-api"
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="consumer-", dir=cache) as directory:
        project = Path(directory)
        (project / "src").mkdir()
        # Reuse the repository's pinned git revisions in offline consumers.
        (project / "Cargo.lock").write_text((ROOT / "Cargo.lock").read_text())
        (project / "Cargo.toml").write_text(f'''[package]
name = "shared-buffer-api-check"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
ostd = {{ path = "{ROOT / 'ostd'}", default-features = false, features = ["kernelet"] }}
aster-bigtcp = {{ path = "{ROOT / 'kernel/libs/aster-bigtcp'}", features = ["kernelet"] }}
''')
        prefix = "#![no_std]\nuse ostd::kernelet::shared_buffer::{Buffer, GrantAccess, ReadBuffer, ReadWriteBuffer, ZeroCopyBlock, ZeroCopyDatagram, ZeroCopyDatagramSocket, ZeroCopyNet};\nuse aster_bigtcp::packet::{FreshTxPacket, LinkLayer, RxPacket, TxPacket, TxPacketBuilder};\n"
        command = ["cargo", "check", "--offline", "--manifest-path", str(project / "Cargo.toml"),
                   "--target", "x86_64-unknown-none", "--target-dir", str(cache / "build"),
                   "-Zbuild-std=core,alloc,compiler_builtins",
                   "-Zbuild-std-features=compiler-builtins-mem"]
        # Establish that dependency/toolchain errors cannot masquerade as an
        # expected compile failure.
        valid = "fn check(mut b: ReadWriteBuffer) { let _ = b.reader(); let _ = b.writer(); let _ = b.handoff(1, GrantAccess::ReadOnly, 1); } fn device(d: ZeroCopyBlock, b: ReadBuffer) { let _ = d.write_read_only(b, 0, 512); } fn network(d: ZeroCopyNet, b: Buffer) { let socket = d.socket(); let _ = socket.info(); let _ = socket.allocate(128); let _ = socket.try_recv(); if let Ok(packet) = ZeroCopyDatagram::import(b) { let _ = packet.reader(); let _ = socket.try_send_datagram(packet); } }"
        valid += " fn packet(b: ReadWriteBuffer) -> ostd::Result<()> { let fresh = FreshTxPacket::<LinkLayer>::from_shared(b, 128, None)?; let mut builder = fresh.to_builder(); builder.append_writer().fill_zeros(128); builder.commit(128); let tx = builder.build(); let _ = tx.reader(); let shared = tx.into_shared_frame(|_| Err(ostd::Error::NoMemory))?; let (buffer, range, _) = shared.into_parts(); let rx = RxPacket::<LinkLayer>::from_shared(Buffer::ReadWrite(buffer), range, None)?; let _ = rx.reader(); Ok(()) }"
        (project / "src/lib.rs").write_text(prefix + valid)
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        for name, (code, source) in CASES.items():
            (project / "src/lib.rs").write_text(prefix + source)
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (cache / f"{name}.log").write_text(result.stdout)
            if result.returncode == 0 or f"error[{code}]" not in result.stdout:
                raise RuntimeError(f"{name}: expected {code}, got exit {result.returncode}; see {cache}")
            print(f"{name}: rejected with {code}", flush=True)


if __name__ == "__main__":
    main()
