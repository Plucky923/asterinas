// SPDX-License-Identifier: MPL-2.0

//! Explicit buffer connections authorized through both private holder sockets.

use std::{
    fs::File,
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{CONTROL_TIMEOUT, Control, Reply};
use crate::{fd, protocol, uapi::Sandbox};

#[derive(Debug, Serialize)]
pub(super) struct Pair {
    id: String,
    peer_id: String,
    connection: u64,
    peer_connection: u64,
}

pub(super) fn connect(root: &Path, id: &str, peer_id: &str) -> Result<Pair> {
    super::validate_id(id)?;
    super::validate_id(peer_id)?;
    ensure!(id != peer_id, "a sandbox cannot connect to itself");
    let local = Sandbox::from_file(capability(&root.join(id), id)?);
    let peer = Sandbox::from_file(capability(&root.join(peer_id), peer_id)?);
    let (connection, peer_connection) = local.connect_shared_buffers(&peer)?;
    Ok(Pair {
        id: id.into(),
        peer_id: peer_id.into(),
        connection,
        peer_connection,
    })
}

fn capability(directory: &Path, expected_id: &str) -> Result<File> {
    let mut stream = super::vsock::connect_control(directory)?;
    stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::send_value(&mut stream, &Control::SharedBufferCapability)?;
    let reply = super::receive_reply(&mut stream)?;
    ensure!(
        matches!(reply, Reply::SharedBufferIdentity { id } if id == expected_id),
        "holder shared-buffer identity differs"
    );
    // Acknowledge identity before any ancillary rights are queued. Ordinary
    // Asterinas reads may otherwise consume adjacent ancillary data.
    protocol::send_value(&mut stream, &())?;
    let mut descriptors = fd::receive(&stream)?;
    ensure!(descriptors.len() == 1, "expected one sandbox descriptor");
    Ok(File::from(
        descriptors.pop().context("missing sandbox descriptor")?,
    ))
}

pub(super) fn send_capability(stream: &mut UnixStream, id: String, sandbox: &File) -> Result<()> {
    stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::send_value(stream, &Reply::SharedBufferIdentity { id })?;
    stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    protocol::receive_value::<()>(stream)?;
    fd::send(stream, &[sandbox.as_raw_fd()])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Read,
        os::unix::net::UnixListener,
        path::PathBuf,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use clap::Parser;

    use super::*;
    use crate::runtime::{Cli, Operation};

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "kernelet-shared-buffer-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn serve(
            &self,
            id: &str,
            handler: impl FnOnce(UnixStream) + Send + 'static,
        ) -> thread::JoinHandle<()> {
            let directory = self.0.join(id);
            fs::create_dir(&directory).unwrap();
            let listener = UnixListener::bind(directory.join("control.sock")).unwrap();
            thread::spawn(move || handler(listener.accept().unwrap().0))
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cli_requires_both_instance_identities() {
        let cli = Cli::try_parse_from([
            "kernelet-runtime",
            "shared-buffer-connect",
            "producer",
            "consumer",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Operation::SharedBufferConnect { id, peer_id }
            if id == "producer" && peer_id == "consumer")
        );
        assert!(
            Cli::try_parse_from(["kernelet-runtime", "shared-buffer-connect", "producer",])
                .is_err()
        );
        assert!(connect(Path::new("/nonexistent"), "same", "same").is_err());
        assert!(connect(Path::new("/nonexistent"), "../outside", "peer").is_err());
    }

    #[test]
    fn capability_transfer_preserves_bytes_and_close_on_exec() {
        let directory = Directory::new();
        let path = directory.0.join("capability");
        fs::write(&path, b"sandbox capability").unwrap();
        let server = directory.serve("local", move |mut stream| {
            assert!(matches!(
                protocol::receive_value(&mut stream).unwrap(),
                Control::SharedBufferCapability
            ));
            send_capability(&mut stream, "local".into(), &File::open(path).unwrap()).unwrap();
        });
        let mut file = capability(&directory.0.join("local"), "local").unwrap();
        server.join().unwrap();
        let flags = nix::fcntl::fcntl(file.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"sandbox capability");
    }

    #[test]
    fn capability_rejects_a_replaced_holder_before_accepting_rights() {
        let directory = Directory::new();
        let server = directory.serve("local", |mut stream| {
            let _: Control = protocol::receive_value(&mut stream).unwrap();
            protocol::send_value(
                &mut stream,
                &Reply::SharedBufferIdentity {
                    id: "replacement".into(),
                },
            )
            .unwrap();
            assert!(protocol::receive_value::<()>(&mut stream).is_err());
        });
        assert!(capability(&directory.0.join("local"), "local").is_err());
        server.join().unwrap();
    }

    #[test]
    fn connection_failure_preserves_real_ioctl_errno_and_closes_capabilities() {
        let directory = Directory::new();
        let mut servers = Vec::new();
        let mut paths = Vec::new();
        for id in ["local", "peer"] {
            let path = directory.0.join(format!("{id}-file"));
            fs::write(&path, b"ordinary file").unwrap();
            paths.push(path.clone());
            servers.push(directory.serve(id, move |mut stream| {
                assert!(matches!(
                    protocol::receive_value(&mut stream).unwrap(),
                    Control::SharedBufferCapability
                ));
                send_capability(&mut stream, id.into(), &File::open(path).unwrap()).unwrap();
            }));
        }
        let error = connect(&directory.0, "local", "peer").unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOTTY)
        );
        for server in servers {
            server.join().unwrap();
        }
        for entry in fs::read_dir("/proc/self/fd").unwrap() {
            assert!(!fs::read_link(entry.unwrap().path()).is_ok_and(|path| paths.contains(&path)));
        }
    }

    #[test]
    fn extra_capabilities_are_rejected_and_closed() {
        let directory = Directory::new();
        let server = directory.serve("local", |mut stream| {
            let _: Control = protocol::receive_value(&mut stream).unwrap();
            protocol::send_value(
                &mut stream,
                &Reply::SharedBufferIdentity { id: "local".into() },
            )
            .unwrap();
            protocol::receive_value::<()>(&mut stream).unwrap();
            let file = File::open("/dev/null").unwrap();
            fd::send(&stream, &[file.as_raw_fd(), file.as_raw_fd()]).unwrap();
        });
        assert!(capability(&directory.0.join("local"), "local").is_err());
        server.join().unwrap();
    }
}
