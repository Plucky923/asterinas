// SPDX-License-Identifier: MPL-2.0

//! Procfs control file for starting and stopping FrameVM instances.
//!
//! Writing a positive number starts FrameVM in the foreground and blocks until it exits.
//! Writing `background N` keeps the old non-blocking control path for scripted checks.

use alloc::vec::Vec;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    vmm,
};

/// Represents the inode at `/proc/framevm`.
pub struct FrameVmFileOps;

const PROC_FRAMEVM_CONTROL_BYTES: usize = 4096;

impl FrameVmFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+rw))
    }
}

impl ProcFileOps for FrameVmFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let status = vmm::framevm_load_status();
        let mut reader = VmReader::from(&status.as_bytes()[offset.min(status.len())..]);
        Ok(writer.write_fallible(&mut reader)?)
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let write_len = reader.remain();
        match read_control_request(reader)? {
            FrameVmControlRequest::None => {}
            FrameVmControlRequest::Stop => vmm::stop_framevm_instances(),
            FrameVmControlRequest::Start { vcpu_count } => {
                validate_start_vcpu_count(vcpu_count)?;
                vmm::load_framevm(vcpu_count)?;
            }
            FrameVmControlRequest::StartBackground { vcpu_count } => {
                validate_start_vcpu_count(vcpu_count)?;
                vmm::load_framevm_background(vcpu_count)?;
            }
            FrameVmControlRequest::SetShare { share } => {
                vmm::set_framevm_task_group_share(share)?;
            }
            FrameVmControlRequest::ConsoleInput { input } => {
                vmm::inject_framevm_console_input(&input)?;
            }
            FrameVmControlRequest::BusyBoxSmoke => {
                vmm::run_framevm_busybox_smoke()?;
            }
            FrameVmControlRequest::ShareTest {
                group0_share,
                group1_share,
                duration_ms,
            } => {
                vmm::run_framevm_share_test(group0_share, group1_share, duration_ms)?;
            }
        }

        Ok(write_len)
    }
}

enum FrameVmControlRequest {
    None,
    Stop,
    Start {
        vcpu_count: usize,
    },
    StartBackground {
        vcpu_count: usize,
    },
    SetShare {
        share: u32,
    },
    ConsoleInput {
        input: String,
    },
    BusyBoxSmoke,
    ShareTest {
        group0_share: u32,
        group1_share: u32,
        duration_ms: u64,
    },
}

fn read_control_request(reader: &mut VmReader) -> Result<FrameVmControlRequest> {
    let write_len = reader.remain();
    if write_len == 0 {
        return Ok(FrameVmControlRequest::None);
    }

    let copied_len = write_len.min(PROC_FRAMEVM_CONTROL_BYTES);
    let mut control_bytes = Vec::with_capacity(copied_len);
    for _ in 0..copied_len {
        control_bytes.push(reader.read_val::<u8>()?);
    }

    if write_len > copied_len {
        reader.skip(write_len - copied_len);
    }

    let control_raw = core::str::from_utf8(&control_bytes)
        .map_err(|_| Error::new(Errno::EINVAL))?
        .trim_start();
    if let Some(input) = parse_console_input_request(control_raw) {
        return Ok(FrameVmControlRequest::ConsoleInput {
            input: String::from(input),
        });
    }

    let control = control_raw.trim();
    if control.is_empty() {
        return Ok(FrameVmControlRequest::None);
    }

    if let Some(share) = parse_share_request(control)? {
        return Ok(FrameVmControlRequest::SetShare { share });
    }

    if let Some(vcpu_count) = parse_background_start_request(control)? {
        return Ok(FrameVmControlRequest::StartBackground { vcpu_count });
    }

    if parse_busybox_smoke_request(control) {
        return Ok(FrameVmControlRequest::BusyBoxSmoke);
    }

    if let Some((group0_share, group1_share, duration_ms)) = parse_share_test_request(control)? {
        return Ok(FrameVmControlRequest::ShareTest {
            group0_share,
            group1_share,
            duration_ms,
        });
    }

    let requested_vcpu_count = control.parse().map_err(|_| Error::new(Errno::EINVAL))?;
    if requested_vcpu_count == 0 {
        Ok(FrameVmControlRequest::Stop)
    } else {
        Ok(FrameVmControlRequest::Start {
            vcpu_count: requested_vcpu_count,
        })
    }
}

fn parse_share_request(control: &str) -> Result<Option<u32>> {
    let Some(share_value) = control
        .strip_prefix("share=")
        .or_else(|| control.strip_prefix("share "))
    else {
        return Ok(None);
    };

    let share = share_value
        .trim()
        .parse()
        .map_err(|_| Error::new(Errno::EINVAL))?;
    Ok(Some(share))
}

fn parse_busybox_smoke_request(control: &str) -> bool {
    matches!(control, "busybox_smoke" | "busybox-smoke" | "smoke")
}

fn parse_console_input_request(control: &str) -> Option<&str> {
    control
        .strip_prefix("input=")
        .or_else(|| control.strip_prefix("input "))
}

fn parse_share_test_request(control: &str) -> Result<Option<(u32, u32, u64)>> {
    let Some(args) = control
        .strip_prefix("share_test=")
        .or_else(|| control.strip_prefix("share_test "))
    else {
        return Ok(None);
    };

    let mut parts = args
        .split(|byte| byte == ',' || byte == ' ')
        .filter(|part| !part.is_empty());
    let group0_share = parts
        .next()
        .ok_or_else(|| Error::new(Errno::EINVAL))?
        .parse()
        .map_err(|_| Error::new(Errno::EINVAL))?;
    let group1_share = parts
        .next()
        .ok_or_else(|| Error::new(Errno::EINVAL))?
        .parse()
        .map_err(|_| Error::new(Errno::EINVAL))?;
    let duration_ms = parts
        .next()
        .ok_or_else(|| Error::new(Errno::EINVAL))?
        .parse()
        .map_err(|_| Error::new(Errno::EINVAL))?;

    if parts.next().is_some() {
        return Err(Error::new(Errno::EINVAL));
    }

    Ok(Some((group0_share, group1_share, duration_ms)))
}

fn parse_background_start_request(control: &str) -> Result<Option<usize>> {
    let Some(vcpu_count_value) = control
        .strip_prefix("background=")
        .or_else(|| control.strip_prefix("background "))
        .or_else(|| control.strip_prefix("bg="))
        .or_else(|| control.strip_prefix("bg "))
    else {
        return Ok(None);
    };

    let vcpu_count = vcpu_count_value
        .trim()
        .parse()
        .map_err(|_| Error::new(Errno::EINVAL))?;
    Ok(Some(vcpu_count))
}

fn validate_start_vcpu_count(vcpu_count: usize) -> Result<()> {
    if (1..=4).contains(&vcpu_count) {
        return Ok(());
    }

    Err(Error::with_message(
        Errno::EINVAL,
        "vcpu count must be between 1 and 4",
    ))
}
