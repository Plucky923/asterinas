// SPDX-License-Identifier: MPL-2.0

//! Procfs control file for starting and stopping FrameVM instances.

use crate::{
    fs::{
        procfs::template::{FileOps, ProcFileBuilder},
        utils::{Inode, mkmod},
    },
    prelude::*,
    vmm,
};

/// Represents the inode at `/proc/framevm`.
pub struct FrameVmFileOps;

const PROC_FRAMEVM_CONTROL_BYTES: usize = 16;

impl FrameVmFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFileBuilder::new(Self, mkmod!(a+rw))
            .parent(parent)
            .build()
            .unwrap()
    }
}

impl FileOps for FrameVmFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let status = vmm::framevm_load_status();
        let mut reader = VmReader::from(&status.as_bytes()[offset.min(status.len())..]);
        Ok(writer.write_fallible(&mut reader)?)
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let write_len = reader.remain();
        let Some(requested_vcpu_count) = read_requested_vcpu_count(reader)? else {
            return Ok(write_len);
        };

        if requested_vcpu_count == 0 {
            vmm::stop_framevm_instances();
            return Ok(write_len);
        }

        if requested_vcpu_count > 4 {
            return Err(Error::with_message(
                Errno::EINVAL,
                "vcpu count must be between 0 and 4",
            ));
        }

        vmm::load_framevm_background(requested_vcpu_count)?;

        Ok(write_len)
    }
}

fn read_requested_vcpu_count(reader: &mut VmReader) -> Result<Option<usize>> {
    let write_len = reader.remain();
    if write_len == 0 {
        return Ok(None);
    }

    let mut control_bytes = [0u8; PROC_FRAMEVM_CONTROL_BYTES];
    let copied_len = write_len.min(control_bytes.len());
    for byte in &mut control_bytes[..copied_len] {
        *byte = reader.read_val::<u8>()?;
    }

    if write_len > copied_len {
        reader.skip(write_len - copied_len);
    }

    let control = core::str::from_utf8(&control_bytes[..copied_len])
        .map_err(|_| Error::new(Errno::EINVAL))?
        .trim();
    if control.is_empty() {
        return Ok(None);
    }

    let requested_vcpu_count = control.parse().map_err(|_| Error::new(Errno::EINVAL))?;
    Ok(Some(requested_vcpu_count))
}
