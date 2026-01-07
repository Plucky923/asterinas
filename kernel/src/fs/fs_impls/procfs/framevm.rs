// SPDX-License-Identifier: MPL-2.0

//! `/proc/framevm` 节点，用于触发 FrameVM 加载。

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

impl FrameVmFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFileBuilder::new(Self, mkmod!(a+rw))
            .parent(parent)
            .build()
            .unwrap()
    }
}

impl FileOps for FrameVmFileOps {
    fn read_at(&self, _offset: usize, _writer: &mut VmWriter) -> Result<usize> {
        Ok(0)
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let len = reader.remain();
        if len == 0 {
            return Ok(0);
        }

        let first_byte = reader.read_val::<u8>()?;

        match first_byte {
            b'1' => {
                // Load FrameVM in background (non-blocking): return from write_at immediately.
                vmm::load_framevm_background()?;
            }
            _ => {
                // Default: load synchronously
                vmm::load_framevm()?;
            }
        }

        if len > 1 {
            reader.skip(len - 1);
        }

        Ok(len)
    }
}
