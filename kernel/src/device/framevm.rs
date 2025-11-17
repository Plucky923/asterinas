// SPDX-License-Identifier: MPL-2.0

use device_id::DeviceId;

use crate::{
    events::IoEvents,
    fs::{
        device::{Device, DeviceType},
        inode_handle::FileIo,
        utils::StatusFlags,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::MultiRead,
    vmm,
};

pub struct FrameVMDevice;

impl Device for FrameVMDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        // The same value as Linux
        DeviceId::new(99, 99)
    }

    fn open(&self) -> Option<Result<Arc<dyn FileIo>>> {
        Some(Ok(Arc::new(FrameVMDevice)))
    }
}

impl Pollable for FrameVMDevice {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        let events = IoEvents::IN | IoEvents::OUT;
        events & mask
    }
}

impl FileIo for FrameVMDevice {
    fn read(&self, writer: &mut VmWriter, status_flags: StatusFlags) -> Result<usize> {
        let len = writer.avail();
        writer.fill_zeros(len)?;
        Ok(len)
    }

    fn write(&self, reader: &mut VmReader, status_flags: StatusFlags) -> Result<usize> {
        let len = reader.remain();
        if len == 0 {
            return Ok(0);
        }

        // 读取第一个字节来判断是否为'1'
        let first_byte = reader.read_val::<u8>()?;

        // 如果写入的是'1'，就使用vmm中的load_framevm逻辑启动framevm
        if first_byte == b'1' {
            vmm::load_framevm()?;
        }

        // 读取并丢弃剩余的字节
        if len > 1 {
            reader.skip(len - 1);
        }

        Ok(len)
    }
}
