// SPDX-License-Identifier: MPL-2.0

use aster_block::{BLOCK_SIZE, BlockDevice, SECTOR_SIZE};
use aster_nvme::NvmeBlockDevice;
use device_id::DeviceId;
use ostd::mm::VmIo;

use crate::{
    context::current_userspace,
    device::{Device, DeviceType, DevtmpfsInodeMeta, add_node},
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, StatusFlags},
        vfs::{inode::FileOps, path::PathResolver},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    thread::kernel_thread::ThreadOptions,
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

pub(super) fn init_in_first_kthread() {
    for device in aster_block::collect_all() {
        if device.is_partition() || device.downcast_ref::<NvmeBlockDevice>().is_none() {
            continue;
        }
        let Some(worker) = aster_nvme::register_worker() else {
            continue;
        };
        let device_clone = device.clone();
        let task_fn = move || {
            let Some(nvme_device) = device_clone.downcast_ref::<NvmeBlockDevice>() else {
                error!("FrameVM NVMe worker received a device with the wrong type");
                return;
            };
            worker.run(nvme_device);
        };
        ThreadOptions::new(task_fn).spawn();
    }
}

pub(super) fn init_in_first_process(path_resolver: &PathResolver) -> Result<()> {
    for device in aster_block::collect_all() {
        let device = Arc::new(BlockFile::new(device));
        if let Some(devtmpfs_meta) = device.devtmpfs_meta() {
            let dev_id = device.id().as_encoded_u64();
            add_node(DeviceType::Block, dev_id, &devtmpfs_meta, path_resolver)?;
        }
    }

    Ok(())
}

mod ioctl_defs {
    use crate::util::ioctl::{NoData, OutData, ioc};

    pub(super) type BlkGetSize64 = ioc!(BLKGETSIZE64, 0x12, 114, OutData<u64>);
    pub(super) type BlkGetSectorSize = ioc!(BLKSSZGET, 0x12, 104, NoData);
}

#[derive(Debug)]
struct BlockFile(Arc<dyn BlockDevice>);

impl BlockFile {
    fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self(device)
    }
}

impl Device for BlockFile {
    fn type_(&self) -> DeviceType {
        DeviceType::Block
    }

    fn id(&self) -> DeviceId {
        self.0.id()
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new(self.0.name()))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(OpenBlockFile(self.0.clone())))
    }
}

struct OpenBlockFile(Arc<dyn BlockDevice>);

impl FileOps for OpenBlockFile {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let total = writer.avail();
        if total == 0 {
            return Ok(0);
        }

        let device_size = self.0.metadata().nr_sectors * SECTOR_SIZE;
        if offset >= device_size {
            return Ok(0);
        }

        let read_len = total.min(device_size - offset);
        {
            let mut limited_writer = writer.clone_exclusive();
            limited_writer.limit(read_len);
            self.0.read(offset, &mut limited_writer)?;
        }
        writer.skip(read_len);
        Ok(read_len)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let total = reader.remain();
        if total == 0 {
            return Ok(0);
        }

        let device_size = self.0.metadata().nr_sectors * SECTOR_SIZE;
        if offset >= device_size {
            return_errno_with_message!(
                Errno::ENOSPC,
                "the write offset is beyond the block device"
            );
        }

        let write_len = total.min(device_size - offset);
        {
            let mut limited_reader = reader.clone();
            limited_reader.limit(write_len);
            self.0.write(offset, &mut limited_reader)?;
        }
        reader.skip(write_len);
        Ok(write_len)
    }
}

impl Pollable for OpenBlockFile {
    fn poll(&self, mask: IoEvents, _: Option<&mut PollHandle>) -> IoEvents {
        (IoEvents::IN | IoEvents::OUT) & mask
    }
}

impl PerOpenFileOps for OpenBlockFile {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        true
    }

    fn seek_end(&self) -> Result<Option<usize>> {
        Ok(Some(self.0.metadata().nr_sectors * SECTOR_SIZE))
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            _cmd @ BlkGetSectorSize => {
                let sector_size = SECTOR_SIZE.max(BLOCK_SIZE) as i32;
                current_userspace!().write_val(raw_ioctl.arg(), &sector_size)?;
                Ok(0)
            }
            cmd @ BlkGetSize64 => {
                let size = (self.0.metadata().nr_sectors * SECTOR_SIZE) as u64;
                cmd.write(&size)?;
                Ok(0)
            }
            _ => return_errno_with_message!(
                Errno::ENOTTY,
                "the ioctl command is not supported by block devices"
            ),
        })
    }
}

pub(super) fn lookup(id: DeviceId) -> Option<Arc<dyn Device>> {
    let block_device = aster_block::lookup(id)?;
    let mut registry = DEVICE_REGISTRY.lock();
    Some(
        registry
            .entry(id.to_raw())
            .or_insert_with(move || Arc::new(BlockFile::new(block_device)))
            .clone(),
    )
}

static DEVICE_REGISTRY: Mutex<BTreeMap<u32, Arc<dyn Device>>> = Mutex::new(BTreeMap::new());
