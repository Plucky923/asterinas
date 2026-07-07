// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec, vec::Vec};

use framev_blk_common::{
    FRAMEV_BLK_SECTOR_SIZE, FrameVBlkCompletion, FrameVBlkConfig, FrameVBlkConfigFlags,
    FrameVBlkOp, FrameVBlkRequestError, FrameVBlkRequestHeader, FrameVBlkResourceShape,
    FrameVBlkStatus,
};
use framev_device::{
    CommonError, CompletionInfo, DeviceGeneration, DeviceStatus, FrameVDevice, FrameVDeviceInfo,
    OperationError, OperationResult, ReadOnly, ResourceResult, ReturnedResource, SubmittedResource,
    WriteOnly,
};

use super::state::CommonDevice;
use crate::{Error, Result};

/// Error returned by a raw block image backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockImageError {
    /// The backend returned fewer bytes than requested for a read.
    ShortRead {
        offset_bytes: u64,
        requested_bytes: usize,
        actual_bytes: usize,
    },
    /// The backend wrote fewer bytes than requested.
    ShortWrite {
        offset_bytes: u64,
        requested_bytes: usize,
        actual_bytes: usize,
    },
    /// The backend rejected a write because the image is readonly.
    Readonly,
    /// The backend reported an I/O failure while reading or writing.
    Io,
    /// The backend reported an I/O failure while flushing durable state.
    Flush,
}

/// Raw byte-addressed image used by the FrameV block backend.
///
/// FrameV-blk validates sector units before calling this trait. This boundary
/// receives byte offsets and byte lengths only, and deliberately does not name
/// kernel VFS, file, path, or descriptor types.
pub trait BlockImage: Send + Sync {
    /// Reads exactly `dst.len()` bytes at `offset_bytes`.
    fn read_exact_at(&self, offset_bytes: u64, dst: &mut [u8]) -> Result<(), BlockImageError>;

    /// Writes exactly `src.len()` bytes at `offset_bytes`.
    fn write_all_at(&self, offset_bytes: u64, src: &[u8]) -> Result<(), BlockImageError>;

    /// Flushes all previously completed writes to the backend durability boundary.
    fn flush(&self) -> Result<(), BlockImageError>;

    /// Returns the raw image capacity in bytes.
    fn capacity_bytes(&self) -> u64;

    /// Returns whether writes must be rejected before mutating the image.
    fn readonly(&self) -> bool;
}

/// Typed host handle for one VM's FrameV block backend.
pub struct Block {
    common: CommonDevice,
    image: Arc<dyn BlockImage>,
    config: FrameVBlkConfig,
}

impl Block {
    pub(super) fn new(info: FrameVDeviceInfo, image: Arc<dyn BlockImage>) -> Result<Self> {
        let capacity_bytes = image.capacity_bytes();
        if capacity_bytes == 0 || capacity_bytes % FRAMEV_BLK_SECTOR_SIZE != 0 {
            return Err(Error::InvalidArgs);
        }

        let capacity_sectors = capacity_bytes / FRAMEV_BLK_SECTOR_SIZE;
        let flags = FrameVBlkConfigFlags::FLUSH
            | if image.readonly() {
                FrameVBlkConfigFlags::READONLY
            } else {
                0
            };
        let config = FrameVBlkConfig::new(capacity_sectors, FRAMEV_BLK_SECTOR_SIZE as u32, flags)
            .map_err(|_| Error::InvalidArgs)?;

        Ok(Self {
            common: CommonDevice::new(info),
            image,
            config,
        })
    }

    /// Returns the backend-authoritative FrameV-blk configuration.
    pub fn config(&self) -> FrameVBlkConfig {
        self.config
    }

    /// Executes one submitted FrameV-blk request.
    ///
    /// This is service-runnable data-path work. IHT may notify that a request is
    /// deliverable, but normal protocol validation, raw image I/O, and
    /// completion construction must run outside IHT notification/control code.
    pub fn submit_request(
        &self,
        header: FrameVBlkRequestHeader,
        resource: BlockRequestResource,
    ) -> Result<BlockRequestCompletion> {
        self.ensure_ready().map_err(|_| Error::InvalidArgs)?;

        let mut request = BlockSubmittedRequest { header, resource };
        let status = self.execute_request(&mut request);
        Ok(request.complete(status))
    }

    fn execute_request(&self, request: &mut BlockSubmittedRequest) -> FrameVBlkStatus {
        let resource_shape = request.resource.shape();
        if let Err(error) = request.header.validate_with_mode(
            self.config.capacity_sectors(),
            self.config.flags().readonly(),
            resource_shape,
        ) {
            return validation_status(error);
        }

        let Ok(op) = request.header.op() else {
            return FrameVBlkStatus::Unsupported;
        };

        match op {
            FrameVBlkOp::Read => self.execute_read(request),
            FrameVBlkOp::Write => self.execute_write(request),
            FrameVBlkOp::Flush => self.execute_flush(),
        }
    }

    fn execute_read(&self, request: &mut BlockSubmittedRequest) -> FrameVBlkStatus {
        let Some(buffer) = request.resource.read_buffer_mut() else {
            return FrameVBlkStatus::IoErr;
        };
        if self
            .image
            .read_exact_at(request_offset(request.header), buffer.get_mut())
            .is_err()
        {
            return FrameVBlkStatus::IoErr;
        }
        FrameVBlkStatus::Ok
    }

    fn execute_write(&self, request: &BlockSubmittedRequest) -> FrameVBlkStatus {
        let Some(buffer) = request.resource.write_buffer() else {
            return FrameVBlkStatus::IoErr;
        };
        if self
            .image
            .write_all_at(request_offset(request.header), buffer.get())
            .is_err()
        {
            return FrameVBlkStatus::IoErr;
        }
        FrameVBlkStatus::Ok
    }

    fn execute_flush(&self) -> FrameVBlkStatus {
        if self.image.flush().is_err() {
            return FrameVBlkStatus::IoErr;
        }
        FrameVBlkStatus::Ok
    }

    pub(super) fn reset(&self) {
        self.common.reset();
    }
}

impl FrameVDevice for Block {
    fn info(&self) -> FrameVDeviceInfo {
        self.common.info()
    }

    fn status(&self) -> DeviceStatus {
        self.common.status()
    }

    fn generation(&self) -> DeviceGeneration {
        self.common.generation()
    }

    fn ensure_ready(&self) -> core::result::Result<DeviceGeneration, CommonError> {
        self.common.ensure_ready()
    }

    fn mark_ready(&self) -> framev_device::Result<()> {
        self.common.mark_ready()
    }

    fn stop(&self) {
        self.common.stop();
    }

    fn begin_reset(&self) -> framev_device::Result<DeviceGeneration> {
        self.common.begin_reset()
    }

    fn reset_backend(&self) {}

    fn finish_reset(&self, generation: DeviceGeneration) -> framev_device::Result<()> {
        self.common.finish_reset(generation)
    }
}

/// A submitted FrameV-blk request data resource.
pub enum BlockRequestResource {
    None,
    ReadBuffer(SubmittedResource<Vec<u8>, WriteOnly>),
    WriteBuffer(SubmittedResource<Vec<u8>, ReadOnly>),
}

impl BlockRequestResource {
    fn shape(&mut self) -> FrameVBlkResourceShape {
        match self {
            Self::None => FrameVBlkResourceShape::NoData,
            Self::ReadBuffer(buffer) => FrameVBlkResourceShape::ReadBuffer {
                len_bytes: buffer.get_mut().len() as u64,
            },
            Self::WriteBuffer(buffer) => FrameVBlkResourceShape::WriteBuffer {
                len_bytes: buffer.get().len() as u64,
            },
        }
    }

    fn read_buffer_mut(&mut self) -> Option<&mut SubmittedResource<Vec<u8>, WriteOnly>> {
        match self {
            Self::ReadBuffer(buffer) => Some(buffer),
            _ => None,
        }
    }

    fn write_buffer(&self) -> Option<&SubmittedResource<Vec<u8>, ReadOnly>> {
        match self {
            Self::WriteBuffer(buffer) => Some(buffer),
            _ => None,
        }
    }
}

/// A resource returned with a FrameV-blk completion.
#[derive(Debug, Eq, PartialEq)]
pub enum BlockReturnedResource {
    ReadBuffer(ReturnedResource<Vec<u8>>),
    WriteBuffer(ReturnedResource<Vec<u8>>),
}

/// Backend completion for one FrameV-blk request.
#[derive(Debug, Eq, PartialEq)]
pub struct BlockRequestCompletion {
    info: FrameVBlkCompletion,
    resource: Option<BlockReturnedResource>,
}

impl BlockRequestCompletion {
    /// Returns the common completion metadata.
    pub fn info(&self) -> &FrameVBlkCompletion {
        &self.info
    }

    /// Consumes the completion and returns its resource, if any.
    pub fn into_resource(self) -> Option<BlockReturnedResource> {
        self.resource
    }
}

struct BlockSubmittedRequest {
    header: FrameVBlkRequestHeader,
    resource: BlockRequestResource,
}

impl BlockSubmittedRequest {
    fn complete(self, status: FrameVBlkStatus) -> BlockRequestCompletion {
        let resource = match self.resource {
            BlockRequestResource::None => None,
            BlockRequestResource::ReadBuffer(buffer) => {
                Some(BlockReturnedResource::ReadBuffer(buffer.return_to_owner()))
            }
            BlockRequestResource::WriteBuffer(buffer) => {
                Some(BlockReturnedResource::WriteBuffer(buffer.return_to_owner()))
            }
        };
        let info = completion_info(status, resource.is_some());
        BlockRequestCompletion { info, resource }
    }
}

fn validation_status(error: FrameVBlkRequestError) -> FrameVBlkStatus {
    match error {
        FrameVBlkRequestError::UnsupportedOperation(_) => FrameVBlkStatus::Unsupported,
        FrameVBlkRequestError::InvalidFlushFields
        | FrameVBlkRequestError::InvalidResourceShape
        | FrameVBlkRequestError::NonZeroReserved
        | FrameVBlkRequestError::OutOfRange { .. }
        | FrameVBlkRequestError::RangeOverflow
        | FrameVBlkRequestError::ResourceLengthMismatch { .. }
        | FrameVBlkRequestError::ReadonlyWrite
        | FrameVBlkRequestError::UnalignedLength(_)
        | FrameVBlkRequestError::ZeroLength => FrameVBlkStatus::IoErr,
    }
}

fn completion_info(status: FrameVBlkStatus, returns_resource: bool) -> FrameVBlkCompletion {
    CompletionInfo::new(
        match status {
            FrameVBlkStatus::Ok => OperationResult::Ok,
            FrameVBlkStatus::IoErr => OperationResult::Error(OperationError::Device(
                framev_blk_common::FrameVBlkDeviceError::Io,
            )),
            FrameVBlkStatus::Unsupported => OperationResult::Error(OperationError::Device(
                framev_blk_common::FrameVBlkDeviceError::Unsupported,
            )),
        },
        if returns_resource {
            vec![ResourceResult::Returned]
        } else {
            vec![]
        },
        status,
    )
}

fn request_offset(header: FrameVBlkRequestHeader) -> u64 {
    header.sector() * FRAMEV_BLK_SECTOR_SIZE
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use framev_device::{FrameVDeviceType, IrqLine, OwnedResource};
    use spin::Mutex;

    use super::*;

    struct MemoryImage {
        data: Mutex<Vec<u8>>,
        readonly: bool,
        fail_flush: bool,
    }

    impl MemoryImage {
        fn new(data: Vec<u8>, readonly: bool, fail_flush: bool) -> Self {
            Self {
                data: Mutex::new(data),
                readonly,
                fail_flush,
            }
        }
    }

    impl BlockImage for MemoryImage {
        fn read_exact_at(&self, offset_bytes: u64, dst: &mut [u8]) -> Result<(), BlockImageError> {
            let offset = offset_bytes as usize;
            let data = self.data.lock();
            let Some(end) = offset.checked_add(dst.len()) else {
                return Err(BlockImageError::ShortRead {
                    offset_bytes,
                    requested_bytes: dst.len(),
                    actual_bytes: 0,
                });
            };
            let Some(src) = data.get(offset..end) else {
                let actual_bytes = data.len().saturating_sub(offset);
                return Err(BlockImageError::ShortRead {
                    offset_bytes,
                    requested_bytes: dst.len(),
                    actual_bytes,
                });
            };
            dst.copy_from_slice(src);
            Ok(())
        }

        fn write_all_at(&self, offset_bytes: u64, src: &[u8]) -> Result<(), BlockImageError> {
            if self.readonly {
                return Err(BlockImageError::Readonly);
            }
            let offset = offset_bytes as usize;
            let mut data = self.data.lock();
            let Some(end) = offset.checked_add(src.len()) else {
                return Err(BlockImageError::ShortWrite {
                    offset_bytes,
                    requested_bytes: src.len(),
                    actual_bytes: 0,
                });
            };
            let Some(dst) = data.get_mut(offset..end) else {
                let actual_bytes = data.len().saturating_sub(offset);
                return Err(BlockImageError::ShortWrite {
                    offset_bytes,
                    requested_bytes: src.len(),
                    actual_bytes,
                });
            };
            dst.copy_from_slice(src);
            Ok(())
        }

        fn flush(&self) -> Result<(), BlockImageError> {
            if self.fail_flush {
                return Err(BlockImageError::Flush);
            }
            Ok(())
        }

        fn capacity_bytes(&self) -> u64 {
            self.data.lock().len() as u64
        }

        fn readonly(&self) -> bool {
            self.readonly
        }
    }

    #[test]
    fn exact_read_write_and_capacity_use_byte_offsets() {
        let image = MemoryImage::new(Vec::from([0_u8; 8]), false, false);

        image.write_all_at(2, &[1, 2, 3]).unwrap();
        let mut out = [0_u8; 3];
        image.read_exact_at(2, &mut out).unwrap();

        assert_eq!(out, [1, 2, 3]);
        assert_eq!(image.capacity_bytes(), 8);
        assert!(!image.readonly());
    }

    #[test]
    fn short_io_reports_typed_errors() {
        let image = MemoryImage::new(Vec::from([0_u8; 4]), false, false);

        assert_eq!(
            image.read_exact_at(2, &mut [0_u8; 4]),
            Err(BlockImageError::ShortRead {
                offset_bytes: 2,
                requested_bytes: 4,
                actual_bytes: 2,
            })
        );
        assert_eq!(
            image.write_all_at(3, &[1, 2]),
            Err(BlockImageError::ShortWrite {
                offset_bytes: 3,
                requested_bytes: 2,
                actual_bytes: 1,
            })
        );
    }

    #[test]
    fn readonly_and_flush_failures_are_typed() {
        let readonly = MemoryImage::new(Vec::from([0_u8; 4]), true, false);
        let flush_fails = MemoryImage::new(Vec::from([0_u8; 4]), false, true);

        assert_eq!(
            readonly.write_all_at(0, &[1]),
            Err(BlockImageError::Readonly)
        );
        assert_eq!(flush_fails.flush(), Err(BlockImageError::Flush));
    }

    #[test]
    fn block_config_reports_capacity_readonly_and_flush_support() {
        let writable = block_with_image(MemoryImage::new(Vec::from([0_u8; 1024]), false, false));
        let readonly = block_with_image(MemoryImage::new(Vec::from([0_u8; 1024]), true, false));

        assert_eq!(writable.config().capacity_sectors(), 2);
        assert_eq!(
            writable.config().logical_block_size(),
            FRAMEV_BLK_SECTOR_SIZE as u32
        );
        assert!(!writable.config().flags().readonly());
        assert!(writable.config().flags().flush_supported());
        assert!(readonly.config().flags().readonly());
    }

    #[test]
    fn block_rejects_zero_or_unaligned_images() {
        assert_eq!(
            Block::new(
                block_info(),
                Arc::new(MemoryImage::new(Vec::new(), false, false))
            )
            .err(),
            Some(Error::InvalidArgs)
        );
        assert_eq!(
            Block::new(
                block_info(),
                Arc::new(MemoryImage::new(Vec::from([0_u8; 513]), false, false))
            )
            .err(),
            Some(Error::InvalidArgs)
        );
    }

    #[test]
    fn block_executes_ordered_write_read_and_flush() {
        let block = block_with_image(MemoryImage::new(Vec::from([0_u8; 1024]), false, false));

        let write = block
            .submit_request(
                FrameVBlkRequestHeader::new(FrameVBlkOp::Write, 1, 512),
                write_resource(Vec::from([7_u8; 512])),
            )
            .unwrap();
        assert_eq!(write.info().payload(), &FrameVBlkStatus::Ok);
        assert_eq!(write.info().resource_results(), &[ResourceResult::Returned]);

        let read = block
            .submit_request(
                FrameVBlkRequestHeader::new(FrameVBlkOp::Read, 1, 512),
                read_resource(512),
            )
            .unwrap();
        assert_eq!(read.info().payload(), &FrameVBlkStatus::Ok);
        let Some(BlockReturnedResource::ReadBuffer(buffer)) = read.into_resource() else {
            panic!("read buffer should be returned");
        };
        assert_eq!(buffer.into_inner(), Vec::from([7_u8; 512]));

        let flush = block
            .submit_request(
                FrameVBlkRequestHeader::new(FrameVBlkOp::Flush, 0, 0),
                BlockRequestResource::None,
            )
            .unwrap();
        assert_eq!(flush.info().payload(), &FrameVBlkStatus::Ok);
        assert!(flush.info().resource_results().is_empty());
    }

    #[test]
    fn block_maps_validation_backend_and_unsupported_failures() {
        let readonly = block_with_image(MemoryImage::new(Vec::from([0_u8; 1024]), true, false));
        let flush_fails = block_with_image(MemoryImage::new(Vec::from([0_u8; 1024]), false, true));

        let write = readonly
            .submit_request(
                FrameVBlkRequestHeader::new(FrameVBlkOp::Write, 0, 512),
                write_resource(Vec::from([1_u8; 512])),
            )
            .unwrap();
        assert_eq!(write.info().payload(), &FrameVBlkStatus::IoErr);

        let invalid_read = readonly
            .submit_request(
                FrameVBlkRequestHeader::new(FrameVBlkOp::Read, 0, 512),
                BlockRequestResource::None,
            )
            .unwrap();
        assert_eq!(invalid_read.info().payload(), &FrameVBlkStatus::IoErr);
        assert!(invalid_read.info().resource_results().is_empty());

        let unsupported = readonly
            .submit_request(
                FrameVBlkRequestHeader::from_raw_fields(99, 0, 0, 0, 0),
                BlockRequestResource::None,
            )
            .unwrap();
        assert_eq!(unsupported.info().payload(), &FrameVBlkStatus::Unsupported);

        let flush = flush_fails
            .submit_request(
                FrameVBlkRequestHeader::new(FrameVBlkOp::Flush, 0, 0),
                BlockRequestResource::None,
            )
            .unwrap();
        assert_eq!(flush.info().payload(), &FrameVBlkStatus::IoErr);
    }

    fn block_with_image(image: MemoryImage) -> Block {
        let block = Block::new(block_info(), Arc::new(image)).unwrap();
        block.mark_ready().unwrap();
        block
    }

    fn block_info() -> FrameVDeviceInfo {
        FrameVDeviceInfo::new(
            FrameVDeviceType::Block.well_known_id(),
            FrameVDeviceType::Block,
            IrqLine::new(4),
        )
    }

    fn read_resource(len: usize) -> BlockRequestResource {
        BlockRequestResource::ReadBuffer(
            OwnedResource::new(Vec::from_iter((0..len).map(|_| 0))).submit(),
        )
    }

    fn write_resource(bytes: Vec<u8>) -> BlockRequestResource {
        BlockRequestResource::WriteBuffer(OwnedResource::new(bytes).submit())
    }
}
