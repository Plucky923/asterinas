use framev_device::{OperationError, OperationResult, ResourceResult};

use crate::*;

#[test]
fn config_rejects_unknown_flags() {
    assert_eq!(
        FrameVBlkConfig::new(1, FRAMEV_BLK_SECTOR_SIZE as u32, 1 << 31),
        Err(FrameVBlkConfigError::UnknownFlags(1 << 31))
    );
}

#[test]
fn operation_values_match_virtio_blk_subset() {
    assert_eq!(FrameVBlkOp::Read.raw(), 0);
    assert_eq!(FrameVBlkOp::Write.raw(), 1);
    assert_eq!(FrameVBlkOp::Flush.raw(), 4);
    assert_eq!(FrameVBlkStatus::Ok.raw(), 0);
    assert_eq!(FrameVBlkStatus::IoErr.raw(), 1);
    assert_eq!(FrameVBlkStatus::Unsupported.raw(), 2);
}

#[test]
fn default_metadata_matches_block_device() {
    let info = default_device_info();

    assert_eq!(info.id, DEFAULT_DEVICE_ID);
    assert_eq!(info.device_type, framev_device::FrameVDeviceType::Block);
    assert_eq!(info.irq_line, DEFAULT_IRQ_LINE);
    assert_eq!(FRAMEV_BLK_QUEUE_COUNT, 1);
}

#[test]
fn request_header_abi_is_fixed() {
    assert_eq!(size_of::<FrameVBlkConfig>(), 16);
    assert_eq!(align_of::<FrameVBlkConfig>(), 8);
    assert_eq!(size_of::<FrameVBlkRequestHeader>(), 32);
    assert_eq!(align_of::<FrameVBlkRequestHeader>(), 8);
}

#[test]
fn read_request_validates_resource_and_range() {
    let request = FrameVBlkRequestHeader::new(FrameVBlkOp::Read, 1, 512);
    assert_eq!(
        request.validate(2, FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 }),
        Ok(())
    );
    assert_eq!(
        request.validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 }),
        Err(FrameVBlkRequestError::OutOfRange {
            offset: 512,
            len_bytes: 512,
            capacity_bytes: 512,
        })
    );
}

#[test]
fn read_write_requests_reject_malformed_resources() {
    let read = FrameVBlkRequestHeader::new(FrameVBlkOp::Read, 0, 512);
    let write = FrameVBlkRequestHeader::new(FrameVBlkOp::Write, 0, 512);

    assert_eq!(
        read.validate(1, FrameVBlkResourceShape::NoData),
        Err(FrameVBlkRequestError::InvalidResourceShape)
    );
    assert_eq!(
        read.validate(1, FrameVBlkResourceShape::WriteBuffer { len_bytes: 512 }),
        Err(FrameVBlkRequestError::InvalidResourceShape)
    );
    assert_eq!(
        write.validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 }),
        Err(FrameVBlkRequestError::InvalidResourceShape)
    );
    assert_eq!(
        read.validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 1024 }),
        Err(FrameVBlkRequestError::ResourceLengthMismatch {
            expected: 512,
            actual: 1024,
        })
    );
}

#[test]
fn request_header_rejects_reserved_and_bad_lengths() {
    assert_eq!(
        FrameVBlkRequestHeader::from_raw_fields(0, 1, 0, 512, 0)
            .validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 }),
        Err(FrameVBlkRequestError::NonZeroReserved)
    );
    assert_eq!(
        FrameVBlkRequestHeader::from_raw_fields(0, 0, 0, 512, 1)
            .validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 }),
        Err(FrameVBlkRequestError::NonZeroReserved)
    );
    assert_eq!(
        FrameVBlkRequestHeader::new(FrameVBlkOp::Read, 0, 0)
            .validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 0 }),
        Err(FrameVBlkRequestError::ZeroLength)
    );
    assert_eq!(
        FrameVBlkRequestHeader::new(FrameVBlkOp::Read, 0, 1)
            .validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 1 }),
        Err(FrameVBlkRequestError::UnalignedLength(1))
    );
}

#[test]
fn request_validation_uses_checked_arithmetic() {
    assert_eq!(
        FrameVBlkRequestHeader::new(FrameVBlkOp::Read, 0, 512).validate(
            u64::MAX,
            FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 }
        ),
        Err(FrameVBlkRequestError::RangeOverflow)
    );
    assert_eq!(
        FrameVBlkRequestHeader::new(FrameVBlkOp::Read, u64::MAX, 512).validate(
            u64::MAX / FRAMEV_BLK_SECTOR_SIZE,
            FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 },
        ),
        Err(FrameVBlkRequestError::RangeOverflow)
    );
}

#[test]
fn flush_request_has_no_data_resource() {
    let request = FrameVBlkRequestHeader::new(FrameVBlkOp::Flush, 0, 0);
    assert_eq!(request.validate(1, FrameVBlkResourceShape::NoData), Ok(()));
    assert_eq!(
        request.validate(1, FrameVBlkResourceShape::ReadBuffer { len_bytes: 512 }),
        Err(FrameVBlkRequestError::InvalidResourceShape)
    );
    assert_eq!(
        FrameVBlkRequestHeader::new(FrameVBlkOp::Flush, 1, 0)
            .validate(1, FrameVBlkResourceShape::NoData),
        Err(FrameVBlkRequestError::InvalidFlushFields)
    );
    assert_eq!(
        FrameVBlkRequestHeader::new(FrameVBlkOp::Flush, 0, 512)
            .validate(1, FrameVBlkResourceShape::NoData),
        Err(FrameVBlkRequestError::InvalidFlushFields)
    );
}

#[test]
fn readonly_write_is_rejected_before_io() {
    let request = FrameVBlkRequestHeader::new(FrameVBlkOp::Write, 0, 512);
    assert_eq!(
        request.validate_with_mode(
            1,
            true,
            FrameVBlkResourceShape::WriteBuffer { len_bytes: 512 },
        ),
        Err(FrameVBlkRequestError::ReadonlyWrite)
    );
}

#[test]
fn completion_status_and_resource_results_are_separate() {
    let completion = data_completion(FrameVBlkStatus::IoErr);
    assert_eq!(
        completion.operation(),
        &OperationResult::Error(OperationError::Device(FrameVBlkDeviceError::Io))
    );
    assert_eq!(completion.resource_results(), &[ResourceResult::Returned]);
    assert_eq!(completion.payload(), &FrameVBlkStatus::IoErr);

    let completion = flush_completion(FrameVBlkStatus::Ok);
    assert_eq!(completion.operation(), &OperationResult::Ok);
    assert!(completion.resource_results().is_empty());
    assert_eq!(completion.payload(), &FrameVBlkStatus::Ok);
}

#[test]
fn completion_status_defines_bio_status_intent() {
    assert_eq!(
        FrameVBlkStatus::Ok.bio_status_intent(),
        FrameVBlkBioStatusIntent::Complete
    );
    assert_eq!(
        FrameVBlkStatus::IoErr.bio_status_intent(),
        FrameVBlkBioStatusIntent::IoError
    );
    assert_eq!(
        FrameVBlkStatus::Unsupported.bio_status_intent(),
        FrameVBlkBioStatusIntent::NotSupported
    );
}
