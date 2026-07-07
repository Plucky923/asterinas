// SPDX-License-Identifier: MPL-2.0

//! FrameV-blk request header and validation.

use framev_device::{FrameVRequest, FrameVResource};

use crate::metadata::FRAMEV_BLK_SECTOR_SIZE;

/// Virtio-blk-style FrameV-blk operation.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkOp {
    Read = 0,
    Write = 1,
    Flush = 4,
}

impl TryFrom<u32> for FrameVBlkOp {
    type Error = FrameVBlkRequestError;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        match raw {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            4 => Ok(Self::Flush),
            value => Err(FrameVBlkRequestError::UnsupportedOperation(value)),
        }
    }
}

impl FrameVBlkOp {
    /// Returns the raw ABI value.
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// FrameV-blk request resource shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkResourceShape {
    NoData,
    ReadBuffer { len_bytes: u64 },
    WriteBuffer { len_bytes: u64 },
}

impl FrameVResource for FrameVBlkResourceShape {}

/// Fixed FrameV-blk v1 request header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVBlkRequestHeader {
    op: u32,
    reserved: u32,
    sector: u64,
    len_bytes: u64,
    reserved2: u64,
}

impl FrameVRequest for FrameVBlkRequestHeader {}

impl FrameVBlkRequestHeader {
    /// Creates a FrameV-blk request header.
    pub const fn new(op: FrameVBlkOp, sector: u64, len_bytes: u64) -> Self {
        Self {
            op: op.raw(),
            reserved: 0,
            sector,
            len_bytes,
            reserved2: 0,
        }
    }

    /// Creates a request header from decoded guest ABI fields.
    pub const fn from_raw_fields(
        op: u32,
        reserved: u32,
        sector: u64,
        len_bytes: u64,
        reserved2: u64,
    ) -> Self {
        Self {
            op,
            reserved,
            sector,
            len_bytes,
            reserved2,
        }
    }

    /// Returns the operation.
    pub fn op(self) -> Result<FrameVBlkOp, FrameVBlkRequestError> {
        FrameVBlkOp::try_from(self.op)
    }

    /// Returns the starting 512-byte sector.
    pub const fn sector(self) -> u64 {
        self.sector
    }

    /// Returns request length in bytes.
    pub const fn len_bytes(self) -> u64 {
        self.len_bytes
    }

    /// Validates this header and resource shape against device capacity.
    pub fn validate(
        self,
        capacity_sectors: u64,
        resource: FrameVBlkResourceShape,
    ) -> Result<(), FrameVBlkRequestError> {
        self.validate_with_mode(capacity_sectors, false, resource)
    }

    /// Validates this header and resource shape with readonly mode.
    pub fn validate_with_mode(
        self,
        capacity_sectors: u64,
        readonly: bool,
        resource: FrameVBlkResourceShape,
    ) -> Result<(), FrameVBlkRequestError> {
        if self.reserved != 0 || self.reserved2 != 0 {
            return Err(FrameVBlkRequestError::NonZeroReserved);
        }
        match self.op()? {
            FrameVBlkOp::Read => self.validate_read_write(capacity_sectors, resource, true),
            FrameVBlkOp::Write => {
                if readonly {
                    return Err(FrameVBlkRequestError::ReadonlyWrite);
                }
                self.validate_read_write(capacity_sectors, resource, false)
            }
            FrameVBlkOp::Flush => self.validate_flush(resource),
        }
    }

    fn validate_read_write(
        self,
        capacity_sectors: u64,
        resource: FrameVBlkResourceShape,
        read: bool,
    ) -> Result<(), FrameVBlkRequestError> {
        if self.len_bytes == 0 {
            return Err(FrameVBlkRequestError::ZeroLength);
        }
        if self.len_bytes % FRAMEV_BLK_SECTOR_SIZE != 0 {
            return Err(FrameVBlkRequestError::UnalignedLength(self.len_bytes));
        }
        let resource_len = match (read, resource) {
            (true, FrameVBlkResourceShape::ReadBuffer { len_bytes }) => len_bytes,
            (false, FrameVBlkResourceShape::WriteBuffer { len_bytes }) => len_bytes,
            _ => return Err(FrameVBlkRequestError::InvalidResourceShape),
        };
        if resource_len != self.len_bytes {
            return Err(FrameVBlkRequestError::ResourceLengthMismatch {
                expected: self.len_bytes,
                actual: resource_len,
            });
        }
        let capacity_bytes = capacity_sectors
            .checked_mul(FRAMEV_BLK_SECTOR_SIZE)
            .ok_or(FrameVBlkRequestError::RangeOverflow)?;
        let offset = self
            .sector
            .checked_mul(FRAMEV_BLK_SECTOR_SIZE)
            .ok_or(FrameVBlkRequestError::RangeOverflow)?;
        let end = offset
            .checked_add(self.len_bytes)
            .ok_or(FrameVBlkRequestError::RangeOverflow)?;
        if end > capacity_bytes {
            return Err(FrameVBlkRequestError::OutOfRange {
                offset,
                len_bytes: self.len_bytes,
                capacity_bytes,
            });
        }
        Ok(())
    }

    fn validate_flush(self, resource: FrameVBlkResourceShape) -> Result<(), FrameVBlkRequestError> {
        if self.sector != 0 || self.len_bytes != 0 {
            return Err(FrameVBlkRequestError::InvalidFlushFields);
        }
        if resource != FrameVBlkResourceShape::NoData {
            return Err(FrameVBlkRequestError::InvalidResourceShape);
        }
        Ok(())
    }
}

/// FrameV-blk request validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkRequestError {
    InvalidFlushFields,
    InvalidResourceShape,
    NonZeroReserved,
    OutOfRange {
        offset: u64,
        len_bytes: u64,
        capacity_bytes: u64,
    },
    RangeOverflow,
    ResourceLengthMismatch {
        expected: u64,
        actual: u64,
    },
    ReadonlyWrite,
    UnalignedLength(u64),
    UnsupportedOperation(u32),
    ZeroLength,
}

const _: () = {
    assert!(size_of::<FrameVBlkRequestHeader>() == 32);
    assert!(align_of::<FrameVBlkRequestHeader>() == 8);
};
