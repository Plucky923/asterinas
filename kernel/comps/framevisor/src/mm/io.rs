//! Virtual memory I/O wrappers exposed through the OSTD-compatible surface.

use core::result::Result as CoreResult;

pub use host_ostd::mm::{Fallible, Infallible, PodAtomic};
use host_ostd::mm::{
    FallibleVmRead as OstdFallibleVmRead, FallibleVmWrite as OstdFallibleVmWrite,
    VmReader as OstdVmReader, VmWriter as OstdVmWriter,
};

use crate::Error;

/// Fallible memory read from a `VmWriter`.
pub trait FallibleVmRead<F> {
    /// Reads data into `writer`, returning service errors on user faults.
    fn read_fallible(&mut self, writer: &mut VmWriter<'_, F>) -> CoreResult<usize, (Error, usize)>;
}

/// Fallible memory write from a `VmReader`.
pub trait FallibleVmWrite<F> {
    /// Writes data from `reader`, returning service errors on user faults.
    fn write_fallible(&mut self, reader: &mut VmReader<'_, F>)
    -> CoreResult<usize, (Error, usize)>;
}

/// Reader for a contiguous range of virtual memory.
pub struct VmReader<'a, Fallibility = Fallible>(OstdVmReader<'a, Fallibility>);

impl<Fallibility> Clone for VmReader<'_, Fallibility> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'a, Fallibility> VmReader<'a, Fallibility> {
    #[inline(always)]
    pub(crate) fn new_with_inner(reader: OstdVmReader<'a, Fallibility>) -> Self {
        Self(reader)
    }

    /// Returns the number of remaining bytes.
    #[inline(always)]
    pub fn remain(&self) -> usize {
        self.0.remain()
    }

    /// Returns whether unread bytes remain.
    #[inline(always)]
    pub fn has_remain(&self) -> bool {
        self.0.has_remain()
    }

    /// Limits the remaining length.
    #[inline(always)]
    pub fn limit(&mut self, max_remain: usize) -> &mut Self {
        self.0.limit(max_remain);
        self
    }

    /// Skips `nbytes` from the current cursor.
    #[inline(always)]
    pub fn skip(&mut self, nbytes: usize) -> &mut Self {
        self.0.skip(nbytes);
        self
    }
}

impl VmReader<'_, Infallible> {
    /// Reads into an infallible writer.
    #[inline(always)]
    pub fn read(&mut self, writer: &mut VmWriter<'_, Infallible>) -> usize {
        self.0.read(&mut writer.0)
    }
}

impl VmReader<'_, Fallible> {
    /// Atomically loads a value from the current cursor.
    #[inline(always)]
    pub fn atomic_load<T: PodAtomic>(&self) -> CoreResult<T, Error> {
        self.0.atomic_load().map_err(Error::from)
    }
}

impl<'a> From<&'a [u8]> for VmReader<'a, Infallible> {
    #[inline(always)]
    fn from(slice: &'a [u8]) -> Self {
        Self(OstdVmReader::from(slice))
    }
}

impl<'a, ReaderFallibility, WriterFallibility> FallibleVmRead<WriterFallibility>
    for VmReader<'a, ReaderFallibility>
where
    OstdVmReader<'a, ReaderFallibility>: OstdFallibleVmRead<WriterFallibility>,
{
    #[inline(always)]
    fn read_fallible(
        &mut self,
        writer: &mut VmWriter<'_, WriterFallibility>,
    ) -> CoreResult<usize, (Error, usize)> {
        match self.0.read_fallible(&mut writer.0) {
            Ok(copied_len) => Ok(copied_len),
            Err((error, copied_len)) => Err((Error::from(error), copied_len)),
        }
    }
}

/// Writer for a contiguous range of virtual memory.
pub struct VmWriter<'a, Fallibility = Fallible>(OstdVmWriter<'a, Fallibility>);

impl<'a, Fallibility> VmWriter<'a, Fallibility> {
    #[inline(always)]
    pub(crate) fn new_with_inner(writer: OstdVmWriter<'a, Fallibility>) -> Self {
        Self(writer)
    }

    /// Returns the number of writable bytes.
    #[inline(always)]
    pub fn avail(&self) -> usize {
        self.0.avail()
    }

    /// Returns whether writable bytes remain.
    #[inline(always)]
    pub fn has_avail(&self) -> bool {
        self.0.has_avail()
    }

    /// Limits the available length.
    #[inline(always)]
    pub fn limit(&mut self, max_avail: usize) -> &mut Self {
        self.0.limit(max_avail);
        self
    }

    /// Skips `nbytes` from the current cursor.
    #[inline(always)]
    pub fn skip(&mut self, nbytes: usize) -> &mut Self {
        self.0.skip(nbytes);
        self
    }
}

impl VmWriter<'_, Infallible> {
    /// Writes from an infallible reader.
    #[inline(always)]
    pub fn write(&mut self, reader: &mut VmReader<'_, Infallible>) -> usize {
        self.0.write(&mut reader.0)
    }

    /// Fills the writer with zeros.
    #[inline(always)]
    pub fn fill_zeros(&mut self, len: usize) -> usize {
        self.0.fill_zeros(len)
    }
}

impl VmWriter<'_, Fallible> {
    /// Fills the writer with zeros, returning service errors on user faults.
    #[inline(always)]
    pub fn fill_zeros(&mut self, len: usize) -> CoreResult<usize, (Error, usize)> {
        match self.0.fill_zeros(len) {
            Ok(copied_len) => Ok(copied_len),
            Err((error, copied_len)) => Err((Error::from(error), copied_len)),
        }
    }

    /// Atomically compares and exchanges a value at the current cursor.
    #[inline(always)]
    pub fn atomic_compare_exchange<T>(
        &self,
        reader: &VmReader<'_, Fallible>,
        old_val: T,
        new_val: T,
    ) -> CoreResult<(T, bool), Error>
    where
        T: PodAtomic + Eq,
    {
        self.0
            .atomic_compare_exchange(&reader.0, old_val, new_val)
            .map_err(Error::from)
    }
}

impl<'a> From<&'a mut [u8]> for VmWriter<'a, Infallible> {
    #[inline(always)]
    fn from(slice: &'a mut [u8]) -> Self {
        Self(OstdVmWriter::from(slice))
    }
}

impl<'a, WriterFallibility, ReaderFallibility> FallibleVmWrite<ReaderFallibility>
    for VmWriter<'a, WriterFallibility>
where
    OstdVmWriter<'a, WriterFallibility>: OstdFallibleVmWrite<ReaderFallibility>,
{
    #[inline(always)]
    fn write_fallible(
        &mut self,
        reader: &mut VmReader<'_, ReaderFallibility>,
    ) -> CoreResult<usize, (Error, usize)> {
        match self.0.write_fallible(&mut reader.0) {
            Ok(copied_len) => Ok(copied_len),
            Err((error, copied_len)) => Err((Error::from(error), copied_len)),
        }
    }
}
