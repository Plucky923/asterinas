//! FrameV ownership-transfer resource typestates.
//!
//! This module defines move-only resource wrappers and receiver access markers
//! used by device-class protocols.

use core::marker::PhantomData;

/// Receiver access mode for a transferred FrameV resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceAccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Consume,
}

/// Read-only resource access marker.
#[derive(Debug, Eq, PartialEq)]
pub struct ReadOnly;

/// Write-only resource access marker.
#[derive(Debug, Eq, PartialEq)]
pub struct WriteOnly;

/// Read-write resource access marker.
#[derive(Debug, Eq, PartialEq)]
pub struct ReadWrite;

/// Consume-style resource access marker.
#[derive(Debug, Eq, PartialEq)]
pub struct Consume;

/// A submitter-owned FrameV resource.
#[derive(Debug, Eq, PartialEq)]
pub struct OwnedResource<T> {
    value: T,
}

impl<T> OwnedResource<T> {
    /// Creates an owned resource.
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Transfers the resource to a receiver with the given access mode.
    pub fn submit<Access>(self) -> SubmittedResource<T, Access> {
        SubmittedResource {
            value: self.value,
            access: PhantomData,
        }
    }

    /// Borrows the owned resource.
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Consumes the wrapper and returns the inner resource.
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// A receiver-owned submitted FrameV resource.
#[derive(Debug, Eq, PartialEq)]
pub struct SubmittedResource<T, Access> {
    value: T,
    access: PhantomData<Access>,
}

impl<T, Access> SubmittedResource<T, Access> {
    /// Returns the submitted resource to the submitter.
    pub fn return_to_owner(self) -> ReturnedResource<T> {
        ReturnedResource { value: self.value }
    }

    /// Consumes the submitted resource.
    pub fn consume(self) -> ConsumedResource {
        ConsumedResource { _private: () }
    }
}

impl<T> SubmittedResource<T, ReadOnly> {
    /// Borrows a read-only submitted resource.
    pub const fn get(&self) -> &T {
        &self.value
    }
}

impl<T> SubmittedResource<T, ReadWrite> {
    /// Borrows a read-write submitted resource.
    pub const fn get(&self) -> &T {
        &self.value
    }

    /// Mutably borrows a read-write submitted resource.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T> SubmittedResource<T, WriteOnly> {
    /// Mutably borrows a write-only submitted resource.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

/// A resource returned to the submitter.
#[derive(Debug, Eq, PartialEq)]
pub struct ReturnedResource<T> {
    value: T,
}

impl<T> ReturnedResource<T> {
    /// Reclaims a returned resource as submitter-owned.
    pub fn reclaim(self) -> OwnedResource<T> {
        OwnedResource { value: self.value }
    }

    /// Consumes the wrapper and returns the inner resource.
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// A consumed-resource marker.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsumedResource {
    _private: (),
}
