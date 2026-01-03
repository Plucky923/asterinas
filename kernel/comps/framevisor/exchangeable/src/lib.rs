// SPDX-License-Identifier: MPL-2.0

//! Exchangeable trait and RRef for zero-copy data transfer between Guest and Host.
//!
//! # Design
//!
//! The `Exchangeable` trait marks types that can be safely transferred between
//! Guest (FrameVM) and Host (Kernel) without copying the data.
//!
//! Types that are NOT Exchangeable:
//! - Raw pointers (*mut T, *const T) - would be invalid across address spaces
//! - References (&T, &mut T) - borrowing doesn't work across boundaries
//! - Unsized slices ([T]) - need a known size for transfer
//!
//! Types that ARE Exchangeable (explicitly implemented):
//! - Vec<u8> - ownership transfer, the Vec's heap allocation stays valid
//! - Box<T> where T: Exchangeable - ownership transfer of boxed value
//! - All primitive types (via auto trait)
//! - Structs composed only of Exchangeable types

#![no_std]
#![deny(unsafe_code)]
#![feature(auto_traits)]
#![feature(negative_impls)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

pub auto trait Exchangeable {}

// Types that cannot be exchanged safely
impl<T> !Exchangeable for *mut T {}
impl<T> !Exchangeable for *const T {}
impl<T> !Exchangeable for &T {}
impl<T> !Exchangeable for &mut T {}
impl<T> !Exchangeable for [T] {}

// Explicitly implement Exchangeable for heap-allocated types
// These are safe because we transfer ownership, not references
// The heap memory remains valid after transfer

/// Vec<u8> is Exchangeable - we transfer ownership of the entire Vec
/// including its heap allocation. The receiver gets full ownership.
impl Exchangeable for Vec<u8> {}

/// Box<T> is Exchangeable if T is Exchangeable
/// We transfer ownership of the boxed value.
impl<T: Exchangeable + ?Sized> Exchangeable for Box<T> {}

pub struct RRef<T: Exchangeable> {
    value: T,
}

impl<T: Exchangeable> RRef<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Gets a reference to the inner value
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Gets a mutable reference to the inner value
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Consumes the RRef and returns the inner value
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T: Exchangeable> core::ops::Deref for RRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: Exchangeable> core::ops::DerefMut for RRef<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}
