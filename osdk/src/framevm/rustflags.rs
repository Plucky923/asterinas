// SPDX-License-Identifier: MPL-2.0

//! Rust symbol-identity flags shared by host and FrameVM service builds.
//!
//! These flags are OSDK transaction policy. They keep Rust v0 symbol names from
//! drifting merely because the host and service roots are compiled by separate
//! Cargo invocations during the current migration.

pub(super) const SHARED_RUSTFLAGS: &[&str] = &[
    "-C metadata=framevm_service",
    "-C symbol-mangling-version=v0",
];
