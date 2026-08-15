// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use framev_rng_common::MAX_FILL_BYTES;

use super::state::FunctionRuntime;
use crate::{Error, Result};

/// Typed host handle for one VM's FrameV RNG backend.
pub struct Rng {
    runtime: Arc<FunctionRuntime>,
}

impl Rng {
    pub(super) fn new(runtime: Arc<FunctionRuntime>) -> Self {
        Self { runtime }
    }

    pub(super) fn runtime(&self) -> &FunctionRuntime {
        &self.runtime
    }

    /// Completes entropy requests for `dst`.
    pub(crate) fn fill_bytes(&self, dst: &mut [u8]) -> Result<()> {
        for chunk in dst.chunks_mut(MAX_FILL_BYTES) {
            fill_host_random(chunk)?;
        }
        Ok(())
    }
}

fn fill_host_random(dst: &mut [u8]) -> Result<()> {
    let mut chunks = dst.chunks_exact_mut(size_of::<u64>());
    for chunk in chunks.by_ref() {
        let value = host_ostd::arch::read_random().ok_or(Error::NotEnoughResources)?;
        chunk.copy_from_slice(&value.to_ne_bytes());
    }

    let tail = chunks.into_remainder();
    if !tail.is_empty() {
        let value = host_ostd::arch::read_random().ok_or(Error::NotEnoughResources)?;
        tail.copy_from_slice(&value.to_ne_bytes()[..tail.len()]);
    }

    Ok(())
}
