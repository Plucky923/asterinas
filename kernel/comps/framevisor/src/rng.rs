// SPDX-License-Identifier: MPL-2.0

//! FrameV RNG backend.

use framev_device::OwnedResource;
use framev_rng_common::{RngFillRequest, RngOutputBuffer, RngRing, RngSubmitOutcome};
use host_ostd::sync::{SpinLock, WaitQueue};

use crate::{Error, Result, task, vm};

const MAX_RNG_REQUEST_BYTES: usize = 256;

struct RngRequestState {
    stopped: bool,
    outstanding: bool,
    submitted_requests: u64,
    completed_requests: u64,
}

impl RngRequestState {
    const fn new() -> Self {
        Self {
            stopped: false,
            outstanding: false,
            submitted_requests: 0,
            completed_requests: 0,
        }
    }
}

/// Host backend state for one required `framev-rng` device.
pub struct FrameVRngDevice {
    state: SpinLock<RngRequestState>,
    request_wait: WaitQueue,
}

impl FrameVRngDevice {
    /// Creates an empty RNG backend.
    pub fn new() -> Self {
        Self {
            state: SpinLock::new(RngRequestState::new()),
            request_wait: WaitQueue::new(),
        }
    }

    /// Completes entropy requests for `dst`.
    pub fn fill_bytes(
        &self,
        dst: &mut [u8],
        mut notify_completion: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        for chunk in dst.chunks_mut(MAX_RNG_REQUEST_BYTES) {
            self.fill_request(chunk, &mut notify_completion)?;
        }
        Ok(())
    }

    /// Stops this RNG backend and wakes request waiters.
    pub fn stop(&self) {
        let mut state = self.state.lock();
        state.stopped = true;
        state.outstanding = false;
        drop(state);
        self.request_wait.wake_all();
    }

    /// Resets this RNG backend for a new lifecycle.
    pub fn reset(&self) {
        let mut state = self.state.lock();
        state.stopped = false;
        state.outstanding = false;
        state.submitted_requests = 0;
        state.completed_requests = 0;
        drop(state);
        self.request_wait.wake_all();
    }

    fn fill_request(
        &self,
        dst: &mut [u8],
        notify_completion: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.begin_request()?;
        let result = fill_rng_request_through_common_path(dst);
        self.complete_request();
        result?;
        notify_completion()
    }

    fn begin_request(&self) -> Result<()> {
        self.request_wait.wait_until(|| {
            let mut state = self.state.lock();
            if state.stopped {
                return Some(Err(Error::IoError));
            }
            if state.outstanding {
                return None;
            }

            state.outstanding = true;
            state.submitted_requests = state.submitted_requests.saturating_add(1);
            Some(Ok(()))
        })
    }

    fn complete_request(&self) {
        let mut state = self.state.lock();
        state.outstanding = false;
        state.completed_requests = state.completed_requests.saturating_add(1);
        drop(state);
        self.request_wait.wake_all();
    }
}

fn fill_rng_request_through_common_path(dst: &mut [u8]) -> Result<()> {
    let mut random_bytes = alloc::vec![0; dst.len()];
    fill_host_random(&mut random_bytes)?;

    let output = RngOutputBuffer::new(dst.len()).map_err(|_| Error::InvalidArgs)?;
    let request = RngFillRequest::new(alloc::vec![OwnedResource::new(output)])
        .map_err(|_| Error::InvalidArgs)?;
    let mut ring = RngRing::new(1).map_err(|_| Error::InvalidArgs)?;
    let outcome = ring
        .submit_with_immediate_fill(request, Some(&random_bytes))
        .map_err(|_| Error::IoError)?;

    let RngSubmitOutcome::Completed(completed) = outcome else {
        return Err(Error::IoError);
    };
    let (_completion, output) = completed.into_parts();
    let output = output.into_inner().into_bytes();
    dst.copy_from_slice(&output[..dst.len()]);
    Ok(())
}

/// Fills `dst` through the current FrameVM's required RNG backend.
#[inline(never)]
pub fn fill_bytes(dst: &mut [u8]) -> Result<()> {
    {
        let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(Error::InvalidArgs)?;
        let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(Error::InvalidArgs)?;
        return vm.devices().rng().fill_bytes(
            dst,
            vm.id(),
            vm.is_running(),
            vm.devices(),
            |vcpu_id| vm.vcpu_irq_load(vcpu_id),
        );
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

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn service_shim_fails_without_current_vm_context() {
        let mut bytes = [0u8; 8];

        assert_eq!(fill_bytes(&mut bytes), Err(Error::InvalidArgs));
    }
}
