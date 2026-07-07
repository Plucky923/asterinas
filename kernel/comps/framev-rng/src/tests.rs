use alloc::{vec, vec::Vec};
use core::cell::Cell;

use framev_device::{
    CommonError, CompletionInfo, FrameVDeviceType, IrqAccepted, IrqDelivery, IrqLine, IrqTarget,
    OperationError, OperationResult, OwnedResource, ResourceResult, RingSlot, SubmitOutcome,
    well_known,
};

use crate::*;

#[derive(Default)]
struct TestNotifier {
    calls: Cell<usize>,
}

impl IrqDelivery for TestNotifier {
    type Error = CommonError;

    fn notify_irq(&self, irq_line: IrqLine, target: IrqTarget) -> Result<IrqAccepted, CommonError> {
        assert_eq!(irq_line, DEFAULT_IRQ_LINE);
        assert_eq!(target, IrqTarget::Untargeted);
        self.calls.set(self.calls.get() + 1);
        Ok(IrqAccepted)
    }
}

fn owned_output(capacity: usize) -> OwnedResource<RngOutputBuffer> {
    OwnedResource::new(RngOutputBuffer::new(capacity).unwrap())
}

#[test]
fn rng_metadata_uses_common_descriptor_model() {
    let info = default_device_info();

    assert_eq!(info.id, well_known::DEFAULT_RNG_DEVICE_ID);
    assert_eq!(info.device_type, FrameVDeviceType::Rng);
    assert_eq!(info.irq_line, DEFAULT_IRQ_LINE);
}

#[test]
fn rng_defines_one_request_ring_with_minimum_depth() {
    assert_eq!(RING_COUNT, 1);
    assert_eq!(MIN_RING_DEPTH, 1);
    assert_eq!(DEFAULT_NOTIFICATION_TARGET, IrqTarget::Untargeted);
    assert_eq!(RngRing::new(0).unwrap_err(), RngError::InvalidRingDepth);
    assert_eq!(RngRing::new(1).unwrap().depth(), 1);
}

#[test]
fn rng_request_requires_exactly_one_nonempty_output_buffer() {
    assert_eq!(RngOutputBuffer::new(0).unwrap_err(), RngError::EmptyBuffer);
    assert_eq!(
        RngFillRequest::new(Vec::new()).unwrap_err(),
        RngError::InvalidRequest
    );
    assert_eq!(
        RngFillRequest::new(vec![owned_output(1), owned_output(1)]).unwrap_err(),
        RngError::InvalidRequest
    );

    let request = RngFillRequest::new(vec![owned_output(8)]).unwrap();
    let mut submitted = request.submit();
    assert_eq!(submitted.capacity(), 8);
}

#[test]
fn successful_fill_returns_buffer_and_bytes_written() {
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let submitted = request.submit();
    let (completion, returned) = submitted.complete_success(&[1, 2, 3]).unwrap();

    assert_eq!(
        completion,
        CompletionInfo::new(
            OperationResult::Ok,
            vec![ResourceResult::Returned],
            RngCompletionPayload::new(3)
        )
    );
    assert_eq!(returned.into_inner().into_bytes(), vec![1, 2, 3, 0]);
}

#[test]
fn successful_fill_rejects_zero_or_oversized_bytes_written() {
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let submitted = request.submit();
    assert_eq!(
        submitted.complete_success(&[]).unwrap_err(),
        RngError::InvalidCompletion
    );

    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let submitted = request.submit();
    assert_eq!(
        submitted.complete_success(&[1, 2, 3, 4, 5]).unwrap_err(),
        RngError::InvalidCompletion
    );
}

#[test]
fn failed_fill_returns_output_buffer_with_zero_bytes_written() {
    let request = RngFillRequest::new(vec![owned_output(2)]).unwrap();
    let submitted = request.submit();
    let (completion, returned) =
        submitted.complete_error(OperationError::Common(CommonError::Reset));

    assert_eq!(
        completion,
        CompletionInfo::new(
            OperationResult::Error(OperationError::Common(CommonError::Reset)),
            vec![ResourceResult::Returned],
            RngCompletionPayload::new(0)
        )
    );
    assert_eq!(returned.into_inner().into_bytes(), vec![0, 0]);
}

#[test]
fn full_rng_ring_keeps_frontend_output_buffer_ownership() {
    let mut ring = RngRing::new(1).unwrap();
    let first = RngFillRequest::new(vec![owned_output(1)]).unwrap();
    let _submitted = ring.submit(first).unwrap();
    let second = RngFillRequest::new(vec![owned_output(2)]).unwrap();
    let error = ring.submit(second).unwrap_err();

    assert_eq!(error.error(), &OperationError::Common(CommonError::Full));
    let mut submitted = error.into_request().submit();
    assert_eq!(submitted.capacity(), 2);
}

#[test]
fn rng_submit_uses_common_submit_outcome() {
    let mut ring = RngRing::new(1).unwrap();
    let request = RngFillRequest::new(vec![owned_output(1)]).unwrap();
    let outcome = ring.submit_outcome(request).unwrap();

    assert!(matches!(outcome, SubmitOutcome::Submitted(_)));
}

#[test]
fn rng_submit_can_complete_synchronously_with_valid_bytes() {
    let mut ring = RngRing::new(1).unwrap();
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let outcome = ring
        .submit_with_immediate_fill(request, Some(&[1, 2, 3]))
        .unwrap();

    let completed = match outcome {
        SubmitOutcome::Completed(completed) => completed,
        SubmitOutcome::Submitted(_) => panic!("valid immediate bytes should complete"),
    };
    let (completion, returned) = completed.into_parts();
    assert_eq!(
        completion,
        CompletionInfo::new(
            OperationResult::Ok,
            vec![ResourceResult::Returned],
            RngCompletionPayload::new(3)
        )
    );
    assert_eq!(returned.into_inner().into_bytes(), vec![1, 2, 3, 0]);
    assert_eq!(ring.depth(), 1);
}

#[test]
fn rng_submit_keeps_request_submitted_when_immediate_bytes_are_unavailable() {
    let mut ring = RngRing::new(1).unwrap();
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let outcome = ring.submit_with_immediate_fill(request, Some(&[])).unwrap();

    let submitted = match outcome {
        SubmitOutcome::Submitted(submitted) => submitted,
        SubmitOutcome::Completed(_) => panic!("zero-byte success must not complete"),
    };
    let mut request = submitted.cleanup().unwrap().into_parts().2;
    assert_eq!(request.capacity(), 4);
}

#[test]
fn rng_notification_can_cover_multiple_visible_completions() {
    let ring = RngRing::new(2).unwrap();
    let notifier = TestNotifier::default();

    assert_eq!(ring.notify_completion(&notifier), Ok(IrqAccepted));
    assert_eq!(notifier.calls.get(), 1);
}

#[test]
fn rng_runtime_reports_reset_and_stopped_common_errors() {
    let mut runtime = RngRuntime::new(1).unwrap();
    let (reset_generation, reset_authority) = runtime.begin_reset().unwrap();
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let error = runtime.submit(request).unwrap_err();
    assert_eq!(error.error(), &OperationError::Common(CommonError::Reset));

    runtime
        .finish_reset(reset_generation, reset_authority)
        .unwrap();
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let error = runtime.submit(request).unwrap_err();
    assert_eq!(
        error.error(),
        &OperationError::Common(CommonError::NotReady)
    );

    runtime.stop();
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let error = runtime.submit(request).unwrap_err();
    assert_eq!(error.error(), &OperationError::Common(CommonError::Stopped));
}

#[test]
fn rng_runtime_topology_is_stable_until_reset_or_stop() {
    let mut runtime = RngRuntime::new(4).unwrap();

    assert_eq!(runtime.depth(), 4);

    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let _submitted = runtime.submit(request).unwrap();
    assert_eq!(runtime.depth(), 4);
}

#[test]
fn rng_reset_returns_submitted_buffer_and_stop_discards_completed_slot() {
    let mut ring = RngRing::new(1).unwrap();
    let request = RngFillRequest::new(vec![owned_output(4)]).unwrap();
    let submitted = ring.submit(request).unwrap();
    let (free, completion, returned) = resolve_submitted_rng_reset(submitted).unwrap();

    assert_eq!(free.index(), 0);
    assert_eq!(
        completion,
        CompletionInfo::new(
            OperationResult::Error(OperationError::Common(CommonError::Reset)),
            vec![ResourceResult::Returned],
            RngCompletionPayload::new(0)
        )
    );
    assert_eq!(returned.into_inner().into_bytes(), vec![0, 0, 0, 0]);

    let submitted = RingSlot::new(0)
        .prepare(RngFillRequest::new(vec![owned_output(2)]).unwrap().submit())
        .submit();
    let completion = CompletionInfo::new(
        OperationResult::Error(OperationError::Common(CommonError::Stopped)),
        vec![ResourceResult::Returned],
        RngCompletionPayload::new(0),
    );
    let completed = submitted.complete(completion);
    let free = discard_completed_rng_for_stop(completed).unwrap();
    assert_eq!(free.index(), 0);
}
