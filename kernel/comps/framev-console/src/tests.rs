use alloc::{vec, vec::Vec};
use core::cell::Cell;

use framev_device::{
    CommonError, CompletionInfo, FrameVDeviceType, IrqAccepted, IrqDelivery, IrqLine, IrqTarget,
    OperationError, OperationResult, OwnedResource, PollOutcome, ResourceResult, RingSlot,
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

fn owned_buffer(bytes: &[u8]) -> OwnedResource<ConsoleByteBuffer> {
    OwnedResource::new(ConsoleByteBuffer::new(bytes.to_vec()).unwrap())
}

#[test]
fn console_metadata_uses_common_descriptor_model() {
    let info = default_device_info();

    assert_eq!(info.id, well_known::DEFAULT_CONSOLE_DEVICE_ID);
    assert_eq!(info.device_type, FrameVDeviceType::Console);
    assert_eq!(info.irq_line, DEFAULT_IRQ_LINE);
}

#[test]
fn console_defines_two_directional_rings() {
    assert_eq!(RING_COUNT, 2);
    assert_eq!(
        ConsoleRingDirection::FrontendToBackendOutput.request_direction(),
        ConsoleDirection::Output
    );
    assert_eq!(
        ConsoleRingDirection::BackendToFrontendInput.request_direction(),
        ConsoleDirection::Input
    );
    assert_eq!(DEFAULT_NOTIFICATION_TARGET, IrqTarget::Untargeted);
}

#[test]
fn console_request_requires_exactly_one_nonempty_byte_buffer() {
    assert_eq!(
        ConsoleByteBuffer::new(Vec::new()).unwrap_err(),
        ConsoleError::EmptyBuffer
    );
    assert_eq!(
        ConsoleRequest::new(ConsoleDirection::Output, Vec::new()).unwrap_err(),
        ConsoleError::InvalidRequest
    );
    assert_eq!(
        ConsoleRequest::new(
            ConsoleDirection::Output,
            vec![owned_buffer(b"a"), owned_buffer(b"b")]
        )
        .unwrap_err(),
        ConsoleError::InvalidRequest
    );

    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    assert_eq!(request.direction(), ConsoleDirection::Output);
}

#[test]
fn submitted_console_buffer_is_read_only_and_consumed_on_success() {
    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let submitted = request.submit();

    assert_eq!(submitted.bytes(), b"abc");
    assert_eq!(
        submitted.complete_success(),
        CompletionInfo::new(OperationResult::Ok, vec![ResourceResult::Consumed], ())
    );
}

#[test]
fn failed_console_request_returns_buffer() {
    let request = ConsoleRequest::new(ConsoleDirection::Input, vec![owned_buffer(b"abc")]).unwrap();
    let submitted = request.submit();
    let (completion, returned) =
        submitted.complete_error(OperationError::Device(ConsoleError::InvalidRequest));

    assert_eq!(
        completion,
        CompletionInfo::new(
            OperationResult::Error(OperationError::Device(ConsoleError::InvalidRequest)),
            vec![ResourceResult::Returned],
            ()
        )
    );
    assert_eq!(returned.into_inner().into_bytes(), b"abc");
}

#[test]
fn input_ring_full_keeps_backend_buffer_ownership() {
    let mut ring = ConsoleRing::new(ConsoleRingDirection::BackendToFrontendInput, 0);
    let request = ConsoleRequest::new(ConsoleDirection::Input, vec![owned_buffer(b"abc")]).unwrap();
    let error = ring.submit(request).unwrap_err();

    assert_eq!(error.error(), &OperationError::Common(CommonError::Full));
    let request = error.into_request();
    let submitted = request.submit();
    assert_eq!(submitted.bytes(), b"abc");
}

#[test]
fn console_ring_rejects_wrong_direction_without_publishing() {
    let mut ring = ConsoleRing::new(ConsoleRingDirection::FrontendToBackendOutput, 1);
    let request = ConsoleRequest::new(ConsoleDirection::Input, vec![owned_buffer(b"abc")]).unwrap();
    let error = ring.submit(request).unwrap_err();

    assert_eq!(
        error.error(),
        &OperationError::Device(ConsoleError::WrongDirection)
    );
    assert_eq!(ring.free_len(), 1);
}

#[test]
fn receiver_backpressure_keeps_console_request_submitted() {
    let mut ring = ConsoleRing::new(ConsoleRingDirection::FrontendToBackendOutput, 1);
    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let submitted = ring.submit(request).unwrap();

    let submitted = match ring.complete_when_accepted(submitted, false) {
        PollOutcome::Pending(submitted) => submitted,
        PollOutcome::Completed(_) => panic!("slot must remain submitted under backpressure"),
    };
    assert_eq!(submitted.request().unwrap().bytes(), b"abc");

    let completed = match ring.complete_when_accepted(submitted, true) {
        PollOutcome::Completed(completed) => completed,
        PollOutcome::Pending(_) => panic!("slot should complete once all bytes are accepted"),
    };
    assert_eq!(
        completed.completion().unwrap(),
        &CompletionInfo::new(OperationResult::Ok, vec![ResourceResult::Consumed], ())
    );
}

#[test]
fn input_publication_uses_common_payload_free_notification() {
    let mut ring = ConsoleRing::new(ConsoleRingDirection::BackendToFrontendInput, 1);
    let request = ConsoleRequest::new(ConsoleDirection::Input, vec![owned_buffer(b"abc")]).unwrap();
    let notifier = TestNotifier::default();

    let (submitted, notification) = ring.submit_input_and_notify(request, &notifier).unwrap();

    assert_eq!(submitted.request().unwrap().bytes(), b"abc");
    assert_eq!(notification, Ok(IrqAccepted));
    assert_eq!(notifier.calls.get(), 1);
}

#[test]
fn completion_notification_happens_after_completion_state_exists() {
    let mut ring = ConsoleRing::new(ConsoleRingDirection::FrontendToBackendOutput, 1);
    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let submitted = ring.submit(request).unwrap();
    let completed = ring.complete_success(submitted);
    assert_eq!(
        completed.completion().unwrap(),
        &CompletionInfo::new(OperationResult::Ok, vec![ResourceResult::Consumed], ())
    );

    let notifier = TestNotifier::default();
    assert_eq!(ring.notify_completion(&notifier), Ok(IrqAccepted));
    assert_eq!(notifier.calls.get(), 1);
}

#[test]
fn console_runtime_reports_reset_and_stopped_common_errors() {
    let mut runtime = ConsoleRuntime::new(1, 1).unwrap();
    let (reset_generation, reset_authority) = runtime.begin_reset().unwrap();
    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let error = runtime.submit_output(request).unwrap_err();
    assert_eq!(error.error(), &OperationError::Common(CommonError::Reset));

    runtime
        .finish_reset(reset_generation, reset_authority)
        .unwrap();
    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let error = runtime.submit_output(request).unwrap_err();
    assert_eq!(
        error.error(),
        &OperationError::Common(CommonError::NotReady)
    );

    runtime.stop();
    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let error = runtime.submit_output(request).unwrap_err();
    assert_eq!(error.error(), &OperationError::Common(CommonError::Stopped));
}

#[test]
fn console_runtime_topology_is_stable_until_reset_or_stop() {
    let mut runtime = ConsoleRuntime::new(4, 8).unwrap();

    assert_eq!(runtime.output_depth(), 4);
    assert_eq!(runtime.input_depth(), 8);

    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let _submitted = runtime.submit_output(request).unwrap();
    assert_eq!(runtime.output_depth(), 4);
    assert_eq!(runtime.input_depth(), 8);
}

#[test]
fn console_reset_returns_submitted_buffer_and_stop_discards_completed_slot() {
    let mut ring = ConsoleRing::new(ConsoleRingDirection::FrontendToBackendOutput, 1);
    let request =
        ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"abc")]).unwrap();
    let submitted = ring.submit(request).unwrap();
    let (free, completion, returned) = resolve_submitted_console_reset(submitted).unwrap();

    assert_eq!(free.index(), 0);
    assert_eq!(
        completion,
        CompletionInfo::new(
            OperationResult::Error(OperationError::Common(CommonError::Reset)),
            vec![ResourceResult::Returned],
            ()
        )
    );
    assert_eq!(returned.into_inner().into_bytes(), b"abc");

    let submitted = RingSlot::new(0)
        .prepare(
            ConsoleRequest::new(ConsoleDirection::Output, vec![owned_buffer(b"def")])
                .unwrap()
                .submit(),
        )
        .submit();
    let completed = ring.complete_success(submitted);
    let free = discard_completed_console_for_stop(completed).unwrap();
    assert_eq!(free.index(), 0);
}
