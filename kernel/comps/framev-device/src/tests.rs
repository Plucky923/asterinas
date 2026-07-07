use alloc::{format, vec, vec::Vec};
use core::cell::Cell;

use crate::*;

struct TestNotifier {
    result: core::result::Result<IrqAccepted, CommonError>,
    calls: Cell<usize>,
}

impl TestNotifier {
    const fn new(result: core::result::Result<IrqAccepted, CommonError>) -> Self {
        Self {
            result,
            calls: Cell::new(0),
        }
    }
}

impl IrqDelivery for TestNotifier {
    type Error = CommonError;

    fn notify_irq(
        &self,
        irq_line: IrqLine,
        target: IrqTarget,
    ) -> core::result::Result<IrqAccepted, CommonError> {
        assert_eq!(irq_line, IrqLine::new(1));
        assert!(matches!(target, IrqTarget::Untargeted | IrqTarget::Vcpu(_)));
        self.calls.set(self.calls.get() + 1);
        self.result
    }
}

fn device(id: u64, irq_line: u16) -> FrameVDeviceInfo {
    FrameVDeviceInfo::new(
        FrameVDeviceId::new(id),
        FrameVDeviceType::Console,
        IrqLine::new(irq_line),
    )
}

#[test]
fn descriptor_rejects_reserved_irq_line() {
    let error = FrameVDeviceDescriptor::new(vec![device(1, 0)]).unwrap_err();
    assert_eq!(error, FrameVDeviceError::ReservedIrqLine);
}

#[test]
fn descriptor_rejects_duplicate_device_id() {
    let error = FrameVDeviceDescriptor::new(vec![device(1, 1), device(1, 2)]).unwrap_err();
    assert_eq!(
        error,
        FrameVDeviceError::DuplicateDeviceId(FrameVDeviceId::new(1))
    );
}

#[test]
fn descriptor_rejects_duplicate_irq_line() {
    let error = FrameVDeviceDescriptor::new(vec![device(1, 1), device(2, 1)]).unwrap_err();
    assert_eq!(error, FrameVDeviceError::DuplicateIrqLine(IrqLine::new(1)));
}

#[test]
fn descriptor_accepts_exact_required_devices() {
    let required = vec![
        device(1, 1),
        FrameVDeviceInfo::new(
            FrameVDeviceId::new(3),
            FrameVDeviceType::Rng,
            IrqLine::new(2),
        ),
    ];
    let descriptor = FrameVDeviceDescriptor::new(required.clone()).unwrap();

    assert_eq!(descriptor.validate_required_exact(&required), Ok(()));
}

#[test]
fn descriptor_rejects_missing_required_device() {
    let required = vec![
        device(1, 1),
        FrameVDeviceInfo::new(
            FrameVDeviceId::new(3),
            FrameVDeviceType::Rng,
            IrqLine::new(2),
        ),
    ];
    let descriptor = FrameVDeviceDescriptor::new(vec![device(1, 1)]).unwrap();

    let error = descriptor.validate_required_exact(&required).unwrap_err();
    assert_eq!(
        error,
        FrameVDeviceError::UnexpectedDeviceCount {
            expected: 2,
            actual: 1,
        }
    );
}

#[test]
fn descriptor_rejects_required_device_mismatch() {
    let required = vec![device(1, 1)];
    let actual = FrameVDeviceInfo::new(
        FrameVDeviceId::new(1),
        FrameVDeviceType::Rng,
        IrqLine::new(1),
    );
    let descriptor = FrameVDeviceDescriptor::new(vec![actual]).unwrap();

    let error = descriptor.validate_required_exact(&required).unwrap_err();
    assert_eq!(
        error,
        FrameVDeviceError::RequiredDeviceMismatch {
            expected: required[0],
            actual,
        }
    );
}

#[test]
fn required_device_mismatch_display_names_expected_and_actual_devices() {
    let expected = device(1, 1);
    let actual = FrameVDeviceInfo::new(
        FrameVDeviceId::new(4),
        FrameVDeviceType::Rng,
        IrqLine::new(7),
    );
    let error = FrameVDeviceError::RequiredDeviceMismatch { expected, actual };

    assert_eq!(
        format!("{error}"),
        "required FrameV console device mismatch: expected id=1, irq=1; actual id=4, type=rng, irq=7"
    );
}

#[test]
fn descriptor_boot_arg_roundtrips() {
    let descriptor = FrameVDeviceDescriptor::new(vec![
        FrameVDeviceInfo::new(
            FrameVDeviceId::new(1),
            FrameVDeviceType::Console,
            IrqLine::new(1),
        ),
        FrameVDeviceInfo::new(
            FrameVDeviceId::new(2),
            FrameVDeviceType::Sock,
            IrqLine::new(2),
        ),
    ])
    .unwrap();

    let encoded = descriptor.encode_boot_arg();
    assert_eq!(encoded, "1:console:1,2:sock:2");
    assert_eq!(
        FrameVDeviceDescriptor::decode_boot_arg(&encoded).unwrap(),
        descriptor
    );
}

#[test]
fn descriptor_boot_arg_rejects_invalid_device_type() {
    let error = FrameVDeviceDescriptor::decode_boot_arg("1:unknown:1").unwrap_err();
    assert_eq!(error, FrameVDeviceError::InvalidDeviceType);
}

#[test]
fn descriptor_boot_arg_rejects_previous_five_field_shape() {
    let error = FrameVDeviceDescriptor::decode_boot_arg("1:console:1:1:0").unwrap_err();
    assert_eq!(error, FrameVDeviceError::InvalidDescriptorEncoding);
}

#[test]
fn well_known_device_ids_are_fixed() {
    assert_eq!(well_known::DEFAULT_CONSOLE_DEVICE_ID.raw(), 1);
    assert_eq!(well_known::DEFAULT_SOCK_DEVICE_ID.raw(), 2);
    assert_eq!(well_known::DEFAULT_RNG_DEVICE_ID.raw(), 3);
    assert_eq!(well_known::DEFAULT_BLOCK_DEVICE_ID.raw(), 4);
    assert_eq!(well_known::DEFAULT_NET_DEVICE_ID.raw(), 5);
}

#[test]
fn lifecycle_uses_init_ready_and_stopped() {
    let mut state = DeviceState::new();

    assert_eq!(state.status(), DeviceStatus::Init);
    assert_eq!(state.ensure_ready(), Err(CommonError::NotReady));

    state.set_status(DeviceStatus::Ready).unwrap();
    assert_eq!(state.ensure_ready(), Ok(()));

    state.reset();
    assert_eq!(state.status(), DeviceStatus::Init);

    state.set_status(DeviceStatus::Stopped).unwrap();
    assert_eq!(state.ensure_ready(), Err(CommonError::Stopped));
    assert_eq!(
        state.set_status(DeviceStatus::Ready),
        Err(FrameVDeviceError::Stopped)
    );
}

#[test]
fn device_state_contains_only_lifecycle_and_generation() {
    let mut state = DeviceState::new();
    let generation = state.generation();

    state.set_status(DeviceStatus::Ready).unwrap();
    state.reset();

    assert_eq!(state.status(), DeviceStatus::Init);
    assert_eq!(state.generation(), generation + 1);
}

#[test]
fn reset_barrier_rejects_normal_data_path_until_cleanup_finishes() {
    let mut state = DeviceState::new();
    state.set_status(DeviceStatus::Ready).unwrap();

    let generation = state.generation();
    let (reset_generation, authority) = state.begin_reset().unwrap();
    assert_eq!(state.ensure_ready(), Err(CommonError::Reset));
    assert_eq!(reset_generation, generation);

    state.finish_reset(reset_generation, authority).unwrap();
    assert_eq!(state.status(), DeviceStatus::Init);
    assert_eq!(state.ensure_ready(), Err(CommonError::NotReady));
    assert_eq!(state.generation(), generation + 1);
}

#[test]
fn stop_is_terminal() {
    let mut state = DeviceState::new();
    state.set_status(DeviceStatus::Ready).unwrap();

    state.stop();
    assert_eq!(state.status(), DeviceStatus::Stopped);
    assert_eq!(
        state.set_status(DeviceStatus::Init),
        Err(FrameVDeviceError::Stopped)
    );
}

#[test]
fn resource_typestate_returns_or_consumes_submitted_resource() {
    let resource = OwnedResource::new(vec![1, 2, 3]);
    let submitted = resource.submit::<ReadOnly>();
    assert_eq!(submitted.get(), &[1, 2, 3]);

    let returned = submitted.return_to_owner();
    let resource = returned.reclaim();
    assert_eq!(resource.into_inner(), vec![1, 2, 3]);

    let _consumed = OwnedResource::new(vec![4]).submit::<Consume>().consume();
}

#[test]
fn ring_slot_typestate_submits_completes_and_reclaims() {
    let free = RingSlot::new(7);
    let submitted = free.prepare("request").submit();
    assert_eq!(submitted.index(), 7);
    assert_eq!(submitted.request().unwrap(), &"request");

    let completed = submitted.complete("done");
    assert_eq!(completed.completion().unwrap(), &"done");

    let (free, request, completion) = completed.reclaim().unwrap().into_parts();
    assert_eq!(free.index(), 7);
    assert_eq!(request, "request");
    assert_eq!(completion, "done");
}

#[test]
fn ring_slot_cleanup_drains_submitted_and_completed_slots() {
    let submitted = RingSlot::new(1).prepare("request").submit();
    let (free, state, request, completion) = submitted.cleanup().unwrap().into_parts();
    assert_eq!(free.index(), 1);
    assert_eq!(state, CleanupState::Submitted);
    assert_eq!(request, "request");
    assert_eq!(completion, None::<()>);

    let submitted = RingSlot::new(2).prepare("request").submit();
    let completed = submitted.complete("completion");
    let (free, state, request, completion) = completed.cleanup().unwrap().into_parts();
    assert_eq!(free.index(), 2);
    assert_eq!(state, CleanupState::Completed);
    assert_eq!(request, "request");
    assert_eq!(completion, Some("completion"));
}

#[test]
fn notification_publication_preserves_state_on_delivery_failure() {
    let notifier = TestNotifier::new(Err(CommonError::Stopped));
    let state = "completion-visible";
    let notification = notifier.notify_irq(IrqLine::new(1), IrqTarget::Vcpu(1));

    assert_eq!(state, "completion-visible");
    assert_eq!(notification, Err(CommonError::Stopped));
    assert_eq!(notifier.calls.get(), 1);
}

#[test]
fn notification_publication_is_payload_free_and_targeted_by_policy() {
    let notifier = TestNotifier::new(Ok(IrqAccepted));
    let state = vec!["slot-a", "slot-b"];
    let notification = notifier.notify_irq(IrqLine::new(1), IrqTarget::Untargeted);

    assert_eq!(notification, Ok(IrqAccepted));
    assert_eq!(state, vec!["slot-a", "slot-b"]);
    assert_eq!(notifier.calls.get(), 1);
}

#[test]
fn ring_authorities_are_split_by_role() {
    let authorities = RingAuthorities::new();

    let _submitter = authorities.submitter();
    let _receiver = authorities.receiver();
    let _control = authorities.control();
}

#[test]
fn synchronous_dispatch_defers_recursive_same_ring_entry() {
    let dispatch = SynchronousDispatchState::new();
    let DispatchEnter::Entered(_guard) = dispatch.enter() else {
        panic!("first entry should run synchronously");
    };
    assert!(dispatch.is_active());

    assert!(matches!(dispatch.enter(), DispatchEnter::Deferred));
    assert!(dispatch.has_deferred_work());

    dispatch.clear_deferred_work();
    assert!(!dispatch.has_deferred_work());
}

#[test]
fn synchronous_dispatch_guard_releases_entry() {
    let dispatch = SynchronousDispatchState::new();
    {
        let DispatchEnter::Entered(_guard) = dispatch.enter() else {
            panic!("first entry should run synchronously");
        };
        assert!(dispatch.is_active());
    }

    assert!(!dispatch.is_active());
    assert!(matches!(dispatch.enter(), DispatchEnter::Entered(_)));
}

struct VecBatchObserver {
    completed: Vec<RingSlot<Completed, &'static str, &'static str>>,
}

impl BatchCompletionObserver<RingSlot<Completed, &'static str, &'static str>> for VecBatchObserver {
    fn observe_batch(
        &mut self,
        completed: &mut Vec<RingSlot<Completed, &'static str, &'static str>>,
    ) {
        completed.append(&mut self.completed);
    }
}

#[test]
fn batch_completion_observer_returns_typed_completed_states() {
    let completed = RingSlot::new(1)
        .prepare("request")
        .submit()
        .complete("done");
    let mut observer = VecBatchObserver {
        completed: vec![completed],
    };
    let mut observed = Vec::new();

    observer.observe_batch(&mut observed);

    let completed = observed.pop().unwrap();
    let (free, request, completion) = completed.reclaim().unwrap().into_parts();
    assert_eq!(free.index(), 1);
    assert_eq!(request, "request");
    assert_eq!(completion, "done");
}

#[test]
fn completion_info_keeps_common_results_and_device_payload() {
    let info = CompletionInfo::<_, ()>::new(
        OperationResult::Ok,
        vec![ResourceResult::Returned, ResourceResult::Consumed],
        16usize,
    );

    assert_eq!(info.operation(), &OperationResult::Ok);
    assert_eq!(
        info.resource_results(),
        &[ResourceResult::Returned, ResourceResult::Consumed]
    );
    assert_eq!(info.payload(), &16);
}

#[test]
fn completion_info_can_report_error_with_returned_resource() {
    let info = CompletionInfo::<(), ()>::new(
        OperationResult::Error(OperationError::Common(CommonError::InvalidResource)),
        vec![ResourceResult::Returned],
        (),
    );

    assert_eq!(
        info.operation(),
        &OperationResult::Error(OperationError::Common(CommonError::InvalidResource))
    );
    assert_eq!(info.resource_results(), &[ResourceResult::Returned]);
}
