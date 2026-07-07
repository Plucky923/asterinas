// SPDX-License-Identifier: MPL-2.0

//! FrameV devices owned by one `FrameVm`.

use alloc::{sync::Arc, vec::Vec};

use framev_device::{
    FrameVDevice, FrameVDeviceDescriptor, FrameVDeviceError, FrameVDeviceInfo, FrameVDeviceType,
    IrqAccepted, IrqDelivery, IrqLine, IrqTarget,
};

use crate::{
    Error, Result, iht,
    irq::FrameVVirtualIrqState,
    irq_routing::{FrameVmIrqNotification, FrameVmIrqRouting, VcpuIrqLoad},
    vm::VmId,
};

mod block;
mod console;
mod rng;
mod sock;
mod state;

pub use self::{
    block::{
        Block, BlockImage, BlockImageError, BlockRequestCompletion, BlockRequestResource,
        BlockReturnedResource,
    },
    console::Console,
    rng::Rng,
    sock::Sock,
};

/// Host-side FrameV device subsystem for one `FrameVm`.
pub struct Devices {
    descriptor: FrameVDeviceDescriptor,
    console: Console,
    sock: Sock,
    rng: Rng,
    block: Option<Block>,
    routing: FrameVmIrqRouting,
    irq_runtime: Arc<FrameVVirtualIrqState>,
}

impl Devices {
    /// Creates the current default FrameV device set.
    pub fn new(vm_id: VmId, vcpu_count: usize) -> Result<Self> {
        Self::new_with_optional_block(vm_id, vcpu_count, None)
    }

    /// Creates the default FrameV device set plus one optional block backend.
    pub fn new_with_block_image(
        vm_id: VmId,
        vcpu_count: usize,
        image: Arc<dyn BlockImage>,
    ) -> Result<Self> {
        Self::new_with_optional_block(vm_id, vcpu_count, Some(image))
    }

    fn new_with_optional_block(
        vm_id: VmId,
        vcpu_count: usize,
        block_image: Option<Arc<dyn BlockImage>>,
    ) -> Result<Self> {
        let required_device_infos = required_device_infos();
        let mut device_infos = required_device_infos.clone();
        if block_image.is_some() {
            device_infos.push(framev_blk_common::default_device_info());
        }
        let descriptor = FrameVDeviceDescriptor::new(device_infos.clone())?;
        validate_device_descriptor_shape(
            &descriptor,
            &required_device_infos,
            block_image.is_some(),
        )?;

        let console = Console::new(
            device_info(&device_infos, FrameVDeviceType::Console)?,
            vm_id,
            vcpu_count,
        );
        let sock = Sock::new(
            device_info(&device_infos, FrameVDeviceType::Sock)?,
            vcpu_count,
        );
        let rng = Rng::new(device_info(&device_infos, FrameVDeviceType::Rng)?);
        let block = match block_image {
            Some(image) => Some(Block::new(
                device_info(&device_infos, FrameVDeviceType::Block)?,
                image,
            )?),
            None => None,
        };
        let routing = FrameVmIrqRouting::new(&device_infos, vcpu_count)?;
        let devices = Self {
            console,
            sock,
            rng,
            block,
            routing,
            irq_runtime: Arc::new(FrameVVirtualIrqState::new()),
            descriptor,
        };
        Ok(devices)
    }

    /// Returns the typed console backend handle.
    pub fn console(&self) -> &Console {
        &self.console
    }

    /// Returns the typed sock backend handle.
    pub fn sock(&self) -> &Sock {
        &self.sock
    }

    /// Returns the typed RNG backend handle.
    pub fn rng(&self) -> &Rng {
        &self.rng
    }

    /// Returns the optional typed block backend handle.
    pub fn block(&self) -> Option<&Block> {
        self.block.as_ref()
    }

    /// Returns the boot-time FrameV descriptor.
    pub(crate) fn descriptor(&self) -> FrameVDeviceDescriptor {
        self.descriptor.clone()
    }

    /// Returns the VM-owned virtual IRQ runtime.
    pub(crate) fn irq_runtime(&self) -> &Arc<FrameVVirtualIrqState> {
        &self.irq_runtime
    }

    /// Resets all device state before starting IHT.
    pub(crate) fn reset_for_start(&self) {
        self.console.reset();
        self.sock.reset();
        self.rng.reset();
        if let Some(block) = &self.block {
            block.reset();
        }
        self.routing.clear_pending_all();
    }

    /// Marks the current default device set ready.
    pub(crate) fn mark_ready_all(&self) -> Result<()> {
        self.console.mark_ready()?;
        self.sock.mark_ready()?;
        self.rng.mark_ready()?;
        if let Some(block) = &self.block {
            block.mark_ready()?;
        }
        Ok(())
    }

    /// Stops all devices and clears delivery/runtime state.
    pub(crate) fn stop_all(&self) {
        self.console.stop();
        self.sock.stop();
        self.rng.stop();
        if let Some(block) = &self.block {
            block.stop();
        }
        self.routing.clear_pending_all();
        self.irq_runtime.clear();
    }

    /// Clears one dispatched FrameV IRQ request.
    pub(crate) fn clear_dispatched_irq(&self, irq_line: IrqLine, target_vcpu: usize) -> Result<()> {
        self.routing.clear_pending(irq_line, target_vcpu)?;
        Ok(())
    }

    /// Dispatches a FrameV IRQ after IHT has selected work for this VM.
    pub(crate) fn dispatch_irq(&self, irq_line: IrqLine, target_vcpu: usize) {
        if self.clear_dispatched_irq(irq_line, target_vcpu).is_ok() {
            self.irq_runtime.dispatch(irq_line);
        }
    }

    /// Notifies the frontend for RNG work.
    pub(crate) fn notify_rng<F>(
        &self,
        vm_id: VmId,
        vm_running: bool,
        load_of: F,
    ) -> Result<IrqAccepted>
    where
        F: Fn(usize) -> Option<VcpuIrqLoad>,
    {
        self.notify_device(&self.rng, vm_id, vm_running, IrqTarget::Untargeted, load_of)
    }

    /// Notifies the frontend for one sock queue.
    pub(crate) fn notify_sock_rx<F>(
        &self,
        vm_id: VmId,
        vm_running: bool,
        target_vcpu: usize,
        load_of: F,
    ) -> Result<IrqAccepted>
    where
        F: Fn(usize) -> Option<VcpuIrqLoad>,
    {
        self.notify_device(
            &self.sock,
            vm_id,
            vm_running,
            IrqTarget::Vcpu(target_vcpu),
            load_of,
        )
    }

    fn notify_device<D, F>(
        &self,
        device: &D,
        vm_id: VmId,
        vm_running: bool,
        target: IrqTarget,
        load_of: F,
    ) -> Result<IrqAccepted>
    where
        D: FrameVDevice,
        F: Fn(usize) -> Option<VcpuIrqLoad>,
    {
        let delivery = DevicesDelivery {
            devices: self,
            vm_id,
            vm_running,
            load_of,
        };
        device.notify(&delivery, target)
    }

    fn route_irq<F>(
        &self,
        vm_id: VmId,
        vm_running: bool,
        irq_line: IrqLine,
        target: IrqTarget,
        load_of: F,
    ) -> Result<FrameVmIrqNotification>
    where
        F: Fn(usize) -> Option<VcpuIrqLoad>,
    {
        if !vm_running {
            return Err(Error::InvalidArgs);
        }

        let notification = match target {
            IrqTarget::Untargeted => self.routing.notify_irq_line(irq_line, load_of)?,
            IrqTarget::Vcpu(target_vcpu) => {
                self.routing
                    .notify_irq_line_on_vcpu(irq_line, target_vcpu, load_of)?
            }
        };

        if notification.coalesced {
            return Ok(notification);
        }

        if let Err(error) = iht::enqueue_virtual_irq(vm_id, notification.target_vcpu, irq_line) {
            let _ = self
                .routing
                .clear_pending(notification.irq_line, notification.target_vcpu);
            return Err(error);
        }

        Ok(notification)
    }
}

/// Returns the current service VM's optional FrameV-blk configuration.
pub fn current_block_config() -> Result<framev_blk_common::FrameVBlkConfig> {
    with_current_block(|block| Ok(block.config()))
}

/// Submits one request to the current service VM's optional FrameV-blk backend.
///
/// This is a service-runnable data-path hook. Callers must invoke it from the
/// FrameVM service runtime, not from IHT notification/control callbacks.
pub fn submit_current_block_request(
    header: framev_blk_common::FrameVBlkRequestHeader,
    resource: BlockRequestResource,
) -> Result<BlockRequestCompletion> {
    with_current_block(|block| block.submit_request(header, resource))
}

fn with_current_block<T>(f: impl FnOnce(&Block) -> Result<T>) -> Result<T> {
    let frame_vcpu_id = crate::task::current_frame_vcpu_id().ok_or(Error::InvalidArgs)?;
    let vm = crate::vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(Error::InvalidArgs)?;
    let block = vm.devices().block().ok_or(Error::InvalidArgs)?;
    f(block)
}

struct DevicesDelivery<'a, F>
where
    F: Fn(usize) -> Option<VcpuIrqLoad>,
{
    devices: &'a Devices,
    vm_id: VmId,
    vm_running: bool,
    load_of: F,
}

impl<F> IrqDelivery for DevicesDelivery<'_, F>
where
    F: Fn(usize) -> Option<VcpuIrqLoad>,
{
    type Error = Error;

    fn notify_irq(&self, irq_line: IrqLine, target: IrqTarget) -> Result<IrqAccepted> {
        self.devices
            .route_irq(self.vm_id, self.vm_running, irq_line, target, |vcpu_id| {
                (self.load_of)(vcpu_id)
            })?;
        Ok(IrqAccepted)
    }
}

fn required_device_infos() -> Vec<FrameVDeviceInfo> {
    Vec::from([
        framev_console_common::default_device_info(),
        framev_sock_common::default_device_info(),
        framev_rng_common::default_device_info(),
    ])
}

fn validate_required_devices(
    descriptor: &FrameVDeviceDescriptor,
    required: &[FrameVDeviceInfo],
) -> Result<()> {
    for required_device in required {
        if descriptor.find_by_id(required_device.id).copied() != Some(*required_device) {
            return Err(Error::InvalidArgs);
        }
        if descriptor
            .devices()
            .iter()
            .filter(|device| device.device_type == required_device.device_type)
            .count()
            != 1
        {
            return Err(Error::InvalidArgs);
        }
    }
    Ok(())
}

fn validate_device_descriptor_shape(
    descriptor: &FrameVDeviceDescriptor,
    required: &[FrameVDeviceInfo],
    block_backend_present: bool,
) -> Result<()> {
    validate_required_devices(descriptor, required)?;

    let mut block_count = 0;
    for device in descriptor.devices() {
        if required.iter().any(|required| required.id == device.id) {
            continue;
        }

        match device.device_type {
            FrameVDeviceType::Block => block_count += 1,
            FrameVDeviceType::Console
            | FrameVDeviceType::Net
            | FrameVDeviceType::Rng
            | FrameVDeviceType::Sock => return Err(Error::InvalidArgs),
        }
    }

    if block_count != usize::from(block_backend_present) {
        return Err(Error::InvalidArgs);
    }
    Ok(())
}

fn device_info(
    devices: &[FrameVDeviceInfo],
    device_type: FrameVDeviceType,
) -> framev_device::Result<FrameVDeviceInfo> {
    devices
        .iter()
        .copied()
        .find(|device| device.device_type == device_type)
        .ok_or(FrameVDeviceError::MissingRequiredDevice(device_type))
}

#[cfg(ktest)]
mod tests {
    use framev_device::DeviceStatus;
    use host_ostd::prelude::ktest;

    use super::*;
    use crate::vm::{DEFAULT_FRAMEVM_SHARE, FrameVm};

    struct TestBlockImage;

    impl BlockImage for TestBlockImage {
        fn read_exact_at(
            &self,
            _offset_bytes: u64,
            dst: &mut [u8],
        ) -> core::result::Result<(), BlockImageError> {
            dst.fill(0);
            Ok(())
        }

        fn write_all_at(
            &self,
            _offset_bytes: u64,
            _src: &[u8],
        ) -> core::result::Result<(), BlockImageError> {
            Ok(())
        }

        fn flush(&self) -> core::result::Result<(), BlockImageError> {
            Ok(())
        }

        fn capacity_bytes(&self) -> u64 {
            4096
        }

        fn readonly(&self) -> bool {
            false
        }
    }

    fn runnable_load(_: usize) -> Option<VcpuIrqLoad> {
        Some(VcpuIrqLoad {
            online: true,
            runnable: true,
            virtual_interrupts_enabled: true,
            pending_work: 0,
        })
    }

    fn has_device_type(descriptor: &FrameVDeviceDescriptor, device_type: FrameVDeviceType) -> bool {
        descriptor
            .devices()
            .iter()
            .any(|device| device.device_type == device_type)
    }

    fn optional_device(id: u64, device_type: FrameVDeviceType, irq_line: u16) -> FrameVDeviceInfo {
        FrameVDeviceInfo::new(
            framev_device::FrameVDeviceId::new(id),
            device_type,
            IrqLine::new(irq_line),
        )
    }

    #[ktest]
    fn host_control_uses_typed_device_handles_without_device_ids() {
        let vm = FrameVm::new(17, 2, DEFAULT_FRAMEVM_SHARE, None).unwrap();
        let devices = vm.devices();

        assert_eq!(devices.console().inject_input(b"x").unwrap(), 1);
        assert!(devices.console().has_input());
        assert_eq!(devices.sock().queue_count(), 2);
        assert_eq!(devices.rng().info().device_type, FrameVDeviceType::Rng);
    }

    #[ktest]
    fn required_device_descriptor_boot_arg_roundtrips() {
        let devices = Devices::new(0, 2).unwrap();
        let encoded = devices.descriptor().encode_boot_arg();
        let decoded = FrameVDeviceDescriptor::decode_boot_arg(&encoded).unwrap();

        assert_eq!(decoded.devices().len(), 3);
        assert!(has_device_type(&decoded, FrameVDeviceType::Console));
        assert!(has_device_type(&decoded, FrameVDeviceType::Sock));
        assert!(has_device_type(&decoded, FrameVDeviceType::Rng));
        assert!(!has_device_type(&decoded, FrameVDeviceType::Block));
    }

    #[ktest]
    fn optional_block_device_descriptor_boot_arg_roundtrips() {
        let devices = Devices::new_with_block_image(0, 2, Arc::new(TestBlockImage)).unwrap();
        let encoded = devices.descriptor().encode_boot_arg();
        let decoded = FrameVDeviceDescriptor::decode_boot_arg(&encoded).unwrap();

        assert_eq!(decoded.devices().len(), 4);
        assert!(has_device_type(&decoded, FrameVDeviceType::Console));
        assert!(has_device_type(&decoded, FrameVDeviceType::Sock));
        assert!(has_device_type(&decoded, FrameVDeviceType::Rng));
        assert!(has_device_type(&decoded, FrameVDeviceType::Block));
    }

    #[ktest]
    fn descriptor_shape_rejects_missing_required_devices() {
        let required = required_device_infos();
        for missing_type in [
            FrameVDeviceType::Console,
            FrameVDeviceType::Sock,
            FrameVDeviceType::Rng,
        ] {
            let devices = required
                .iter()
                .copied()
                .filter(|device| device.device_type != missing_type)
                .collect();
            let descriptor = FrameVDeviceDescriptor::new(devices).unwrap();

            assert_eq!(
                validate_device_descriptor_shape(&descriptor, &required, false),
                Err(Error::InvalidArgs)
            );
        }
    }

    #[ktest]
    fn descriptor_shape_rejects_unsupported_optional_device() {
        let required = required_device_infos();
        let mut devices = required.clone();
        devices.push(optional_device(99, FrameVDeviceType::Net, 99));
        let descriptor = FrameVDeviceDescriptor::new(devices).unwrap();

        assert_eq!(
            validate_device_descriptor_shape(&descriptor, &required, false),
            Err(Error::InvalidArgs)
        );
    }

    #[ktest]
    fn descriptor_shape_rejects_multiple_block_devices() {
        let required = required_device_infos();
        let mut devices = required.clone();
        devices.push(optional_device(40, FrameVDeviceType::Block, 40));
        devices.push(optional_device(41, FrameVDeviceType::Block, 41));
        let descriptor = FrameVDeviceDescriptor::new(devices).unwrap();

        assert_eq!(
            validate_device_descriptor_shape(&descriptor, &required, true),
            Err(Error::InvalidArgs)
        );
    }

    #[ktest]
    fn enqueue_failure_rolls_back_delivery_pending_state() {
        let devices = Devices::new(0, 1).unwrap();
        let irq_line = devices.rng().info().irq_line;

        let result = devices.notify_rng(99, true, runnable_load);

        assert_eq!(result, Err(Error::InvalidArgs));
        assert!(!devices.routing.is_pending(irq_line));
    }

    #[ktest]
    fn reset_cleans_delivery_pending_and_typed_device_state() {
        let devices = Devices::new(0, 1).unwrap();
        devices.mark_ready_all().unwrap();
        let notification = devices
            .routing
            .notify_irq_line(devices.rng().info().irq_line, runnable_load)
            .unwrap();

        assert!(devices.routing.is_pending(notification.irq_line));
        assert_eq!(devices.rng().status(), DeviceStatus::Ready);

        devices.reset_for_start();

        assert!(!devices.routing.is_pending(notification.irq_line));
        assert_eq!(devices.console().status(), DeviceStatus::Init);
        assert_eq!(devices.sock().status(), DeviceStatus::Init);
        assert_eq!(devices.rng().status(), DeviceStatus::Init);
    }

    #[ktest]
    fn stop_cleans_delivery_pending_and_stops_typed_devices() {
        let devices = Devices::new(0, 1).unwrap();
        devices.mark_ready_all().unwrap();
        let notification = devices
            .routing
            .notify_irq_line(devices.sock().info().irq_line, runnable_load)
            .unwrap();

        assert!(devices.routing.is_pending(notification.irq_line));

        devices.stop_all();

        assert!(!devices.routing.is_pending(notification.irq_line));
        assert_eq!(devices.console().status(), DeviceStatus::Stopped);
        assert_eq!(devices.sock().status(), DeviceStatus::Stopped);
        assert_eq!(devices.rng().status(), DeviceStatus::Stopped);
    }
}
