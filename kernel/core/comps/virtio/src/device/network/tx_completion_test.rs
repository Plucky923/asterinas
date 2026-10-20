// SPDX-License-Identifier: MPL-2.0

use aster_pci::cfg_space::BarAccess;
use aster_util::safe_ptr::SafePtr;
use ostd::{
    io::IoMem,
    irq::IrqCallbackFunction,
    mm::{VmReader, dma::DmaCoherent},
    prelude::ktest,
};

use super::*;
use crate::{
    device::VirtioDeviceType,
    queue::{AvailRing, Descriptor, UsedRing},
    transport::{DeviceStatus, VirtioTransport, VirtioTransportError},
};

#[ktest]
fn completion_before_tx_callback_arm_restores_send_credit() {
    let mut transport = DeviceTransport::new(Box::new(ControlledTransport));
    let mut send_queue = VirtQueue::new(QUEUE_SEND, 1, transport.as_mut()).unwrap();
    send_queue.disable_callback();
    send_queue.complete_before_callback_for_test();
    let recv_queue = VirtQueue::new(QUEUE_RECV, 1, transport.as_mut()).unwrap();
    transport.finish_init();
    let mut device = NetworkDevice {
        config_manager: ConfigManager::new(None, None),
        caps: DeviceCapabilities::default(),
        mac_addr: EthernetAddress::default(),
        send_queue,
        recv_queue,
        header: VirtioNetHdr::default(),
        tx_buffers: (0..QUEUE_SIZE).map(|_| None).collect(),
        rx_buffers: SlotVec::new(),
        new_rx_buffer: None,
        transport,
        poll_stat: PollStatistics::new(),
    };
    let mut packet = FreshTxPacket::<LinkLayer>::alloc(64).unwrap().to_builder();
    let bytes = [0u8; 64];
    let written = packet
        .append_writer()
        .write(&mut VmReader::from(bytes.as_slice()));
    assert_eq!(written, bytes.len());
    packet.commit(written);
    device.send(packet.build()).unwrap();

    // Completion happened after the first reap, before the callback was armed.
    // No new packet, polling operation, or interrupt restores credit for us.
    assert!(
        device.can_send(),
        "completion before callback arming must restore TX credit without another interrupt"
    );
    assert_eq!(device.send_queue.available_desc(), 1);
    assert!(device.tx_buffers.iter().all(Option::is_none));
}

/// Only the transport boundary is controlled. The real driver, DMA rings,
/// descriptor publication, completion validation and buffer reclamation run.
#[derive(Debug)]
struct ControlledTransport;

impl VirtioTransport for ControlledTransport {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Network
    }
    fn read_device_features(&self) -> u64 {
        unreachable!("feature negotiation is outside this queue regression")
    }
    fn write_driver_features(&mut self, _: u64) -> Result<(), VirtioTransportError> {
        unreachable!("feature negotiation is outside this queue regression")
    }
    fn read_device_status(&self) -> DeviceStatus {
        DeviceStatus::FEATURES_OK
    }
    fn write_device_status(&mut self, _: DeviceStatus) -> Result<(), VirtioTransportError> {
        Ok(())
    }
    fn device_config_mem(&self) -> Option<IoMem> {
        unreachable!("configuration reads are outside this queue regression")
    }
    fn device_config_bar(&self) -> Option<(BarAccess, usize)> {
        unreachable!("configuration reads are outside this queue regression")
    }
    fn num_queues(&self) -> u16 {
        2
    }
    fn set_queue(
        &mut self,
        index: u16,
        size: u16,
        _: &SafePtr<Descriptor, Arc<DmaCoherent>>,
        _: &SafePtr<AvailRing, Arc<DmaCoherent>>,
        _: &SafePtr<UsedRing, Arc<DmaCoherent>>,
    ) -> Result<(), VirtioTransportError> {
        assert!(index < 2);
        assert_eq!(size, 1);
        Ok(())
    }
    fn max_queue_size(&self, _: u16) -> Result<u16, VirtioTransportError> {
        Ok(1)
    }
    fn notify_config(&self, _: usize) -> ConfigManager<u32> {
        // The controlled device suppresses doorbells and completes by writing
        // its actual used ring at the selected callback-arm boundary.
        ConfigManager::new(None, None)
    }
    fn is_legacy_version(&self) -> bool {
        false
    }
    fn register_queue_callback(
        &mut self,
        _: u16,
        _: Box<IrqCallbackFunction>,
        _: bool,
    ) -> Result<(), VirtioTransportError> {
        unreachable!("this completion intentionally produces no interrupt")
    }
    fn register_cfg_callback(
        &mut self,
        _: Box<IrqCallbackFunction>,
    ) -> Result<(), VirtioTransportError> {
        unreachable!("configuration callbacks are outside this queue regression")
    }
}
