// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::Arc};
use core::mem;

use framev_net_common::{
    FrameVNetConfig, FrameVNetError, FrameVNetReceiveStatus, NetworkEndpointError,
    OwnedNetworkBuffer,
};
use framev_pci_common::FrameVFunctionFamily;

use super::state::FunctionRuntime;
use crate::{
    Result,
    pci::{PciRaiseOutcome, VirtualPciBus},
    sync::SpinLock,
};

const ETHERNET_HEADER_LEN: usize = 14;
const ETHER_TYPE_OFFSET: usize = 12;
const MAC_ADDRESS_LEN: usize = 6;
const SOURCE_MAC_OFFSET: usize = 6;

/// Host endpoint owned by one FrameV-net function.
///
/// The endpoint receives only already-validated Ethernet frames. Implementors
/// must not retain either borrowed payload or receive-buffer storage after the
/// corresponding method returns.
pub trait NetworkEndpoint: Send + Sync {
    /// Sends one validated untagged Ethernet frame without blocking.
    fn send(&self, ethernet_frame: &[u8]) -> Result<(), NetworkEndpointError>;

    /// Receives one Ethernet frame into the caller-owned buffer without blocking.
    fn receive(
        &self,
        receive_buffer: &mut OwnedNetworkBuffer,
    ) -> Result<Option<usize>, NetworkEndpointError>;

    /// Installs the one receive-readiness callback for this endpoint.
    fn install_receive_callback(&self, callback: Arc<dyn Fn() + Send + Sync>);
}

/// Immutable network configuration and captured endpoint for one FrameVM.
pub struct NetworkConfiguration {
    config: FrameVNetConfig,
    endpoint: Arc<dyn NetworkEndpoint>,
}

impl NetworkConfiguration {
    /// Creates one immutable network configuration with its captured endpoint.
    pub fn new(config: FrameVNetConfig, endpoint: Arc<dyn NetworkEndpoint>) -> Self {
        Self { config, endpoint }
    }

    pub(super) const fn config(&self) -> FrameVNetConfig {
        self.config
    }
}

/// Typed host handle for one VM's FrameV-net backend.
pub(crate) struct Net {
    runtime: Arc<FunctionRuntime>,
    config: FrameVNetConfig,
    endpoint: Arc<dyn NetworkEndpoint>,
    pci: Arc<VirtualPciBus>,
    receive_state: SpinLock<ReceiveState>,
}

struct ReceiveState {
    completed: VecDeque<FrameVReceivedFrame>,
    endpoint_lost: bool,
    is_receiving: bool,
    posted: VecDeque<OwnedNetworkBuffer>,
    reclaimed: VecDeque<OwnedNetworkBuffer>,
}

/// One received Ethernet frame backed by its original posted storage.
pub(crate) struct FrameVReceivedFrame {
    buffer: OwnedNetworkBuffer,
    frame_len: usize,
}

impl FrameVReceivedFrame {
    /// Returns the original storage and its validated Ethernet frame length.
    pub(crate) fn into_parts(self) -> (OwnedNetworkBuffer, usize) {
        (self.buffer, self.frame_len)
    }

    fn into_buffer(self) -> OwnedNetworkBuffer {
        self.buffer
    }
}

impl Net {
    pub(super) fn new(
        runtime: Arc<FunctionRuntime>,
        configuration: NetworkConfiguration,
        pci: Arc<VirtualPciBus>,
    ) -> Arc<Self> {
        let NetworkConfiguration { config, endpoint } = configuration;
        let endpoint_for_callback = endpoint.clone();
        let net = Arc::new(Self {
            runtime,
            config,
            endpoint,
            pci,
            receive_state: SpinLock::new(ReceiveState {
                completed: VecDeque::new(),
                endpoint_lost: false,
                is_receiving: false,
                posted: VecDeque::new(),
                reclaimed: VecDeque::new(),
            }),
        });
        let weak_net = Arc::downgrade(&net);
        endpoint_for_callback.install_receive_callback(Arc::new(move || {
            if let Some(net) = weak_net.upgrade() {
                net.process_receive_notification();
            }
        }));
        net
    }

    pub(super) fn runtime(&self) -> &FunctionRuntime {
        &self.runtime
    }

    /// Returns the backend-authoritative immutable network configuration.
    pub(crate) fn config(&self) -> FrameVNetConfig {
        self.config
    }

    /// Returns whether the captured endpoint has become permanently unavailable.
    pub(crate) fn is_endpoint_lost(&self) -> bool {
        self.receive_state.lock().endpoint_lost
    }

    /// Sends one validated Ethernet frame to the captured endpoint.
    pub(crate) fn send(&self, ethernet_frame: &[u8]) -> Result<(), FrameVNetError> {
        validate_outbound_frame(self.config, ethernet_frame)?;
        match self.endpoint.send(ethernet_frame) {
            Ok(()) => Ok(()),
            Err(NetworkEndpointError::NotReady) => Err(FrameVNetError::NotReady),
            Err(NetworkEndpointError::Lost) => {
                self.mark_endpoint_lost();
                Err(FrameVNetError::EndpointLost)
            }
        }
    }

    /// Posts one owned receive buffer without duplicating its storage.
    pub(crate) fn post_receive_buffer(
        &self,
        receive_buffer: OwnedNetworkBuffer,
    ) -> Result<(), (FrameVNetError, OwnedNetworkBuffer)> {
        if receive_buffer.len() < self.config.maximum_frame_bytes() as usize {
            return Err((FrameVNetError::ReceiveBufferTooSmall, receive_buffer));
        }

        let mut state = self.receive_state.lock();
        if state.endpoint_lost {
            return Err((FrameVNetError::EndpointLost, receive_buffer));
        }
        if receive_inventory_len(&state) >= self.config.maximum_posted_receive_buffers() as usize {
            return Err((FrameVNetError::ReceiveQueueFull, receive_buffer));
        }
        state.posted.push_back(receive_buffer);
        Ok(())
    }

    /// Polls the endpoint once and publishes at most one validated received frame.
    pub(crate) fn poll_receive(&self) -> FrameVNetReceiveStatus {
        if self.receive_state.lock().endpoint_lost {
            return FrameVNetReceiveStatus::EndpointLost;
        }
        let Some(mut receive_buffer) = self.begin_receive() else {
            return FrameVNetReceiveStatus::NoBuffer;
        };

        match self.endpoint.receive(&mut receive_buffer) {
            Ok(Some(frame_len)) => self.finish_received_buffer(receive_buffer, frame_len),
            Ok(None) | Err(NetworkEndpointError::NotReady) => {
                self.finish_without_frame(receive_buffer);
                FrameVNetReceiveStatus::NotReady
            }
            Err(NetworkEndpointError::Lost) => {
                self.reclaim_after_endpoint_loss(receive_buffer);
                FrameVNetReceiveStatus::EndpointLost
            }
        }
    }

    /// Returns one validated frame published by `poll_receive`.
    pub(crate) fn take_completed_frame(&self) -> Option<FrameVReceivedFrame> {
        self.receive_state.lock().completed.pop_front()
    }

    /// Returns whether a validated received frame is available to the frontend.
    pub(crate) fn has_completed_frame(&self) -> bool {
        !self.receive_state.lock().completed.is_empty()
    }

    /// Returns one buffer reclaimed after endpoint loss.
    pub(crate) fn take_reclaimed_buffer(&self) -> Option<OwnedNetworkBuffer> {
        self.receive_state.lock().reclaimed.pop_front()
    }

    /// Polls one endpoint datagram and notifies the PCI frontend after publication.
    pub(crate) fn poll_receive_and_notify(&self) -> Result<FrameVNetReceiveStatus> {
        let _call = self.runtime.enter_host()?;
        let receive_status = self.poll_receive();
        if matches!(
            receive_status,
            FrameVNetReceiveStatus::Delivered | FrameVNetReceiveStatus::EndpointLost
        ) {
            self.raise_receive_interrupt()?;
        }
        Ok(receive_status)
    }

    pub(super) fn reset(&self) {
        let mut state = self.receive_state.lock();
        state.completed.clear();
        state.endpoint_lost = false;
        state.is_receiving = false;
        state.posted.clear();
        state.reclaimed.clear();
    }

    fn begin_receive(&self) -> Option<OwnedNetworkBuffer> {
        let mut state = self.receive_state.lock();
        if state.endpoint_lost || state.is_receiving {
            return None;
        }
        let receive_buffer = state.posted.pop_front()?;
        state.is_receiving = true;
        Some(receive_buffer)
    }

    fn finish_received_buffer(
        &self,
        receive_buffer: OwnedNetworkBuffer,
        frame_len: usize,
    ) -> FrameVNetReceiveStatus {
        if validate_inbound_frame(self.config, &receive_buffer, frame_len).is_err() {
            self.finish_without_frame(receive_buffer);
            return FrameVNetReceiveStatus::Dropped;
        }

        let mut state = self.receive_state.lock();
        state.is_receiving = false;
        if state.endpoint_lost {
            state.reclaimed.push_back(receive_buffer);
            return FrameVNetReceiveStatus::EndpointLost;
        }
        state.completed.push_back(FrameVReceivedFrame {
            buffer: receive_buffer,
            frame_len,
        });
        FrameVNetReceiveStatus::Delivered
    }

    fn finish_without_frame(&self, receive_buffer: OwnedNetworkBuffer) {
        let mut state = self.receive_state.lock();
        state.is_receiving = false;
        if state.endpoint_lost {
            state.reclaimed.push_back(receive_buffer);
        } else {
            state.posted.push_front(receive_buffer);
        }
    }

    fn reclaim_after_endpoint_loss(&self, receive_buffer: OwnedNetworkBuffer) {
        let mut state = self.receive_state.lock();
        if state.endpoint_lost {
            state.is_receiving = false;
            state.reclaimed.push_back(receive_buffer);
            return;
        }
        let mut posted_buffers = mem::take(&mut state.posted);
        let completed_frames = mem::take(&mut state.completed);
        state.endpoint_lost = true;
        state.is_receiving = false;
        state.reclaimed.push_back(receive_buffer);
        state.reclaimed.append(&mut posted_buffers);
        state.reclaimed.extend(
            completed_frames
                .into_iter()
                .map(FrameVReceivedFrame::into_buffer),
        );
    }

    fn mark_endpoint_lost(&self) {
        let mut state = self.receive_state.lock();
        if state.endpoint_lost {
            return;
        }
        let mut posted_buffers = mem::take(&mut state.posted);
        let completed_frames = mem::take(&mut state.completed);
        state.endpoint_lost = true;
        state.reclaimed.append(&mut posted_buffers);
        state.reclaimed.extend(
            completed_frames
                .into_iter()
                .map(FrameVReceivedFrame::into_buffer),
        );
    }

    fn process_receive_notification(&self) {
        for _ in 0..self.config.maximum_posted_receive_buffers() {
            let receive_status = match self.poll_receive_and_notify() {
                Ok(receive_status) => receive_status,
                Err(_) => return,
            };
            match receive_status {
                FrameVNetReceiveStatus::Delivered | FrameVNetReceiveStatus::Dropped => {}
                FrameVNetReceiveStatus::EndpointLost
                | FrameVNetReceiveStatus::NoBuffer
                | FrameVNetReceiveStatus::NotReady => return,
            }
        }
    }

    fn raise_receive_interrupt(&self) -> Result<()> {
        let generation = self.runtime.generation();
        let outcome = self.pci.raise(FrameVFunctionFamily::Net, 0, generation)?;
        match outcome {
            PciRaiseOutcome::Deliver(_) | PciRaiseOutcome::Masked | PciRaiseOutcome::Coalesced => {
                Ok(())
            }
        }
    }
}

fn validate_outbound_frame(
    config: FrameVNetConfig,
    ethernet_frame: &[u8],
) -> Result<(), FrameVNetError> {
    if ethernet_frame.len() < ETHERNET_HEADER_LEN {
        return Err(FrameVNetError::FrameTooShort);
    }
    if ethernet_frame.len() > config.maximum_frame_bytes() as usize {
        return Err(FrameVNetError::FrameTooLong);
    }
    if ethernet_frame[SOURCE_MAC_OFFSET..SOURCE_MAC_OFFSET + MAC_ADDRESS_LEN]
        != config.mac_address()
    {
        return Err(FrameVNetError::SourceMacMismatch);
    }

    let ether_type = u16::from_be_bytes([
        ethernet_frame[ETHER_TYPE_OFFSET],
        ethernet_frame[ETHER_TYPE_OFFSET + 1],
    ]);
    if matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        return Err(FrameVNetError::TaggedFrame);
    }
    Ok(())
}

fn validate_inbound_frame(
    config: FrameVNetConfig,
    receive_buffer: &OwnedNetworkBuffer,
    frame_len: usize,
) -> Result<(), FrameVNetError> {
    if frame_len < ETHERNET_HEADER_LEN {
        return Err(FrameVNetError::FrameTooShort);
    }
    if frame_len > receive_buffer.len() || frame_len > config.maximum_frame_bytes() as usize {
        return Err(FrameVNetError::FrameTooLong);
    }

    let ethernet_frame = &receive_buffer.as_bytes()[..frame_len];
    let ether_type = u16::from_be_bytes([
        ethernet_frame[ETHER_TYPE_OFFSET],
        ethernet_frame[ETHER_TYPE_OFFSET + 1],
    ]);
    if matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        return Err(FrameVNetError::TaggedFrame);
    }

    let destination_mac = &ethernet_frame[..SOURCE_MAC_OFFSET];
    if destination_mac[0] & 1 == 0 && destination_mac != config.mac_address() {
        return Err(FrameVNetError::ForeignUnicastDestination);
    }
    Ok(())
}

fn receive_inventory_len(state: &ReceiveState) -> usize {
    state
        .posted
        .len()
        .saturating_add(state.completed.len())
        .saturating_add(state.reclaimed.len())
}

#[cfg(ktest)]
mod tests {
    use alloc::{vec, vec::Vec};

    use framev_pci_common::VirtualPciBdf;
    use host_ostd::prelude::ktest;

    use super::*;

    struct RecordingEndpoint {
        observed_frame: SpinLock<Option<(usize, usize)>>,
        observed_receive_buffer: SpinLock<Option<usize>>,
        receive_outcomes: SpinLock<VecDeque<ReceiveOutcome>>,
        send_outcomes: SpinLock<VecDeque<NetworkEndpointError>>,
    }

    enum ReceiveOutcome {
        Frame(Vec<u8>),
        Lost,
    }

    impl RecordingEndpoint {
        fn new() -> Self {
            Self {
                observed_frame: SpinLock::new(None),
                observed_receive_buffer: SpinLock::new(None),
                receive_outcomes: SpinLock::new(VecDeque::new()),
                send_outcomes: SpinLock::new(VecDeque::new()),
            }
        }

        fn queue_received_frame(&self, ethernet_frame: Vec<u8>) {
            self.receive_outcomes
                .lock()
                .push_back(ReceiveOutcome::Frame(ethernet_frame));
        }

        fn queue_endpoint_loss(&self) {
            self.receive_outcomes.lock().push_back(ReceiveOutcome::Lost);
        }

        fn queue_send_error(&self, error: NetworkEndpointError) {
            self.send_outcomes.lock().push_back(error);
        }
    }

    impl NetworkEndpoint for RecordingEndpoint {
        fn send(&self, ethernet_frame: &[u8]) -> Result<(), NetworkEndpointError> {
            if let Some(error) = self.send_outcomes.lock().pop_front() {
                return Err(error);
            }
            *self.observed_frame.lock() =
                Some((ethernet_frame.as_ptr() as usize, ethernet_frame.len()));
            Ok(())
        }

        fn receive(
            &self,
            receive_buffer: &mut OwnedNetworkBuffer,
        ) -> Result<Option<usize>, NetworkEndpointError> {
            let Some(outcome) = self.receive_outcomes.lock().pop_front() else {
                return Ok(None);
            };
            match outcome {
                ReceiveOutcome::Frame(ethernet_frame) => {
                    if ethernet_frame.len() > receive_buffer.len() {
                        return Err(NetworkEndpointError::Lost);
                    }
                    receive_buffer.as_mut_bytes()[..ethernet_frame.len()]
                        .copy_from_slice(&ethernet_frame);
                    *self.observed_receive_buffer.lock() =
                        Some(receive_buffer.as_bytes().as_ptr() as usize);
                    Ok(Some(ethernet_frame.len()))
                }
                ReceiveOutcome::Lost => Err(NetworkEndpointError::Lost),
            }
        }

        fn install_receive_callback(&self, _callback: Arc<dyn Fn() + Send + Sync>) {}
    }

    fn net() -> (Arc<Net>, Arc<RecordingEndpoint>) {
        let endpoint = Arc::new(RecordingEndpoint::new());
        let config = FrameVNetConfig::new([0x02, 0, 0, 0, 0, 1], 1_500, 1_514, 16).unwrap();
        let configuration = NetworkConfiguration::new(config, endpoint.clone());
        let runtime = Arc::new(FunctionRuntime::new(
            crate::vm::VmId::new(1),
            VirtualPciBdf::new(0, 4, 0).unwrap(),
            FrameVFunctionFamily::Net,
        ));
        let pci =
            Arc::new(VirtualPciBus::new(crate::vm::VmId::new(1), 1, 3, &[], Some(config)).unwrap());
        (Net::new(runtime, configuration, pci), endpoint)
    }

    #[ktest]
    fn send_validates_before_borrowing_the_endpoint() {
        let (net, endpoint) = net();
        let frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00,
        ];

        assert_eq!(net.send(&frame), Ok(()));
        assert_eq!(
            *endpoint.observed_frame.lock(),
            Some((frame.as_ptr() as usize, frame.len()))
        );

        let mut spoofed_frame = frame;
        spoofed_frame[6] = 0x04;
        assert_eq!(
            net.send(&spoofed_frame),
            Err(FrameVNetError::SourceMacMismatch)
        );
        assert_eq!(
            *endpoint.observed_frame.lock(),
            Some((frame.as_ptr() as usize, frame.len()))
        );

        let mut tagged_frame = frame;
        tagged_frame[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        assert_eq!(net.send(&tagged_frame), Err(FrameVNetError::TaggedFrame));
    }

    #[ktest]
    fn receive_publishes_the_original_posted_storage() {
        let (net, endpoint) = net();
        let receive_buffer = OwnedNetworkBuffer::new(vec![0; 1_514]);
        let receive_buffer_ptr = receive_buffer.as_bytes().as_ptr() as usize;
        endpoint.queue_received_frame(vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00]);

        assert!(net.post_receive_buffer(receive_buffer).is_ok());
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::Delivered);

        let received_frame = net.take_completed_frame().unwrap();
        assert_eq!(
            *endpoint.observed_receive_buffer.lock(),
            Some(receive_buffer_ptr)
        );
        let (receive_buffer, frame_len) = received_frame.into_parts();
        assert_eq!(
            &receive_buffer.as_bytes()[..frame_len],
            [0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00]
        );
        assert_eq!(
            receive_buffer.as_bytes().as_ptr() as usize,
            receive_buffer_ptr
        );
        assert_eq!(frame_len, 14);
    }

    #[ktest]
    fn receive_filters_frames_and_reuses_the_posted_storage() {
        let (net, endpoint) = net();
        let receive_buffer = OwnedNetworkBuffer::new(vec![0; 1_514]);
        let receive_buffer_ptr = receive_buffer.as_bytes().as_ptr() as usize;
        endpoint.queue_received_frame(vec![0x02, 0, 0, 0, 0, 9, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00]);
        endpoint.queue_received_frame(vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x81, 0x00]);
        let accepted_frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00,
        ];
        endpoint.queue_received_frame(accepted_frame.clone());

        assert!(net.post_receive_buffer(receive_buffer).is_ok());
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::Dropped);
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::Dropped);
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::Delivered);

        let received_frame = net.take_completed_frame().unwrap();
        let (receive_buffer, frame_len) = received_frame.into_parts();
        assert_eq!(&receive_buffer.as_bytes()[..frame_len], accepted_frame);
        assert_eq!(
            receive_buffer.as_bytes().as_ptr() as usize,
            receive_buffer_ptr
        );
    }

    #[ktest]
    fn undersized_receive_buffer_is_returned_to_the_caller() {
        let (net, _) = net();
        let receive_buffer = OwnedNetworkBuffer::new(vec![0; 128]);
        let receive_buffer_ptr = receive_buffer.as_bytes().as_ptr() as usize;

        let (error, receive_buffer) = net.post_receive_buffer(receive_buffer).unwrap_err();

        assert_eq!(error, FrameVNetError::ReceiveBufferTooSmall);
        assert_eq!(
            receive_buffer.as_bytes().as_ptr() as usize,
            receive_buffer_ptr
        );
    }

    #[ktest]
    fn endpoint_loss_reclaims_each_posted_buffer_once() {
        let (net, endpoint) = net();
        let receive_buffer = OwnedNetworkBuffer::new(vec![0; 1_514]);
        let receive_buffer_ptr = receive_buffer.as_bytes().as_ptr() as usize;
        endpoint.queue_endpoint_loss();

        assert!(net.post_receive_buffer(receive_buffer).is_ok());
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::EndpointLost);
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::EndpointLost);

        let reclaimed_buffer = net.take_reclaimed_buffer().unwrap();
        assert_eq!(
            reclaimed_buffer.as_bytes().as_ptr() as usize,
            receive_buffer_ptr
        );
        assert!(net.take_reclaimed_buffer().is_none());
    }

    #[ktest]
    fn endpoint_loss_reclaims_completed_and_posted_storage_once() {
        let (net, endpoint) = net();
        let first_buffer = OwnedNetworkBuffer::new(vec![0; 1_514]);
        let first_buffer_ptr = first_buffer.as_bytes().as_ptr() as usize;
        let second_buffer = OwnedNetworkBuffer::new(vec![0; 1_514]);
        let second_buffer_ptr = second_buffer.as_bytes().as_ptr() as usize;
        endpoint.queue_received_frame(vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00]);
        endpoint.queue_endpoint_loss();

        assert!(net.post_receive_buffer(first_buffer).is_ok());
        assert!(net.post_receive_buffer(second_buffer).is_ok());
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::Delivered);
        assert_eq!(net.poll_receive(), FrameVNetReceiveStatus::EndpointLost);

        let mut reclaimed_buffer_ptrs = [
            net.take_reclaimed_buffer().unwrap().as_bytes().as_ptr() as usize,
            net.take_reclaimed_buffer().unwrap().as_bytes().as_ptr() as usize,
        ];
        reclaimed_buffer_ptrs.sort_unstable();
        let mut expected_buffer_ptrs = [first_buffer_ptr, second_buffer_ptr];
        expected_buffer_ptrs.sort_unstable();
        assert_eq!(reclaimed_buffer_ptrs, expected_buffer_ptrs);
        assert!(net.take_reclaimed_buffer().is_none());
        assert!(net.take_completed_frame().is_none());
    }

    #[ktest]
    fn send_endpoint_loss_reclaims_posted_receive_storage() {
        let (net, endpoint) = net();
        let receive_buffer = OwnedNetworkBuffer::new(vec![0; 1_514]);
        let receive_buffer_ptr = receive_buffer.as_bytes().as_ptr() as usize;
        endpoint.queue_send_error(NetworkEndpointError::Lost);
        let ethernet_frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00,
        ];

        assert!(net.post_receive_buffer(receive_buffer).is_ok());
        assert_eq!(net.send(&ethernet_frame), Err(FrameVNetError::EndpointLost));
        assert!(net.is_endpoint_lost());
        assert_eq!(
            net.take_reclaimed_buffer().unwrap().as_bytes().as_ptr() as usize,
            receive_buffer_ptr
        );
    }
}
