// SPDX-License-Identifier: MPL-2.0

//! Ethernet NAT frontend forwarded through native Host TCP and UDP sockets.
//!
//! One adopted device Task drives virtqueues and the protocol frontend. It
//! sleeps on native socket events, device notifications and protocol deadlines.

use core::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use aster_bigtcp::socket::{TCP_RECV_BUF_LEN, TCP_SEND_BUF_LEN};
use kernelet_abi::{MAX_NET_PORTS, NET_PROTOCOL_TCP, NET_PROTOCOL_UDP, NetConfigArgs};
use ostd::kernelet::control::HostByteCharge;
use smoltcp::{
    iface::{
        Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, SocketHandle,
        SocketSet,
    },
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{Socket, tcp, udp},
    time::Instant as NetworkInstant,
    wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
        IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket,
    },
};

#[cfg(kernelet_nat_failure_diag_host)]
use super::{
    super::policy::{QuotaClass, QuotaTag},
    endpoint::{NatContext, NatEvent},
};
use super::{
    super::{
        policy::{NativeTcpBufferCharge, UserEndpointReservation},
        shared_net::{SharedFrame, SharedNetTransport, SharedTxFrame},
    },
    Frame, MAX_FRAME_BYTES, NetEndpoint, NetWorker, Work,
    sockets::{TcpListener, TcpStream, UdpSocket},
};
use crate::{events::IoEvents, prelude::*, process::signal::Poller};

const MAX_FRAME: usize = MAX_FRAME_BYTES;
const MAX_FLOWS: usize = 256;
const BUFFER_BYTES: usize = 64 * 1024;
const TCP_FORWARD_BYTES: usize = 16 * 1024;
const FLOW_RESERVATION_BYTES: usize = 512 * 1024;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
// Other shared-buffer links can release Image import quota without a NIC IRQ.
// Retry only that blocked condition; returned NIC buffers retain IRQ wakeups.
const IMPORT_CREDIT_RETRY_DELAY: Duration = Duration::from_millis(10);
// Split the existing 64 KiB metadata margin evenly between native TCP and
// the Guest frontend. Closing snapshots reserve their extra 64 KiB first.
const NATIVE_TCP_RESERVATION_BYTES: usize = TCP_RECV_BUF_LEN
    + TCP_SEND_BUF_LEN
    + (FLOW_RESERVATION_BYTES - TCP_RECV_BUF_LEN - TCP_SEND_BUF_LEN - 3 * BUFFER_BYTES) / 2;
const GATEWAY_MAC: [u8; 6] = [2, 0xc7, 0, 0, 0, 1];
const GATEWAY: Ipv4Address = Ipv4Addr::new(10, 0, 2, 2);
const GUEST: Ipv4Address = Ipv4Addr::new(10, 0, 2, 15);
/// Guest-facing source ports handed out to Host-initiated NAT flows.
const FIRST_SOURCE_PORT: u16 = 40000;
const LAST_SOURCE_PORT: u16 = 60000;
/// The bounded allocator is scanned at most one full cycle per flow.
const SOURCE_PORT_CYCLE: usize = (LAST_SOURCE_PORT - FIRST_SOURCE_PORT) as usize + 1;

pub(super) struct NatBackend {
    config: NetConfigArgs,
    listeners: Vec<(TcpListener, u16)>,
    datagram_listeners: Vec<(UdpSocket, u16)>,
}

impl NatBackend {
    pub(super) fn new(
        config: NetConfigArgs,
        reservation: &super::endpoint::BackendReservation,
    ) -> Result<Self> {
        let count = usize::from(config.num_ports);
        if count > MAX_NET_PORTS || config.reserved0 != 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid network configuration");
        }
        let mut listeners = Vec::new();
        let mut datagram_listeners = Vec::new();
        for (index, port) in config.ports.iter().enumerate() {
            if port.reserved0 != 0
                || (index >= count
                    && (port.host_address != [0; 4]
                        || port.host_port != 0
                        || port.guest_port != 0
                        || port.protocol != 0))
            {
                return_errno_with_message!(Errno::EINVAL, "invalid network port mapping");
            }
            if index >= count {
                continue;
            }
            if port.host_port == 0 || port.guest_port == 0 {
                return_errno_with_message!(Errno::EINVAL, "empty network port mapping");
            }
            let local = SocketAddrV4::new(Ipv4Addr::from(port.host_address), port.host_port);
            match port.protocol {
                NET_PROTOCOL_TCP => listeners.push((
                    TcpListener::bind(local, reservation.clone())?,
                    port.guest_port,
                )),
                NET_PROTOCOL_UDP => {
                    datagram_listeners.push((UdpSocket::bind(local)?, port.guest_port))
                }
                _ => return_errno_with_message!(Errno::EINVAL, "unsupported network protocol"),
            }
        }
        Ok(Self {
            config,
            listeners,
            datagram_listeners,
        })
    }

    pub(super) fn run(self, model: &NetWorker) -> Result<()> {
        let Self {
            config,
            listeners,
            datagram_listeners,
        } = self;
        #[cfg(kernelet_nat_failure_diag_host)]
        for port in config.ports.iter().take(usize::from(config.num_ports)) {
            if port.protocol == NET_PROTOCOL_TCP {
                let mut context = NatContext::new("listener_owner_entered_worker");
                context.listener = Some(SocketAddrV4::new(
                    Ipv4Addr::from(port.host_address),
                    port.host_port,
                ));
                context.guest_port = Some(port.guest_port);
                model.record_diagnostic(NatEvent::ListenersOwned, context, None);
            }
        }
        #[cfg(kernelet_nat_failure_diag_host)]
        model.endpoint.emit_diagnostics();
        let result = match model.shared_transport() {
            Some(transport) => run(
                model,
                config,
                listeners,
                datagram_listeners,
                FrameDevice::new(SharedFrames {
                    endpoint: &model.endpoint,
                    transport,
                    prepared: None,
                    import_blocked: false,
                }),
            ),
            None => run(
                model,
                config,
                listeners,
                datagram_listeners,
                FrameDevice::new(CopyFrames(&model.endpoint)),
            ),
        };
        // run's owned listener parameters have now dropped; this is not a
        // claim that a native registry entry or a background TCP was reclaimed.
        #[cfg(kernelet_nat_failure_diag_host)]
        for port in config.ports.iter().take(usize::from(config.num_ports)) {
            if port.protocol == NET_PROTOCOL_TCP {
                let mut context = NatContext::new("listener_owner_run_returned");
                context.listener = Some(SocketAddrV4::new(
                    Ipv4Addr::from(port.host_address),
                    port.host_port,
                ));
                context.guest_port = Some(port.guest_port);
                model.record_diagnostic(NatEvent::ListenersReleased, context, None);
            }
        }
        result
    }
}

fn now() -> Duration {
    aster_time::read_monotonic_time()
}
fn elapsed(since: Duration) -> Duration {
    now().saturating_sub(since)
}
fn guest_socket_error(error: impl Debug) -> Error {
    error!("kernelet network frontend socket failed: {:?}", error);
    Error::with_message(Errno::EINVAL, "invalid guest network socket endpoint")
}

/// Returns the next guest-facing source port that no live socket holds,
/// advancing the bounded allocator at most one full cycle; `None` when
/// every port is taken.
///
/// smoltcp hands a received packet to the first socket whose endpoints
/// match, so once the allocator wraps around while earlier flows are still
/// alive, a reused port would let a new flow collide with an existing
/// tuple and steal its traffic. The existing socket state is the source of
/// truth; no separate port set is kept.
fn next_source_port(next_port: &mut u16, in_use: impl Fn(u16) -> bool) -> Option<u16> {
    (0..SOURCE_PORT_CYCLE).find_map(|_| {
        let port = *next_port;
        *next_port = if port == LAST_SOURCE_PORT {
            FIRST_SOURCE_PORT
        } else {
            port + 1
        };
        (!in_use(port)).then_some(port)
    })
}

/// Covers active socket buffers and pending stream data conservatively.
struct FlowCharge {
    host: HostByteCharge,
    user: UserEndpointReservation,
}
impl FlowCharge {
    fn new(
        model: &NetWorker,
        #[cfg(kernelet_nat_failure_diag_host)] context: NatContext,
    ) -> Result<Self> {
        Self::with_bytes(
            model,
            FLOW_RESERVATION_BYTES,
            #[cfg(kernelet_nat_failure_diag_host)]
            context,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaClass::NatFlow,
        )
    }

    fn with_bytes(
        model: &NetWorker,
        bytes: usize,
        #[cfg(kernelet_nat_failure_diag_host)] context: NatContext,
        #[cfg(kernelet_nat_failure_diag_host)] class: QuotaClass,
    ) -> Result<Self> {
        #[cfg(not(kernelet_nat_failure_diag_host))]
        let user = model.endpoint.reserve_backend_bytes(bytes)?;
        #[cfg(kernelet_nat_failure_diag_host)]
        let user = {
            let mut failure = None;
            let mut categories = None;
            // Release the endpoint diagnostic lock before taking LEDGER.
            let capture_categories = model.endpoint.wants_quota_categories();
            let result = UserEndpointReservation::reserve_diagnostic(
                model.endpoint.owner(),
                bytes,
                QuotaTag::new(class, Some(model.endpoint.diagnostic_cid())),
                &mut failure,
                capture_categories.then_some(&mut categories),
            );
            if let Err(error) = &result {
                // reserve_diagnostic returned: the LEDGER guard is gone.
                let mut context = context;
                context.error = Some(*error);
                model.endpoint.record_quota_failure(
                    context,
                    Some(error.error()),
                    None,
                    bytes,
                    failure,
                    categories,
                    model.diagnostic_cancelled(),
                );
            }
            result?
        };
        let host = model.kernelet.reserve_host_bytes(bytes).map_err(|error| {
            #[cfg(kernelet_nat_failure_diag_host)]
            model.endpoint.record_diagnostic(
                NatEvent::HostReservation,
                context,
                Some(Errno::ENOMEM),
                Some(error),
                bytes,
                None,
                model.diagnostic_cancelled(),
            );
            debug!("kernelet NAT Host-memory charge failed: {:?}", error);
            Error::with_message(Errno::ENOMEM, "cannot charge network flow")
        })?;
        Ok(Self { host, user })
    }

    fn split_native_tcp(&mut self) -> NativeTcpBufferCharge {
        NativeTcpBufferCharge::new(
            self.host
                .split_off(NATIVE_TCP_RESERVATION_BYTES)
                .expect("native TCP charge fits the flow reservation"),
            self.user
                .split_off(
                    NATIVE_TCP_RESERVATION_BYTES,
                    #[cfg(kernelet_nat_failure_diag_host)]
                    QuotaClass::NatNativeTcp,
                )
                .expect("native TCP charge fits the flow reservation"),
        )
    }
}
struct UdpFrontend {
    handle: SocketHandle,
    _charge: FlowCharge,
}

fn accept_mapped_tcp(
    model: &NetWorker,
    listener: &TcpListener,
    #[cfg(kernelet_nat_failure_diag_host)] context: NatContext,
) -> Result<Option<(TcpStream, FlowCharge)>> {
    if !listener.poll(None).contains(IoEvents::IN) {
        return Ok(None);
    }
    let mut charge = FlowCharge::new(
        model,
        #[cfg(kernelet_nat_failure_diag_host)]
        context,
    )?;
    match listener.accept(
        charge.split_native_tcp(),
        #[cfg(kernelet_nat_failure_diag_host)]
        model,
        #[cfg(kernelet_nat_failure_diag_host)]
        context,
    ) {
        Ok(stream) => Ok(Some((stream, charge))),
        Err(error) if error.error() == Errno::EAGAIN => Ok(None),
        Err(error) => Err(error),
    }
}

/// Masks level-triggered listener readiness while admission cannot progress.
fn accept_mapped_tcp_with_backoff(
    model: &NetWorker,
    listener: &TcpListener,
    retry: &mut Option<Duration>,
    current: Duration,
    #[cfg(kernelet_nat_failure_diag_host)] context: NatContext,
) -> Result<Option<(TcpStream, FlowCharge)>> {
    if retry.is_some_and(|deadline| current < deadline) {
        return Ok(None);
    }
    *retry = None;
    let result = accept_mapped_tcp(
        model,
        listener,
        #[cfg(kernelet_nat_failure_diag_host)]
        context,
    );
    if result.is_err() {
        *retry = Some(current + ACCEPT_RETRY_DELAY);
    }
    result
}

// Keep the two transport loops separate so the shared worker's stack does not
// inherit the copying worker's inline-frame locals. This call occurs once per worker.
#[inline(never)]
fn run<B: FrameBackend>(
    model: &NetWorker,
    config: NetConfigArgs,
    listeners: Vec<(TcpListener, u16)>,
    datagram_listeners: Vec<(UdpSocket, u16)>,
    mut device: FrameDevice<B>,
) -> Result<()> {
    let mut interface_config =
        InterfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(GATEWAY_MAC)));
    let mac = model.mac;
    interface_config.random_seed =
        u64::from_be_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 1]);
    let mut interface = Interface::new(
        interface_config,
        &mut device,
        NetworkInstant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(GATEWAY), 24))
            .unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(GATEWAY)
        .unwrap();
    interface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_flows = Vec::<TcpFlow>::new();
    let mut udp_sockets = BTreeMap::<SocketAddrV4, UdpFrontend>::new();
    let mut udp_flows = BTreeMap::<(SocketAddrV4, SocketAddrV4), UdpFlow>::new();
    let mut inbound_datagrams = Vec::<UdpPortFlow>::new();
    let mut next_port = FIRST_SOURCE_PORT;
    let mut accept_retry = vec![None; listeners.len()];
    let result = (|| {
        loop {
            let generation = model.endpoint.generation();
            let timestamp =
                NetworkInstant::from_millis(now().as_millis().min(i64::MAX as u128) as i64);
            let mut progressed = false;
            for _ in 0..128 {
                match device.backend.take_work(model) {
                    Some(Work::Cancel) => {
                        #[cfg(kernelet_nat_failure_diag_host)]
                        model.record_diagnostic(
                            NatEvent::CancelObserved,
                            NatContext::new("work_cancel_observed"),
                            None,
                        );
                        return Ok(());
                    }
                    Some(Work::Progress) => progressed = true,
                    None => break,
                }
            }
            let mut ingress_progressed = false;
            for _ in 0..32 {
                if device.received.is_none() {
                    let Some(frame) = device.backend.pop_output() else {
                        break;
                    };
                    frame.with_bytes(|bytes| {
                        prepare_incoming(
                            bytes,
                            &config,
                            model,
                            &mut sockets,
                            &mut tcp_flows,
                            &mut udp_sockets,
                        )
                    })?;
                    device.received = Some(frame);
                }
                // Drain the existing bounded ingress batch before scanning all
                // sockets for egress. Immediate protocol replies still use the
                // ingress TxToken; the egress pass below dispatches queued data.
                if interface.poll_ingress_single(timestamp, &mut device, &mut sockets)
                    == PollIngressSingleResult::None
                {
                    // A missing paired transmit credit retains this frame.
                    // Retry it after a return IRQ or import-credit deadline.
                    break;
                }
                ingress_progressed = true;
            }
            progressed |= ingress_progressed;
            if ingress_progressed {
                progressed |=
                    interface.poll_egress(timestamp, &mut device, &mut sockets) != PollResult::None;
            }
            for (index, (listener, destination_port)) in listeners.iter().enumerate() {
                #[cfg(kernelet_nat_failure_diag_host)]
                let context = listener
                    .diagnostic_context("mapped_tcp_reserve_before_accept", *destination_port);
                if tcp_flows.len() + udp_flows.len() + inbound_datagrams.len() >= MAX_FLOWS {
                    #[cfg(kernelet_nat_failure_diag_host)]
                    model.record_diagnostic(NatEvent::FlowCapacity, context, None);
                    break;
                }
                let accepted = accept_mapped_tcp_with_backoff(
                    model,
                    listener,
                    &mut accept_retry[index],
                    now(),
                    #[cfg(kernelet_nat_failure_diag_host)]
                    context,
                );
                let (stream, charge) = match accepted {
                    Ok(Some(accepted)) => accepted,
                    Ok(None) => continue,
                    Err(error) => {
                        // A readable listener cannot make progress without a
                        // flow reservation. Mask its level event until retry.
                        debug!("kernelet mapped TCP accept deferred: {:?}", error);
                        continue;
                    }
                };
                {
                    progressed = true;
                    // Skip ports still held by live TCP sockets, including
                    // sockets listening on a mapped guest port, so the new
                    // flow gets a unique guest-facing tuple.
                    let Some(source_port) = next_source_port(&mut next_port, |port| {
                        sockets.iter().any(|(_, socket)| {
                            matches!(socket, Socket::Tcp(socket)
                            if socket.local_endpoint().is_some_and(|endpoint| endpoint.port == port)
                                || socket.listen_endpoint().port == port)
                        })
                    }) else {
                        // Every source port is taken: refuse this connection.
                        #[cfg(kernelet_nat_failure_diag_host)]
                        model.record_diagnostic(NatEvent::SourcePorts, context, None);
                        continue;
                    };
                    let mut socket = tcp_socket();
                    socket
                        .connect(
                            interface.context(),
                            (GUEST, *destination_port),
                            (GATEWAY, source_port),
                        )
                        .map_err(guest_socket_error)?;
                    let handle = sockets.add(socket);
                    tcp_flows.push(TcpFlow::new(handle, stream, charge));
                }
            }
            for (index, (host, guest_port)) in datagram_listeners.iter().enumerate() {
                let mut packet = [0; 1472];
                if let Ok((length, peer)) = host.recv_from(&mut packet) {
                    let existing = inbound_datagrams
                        .iter()
                        .position(|flow| flow.listener == index && flow.peer == peer);
                    let flow_index = if let Some(index) = existing {
                        index
                    } else {
                        if tcp_flows.len() + udp_flows.len() + inbound_datagrams.len() >= MAX_FLOWS
                        {
                            continue;
                        }
                        let Ok(charge) = FlowCharge::new(
                            model,
                            #[cfg(kernelet_nat_failure_diag_host)]
                            NatContext::new("mapped_udp_reserve"),
                        ) else {
                            continue;
                        };
                        let mut socket = udp_socket();
                        // A mapping gives each Host peer its own guest-facing tuple.
                        // Do not reuse a live port when the bounded allocator wraps.
                        let Some(port) = next_source_port(&mut next_port, |port| {
                            sockets.iter().any(|(_, socket)| matches!(socket, Socket::Udp(socket) if socket.endpoint().port == port))
                        }) else {
                            continue;
                        };
                        socket.bind((GATEWAY, port)).map_err(guest_socket_error)?;
                        inbound_datagrams.push(UdpPortFlow {
                            listener: index,
                            peer,
                            handle: sockets.add(socket),
                            last_active: now(),
                            _charge: charge,
                        });
                        inbound_datagrams.len() - 1
                    };
                    let flow = &mut inbound_datagrams[flow_index];
                    let _ = sockets
                        .get_mut::<udp::Socket>(flow.handle)
                        .send_slice(&packet[..length], (GUEST, *guest_port));
                    flow.last_active = now();
                }
            }
            progressed |= interface.poll(timestamp, &mut device, &mut sockets) != PollResult::None;
            for flow in &mut tcp_flows {
                let previous = flow.last_active;
                flow.forward(model, sockets.get_mut::<tcp::Socket>(flow.handle));
                progressed |= flow.last_active != previous;
            }
            for (destination, frontend) in &udp_sockets {
                let socket = sockets.get_mut::<udp::Socket>(frontend.handle);
                while let Ok((payload, metadata)) = socket.recv() {
                    let IpAddress::Ipv4(source_ip) = metadata.endpoint.addr else {
                        continue;
                    };
                    let source = SocketAddrV4::new(source_ip, metadata.endpoint.port);
                    let key = (source, *destination);
                    if !udp_flows.contains_key(&key) {
                        if udp_flows.len() + tcp_flows.len() + inbound_datagrams.len() >= MAX_FLOWS
                        {
                            continue;
                        }
                        let Ok(charge) = FlowCharge::new(
                            model,
                            #[cfg(kernelet_nat_failure_diag_host)]
                            NatContext::new("outbound_udp_reserve"),
                        ) else {
                            continue;
                        };
                        let host_destination = translate_destination(*destination, &config);
                        let host = match UdpSocket::connect(host_destination) {
                            Ok(host) => host,
                            Err(error) => {
                                debug!("kernelet UDP connect failed: {:?}", error);
                                continue;
                            }
                        };
                        udp_flows.insert(
                            key,
                            UdpFlow {
                                host,
                                last_active: now(),
                                handle: frontend.handle,
                                _charge: charge,
                            },
                        );
                    }
                    let flow = udp_flows.get_mut(&key).unwrap();
                    if let Err(error) = flow.host.send(payload)
                        && error.error() != Errno::EAGAIN
                    {
                        debug!("kernelet UDP send failed: {:?}", error);
                    }
                    progressed = true;
                    flow.last_active = now();
                }
            }
            udp_flows.retain(|(source, _), flow| {
                if elapsed(flow.last_active) > Duration::from_secs(60) {
                    return false;
                }
                let mut packet = [0; 1472];
                if let Ok(length) = flow.host.recv(&mut packet) {
                    let socket = sockets.get_mut::<udp::Socket>(flow.handle);
                    let _ = socket.send_slice(
                        &packet[..length],
                        IpEndpoint::new(IpAddress::Ipv4(*source.ip()), source.port()),
                    );
                    flow.last_active = now();
                }
                true
            });
            inbound_datagrams.retain_mut(|flow| {
                if elapsed(flow.last_active) > Duration::from_secs(60) {
                    sockets.remove(flow.handle);
                    return false;
                }
                let (host, port) = &datagram_listeners[flow.listener];
                let socket = sockets.get_mut::<udp::Socket>(flow.handle);
                while let Ok((payload, metadata)) = socket.recv() {
                    if metadata.endpoint == IpEndpoint::new(IpAddress::Ipv4(GUEST), *port) {
                        let _ = host.send_to(payload, flow.peer);
                        flow.last_active = now();
                    }
                }
                true
            });
            udp_sockets.retain(|_, frontend| {
                let used = udp_flows
                    .values()
                    .any(|flow| flow.handle == frontend.handle);
                if !used {
                    sockets.remove(frontend.handle);
                }
                used
            });
            progressed |= interface.poll(timestamp, &mut device, &mut sockets) != PollResult::None;
            tcp_flows.retain(|flow| {
                let socket = sockets.get::<tcp::Socket>(flow.handle);
                // abort() only queues an RST. Keep its tuple until poll dispatches
                // it, including when the guest receive queue is temporarily full.
                let reset_pending = !flow.alive
                    && socket.state() == tcp::State::Closed
                    && socket.remote_endpoint().is_some();
                if (!flow.alive && !reset_pending)
                    || elapsed(flow.last_active) > Duration::from_secs(300)
                {
                    sockets.remove(flow.handle);
                    false
                } else {
                    true
                }
            });
            // Publish before a possibly indefinite poll wait; logging owns no
            // socket, device-register or ledger guard.
            #[cfg(kernelet_nat_failure_diag_host)]
            model.endpoint.emit_diagnostics();
            if progressed {
                continue;
            }
            let current = now();
            let mut timeout = tcp_flows
                .iter()
                .map(|flow| (flow.last_active + Duration::from_secs(300)).saturating_sub(current))
                .chain(udp_flows.values().map(|flow| {
                    (flow.last_active + Duration::from_secs(60)).saturating_sub(current)
                }))
                .chain(inbound_datagrams.iter().map(|flow| {
                    (flow.last_active + Duration::from_secs(60)).saturating_sub(current)
                }))
                .min();
            if let Some(delay) = interface.poll_delay(timestamp, &sockets) {
                let delay = Duration::from_millis(delay.total_millis());
                if !delay.is_zero() || device.can_transmit() {
                    timeout = Some(timeout.map_or(delay, |previous| previous.min(delay)));
                }
            }
            for deadline in accept_retry.iter().flatten() {
                let delay = deadline.saturating_sub(current);
                timeout = Some(timeout.map_or(delay, |previous| previous.min(delay)));
            }
            if let Some(delay) = device.backend.transmit_retry_delay() {
                timeout = Some(timeout.map_or(delay, |previous| previous.min(delay)));
            }
            if timeout.is_some_and(|duration| duration.is_zero()) {
                continue;
            }
            let mut poller = Poller::new(timeout.as_ref());
            let mut ready = !model
                .endpoint
                .poll_change(generation, poller.as_handle_mut())
                .is_empty();
            if tcp_flows.len() + udp_flows.len() + inbound_datagrams.len() < MAX_FLOWS {
                for (index, (listener, _)) in listeners.iter().enumerate() {
                    if accept_retry[index].is_none() {
                        ready |= !listener.poll(Some(poller.as_handle_mut())).is_empty();
                    }
                }
                for (listener, _) in &datagram_listeners {
                    ready |= !listener
                        .poll(IoEvents::IN, poller.as_handle_mut())
                        .is_empty();
                }
            }
            for flow in &tcp_flows {
                if !flow.alive {
                    continue;
                }
                let Some(host) = &flow.host else {
                    continue;
                };
                let guest = sockets.get::<tcp::Socket>(flow.handle);
                let mut events = IoEvents::empty();
                if host.is_connecting() || !flow.to_host.is_empty() || guest.can_recv() {
                    events |= IoEvents::OUT;
                }
                if !flow.host_eof && guest.can_send() {
                    events |= IoEvents::IN;
                }
                if !events.is_empty() {
                    ready |= !host.poll(events, poller.as_handle_mut()).is_empty();
                }
            }
            for flow in udp_flows.values() {
                if sockets.get::<udp::Socket>(flow.handle).can_send() {
                    ready |= !flow
                        .host
                        .poll(IoEvents::IN, poller.as_handle_mut())
                        .is_empty();
                }
            }
            if !ready {
                match poller.wait() {
                    Ok(()) => {}
                    Err(error) if error.error() == Errno::ETIME => {}
                    Err(error) => return Err(error),
                }
            }
        }
    })();
    drop(sockets);
    drop(tcp_flows);
    drop(udp_flows);
    drop(inbound_datagrams);
    drop(udp_sockets);
    result
}

// The frontend socket belongs to this worker alone. These closures hold no
// frontend lock while calling the existing nonblocking native socket APIs.
// Commit only bytes accepted by the other socket; EAGAIN preserves the queue.
fn forward_tcp_recv(
    guest: &mut tcp::Socket,
    write_fn: impl FnOnce(&[u8]) -> Result<usize>,
) -> Result<usize> {
    guest
        .recv(|bytes| {
            let count = bytes.len().min(TCP_FORWARD_BYTES);
            let result = write_fn(&bytes[..count]);
            (result.as_ref().copied().unwrap_or(0), result)
        })
        .map_err(guest_socket_error)?
}

fn forward_tcp_send(
    guest: &mut tcp::Socket,
    read_fn: impl FnOnce(&mut [u8]) -> Result<usize>,
) -> Result<usize> {
    guest
        .send(|bytes| {
            let count = bytes.len().min(TCP_FORWARD_BYTES);
            let result = read_fn(&mut bytes[..count]);
            (result.as_ref().copied().unwrap_or(0), result)
        })
        .map_err(guest_socket_error)?
}

struct TcpFlow {
    handle: SocketHandle,
    host: Option<TcpStream>,
    to_host: VecDeque<u8>,
    last_active: Duration,
    alive: bool,
    host_eof: bool,
    guest_eof: bool,
    guest_time_wait: bool,
    drain_charge: Option<FlowCharge>,
    requested: Option<(IpEndpoint, IpEndpoint)>,
    write_closed: bool,
    _charge: FlowCharge,
}
impl TcpFlow {
    fn new(handle: SocketHandle, host: TcpStream, charge: FlowCharge) -> Self {
        Self {
            handle,
            host: Some(host),
            to_host: VecDeque::with_capacity(BUFFER_BYTES),
            last_active: now(),
            alive: true,
            host_eof: false,
            guest_eof: false,
            guest_time_wait: false,
            drain_charge: None,
            requested: None,
            write_closed: false,
            _charge: charge,
        }
    }
    #[cfg(kernelet_nat_failure_diag)]
    fn log_failure(
        &self,
        #[cfg(kernelet_nat_failure_diag_host)] model: &NetWorker,
        guest: &tcp::Socket,
        stage: &'static str,
        error: &Error,
    ) {
        #[cfg(kernelet_nat_failure_diag_host)]
        {
            let context = self.host.as_ref().unwrap().failure_context(
                self.handle,
                self.requested,
                guest,
                stage,
                error,
            );
            model.record_diagnostic(NatEvent::FlowFailure, context, Some(error.error()));
        }
        #[cfg(not(kernelet_nat_failure_diag_host))]
        error!(
            "kernelet NAT failure stage={} handle={:?} requested={:?} guest_local={:?} guest_remote={:?} guest_state={:?} errno={:?} error={:?}",
            stage,
            self.handle,
            self.requested,
            guest.local_endpoint(),
            guest.remote_endpoint(),
            guest.state(),
            error.error(),
            error,
        );
    }
    fn flush_to_host(
        &mut self,
        #[cfg(kernelet_nat_failure_diag_host)] model: &NetWorker,
        guest: &mut tcp::Socket,
    ) -> bool {
        loop {
            let snapshot = !self.to_host.is_empty();
            let result = if snapshot {
                let (first, _) = self.to_host.as_slices();
                self.host.as_ref().unwrap().write(first)
            } else if !self.guest_eof && guest.can_recv() {
                forward_tcp_recv(guest, |bytes| self.host.as_ref().unwrap().write(bytes))
            } else {
                break;
            };
            match result {
                Ok(0) => {
                    let error =
                        Error::with_message(Errno::EPIPE, "native NAT TCP write made no progress");
                    debug!("kernelet TCP send failed: {:?}", error);
                    #[cfg(kernelet_nat_failure_diag)]
                    self.log_failure(
                        #[cfg(kernelet_nat_failure_diag_host)]
                        model,
                        guest,
                        "send_zero",
                        &error,
                    );
                    guest.abort();
                    self.alive = false;
                    return false;
                }
                Ok(length) => {
                    if snapshot {
                        self.to_host.drain(..length);
                    }
                    self.last_active = now();
                    if !snapshot {
                        break;
                    }
                }
                Err(error) if error.error() == Errno::EAGAIN => break,
                Err(error) => {
                    debug!("kernelet TCP send failed: {:?}", error);
                    #[cfg(kernelet_nat_failure_diag)]
                    self.log_failure(
                        #[cfg(kernelet_nat_failure_diag_host)]
                        model,
                        guest,
                        "send",
                        &error,
                    );
                    guest.abort();
                    self.alive = false;
                    return false;
                }
            }
        }
        true
    }

    fn forward(&mut self, model: &NetWorker, guest: &mut tcp::Socket) {
        if !self.alive {
            return;
        }
        if self.host.is_none() {
            // The native background already owns the orderly close. The Guest
            // socket still completes its existing FIN/ACK retirement policy.
            self.alive = guest.is_open();
            return;
        }
        if guest.state() == tcp::State::Closed {
            // TIME_WAIT expiry resets rx_fin_received; an accepted RST does
            // not. This distinguishes the timer from a Guest abort after the
            // TIME_WAIT receive queue was transferred in an earlier call.
            let time_wait_expired = self.guest_time_wait
                && guest.recv_queue() == 0
                && matches!(guest.recv_slice(&mut []), Err(tcp::RecvError::InvalidState));
            if !time_wait_expired {
                self.alive = false;
                return;
            }
        }
        match guest.state() {
            tcp::State::CloseWait | tcp::State::Closing | tcp::State::LastAck => {
                self.guest_eof = true;
            }
            tcp::State::TimeWait => {
                self.guest_eof = true;
                self.guest_time_wait = true;
            }
            _ => {}
        }
        match self.host.as_mut().unwrap().finish_connect() {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                debug!("kernelet TCP connect failed: {:?}", error);
                #[cfg(kernelet_nat_failure_diag)]
                self.log_failure(
                    #[cfg(kernelet_nat_failure_diag_host)]
                    model,
                    guest,
                    "finish_connect",
                    &error,
                );
                guest.abort();
                self.alive = false;
                return;
            }
        }
        match self.host.as_ref().unwrap().take_error(
            #[cfg(kernelet_nat_failure_diag_host)]
            model,
            #[cfg(kernelet_nat_failure_diag_host)]
            self.handle,
            #[cfg(kernelet_nat_failure_diag_host)]
            self.requested,
            #[cfg(kernelet_nat_failure_diag_host)]
            guest,
        ) {
            Ok(None) => {}
            Ok(Some(error)) | Err(error) => {
                debug!("kernelet TCP socket failed: {:?}", error);
                #[cfg(kernelet_nat_failure_diag)]
                self.log_failure(
                    #[cfg(kernelet_nat_failure_diag_host)]
                    model,
                    guest,
                    "socket_error",
                    &error,
                );
                guest.abort();
                self.alive = false;
                return;
            }
        }
        if !self.flush_to_host(
            #[cfg(kernelet_nat_failure_diag_host)]
            model,
            guest,
        ) {
            return;
        }
        if self.guest_eof {
            // A closing Guest can retain its entire receive buffer. Transfer
            // it before another poll can expire TIME_WAIT and clear it. Bound
            // malformed post-FIN input as well as previously blocked writes.
            let pending = self.to_host.len() + guest.recv_queue();
            if pending > 2 * BUFFER_BYTES {
                let error = Error::with_message(Errno::ENOBUFS, "closing NAT TCP queue is full");
                debug!("kernelet TCP closing receive failed: {:?}", error);
                #[cfg(kernelet_nat_failure_diag)]
                self.log_failure(
                    #[cfg(kernelet_nat_failure_diag_host)]
                    model,
                    guest,
                    "closing_capacity",
                    &error,
                );
                guest.abort();
                self.alive = false;
                return;
            }
            if pending > BUFFER_BYTES && self.drain_charge.is_none() {
                match FlowCharge::with_bytes(
                    model,
                    BUFFER_BYTES,
                    #[cfg(kernelet_nat_failure_diag_host)]
                    {
                        let mut context = NatContext::new("closing_tcp_drain_reserve");
                        context.flow_handle = Some(self.handle);
                        context.guest_local = guest.local_endpoint().and_then(ipv4_endpoint);
                        context.guest_remote = guest.remote_endpoint().and_then(ipv4_endpoint);
                        if let Some((source, destination)) = self.requested {
                            context.requested = ipv4_pair(source, destination);
                        }
                        context
                    },
                    #[cfg(kernelet_nat_failure_diag_host)]
                    QuotaClass::NatExtraDrain,
                ) {
                    Ok(charge) => self.drain_charge = Some(charge),
                    Err(error) => {
                        debug!("kernelet TCP closing reservation failed: {:?}", error);
                        #[cfg(kernelet_nat_failure_diag)]
                        self.log_failure(
                            #[cfg(kernelet_nat_failure_diag_host)]
                            model,
                            guest,
                            "closing_reservation",
                            &error,
                        );
                        guest.abort();
                        self.alive = false;
                        return;
                    }
                }
            }
            while guest.can_recv() {
                let length = match guest.recv(|bytes| {
                    let length = bytes.len();
                    self.to_host.extend(bytes.iter().copied());
                    (length, length)
                }) {
                    Ok(length) => length,
                    Err(error) => {
                        let _error = guest_socket_error(error);
                        #[cfg(kernelet_nat_failure_diag)]
                        self.log_failure(
                            #[cfg(kernelet_nat_failure_diag_host)]
                            model,
                            guest,
                            "closing_receive",
                            &_error,
                        );
                        guest.abort();
                        self.alive = false;
                        return;
                    }
                };
                if length != 0 {
                    self.last_active = now();
                }
            }
            // A closing socket must preserve its snapshot before a later
            // protocol poll can expire TIME_WAIT and clear the receive ring.
            if !self.flush_to_host(
                #[cfg(kernelet_nat_failure_diag_host)]
                model,
                guest,
            ) {
                return;
            }
        }
        if guest.can_send() && !self.host_eof {
            match forward_tcp_send(guest, |bytes| self.host.as_ref().unwrap().read(bytes)) {
                Ok(0) => {
                    self.host_eof = true;
                }
                Ok(length) => {
                    if length != 0 {
                        self.last_active = now();
                    }
                }
                Err(error) if error.error() == Errno::EAGAIN => {}
                Err(error) => {
                    debug!("kernelet TCP receive failed: {:?}", error);
                    #[cfg(kernelet_nat_failure_diag)]
                    self.log_failure(
                        #[cfg(kernelet_nat_failure_diag_host)]
                        model,
                        guest,
                        "receive",
                        &error,
                    );
                    guest.abort();
                    self.alive = false;
                    return;
                }
            }
        }
        if self.guest_eof && self.to_host.is_empty() && !self.write_closed {
            if let Err(error) = self.host.as_ref().unwrap().shutdown_write() {
                debug!("kernelet TCP half-close failed: {:?}", error);
                #[cfg(kernelet_nat_failure_diag)]
                self.log_failure(
                    #[cfg(kernelet_nat_failure_diag_host)]
                    model,
                    guest,
                    "shutdown_write",
                    &error,
                );
                guest.abort();
                self.alive = false;
                return;
            }
            self.write_closed = true;
        }
        if self.host_eof
            && self.guest_eof
            && self.to_host.is_empty()
            && guest.recv_queue() == 0
            && self.write_closed
        {
            if let Err(error) = self.host.as_ref().unwrap().allow_graceful_drop() {
                debug!("kernelet TCP graceful close failed: {:?}", error);
                #[cfg(kernelet_nat_failure_diag)]
                self.log_failure(
                    #[cfg(kernelet_nat_failure_diag_host)]
                    model,
                    guest,
                    "graceful_close",
                    &error,
                );
                guest.abort();
                self.alive = false;
                return;
            }
            // Delay the Guest FIN until native handoff is safe. Otherwise
            // LastAck can become Closed while native writes remain blocked.
            guest.close();
            // Native TCP owns queued data, FIN and ACK handling. A successful
            // write only transfers ownership; it does not prove a peer ACK.
            drop(self.host.take());
            self.to_host = VecDeque::new();
            drop(self.drain_charge.take());
            self.alive = guest.is_open();
        } else if self.host_eof && !self.guest_eof {
            // A Host-first EOF must still reach a Guest that waits for it
            // before sending its remaining data and FIN.
            guest.close();
        }
    }
}
struct UdpPortFlow {
    listener: usize,
    peer: SocketAddrV4,
    handle: SocketHandle,
    last_active: Duration,
    _charge: FlowCharge,
}

fn udp_socket() -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUFFER_BYTES]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUFFER_BYTES]),
    )
}

struct UdpFlow {
    host: UdpSocket,
    last_active: Duration,
    handle: SocketHandle,
    _charge: FlowCharge,
}

fn prepare_incoming(
    frame: &[u8],
    config: &NetConfigArgs,
    model: &NetWorker,
    sockets: &mut SocketSet<'static>,
    tcp_flows: &mut Vec<TcpFlow>,
    udp_sockets: &mut BTreeMap<SocketAddrV4, UdpFrontend>,
) -> Result<()> {
    let ethernet = match EthernetFrame::new_checked(frame) {
        Ok(packet) if packet.ethertype() == EthernetProtocol::Ipv4 => packet,
        _ => return Ok(()),
    };
    let ipv4 = match Ipv4Packet::new_checked(ethernet.payload()) {
        Ok(packet) => packet,
        Err(_) => return Ok(()),
    };
    if ipv4.src_addr() != GUEST
        || !ipv4.verify_checksum()
        || ipv4.frag_offset() != 0
        || ipv4.more_frags()
    {
        return Ok(());
    }
    match ipv4.next_header() {
        IpProtocol::Tcp => {
            let packet = match TcpPacket::new_checked(ipv4.payload()) {
                Ok(packet)
                    if packet.syn()
                        && !packet.ack()
                        && packet.src_port() != 0
                        && packet.dst_port() != 0
                        && packet.verify_checksum(
                            &IpAddress::Ipv4(ipv4.src_addr()),
                            &IpAddress::Ipv4(ipv4.dst_addr()),
                        ) =>
                {
                    packet
                }
                _ => return Ok(()),
            };
            let source = IpEndpoint::new(IpAddress::Ipv4(ipv4.src_addr()), packet.src_port());
            let destination = IpEndpoint::new(IpAddress::Ipv4(ipv4.dst_addr()), packet.dst_port());
            #[cfg(kernelet_nat_failure_diag_host)]
            let context = {
                let mut context = NatContext::new("outbound_tcp_syn_reserve");
                context.requested = ipv4_pair(source, destination);
                context.translated = Some(translate_destination(
                    SocketAddrV4::new(ipv4.dst_addr(), packet.dst_port()),
                    config,
                ));
                context
            };
            if sockets.iter().count() >= MAX_FLOWS
                || tcp_flows.iter().any(|flow| {
                    let socket = sockets.get::<tcp::Socket>(flow.handle);
                    flow.requested == Some((source, destination))
                        || socket.remote_endpoint() == Some(source)
                            && socket.local_endpoint() == Some(destination)
                })
            {
                #[cfg(kernelet_nat_failure_diag_host)]
                if sockets.iter().count() >= MAX_FLOWS {
                    model.record_diagnostic(NatEvent::FlowCapacity, context, None);
                }
                return Ok(());
            }
            let Ok(mut charge) = FlowCharge::new(
                model,
                #[cfg(kernelet_nat_failure_diag_host)]
                context,
            ) else {
                return Ok(());
            };
            let host = match TcpStream::connect(
                translate_destination(
                    SocketAddrV4::new(ipv4.dst_addr(), packet.dst_port()),
                    config,
                ),
                charge.split_native_tcp(),
            ) {
                Ok(host) => host,
                Err(_error) => {
                    #[cfg(kernelet_nat_failure_diag_host)]
                    {
                        let mut context = context;
                        context.stage = "outbound_stream_create";
                        context.error = Some(_error);
                        model.record_diagnostic(
                            NatEvent::StreamCreate,
                            context,
                            Some(_error.error()),
                        );
                    }
                    #[cfg(all(kernelet_nat_failure_diag, not(kernelet_nat_failure_diag_host)))]
                    error!(
                        "kernelet NAT failure stage=outbound_stream_create source={:?} destination={:?} errno={:?} error={:?}",
                        source,
                        destination,
                        _error.error(),
                        _error,
                    );
                    return Ok(());
                }
            };
            let mut socket = tcp_socket();
            socket.listen(destination).map_err(guest_socket_error)?;
            let handle = sockets.add(socket);
            let mut flow = TcpFlow::new(handle, host, charge);
            flow.requested = Some((source, destination));
            tcp_flows.push(flow);
        }
        IpProtocol::Udp => {
            let packet = match UdpPacket::new_checked(ipv4.payload()) {
                Ok(packet)
                    if packet.src_port() != 0
                        && packet.dst_port() != 0
                        && packet.verify_checksum(
                            &IpAddress::Ipv4(ipv4.src_addr()),
                            &IpAddress::Ipv4(ipv4.dst_addr()),
                        ) =>
                {
                    packet
                }
                _ => return Ok(()),
            };
            let destination = SocketAddrV4::new(ipv4.dst_addr(), packet.dst_port());
            if sockets.iter().count() >= MAX_FLOWS
                || sockets.iter().any(|(_, socket)| {
                    matches!(socket, Socket::Udp(socket)
                    if socket.endpoint().port == destination.port()
                    && socket.endpoint().addr == Some(IpAddress::Ipv4(*destination.ip())))
                })
            {
                return Ok(());
            }
            let Ok(charge) = FlowCharge::new(
                model,
                #[cfg(kernelet_nat_failure_diag_host)]
                NatContext::new("udp_frontend_reserve"),
            ) else {
                return Ok(());
            };
            let mut socket = udp_socket();
            socket
                .bind((ipv4.dst_addr(), packet.dst_port()))
                .map_err(guest_socket_error)?;
            udp_sockets.insert(
                destination,
                UdpFrontend {
                    handle: sockets.add(socket),
                    _charge: charge,
                },
            );
        }
        _ => {}
    }
    Ok(())
}
#[cfg(kernelet_nat_failure_diag_host)]
fn ipv4_endpoint(endpoint: IpEndpoint) -> Option<SocketAddrV4> {
    match endpoint.addr {
        IpAddress::Ipv4(ip) => Some(SocketAddrV4::new(ip, endpoint.port)),
        _ => None,
    }
}

#[cfg(kernelet_nat_failure_diag_host)]
fn ipv4_pair(source: IpEndpoint, destination: IpEndpoint) -> Option<(SocketAddrV4, SocketAddrV4)> {
    match (source.addr, destination.addr) {
        (IpAddress::Ipv4(source_ip), IpAddress::Ipv4(destination_ip)) => Some((
            SocketAddrV4::new(source_ip, source.port),
            SocketAddrV4::new(destination_ip, destination.port),
        )),
        _ => None,
    }
}

fn translate_destination(destination: SocketAddrV4, config: &NetConfigArgs) -> SocketAddrV4 {
    if *destination.ip() == Ipv4Addr::new(10, 0, 2, 3) && destination.port() == 53 {
        SocketAddrV4::new(Ipv4Addr::from(config.host_resolver), 53)
    } else {
        destination
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
        tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
    );
    // A private bridge must not add another Nagle wait to the application's stream.
    socket.set_nagle_enabled(false);
    socket
}

// Monomorphization keeps shared handles out of the copying frame's inline
// array, including queue removal, the pending receive slot, and RxToken moves.
trait FrameBytes {
    fn with_bytes<R>(&self, read_fn: impl for<'a> FnOnce(&'a [u8]) -> R) -> R;
}

impl FrameBytes for Frame {
    fn with_bytes<R>(&self, read_fn: impl for<'a> FnOnce(&'a [u8]) -> R) -> R {
        Frame::with_bytes(self, read_fn)
    }
}

impl FrameBytes for SharedFrame {
    fn with_bytes<R>(&self, read_fn: impl for<'a> FnOnce(&'a [u8]) -> R) -> R {
        SharedFrame::with_bytes(self, read_fn)
    }
}

trait FrameBackend {
    type Frame: FrameBytes;
    type Transmit<'a>: TxToken
    where
        Self: 'a;

    fn pop_output(&self) -> Option<Self::Frame>;
    fn take_work(&self, model: &NetWorker) -> Option<Work>;
    fn can_transmit(&self) -> bool;
    fn prepare_transmit(&mut self) -> bool;
    fn transmit(&mut self) -> Option<Self::Transmit<'_>>;

    fn transmit_retry_delay(&mut self) -> Option<Duration> {
        None
    }
}

struct CopyFrames<'a>(&'a NetEndpoint);

impl FrameBackend for CopyFrames<'_> {
    type Frame = Frame;
    type Transmit<'a>
        = CopyTransmit<'a>
    where
        Self: 'a;

    fn pop_output(&self) -> Option<Frame> {
        self.0.pop_output()
    }

    fn take_work(&self, model: &NetWorker) -> Option<Work> {
        model.take_work()
    }

    fn can_transmit(&self) -> bool {
        self.0.input_has_space()
    }

    fn prepare_transmit(&mut self) -> bool {
        self.can_transmit()
    }

    fn transmit(&mut self) -> Option<CopyTransmit<'_>> {
        self.can_transmit().then_some(CopyTransmit(self.0))
    }
}

struct SharedFrames<'a> {
    endpoint: &'a NetEndpoint,
    transport: &'a Arc<SharedNetTransport>,
    // Unconsumed tokens borrow this slot, so the complete grant/import-credit
    // reservation survives the RX poll and can be used by its next reply.
    prepared: Option<SharedTxFrame>,
    import_blocked: bool,
}

impl SharedFrames<'_> {
    fn active(&self) -> bool {
        !self.endpoint.is_revoked() && !self.transport.is_cancelled()
    }
}

impl FrameBackend for SharedFrames<'_> {
    type Frame = SharedFrame;
    type Transmit<'a>
        = SharedTransmit<'a>
    where
        Self: 'a;

    fn pop_output(&self) -> Option<SharedFrame> {
        self.endpoint.pop_shared_output()
    }

    fn take_work(&self, _model: &NetWorker) -> Option<Work> {
        self.transport.take_work()
    }

    fn can_transmit(&self) -> bool {
        self.active() && (self.prepared.is_some() || self.transport.can_transmit())
    }

    fn prepare_transmit(&mut self) -> bool {
        if !self.active() {
            self.import_blocked = false;
            return false;
        }
        if self.prepared.is_none() {
            self.prepared = self.transport.allocate_frame();
            self.import_blocked = self.prepared.is_none() && self.transport.has_free_buffer();
        }
        self.prepared.is_some()
    }

    fn transmit(&mut self) -> Option<SharedTransmit<'_>> {
        self.prepare_transmit().then_some(SharedTransmit {
            prepared: &mut self.prepared,
        })
    }

    fn transmit_retry_delay(&mut self) -> Option<Duration> {
        // Import quota is shared with other connections, whose releases do
        // not notify this NIC. Retained empty returns need the same retry as
        // a failed new transmit reservation, including with a prepared token.
        let transmit_blocked = core::mem::take(&mut self.import_blocked);
        let return_blocked = self.transport.take_return_retry();
        ((transmit_blocked || return_blocked) && self.active()).then_some(IMPORT_CREDIT_RETRY_DELAY)
    }
}

struct FrameDevice<B: FrameBackend> {
    backend: B,
    received: Option<B::Frame>,
}

impl<B: FrameBackend> FrameDevice<B> {
    fn new(backend: B) -> Self {
        Self {
            backend,
            received: None,
        }
    }

    fn can_transmit(&self) -> bool {
        self.backend.can_transmit()
    }
}

struct Receive<F>(F);
struct CopyTransmit<'a>(&'a NetEndpoint);
struct SharedTransmit<'a> {
    prepared: &'a mut Option<SharedTxFrame>,
}

impl<T: FrameBytes> RxToken for Receive<T> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.0.with_bytes(f)
    }
}
impl TxToken for CopyTransmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= MAX_FRAME);
        // Preserve the copying backend's lazy inline-array initialization.
        let mut frame = Frame::empty();
        frame.len = len;
        let result = frame.with_bytes_mut(f);
        let _ = self.0.push_input(frame);
        result
    }
}

impl TxToken for SharedTransmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= MAX_FRAME);
        let mut frame = self
            .prepared
            .take()
            .expect("reserved shared transmit frame");
        let result = frame.with_bytes_mut(len, f);
        // This worker is already running. Publish directly to the Image using
        // the retained import credit; a concurrent close may discard delivery.
        let _ = frame.deliver(len);
        result
    }
}

impl<B: FrameBackend> Device for FrameDevice<B> {
    type RxToken<'a>
        = Receive<B::Frame>
    where
        Self: 'a;
    type TxToken<'a>
        = B::Transmit<'a>
    where
        Self: 'a;
    fn receive(&mut self, _: NetworkInstant) -> Option<(Receive<B::Frame>, B::Transmit<'_>)> {
        self.received.as_ref()?;
        let transmit = self.backend.transmit()?;
        Some((Receive(self.received.take()?), transmit))
    }
    fn transmit(&mut self, _: NetworkInstant) -> Option<B::Transmit<'_>> {
        self.backend.transmit()
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut result = DeviceCapabilities::default();
        result.medium = Medium::Ethernet;
        result.max_transmission_unit = MAX_FRAME;
        result.max_burst_size = Some(32);
        result
    }
}

#[cfg(ktest)]
mod source_port_tests {
    use core::cell::Cell;

    use ostd::prelude::*;

    use super::{FIRST_SOURCE_PORT, LAST_SOURCE_PORT, SOURCE_PORT_CYCLE, next_source_port};

    #[ktest]
    fn source_port_wrap_skips_live_ports() {
        let mut next = LAST_SOURCE_PORT;
        let occupied = [LAST_SOURCE_PORT, FIRST_SOURCE_PORT, FIRST_SOURCE_PORT + 1];
        assert_eq!(
            next_source_port(&mut next, |port| occupied.contains(&port)),
            Some(FIRST_SOURCE_PORT + 2)
        );
        assert_eq!(next, FIRST_SOURCE_PORT + 3);
        // Reclaimed ports are eligible on the next visit; no stale ledger persists.
        next = LAST_SOURCE_PORT;
        assert_eq!(
            next_source_port(&mut next, |port| port == FIRST_SOURCE_PORT),
            Some(LAST_SOURCE_PORT)
        );
        assert_eq!(next, FIRST_SOURCE_PORT);
    }

    #[ktest]
    fn source_port_exhaustion_is_bounded() {
        let mut next = FIRST_SOURCE_PORT + 10;
        let initial = next;
        let checks = Cell::new(0);
        assert_eq!(
            next_source_port(&mut next, |_| {
                checks.set(checks.get() + 1);
                true
            }),
            None
        );
        assert_eq!(checks.get(), SOURCE_PORT_CYCLE);
        assert_eq!(next, initial);
    }
}

#[cfg(all(ktest, kernelet_nat_failure_diag_host))]
mod mapped_tcp_admission_tests {
    use core::sync::atomic::{AtomicU32, Ordering};

    use ostd::{
        cpu::{CpuId, CpuSet, PinCurrentCpu},
        kernelet::{
            abi::MmioResult,
            control::{
                CpuBudget, Kernelet, KerneletConfig, KerneletHooks, KerneletKind, KerneletPolicy,
                KerneletState, KillReason,
            },
        },
        prelude::ktest,
        task::{Task, TaskOptions},
    };
    use spin::Once;

    use super::{super::VirtioNet, *};
    use crate::{
        endovisor::policy::{Admission, NatQuotaSnapshot},
        net::{
            init_loopback_for_ktest, poll_loopback_for_ktest,
            socket::{
                Socket,
                ip::{IpAddressFamily, StreamSocket},
                util::SocketAddr,
            },
        },
        process::Uid,
    };

    static INIT: Once<()> = Once::new();
    static FIXTURE_KIND: Once<KerneletKind> = Once::new();
    static NEXT_FIXTURE_ID: AtomicU32 = AtomicU32::new(0x6f80_0000);
    static NEXT_LISTENER_PORT: AtomicU32 = AtomicU32::new(49152);
    const TEST_WAIT: Duration = Duration::from_secs(5);

    #[ktest]
    fn shared_import_backpressure_retries_without_a_nic_notification() {
        let fixture = Fixture::new();
        let endpoint = NetEndpoint::new(fixture.uid, fixture.port.into());
        let shared = crate::endovisor::shared_net::SharedNet::new(
            &fixture.admission,
            fixture.model.kernelet.clone(),
            endpoint.clone(),
            [2, 0x71, 4, 0, 0, 2],
            33,
        )
        .unwrap();
        let other_link = fixture
            .model
            .kernelet
            .shared_buffer_host_endpoint()
            .unwrap();
        // Real import credits from a different private link exhaust the same
        // Image participant quota used by the NIC.
        let held: Vec<_> = (0..64)
            .map(|_| other_link.reserve_send(PAGE_SIZE).unwrap())
            .collect();
        let mut backend = SharedFrames {
            endpoint: &endpoint,
            transport: shared.transport_for_test(),
            prepared: None,
            import_blocked: false,
        };
        assert!(!backend.prepare_transmit());
        let retry = backend
            .transmit_retry_delay()
            .expect("import retry deadline");
        assert!(backend.transmit_retry_delay().is_none());
        assert!(!backend.prepare_transmit());
        assert_eq!(backend.transmit_retry_delay(), Some(retry));
        let generation = endpoint.generation();
        drop(held);
        assert_eq!(endpoint.generation(), generation);
        let mut poller = Poller::new(Some(&retry));
        assert!(
            endpoint
                .poll_change(generation, poller.as_handle_mut())
                .is_empty()
        );
        assert_eq!(poller.wait().unwrap_err().error(), Errno::ETIME);
        assert!(backend.prepare_transmit());
        assert!(backend.transmit_retry_delay().is_none());

        // Unused paired transmit tokens must retain the original reservation.
        for _ in 0..64 {
            drop(backend.transmit().unwrap());
        }
        let held: Vec<_> = (0..63)
            .map(|_| other_link.reserve_send(PAGE_SIZE).unwrap())
            .collect();
        assert!(other_link.reserve_send(PAGE_SIZE).is_err());
        drop(held);
        drop(backend);
        shared.cancel();
        drop(shared);
        other_link.close();
        endpoint.revoke();
        drop(endpoint);
        fixture.finish();
    }

    #[ktest]
    fn empty_returns_retry_with_an_unused_transmit_credit() {
        use ostd::kernelet::{abi::buffer, shared_buffer::SharedNetHeader};

        let fixture = Fixture::new();
        let image = &fixture.model.kernelet;
        let endpoint = NetEndpoint::new(fixture.uid, fixture.port.into());
        let shared = crate::endovisor::shared_net::SharedNet::new(
            &fixture.admission,
            image.clone(),
            endpoint.clone(),
            [2, 0x71, 4, 0, 0, 3],
            33,
        )
        .unwrap();
        let transport = shared.transport_for_test();
        let nic_connection = shared.info(buffer::NET_QUERY_CONNECTION).value;
        let other_link = image.shared_buffer_host_endpoint().unwrap();
        const TX_POOL_SIZE: usize = 32;
        const FRAME_LEN: usize = 14;
        // Put a complete Image TX pool onto the private NIC connection using
        // real owning handoffs. No response traffic is needed for this test.
        for _ in 0..TX_POOL_SIZE {
            let mut grant = other_link.allocate(PAGE_SIZE, Box::new(())).unwrap();
            grant
                .with_bytes_mut(0..SharedNetHeader::SIZE, |bytes| {
                    bytes.copy_from_slice(
                        &SharedNetHeader::new(SharedNetHeader::SIZE, FRAME_LEN, false)
                            .unwrap()
                            .encode(),
                    );
                })
                .unwrap();
            let payload = SharedNetHeader::SIZE + FRAME_LEN;
            grant
                .handoff(other_link.reserve_send(PAGE_SIZE).unwrap(), payload)
                .map_err(|(_, _, error)| error)
                .unwrap();
            let delivery = image.test_shared_buffer_service(
                buffer::RECEIVE,
                0,
                [other_link.connection(), 0, 0],
            );
            assert_eq!(delivery.status, 0);
            assert_ne!(delivery.value, 0);
            assert!(
                image
                    .test_shared_buffer_service(buffer::REDEEM, delivery.value, [0; 3])
                    .status
                    >= 0
            );
            assert_eq!(
                image
                    .test_shared_buffer_service(
                        buffer::HANDOFF,
                        delivery.value,
                        [nic_connection, buffer::READ_WRITE, payload as u64]
                    )
                    .status,
                0
            );
        }
        let mut backend = SharedFrames {
            endpoint: &endpoint,
            transport,
            prepared: None,
            import_blocked: false,
        };
        assert!(backend.prepare_transmit());
        // The unused paired transmit token owns the final import slot.
        let held: Vec<_> = (0..63)
            .map(|_| other_link.reserve_send(PAGE_SIZE).unwrap())
            .collect();
        for _ in 0..TX_POOL_SIZE {
            assert!(matches!(
                backend.take_work(&fixture.model),
                Some(Work::Progress)
            ));
            drop(endpoint.pop_shared_output().expect("queued Image frame"));
        }
        assert!(backend.take_work(&fixture.model).is_none());
        let retry = backend
            .transmit_retry_delay()
            .expect("empty-return retry deadline");
        assert!(backend.transmit_retry_delay().is_none());
        // A new failed return attempt arms one more retry, even though the
        // cached transmit reservation avoids a new transmit attempt.
        assert!(backend.take_work(&fixture.model).is_none());
        assert_eq!(backend.transmit_retry_delay(), Some(retry));
        let generation = endpoint.generation();
        drop(held);
        assert_eq!(endpoint.generation(), generation);
        let mut poller = Poller::new(Some(&retry));
        assert!(
            endpoint
                .poll_change(generation, poller.as_handle_mut())
                .is_empty()
        );
        assert_eq!(poller.wait().unwrap_err().error(), Errno::ETIME);
        for _ in 0..TX_POOL_SIZE {
            assert!(matches!(
                backend.take_work(&fixture.model),
                Some(Work::Progress)
            ));
            let delivery =
                image.test_shared_buffer_service(buffer::RECEIVE, 0, [nic_connection, 0, 0]);
            assert_eq!(delivery.status, 0);
            assert_ne!(delivery.value, 0);
            assert_eq!(
                image
                    .test_shared_buffer_service(buffer::DISCARD, delivery.value, [0; 3])
                    .status,
                0
            );
        }
        assert!(backend.take_work(&fixture.model).is_none());
        assert!(backend.transmit_retry_delay().is_none());
        drop(backend);
        shared.cancel();
        drop(shared);
        other_link.close();
        endpoint.revoke();
        drop(endpoint);
        fixture.finish();
    }

    #[ktest]
    fn empty_mapped_tcp_listener_does_not_request_full_uid_quota() {
        let fixture = Fixture::new();
        let before = fixture.quota_snapshot();
        let filler = fixture.fill_quota(before);
        assert!(!fixture.listener().poll(None).contains(IoEvents::IN));

        // The old admission-first body returns the real ENOSPC here, even
        // though there is no connection. Final byte equality alone would
        // miss successful reserve/EAGAIN/refund churn with spare quota.
        match accept_mapped_tcp(&fixture.model, fixture.listener(), fixture.context()) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("empty listener unexpectedly accepted a connection"),
            Err(error) => panic!("empty listener attempted flow admission: {error:?}"),
        }
        assert_eq!(fixture.host_bytes(), fixture.baseline_host_bytes);
        assert_eq!(fixture.quota_snapshot().endpoint_bytes, Some(before.limit));

        drop(filler);
        assert_eq!(
            fixture.quota_snapshot().endpoint_bytes,
            before.endpoint_bytes
        );
        fixture.finish();
    }

    #[ktest]
    fn quota_blocked_pending_tcp_accept_waits_for_retry_deadline() {
        let fixture = Fixture::new();
        let client = fixture.connect_client();
        let before = fixture.quota_snapshot();
        let filler = fixture.fill_quota(before);
        let mut retry = None;
        let start = Duration::from_secs(1);
        let result = accept_mapped_tcp_with_backoff(
            &fixture.model,
            fixture.listener(),
            &mut retry,
            start,
            fixture.context(),
        );
        assert!(matches!(result, Err(error) if error.error() == Errno::ENOSPC));
        let attempts = fixture.quota_snapshot().attempt;
        assert_eq!(retry, Some(start + ACCEPT_RETRY_DELAY));
        assert!(fixture.listener().poll(None).contains(IoEvents::IN));
        for _ in 0..32 {
            assert!(
                accept_mapped_tcp_with_backoff(
                    &fixture.model,
                    fixture.listener(),
                    &mut retry,
                    start + ACCEPT_RETRY_DELAY / 2,
                    fixture.context()
                )
                .unwrap()
                .is_none()
            );
        }
        // A retained pending connection must not repeatedly enter UID admission.
        // The snapshot query itself is one diagnostic admission attempt.
        assert_eq!(fixture.quota_snapshot().attempt, attempts + 1);
        drop(filler);
        let (stream, charge) = accept_mapped_tcp_with_backoff(
            &fixture.model,
            fixture.listener(),
            &mut retry,
            start + ACCEPT_RETRY_DELAY,
            fixture.context(),
        )
        .unwrap()
        .expect("deadline retry must consume the pending connection");
        assert_eq!(retry, None);
        drop((stream, charge, client));
        assert!(poll_until(
            || fixture.host_bytes() == fixture.baseline_host_bytes
        ));
        fixture.finish();
    }

    #[ktest]
    fn pending_mapped_tcp_connection_requires_quota_before_accept() {
        let fixture = Fixture::new();
        let client = fixture.connect_client();
        let before = fixture.quota_snapshot();
        let filler = fixture.fill_quota(before);

        match accept_mapped_tcp(&fixture.model, fixture.listener(), fixture.context()) {
            Err(error) => assert_eq!(error.error(), Errno::ENOSPC),
            _ => panic!("pending connection bypassed the real UID quota limit"),
        }
        assert!(fixture.listener().poll(None).contains(IoEvents::IN));
        assert_eq!(fixture.host_bytes(), fixture.baseline_host_bytes);
        assert_eq!(fixture.quota_snapshot().endpoint_bytes, Some(before.limit));

        drop(filler);
        let (stream, charge) =
            accept_mapped_tcp(&fixture.model, fixture.listener(), fixture.context())
                .unwrap()
                .expect("quota release must allow the still-pending connection");
        assert!(!fixture.listener().poll(None).contains(IoEvents::IN));
        assert_eq!(
            fixture.host_bytes(),
            fixture.baseline_host_bytes + FLOW_RESERVATION_BYTES
        );
        assert_eq!(
            fixture.quota_snapshot().endpoint_bytes,
            Some(before.endpoint_bytes.unwrap() + FLOW_RESERVATION_BYTES)
        );

        drop(stream);
        drop(charge);
        drop(client);
        // Native TCP retains its split charge through its real protocol
        // lifetime. Poll the actual loopback until that owner releases it.
        assert!(poll_until(
            || fixture.host_bytes() == fixture.baseline_host_bytes
        ));
        assert_eq!(
            fixture.quota_snapshot().endpoint_bytes,
            before.endpoint_bytes
        );
        fixture.finish();
    }

    #[ktest]
    fn empty_native_accept_eagain_refunds_both_real_split_charges() {
        let fixture = Fixture::new();
        let before = fixture.quota_snapshot();
        let mut charge = FlowCharge::new(&fixture.model, fixture.context()).unwrap();
        assert_eq!(
            fixture.host_bytes(),
            fixture.baseline_host_bytes + FLOW_RESERVATION_BYTES
        );
        assert_eq!(
            fixture.quota_snapshot().endpoint_bytes,
            Some(before.endpoint_bytes.unwrap() + FLOW_RESERVATION_BYTES)
        );

        // This is the real callee's EAGAIN/RAII boundary. It does not force
        // a readiness-versus-accept race in accept_mapped_tcp or run a worker.
        let result =
            fixture
                .listener()
                .accept(charge.split_native_tcp(), &fixture.model, fixture.context());
        assert_eq!(
            result.err().expect("empty accept must fail").error(),
            Errno::EAGAIN
        );
        let retained = FLOW_RESERVATION_BYTES - NATIVE_TCP_RESERVATION_BYTES;
        assert_eq!(fixture.host_bytes(), fixture.baseline_host_bytes + retained);
        assert_eq!(
            fixture.quota_snapshot().endpoint_bytes,
            Some(before.endpoint_bytes.unwrap() + retained)
        );
        drop(charge);
        assert_eq!(fixture.host_bytes(), fixture.baseline_host_bytes);
        assert_eq!(
            fixture.quota_snapshot().endpoint_bytes,
            before.endpoint_bytes
        );
        fixture.finish();
    }

    struct Fixture {
        uid: Uid,
        model: NetWorker,
        copy_device: Arc<VirtioNet>,
        admission: Arc<Admission>,
        listener: Option<TcpListener>,
        listener_reservation: Option<Arc<crate::endovisor::NativeTcpBufferCharge>>,
        port: u16,
        baseline_host_bytes: usize,
        cleanup_attempted: bool,
    }

    impl Fixture {
        fn new() -> Self {
            INIT.call_once(|| {
                crate::time::clocks::init_for_ktest();
                crate::util::random::init();
                init_loopback_for_ktest();
                crate::endovisor::reaper::init().unwrap();
            });
            let kind = FIXTURE_KIND.call_once(|| KerneletKind::register_dormant_fixture().unwrap());
            let cid = NEXT_FIXTURE_ID
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .unwrap();
            let uid = Uid::new(cid);
            let admission = Admission::reserve(uid, 1, 1, 0).unwrap();
            let cpu = ostd::irq::disable_local().current_cpu();
            let mut cpus = CpuSet::new_empty();
            cpus.add(cpu);
            let owner = kind
                .create(
                    &KerneletConfig {
                        cmdline: "",
                        initial_grains: 1,
                        max_grains: 1,
                        max_meta_sections: 1,
                        budget: CpuBudget::default(),
                        policy: KerneletPolicy::default(),
                        max_tasks: 1,
                        devices: &[],
                        cpus,
                    },
                    Arc::new(DormantHooks),
                )
                .unwrap();
            admission.mark_created();
            let baseline_host_bytes = owner.stats().host_bytes_charged;
            let endpoint = NetEndpoint::new(uid, cid);
            let copy_device = VirtioNet::new(owner, endpoint, [2, 0x71, 4, 0, 0, 1], 32);
            let model = NetWorker::for_copy(copy_device.clone());
            let mut fixture = Self {
                uid,
                model,
                copy_device,
                admission,
                listener: None,
                listener_reservation: None,
                port: 0,
                baseline_host_bytes,
                cleanup_attempted: false,
            };
            fixture.listener_reservation =
                Some(Arc::new(crate::endovisor::NativeTcpBufferCharge::prestart(
                    fixture
                        .model
                        .endpoint
                        .reserve_backend_bytes(
                            super::super::sockets::TCP_LISTENER_RESERVATION_BYTES,
                        )
                        .unwrap(),
                )));
            let port = NEXT_LISTENER_PORT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    (next < u16::MAX as u32).then_some(next + 1)
                })
                .unwrap();
            fixture.port = u16::try_from(port).unwrap();
            fixture.listener = Some(
                TcpListener::bind(
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, fixture.port),
                    fixture.listener_reservation.as_ref().unwrap().clone(),
                )
                .unwrap(),
            );
            fixture
        }

        fn listener(&self) -> &TcpListener {
            self.listener.as_ref().unwrap()
        }

        fn context(&self) -> NatContext {
            self.listener()
                .diagnostic_context("test_mapped_tcp_admission", 18080)
        }

        fn host_bytes(&self) -> usize {
            self.model.kernelet.stats().host_bytes_charged
        }

        fn quota_snapshot(&self) -> NatQuotaSnapshot {
            let mut failure = None;
            // This rejected addition copies the real UID row under LEDGER.
            // It never acquires a charge or allocates a local Ledger.
            let result = UserEndpointReservation::reserve_diagnostic(
                self.uid,
                usize::MAX,
                QuotaTag::new(QuotaClass::TestOnly, None),
                &mut failure,
                None,
            );
            assert_eq!(result.err().unwrap().error(), Errno::ENOSPC);
            let snapshot = failure.unwrap();
            assert_eq!(snapshot.owner, self.uid);
            assert_eq!(snapshot.endpoint_bytes, snapshot.prestart_bytes);
            snapshot
        }

        fn fill_quota(&self, before: NatQuotaSnapshot) -> UserEndpointReservation {
            let available = before
                .limit
                .checked_sub(before.endpoint_bytes.unwrap())
                .unwrap();
            assert!(available > 0);
            UserEndpointReservation::reserve(
                self.uid,
                available,
                QuotaTag::new(QuotaClass::TestOnly, None),
            )
            .unwrap()
        }

        fn connect_client(&self) -> Arc<StreamSocket> {
            let client = StreamSocket::new(true, IpAddressFamily::IPv4);
            match client.connect(SocketAddr::IPv4(Ipv4Addr::LOCALHOST, self.port)) {
                Ok(()) => {}
                Err(error) => assert_eq!(error.error(), Errno::EINPROGRESS),
            }
            assert!(poll_until(|| self
                .listener()
                .poll(None)
                .contains(IoEvents::IN)));
            client
        }

        fn cleanup(&mut self) -> bool {
            drop(self.listener.take());
            drop(self.listener_reservation.take());
            self.copy_device.cancel();
            self.model.endpoint.revoke();
            if !poll_until(|| self.host_bytes() == self.baseline_host_bytes) {
                error!(
                    "NAT admission fixture retained native Host charges for UID {:?}",
                    self.uid
                );
                return false;
            }
            let owner = &self.model.kernelet;
            if owner.state() == KerneletState::Created
                && let Err(error) = owner.kill(KillReason::Requested)
            {
                error!("NAT admission fixture kill failed: {:?}", error);
                return false;
            }
            if !poll_until(|| owner.state() == KerneletState::Exited) {
                error!("NAT admission fixture did not exit: {:?}", owner.state());
                return false;
            }
            match owner.destroy() {
                Ok(_) => self.admission.release_after_destroy(),
                Err(error) => {
                    error!("NAT admission fixture destroy failed: {:?}", error);
                    return false;
                }
            }
            true
        }

        fn finish(mut self) {
            let cleaned = self.cleanup();
            self.cleanup_attempted = true;
            assert!(cleaned, "NAT admission fixture teardown failed");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if !self.cleanup_attempted {
                self.cleanup_attempted = true;
                // An unwinding red test still attempts real destruction.
                // Failed teardown retains admission rather than faking refunds.
                if !self.cleanup() {
                    error!("NAT admission fixture teardown retained UID {:?}", self.uid);
                }
            }
        }
    }

    fn poll_until(mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = now() + TEST_WAIT;
        loop {
            poll_loopback_for_ktest();
            if predicate() {
                return true;
            }
            if now() >= deadline {
                return false;
            }
            Task::yield_now();
        }
    }
    struct DormantHooks;

    impl KerneletHooks for DormantHooks {
        fn create_vcpu_thread(
            &self,
            _: &Arc<Kernelet>,
            _: u16,
            _: CpuId,
            _: i8,
        ) -> ostd::Result<Arc<Task>> {
            TaskOptions::new(|| panic!("NAT admission fixture carrier must stay dormant"))
                .data(())
                .build()
                .map(Arc::new)
        }

        fn realtime_now(&self) -> Duration {
            Duration::ZERO
        }

        fn mmio_read(&self, _: u16, _: u32, _: u32) -> MmioResult {
            panic!("NAT admission fixture must not execute Image MMIO")
        }

        fn mmio_write(&self, _: u16, _: u32, _: u32, _: u64) -> i64 {
            panic!("NAT admission fixture must not execute Image MMIO")
        }

        fn log(&self, _: u32, _: &str, _: &str) -> bool {
            panic!("NAT admission fixture must not execute Image logging")
        }

        fn set_vcpu_nice(&self, _: i8) -> ostd::Result<()> {
            panic!("NAT admission fixture must not change a dormant carrier's budget")
        }
    }
}
