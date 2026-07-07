// SPDX-License-Identifier: MPL-2.0

//! FrameVsock transport space management.
//!
//! # Zero-Copy Design
//!
//! - Data carriers are passed by ownership to connected sockets
//! - Control carriers are processed and dropped
//! - No intermediate buffer copies
//!
//! # Performance Optimizations
//!
//! - Uses HashMap for O(1) socket lookup (critical for packet dispatch)
//! - Uses HashSet for O(1) port availability check

use framev_sock_common::{ConnectionId, FrameVsockPacket, VsockOp, cid_to_vm_id};
use hashbrown::{HashMap, hash_map::Entry};
use ostd::sync::LocalIrqDisabled;

use super::{Connected, Listener, PortTable};
use crate::{
    net::socket::framevsock::{
        addr::{FrameVsockAddr, VMADDR_CID_HOST},
        backend::{self, PacketCarrier},
        stream::connecting::Connecting,
    },
    prelude::*,
};

/// Manage all active sockets
pub(in crate::net::socket::framevsock) struct FrameVsockSpace {
    // (key, value) = (local_addr, connecting)
    // Using HashMap for O(1) lookup - connecting sockets are looked up during connection setup
    connecting_sockets: SpinLock<HashMap<FrameVsockAddr, Arc<Connecting>>>,
    // (key, value) = (local_addr, listen)
    // Using HashMap for O(1) lookup - listen sockets are looked up when handling connection requests
    listen_sockets: SpinLock<HashMap<FrameVsockAddr, Arc<Listener>>>,
    // (key, value) = (id(local_addr,peer_addr), connected)
    // Using HashMap for O(1) lookup - connected sockets are looked up for EVERY data packet
    // This is the most critical path for throughput
    connected_sockets: RwLock<HashMap<ConnectionId, Arc<Connected>>, LocalIrqDisabled>,
    // Per-vCPU index from vCPU ID to the set of ConnectionIds mapped to it.
    // Maintained alongside connected_sockets so notify_tx_queue_drained only
    // iterates connections on the target vCPU in O(k) instead of O(n).
    vcpu_connections: SpinLock<Vec<hashbrown::HashSet<ConnectionId>>>,
    ports: SpinLock<PortTable>,
}

impl FrameVsockSpace {
    /// Create a new global FrameVsockSpace
    pub(in crate::net::socket::framevsock) fn new() -> Self {
        Self {
            connecting_sockets: SpinLock::new(HashMap::new()),
            listen_sockets: SpinLock::new(HashMap::new()),
            connected_sockets: RwLock::new(HashMap::new()),
            vcpu_connections: SpinLock::new(Vec::new()),
            ports: SpinLock::new(PortTable::new()),
        }
    }

    /// Alloc an unused port range
    pub(in crate::net::socket::framevsock) fn alloc_ephemeral_port(&self) -> Result<u32> {
        self.ports.disable_irq().lock().alloc_ephemeral_port()
    }

    /// Bind a port
    pub(in crate::net::socket::framevsock) fn bind_port(&self, port: u32) -> bool {
        self.ports.disable_irq().lock().bind_exclusive(port)
    }

    /// Recycle a port
    pub(in crate::net::socket::framevsock) fn recycle_port(&self, port: &u32) -> bool {
        self.ports.disable_irq().lock().recycle(*port)
    }

    /// Insert a connected socket.
    pub(in crate::net::socket::framevsock) fn insert_connected_socket(
        &self,
        id: ConnectionId,
        connected: Arc<Connected>,
    ) -> Result<()> {
        let vcpu_id = connected.cached_vcpu_id();
        {
            let mut connected_sockets = self.connected_sockets.write();
            let Entry::Vacant(entry) = connected_sockets.entry(id) else {
                return_errno_with_message!(Errno::EADDRINUSE, "the FrameVsock connection exists");
            };
            entry.insert(connected);
        }

        let mut vcpu_conns = self.vcpu_connections.disable_irq().lock();
        if vcpu_id >= vcpu_conns.len() {
            vcpu_conns.resize_with(vcpu_id + 1, hashbrown::HashSet::new);
        }
        vcpu_conns[vcpu_id].insert(id);

        Ok(())
    }

    /// Remove a connected socket
    pub(in crate::net::socket::framevsock) fn remove_connected_socket(
        &self,
        id: &ConnectionId,
    ) -> Option<Arc<Connected>> {
        let removed = {
            let mut connected_sockets = self.connected_sockets.write();
            connected_sockets.remove(id)
        };

        // Maintain per-vCPU index.
        if let Some(ref conn) = removed {
            let vcpu_id = conn.cached_vcpu_id();
            let mut vcpu_conns = self.vcpu_connections.disable_irq().lock();
            if vcpu_id < vcpu_conns.len() {
                vcpu_conns[vcpu_id].remove(id);
            }
        }

        removed
    }

    /// Get a connected socket by connection ID
    pub(in crate::net::socket::framevsock) fn get_connected_socket(
        &self,
        id: &ConnectionId,
    ) -> Option<Arc<Connected>> {
        self.connected_sockets.read().get(id).cloned()
    }

    /// Notify host TX senders that a backend vCPU queue has drained.
    ///
    /// Queue pressure is per-vCPU queue, not per-connection packet identity.
    /// When Guest pops from a vCPU queue, any connection mapped to the same
    /// vCPU may become sendable again, even if the popped packet belongs to a
    /// different connection.
    pub(in crate::net::socket::framevsock) fn notify_tx_queue_drained(
        &self,
        vcpu_id: usize,
        queue_reserved_len_before_pop: usize,
    ) {
        // Notify on every queue-pop signal from FrameVisor and rely on per-connection
        // blocked-state filtering below. This avoids missing wakeups when queue
        // reservation snapshots race with producers around the full edge.

        // Use the per-vCPU index to only iterate connections on this vCPU.
        let conn_ids: Vec<ConnectionId> = {
            let vcpu_conns = self.vcpu_connections.disable_irq().lock();
            if vcpu_id < vcpu_conns.len() {
                vcpu_conns[vcpu_id].iter().copied().collect()
            } else {
                return;
            }
        };

        let connections: Vec<Arc<Connected>> = {
            let connected_sockets = self.connected_sockets.read();
            conn_ids
                .iter()
                .filter_map(|conn_id| connected_sockets.get(conn_id).cloned())
                .collect()
        };

        for connected in connections {
            if connected.is_tx_blocked_on_queue() {
                connected.on_tx_queue_drained(queue_reserved_len_before_pop);
            }
        }
    }

    /// Insert a connecting socket.
    pub(in crate::net::socket::framevsock) fn insert_connecting_socket(
        &self,
        addr: FrameVsockAddr,
        connecting: Arc<Connecting>,
    ) -> Result<()> {
        let mut connecting_sockets = self.connecting_sockets.disable_irq().lock();
        let Entry::Vacant(entry) = connecting_sockets.entry(addr) else {
            return_errno_with_message!(Errno::EADDRINUSE, "the FrameVsock port is connecting");
        };
        entry.insert(connecting);
        Ok(())
    }

    /// Remove a connecting socket
    pub(in crate::net::socket::framevsock) fn remove_connecting_socket(
        &self,
        addr: &FrameVsockAddr,
    ) -> Option<Arc<Connecting>> {
        let mut connecting_sockets = self.connecting_sockets.disable_irq().lock();
        connecting_sockets.remove(addr)
    }

    /// Get a connecting socket
    pub(in crate::net::socket::framevsock) fn get_connecting_socket(
        &self,
        addr: &FrameVsockAddr,
    ) -> Option<Arc<Connecting>> {
        self.connecting_sockets
            .disable_irq()
            .lock()
            .get(addr)
            .cloned()
    }

    /// Insert a listening socket.
    pub(in crate::net::socket::framevsock) fn insert_listen_socket(
        &self,
        addr: FrameVsockAddr,
        listen: Arc<Listener>,
    ) -> Result<()> {
        let mut listen_sockets = self.listen_sockets.disable_irq().lock();
        let Entry::Vacant(entry) = listen_sockets.entry(addr) else {
            return_errno_with_message!(Errno::EADDRINUSE, "the FrameVsock listener exists");
        };
        entry.insert(listen);
        Ok(())
    }

    /// Remove a listening socket
    pub(in crate::net::socket::framevsock) fn remove_listen_socket(
        &self,
        addr: &FrameVsockAddr,
    ) -> Option<Arc<Listener>> {
        let mut listen_sockets = self.listen_sockets.disable_irq().lock();
        listen_sockets.remove(addr)
    }

    /// Get a listening socket
    pub(in crate::net::socket::framevsock) fn get_listen_socket(
        &self,
        addr: &FrameVsockAddr,
    ) -> Option<Arc<Listener>> {
        self.listen_sockets.disable_irq().lock().get(addr).cloned()
    }

    /// Dispatches an incoming unified packet to the appropriate socket.
    pub(in crate::net::socket::framevsock) fn on_packet_received(
        &self,
        packet: PacketCarrier,
    ) -> Result<()> {
        let header = packet.packet().header();
        let src_addr = FrameVsockAddr::new(header.src_cid, header.src_port);
        let dst_addr = FrameVsockAddr::new(header.dst_cid, header.dst_port);
        if !is_valid_guest_to_host_control(src_addr, dst_addr) {
            return Ok(());
        }
        let conn_id = ConnectionId::from_addrs(dst_addr, src_addr);
        let op = packet.packet().operation();

        match op {
            VsockOp::Request => self.handle_request(packet.packet(), src_addr, dst_addr),
            VsockOp::Response => self.handle_response(packet.packet(), src_addr, dst_addr),
            VsockOp::Shutdown => self.handle_shutdown(packet.packet(), conn_id),
            VsockOp::Rst => self.handle_rst(conn_id),
            VsockOp::CreditUpdate => self.handle_credit_update(packet.packet(), conn_id),
            VsockOp::CreditRequest => self.handle_credit_request(packet.packet(), conn_id),
            VsockOp::Rw => {
                if let Some(connected) = self.get_connected_socket(&conn_id) {
                    return connected.on_packet_received(packet.into_packet());
                }
                Ok(())
            }
            VsockOp::Invalid => Ok(()),
        }
    }

    /// Handle connection request from Guest
    fn handle_request(
        &self,
        packet: &FrameVsockPacket,
        src_addr: FrameVsockAddr,
        dst_addr: FrameVsockAddr,
    ) -> Result<()> {
        let header = packet.header();
        let conn_id = ConnectionId::from_addrs(dst_addr.into(), src_addr.into());
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            connected.on_credit_update(header.buf_alloc, header.fwd_cnt);
            self.send_response_to_guest(&connected, dst_addr, src_addr);
            return Ok(());
        }

        // Check if there's a listening socket on the destination address
        if let Some(listen) = self.get_listen_socket(&dst_addr) {
            // Create a new connected socket for this connection
            // Pass the peer's credit info from the request packet
            let connected = Arc::new(Connected::new_passive_with_credit(
                src_addr,
                dst_addr,
                header.buf_alloc,
                header.fwd_cnt,
            ));

            // Reserve the connection before publishing it through accept().
            self.insert_connected_socket(conn_id, connected.clone())?;
            if let Err(error) = listen.push_incoming(connected.clone()) {
                self.remove_connected_socket(&conn_id);
                return Err(error);
            }

            // Send Response back to Guest with our credit info
            self.send_response_to_guest(&connected, dst_addr, src_addr);

            return Ok(());
        }

        // No listening socket found - send RST
        self.send_rst_to_guest(dst_addr, src_addr);
        Ok(())
    }

    /// Send a Response packet to Guest with credit info
    fn send_response_to_guest(
        &self,
        connected: &Connected,
        local_addr: FrameVsockAddr,
        peer_addr: FrameVsockAddr,
    ) {
        let packet = FrameVsockPacket::response(
            local_addr,
            peer_addr,
            connected.buf_alloc(),
            connected.fwd_cnt(),
        );

        Self::send_control_to_guest(0, packet);
    }

    /// Send a RST packet to Guest
    fn send_rst_to_guest(&self, local_addr: FrameVsockAddr, peer_addr: FrameVsockAddr) {
        let packet = FrameVsockPacket::rst(local_addr, peer_addr);

        Self::send_control_to_guest(0, packet);
    }

    fn send_control_to_guest(preferred_vcpu_id: usize, packet: FrameVsockPacket) {
        let mut packet = PacketCarrier::from_owned(packet);
        let mut retries = 0usize;
        loop {
            match backend::send_packet(preferred_vcpu_id, packet) {
                Ok(()) => {
                    break;
                }
                Err(returned_packet) => {
                    retries = retries.saturating_add(1);
                    if retries >= MAX_CONTROL_SEND_RETRIES {
                        break;
                    }
                    packet = returned_packet;
                    crate::thread::Thread::yield_now();
                }
            }
        }
    }

    /// Handle connection response
    fn handle_response(
        &self,
        packet: &FrameVsockPacket,
        src_addr: FrameVsockAddr,
        dst_addr: FrameVsockAddr,
    ) -> Result<()> {
        let header = packet.header();
        // Check if there's a connecting socket waiting for this response
        if let Some(connecting) = self.get_connecting_socket(&dst_addr) {
            if connecting.peer_addr() != src_addr {
                return Ok(());
            }
            // Update with peer's credit info
            connecting.set_connected_with_credit(header.buf_alloc, header.fwd_cnt);
        }
        Ok(())
    }

    /// Handle shutdown request
    fn handle_shutdown(&self, packet: &FrameVsockPacket, conn_id: ConnectionId) -> Result<()> {
        let header = packet.header();
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            let should_remove = connected.on_shutdown_received(header.flags)?;
            if should_remove {
                self.remove_connected_socket(&conn_id);
            }
        }
        Ok(())
    }

    /// Handle reset
    fn handle_rst(&self, conn_id: ConnectionId) -> Result<()> {
        // Remove the connection from the map
        if let Some(connected) = self.remove_connected_socket(&conn_id) {
            connected.on_rst_received()?;
        } else if let Some(connecting) = self.get_connecting_socket(&conn_id.local_addr) {
            if connecting.peer_addr() != conn_id.peer_addr {
                return Ok(());
            }
            let _ = self.remove_connecting_socket(&conn_id.local_addr);
            connecting.set_failed();
        }
        Ok(())
    }

    /// Handle credit update from peer
    fn handle_credit_update(&self, packet: &FrameVsockPacket, conn_id: ConnectionId) -> Result<()> {
        let header = packet.header();
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            connected.on_credit_update(header.buf_alloc, header.fwd_cnt);
        }
        Ok(())
    }

    /// Handle credit request from peer - send our credit info back
    fn handle_credit_request(
        &self,
        packet: &FrameVsockPacket,
        conn_id: ConnectionId,
    ) -> Result<()> {
        let header = packet.header();
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            // Linux virtio-vsock semantics: every packet can carry credit info.
            // For backward compatibility, ignore zero buf_alloc from older peers
            // that did not populate credit fields in CreditRequest.
            if header.buf_alloc != 0 {
                connected.on_credit_update(header.buf_alloc, header.fwd_cnt);
            }
            connected.send_credit_update();
        }
        Ok(())
    }
}

const MAX_CONTROL_SEND_RETRIES: usize = 1024;

fn is_valid_guest_to_host_control(src_addr: FrameVsockAddr, dst_addr: FrameVsockAddr) -> bool {
    dst_addr.cid == VMADDR_CID_HOST
        && src_addr.cid != VMADDR_CID_HOST
        && cid_to_vm_id(src_addr.cid).is_some()
}

impl Default for FrameVsockSpace {
    fn default() -> Self {
        Self::new()
    }
}
