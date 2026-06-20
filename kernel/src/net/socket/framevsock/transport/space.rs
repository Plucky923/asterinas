// SPDX-License-Identifier: MPL-2.0

//! FrameVsock transport space management.
//!
//! # Zero-Copy Design
//!
//! - Data packets (RRef<DataPacket>) are passed by ownership to Connected sockets
//! - Control packets (RRef<ControlPacket>) are processed and dropped
//! - No intermediate buffer copies
//!
//! # Performance Optimizations
//!
//! - Uses HashMap for O(1) socket lookup (critical for packet dispatch)
//! - Uses HashSet for O(1) port availability check

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{ConnectionId, ControlPacket, DataPacket, VsockOp};
use hashbrown::{HashMap, hash_map::Entry};
use ostd::sync::LocalIrqDisabled;

use super::{Connected, Listener, PortTable};
use crate::{
    net::socket::framevsock::{addr::FrameVsockAddr, backend, stream::connecting::Connecting},
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
        let vcpu_count = backend::vcpu_count();
        let mut vcpu_conns = Vec::with_capacity(vcpu_count);
        for _ in 0..vcpu_count {
            vcpu_conns.push(hashbrown::HashSet::new());
        }
        Self {
            connecting_sockets: SpinLock::new(HashMap::new()),
            listen_sockets: SpinLock::new(HashMap::new()),
            connected_sockets: RwLock::new(HashMap::new()),
            vcpu_connections: SpinLock::new(vcpu_conns),
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
        let mut connected_sockets = self.connected_sockets.write();
        let Entry::Vacant(entry) = connected_sockets.entry(id) else {
            return_errno_with_message!(Errno::EADDRINUSE, "the FrameVsock connection exists");
        };
        entry.insert(connected);

        let mut vcpu_conns = self.vcpu_connections.disable_irq().lock();
        if vcpu_id < vcpu_conns.len() {
            vcpu_conns[vcpu_id].insert(id);
        }

        Ok(())
    }

    /// Remove a connected socket
    pub(in crate::net::socket::framevsock) fn remove_connected_socket(
        &self,
        id: &ConnectionId,
    ) -> Option<Arc<Connected>> {
        let mut connected_sockets = self.connected_sockets.write();
        let removed = connected_sockets.remove(id);

        // Maintain per-vCPU index
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

        let connected_sockets = self.connected_sockets.read();
        for conn_id in &conn_ids {
            if let Some(connected) = connected_sockets.get(conn_id) {
                if connected.is_tx_blocked_on_queue() {
                    connected.on_tx_queue_drained(queue_reserved_len_before_pop);
                }
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

    /// Dispatch incoming data packet to the appropriate socket
    /// This is called when Guest sends a data packet to Host
    ///
    /// Zero-copy: The packet RRef is passed by ownership to the connected socket
    pub(in crate::net::socket::framevsock) fn on_data_packet_received(
        &self,
        packet: RRef<DataPacket>,
    ) -> Result<()> {
        let src_addr = FrameVsockAddr::new(packet.header.src_cid, packet.header.src_port);
        let dst_addr = FrameVsockAddr::new(packet.header.dst_cid, packet.header.dst_port);
        let conn_id = ConnectionId::from_addrs(dst_addr, src_addr);

        if let Some(connected) = self.get_connected_socket(&conn_id) {
            // Zero-copy: pass packet ownership to connected socket
            return connected.on_data_packet_received(packet);
        }

        Ok(())
    }

    /// Dispatch incoming control packet to the appropriate socket
    /// This is called when Guest sends a control packet to Host
    pub(in crate::net::socket::framevsock) fn on_control_packet_received(
        &self,
        packet: RRef<ControlPacket>,
    ) -> Result<()> {
        let src_addr = FrameVsockAddr::new(packet.header.src_cid, packet.header.src_port);
        let dst_addr = FrameVsockAddr::new(packet.header.dst_cid, packet.header.dst_port);
        let conn_id = ConnectionId::from_addrs(dst_addr, src_addr);

        let op = packet.operation();

        match op {
            VsockOp::Request => {
                // Connection request from Guest to Host
                self.handle_request(&packet, src_addr, dst_addr)
            }
            VsockOp::Response => {
                // Connection response
                self.handle_response(&packet, src_addr, dst_addr)
            }
            VsockOp::Shutdown => {
                // Shutdown request
                self.handle_shutdown(&packet, conn_id)
            }
            VsockOp::Rst => {
                // Reset connection
                self.handle_rst(&packet, conn_id)
            }
            VsockOp::CreditUpdate => {
                // Flow control - credit update from peer
                self.handle_credit_update(&packet, conn_id)
            }
            VsockOp::CreditRequest => {
                // Flow control - peer requests credit info
                self.handle_credit_request(&packet, conn_id)
            }
            VsockOp::Rw | VsockOp::Invalid => Ok(()),
        }
    }

    /// Handle connection request from Guest
    fn handle_request(
        &self,
        packet: &ControlPacket,
        src_addr: FrameVsockAddr,
        dst_addr: FrameVsockAddr,
    ) -> Result<()> {
        let conn_id = ConnectionId::from_addrs(dst_addr.into(), src_addr.into());
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            connected.on_credit_update(packet.header.buf_alloc, packet.header.fwd_cnt);
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
                packet.header.buf_alloc,
                packet.header.fwd_cnt,
            ));

            // Add to the accept queue
            listen.push_incoming(connected.clone())?;

            // Also add to connected sockets map
            self.insert_connected_socket(conn_id, connected.clone())?;

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
        use aster_framevsock::create_response_with_credit;

        let packet = create_response_with_credit(
            local_addr.cid,
            local_addr.port,
            peer_addr.cid,
            peer_addr.port,
            connected.buf_alloc(),
            connected.fwd_cnt(),
        );

        // Deliver to the peer through the packet backend.
        let _ = backend::send_control(0, packet);
    }

    /// Send a RST packet to Guest
    fn send_rst_to_guest(&self, local_addr: FrameVsockAddr, peer_addr: FrameVsockAddr) {
        use aster_framevsock::create_rst;

        let packet = create_rst(
            local_addr.cid,
            local_addr.port,
            peer_addr.cid,
            peer_addr.port,
        );

        // Deliver to the peer through the packet backend.
        let _ = backend::send_control(0, packet);
    }

    /// Handle connection response
    fn handle_response(
        &self,
        packet: &ControlPacket,
        _src_addr: FrameVsockAddr,
        dst_addr: FrameVsockAddr,
    ) -> Result<()> {
        // Check if there's a connecting socket waiting for this response
        if let Some(connecting) = self.get_connecting_socket(&dst_addr) {
            // Update with peer's credit info
            connecting.set_connected_with_credit(packet.header.buf_alloc, packet.header.fwd_cnt);
        }
        Ok(())
    }

    /// Handle shutdown request
    fn handle_shutdown(&self, packet: &ControlPacket, conn_id: ConnectionId) -> Result<()> {
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            let should_remove = connected.on_shutdown_received(packet.header.flags as u32)?;
            if should_remove {
                self.remove_connected_socket(&conn_id);
                let src_addr = FrameVsockAddr::new(packet.header.src_cid, packet.header.src_port);
                let dst_addr = FrameVsockAddr::new(packet.header.dst_cid, packet.header.dst_port);
                self.send_rst_to_guest(dst_addr, src_addr);
            }
        }
        Ok(())
    }

    /// Handle reset
    fn handle_rst(&self, _packet: &ControlPacket, conn_id: ConnectionId) -> Result<()> {
        // Remove the connection from the map
        if let Some(connected) = self.remove_connected_socket(&conn_id) {
            connected.on_rst_received()?;
        } else if let Some(connecting) = self.remove_connecting_socket(&conn_id.local_addr) {
            connecting.set_failed();
        }
        Ok(())
    }

    /// Handle credit update from peer
    fn handle_credit_update(&self, packet: &ControlPacket, conn_id: ConnectionId) -> Result<()> {
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            connected.on_credit_update(packet.header.buf_alloc, packet.header.fwd_cnt);
        }
        Ok(())
    }

    /// Handle credit request from peer - send our credit info back
    fn handle_credit_request(&self, packet: &ControlPacket, conn_id: ConnectionId) -> Result<()> {
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            // Linux virtio-vsock semantics: every packet can carry credit info.
            // For backward compatibility, ignore zero buf_alloc from older peers
            // that did not populate credit fields in CreditRequest.
            if packet.header.buf_alloc != 0 {
                connected.on_credit_update(packet.header.buf_alloc, packet.header.fwd_cnt);
            }
            connected.send_credit_update();
        }
        Ok(())
    }
}

impl Default for FrameVsockSpace {
    fn default() -> Self {
        Self::new()
    }
}
