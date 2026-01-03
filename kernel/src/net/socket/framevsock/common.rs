// SPDX-License-Identifier: MPL-2.0

//! FrameVsock space management
//!
//! # Zero-Copy Design
//!
//! - Data packets (RRef<DataPacket>) are passed by ownership to Connected sockets
//! - Control packets (RRef<ControlPacket>) are processed and dropped
//! - No intermediate buffer copies

use alloc::collections::BTreeSet;

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{ConnectionId, ControlPacket, DataPacket, VsockOp};
use log::debug;
use ostd::sync::LocalIrqDisabled;

use super::{
    addr::FrameVsockAddr,
    stream::{connected::Connected, connecting::Connecting, listen::Listen},
};
use crate::prelude::*;

/// Manage all active sockets
pub struct FrameVsockSpace {
    // (key, value) = (local_addr, connecting)
    connecting_sockets: SpinLock<BTreeMap<FrameVsockAddr, Arc<Connecting>>>,
    // (key, value) = (local_addr, listen)
    listen_sockets: SpinLock<BTreeMap<FrameVsockAddr, Arc<Listen>>>,
    // (key, value) = (id(local_addr,peer_addr), connected)
    connected_sockets: RwLock<BTreeMap<ConnectionId, Arc<Connected>>, LocalIrqDisabled>,
    // Used ports
    used_ports: SpinLock<BTreeSet<u32>>,
}

impl FrameVsockSpace {
    /// Create a new global FrameVsockSpace
    pub fn new() -> Self {
        Self {
            connecting_sockets: SpinLock::new(BTreeMap::new()),
            listen_sockets: SpinLock::new(BTreeMap::new()),
            connected_sockets: RwLock::new(BTreeMap::new()),
            used_ports: SpinLock::new(BTreeSet::new()),
        }
    }

    /// Alloc an unused port range
    pub fn alloc_ephemeral_port(&self) -> Result<u32> {
        let mut used_ports = self.used_ports.disable_irq().lock();
        for port in 1024..u32::MAX {
            if !used_ports.contains(&port) {
                used_ports.insert(port);
                return Ok(port);
            }
        }
        return_errno_with_message!(Errno::EAGAIN, "cannot find unused high port");
    }

    /// Bind a port
    pub fn bind_port(&self, port: u32) -> bool {
        let mut used_ports = self.used_ports.disable_irq().lock();
        used_ports.insert(port)
    }

    /// Recycle a port
    pub fn recycle_port(&self, port: &u32) -> bool {
        let mut used_ports = self.used_ports.disable_irq().lock();
        used_ports.remove(port)
    }

    /// Insert a connected socket
    pub fn insert_connected_socket(
        &self,
        id: ConnectionId,
        connected: Arc<Connected>,
    ) -> Option<Arc<Connected>> {
        let mut connected_sockets = self.connected_sockets.write();
        connected_sockets.insert(id, connected)
    }

    /// Remove a connected socket
    pub fn remove_connected_socket(&self, id: &ConnectionId) -> Option<Arc<Connected>> {
        let mut connected_sockets = self.connected_sockets.write();
        connected_sockets.remove(id)
    }

    /// Get a connected socket by connection ID
    pub fn get_connected_socket(&self, id: &ConnectionId) -> Option<Arc<Connected>> {
        self.connected_sockets.read().get(id).cloned()
    }

    /// Insert a connecting socket
    pub fn insert_connecting_socket(
        &self,
        addr: FrameVsockAddr,
        connecting: Arc<Connecting>,
    ) -> Option<Arc<Connecting>> {
        let mut connecting_sockets = self.connecting_sockets.disable_irq().lock();
        connecting_sockets.insert(addr, connecting)
    }

    /// Remove a connecting socket
    pub fn remove_connecting_socket(&self, addr: &FrameVsockAddr) -> Option<Arc<Connecting>> {
        let mut connecting_sockets = self.connecting_sockets.disable_irq().lock();
        connecting_sockets.remove(addr)
    }

    /// Get a connecting socket
    pub fn get_connecting_socket(&self, addr: &FrameVsockAddr) -> Option<Arc<Connecting>> {
        self.connecting_sockets
            .disable_irq()
            .lock()
            .get(addr)
            .cloned()
    }

    /// Insert a listening socket
    pub fn insert_listen_socket(
        &self,
        addr: FrameVsockAddr,
        listen: Arc<Listen>,
    ) -> Option<Arc<Listen>> {
        let mut listen_sockets = self.listen_sockets.disable_irq().lock();
        listen_sockets.insert(addr, listen)
    }

    /// Remove a listening socket
    pub fn remove_listen_socket(&self, addr: &FrameVsockAddr) -> Option<Arc<Listen>> {
        let mut listen_sockets = self.listen_sockets.disable_irq().lock();
        listen_sockets.remove(addr)
    }

    /// Get a listening socket
    pub fn get_listen_socket(&self, addr: &FrameVsockAddr) -> Option<Arc<Listen>> {
        self.listen_sockets.disable_irq().lock().get(addr).cloned()
    }

    /// Dispatch incoming data packet to the appropriate socket
    /// This is called when Guest sends a data packet to Host
    ///
    /// Zero-copy: The packet RRef is passed by ownership to the connected socket
    pub fn on_data_packet_received(&self, packet: RRef<DataPacket>) -> Result<()> {
        let src_addr = FrameVsockAddr::new(packet.header.src_cid, packet.header.src_port);
        let dst_addr = FrameVsockAddr::new(packet.header.dst_cid, packet.header.dst_port);
        let conn_id = ConnectionId::from_addrs(dst_addr, src_addr);

        debug!(
            "[FrameVsock] Received data packet: src={}:{}, dst={}:{}, len={}",
            src_addr.cid,
            src_addr.port,
            dst_addr.cid,
            dst_addr.port,
            packet.data.len()
        );

        if let Some(connected) = self.get_connected_socket(&conn_id) {
            // Zero-copy: pass packet ownership to connected socket
            return connected.on_data_packet_received(packet);
        }

        debug!("[FrameVsock] No connected socket found for {:?}", conn_id);
        Ok(())
    }

    /// Dispatch incoming control packet to the appropriate socket
    /// This is called when Guest sends a control packet to Host
    pub fn on_control_packet_received(&self, packet: RRef<ControlPacket>) -> Result<()> {
        let src_addr = FrameVsockAddr::new(packet.header.src_cid, packet.header.src_port);
        let dst_addr = FrameVsockAddr::new(packet.header.dst_cid, packet.header.dst_port);
        let conn_id = ConnectionId::from_addrs(dst_addr, src_addr);

        let op = packet.operation();

        debug!(
            "[FrameVsock] Received control packet: op={:?}, src={}:{}, dst={}:{}",
            op, src_addr.cid, src_addr.port, dst_addr.cid, dst_addr.port
        );

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
            VsockOp::Rw | VsockOp::Invalid => {
                debug!(
                    "[FrameVsock] Unexpected operation in control packet: {:?}",
                    op
                );
                Ok(())
            }
        }
    }

    /// Handle connection request from Guest
    fn handle_request(
        &self,
        packet: &ControlPacket,
        src_addr: FrameVsockAddr,
        dst_addr: FrameVsockAddr,
    ) -> Result<()> {
        // Check if there's a listening socket on the destination address
        if let Some(listen) = self.get_listen_socket(&dst_addr) {
            // Create a new connected socket for this connection
            // Pass the peer's credit info from the request packet
            let connected = Arc::new(Connected::new_with_credit(
                src_addr,
                dst_addr,
                packet.header.buf_alloc,
                packet.header.fwd_cnt,
            ));

            // Add to the accept queue
            listen.push_incoming(connected.clone())?;

            // Also add to connected sockets map
            let conn_id = ConnectionId::from_addrs(dst_addr, src_addr);
            self.insert_connected_socket(conn_id, connected);

            debug!(
                "[FrameVsock] Accepted connection from {}:{} to {}:{}",
                src_addr.cid, src_addr.port, dst_addr.cid, dst_addr.port
            );

            // Send Response back to Guest
            self.send_response_to_guest(dst_addr, src_addr);

            return Ok(());
        }

        // No listening socket found - send RST
        debug!(
            "[FrameVsock] No listening socket found for {}:{}",
            dst_addr.cid, dst_addr.port
        );
        self.send_rst_to_guest(dst_addr, src_addr);
        Ok(())
    }

    /// Send a Response packet to Guest
    fn send_response_to_guest(&self, local_addr: FrameVsockAddr, peer_addr: FrameVsockAddr) {
        use aster_framevisor::vsock as framevisor_vsock;
        use aster_framevsock::create_response;

        let packet = create_response(
            local_addr.cid,
            local_addr.port,
            peer_addr.cid,
            peer_addr.port,
        );

        // Deliver to Guest via FrameVisor (use vCPU 0 for now)
        if framevisor_vsock::deliver_control_packet(0, packet).is_err() {
            debug!(
                "[FrameVsock] Failed to send Response to Guest {}:{}",
                peer_addr.cid, peer_addr.port
            );
        }
    }

    /// Send a RST packet to Guest
    fn send_rst_to_guest(&self, local_addr: FrameVsockAddr, peer_addr: FrameVsockAddr) {
        use aster_framevisor::vsock as framevisor_vsock;
        use aster_framevsock::create_rst;

        let packet = create_rst(
            local_addr.cid,
            local_addr.port,
            peer_addr.cid,
            peer_addr.port,
        );

        // Deliver to Guest via FrameVisor (use vCPU 0 for now)
        if framevisor_vsock::deliver_control_packet(0, packet).is_err() {
            debug!(
                "[FrameVsock] Failed to send RST to Guest {}:{}",
                peer_addr.cid, peer_addr.port
            );
        }
    }

    /// Handle connection response
    fn handle_response(
        &self,
        packet: &ControlPacket,
        src_addr: FrameVsockAddr,
        dst_addr: FrameVsockAddr,
    ) -> Result<()> {
        // Check if there's a connecting socket waiting for this response
        if let Some(connecting) = self.get_connecting_socket(&dst_addr) {
            // Update with peer's credit info
            connecting.set_connected_with_credit(packet.header.buf_alloc, packet.header.fwd_cnt);
            debug!(
                "[FrameVsock] Connection established to {}:{}",
                src_addr.cid, src_addr.port
            );
        }
        Ok(())
    }

    /// Handle shutdown request
    fn handle_shutdown(&self, _packet: &ControlPacket, conn_id: ConnectionId) -> Result<()> {
        if let Some(connected) = self.get_connected_socket(&conn_id) {
            connected.on_shutdown_received()?;
        }
        Ok(())
    }

    /// Handle reset
    fn handle_rst(&self, _packet: &ControlPacket, conn_id: ConnectionId) -> Result<()> {
        // Remove the connection from the map
        if let Some(connected) = self.remove_connected_socket(&conn_id) {
            connected.on_rst_received()?;
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
    fn handle_credit_request(&self, _packet: &ControlPacket, conn_id: ConnectionId) -> Result<()> {
        if let Some(connected) = self.get_connected_socket(&conn_id) {
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
