// SPDX-License-Identifier: MPL-2.0

//! Per-VM vsock active state tracking.

use super::current_service_sock;

/// Sets the current service VM's vsock active state.
pub fn set_guest_active(active: bool) {
    if let Some(sock) = current_service_sock() {
        sock.set_active(active);
    }
}
