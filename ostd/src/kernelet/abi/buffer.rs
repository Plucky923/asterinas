// SPDX-License-Identifier: MPL-2.0

//! Whole-buffer grant operations. Tokens contain a slot and a nonwrapping
//! generation; every accepted handoff and backend return issues a fresh token.
//! Caller identity comes from the carrier, never from an argument.
//!
//! A negative `MmioResult.status` is an ABI error. Nonnegative status and value
//! fields have operation-specific meanings: REDEEM returns packed mapping
//! metadata, BLOCK_INFO returns flags, NET_INFO returns a payload limit, and
//! SHARED_NET_EXCHANGE reports whether more deliveries remain pending.
//! ALLOCATE: arg0=capacity. REDEEM/RELEASE/DISCARD: token only.
//! HANDOFF: token, arg0=connection, arg1=mode, arg2=payload length.
//! RECEIVE: arg0=connection. SUBMIT: token, arg0=device, arg1=byte offset,
//! arg2=(direction << 32)|length. POLL/CANCEL: token=request identity.
//! POLL returns the return-grant token; status is the backend result. A zero
//! value means pending. Accepted backend errors accompany a nonzero grant.

/// Shared Ethernet discovery query for the private connection identity.
pub const NET_QUERY_CONNECTION: u32 = 0;
/// Shared Ethernet discovery query for the six-byte MAC address.
pub const NET_QUERY_MAC: u32 = 1;
/// Shared Ethernet discovery query for the maximum Ethernet frame size.
pub const NET_QUERY_MAX_FRAME: u32 = 2;
/// Shared Ethernet discovery query for its virtual interrupt line.
pub const NET_QUERY_IRQ: u32 = 3;

/// Reserve and zero a whole buffer; arg0 is its requested capacity.
pub const ALLOCATE: u32 = 0;
/// Activate one issued grant and return its mapping and packed metadata.
pub const REDEEM: u32 = 1;
/// End an active grant after local borrows end.
pub const RELEASE: u32 = 2;
/// End an unredeemed grant.
pub const DISCARD: u32 = 3;
/// Transfer access using a Host-authorized connection.
pub const HANDOFF: u32 = 4;
/// Observe an issued delivery without consuming it.
pub const RECEIVE: u32 = 5;
/// End local access and establish an accepted backend operation.
pub const SUBMIT: u32 = 6;
/// Take an operation's return grant after all backend accesses end.
pub const POLL: u32 = 7;
/// Request cancellation without returning buffer access.
pub const CANCEL: u32 = 8;
/// Enumerate this participant's Host-authorized connections; arg0 is an index.
pub const CONNECTION: u32 = 9;
/// Discard interest in an accepted operation; backend holds must still drain.
pub const ABANDON: u32 = 10;
/// Query a zero-copy block attachment: arg0=index, other arguments zero.
/// A zero value means absent. Otherwise value=capacity in bytes and status
/// contains DEVICE_READ_ONLY. These indices are separate from MMIO slots.
pub const BLOCK_INFO: u32 = 11;
/// Enumerate a zero-copy datagram device: arg0=index, other arguments zero.
/// value=authorized connection, status=maximum payload; value zero means absent.
pub const NET_INFO: u32 = 12;
/// Query an Ethernet shared-buffer device: arg0=device, arg1=query, arg2=0.
/// Queries 0..3 return connection, little-endian MAC, maximum frame size, IRQ.
/// A zero connection means absent. These devices retain the Host NAT backend.
pub const SHARED_NET_INFO: u32 = 13;
/// Notify the Ethernet worker after a bounded batch of owning handoffs.
pub const SHARED_NET_KICK: u32 = 14;
/// Exchanges empty returns for active Ethernet grants on a private NIC link.
/// token=0, arg0=connection, arg1=registered DMA scratch physical address,
/// arg2=number of return tokens. Success value is the received grant count;
/// status=1 when the connection still has pending deliveries, otherwise zero.
/// Rejection preserves every grant. The fixed scratch contains return tokens
/// followed by mapping descriptors, each bounded by `SHARED_NET_BATCH_SIZE`.
pub const SHARED_NET_EXCHANGE: u32 = 15;
/// Atomically publishes at most one private NIC transmit batch. The scratch
/// contains NetTransmitDescriptor entries. Rejection preserves all owners.
pub const SHARED_NET_TRANSMIT: u32 = 16;
/// Allocates one initialized private NIC page under its separate pool quota.
/// token=0, arg0=PAGE_SIZE, arg1=live private connection, arg2=0.
pub const SHARED_NET_ALLOCATE: u32 = 17;
/// Maximum empty returns and received grants in one Ethernet exchange.
pub const SHARED_NET_BATCH_SIZE: usize = 32;
/// Private NIC data window per direction, separate from its empty-return slots.
pub const SHARED_NET_POOL_SIZE: usize = 64;
pub const SHARED_NET_IMPORT_LIMIT: usize = 2 * SHARED_NET_POOL_SIZE;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct NetTransmitDescriptor {
    pub token: u64,
    pub payload: u64,
}

/// Host-written active grant metadata; image callers receive owning wrappers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct NetGrantDescriptor {
    pub token: u64,
    pub address: u64,
    pub mapping: i64,
}

pub(crate) const NET_RETURN_BYTES: usize = size_of::<[u64; SHARED_NET_BATCH_SIZE]>();
pub(crate) const NET_EXCHANGE_BYTES: usize =
    NET_RETURN_BYTES + size_of::<[NetGrantDescriptor; SHARED_NET_BATCH_SIZE]>();

/// Block information flag: disk writes are forbidden.
pub const DEVICE_READ_ONLY: i64 = 1;
/// Minimum transfer and offset alignment for zero-copy block devices.
pub const BLOCK_ALIGNMENT: usize = 512;
/// Read-only access cannot be upgraded during transfer.
pub const READ_ONLY: u64 = 0;
/// Read/write access permits a local exclusive writer.
pub const READ_WRITE: u64 = 1;
/// The backend reads the buffer (disk write or network transmit).
pub const DEVICE_READ: u32 = 0;
/// The backend writes the buffer (disk read or network receive).
pub const DEVICE_WRITE: u32 = 1;
/// Prototype limit; capacity and payload length each occupy 21 metadata bits.
pub const MAX_CAPACITY: usize = 1024 * 1024;
const LENGTH_BITS: u32 = 21;
#[cfg(any(feature = "kernelet", ktest))]
const LENGTH_MASK: u64 = (1 << LENGTH_BITS) - 1;

#[cfg(any(feature = "kernelet-host", ktest))]
pub(crate) const fn mapping_info(capacity: usize, payload: usize, writable: bool) -> i64 {
    (capacity as u64 | (payload as u64) << LENGTH_BITS | (writable as u64) << 42) as i64
}

#[cfg(any(feature = "kernelet", ktest))]
pub(crate) const fn mapping_fields(info: i64) -> (usize, usize, bool) {
    let info = info as u64;
    (
        (info & LENGTH_MASK) as usize,
        ((info >> LENGTH_BITS) & LENGTH_MASK) as usize,
        info & (1 << 42) != 0,
    )
}
