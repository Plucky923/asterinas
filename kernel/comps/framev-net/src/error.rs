// SPDX-License-Identifier: MPL-2.0

/// Error returned by one FrameV-net payload operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVNetError {
    /// The endpoint is permanently unavailable.
    EndpointLost,
    /// The frame targets an unconfigured unicast Ethernet address.
    ForeignUnicastDestination,
    /// The Ethernet frame exceeds the configured maximum length.
    FrameTooLong,
    /// The Ethernet frame does not contain a complete Ethernet header.
    FrameTooShort,
    /// The endpoint cannot accept a frame without blocking.
    NotReady,
    /// The caller-provided receive storage cannot hold one complete frame.
    ReceiveBufferTooSmall,
    /// The caller-provided receive storage was not allocated by Host.
    ReceiveBufferNotHostOwned,
    /// The bounded receive-buffer inventory is full.
    ReceiveQueueFull,
    /// The frame source address differs from the immutable configured address.
    SourceMacMismatch,
    /// The frame uses an unsupported Ethernet VLAN tag.
    TaggedFrame,
}

/// Result of one nonblocking FrameV-net receive poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVNetReceiveStatus {
    /// A validated frame was published for the frontend.
    Delivered,
    /// An invalid or foreign-unicast frame was discarded and its storage reused.
    Dropped,
    /// The endpoint is permanently unavailable and all retained storage was reclaimed.
    EndpointLost,
    /// No receive storage is currently posted.
    NoBuffer,
    /// The endpoint has no datagram ready without blocking.
    NotReady,
}

/// Error returned by the host-owned network endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkEndpointError {
    /// The endpoint is permanently unavailable.
    Lost,
    /// The endpoint cannot make progress without blocking.
    NotReady,
}

impl From<NetworkEndpointError> for FrameVNetError {
    fn from(error: NetworkEndpointError) -> Self {
        match error {
            NetworkEndpointError::Lost => Self::EndpointLost,
            NetworkEndpointError::NotReady => Self::NotReady,
        }
    }
}
