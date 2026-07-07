//! FrameV endpoint authority tokens.
//!
//! This module defines small capability tokens that separate submitter,
//! receiver, and control-path authority.

/// Submitter-side ring authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmitterEndpoint {
    _private: (),
}

/// Receiver-side ring authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverEndpoint {
    _private: (),
}

/// Control-path authority for lifecycle, reset, stop, and drain operations.
#[derive(Debug, Eq, PartialEq)]
pub struct ControlPathAuthority {
    _private: (),
}

/// Split common ring authorities.
#[derive(Debug, Eq, PartialEq)]
pub struct RingAuthorities {
    submitter: SubmitterEndpoint,
    receiver: ReceiverEndpoint,
    control: ControlPathAuthority,
}

impl RingAuthorities {
    /// Creates common ring authority tokens.
    pub const fn new() -> Self {
        Self {
            submitter: SubmitterEndpoint::new(),
            receiver: ReceiverEndpoint::new(),
            control: ControlPathAuthority::new(),
        }
    }

    /// Returns the submitter endpoint authority.
    pub const fn submitter(&self) -> SubmitterEndpoint {
        self.submitter
    }

    /// Returns the receiver endpoint authority.
    pub const fn receiver(&self) -> ReceiverEndpoint {
        self.receiver
    }

    /// Returns the control-path authority.
    pub const fn control(self) -> ControlPathAuthority {
        self.control
    }
}

impl SubmitterEndpoint {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

impl ReceiverEndpoint {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

impl ControlPathAuthority {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}
