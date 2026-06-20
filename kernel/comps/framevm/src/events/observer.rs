// SPDX-License-Identifier: MPL-2.0

use super::Events;

/// An observer for events.
///
/// In a sense, event observers are just a fancy form of callback functions.
/// An observer's `on_events` methods are supposed to be called when
/// some events that are interesting to the observer happen.
///
/// # The no-op observer
///
/// The unit type `()` can serve as a no-op observer.
/// It implements `Observer<E>` for any events type `E`,
/// with an `on_events` method that simply does nothing.
pub trait Observer<E: Events>: Send + Sync {
    /// Notifies the observer that some interesting events happen.
    fn on_events(&self, events: &E);
}

impl<E: Events> Observer<E> for () {
    fn on_events(&self, _events: &E) {}
}
