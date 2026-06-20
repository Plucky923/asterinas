// SPDX-License-Identifier: MPL-2.0

#[expect(clippy::module_inception)]
mod events;
mod io_events;
mod observer;
mod subject;

#[expect(
    unused_imports,
    reason = "Keep the kernel events API shape for copied modules"
)]
pub use self::subject::Subject;
pub use self::{
    events::{Events, EventsFilter},
    io_events::IoEvents,
    observer::Observer,
    subject::SyncSubject,
};
