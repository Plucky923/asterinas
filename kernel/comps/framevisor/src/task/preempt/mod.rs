//! Preemption-control helpers exposed through the OSTD-compatible surface.

mod guard;

pub use guard::{DisabledPreemptGuard, disable_preempt};

pub(super) fn init_preempt() {
    guard::init_preempt();
}
