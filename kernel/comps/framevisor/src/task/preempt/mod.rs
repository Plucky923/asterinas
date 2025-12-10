mod guard;

pub use guard::disable_preempt;

pub fn init_preempt() {
    guard::init_preempt();
}
