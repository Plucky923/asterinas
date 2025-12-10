mod id;

pub use id::init_cpu_id;
use ostd::early_println;

pub fn init_cpu() {
    early_println!("[framevisor] Initializing CPU...");
    init_cpu_id();
    early_println!("[framevisor] CPU initialized");
}
