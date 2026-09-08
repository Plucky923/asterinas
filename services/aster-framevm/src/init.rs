// SPDX-License-Identifier: MPL-2.0

//! FrameVM boot and initialization flow.

use alloc::sync::Arc;

use aster_cmdline::InitProcessConfig;
use component::InitStage;
use ostd::sync::Once;

use crate::{
    device, net,
    prelude::{Context, Result},
    process::{self, Process, spawn_init_process},
    sched, thread, time,
    vm::activate_kernel_vm_space,
};

/// Initializes the FrameVM service.
pub(crate) fn main() {
    ostd::early_println!("OSTD initialized. Preparing components.");
    let init_process_config = init_framevm_components(InitStage::Bootstrap)
        .expect("bootstrap must produce the init-process configuration");
    if let Err(error) = init() {
        ostd::error!("[kernel] FrameVM initialization failed: {:?}", error);
        ostd::panic::abort();
    }
    init_on_each_cpu();
    activate_kernel_vm_space();
    if let Err(error) = first_kthread(init_process_config) {
        ostd::error!("[kernel] failed to start the init process: {:?}", error);
        ostd::panic::abort();
    }
}

fn init() -> Result<()> {
    thread::init()?;
    crate::util::random::init();
    time::init()?;
    sched::init();
    process::init()?;
    crate::fs::init();
    crate::security::init();
    Ok(())
}

fn init_on_each_cpu() {
    sched::init_on_each_cpu();
    process::init_on_each_cpu();
    time::init_on_each_cpu();
}

fn first_kthread(init_process_config: InitProcessConfig) -> Result<()> {
    init_in_first_kthread();
    print_banner();
    run_init_process(init_process_config)
}

fn init_in_first_kthread() {
    ostd::early_println!("[kernel] kthread init: components");
    let _ = init_framevm_components(InitStage::Kthread);
    ostd::early_println!("[kernel] kthread init: work queue");
    // Work queue should be initialized before interrupt is enabled,
    // in case any irq handler uses work queue as bottom half
    crate::thread::work_queue::init_in_first_kthread();
    ostd::early_println!("[kernel] kthread init: device");
    device::init_in_first_kthread().expect("failed to initialize devices");
    ostd::early_println!("[kernel] kthread init: net");
    net::init_in_first_kthread().expect("failed to initialize network");
    ostd::early_println!("[kernel] kthread init: fs");
    crate::fs::init_in_first_kthread().expect("failed to initialize filesystem");
    ostd::early_println!("[kernel] kthread init: done");
}

fn init_framevm_components(stage: InitStage) -> Option<InitProcessConfig> {
    init_framevm_component_profile(stage)
}

fn init_framevm_component_profile(stage: InitStage) -> Option<InitProcessConfig> {
    match stage {
        InitStage::Bootstrap => {
            aster_block::init_for_framevm_component_profile().unwrap();
            aster_cmdline::init_for_framevm_component_profile().unwrap();
            let init_process_config =
                aster_cmdline::prepare_for_framevm_component_profile().unwrap();
            aster_softirq::init_for_framevm_component_profile().unwrap();
            aster_systree::init_for_framevm_component_profile().unwrap();
            aster_time::init_for_framevm_component_profile().unwrap();
            aster_network::init_for_framevm_component_profile().unwrap();
            aster_pci::init_for_framevm_component_profile().unwrap();
            framev_pci::init_for_framevm_component_profile().unwrap();
            Some(init_process_config)
        }
        InitStage::Kthread => {
            aster_nvme::init_for_framevm_component_profile().unwrap();
            framev_console_frontend::init_for_framevm_component_profile().unwrap();
            framev_rng_frontend::init_for_framevm_component_profile().unwrap();
            framev_sock_frontend::init_for_framevm_component_profile().unwrap();
            framev_blk_frontend::init_for_framevm_component_profile().unwrap();
            framev_net_frontend::init_for_framevm_component_profile().unwrap();
            None
        }
        InitStage::Process => {
            aster_block::init_process_for_framevm_component_profile().unwrap();
            None
        }
    }
}

fn print_banner() {
    ostd::early_println!("");
    ostd::early_println!("{}", logo_ascii_art::get_framevm_gradient_color_version());
}

fn run_init_process(config: InitProcessConfig) -> Result<()> {
    let process = spawn_init_process(
        config.executable_path(),
        config.args().argv().to_vec(),
        config.args().envp().to_vec(),
    )?;
    INIT_PROCESS.call_once(|| process);
    Ok(())
}

static INIT_PROCESS: Once<Arc<Process>> = Once::new();

pub(super) fn on_first_process_startup(ctx: &Context) {
    ostd::early_println!("[kernel] process init: components");
    let _ = init_framevm_components(InitStage::Process);
    ostd::early_println!("[kernel] process init: device");
    device::init_in_first_process(ctx).unwrap();
    ostd::early_println!("[kernel] process init: fs");
    crate::fs::init_in_first_process(ctx);
    ostd::early_println!("[kernel] process init: done");
}
