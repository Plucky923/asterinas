// SPDX-License-Identifier: MPL-2.0

//! FrameVM boot and initialization flow.

use alloc::string::String;

use aster_cmdline::INIT_PROC_ARGS;
use component::InitStage;
use spin::once::Once;

use crate::{
    device, net,
    prelude::Context,
    process::{self, spawn_init_process},
    sched, thread, time,
    vm::activate_kernel_vm_space,
};

/// Initializes the FrameVM service.
pub(crate) fn main() {
    ostd::early_println!("OSTD initialized. Preparing components.");
    init_framevm_components(InitStage::Bootstrap);
    init();
    init_on_each_cpu();
    activate_kernel_vm_space();
    first_kthread();
}

fn init() {
    thread::init();
    crate::util::random::init();
    time::init();
    sched::init();
    process::init();
    crate::fs::init();
    crate::security::init();
}

fn init_on_each_cpu() {
    sched::init_on_each_cpu();
    process::init_on_each_cpu();
    time::init_on_each_cpu();
}

fn first_kthread() {
    init_in_first_kthread();
    print_banner();
    run_init_process();
}

fn init_in_first_kthread() {
    ostd::early_println!("[kernel] kthread init: components");
    init_framevm_components(InitStage::Kthread);
    ostd::early_println!("[kernel] kthread init: device");
    device::init_in_first_kthread().expect("failed to initialize devices");
    ostd::early_println!("[kernel] kthread init: net");
    net::init_in_first_kthread().expect("failed to initialize network");
    ostd::early_println!("[kernel] kthread init: fs");
    crate::fs::init_in_first_kthread().expect("failed to initialize filesystem");
    ostd::early_println!("[kernel] kthread init: done");
}

fn init_framevm_components(stage: InitStage) {
    init_framevm_component_profile(stage);
}

fn init_framevm_component_profile(stage: InitStage) {
    match stage {
        InitStage::Bootstrap => {
            aster_block::init_for_framevm_component_profile().unwrap();
            aster_cmdline::init_for_framevm_component_profile().unwrap();
            aster_softirq::init_for_framevm_component_profile().unwrap();
            aster_systree::init_for_framevm_component_profile().unwrap();
            aster_time::init_for_framevm_component_profile().unwrap();
            framev_bus::init_for_framevm_component_profile().unwrap();
        }
        InitStage::Kthread => {
            framev_console_frontend::init_for_framevm_component_profile().unwrap();
            framev_rng_frontend::init_for_framevm_component_profile().unwrap();
            framev_sock_frontend::init_for_framevm_component_profile().unwrap();
            framev_blk_frontend::init_for_framevm_component_profile().unwrap();
        }
        InitStage::Process => {
            aster_block::init_process_for_framevm_component_profile().unwrap();
        }
    }
}

fn print_banner() {
    ostd::early_println!("");
    ostd::early_println!("{}", logo_ascii_art::get_framevm_gradient_color_version());
}

fn run_init_process() {
    let init_args = INIT_PROC_ARGS.get().unwrap();
    let init_path = INIT_PATH.get().map(String::as_str);
    spawn_init_process(
        init_path,
        init_args.argv().to_vec(),
        init_args.envp().to_vec(),
    )
    .expect("Failed to run the init process");
}

pub(super) fn on_first_process_startup(ctx: &Context) {
    ostd::early_println!("[kernel] process init: components");
    init_framevm_components(InitStage::Process);
    ostd::early_println!("[kernel] process init: device");
    device::init_in_first_process(ctx).unwrap();
    ostd::early_println!("[kernel] process init: fs");
    crate::fs::init_in_first_process(ctx);
    ostd::early_println!("[kernel] process init: done");
}

static INIT_PATH: Once<String> = Once::new();
aster_cmdline::define_kv_param!("init", INIT_PATH);
