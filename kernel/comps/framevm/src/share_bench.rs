//! CPU-share benchmark workload for the kernel image.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use ostd::{
    cpu::CpuId,
    task::{Task, disable_preempt},
};

use crate::{
    error::{Errno, Error, Result},
    rootfs::RootFs,
    task::{create_transient_user_task, wait_for_user_task_to_exit},
    vm::create_vm_space,
};

const BURN_PROGRAM: &str = "/bin/cpu-burn";

/// Runs two CPU-bound workloads under two kernel-local runqueues.
pub fn run(rootfs: Arc<RootFs>, duration_ms: u64) -> Result<Vec<Arc<Task>>> {
    let cpu0 = cpu_id(0)?;
    let cpu1 = cpu_id(1)?;

    ostd::early_println!(
        "[kernel] share benchmark starting: duration_ms={} cpu0=0 cpu1=1",
        duration_ms
    );

    let task0 = create_burn_task(rootfs.as_ref(), cpu0, duration_ms, "worker0")?;
    let task1 = create_burn_task(rootfs.as_ref(), cpu1, duration_ms, "worker1")?;

    ostd::early_println!("[kernel] share benchmark workers running");
    {
        let _preempt_guard = disable_preempt();
        task0.run();
        task1.run();
    }

    wait_for_user_task_to_exit(&task0);
    wait_for_user_task_to_exit(&task1);

    ostd::early_println!("[kernel] share benchmark workloads completed");
    Ok(vec![task0, task1])
}

fn cpu_id(raw_id: usize) -> Result<CpuId> {
    CpuId::try_from(raw_id).map_err(|_| Error::with_message(Errno::EINVAL, "missing CPU"))
}

fn create_burn_task(
    rootfs: &RootFs,
    cpu_id: CpuId,
    duration_ms: u64,
    label: &str,
) -> Result<Arc<Task>> {
    let argv = Vec::from([
        String::from(BURN_PROGRAM),
        duration_ms.to_string(),
        String::from(label),
    ]);
    create_program_task(rootfs, cpu_id, argv)
}

fn create_program_task(rootfs: &RootFs, cpu_id: CpuId, argv: Vec<String>) -> Result<Arc<Task>> {
    let program = rootfs.open_file(argv.first().ok_or(Error::new(Errno::EINVAL))?)?;
    let envp = Vec::from([
        String::from("PATH=/bin"),
        String::from("HOME=/"),
        String::from("TERM=linux"),
    ]);

    let vm_info = create_vm_space(program.data().as_ref(), &argv, &envp)?;
    let vm_space = Arc::new(vm_info.vm_space);

    create_transient_user_task(
        argv.first().ok_or(Error::new(Errno::EINVAL))?,
        vm_space,
        vm_info.entry_point,
        vm_info.stack_top,
        vm_info.heap_base,
        Arc::new(vm_info.lazy_ranges),
        Arc::new(ostd::sync::WaitQueue::new()),
        cpu_id,
    )
}
