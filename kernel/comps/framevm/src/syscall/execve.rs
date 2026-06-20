// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};

use ostd::{arch::cpu::context::UserContext, mm::VmSpace};

use super::{
    Result, RootFs, SyscallReturn, create_vm_space, current_fd_table, notify_current_exec_boundary,
    read_c_string, read_string_array, resolve_guest_path, unshare_current_fd_table,
    with_current_user_task_data,
};

/// Replaces the current task image with another executable.
pub(super) fn sys_execve(
    ctx: &mut UserContext,
    pathname_addr: usize,
    argv_addr: usize,
    envp_addr: usize,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    let raw_pathname = read_c_string(vm_space, pathname_addr)?;
    let pathname = resolve_guest_path(&raw_pathname)?;
    let argv = read_string_array(vm_space, argv_addr)?;
    let envp = read_string_array(vm_space, envp_addr)?;
    let argv = if argv.is_empty() {
        Vec::from([raw_pathname])
    } else {
        argv
    };

    let program = RootFs::get()?.open_file(&pathname)?;
    let vm_info = create_vm_space(program.data().as_ref(), &argv, &envp)?;
    let new_vm_space = Arc::new(vm_info.vm_space);
    new_vm_space.activate();

    unshare_current_fd_table()?;
    let files_to_drop = current_fd_table()?.lock().close_files_on_exec();
    drop(files_to_drop);

    with_current_user_task_data(|task_data| {
        task_data.replace_exec_image(
            new_vm_space,
            vm_info.entry_point,
            vm_info.stack_top,
            vm_info.heap_base,
            Arc::new(vm_info.lazy_ranges),
            &pathname,
        );
        Ok(())
    })?;
    notify_current_exec_boundary()?;

    let mut new_context = UserContext::default();
    new_context.set_rip(vm_info.entry_point);
    new_context.set_rsp(vm_info.stack_top);
    *ctx = new_context;
    Ok(SyscallReturn::NoReturn)
}
