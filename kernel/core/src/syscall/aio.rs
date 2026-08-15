// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::prelude::*;

pub fn sys_io_setup(
    max_events: u32,
    context_id_addr: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if max_events == 0 {
        return_errno_with_message!(Errno::EINVAL, "AIO context capacity must be nonzero");
    }

    let user_space = ctx.user_space();
    let initial_context_id = user_space.read_val::<u64>(context_id_addr)?;
    if initial_context_id != 0 {
        return_errno_with_message!(
            Errno::EINVAL,
            "AIO context identifier must initially be zero"
        );
    }

    let process_vm = user_space.vmar().process_vm();
    let context_id = process_vm.create_aio_context(max_events)?;
    if let Err(error) = user_space.write_val(context_id_addr, &context_id) {
        let removed = process_vm.remove_aio_context(context_id);
        debug_assert!(removed);
        return Err(error.into());
    }

    Ok(SyscallReturn::Return(0))
}

pub fn sys_io_destroy(context_id: u64, ctx: &Context) -> Result<SyscallReturn> {
    let user_space = ctx.user_space();
    if !user_space
        .vmar()
        .process_vm()
        .remove_aio_context(context_id)
    {
        return_errno_with_message!(Errno::EINVAL, "invalid AIO context identifier");
    }

    Ok(SyscallReturn::Return(0))
}
