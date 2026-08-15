// SPDX-License-Identifier: MPL-2.0

//! Boot information exposed through the OSTD-compatible surface.

use alloc::{boxed::Box, string::String, vec::Vec};

pub use host_ostd::boot::{BootInfo, BootloaderAcpiArg, BootloaderFramebufferArg, memory_region};

use crate::{Error, Result, task, vm};

/// Installs boot information for one FrameVM service entrypoint.
pub fn set_boot_info_without_initramfs(vm_id: vm::VmId, kernel_cmdline: String) -> Result<()> {
    let boot_info = Box::leak(Box::new(BootInfo {
        bootloader_name: String::from("OSTD"),
        kernel_cmdline,
        initramfs: None,
        framebuffer_arg: None,
        memory_regions: Vec::new(),
    }));
    crate::log::init_from_cmdline(boot_info.kernel_cmdline.as_str());
    let frame_vm = vm::get_vm_by_id(vm_id).ok_or(Error::InvalidArgs)?;
    frame_vm.set_boot_info(boot_info);
    Ok(())
}

/// Returns the boot information owned by the current FrameVM.
pub fn boot_info() -> &'static BootInfo {
    task::current_frame_vm()
        .and_then(|frame_vm| frame_vm.boot_info())
        .expect("kernel image boot info is missing")
}

/// Releases service-owned host hooks after Host scheduling is quiescent.
pub fn release_service_resources(vm_id: vm::VmId) {
    let Some(frame_vm) = vm::get_vm_by_id(vm_id) else {
        return;
    };

    frame_vm.clear_task_state();
    frame_vm.clear_timer_runtime();
    frame_vm.devices().console().clear_input();
    frame_vm.clear_boot_info();
}
