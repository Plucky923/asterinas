// SPDX-License-Identifier: MPL-2.0

//! Boot information exposed through the OSTD-compatible surface.

use alloc::{boxed::Box, string::String, vec::Vec};

pub use host_ostd::boot::{BootInfo, BootloaderAcpiArg, BootloaderFramebufferArg, memory_region};
use host_ostd::sync::SpinLock;

use crate::{sync::Once, task, timer, vm};

static BOOT_INFO: Once<SpinLock<Option<&'static BootInfo>>> = Once::new();

fn boot_info_slot() -> &'static SpinLock<Option<&'static BootInfo>> {
    BOOT_INFO.call_once(|| SpinLock::new(None))
}

/// Installs boot information for the next kernel image entrypoint.
pub fn set_boot_info(initramfs: Vec<u8>) {
    set_boot_info_with_cmdline(initramfs, String::new());
}

/// Installs boot information with additional kernel command line arguments.
pub fn set_boot_info_with_extra(initramfs: Vec<u8>, extra_cmdline: String) {
    set_boot_info_with_cmdline(initramfs, extra_cmdline);
}

/// Installs boot information and command line for the next kernel image entrypoint.
pub fn set_boot_info_with_cmdline(initramfs: Vec<u8>, kernel_cmdline: String) {
    install_boot_info(Some(initramfs), kernel_cmdline);
}

/// Installs boot information without an initramfs payload.
pub fn set_boot_info_without_initramfs(kernel_cmdline: String) {
    install_boot_info(None, kernel_cmdline);
}

fn install_boot_info(initramfs: Option<Vec<u8>>, kernel_cmdline: String) {
    let initramfs = initramfs.map(|initramfs| Box::leak(initramfs.into_boxed_slice()) as &[u8]);
    let boot_info = Box::leak(Box::new(BootInfo {
        bootloader_name: String::from("OSTD"),
        kernel_cmdline,
        initramfs,
        symbols: None,
        framevm_symbols: None,
        framebuffer_arg: None,
        memory_regions: Vec::new(),
    }));
    crate::log::init_from_cmdline(boot_info.kernel_cmdline.as_str());
    *boot_info_slot().lock() = Some(boot_info);
}

fn clear_boot_info_slot() {
    *boot_info_slot().lock() = None;
}

/// Clears the current kernel image boot information.
pub fn clear_boot_info() {
    clear_boot_info_slot();
}

/// Returns a snapshot of the current kernel image boot information.
pub fn boot_info() -> &'static BootInfo {
    boot_info_slot()
        .lock()
        .expect("kernel image boot info is missing")
}

/// Enters the domain for the current dynamically loaded service.
pub fn enter_current_service() -> bool {
    current_service_vm_id().is_some()
}

pub(crate) fn current_service_vm_id() -> Option<vm::VmId> {
    if let Some(frame_vcpu_id) = task::current_frame_vcpu_id() {
        return Some(frame_vcpu_id.vm_id());
    }

    // Service-originated teardown can run from a copied kernel task that no
    // longer carries a host-backed vCPU binding. Falling back is safe only when
    // there is exactly one live FrameVM; multi-VM teardown must be explicit.
    let mut vm_ids = vm::list_vms().into_iter();
    let vm_id = vm_ids.next()?;
    vm_ids.next().is_none().then_some(vm_id)
}

/// Stops the current dynamically loaded service and releases host-side hooks.
pub fn shutdown_current_service() -> bool {
    let Some(vm_id) = current_service_vm_id() else {
        return false;
    };
    let Some(frame_vm) = vm::get_vm_by_id(vm_id) else {
        return false;
    };

    frame_vm.devices().console().clear_input_callbacks();
    task::clear_service_hooks_for_vm(vm_id);
    timer::clear_callbacks_for_vm(vm_id);
    frame_vm.request_stop();
    frame_vm.devices().console().clear_input();
    clear_boot_info_slot();
    true
}
