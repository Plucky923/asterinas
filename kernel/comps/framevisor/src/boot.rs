// SPDX-License-Identifier: MPL-2.0

//! Boot information exposed through the OSTD-compatible surface.

#[cfg(feature = "host-api")]
use alloc::{boxed::Box, format, string::String, vec::Vec};

pub use host_ostd::boot::{BootInfo, BootloaderAcpiArg, BootloaderFramebufferArg, memory_region};
use host_ostd::sync::SpinLock;

use crate::sync::Once;
#[cfg(feature = "host-api")]
use crate::{console, task, timer, vm};

/// Kernel image entry mode requested by the host control plane.
#[cfg(feature = "host-api")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootMode {
    /// Starts the normal interactive shell.
    InteractiveShell,
    /// Runs a bounded BusyBox/rootfs smoke test.
    BusyBoxSmoke,
    /// Runs the CPU-share benchmark for a bounded duration.
    ShareBenchmark {
        /// Benchmark duration in milliseconds.
        duration_ms: u64,
    },
}

#[cfg(feature = "host-api")]
impl BootMode {
    fn kernel_cmdline(self) -> String {
        match self {
            Self::InteractiveShell => String::new(),
            Self::BusyBoxSmoke => String::from("kernel.mode=busybox-smoke"),
            Self::ShareBenchmark { duration_ms } => {
                format!("kernel.mode=share-benchmark kernel.duration_ms={duration_ms}")
            }
        }
    }
}

static BOOT_INFO: Once<SpinLock<Option<&'static BootInfo>>> = Once::new();

fn boot_info_slot() -> &'static SpinLock<Option<&'static BootInfo>> {
    BOOT_INFO.call_once(|| SpinLock::new(None))
}

/// Installs boot information for the next kernel image entrypoint.
#[cfg(feature = "host-api")]
pub fn set_boot_info(initramfs: Vec<u8>) {
    set_boot_info_with_cmdline(initramfs, String::new());
}

/// Installs boot information with additional kernel command line arguments.
#[cfg(feature = "host-api")]
pub fn set_boot_info_with_extra(initramfs: Vec<u8>, extra_cmdline: String) {
    set_boot_info_with_cmdline(initramfs, extra_cmdline);
}

/// Installs boot information and entry mode for the next kernel image entrypoint.
#[cfg(feature = "host-api")]
pub fn set_boot_info_with_mode(initramfs: Vec<u8>, mode: BootMode) {
    set_boot_info_with_cmdline(initramfs, mode.kernel_cmdline());
}

/// Installs boot information, entry mode, and extra kernel command line arguments.
#[cfg(feature = "host-api")]
pub fn set_boot_info_with_mode_and_extra(
    initramfs: Vec<u8>,
    mode: BootMode,
    extra_cmdline: String,
) {
    set_boot_info_with_cmdline(
        initramfs,
        merge_cmdline(mode.kernel_cmdline(), extra_cmdline),
    );
}

/// Installs boot information and command line for the next kernel image entrypoint.
#[cfg(feature = "host-api")]
pub fn set_boot_info_with_cmdline(initramfs: Vec<u8>, kernel_cmdline: String) {
    let initramfs = Box::leak(initramfs.into_boxed_slice());
    let boot_info = Box::leak(Box::new(BootInfo {
        bootloader_name: String::from("OSTD"),
        kernel_cmdline,
        initramfs: Some(initramfs),
        symbols: None,
        framebuffer_arg: None,
        memory_regions: Vec::new(),
    }));
    *boot_info_slot().lock() = Some(boot_info);
}

#[cfg(feature = "host-api")]
fn merge_cmdline(mut base: String, extra: String) -> String {
    if extra.is_empty() {
        return base;
    }
    if base.is_empty() {
        return extra;
    }
    base.push(' ');
    base.push_str(&extra);
    base
}

fn clear_boot_info_slot() {
    *boot_info_slot().lock() = None;
}

/// Clears the current kernel image boot information.
#[cfg(feature = "host-api")]
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
#[cfg(feature = "host-api")]
pub fn enter_current_service() -> bool {
    task::current_frame_task_group_id().is_some()
}

/// Stops the current dynamically loaded service and releases host-side hooks.
#[cfg(feature = "host-api")]
pub fn shutdown_current_service() -> bool {
    let Some(frame_vm) = vm::get_vm() else {
        return false;
    };

    let vm_id = frame_vm.id();
    frame_vm.stop();
    for vcpu_id in 0..frame_vm.vcpu_count() {
        if let Some(ctx) = frame_vm.iht_context(vcpu_id) {
            ctx.wait_for_exit();
        }
    }
    let _ = console::release_input();
    let _ = console::clear_input();
    console::clear_transport_input_callbacks();
    task::clear_service_hooks_for_vm(vm_id);
    timer::clear_callbacks_for_vm(vm_id);
    drop(frame_vm);
    let _ = vm::destroy_vm(vm_id);
    clear_boot_info_slot();
    true
}
