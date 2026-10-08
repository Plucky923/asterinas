// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use aster_cmdline::types::MmioDevice;
#[cfg(not(feature = "kernelet"))]
use ostd::arch::irq::IRQ_CHIP;
pub(super) use ostd::arch::irq::MappedIrqLine;
#[cfg(not(feature = "kernelet"))]
use ostd::debug;
use ostd::{info, warn};
use spin::Once;

use crate::transport::mmio::bus::MmioRegisterError;

pub(super) fn probe_for_device() {
    probe_from_kernel_cmdline();
    #[cfg(not(feature = "kernelet"))]
    probe_from_microvm_constants();
}

static VIRTIO_MMIO_CMDLINE_DEVICES: Once<Vec<MmioDevice>> = Once::new();
aster_cmdline::define_repeatable_kv_param!("virtio_mmio.device", VIRTIO_MMIO_CMDLINE_DEVICES);

/// Probes Linux-compatible `virtio_mmio.device=<size>@<base>:<irq>[:<id>]` parameters.
///
/// This format follows Linux's `virtio_mmio.device` kernel parameter.
fn probe_from_kernel_cmdline() {
    let Some(devices) = VIRTIO_MMIO_CMDLINE_DEVICES.get() else {
        return;
    };

    #[cfg(not(feature = "kernelet"))]
    let irq_chip = IRQ_CHIP.get().unwrap();

    for device in devices {
        info!(
            "Probe MMIO command-line device: base={:#x}, size={:#x}, irq={}",
            device.base(),
            device.size().get(),
            device.irq().get()
        );

        let Some(mmio_end) = device.base().checked_add(device.size().get()) else {
            warn!(
                "Ignore MMIO command-line device at {:#x} because its range overflows",
                device.base()
            );
            continue;
        };

        #[cfg(feature = "kernelet")]
        let registration =
            super::try_register_mmio_device(device.base()..mmio_end, device.irq().get(), |line| {
                Ok(line)
            });
        #[cfg(not(feature = "kernelet"))]
        let registration = super::try_register_mmio_device(device.base()..mmio_end, |irq_line| {
            irq_chip.map_gsi_pin_to(irq_line, device.irq().get())
        });
        if let Err(err) = registration {
            warn!(
                "Ignore MMIO command-line device at {:#x} due to an error ({:?})",
                device.base(),
                err,
            );
        }
    }
}

#[cfg(not(feature = "kernelet"))]
fn probe_from_microvm_constants() {
    // TODO: If ACPI tables are present, the correct method for detecting VirtIO-MMIO
    // devices is to parse the ACPI SSDT [1]. It is not supported yet, so we fall
    // back to blindly scanning QEMU MicroVM's fixed MMIO window as a workaround.
    // [1]: https://github.com/torvalds/linux/blob/0ff41df1cb268fc69e703a08a57ee14ae967d0ca/drivers/virtio/virtio_mmio.c#L840

    // Constants from QEMU MicroVM. We should remove them as they're QEMU's implementation details.
    //
    // https://github.com/qemu/qemu/blob/3c5a5e213e5f08fbfe70728237f7799ac70f5b99/hw/i386/microvm.c#L201
    const QEMU_MMIO_BASE: usize = 0xFEB0_0000;
    const QEMU_MMIO_SIZE: usize = 512;
    // https://github.com/qemu/qemu/blob/3c5a5e213e5f08fbfe70728237f7799ac70f5b99/hw/i386/microvm.c#L196
    const QEMU_IOAPIC1_GSI_BASE: u32 = 16;
    const QEMU_IOAPIC1_NUM_TRANS: u32 = 8;
    // https://github.com/qemu/qemu/blob/3c5a5e213e5f08fbfe70728237f7799ac70f5b99/hw/i386/microvm.c#L192
    const QEMU_IOAPIC2_GSI_BASE: u32 = 24;
    const QEMU_IOAPIC2_NUM_TRANS: u32 = 24;

    let irq_chip = IRQ_CHIP.get().unwrap();
    let (gsi_base, num_trans) = match irq_chip.count_io_apics() {
        1 => (QEMU_IOAPIC1_GSI_BASE, QEMU_IOAPIC1_NUM_TRANS),
        2.. => (QEMU_IOAPIC2_GSI_BASE, QEMU_IOAPIC2_NUM_TRANS),
        0 => {
            debug!("Skip MMIO detection because there are no I/O APICs");
            return;
        }
    };

    for index in 0..num_trans {
        let mmio_base = QEMU_MMIO_BASE + (index as usize) * QEMU_MMIO_SIZE;
        match super::try_register_mmio_device(mmio_base..(mmio_base + QEMU_MMIO_SIZE), |irq_line| {
            irq_chip.map_gsi_pin_to(irq_line, gsi_base + index)
        }) {
            Err(e) if e.is_fatal() => break,
            _ => continue,
        }
    }
}

impl MmioRegisterError {
    /// Returns `true` if it should terminate a linear MMIO scan.
    fn is_fatal(self) -> bool {
        matches!(self, Self::MmioUnavailable | Self::MagicMismatch)
    }
}
