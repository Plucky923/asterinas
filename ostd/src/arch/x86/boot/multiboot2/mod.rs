// SPDX-License-Identifier: MPL-2.0

use core::{arch::global_asm, cell::UnsafeCell, mem::MaybeUninit, ptr, slice};

use multiboot2::{BootInformation, BootInformationHeader, MemoryAreaType, ModuleTag};

use crate::{
    boot::{
        BootloaderAcpiArg, BootloaderFramebufferArg,
        memory_region::{MemoryRegion, MemoryRegionArray, MemoryRegionType},
    },
    mm::{Paddr, kspace::paddr_to_vaddr},
};

global_asm!(include_str!("header.S"));

const MAX_FRAMEVM_SYMBOLS_BOOT_PAYLOAD_SIZE: usize = 1024 * 1024;

struct FrameVmSymbolsBootStorage {
    bytes: UnsafeCell<MaybeUninit<[u8; MAX_FRAMEVM_SYMBOLS_BOOT_PAYLOAD_SIZE]>>,
}

impl FrameVmSymbolsBootStorage {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn copy_from(&self, source: &[u8]) -> Option<&'static [u8]> {
        if source.len() > MAX_FRAMEVM_SYMBOLS_BOOT_PAYLOAD_SIZE {
            crate::early_println!(
                "[ostd] FrameVM symbol-table module is too large: len={}, max={}",
                source.len(),
                MAX_FRAMEVM_SYMBOLS_BOOT_PAYLOAD_SIZE
            );
            return None;
        }

        // SAFETY: Multiboot2 parsing runs on the boot CPU before concurrent
        // access to this storage is possible. The destination is OSTD-owned
        // static storage and does not overlap the bootloader-owned source.
        let destination = unsafe { (*self.bytes.get()).as_mut_ptr().cast::<u8>() };
        // SAFETY: The destination has at least MAX_FRAMEVM_SYMBOLS_BOOT_PAYLOAD_SIZE
        // bytes and the source length was checked above.
        unsafe {
            ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len());
        }
        // SAFETY: The copied prefix is initialized by copy_nonoverlapping and the
        // static storage lives for the rest of the kernel lifetime.
        Some(unsafe { slice::from_raw_parts(destination.cast_const(), source.len()) })
    }
}

// SAFETY: The storage is written once during single-threaded boot before it is
// published through EarlyBootInfo, and is immutable afterwards.
unsafe impl Sync for FrameVmSymbolsBootStorage {}

static FRAMEVM_SYMBOLS_BOOT_STORAGE: FrameVmSymbolsBootStorage = FrameVmSymbolsBootStorage::new();

fn parse_bootloader_name(mb2_info: &BootInformation) -> Option<&'static str> {
    let name = mb2_info.boot_loader_name_tag()?.name().ok()?;

    // SAFETY: The address of `name` is physical and the bootloader name will live for `'static`.
    Some(unsafe { make_str_vaddr_static(name) })
}

fn parse_kernel_commandline(mb2_info: &BootInformation) -> Option<&'static str> {
    let cmdline = mb2_info.command_line_tag()?.cmdline().ok()?;

    // SAFETY: The address of `cmdline` is physical and the command line will live for `'static`.
    Some(unsafe { make_str_vaddr_static(cmdline) })
}

unsafe fn make_str_vaddr_static(str: &str) -> &'static str {
    let vaddr = paddr_to_vaddr(str.as_ptr() as Paddr);

    // SAFETY: The safety is upheld by the caller.
    let bytes = unsafe { core::slice::from_raw_parts(vaddr as *const u8, str.len()) };

    core::str::from_utf8(bytes).unwrap()
}

fn parse_initramfs(mb2_info: &BootInformation) -> Option<&'static [u8]> {
    let module_tag = mb2_info
        .module_tags()
        .find(|module| {
            is_initramfs_module(module)
                && !is_kernel_binary_module(module)
                && !is_framevm_symbols_module(module)
        })
        .or_else(|| {
            mb2_info.module_tags().find(|module| {
                !is_kernel_binary_module(module) && !is_framevm_symbols_module(module)
            })
        })?;

    module_bytes(module_tag)
}

const MODULE_ARG_TYPE_INITRAMFS: &str = "type=initramfs";
const MODULE_ARG_TYPE_KERNEL_BIN: &str = "type=kernel-bin";
const MODULE_ARG_TYPE_FRAMEVM_SYMBOL_TABLE: &str = "type=framevm-symbol-table";
const MODULE_ARG_NAME_PREFIX: &str = "name=";

fn module_contains_arg(module: &ModuleTag, arg: &str) -> bool {
    module
        .cmdline()
        .is_ok_and(|cmd| cmd.split_whitespace().any(|token| token == arg))
}

fn is_kernel_binary_module(module: &ModuleTag) -> bool {
    module_contains_arg(module, MODULE_ARG_TYPE_KERNEL_BIN)
}

fn is_framevm_symbols_module(module: &ModuleTag) -> bool {
    module_contains_arg(module, MODULE_ARG_TYPE_FRAMEVM_SYMBOL_TABLE)
        && module_name(module) == Some("framevm.symbols")
}

fn is_initramfs_module(module: &ModuleTag) -> bool {
    module_contains_arg(module, MODULE_ARG_TYPE_INITRAMFS)
}

fn module_name(module: &ModuleTag) -> Option<&str> {
    module.cmdline().ok().and_then(|cmd| {
        cmd.split_whitespace()
            .find_map(|token| token.strip_prefix(MODULE_ARG_NAME_PREFIX))
    })
}

fn parse_symbols(mb2_info: &BootInformation) -> Option<&'static [u8]> {
    let module_tag = mb2_info
        .module_tags()
        .find(|module| is_kernel_binary_module(module))?;

    let symbols = module_bytes(module_tag)?;
    crate::early_println!("[ostd] Kernel symbols module found: len={}", symbols.len());
    Some(symbols)
}

fn parse_framevm_symbols_module(mb2_info: &BootInformation) -> Option<&'static [u8]> {
    let module_tag = mb2_info
        .module_tags()
        .find(|module| is_framevm_symbols_module(module))?;

    let symbols = module_bytes(module_tag)?;
    crate::early_println!(
        "[ostd] FrameVM symbol-table module found: len={}",
        symbols.len()
    );
    Some(symbols)
}

fn stabilize_framevm_symbols(symbols: &'static [u8]) -> Option<&'static [u8]> {
    FRAMEVM_SYMBOLS_BOOT_STORAGE.copy_from(symbols)
}

fn module_bytes(module_tag: &ModuleTag) -> Option<&'static [u8]> {
    let module_ptr = paddr_to_vaddr(module_tag.start_address() as usize);
    let module_len = module_tag.module_size() as usize;
    // SAFETY: The module bytes are resident and immutable according to the bootloader contract.
    Some(unsafe { core::slice::from_raw_parts(module_ptr as *const u8, module_len) })
}

fn parse_acpi_arg(mb2_info: &BootInformation) -> BootloaderAcpiArg {
    if let Some(v2_tag) = mb2_info.rsdp_v2_tag() {
        // Check for RSDP v2
        BootloaderAcpiArg::Xsdt(v2_tag.xsdt_address())
    } else if let Some(v1_tag) = mb2_info.rsdp_v1_tag() {
        // Fall back to RSDP v1
        BootloaderAcpiArg::Rsdt(v1_tag.rsdt_address())
    } else if is_efi_boot(mb2_info) {
        BootloaderAcpiArg::NotProvided
    } else {
        BootloaderAcpiArg::ScanBios
    }
}

fn is_efi_boot(mb2_info: &BootInformation) -> bool {
    mb2_info.efi_sdt32_tag().is_some()
        || mb2_info.efi_sdt64_tag().is_some()
        || mb2_info.efi_memory_map_tag().is_some()
        || mb2_info.efi_bs_not_exited_tag().is_some()
        || mb2_info.efi_ih32_tag().is_some()
        || mb2_info.efi_ih64_tag().is_some()
}

fn parse_framebuffer_info(mb2_info: &BootInformation) -> Option<BootloaderFramebufferArg> {
    let fb_tag = mb2_info.framebuffer_tag()?.ok()?;

    Some(BootloaderFramebufferArg {
        address: fb_tag.address() as usize,
        width: fb_tag.width() as usize,
        height: fb_tag.height() as usize,
        bpp: fb_tag.bpp() as usize,
    })
}

impl From<MemoryAreaType> for MemoryRegionType {
    fn from(value: MemoryAreaType) -> Self {
        match value {
            MemoryAreaType::Available => Self::Usable,
            MemoryAreaType::Reserved => Self::Reserved,
            MemoryAreaType::AcpiAvailable => Self::Reclaimable,
            MemoryAreaType::ReservedHibernate => Self::NonVolatileSleep,
            MemoryAreaType::Defective => Self::BadMemory,
            MemoryAreaType::Custom(_) => Self::Reserved,
        }
    }
}

fn parse_memory_regions(
    mb2_info: &BootInformation,
    symbols: Option<&'static [u8]>,
    framevm_symbols_module: Option<&'static [u8]>,
) -> MemoryRegionArray {
    let mut regions = MemoryRegionArray::new();

    // Add the regions returned by Grub.
    let memory_regions_tag = mb2_info
        .memory_map_tag()
        .expect("No memory regions are found in the Multiboot2 header!");
    for region in memory_regions_tag.memory_areas() {
        let start = region.start_address();
        let end = region.end_address();
        let area_typ: MemoryRegionType = MemoryAreaType::from(region.typ()).into();
        let region = MemoryRegion::new(
            start.try_into().unwrap(),
            (end - start).try_into().unwrap(),
            area_typ,
        );
        regions.push(region).unwrap();
    }

    // Add the framebuffer region since Grub does not specify it.
    if let Some(fb) = parse_framebuffer_info(mb2_info) {
        regions.push(MemoryRegion::framebuffer(&fb)).unwrap();
    }

    // Add the kernel region since Grub does not specify it.
    regions.push(MemoryRegion::kernel()).unwrap();

    // Add the initramfs region.
    if let Some(initramfs) = parse_initramfs(mb2_info) {
        regions.push(MemoryRegion::module(initramfs)).unwrap();
    }

    if let Some(symbols) = symbols {
        regions.push(MemoryRegion::module(symbols)).unwrap();
    }
    if let Some(framevm_symbols_module) = framevm_symbols_module {
        regions
            .push(MemoryRegion::module(framevm_symbols_module))
            .unwrap();
    }

    // Add the AP boot code region that will be copied into by the BSP.
    regions
        .push(super::smp::reclaimable_memory_region())
        .unwrap();

    // Add the kernel cmdline and boot loader name region since Grub does not specify it.
    if let Some(kcmdline) = parse_kernel_commandline(mb2_info) {
        regions
            .push(MemoryRegion::module(kcmdline.as_bytes()))
            .unwrap();
    }
    if let Some(bootloader_name) = parse_bootloader_name(mb2_info) {
        regions
            .push(MemoryRegion::module(bootloader_name.as_bytes()))
            .unwrap();
    }

    regions.into_non_overlapping()
}

/// The entry point of the Rust code portion of Asterinas (with multiboot2 parameters).
///
/// # Safety
///
/// - This function must be called only once at a proper timing in the BSP's boot assembly code.
/// - The caller must follow C calling conventions and put the right arguments in registers.
/// - If this function is called, entry points of other boot protocols must never be called.
// SAFETY: The name does not collide with other symbols.
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn __multiboot2_entry(boot_magic: u32, boot_params: u64) -> ! {
    assert_eq!(boot_magic, multiboot2::MAGIC);
    let mb2_info =
        unsafe { BootInformation::load(boot_params as *const BootInformationHeader).unwrap() };

    use crate::boot::{EARLY_INFO, EarlyBootInfo, start_kernel};

    let module_iter = mb2_info.module_tags();
    for module_tag in module_iter {
        let name = module_name(module_tag);
        crate::early_println!(
            "[ostd] Multiboot2 Module Found! name={:?}, cmdline='{}', start=0x{:x}, end=0x{:x}",
            name,
            module_tag.cmdline().unwrap_or("<invalid utf8>"),
            module_tag.start_address(),
            module_tag.end_address(),
        );
        crate::early_println!("[ostd] Module {:?}", module_tag);
    }

    let symbols = parse_symbols(&mb2_info);
    let framevm_symbols_module = parse_framevm_symbols_module(&mb2_info);
    let framevm_symbols = framevm_symbols_module.and_then(stabilize_framevm_symbols);

    EARLY_INFO.call_once(|| EarlyBootInfo {
        bootloader_name: parse_bootloader_name(&mb2_info).unwrap_or("Unknown Multiboot2 Loader"),
        kernel_cmdline: parse_kernel_commandline(&mb2_info).unwrap_or(""),
        initramfs: parse_initramfs(&mb2_info),
        symbols,
        framevm_symbols,
        acpi_arg: parse_acpi_arg(&mb2_info),
        framebuffer_arg: parse_framebuffer_info(&mb2_info),
        memory_regions: parse_memory_regions(&mb2_info, symbols, framevm_symbols_module),
    });

    // SAFETY: The safety is guaranteed by the safety preconditions and the fact that we call it
    // once after setting up necessary resources.
    unsafe { start_kernel() };
}
