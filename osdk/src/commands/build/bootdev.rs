// SPDX-License-Identifier: MPL-2.0

use std::{
    fs,
    path::{Path, PathBuf},
};

use super::bin::make_install_bzimage;
use crate::{
    bundle::{
        bin::AsterBin,
        file::BundleFile,
        vm_image::{AsterGrubIsoImageMeta, AsterVmImage, AsterVmImageType},
    },
    config::{
        scheme::{ActionChoice, BootProtocol},
        Config,
    },
    util::{get_current_crates, hard_link_or_copy, new_command_checked_exists},
};

/// Creates a bootable device image (CD-ROM ISO) with GRUB bootloader.
///
/// # Arguments
/// * `target_dir` - Target directory where the ISO will be created
/// * `aster_bin` - Asterinas binary kernel to include
/// * `initramfs_path` - Optional path to initramfs CPIO archive
/// * `binary_path` - Optional path to additional binary module
/// * `config` - Build configuration
/// * `action` - Build action (Run/Test)
///
/// # Returns
/// Returns `AsterVmImage` containing the path to the generated ISO and metadata
pub fn create_bootdev_image(
    target_dir: impl AsRef<Path>,
    aster_bin: &AsterBin,
    initramfs_path: Option<impl AsRef<Path>>,
    binary_path: Option<impl AsRef<Path>>,
    config: &Config,
    action: ActionChoice,
) -> AsterVmImage {
    let target_name = get_current_crates().remove(0).name;
    let iso_root = target_dir.as_ref().join("iso_root");
    let action = match &action {
        ActionChoice::Run => &config.run,
        ActionChoice::Test => &config.test,
    };
    let protocol = &action.grub.boot_protocol;

    // Clean or create ISO directory
    if iso_root.exists() {
        fs::remove_dir_all(&iso_root)
            .expect("Failed to remove existing ISO root directory");
    }
    fs::create_dir_all(iso_root.join("boot").join("grub"))
        .expect("Failed to create ISO directory structure");

    // Copy initramfs to boot directory if provided
    if let Some(init_path) = &initramfs_path {
        hard_link_or_copy(
            init_path.as_ref().to_str()
                .expect("Invalid UTF-8 in initramfs path"),
            iso_root.join("boot").join("initramfs.cpio.gz"),
        )
        .expect("Failed to copy initramfs");
    }

    // Handle additional binary module (like FrameVM)
    let binary_in_image = if let Some(bin_path) = &binary_path {
        let binary_file_name = bin_path.as_ref()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("Invalid binary file name");

        hard_link_or_copy(
            bin_path.as_ref().to_str()
                .expect("Invalid UTF-8 in binary path"),
            iso_root.join("boot").join(binary_file_name),
        )
        .expect("Failed to copy binary file");

        Some(format!("/boot/{}", binary_file_name))
    } else {
        None
    };

    // Generate kernel image based on boot protocol
    match protocol {
        BootProtocol::Linux => {
            make_install_bzimage(
                iso_root.join("boot"),
                target_dir.as_ref(),
                aster_bin,
                action.build.linux_x86_legacy_boot,
                config.build.encoding.clone(),
            );
        }
        _ => {
            // Copy kernel image directly to boot directory
            let target_path = iso_root.join("boot").join(&target_name);
            hard_link_or_copy(aster_bin.path(), target_path)
                .expect("Failed to copy kernel image");
        }
    };

    // Generate GRUB configuration
    let initramfs_in_image = if initramfs_path.is_some() {
        Some("/boot/initramfs.cpio.gz".to_string())
    } else {
        None
    };

    let grub_cfg = generate_grub_cfg(
        &action.boot.kcmdline.join(" "),
        !action.grub.display_grub_menu,
        initramfs_in_image,
        binary_in_image,
        protocol,
    );

    let grub_cfg_path = iso_root.join("boot").join("grub").join("grub.cfg");
    fs::write(grub_cfg_path, grub_cfg)
        .expect("Failed to write GRUB configuration");

    // Create bootable ISO image using grub-mkrescue
    let iso_path = target_dir.as_ref().join(format!("{}.iso", target_name));
    let mut grub_mkrescue_cmd = new_command_checked_exists(action.grub.grub_mkrescue.as_os_str());
    grub_mkrescue_cmd
        .arg(&iso_root)
        .arg("-o")
        .arg(&iso_path);

    if !grub_mkrescue_cmd.status().expect("Failed to execute grub-mkrescue").success() {
        panic!("Failed to create ISO using grub-mkrescue: {:?}", grub_mkrescue_cmd);
    }

    AsterVmImage::new(
        iso_path,
        AsterVmImageType::GrubIso(AsterGrubIsoImageMeta {
            grub_version: get_grub_mkrescue_version(&action.grub.grub_mkrescue),
        }),
        aster_bin.version().clone(),
    )
}

/// Generates GRUB configuration file content.
///
/// # Arguments
/// * `kcmdline` - Kernel command line parameters
/// * `skip_grub_menu` - Whether to hide GRUB menu
/// * `initramfs_path` - Optional path to initramfs
/// * `binary_path` - Optional path to additional binary
/// * `protocol` - Boot protocol to use
///
/// # Returns
/// Generated GRUB configuration as string
fn generate_grub_cfg(
    kcmdline: &str,
    skip_grub_menu: bool,
    initramfs_path: Option<String>,
    binary_path: Option<String>,
    protocol: &BootProtocol,
) -> String {
    let target_name = get_current_crates().remove(0).name;
    let grub_cfg = include_str!("grub.cfg.template").to_string();

    // Remove template header (first two lines)
    let grub_cfg = grub_cfg
        .lines()
        .skip(2)
        .collect::<Vec<&str>>()
        .join("\n");

    // Set timeout style and duration
    let grub_cfg = grub_cfg
        .replace(
            "#GRUB_TIMEOUT_STYLE#",
            if skip_grub_menu { "hidden" } else { "menu" },
        )
        .replace(
            "#GRUB_TIMEOUT#",
            if skip_grub_menu { "0" } else { "5" }
        );

    // Set kernel command line
    let grub_cfg = grub_cfg.replace("#KERNEL_COMMAND_LINE#", kcmdline);

    // Configure kernel path
    let aster_bin_path_on_device = Path::new("/boot")
        .join(&target_name)
        .to_str()
        .expect("Invalid kernel path")
        .to_string();

    // Apply protocol-specific configuration
    match protocol {
        BootProtocol::Multiboot => grub_cfg
            .replace("#GRUB_CMD_KERNEL#", "multiboot")
            .replace("#KERNEL#", &aster_bin_path_on_device)
            .replace(
                "#GRUB_CMD_INITRAMFS#",
                &if let Some(p) = &initramfs_path {
                    format!("module --nounzip {}", p)
                } else {
                    String::new()
                },
            ),
        BootProtocol::Multiboot2 => grub_cfg
            .replace("#GRUB_CMD_KERNEL#", "multiboot2")
            .replace("#KERNEL#", &aster_bin_path_on_device)
            .replace(
                "#GRUB_CMD_INITRAMFS#",
                &if let Some(p) = &initramfs_path {
                    format!("module2 --nounzip {}", p)
                } else {
                    String::new()
                },
            )
            .replace(
                "#GRUB_CMD_BINARY#",
                &if let Some(p) = &binary_path {
                    format!("module2 {}", p)
                } else {
                    String::new()
                },
            ),
        BootProtocol::Linux => grub_cfg
            .replace("#GRUB_CMD_KERNEL#", "linux")
            .replace("#KERNEL#", &aster_bin_path_on_device)
            .replace(
                "#GRUB_CMD_INITRAMFS#",
                &if let Some(p) = &initramfs_path {
                    format!("initrd {}", p)
                } else {
                    String::new()
                },
            ),
    }
}

/// Retrieves the version string of grub-mkrescue utility.
///
/// # Arguments
/// * `grub_mkrescue` - Path to grub-mkrescue executable
///
/// # Returns
/// Version string from grub-mkrescue --version output
fn get_grub_mkrescue_version(grub_mkrescue: &PathBuf) -> String {
    let mut cmd = new_command_checked_exists(grub_mkrescue);
    cmd.arg("--version");

    let output = cmd.output()
        .expect("Failed to execute grub-mkrescue --version");

    String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 in grub-mkrescue version output")
        .trim()
        .to_string()
}