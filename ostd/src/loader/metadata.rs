use alloc::{format, string::String};
use core::fmt::Write;

use xmas_elf::{
    ElfFile,
    sections::{SHF_ALLOC, SectionHeader, ShType},
};

use super::{invalid_args, service_object::ServiceObject};
use crate::Result;

const FRAMEVM_METADATA_SECTION: &str = ".framevm.meta";
const MAGIC: &[u8; 8] = b"FVMETA\0\0";
const FORMAT_VERSION: u16 = 1;
const ENDIAN_LITTLE: u8 = 1;
const WORD_SIZE_64: u8 = 8;
const VALIDATION_PASSED: u8 = 1;
const TARGET_ARCH_X86_64: u8 = 1;
const ARTIFACT_FORMAT_RELOCATABLE_ELF: u8 = 1;
const ENTRY_POINT_RETURNS_TO_LOADER: u8 = 1;
const PAYLOAD_SIZE: usize = 128;
const HASH_OFFSET: usize = 48;
const HASH_SIZE: usize = 32;
const LOADABLE_PAYLOAD_SIZE_OFFSET: usize = 112;

pub(super) fn validate_framevm_metadata(service_object: &ServiceObject) -> Result<()> {
    let elf_file = service_object.elf_file();
    let section = find_framevm_metadata_section(elf_file)
        .ok_or_else(|| invalid_args("service module object is missing `.framevm.meta`"))?;
    if section.get_type() != Ok(ShType::ProgBits) {
        return Err(invalid_args(
            "service module `.framevm.meta` section has an unexpected type",
        ));
    }
    if (section.flags() & SHF_ALLOC) != 0 {
        return Err(invalid_args(
            "service module `.framevm.meta` section must not be loaded",
        ));
    }

    let payload = section.raw_data(elf_file);
    if payload.len() != PAYLOAD_SIZE {
        return Err(invalid_args(format!(
            "service module `.framevm.meta` size is {}, expected {}",
            payload.len(),
            PAYLOAD_SIZE
        )));
    }
    validate_header(payload)?;
    validate_symbols_hash(payload)?;
    validate_loadable_payload_size(payload, elf_file)
}

fn find_framevm_metadata_section<'a>(elf_file: &'a ElfFile) -> Option<SectionHeader<'a>> {
    for section_index in (0..elf_file.header.pt2.sh_count()).rev() {
        let Ok(section) = elf_file.section_header(section_index) else {
            continue;
        };
        let Ok(name) = section.get_name(elf_file) else {
            continue;
        };
        if name == FRAMEVM_METADATA_SECTION {
            return Some(section);
        }
    }
    None
}

fn validate_header(payload: &[u8]) -> Result<()> {
    if &payload[..MAGIC.len()] != MAGIC {
        return Err(invalid_args(
            "service module `.framevm.meta` magic mismatch",
        ));
    }
    let version = u16::from_le_bytes([payload[8], payload[9]]);
    if version != FORMAT_VERSION {
        return Err(invalid_args(format!(
            "unsupported service module `.framevm.meta` version {}",
            version
        )));
    }
    if payload[10] != ENDIAN_LITTLE {
        return Err(invalid_args(format!(
            "unsupported service module `.framevm.meta` endian {}",
            payload[10]
        )));
    }
    if payload[11] != WORD_SIZE_64 {
        return Err(invalid_args(format!(
            "unsupported service module `.framevm.meta` word size {}",
            payload[11]
        )));
    }
    if payload[12] != VALIDATION_PASSED {
        return Err(invalid_args(
            "service module `.framevm.meta` validation status is not passed",
        ));
    }
    if payload[13] != TARGET_ARCH_X86_64 {
        return Err(invalid_args(format!(
            "unsupported service module `.framevm.meta` target architecture {}",
            payload[13]
        )));
    }
    if payload[14] != ARTIFACT_FORMAT_RELOCATABLE_ELF {
        return Err(invalid_args(format!(
            "unsupported service module `.framevm.meta` artifact format {}",
            payload[14]
        )));
    }
    if payload[15] != ENTRY_POINT_RETURNS_TO_LOADER {
        return Err(invalid_args(format!(
            "unsupported service module `.framevm.meta` entry point assumption {}",
            payload[15]
        )));
    }
    Ok(())
}

fn validate_symbols_hash(payload: &[u8]) -> Result<()> {
    let expected = crate::symbols::framevm_symbols_payload_hash().ok_or_else(|| {
        invalid_args("framevm symbol table hash is unavailable during metadata validation")
    })?;
    let actual = &payload[HASH_OFFSET..HASH_OFFSET + HASH_SIZE];
    if actual != expected {
        return Err(invalid_args(format!(
            "service module `.framevm.meta` framevm_symbols_hash mismatch: expected {}, got {}",
            hex(&expected),
            hex(actual)
        )));
    }
    Ok(())
}

fn validate_loadable_payload_size(payload: &[u8], elf_file: &ElfFile) -> Result<()> {
    let recorded_size = read_u64(payload, LOADABLE_PAYLOAD_SIZE_OFFSET)?;
    let actual_size = loadable_payload_size(elf_file)?;
    if recorded_size != actual_size {
        return Err(invalid_args(format!(
            "service module `.framevm.meta` loadable payload size mismatch: expected {}, got {}",
            recorded_size, actual_size
        )));
    }
    Ok(())
}

fn loadable_payload_size(elf_file: &ElfFile) -> Result<u64> {
    let mut total = 0u64;
    for section in elf_file.section_iter() {
        if (section.flags() & SHF_ALLOC) == 0 {
            continue;
        }
        let section_name = section.get_name(elf_file).ok();
        if section_name == Some(FRAMEVM_METADATA_SECTION)
            || section_name
                .map(|name| name.starts_with(".debug"))
                .unwrap_or(false)
        {
            continue;
        }
        total = total
            .checked_add(section.size())
            .ok_or_else(|| invalid_args("service module loadable payload size overflows u64"))?;
    }
    Ok(total)
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| invalid_args("service module `.framevm.meta` u64 offset overflows"))?;
    let bytes = payload
        .get(offset..end)
        .ok_or_else(|| invalid_args("service module `.framevm.meta` u64 field exceeds payload"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
