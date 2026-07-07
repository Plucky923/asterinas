// SPDX-License-Identifier: MPL-2.0

//! Embedded FrameVM service metadata generation.
//!
//! The metadata section is a small loader-facing contract. Detailed import and
//! host-symbol evidence remains in OSDK reports; the runtime loader only needs
//! enough data to reject a service object paired with the wrong symbol table.

use std::{fs, io::Write, path::Path};

use sha2::{Digest, Sha256};
use xmas_elf::{
    ElfFile,
    sections::{SHF_ALLOC, SectionHeader, ShType},
};

use super::{
    identity::{FrameVmExportManifestArtifact, FrameVmTransactionIdentity},
    object::FrameVmObjectArtifact,
    process,
    symbols::FrameVmSymbolsArtifact,
    types::FrameVmStageError,
};

pub(super) const FRAMEVM_METADATA_SECTION: &str = ".framevm.meta";

const FRAMEVM_METADATA_FILE_NAME: &str = "framevm.meta";
const MAGIC: &[u8; 8] = b"FVMETA\0\0";
const FORMAT_VERSION: u16 = 1;
const ENDIAN_LITTLE: u8 = 1;
const WORD_SIZE_64: u8 = 8;
const VALIDATION_PASSED: u8 = 1;
const TARGET_ARCH_X86_64: u8 = 1;
const ARTIFACT_FORMAT_RELOCATABLE_ELF: u8 = 1;
const ENTRY_POINT_RETURNS_TO_LOADER: u8 = 1;
const PAYLOAD_SIZE: usize = 128;
const TRANSACTION_ID_OFFSET: usize = 16;
const HASH_SIZE: usize = 32;
const FRAMEVM_SYMBOLS_HASH_OFFSET: usize = 48;
const EXPORT_MANIFEST_HASH_OFFSET: usize = 80;
const LOADABLE_PAYLOAD_SIZE_OFFSET: usize = 112;
const RETAINED_RLIB_COUNT_OFFSET: usize = 120;
const BUNDLED_OBJECT_COUNT_OFFSET: usize = 124;

#[derive(Clone, Debug)]
pub(super) struct FrameVmMetadataArtifact {
    path: std::path::PathBuf,
    payload_hash: FrameVmMetadataHash,
    payload_size: usize,
}

#[derive(Clone, Debug)]
pub(super) struct EmbeddedFrameVmMetadata {
    pub(super) transaction_id: String,
    pub(super) framevm_symbols_hash: String,
    pub(super) export_manifest_hash: String,
    pub(super) loadable_payload_size: u64,
    pub(super) retained_rlib_count: u32,
    pub(super) bundled_object_count: u32,
    pub(super) payload_hash: String,
}

impl FrameVmMetadataArtifact {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn with_path(&self, path: std::path::PathBuf) -> Self {
        Self {
            path,
            payload_hash: self.payload_hash.clone(),
            payload_size: self.payload_size,
        }
    }

    pub(super) fn payload_hash(&self) -> &FrameVmMetadataHash {
        &self.payload_hash
    }

    pub(super) fn payload_size(&self) -> usize {
        self.payload_size
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FrameVmMetadataHash([u8; 32]);

impl FrameVmMetadataHash {
    pub(super) fn hex(&self) -> String {
        super::imports::bytes_to_hex(&self.0)
    }
}

pub(super) fn embed_framevm_metadata(
    object: &FrameVmObjectArtifact,
    symbols: &FrameVmSymbolsArtifact,
    transaction_identity: &FrameVmTransactionIdentity,
    export_manifest: &FrameVmExportManifestArtifact,
) -> Result<FrameVmMetadataArtifact, FrameVmStageError> {
    let output_path = object.report_dir.join(FRAMEVM_METADATA_FILE_NAME);
    let loadable_payload_size = validated_loadable_payload_size(&object.path)?;
    let payload = encode_payload(
        object,
        symbols,
        transaction_identity,
        export_manifest,
        loadable_payload_size,
    )?;
    write_payload(&output_path, &payload)?;
    add_metadata_section(&object.path, &output_path)?;

    Ok(FrameVmMetadataArtifact {
        path: output_path,
        payload_hash: hash_payload(&payload),
        payload_size: payload.len(),
    })
}

pub(super) fn inspect_embedded_metadata(
    object_path: &Path,
) -> Result<EmbeddedFrameVmMetadata, FrameVmStageError> {
    let bytes = fs::read(object_path).map_err(|error| {
        FrameVmStageError::Run(format!(
            "failed to read FrameVM object {}: {error}",
            object_path.display()
        ))
    })?;
    let elf = ElfFile::new(&bytes).map_err(|error| {
        FrameVmStageError::Run(format!(
            "failed to parse FrameVM object {} while reading metadata: {error:?}",
            object_path.display()
        ))
    })?;
    let section = find_metadata_section(&elf).ok_or_else(|| {
        FrameVmStageError::Run(format!(
            "FrameVM object {} is missing `{FRAMEVM_METADATA_SECTION}`",
            object_path.display()
        ))
    })?;
    validate_metadata_section(&section, &elf)?;

    let payload = section.raw_data(&elf);
    validate_payload(payload)?;
    Ok(EmbeddedFrameVmMetadata {
        transaction_id: hash_field(payload, TRANSACTION_ID_OFFSET)?,
        framevm_symbols_hash: hash_field(payload, FRAMEVM_SYMBOLS_HASH_OFFSET)?,
        export_manifest_hash: hash_field(payload, EXPORT_MANIFEST_HASH_OFFSET)?,
        loadable_payload_size: read_u64(payload, LOADABLE_PAYLOAD_SIZE_OFFSET)?,
        retained_rlib_count: read_u32(payload, RETAINED_RLIB_COUNT_OFFSET)?,
        bundled_object_count: read_u32(payload, BUNDLED_OBJECT_COUNT_OFFSET)?,
        payload_hash: hash_payload(payload).hex(),
    })
}

fn encode_payload(
    object: &FrameVmObjectArtifact,
    symbols: &FrameVmSymbolsArtifact,
    transaction_identity: &FrameVmTransactionIdentity,
    export_manifest: &FrameVmExportManifestArtifact,
    loadable_payload_size: u64,
) -> Result<Vec<u8>, FrameVmStageError> {
    let retained_rlib_count = u32::try_from(object.dependency_summary.retained_rlib_count())
        .map_err(|_| {
            FrameVmStageError::ObjectBuild(
                "FrameVM metadata retained rlib count exceeds u32::MAX".to_string(),
            )
        })?;
    let bundled_object_count = u32::try_from(object.dependency_summary.bundled_object_count())
        .map_err(|_| {
            FrameVmStageError::ObjectBuild(
                "FrameVM metadata bundled object count exceeds u32::MAX".to_string(),
            )
        })?;
    let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
    payload.extend(MAGIC);
    payload.extend(FORMAT_VERSION.to_le_bytes());
    payload.push(ENDIAN_LITTLE);
    payload.push(WORD_SIZE_64);
    payload.push(VALIDATION_PASSED);
    payload.push(TARGET_ARCH_X86_64);
    payload.push(ARTIFACT_FORMAT_RELOCATABLE_ELF);
    payload.push(ENTRY_POINT_RETURNS_TO_LOADER);
    payload.extend(transaction_identity.transaction_id().as_bytes());
    payload.extend(symbols.payload_hash().as_bytes());
    payload.extend(export_manifest.payload_hash().as_bytes());
    payload.extend(loadable_payload_size.to_le_bytes());
    payload.extend(retained_rlib_count.to_le_bytes());
    payload.extend(bundled_object_count.to_le_bytes());
    payload.resize(PAYLOAD_SIZE, 0);
    Ok(payload)
}

fn validated_loadable_payload_size(object_path: &Path) -> Result<u64, FrameVmStageError> {
    let bytes = fs::read(object_path).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to read FrameVM object {} while sizing loadable payload: {error}",
            object_path.display()
        ))
    })?;
    let elf = ElfFile::new(&bytes).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to parse FrameVM object {} while sizing loadable payload: {error:?}",
            object_path.display()
        ))
    })?;
    let mut total = 0u64;
    for section in elf.section_iter() {
        if (section.flags() & SHF_ALLOC) == 0 {
            continue;
        }
        let name = section.get_name(&elf).unwrap_or("");
        if name == FRAMEVM_METADATA_SECTION || name.starts_with(".debug") {
            continue;
        }
        total = total.checked_add(section.size()).ok_or_else(|| {
            FrameVmStageError::ObjectBuild(
                "FrameVM metadata loadable payload size overflows u64".to_string(),
            )
        })?;
    }
    Ok(total)
}

fn write_payload(path: &Path, payload: &[u8]) -> Result<(), FrameVmStageError> {
    let mut file = fs::File::create(path).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to create FrameVM metadata {}: {error}",
            path.display()
        ))
    })?;
    file.write_all(payload).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to write FrameVM metadata {}: {error}",
            path.display()
        ))
    })
}

fn add_metadata_section(object_path: &Path, metadata_path: &Path) -> Result<(), FrameVmStageError> {
    let mut command = process::command("objcopy");
    command
        .arg("--add-section")
        .arg(format!(
            "{FRAMEVM_METADATA_SECTION}={}",
            metadata_path.display()
        ))
        .arg("--set-section-flags")
        .arg(format!("{FRAMEVM_METADATA_SECTION}=readonly,contents"))
        .arg(object_path);

    process::run_status(
        command,
        "embedding FrameVM service metadata",
        FrameVmStageError::ObjectBuild,
    )
}

fn find_metadata_section<'a>(elf: &'a ElfFile) -> Option<SectionHeader<'a>> {
    for section_index in (0..elf.header.pt2.sh_count()).rev() {
        let Ok(section) = elf.section_header(section_index) else {
            continue;
        };
        let Ok(name) = section.get_name(elf) else {
            continue;
        };
        if name == FRAMEVM_METADATA_SECTION {
            return Some(section);
        }
    }
    None
}

fn validate_metadata_section(
    section: &SectionHeader,
    elf: &ElfFile,
) -> Result<(), FrameVmStageError> {
    if section.get_type() != Ok(ShType::ProgBits) {
        return Err(FrameVmStageError::Run(
            "FrameVM metadata section has an unexpected ELF section type".to_string(),
        ));
    }
    if (section.flags() & SHF_ALLOC) != 0 {
        return Err(FrameVmStageError::Run(
            "FrameVM metadata section must not be loaded".to_string(),
        ));
    }
    let payload = section.raw_data(elf);
    if payload.len() != PAYLOAD_SIZE {
        return Err(FrameVmStageError::Run(format!(
            "FrameVM metadata section size is {}, expected {}",
            payload.len(),
            PAYLOAD_SIZE
        )));
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> Result<(), FrameVmStageError> {
    if payload.len() != PAYLOAD_SIZE {
        return Err(FrameVmStageError::Run(format!(
            "FrameVM metadata payload size is {}, expected {}",
            payload.len(),
            PAYLOAD_SIZE
        )));
    }
    if payload.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(FrameVmStageError::Run(
            "FrameVM metadata magic mismatch".to_string(),
        ));
    }
    let version = u16::from_le_bytes([payload[8], payload[9]]);
    if version != FORMAT_VERSION {
        return Err(FrameVmStageError::Run(format!(
            "unsupported FrameVM metadata version {version}"
        )));
    }
    if payload[10] != ENDIAN_LITTLE {
        return Err(FrameVmStageError::Run(format!(
            "unsupported FrameVM metadata endian {}",
            payload[10]
        )));
    }
    if payload[11] != WORD_SIZE_64 {
        return Err(FrameVmStageError::Run(format!(
            "unsupported FrameVM metadata word size {}",
            payload[11]
        )));
    }
    if payload[12] != VALIDATION_PASSED {
        return Err(FrameVmStageError::Run(
            "FrameVM metadata validation status is not passed".to_string(),
        ));
    }
    if payload[13] != TARGET_ARCH_X86_64 {
        return Err(FrameVmStageError::Run(format!(
            "unsupported FrameVM metadata target architecture {}",
            payload[13]
        )));
    }
    if payload[14] != ARTIFACT_FORMAT_RELOCATABLE_ELF {
        return Err(FrameVmStageError::Run(format!(
            "unsupported FrameVM metadata artifact format {}",
            payload[14]
        )));
    }
    if payload[15] != ENTRY_POINT_RETURNS_TO_LOADER {
        return Err(FrameVmStageError::Run(format!(
            "unsupported FrameVM metadata entry point assumption {}",
            payload[15]
        )));
    }
    Ok(())
}

fn hash_field(payload: &[u8], offset: usize) -> Result<String, FrameVmStageError> {
    let end = offset.checked_add(HASH_SIZE).ok_or_else(|| {
        FrameVmStageError::Run("FrameVM metadata hash field offset overflow".to_string())
    })?;
    let field = payload.get(offset..end).ok_or_else(|| {
        FrameVmStageError::Run("FrameVM metadata hash field is out of bounds".to_string())
    })?;
    Ok(super::imports::bytes_to_hex(field))
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, FrameVmStageError> {
    let end = offset.checked_add(4).ok_or_else(|| {
        FrameVmStageError::Run("FrameVM metadata u32 field offset overflow".to_string())
    })?;
    let field = payload.get(offset..end).ok_or_else(|| {
        FrameVmStageError::Run("FrameVM metadata u32 field is out of bounds".to_string())
    })?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64, FrameVmStageError> {
    let end = offset.checked_add(8).ok_or_else(|| {
        FrameVmStageError::Run("FrameVM metadata u64 field offset overflow".to_string())
    })?;
    let field = payload.get(offset..end).ok_or_else(|| {
        FrameVmStageError::Run("FrameVM metadata u64 field is out of bounds".to_string())
    })?;
    Ok(u64::from_le_bytes([
        field[0], field[1], field[2], field[3], field[4], field[5], field[6], field[7],
    ]))
}

fn hash_payload(payload: &[u8]) -> FrameVmMetadataHash {
    let digest = Sha256::digest(payload);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    FrameVmMetadataHash(hash)
}
