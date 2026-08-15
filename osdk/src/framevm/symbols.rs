// SPDX-License-Identifier: MPL-2.0

//! Runtime symbol-table payload generation for FrameVM loading.
//!
//! This module writes the OSDK-owned `framevm.symbols` boot payload from final
//! host validation facts. The payload layout is the cross-component contract;
//! report formatting and host-symbol diagnostics remain outside this module.

use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    host::{HostImportValidation, HostSymbolMatch},
    imports::RawSymbolName,
    object::FrameVmObjectArtifact,
    types::FrameVmStageError,
};

const FRAMEVM_SYMBOLS_FILE_NAME: &str = "framevm.symbols";
const MAGIC: &[u8; 8] = b"FVSYMTB\0";
const FORMAT_VERSION: u16 = 1;
const ENDIAN_LITTLE: u8 = 1;
const WORD_SIZE_64: u8 = 8;
const HEADER_SIZE: usize = 64;
const HEADER_SIZE_U32: u32 = 64;

#[derive(Clone, Debug)]
pub(super) struct FrameVmSymbolsArtifact {
    path: PathBuf,
    payload_hash: FrameVmSymbolsHash,
    symbol_count: usize,
    payload_size: usize,
}

impl FrameVmSymbolsArtifact {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn with_path(&self, path: PathBuf) -> Self {
        Self {
            path,
            payload_hash: self.payload_hash.clone(),
            symbol_count: self.symbol_count,
            payload_size: self.payload_size,
        }
    }

    pub(super) fn payload_hash(&self) -> &FrameVmSymbolsHash {
        &self.payload_hash
    }

    pub(super) fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    pub(super) fn payload_size(&self) -> usize {
        self.payload_size
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FrameVmSymbolsHash([u8; 32]);

impl FrameVmSymbolsHash {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn hex(&self) -> String {
        super::imports::bytes_to_hex(&self.0)
    }
}

struct SymbolPayloadEntry<'a> {
    raw_name: &'a RawSymbolName,
    value: u64,
}

pub(super) fn write_framevm_symbols(
    object: &FrameVmObjectArtifact,
    validation: &HostImportValidation,
) -> Result<FrameVmSymbolsArtifact, FrameVmStageError> {
    if !validation.is_exact_match() {
        return Err(FrameVmStageError::ImportValidation(
            "cannot generate framevm.symbols before final host validation succeeds".to_string(),
        ));
    }

    let output_path = object.report_dir.join(FRAMEVM_SYMBOLS_FILE_NAME);
    let entries = sorted_payload_entries(validation.matches())?;
    let payload = encode_payload(&entries)?;
    let payload_hash = hash_payload(&payload);

    write_payload(&output_path, &payload)?;

    Ok(FrameVmSymbolsArtifact {
        path: output_path,
        payload_hash,
        symbol_count: entries.len(),
        payload_size: payload.len(),
    })
}

pub(super) fn inspect_framevm_symbols(
    path: &Path,
) -> Result<FrameVmSymbolsArtifact, FrameVmStageError> {
    let payload = fs::read(path).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to read framevm.symbols {}: {error}",
            path.display()
        ))
    })?;
    let symbol_count = parse_symbol_count(&payload, path)?;
    let payload_hash = hash_payload(&payload);

    Ok(FrameVmSymbolsArtifact {
        path: path.to_path_buf(),
        payload_hash,
        symbol_count,
        payload_size: payload.len(),
    })
}

fn sorted_payload_entries(
    matches: &[HostSymbolMatch],
) -> Result<Vec<SymbolPayloadEntry<'_>>, FrameVmStageError> {
    let mut entries = matches
        .iter()
        .map(|symbol_match| SymbolPayloadEntry {
            raw_name: symbol_match.import_name(),
            value: symbol_match.value(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.raw_name.as_bytes().cmp(right.raw_name.as_bytes()));
    validate_payload_entries(&entries)?;

    Ok(entries)
}

fn validate_payload_entries(entries: &[SymbolPayloadEntry<'_>]) -> Result<(), FrameVmStageError> {
    let mut seen_names = BTreeSet::new();
    for entry in entries {
        let raw_name = entry.raw_name.as_bytes();
        if raw_name.is_empty() {
            return Err(FrameVmStageError::ImportValidation(
                "framevm.symbols cannot encode an empty raw symbol name".to_string(),
            ));
        }
        if raw_name.len() > u16::MAX as usize {
            return Err(FrameVmStageError::ImportValidation(format!(
                "framevm.symbols raw symbol name is too long: {} bytes",
                raw_name.len()
            )));
        }
        if !seen_names.insert(raw_name) {
            return Err(FrameVmStageError::ImportValidation(format!(
                "framevm.symbols duplicate raw symbol name: {}",
                entry.raw_name
            )));
        }
    }
    Ok(())
}

fn encode_payload(entries: &[SymbolPayloadEntry<'_>]) -> Result<Vec<u8>, FrameVmStageError> {
    let symbol_count = u32::try_from(entries.len()).map_err(|_| {
        FrameVmStageError::ImportValidation(
            "framevm.symbols symbol count exceeds u32::MAX".to_string(),
        )
    })?;

    let mut raw_names = Vec::new();
    let mut name_offsets = Vec::with_capacity(entries.len());
    for entry in entries {
        let offset = u32::try_from(raw_names.len()).map_err(|_| {
            FrameVmStageError::ImportValidation(
                "framevm.symbols raw-name stream offset exceeds u32::MAX".to_string(),
            )
        })?;
        name_offsets.push(offset);

        let raw_name = entry.raw_name.as_bytes();
        let name_len = u16::try_from(raw_name.len()).map_err(|_| {
            FrameVmStageError::ImportValidation(format!(
                "framevm.symbols raw symbol name is too long: {} bytes",
                raw_name.len()
            ))
        })?;
        raw_names.extend(name_len.to_le_bytes());
        raw_names.extend(raw_name);
    }

    let name_seqs = sorted_name_sequences(entries)?;

    let values_offset = HEADER_SIZE_U32;
    let values_size = checked_table_size(entries.len(), 8, "value table")?;
    let name_seqs_offset = checked_u32_add(values_offset, values_size, "name_seqs offset")?;
    let name_seqs_size = checked_table_size(entries.len(), 4, "name_seqs table")?;
    let name_offsets_offset =
        checked_u32_add(name_seqs_offset, name_seqs_size, "name_offsets offset")?;
    let name_offsets_size = checked_table_size(entries.len(), 4, "name_offsets table")?;
    let raw_names_offset =
        checked_u32_add(name_offsets_offset, name_offsets_size, "raw_names offset")?;
    let raw_names_size = u32::try_from(raw_names.len()).map_err(|_| {
        FrameVmStageError::ImportValidation(
            "framevm.symbols raw-name stream size exceeds u32::MAX".to_string(),
        )
    })?;
    let payload_size = checked_u32_add(raw_names_offset, raw_names_size, "payload size")?;

    let mut payload = Vec::with_capacity(payload_size as usize);
    write_header(
        &mut payload,
        symbol_count,
        values_offset,
        name_seqs_offset,
        name_offsets_offset,
        raw_names_offset,
        raw_names_size,
        payload_size,
    );
    for entry in entries {
        payload.extend(entry.value.to_le_bytes());
    }
    for seq in name_seqs {
        payload.extend(seq.to_le_bytes());
    }
    for offset in name_offsets {
        payload.extend(offset.to_le_bytes());
    }
    payload.extend(raw_names);

    debug_assert_eq!(payload.len(), payload_size as usize);
    Ok(payload)
}

fn sorted_name_sequences(
    entries: &[SymbolPayloadEntry<'_>],
) -> Result<Vec<u32>, FrameVmStageError> {
    let mut name_seqs = (0..entries.len()).collect::<Vec<_>>();
    name_seqs.sort_by(|left, right| {
        entries[*left]
            .raw_name
            .as_bytes()
            .cmp(entries[*right].raw_name.as_bytes())
    });

    name_seqs
        .into_iter()
        .map(|seq| {
            u32::try_from(seq).map_err(|_| {
                FrameVmStageError::ImportValidation(
                    "framevm.symbols symbol sequence exceeds u32::MAX".to_string(),
                )
            })
        })
        .collect()
}

#[expect(clippy::too_many_arguments)]
fn write_header(
    payload: &mut Vec<u8>,
    symbol_count: u32,
    values_offset: u32,
    name_seqs_offset: u32,
    name_offsets_offset: u32,
    raw_names_offset: u32,
    raw_names_size: u32,
    payload_size: u32,
) {
    payload.extend(MAGIC);
    payload.extend(FORMAT_VERSION.to_le_bytes());
    payload.push(ENDIAN_LITTLE);
    payload.push(WORD_SIZE_64);
    payload.extend(0u32.to_le_bytes());
    payload.extend(symbol_count.to_le_bytes());
    payload.extend(values_offset.to_le_bytes());
    payload.extend(name_seqs_offset.to_le_bytes());
    payload.extend(name_offsets_offset.to_le_bytes());
    payload.extend(raw_names_offset.to_le_bytes());
    payload.extend(raw_names_size.to_le_bytes());
    payload.extend(payload_size.to_le_bytes());
    payload.resize(HEADER_SIZE, 0);
}

fn checked_table_size(
    count: usize,
    entry_size: usize,
    table_name: &str,
) -> Result<u32, FrameVmStageError> {
    let size = count.checked_mul(entry_size).ok_or_else(|| {
        FrameVmStageError::ImportValidation(format!("framevm.symbols {table_name} size overflows"))
    })?;
    u32::try_from(size).map_err(|_| {
        FrameVmStageError::ImportValidation(format!(
            "framevm.symbols {table_name} size exceeds u32::MAX"
        ))
    })
}

fn checked_u32_add(left: u32, right: u32, context: &str) -> Result<u32, FrameVmStageError> {
    left.checked_add(right).ok_or_else(|| {
        FrameVmStageError::ImportValidation(format!("framevm.symbols {context} overflows"))
    })
}

fn hash_payload(payload: &[u8]) -> FrameVmSymbolsHash {
    let digest = Sha256::digest(payload);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    FrameVmSymbolsHash(hash)
}

fn parse_symbol_count(payload: &[u8], path: &Path) -> Result<usize, FrameVmStageError> {
    if payload.len() < HEADER_SIZE {
        return Err(FrameVmStageError::ImportValidation(format!(
            "framevm.symbols {} is too small: {} bytes",
            path.display(),
            payload.len()
        )));
    }
    if &payload[..MAGIC.len()] != MAGIC {
        return Err(FrameVmStageError::ImportValidation(format!(
            "framevm.symbols {} has invalid magic",
            path.display()
        )));
    }
    let version = u16::from_le_bytes([payload[8], payload[9]]);
    if version != FORMAT_VERSION {
        return Err(FrameVmStageError::ImportValidation(format!(
            "framevm.symbols {} has unsupported format version {version}",
            path.display()
        )));
    }
    if payload[10] != ENDIAN_LITTLE || payload[11] != WORD_SIZE_64 {
        return Err(FrameVmStageError::ImportValidation(format!(
            "framevm.symbols {} has incompatible endian or word-size fields",
            path.display()
        )));
    }
    Ok(u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]) as usize)
}

fn write_payload(path: &Path, payload: &[u8]) -> Result<(), FrameVmStageError> {
    let mut file = fs::File::create(path).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to create framevm.symbols {}: {error}",
            path.display()
        ))
    })?;
    file.write_all(payload).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to write framevm.symbols {}: {error}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{super::imports::RawSymbolName, *};

    #[test]
    fn duplicate_raw_lookup_keys_fail_payload_validation() {
        let raw_name = RawSymbolName::new(b"duplicate_import").unwrap();
        let entries = [
            SymbolPayloadEntry {
                raw_name: &raw_name,
                value: 0x1000,
            },
            SymbolPayloadEntry {
                raw_name: &raw_name,
                value: 0x2000,
            },
        ];

        let error = validate_payload_entries(&entries).unwrap_err();
        assert!(
            error.to_string().contains("duplicate raw symbol name"),
            "{error}"
        );
    }

    #[test]
    fn encoded_payload_orders_lookup_index_by_raw_name() {
        let z_name = RawSymbolName::new(b"z_import").unwrap();
        let a_name = RawSymbolName::new(b"a_import").unwrap();
        let entries = [
            SymbolPayloadEntry {
                raw_name: &z_name,
                value: 0x2000,
            },
            SymbolPayloadEntry {
                raw_name: &a_name,
                value: 0x1000,
            },
        ];

        let payload = encode_payload(&entries).unwrap();
        let name_seqs_offset = u32::from_le_bytes(payload[24..28].try_into().unwrap()) as usize;
        let first_seq = u32::from_le_bytes(
            payload[name_seqs_offset..name_seqs_offset + 4]
                .try_into()
                .unwrap(),
        );

        assert_eq!(first_seq, 1);
    }
}
