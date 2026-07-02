// SPDX-License-Identifier: MPL-2.0

use alloc::{
    format,
    string::{String, ToString},
};
use core::{cmp::Ordering, ops::Range};

use sha2::{Digest, Sha256};
use spin::Once;

use crate::{early_println, sync::SpinLock};

const MAGIC: &[u8; 8] = b"FVSYMTB\0";
const FORMAT_VERSION: u16 = 1;
const ENDIAN_LITTLE: u8 = 1;
const WORD_SIZE_64: u8 = 8;
const HEADER_SIZE: usize = 64;

static SYMBOL_TABLE: Once<Option<SymbolTable<'static>>> = Once::new();
static INIT_ERROR: Once<SpinLock<Option<String>>> = Once::new();

#[derive(Clone, Debug)]
struct SymbolTable<'a> {
    payload: &'a [u8],
    values: Range<usize>,
    name_seqs: Range<usize>,
    name_offsets: Range<usize>,
    raw_names: Range<usize>,
    symbol_count: usize,
    payload_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DiagnosticSymbol<'a> {
    raw_name: &'a [u8],
    addr: usize,
}

impl<'a> DiagnosticSymbol<'a> {
    pub(super) fn raw_name(self) -> &'a [u8] {
        self.raw_name
    }

    pub(super) fn addr(self) -> usize {
        self.addr
    }
}

#[derive(Clone, Copy, Debug)]
struct Header {
    symbol_count: usize,
    values_offset: usize,
    name_seqs_offset: usize,
    name_offsets_offset: usize,
    raw_names_offset: usize,
    raw_names_size: usize,
    payload_size: usize,
}

pub(super) fn init_from_boot_payload(payload: Option<&'static [u8]>) {
    SYMBOL_TABLE.call_once(|| match payload {
        Some(payload) => match SymbolTable::parse(payload) {
            Ok(table) => {
                early_println!(
                    "[ostd] FrameVM symbol table initialized: symbols={}, bytes={}",
                    table.symbol_count,
                    payload.len()
                );
                Some(table)
            }
            Err(error) => {
                record_error(error);
                None
            }
        },
        None => {
            record_error("framevm.symbols boot payload is missing".to_string());
            None
        }
    });
}

pub(super) fn is_available() -> bool {
    SYMBOL_TABLE
        .get()
        .and_then(|table| table.as_ref())
        .is_some()
}

pub(super) fn lookup(raw_name: &[u8]) -> Option<usize> {
    SYMBOL_TABLE
        .get()
        .and_then(|table| table.as_ref())
        .and_then(|table| table.lookup(raw_name))
}

pub(super) fn payload_hash() -> Option<[u8; 32]> {
    SYMBOL_TABLE
        .get()
        .and_then(|table| table.as_ref())
        .map(|table| table.payload_hash)
}

pub(super) fn lookup_by_addr(addr: usize) -> Option<DiagnosticSymbol<'static>> {
    SYMBOL_TABLE
        .get()
        .and_then(|table| table.as_ref())
        .and_then(|table| table.lookup_by_addr(addr))
}

pub(super) fn for_each_symbol(mut callback: impl FnMut(DiagnosticSymbol<'static>) -> bool) {
    let Some(table) = SYMBOL_TABLE.get().and_then(|table| table.as_ref()) else {
        return;
    };
    for seq in 0..table.symbol_count {
        let Ok(symbol) = table.diagnostic_symbol(seq) else {
            continue;
        };
        if !callback(symbol) {
            break;
        }
    }
}

fn record_error(error: String) {
    early_println!("[ostd] FrameVM symbol table unavailable: {}", error);
    *INIT_ERROR.call_once(|| SpinLock::new(None)).lock() = Some(error);
}

impl<'a> SymbolTable<'a> {
    fn parse(payload: &'a [u8]) -> Result<Self, String> {
        let header = parse_header(payload)?;
        let values = table_range(
            header.values_offset,
            header.symbol_count,
            8,
            header.payload_size,
            "value table",
        )?;
        let name_seqs = table_range(
            header.name_seqs_offset,
            header.symbol_count,
            4,
            header.payload_size,
            "name_seqs table",
        )?;
        let name_offsets = table_range(
            header.name_offsets_offset,
            header.symbol_count,
            4,
            header.payload_size,
            "name_offsets table",
        )?;
        let raw_names_end = header
            .raw_names_offset
            .checked_add(header.raw_names_size)
            .ok_or_else(|| "raw-name stream range overflows".to_string())?;
        if raw_names_end > header.payload_size {
            return Err("raw-name stream exceeds payload size".to_string());
        }
        let raw_names = header.raw_names_offset..raw_names_end;

        if values.start != HEADER_SIZE
            || values.end > name_seqs.start
            || name_seqs.end > name_offsets.start
            || name_offsets.end > raw_names.start
            || raw_names.end != header.payload_size
        {
            return Err("framevm.symbols table layout is not canonical".to_string());
        }

        let mut table = Self {
            payload,
            values,
            name_seqs,
            name_offsets,
            raw_names,
            symbol_count: header.symbol_count,
            payload_hash: hash_payload(payload),
        };
        table.validate_names()?;
        Ok(table)
    }

    fn validate_names(&mut self) -> Result<(), String> {
        for seq in 0..self.symbol_count {
            self.raw_name(seq)?;
        }

        let mut previous_name = None;
        for sorted_index in 0..self.symbol_count {
            let seq = self.name_seq(sorted_index)?;
            if seq >= self.symbol_count {
                return Err(format!(
                    "name_seqs entry {} references out-of-range sequence {}",
                    sorted_index, seq
                ));
            }
            let name = self.raw_name(seq)?;
            if let Some(previous) = previous_name
                && previous >= name
            {
                return Err("name_seqs entries are not strictly sorted by raw name".to_string());
            }
            previous_name = Some(name);
        }

        Ok(())
    }

    fn lookup(&self, raw_name: &[u8]) -> Option<usize> {
        let mut left = 0usize;
        let mut right = self.symbol_count;
        while left < right {
            let mid = left + (right - left) / 2;
            let seq = self.name_seq(mid).ok()?;
            let candidate = self.raw_name(seq).ok()?;
            match candidate.cmp(raw_name) {
                Ordering::Less => left = mid + 1,
                Ordering::Equal => return self.value(seq).ok(),
                Ordering::Greater => right = mid,
            }
        }
        None
    }

    fn lookup_by_addr(&self, addr: usize) -> Option<DiagnosticSymbol<'a>> {
        for seq in 0..self.symbol_count {
            let symbol = self.diagnostic_symbol(seq).ok()?;
            if symbol.addr == addr {
                return Some(symbol);
            }
        }
        None
    }

    fn diagnostic_symbol(&self, seq: usize) -> Result<DiagnosticSymbol<'a>, String> {
        Ok(DiagnosticSymbol {
            raw_name: self.raw_name(seq)?,
            addr: self.value(seq)?,
        })
    }

    fn value(&self, seq: usize) -> Result<usize, String> {
        if seq >= self.symbol_count {
            return Err(format!("symbol sequence {} is out of range", seq));
        }
        let offset = self
            .values
            .start
            .checked_add(
                seq.checked_mul(8)
                    .ok_or_else(|| "value offset overflows".to_string())?,
            )
            .ok_or_else(|| "value offset overflows".to_string())?;
        Ok(read_u64(self.payload, offset)? as usize)
    }

    fn name_seq(&self, sorted_index: usize) -> Result<usize, String> {
        if sorted_index >= self.symbol_count {
            return Err(format!("name_seqs index {} is out of range", sorted_index));
        }
        let offset = self
            .name_seqs
            .start
            .checked_add(
                sorted_index
                    .checked_mul(4)
                    .ok_or_else(|| "name_seqs offset overflows".to_string())?,
            )
            .ok_or_else(|| "name_seqs offset overflows".to_string())?;
        Ok(read_u32(self.payload, offset)? as usize)
    }

    fn name_offset(&self, seq: usize) -> Result<usize, String> {
        if seq >= self.symbol_count {
            return Err(format!("symbol sequence {} is out of range", seq));
        }
        let offset = self
            .name_offsets
            .start
            .checked_add(
                seq.checked_mul(4)
                    .ok_or_else(|| "name offset table offset overflows".to_string())?,
            )
            .ok_or_else(|| "name offset table offset overflows".to_string())?;
        Ok(read_u32(self.payload, offset)? as usize)
    }

    fn raw_name(&self, seq: usize) -> Result<&'a [u8], String> {
        let relative_offset = self.name_offset(seq)?;
        if relative_offset >= self.raw_names.len() {
            return Err(format!(
                "raw-name offset {} for sequence {} exceeds raw-name stream",
                relative_offset, seq
            ));
        }
        let length_offset = self
            .raw_names
            .start
            .checked_add(relative_offset)
            .ok_or_else(|| "raw-name length offset overflows".to_string())?;
        let name_len = read_u16(self.payload, length_offset)? as usize;
        if name_len == 0 {
            return Err(format!("raw name for sequence {} is empty", seq));
        }
        let name_start = length_offset
            .checked_add(2)
            .ok_or_else(|| "raw-name start overflows".to_string())?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| "raw-name end overflows".to_string())?;
        if name_end > self.raw_names.end {
            return Err(format!(
                "raw name for sequence {} exceeds raw-name stream",
                seq
            ));
        }
        Ok(&self.payload[name_start..name_end])
    }
}

fn parse_header(payload: &[u8]) -> Result<Header, String> {
    if payload.len() < HEADER_SIZE {
        return Err(format!(
            "framevm.symbols header is too short: {} bytes",
            payload.len()
        ));
    }
    if &payload[..MAGIC.len()] != MAGIC {
        return Err("framevm.symbols magic does not match".to_string());
    }
    let version = read_u16(payload, 8)?;
    if version != FORMAT_VERSION {
        return Err(format!(
            "unsupported framevm.symbols format version {}",
            version
        ));
    }
    let endian = read_u8(payload, 10)?;
    if endian != ENDIAN_LITTLE {
        return Err(format!("unsupported framevm.symbols endian {}", endian));
    }
    let word_size = read_u8(payload, 11)?;
    if word_size != WORD_SIZE_64 {
        return Err(format!(
            "unsupported framevm.symbols word size {}",
            word_size
        ));
    }
    let payload_size = read_u32(payload, 40)? as usize;
    if payload_size != payload.len() {
        return Err(format!(
            "framevm.symbols payload size {} does not match boot module size {}",
            payload_size,
            payload.len()
        ));
    }

    Ok(Header {
        symbol_count: read_u32(payload, 16)? as usize,
        values_offset: read_u32(payload, 20)? as usize,
        name_seqs_offset: read_u32(payload, 24)? as usize,
        name_offsets_offset: read_u32(payload, 28)? as usize,
        raw_names_offset: read_u32(payload, 32)? as usize,
        raw_names_size: read_u32(payload, 36)? as usize,
        payload_size,
    })
}

fn table_range(
    offset: usize,
    count: usize,
    entry_size: usize,
    payload_size: usize,
    table_name: &str,
) -> Result<Range<usize>, String> {
    let byte_len = count
        .checked_mul(entry_size)
        .ok_or_else(|| format!("{} size overflows", table_name))?;
    let end = offset
        .checked_add(byte_len)
        .ok_or_else(|| format!("{} range overflows", table_name))?;
    if end > payload_size {
        return Err(format!("{} exceeds payload size", table_name));
    }
    Ok(offset..end)
}

fn hash_payload(payload: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(payload);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn read_u8(payload: &[u8], offset: usize) -> Result<u8, String> {
    payload
        .get(offset)
        .copied()
        .ok_or_else(|| format!("offset {} exceeds payload size", offset))
}

fn read_u16(payload: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| format!("u16 at offset {} overflows", offset))?;
    let bytes = payload
        .get(offset..end)
        .ok_or_else(|| format!("u16 at offset {} exceeds payload size", offset))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format!("u32 at offset {} overflows", offset))?;
    let bytes = payload
        .get(offset..end)
        .ok_or_else(|| format!("u32 at offset {} exceeds payload size", offset))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| format!("u64 at offset {} overflows", offset))?;
    let bytes = payload
        .get(offset..end)
        .ok_or_else(|| format!("u64 at offset {} exceeds payload size", offset))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::prelude::*;

    fn payload(entries: &[(&[u8], u64)]) -> Vec<u8> {
        let symbol_count = entries.len() as u32;
        let values_offset = HEADER_SIZE as u32;
        let name_seqs_offset = values_offset + symbol_count * 8;
        let name_offsets_offset = name_seqs_offset + symbol_count * 4;
        let raw_names_offset = name_offsets_offset + symbol_count * 4;

        let mut raw_names = Vec::new();
        let mut name_offsets = Vec::new();
        for (raw_name, _) in entries {
            name_offsets.push(raw_names.len() as u32);
            let raw_name_len = (*raw_name).len() as u16;
            raw_names.extend(raw_name_len.to_le_bytes());
            raw_names.extend(*raw_name);
        }

        let mut name_seqs = (0..entries.len() as u32).collect::<Vec<_>>();
        name_seqs.sort_by(|left, right| entries[*left as usize].0.cmp(entries[*right as usize].0));
        let raw_names_size = raw_names.len() as u32;
        let payload_size = raw_names_offset + raw_names_size;

        let mut bytes = Vec::new();
        bytes.extend(MAGIC);
        bytes.extend(FORMAT_VERSION.to_le_bytes());
        bytes.push(ENDIAN_LITTLE);
        bytes.push(WORD_SIZE_64);
        bytes.extend([0u8; 4]);
        bytes.extend(symbol_count.to_le_bytes());
        bytes.extend(values_offset.to_le_bytes());
        bytes.extend(name_seqs_offset.to_le_bytes());
        bytes.extend(name_offsets_offset.to_le_bytes());
        bytes.extend(raw_names_offset.to_le_bytes());
        bytes.extend(raw_names_size.to_le_bytes());
        bytes.extend(payload_size.to_le_bytes());
        bytes.resize(HEADER_SIZE, 0);
        for (_, value) in entries {
            bytes.extend(value.to_le_bytes());
        }
        for seq in name_seqs {
            bytes.extend(seq.to_le_bytes());
        }
        for offset in name_offsets {
            bytes.extend(offset.to_le_bytes());
        }
        bytes.extend(raw_names);
        bytes
    }

    #[ktest]
    fn parses_and_looks_up_exact_raw_names() {
        let bytes = payload(&[(b"z_import", 0x2000), (b"a_import", 0x1000)]);
        let table = SymbolTable::parse(&bytes).unwrap();

        assert_eq!(table.lookup(b"a_import"), Some(0x1000));
        assert_eq!(table.lookup(b"z_import"), Some(0x2000));
        assert_eq!(table.lookup(b"missing"), None);
    }

    #[ktest]
    fn lookup_accepts_non_utf8_raw_names() {
        let raw_name = b"\xffraw";
        let bytes = payload(&[(raw_name, 0x1234)]);
        let table = SymbolTable::parse(&bytes).unwrap();

        assert_eq!(table.lookup(raw_name), Some(0x1234));
        assert_eq!(table.lookup(b"raw"), None);
    }

    #[ktest]
    fn rejects_malformed_header_and_bounds() {
        assert!(SymbolTable::parse(b"short").is_err());

        let mut bytes = payload(&[(b"only", 1)]);
        bytes[0] = b'X';
        assert!(SymbolTable::parse(&bytes).is_err());

        let mut bytes = payload(&[(b"only", 1)]);
        let oversized_payload = (bytes.len() as u32 + 1).to_le_bytes();
        bytes[40..44].copy_from_slice(&oversized_payload);
        assert!(SymbolTable::parse(&bytes).is_err());
    }

    #[ktest]
    fn rejects_duplicate_or_unsorted_lookup_names() {
        let duplicate = payload(&[(b"dup", 1), (b"dup", 2)]);
        assert!(SymbolTable::parse(&duplicate).is_err());

        let mut unsorted = payload(&[(b"a", 1), (b"z", 2)]);
        let name_seqs_offset = u32::from_le_bytes(unsorted[24..28].try_into().unwrap()) as usize;
        unsorted[name_seqs_offset..name_seqs_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        unsorted[name_seqs_offset + 4..name_seqs_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        assert!(SymbolTable::parse(&unsorted).is_err());
    }
}
