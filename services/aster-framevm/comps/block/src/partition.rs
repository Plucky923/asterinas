// SPDX-License-Identifier: MPL-2.0

use alloc::collections::BTreeSet;

use device_id::DeviceId;
use ostd::mm::VmIo;
use ostd_pod::Pod;

use crate::{
    BlockDevice, BlockDeviceMeta, SECTOR_SIZE,
    bio::{BioEnqueueError, SubmittedBio},
    prelude::*,
};

/// Represents a partition entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartitionInfo {
    Mbr(MbrEntry),
    Gpt(GptEntry),
}

impl PartitionInfo {
    pub fn start_sector(&self) -> u64 {
        match self {
            PartitionInfo::Mbr(entry) => entry.start_sector as u64,
            PartitionInfo::Gpt(entry) => entry.start_lba,
        }
    }

    pub fn total_sectors(&self) -> u64 {
        match self {
            PartitionInfo::Mbr(entry) => entry.total_sectors as u64,
            PartitionInfo::Gpt(entry) => entry.end_lba - entry.start_lba + 1,
        }
    }
}

/// A MBR (Master Boot Record) partition table header.
///
/// See <https://wiki.osdev.org/MBR_(x86)#MBR_Format>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct MbrHeader {
    bootstrap_code: [u8; 440],
    id: u32,
    reserved: u16,
    entries: [MbrEntry; 4],
    signature: u16,
}

impl MbrHeader {
    fn check_signature(&self) -> bool {
        self.signature == 0xAA55
    }
}

/// A MBR (Master Boot Record) partition entry.
///
/// See <https://wiki.osdev.org/Partition_Table>.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod)]
pub struct MbrEntry {
    flag: u8,
    start_chs: ChsAddr,
    type_: u8,
    end_chs: ChsAddr,
    start_sector: u32,
    total_sectors: u32,
}

impl MbrEntry {
    fn is_extended(&self) -> bool {
        self.type_ == 0x05 || self.type_ == 0x0F
    }

    fn is_valid(&self) -> bool {
        // A System ID byte value of 0 is the definitive indicator for an unused entry.
        // Any other illegal value (CHS Sector = 0 or Total Sectors = 0) may also indicate an unused entry.
        self.type_ != 0x00
            && self.start_chs.0[1] != 0
            && self.end_chs.0[1] != 0
            && self.total_sectors != 0
    }
}

/// A CHS (Cylinder-Head-Sector) address.
///
/// In CHS addressing, sector numbers always start at 1; there is no sector 0.
///
/// The CHS address is stored as a 3-byte field:
/// - Byte 0: Head number (8 bits)
/// - Byte 1: Bits 0–5 are the sector number (6 bits, valid values 1–63);
///   bits 6–7 are the upper two bits of the cylinder number
/// - Byte 2: Lower 8 bits of the cylinder number (bits 0–7)
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod)]
struct ChsAddr([u8; 3]);

/// A GPT (GUID Partition Table) header.
///
/// See <https://wiki.osdev.org/GPT#LBA_1:_Partition_Table_Header>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct GptHeader {
    signature: u64,
    revision: u32,
    size: u32,
    crc32: u32,
    reserved: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    guid: [u8; 16],
    partition_entry_lba: u64,
    nr_partition_entries: u32,
    size_of_partition_entry: u32,
    crc32_of_partition_entries: u32,
    _padding: [u8; 420],
}

impl GptHeader {
    fn check_signature(&self) -> bool {
        &self.signature.to_le_bytes() == b"EFI PART"
    }
}

fn is_supported_gpt_entry_size(entry_size: usize) -> bool {
    entry_size >= size_of::<GptEntry>()
        && entry_size <= SECTOR_SIZE
        && SECTOR_SIZE.is_multiple_of(entry_size)
}

/// A GPT (GUID Partition Table) partition entry.
///
/// See <https://wiki.osdev.org/GPT#LBA_2:_Partition_Entries>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod)]
pub struct GptEntry {
    // Unique ID that defines the purpose and type of this Partition.
    // A value of zero defines that this partition entry is not being used.
    type_guid: [u8; 16],
    // GUID that is unique for every partition entry.
    guid: [u8; 16],
    start_lba: u64,
    end_lba: u64,
    attributes: u64,
    // Null-terminated string containing a human-readable name of the partition.
    name: [u8; 72],
}

impl GptEntry {
    fn is_valid(&self) -> bool {
        self.type_guid != [0; 16]
    }
}

pub(super) fn parse(device: &Arc<dyn BlockDevice>) -> Option<Vec<Option<PartitionInfo>>> {
    let mbr = device.read_val::<MbrHeader>(0).ok()?;

    // 0xEE indicates a GPT Protective MBR, a fake partition covering the entire disk.
    let partitions = if mbr.check_signature() && mbr.entries[0].type_ != 0xEE {
        parse_mbr(device, &mbr)
    } else {
        parse_gpt(device)?
    };

    partitions.iter().any(|p| p.is_some()).then_some(partitions)
}

fn parse_mbr(device: &Arc<dyn BlockDevice>, mbr: &MbrHeader) -> Vec<Option<PartitionInfo>> {
    let mut partitions = Vec::new();
    let mut extended_partition = None;
    for entry in mbr.entries {
        if entry.is_extended() {
            extended_partition = Some(entry.start_sector);
        }

        if entry.is_valid() {
            partitions.push(Some(PartitionInfo::Mbr(entry)));
        } else {
            partitions.push(None);
        }
    }

    if let Some(start_sector) = extended_partition {
        parse_ebr(device, &mut partitions, start_sector);
    }

    partitions
}

fn parse_ebr(
    device: &Arc<dyn BlockDevice>,
    partitions: &mut Vec<Option<PartitionInfo>>,
    start_sector: u32,
) {
    let nr_sectors = device.metadata().nr_sectors;
    let mut visited = BTreeSet::new();
    let mut offset = 0;

    loop {
        let Some(ebr_sector) = start_sector.checked_add(offset) else {
            return;
        };
        let Ok(ebr_sector_usize) = usize::try_from(ebr_sector) else {
            return;
        };
        if ebr_sector_usize >= nr_sectors || !visited.insert(ebr_sector) {
            return;
        }
        let Some(byte_offset) = ebr_sector_usize.checked_mul(SECTOR_SIZE) else {
            return;
        };
        let Ok(mut ebr) = device.read_val::<MbrHeader>(byte_offset) else {
            return;
        };
        if !ebr.check_signature() {
            return;
        }
        if ebr.entries[0].is_valid() {
            let Some(absolute_start) = ebr.entries[0].start_sector.checked_add(ebr_sector) else {
                return;
            };
            ebr.entries[0].start_sector = absolute_start;
            partitions.push(Some(PartitionInfo::Mbr(ebr.entries[0])));
        }

        if !ebr.entries[1].is_extended() {
            return;
        }
        offset = ebr.entries[1].start_sector;
    }
}

fn parse_gpt(device: &Arc<dyn BlockDevice>) -> Option<Vec<Option<PartitionInfo>>> {
    let mut partitions = Vec::new();

    // The primary GPT Header must be located in LBA 1.
    let gpt = device.read_val::<GptHeader>(SECTOR_SIZE).ok()?;

    if !gpt.check_signature() {
        return Some(partitions);
    }

    // TODO: Check the CRC32 of the header and the partition entries, check the backup GPT header.

    let entry_size = gpt.size_of_partition_entry as usize;
    if !is_supported_gpt_entry_size(entry_size) {
        return None;
    }
    let entries_per_sector = SECTOR_SIZE / entry_size;
    let nr_entries = gpt.nr_partition_entries as usize;
    let total_sectors = nr_entries.checked_add(entries_per_sector - 1)? / entries_per_sector;
    let table_start = usize::try_from(gpt.partition_entry_lba).ok()?;
    let table_end = table_start.checked_add(total_sectors)?;
    if table_end > device.metadata().nr_sectors {
        return None;
    }
    for i in 0..total_sectors {
        let mut buf = [0u8; SECTOR_SIZE];
        let sector = table_start.checked_add(i)?;
        let offset = sector.checked_mul(SECTOR_SIZE)?;
        device.read_bytes(offset, buf.as_mut_slice()).ok()?;

        let first_entry = i.checked_mul(entries_per_sector)?;
        let entries_in_sector = entries_per_sector.min(nr_entries.saturating_sub(first_entry));
        for j in 0..entries_in_sector {
            let entry_offset = j.checked_mul(entry_size)?;
            let entry = GptEntry::from_first_bytes(&buf[entry_offset..entry_offset + entry_size]);
            if entry.is_valid()
                && entry.start_lba <= entry.end_lba
                && entry.end_lba < device.metadata().nr_sectors as u64
            {
                partitions.push(Some(PartitionInfo::Gpt(entry)));
            } else {
                partitions.push(None);
            }
        }
    }

    Some(partitions)
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn rejects_invalid_gpt_entry_sizes() {
        assert!(!is_supported_gpt_entry_size(0));
        assert!(!is_supported_gpt_entry_size(size_of::<GptEntry>() - 1));
        assert!(!is_supported_gpt_entry_size(SECTOR_SIZE + 1));
        assert!(is_supported_gpt_entry_size(size_of::<GptEntry>()));
    }
}

#[derive(Debug)]
pub struct PartitionNode {
    id: DeviceId,
    name: String,
    device: Arc<dyn BlockDevice>,
    info: PartitionInfo,
}

impl BlockDevice for PartitionNode {
    fn enqueue(&self, mut bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        bio.set_sid_offset(self.info.start_sector());
        self.device.enqueue(bio)
    }

    fn metadata(&self) -> BlockDeviceMeta {
        let mut metadata = self.device.metadata();
        metadata.nr_sectors = self.info.total_sectors() as usize;
        metadata
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }
}

impl PartitionNode {
    pub fn new(
        id: DeviceId,
        name: String,
        device: Arc<dyn BlockDevice>,
        info: PartitionInfo,
    ) -> Self {
        Self {
            id,
            name,
            device,
            info,
        }
    }
}
