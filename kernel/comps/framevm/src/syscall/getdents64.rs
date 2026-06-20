// SPDX-License-Identifier: MPL-2.0

use alloc::string::String;
use core::marker::PhantomData;

use ostd::mm::{VmReader, VmSpace, VmWriter, io::FallibleVmWrite};

use super::{Errno, Error, FileKind, Result, RootDirEntry, current_fd_table};

/// Reads directory entries from a directory file descriptor.
pub(super) fn sys_getdents64(
    fd: i32,
    dirent_addr: usize,
    count: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let fd_table = current_fd_table()?;
    let file = fd_table.lock().get(fd)?;
    let entries = file.collect_dir_entries(count, &mut linux_dirent64_record_len)?;

    if entries.is_empty() {
        return Ok(0);
    }

    let writer = vm_space.writer(dirent_addr, count).map_err(Error::from)?;
    let mut reader = DirentBufferReader::<Dirent64>::new(writer);
    for (next_offset, entry) in entries {
        reader.visit(
            &entry,
            inode_for_dirent(next_offset, entry.name()),
            next_offset,
        )?;
    }

    let read_len = reader.read_len();
    if read_len == 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    Ok(read_len as isize)
}

fn linux_dirent64_record_len(entry: &RootDirEntry) -> usize {
    Dirent64::new(entry, 0, 0).len()
}

trait DirentSerializer {
    fn new(entry: &RootDirEntry, ino: u64, offset: usize) -> Self;

    fn len(&self) -> usize;

    fn serialize(&self, writer: &mut VmWriter<'_>) -> Result<()>;
}

struct DirentBufferReader<'a, T: DirentSerializer> {
    writer: VmWriter<'a>,
    read_len: usize,
    phantom: PhantomData<T>,
}

impl<'a, T: DirentSerializer> DirentBufferReader<'a, T> {
    fn new(writer: VmWriter<'a>) -> Self {
        Self {
            writer,
            read_len: 0,
            phantom: PhantomData,
        }
    }

    fn read_len(&self) -> usize {
        self.read_len
    }

    fn visit(&mut self, entry: &RootDirEntry, ino: u64, offset: usize) -> Result<()> {
        let dirent_serializer = T::new(entry, ino, offset);
        let len = dirent_serializer.len();
        if self.writer.avail() < len {
            return Err(Error::new(Errno::EINVAL));
        }

        dirent_serializer.serialize(&mut self.writer)?;
        self.read_len += len;
        Ok(())
    }
}

struct Dirent64 {
    ino: u64,
    offset: usize,
    kind: FileKind,
    name: String,
}

impl Dirent64 {
    fn new(entry: &RootDirEntry, ino: u64, offset: usize) -> Self {
        Self {
            ino,
            offset,
            kind: entry.kind(),
            name: String::from(entry.name()),
        }
    }
}

impl DirentSerializer for Dirent64 {
    fn new(entry: &RootDirEntry, ino: u64, offset: usize) -> Self {
        Dirent64::new(entry, ino, offset)
    }

    fn len(&self) -> usize {
        const DIRENT64_HEADER_SIZE: usize = 19;
        align_up(DIRENT64_HEADER_SIZE + self.name.len() + 1, 8)
    }

    fn serialize(&self, writer: &mut VmWriter<'_>) -> Result<()> {
        const DIRENT64_HEADER_SIZE: usize = 19;

        let mut header = [0u8; DIRENT64_HEADER_SIZE];
        write_u64_ne(&mut header, 0, self.ino);
        write_i64_ne(&mut header, 8, self.offset as i64);
        write_u16_ne(&mut header, 16, self.len() as u16);
        header[18] = DirentType::from(self.kind) as u8;
        write_bytes_to_writer(writer, &header)?;
        write_bytes_to_writer(writer, self.name.as_bytes())?;

        let zero_len = self.len() - DIRENT64_HEADER_SIZE - self.name.len();
        let filled_len = writer.fill_zeros(zero_len).map_err(Error::from)?;
        if filled_len != zero_len {
            return Err(Error::new(Errno::EFAULT));
        }
        Ok(())
    }
}

#[expect(dead_code)]
#[expect(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum DirentType {
    DT_UNKNOWN = 0,
    DT_FIFO = 1,
    DT_CHR = 2,
    DT_DIR = 4,
    DT_BLK = 6,
    DT_REG = 8,
    DT_LNK = 10,
    DT_SOCK = 12,
    DT_WHT = 14,
}

impl From<FileKind> for DirentType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => DirentType::DT_REG,
            FileKind::Directory => DirentType::DT_DIR,
            FileKind::Symlink => DirentType::DT_LNK,
            FileKind::Special => DirentType::DT_CHR,
        }
    }
}

fn inode_for_dirent(next_offset: usize, name: &str) -> u64 {
    let mut hash = next_offset as u64 + 1;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(byte));
    }
    hash.max(1)
}

fn write_u64_ne(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn write_i64_ne(buf: &mut [u8], offset: usize, value: i64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn write_u16_ne(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn write_bytes_to_writer(writer: &mut VmWriter<'_>, bytes: &[u8]) -> Result<()> {
    let mut reader = VmReader::from(bytes);
    let written_len = writer.write_fallible(&mut reader).map_err(Error::from)?;
    if written_len != bytes.len() {
        return Err(Error::new(Errno::EFAULT));
    }
    Ok(())
}
