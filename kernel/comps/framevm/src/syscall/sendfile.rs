// SPDX-License-Identifier: MPL-2.0

//! `sendfile` syscall support for the trimmed kernel image.

use alloc::{sync::Arc, vec};

use ostd::mm::VmSpace;

use super::{
    Errno, Error, FileKind, FileLike, Result, StatusFlags, current_fd_file,
    reactivate_current_vm_space, read_i64_from_user, write_to_user,
};

const MAX_COUNT: usize = 0x7fff_f000;
const BUFFER_SIZE: usize = super::PAGE_SIZE;
const SEEK_CUR: i32 = 1;
const SEEK_SET: i32 = 0;

/// Transfers bytes between two file descriptors.
///
/// This mirrors the kernel `sendfile` implementation for the subset of file
/// operations available in the rootfs and console fd layer.
pub(super) fn sys_sendfile(
    out_fd: i32,
    in_fd: i32,
    offset_ptr: usize,
    count: isize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let mut offset = if offset_ptr == 0 {
        None
    } else {
        let offset = read_i64_from_user(vm_space, offset_ptr)?;
        if offset < 0 {
            return Err(Error::new(Errno::EINVAL));
        }
        Some(offset as usize)
    };
    validate_sendfile_count_and_offset(count, offset)?;

    let out_file = current_fd_file(out_fd)?.ok_or(Error::new(Errno::EBADF))?;
    let in_file = current_fd_file(in_fd)?.ok_or(Error::new(Errno::EBADF))?;
    validate_sendfile_files(&out_file, &in_file)?;

    let count = (count as usize).min(MAX_COUNT);
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total_len = 0usize;

    let original_in_offset = if offset.is_none() {
        Some(in_file.seek(0, SEEK_CUR)?)
    } else {
        None
    };
    let mut short_write = false;

    while total_len < count {
        let max_read_len = buffer.len().min(count - total_len);

        let read_result = if let Some(read_offset) = offset {
            in_file.read_at(read_offset, &mut buffer[..max_read_len])
        } else {
            in_file.read(&mut buffer[..max_read_len])
        };

        let read_len = match read_result {
            Ok(read_len) => read_len,
            Err(_) if total_len > 0 => break,
            Err(error) => {
                restore_offset_if_needed(in_file.as_ref(), original_in_offset)?;
                return Err(error);
            }
        };
        if read_len == 0 {
            break;
        }

        let write_len = match out_file.write(&buffer[..read_len]) {
            Ok(write_len) => write_len,
            Err(_) if total_len > 0 => {
                short_write = true;
                break;
            }
            Err(error) => {
                restore_offset_if_needed(in_file.as_ref(), original_in_offset)?;
                return Err(error);
            }
        };

        total_len = total_len.saturating_add(write_len);
        if let Some(read_offset) = offset.as_mut() {
            *read_offset = read_offset.saturating_add(write_len);
        }
        if write_len < read_len {
            short_write = true;
            break;
        }
    }

    if let Some(read_offset) = offset {
        reactivate_current_vm_space()?;
        write_to_user(vm_space, offset_ptr, &(read_offset as i64).to_ne_bytes())?;
    } else if short_write {
        let original_offset = original_in_offset.unwrap();
        in_file.seek((original_offset + total_len) as isize, SEEK_SET)?;
    }

    Ok(total_len as isize)
}

fn validate_sendfile_count_and_offset(count: isize, offset: Option<usize>) -> Result<()> {
    if count < 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    if let Some(offset) = offset {
        let offset = isize::try_from(offset).map_err(|_| Error::new(Errno::EINVAL))?;
        let _ = offset.checked_add(count).ok_or(Error::new(Errno::EINVAL))?;
    }
    Ok(())
}

fn validate_sendfile_files(
    out_file: &Arc<dyn FileLike>,
    in_file: &Arc<dyn FileLike>,
) -> Result<()> {
    if !in_file.access_mode().is_readable() {
        return Err(Error::new(Errno::EBADF));
    }
    if !out_file.access_mode().is_writable() {
        return Err(Error::new(Errno::EBADF));
    }
    if in_file
        .metadata()
        .is_some_and(|metadata| metadata.kind == FileKind::Directory)
    {
        return Err(Error::new(Errno::EINVAL));
    }
    if out_file.status_flags().contains(StatusFlags::O_APPEND) {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

fn restore_offset_if_needed(file: &dyn FileLike, original_offset: Option<usize>) -> Result<()> {
    if let Some(original_offset) = original_offset {
        file.seek(original_offset as isize, SEEK_SET)?;
    }
    Ok(())
}
