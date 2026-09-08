// SPDX-License-Identifier: MPL-2.0

//! Boot-authorized FrameVM service artifacts.

use spin::Once;

use crate::{fs::file::FileLike, prelude::*};

static AUTHORIZED_ARTIFACT: Once<Arc<[u8]>> = Once::new();

/// Bounds the temporary allocation used while checking an untrusted artifact.
///
/// The complete authorized image is retained once at boot. Per-FrameVM
/// authorization must not allocate another contiguous copy of that image.
const ARTIFACT_CHECK_CHUNK_SIZE: usize = 1024 * 1024;

pub(super) fn init_authorized_artifacts() -> Result<()> {
    let artifact = match crate::vmm::read_packaged_framevm_artifact() {
        Ok(artifact) => artifact,
        Err(error) if error.error() == Errno::ENOENT => return Ok(()),
        Err(error) => return Err(error),
    };
    AUTHORIZED_ARTIFACT.call_once(|| Arc::from(artifact));
    Ok(())
}

pub(super) fn capture_authorized_artifact(file: Arc<dyn FileLike>) -> Result<Arc<[u8]>> {
    if !file.path().metadata()?.type_.is_regular_file() {
        return_errno_with_message!(Errno::EINVAL, "FrameVM artifact must be a regular file");
    }
    if !file.access_mode().is_readable() {
        return_errno_with_message!(Errno::EBADF, "FrameVM artifact fd must be readable");
    }

    let authorized = AUTHORIZED_ARTIFACT.get().ok_or_else(|| {
        Error::with_message(
            Errno::EIO,
            "FrameVM artifact authorization is not initialized",
        )
    })?;
    let file_size = file.path().size();
    if file_size == 0 || file_size != authorized.len() {
        return_errno_with_message!(Errno::EACCES, "FrameVM artifact is not authorized");
    }

    let mut bytes = vec![0_u8; ARTIFACT_CHECK_CHUNK_SIZE];
    let mut offset = 0;
    while offset < file_size {
        let chunk_len = (file_size - offset).min(bytes.len());
        let read_len = file.read_bytes_at(offset, &mut bytes[..chunk_len])?;
        if read_len != chunk_len || bytes[..chunk_len] != authorized[offset..offset + chunk_len] {
            return_errno_with_message!(Errno::EACCES, "FrameVM artifact is not authorized");
        }
        offset += chunk_len;
    }

    // The checked input is byte-for-byte identical to the boot-authorized
    // immutable image. Share that image instead of retaining a fresh large
    // copy for each VM instance.
    Ok(authorized.clone())
}
