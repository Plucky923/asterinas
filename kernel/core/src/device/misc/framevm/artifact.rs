// SPDX-License-Identifier: MPL-2.0

//! Boot-authorized FrameVM service artifacts.

use spin::Once;

use crate::{fs::file::FileLike, prelude::*};

static AUTHORIZED_ARTIFACT: Once<Arc<[u8]>> = Once::new();

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
    if !file.path().metadata().type_.is_regular_file() {
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

    let mut bytes = vec![0; file_size];
    let read_len = file.read_bytes_at(0, &mut bytes)?;
    if read_len != file_size || bytes.as_slice() != authorized.as_ref() {
        return_errno_with_message!(Errno::EACCES, "FrameVM artifact is not authorized");
    }
    Ok(Arc::from(bytes))
}
