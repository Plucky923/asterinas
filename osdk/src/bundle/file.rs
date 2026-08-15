// SPDX-License-Identifier: MPL-2.0

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::util::hard_link_or_copy;

/// A trait for files in a bundle. The file in a bundle should have its modified time and be validatable.
pub trait BundleFile {
    fn path(&self) -> &PathBuf;

    fn modified_time(&self) -> &SystemTime;

    fn size(&self) -> &u64;

    fn get_modified_time(&self) -> SystemTime {
        self.path()
            .metadata()
            .unwrap_or_else(|error| {
                panic!(
                    "failed to inspect bundle file {}: {error}",
                    self.path().display()
                )
            })
            .modified()
            .unwrap_or_else(|error| {
                panic!(
                    "failed to read modified time for bundle file {}: {error}",
                    self.path().display()
                )
            })
    }

    fn get_size(&self) -> u64 {
        self.path()
            .metadata()
            .unwrap_or_else(|error| {
                panic!(
                    "failed to inspect bundle file {}: {error}",
                    self.path().display()
                )
            })
            .size()
    }

    fn validate(&self) -> bool {
        let Ok(metadata) = self.path().metadata() else {
            return false;
        };
        let Ok(modified_time) = metadata.modified() else {
            return false;
        };

        self.size() == &metadata.size() && self.modified_time() >= &modified_time
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Initramfs {
    path: PathBuf,
    modified_time: SystemTime,
    size: u64,
}

impl BundleFile for Initramfs {
    fn path(&self) -> &PathBuf {
        &self.path
    }

    fn modified_time(&self) -> &SystemTime {
        &self.modified_time
    }

    fn size(&self) -> &u64 {
        &self.size
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FrameVmSymbols {
    path: PathBuf,
    modified_time: SystemTime,
    size: u64,
}

impl BundleFile for FrameVmSymbols {
    fn path(&self) -> &PathBuf {
        &self.path
    }

    fn modified_time(&self) -> &SystemTime {
        &self.modified_time
    }

    fn size(&self) -> &u64 {
        &self.size
    }
}

impl FrameVmSymbols {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let created = Self {
            path: path.as_ref().to_path_buf(),
            modified_time: SystemTime::UNIX_EPOCH,
            size: 0,
        };
        Self {
            modified_time: created.get_modified_time(),
            size: created.get_size(),
            ..created
        }
    }

    /// Copies the FrameVM symbol table into the bundle.
    pub fn copy_to(self, base: impl AsRef<Path>) -> Self {
        let name = self.path.file_name().unwrap();
        let dest = base.as_ref().join(name);
        replace_bundle_file(&self.path, &dest);
        Self {
            path: PathBuf::from(name),
            modified_time: dest.metadata().unwrap().modified().unwrap(),
            ..self
        }
    }
}

impl Initramfs {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let created = Self {
            path: path.as_ref().to_path_buf(),
            modified_time: SystemTime::UNIX_EPOCH,
            size: 0,
        };
        Self {
            modified_time: created.get_modified_time(),
            size: created.get_size(),
            ..created
        }
    }

    /// Copy the initramfs to the `base` directory and convert the path to a relative path.
    pub fn copy_to(self, base: impl AsRef<Path>) -> Self {
        let name = self.path.file_name().unwrap();
        let dest = base.as_ref().join(name);
        replace_bundle_file(&self.path, &dest);
        Self {
            path: PathBuf::from(name),
            modified_time: dest.metadata().unwrap().modified().unwrap(),
            ..self
        }
    }
}

fn replace_bundle_file(source: &Path, dest: &Path) {
    if !same_file(source, dest) {
        let _ = fs::remove_file(dest);
    }
    hard_link_or_copy(source, dest).unwrap();
}

fn same_file(left: &Path, right: &Path) -> bool {
    let Ok(left_metadata) = fs::metadata(left) else {
        return false;
    };
    let Ok(right_metadata) = fs::metadata(right) else {
        return false;
    };
    left_metadata.dev() == right_metadata.dev() && left_metadata.ino() == right_metadata.ino()
}
