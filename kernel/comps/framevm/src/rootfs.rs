// SPDX-License-Identifier: MPL-2.0

//! Kernel-local rootfs support.

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use cpio_decoder::{CpioDecoder, CpioEntry, FileType};
use lending_iterator::LendingIterator;
use no_std_io2::io::{Cursor, Read};
use ostd::sync::{Once, SpinLock};

use crate::error::{Errno, Error, Result};

const MAX_SYMLINK_DEPTH: usize = 40;
const ROOTFS_BLOCK_SIZE: u64 = 4096;
const ROOTFS_MAGIC: u64 = 0x8584_58f6;
const ROOTFS_NAME_MAX: u64 = 255;
const ROOT_MOUNTS_CONTENT: &[u8] = b"rootfs / rootfs rw,relatime 0 0\n";
const ROOT_MOUNTINFO_CONTENT: &[u8] = b"1 1 0:0 / / rw,relatime - rootfs rootfs rw\n";

static ROOTFS: Once<Arc<RootFs>> = Once::new();

struct BoxedReader<'a>(Box<dyn Read + 'a>);

impl<'a> BoxedReader<'a> {
    fn new(reader: Box<dyn Read + 'a>) -> Self {
        Self(reader)
    }
}

impl Read for BoxedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> no_std_io2::io::Result<usize> {
        self.0.read(buf)
    }
}

#[derive(Clone)]
pub struct RootFile {
    nodes: Arc<SpinLock<BTreeMap<String, RootNode>>>,
    path: String,
    data: Arc<SpinLock<Vec<u8>>>,
}

impl RootFile {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn data(&self) -> Arc<[u8]> {
        Arc::from(self.data.lock().clone().into_boxed_slice())
    }

    pub fn len(&self) -> usize {
        self.data.lock().len()
    }

    pub fn metadata(&self) -> FileMetadata {
        let nodes = self.nodes.lock();
        match nodes.get(&self.path) {
            Some(node) => FileMetadata::from_node(&nodes, &self.path, node),
            None => FileMetadata {
                mode: 0,
                size: self.data.lock().len(),
                kind: FileKind::File,
                nlink: 0,
            },
        }
    }

    pub fn read_at(&self, offset: usize, output: &mut [u8]) -> Result<usize> {
        let data = self.data.lock();
        if offset >= data.len() {
            return Ok(0);
        }
        let remain = data.len().saturating_sub(offset);
        let read_len = remain.min(output.len());
        output[..read_len].copy_from_slice(&data[offset..offset + read_len]);
        Ok(read_len)
    }

    pub fn write_at(&self, offset: usize, input: &[u8]) -> Result<usize> {
        let mut data = self.data.lock();
        let end = offset
            .checked_add(input.len())
            .ok_or(Error::new(Errno::EFBIG))?;
        if end > data.len() {
            data.resize(end, 0);
        }
        data[offset..end].copy_from_slice(input);
        Ok(input.len())
    }

    pub fn truncate(&self, len: usize) -> Result<()> {
        self.data.lock().resize(len, 0);
        Ok(())
    }
}

pub struct RootDir {
    path: String,
    entries: Arc<[RootDirEntry]>,
    mode: u16,
}

impl RootDir {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn entries(&self) -> Arc<[RootDirEntry]> {
        self.entries.clone()
    }

    pub fn mode(&self) -> u16 {
        self.mode
    }
}

#[derive(Clone)]
pub struct RootDirEntry {
    name: String,
    kind: FileKind,
}

impl RootDirEntry {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> FileKind {
        self.kind
    }
}

#[derive(Clone)]
enum RootNode {
    File {
        data: Arc<SpinLock<Vec<u8>>>,
        mode: u16,
    },
    Directory {
        mode: u16,
    },
    Symlink {
        target: String,
        mode: u16,
    },
    Special {
        mode: u16,
    },
}

impl RootNode {
    fn set_mode(&mut self, new_mode: u16) {
        match self {
            Self::File { mode, .. }
            | Self::Directory { mode }
            | Self::Symlink { mode, .. }
            | Self::Special { mode } => {
                *mode = new_mode;
            }
        }
    }
}

pub struct RootFs {
    nodes: Arc<SpinLock<BTreeMap<String, RootNode>>>,
}

impl RootFs {
    pub fn install_from_boot_info() -> Result<Arc<Self>> {
        let boot_info = ostd::boot::boot_info();
        let initramfs = boot_info
            .initramfs
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "missing initramfs"))?;
        let rootfs = Arc::new(Self::from_cpio_image(initramfs)?);
        let _ = ROOTFS.call_once(|| rootfs.clone());
        Ok(rootfs)
    }

    pub fn get() -> Result<Arc<Self>> {
        ROOTFS
            .get()
            .cloned()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "rootfs is not installed"))
    }

    pub fn sync(&self) -> Result<()> {
        Ok(())
    }

    pub fn statfs(&self) -> RootFsStat {
        let mut file_bytes = 0u64;
        let mut file_count = 0u64;
        let mut seen_files = Vec::new();
        let nodes = self.nodes.lock();

        for node in nodes.values() {
            match node {
                RootNode::File { data, .. } => {
                    if seen_files.iter().any(|seen| Arc::ptr_eq(seen, data)) {
                        continue;
                    }

                    seen_files.push(data.clone());
                    file_count = file_count.saturating_add(1);
                    let file_len = u64::try_from(data.lock().len()).unwrap_or(u64::MAX);
                    file_bytes = file_bytes.saturating_add(file_len);
                }
                RootNode::Directory { .. }
                | RootNode::Symlink { .. }
                | RootNode::Special { .. } => {
                    file_count = file_count.saturating_add(1);
                }
            }
        }

        RootFsStat {
            magic: ROOTFS_MAGIC,
            block_size: ROOTFS_BLOCK_SIZE,
            blocks: file_bytes.div_ceil(ROOTFS_BLOCK_SIZE),
            free_blocks: 0,
            available_blocks: 0,
            files: file_count,
            free_files: 0,
            fsid: 0,
            name_max: ROOTFS_NAME_MAX,
            fragment_size: ROOTFS_BLOCK_SIZE,
            flags: 0,
        }
    }

    fn from_cpio_image(image: &[u8]) -> Result<Self> {
        if image.len() < 4 {
            return Err(Error::with_message(
                Errno::EINVAL,
                "rootfs image is too small",
            ));
        }

        let mut rootfs = Self {
            nodes: Arc::new(SpinLock::new(BTreeMap::new())),
        };
        rootfs
            .nodes
            .lock()
            .insert(String::from("/"), RootNode::Directory { mode: 0o755 });

        let reader = BoxedReader::new(Box::new(Cursor::new(image)));

        let mut decoder = CpioDecoder::new(reader);
        while let Some(entry_result) = decoder.next() {
            let mut entry =
                entry_result.map_err(|_| Error::with_message(Errno::EINVAL, "invalid cpio"))?;
            rootfs.append_entry(&mut entry)?;
        }

        rootfs.install_single_root_mount_view();

        Ok(rootfs)
    }

    fn install_single_root_mount_view(&mut self) {
        let mut nodes = self.nodes.lock();
        ensure_directory(&mut nodes, "/proc", 0o555);
        ensure_directory(&mut nodes, "/proc/self", 0o555);
        ensure_directory(&mut nodes, "/etc", 0o755);

        nodes.insert(
            String::from("/proc/mounts"),
            RootNode::File {
                data: Arc::new(SpinLock::new(ROOT_MOUNTS_CONTENT.to_vec())),
                mode: 0o444,
            },
        );
        nodes.insert(
            String::from("/proc/self/mounts"),
            RootNode::File {
                data: Arc::new(SpinLock::new(ROOT_MOUNTS_CONTENT.to_vec())),
                mode: 0o444,
            },
        );
        nodes.insert(
            String::from("/proc/self/mountinfo"),
            RootNode::File {
                data: Arc::new(SpinLock::new(ROOT_MOUNTINFO_CONTENT.to_vec())),
                mode: 0o444,
            },
        );
        nodes.insert(
            String::from("/etc/mtab"),
            RootNode::Symlink {
                target: String::from("/proc/mounts"),
                mode: 0o777,
            },
        );
    }

    fn append_entry<R: Read>(&mut self, entry: &mut CpioEntry<R>) -> Result<()> {
        let path = normalize_path(entry.name());
        if path == "/" {
            return Ok(());
        }

        let metadata = entry.metadata();
        let mode = metadata.permission_mode();
        let node = match metadata.file_type() {
            FileType::File => {
                let mut data = Vec::new();
                entry
                    .read_all(&mut data)
                    .map_err(|_| Error::with_message(Errno::EIO, "failed to read cpio file"))?;
                RootNode::File {
                    data: Arc::new(SpinLock::new(data)),
                    mode,
                }
            }
            FileType::Dir => RootNode::Directory { mode },
            FileType::Link => {
                let mut data = Vec::new();
                entry
                    .read_all(&mut data)
                    .map_err(|_| Error::with_message(Errno::EIO, "failed to read cpio link"))?;
                let target = core::str::from_utf8(&data)
                    .map_err(|_| Error::with_message(Errno::EINVAL, "invalid symlink target"))?
                    .to_string();
                RootNode::Symlink { target, mode }
            }
            FileType::Char | FileType::Block | FileType::FiFo => RootNode::Special { mode },
            FileType::Socket => {
                return Err(Error::with_message(
                    Errno::EINVAL,
                    "socket files are not supported in the rootfs",
                ));
            }
        };

        self.nodes.lock().insert(path, node);
        Ok(())
    }

    pub fn open_file(&self, path: &str) -> Result<RootFile> {
        self.open_file_with_options(path, 0, false, false, false)
    }

    pub fn open_file_with_options(
        &self,
        path: &str,
        mode: u16,
        create: bool,
        exclusive: bool,
        truncate_existing: bool,
    ) -> Result<RootFile> {
        if path == "/" {
            return Err(Error::new(Errno::EISDIR));
        }

        if create && exclusive {
            match self.resolve_path_no_follow(path) {
                Ok(_) => return Err(Error::new(Errno::EEXIST)),
                Err(error) if error.errno() != Errno::ENOENT => return Err(error),
                Err(_) => {}
            }
        }

        match self.open_existing_file(path, truncate_existing) {
            Ok(file) => Ok(file),
            Err(error) if error.errno() == Errno::ENOENT && create => {
                self.create_new_file(path, mode)
            }
            Err(error) => Err(error),
        }
    }

    fn open_existing_file(&self, path: &str, truncate: bool) -> Result<RootFile> {
        let resolved_path = self.resolve_path(path)?;
        let nodes = self.nodes.lock();
        match nodes.get(&resolved_path) {
            Some(RootNode::File { data, .. }) => {
                let data = data.clone();
                if truncate {
                    data.lock().clear();
                }
                Ok(RootFile {
                    nodes: self.nodes.clone(),
                    path: resolved_path,
                    data,
                })
            }
            Some(RootNode::Directory { .. }) => Err(Error::new(Errno::EISDIR)),
            Some(_) => Err(Error::new(Errno::EINVAL)),
            None => Err(Error::new(Errno::ENOENT)),
        }
    }

    fn create_new_file(&self, path: &str, mode: u16) -> Result<RootFile> {
        let mut nodes = self.nodes.lock();
        let path = self.resolve_create_path_locked(&nodes, path)?;
        let parent = parent_path(&path).ok_or(Error::new(Errno::ENOENT))?;
        match nodes.get(parent) {
            Some(RootNode::Directory { .. }) => {}
            Some(_) => return Err(Error::new(Errno::ENOTDIR)),
            None => return Err(Error::new(Errno::ENOENT)),
        }
        if nodes.contains_key(&path) {
            return Err(Error::new(Errno::EEXIST));
        }
        let data = Arc::new(SpinLock::new(Vec::new()));
        nodes.insert(
            path.clone(),
            RootNode::File {
                data: data.clone(),
                mode,
            },
        );
        Ok(RootFile {
            nodes: self.nodes.clone(),
            path,
            data,
        })
    }

    pub fn mkdir(&self, path: &str, mode: u16) -> Result<()> {
        let mut nodes = self.nodes.lock();
        match self.resolve_path_with_tail_policy_locked(&nodes, path, false) {
            Ok(_) => return Err(Error::new(Errno::EEXIST)),
            Err(error) if error.errno() != Errno::ENOENT => return Err(error),
            Err(_) => {}
        }

        let path = self.resolve_create_path_locked(&nodes, path)?;
        let parent = parent_path(&path).ok_or(Error::new(Errno::ENOENT))?;
        match nodes.get(parent) {
            Some(RootNode::Directory { .. }) => {}
            Some(_) => return Err(Error::new(Errno::ENOTDIR)),
            None => return Err(Error::new(Errno::ENOENT)),
        }

        nodes.insert(
            path,
            RootNode::Directory {
                mode: mode & 0o7777,
            },
        );
        Ok(())
    }

    pub fn unlink(&self, path: &str) -> Result<()> {
        let mut nodes = self.nodes.lock();
        let path = self.resolve_path_with_tail_policy_locked(&nodes, path, false)?;
        match nodes.get(&path) {
            Some(RootNode::Directory { .. }) => return Err(Error::new(Errno::EISDIR)),
            Some(_) => {}
            None => return Err(Error::new(Errno::ENOENT)),
        }

        nodes.remove(&path);
        Ok(())
    }

    pub fn link(&self, old_path: &str, new_path: &str, follow_old_tail_link: bool) -> Result<()> {
        let mut nodes = self.nodes.lock();
        let old_path =
            self.resolve_path_with_tail_policy_locked(&nodes, old_path, follow_old_tail_link)?;
        let new_path = self.resolve_create_path_locked(&nodes, new_path)?;
        let parent = parent_path(&new_path).ok_or(Error::new(Errno::ENOENT))?;
        match nodes.get(parent) {
            Some(RootNode::Directory { .. }) => {}
            Some(_) => return Err(Error::new(Errno::ENOTDIR)),
            None => return Err(Error::new(Errno::ENOENT)),
        }

        let node = nodes
            .get(&old_path)
            .ok_or(Error::new(Errno::ENOENT))?
            .clone();
        if matches!(node, RootNode::Directory { .. }) {
            return Err(Error::new(Errno::EPERM));
        }
        nodes.insert(new_path, node);
        Ok(())
    }

    pub fn symlink(&self, target: &str, link_path: &str) -> Result<()> {
        if target.is_empty() {
            return Err(Error::new(Errno::ENOENT));
        }

        let mut nodes = self.nodes.lock();
        let link_path = self.resolve_create_path_locked(&nodes, link_path)?;
        let parent = parent_path(&link_path).ok_or(Error::new(Errno::ENOENT))?;
        match nodes.get(parent) {
            Some(RootNode::Directory { .. }) => {}
            Some(_) => return Err(Error::new(Errno::ENOTDIR)),
            None => return Err(Error::new(Errno::ENOENT)),
        }

        nodes.insert(
            link_path,
            RootNode::Symlink {
                target: target.to_string(),
                mode: 0o777,
            },
        );
        Ok(())
    }

    pub fn rmdir(&self, path: &str) -> Result<()> {
        let mut nodes = self.nodes.lock();
        let path = self.resolve_path_with_tail_policy_locked(&nodes, path, false)?;
        if path == "/" {
            return Err(Error::new(Errno::EBUSY));
        }

        match nodes.get(&path) {
            Some(RootNode::Directory { .. }) => {}
            Some(_) => return Err(Error::new(Errno::ENOTDIR)),
            None => return Err(Error::new(Errno::ENOENT)),
        }

        if nodes
            .keys()
            .any(|node_path| direct_child_name(&path, node_path).is_some())
        {
            return Err(Error::new(Errno::ENOTEMPTY));
        }

        nodes.remove(&path);
        Ok(())
    }

    pub fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let mut nodes = self.nodes.lock();
        let old_path = self.resolve_path_with_tail_policy_locked(&nodes, old_path, false)?;
        let new_path = match self.resolve_path_with_tail_policy_locked(&nodes, new_path, false) {
            Ok(path) => path,
            Err(error) if error.errno() == Errno::ENOENT => {
                self.resolve_create_path_locked(&nodes, new_path)?
            }
            Err(error) => return Err(error),
        };
        if old_path == new_path {
            return Ok(());
        }
        if old_path == "/" || new_path == "/" {
            return Err(Error::new(Errno::EBUSY));
        }

        let old_is_dir = match nodes.get(&old_path) {
            Some(RootNode::Directory { .. }) => true,
            Some(_) => false,
            None => return Err(Error::new(Errno::ENOENT)),
        };
        let new_parent = parent_path(&new_path).ok_or(Error::new(Errno::ENOENT))?;
        match nodes.get(new_parent) {
            Some(RootNode::Directory { .. }) => {}
            Some(_) => return Err(Error::new(Errno::ENOTDIR)),
            None => return Err(Error::new(Errno::ENOENT)),
        }

        if old_is_dir && path_is_descendant(&new_path, &old_path) {
            return Err(Error::new(Errno::EINVAL));
        }

        match nodes.get(&new_path) {
            Some(RootNode::Directory { .. }) if !old_is_dir => {
                return Err(Error::new(Errno::EISDIR));
            }
            Some(RootNode::Directory { .. }) if directory_has_descendants(&nodes, &new_path) => {
                return Err(Error::new(Errno::ENOTEMPTY));
            }
            Some(RootNode::Directory { .. }) => {}
            Some(_) if old_is_dir => return Err(Error::new(Errno::ENOTDIR)),
            Some(_) | None => {}
        }

        if nodes.contains_key(&new_path) {
            nodes.remove(&new_path);
        }

        let old_prefix = alloc::format!("{old_path}/");
        let old_keys = nodes
            .keys()
            .filter(|path| **path == old_path || path.starts_with(&old_prefix))
            .cloned()
            .collect::<Vec<_>>();
        let mut renamed_nodes = Vec::new();
        for old_key in old_keys {
            let suffix = old_key.strip_prefix(&old_path).unwrap_or("");
            let new_key = alloc::format!("{new_path}{suffix}");
            let node = nodes.remove(&old_key).ok_or(Error::new(Errno::ENOENT))?;
            renamed_nodes.push((new_key, node));
        }
        for (path, node) in renamed_nodes {
            nodes.insert(path, node);
        }

        Ok(())
    }

    pub fn chmod(&self, path: &str, mode: u16, follow_tail_link: bool) -> Result<()> {
        let path = self.resolve_path_with_tail_policy(path, follow_tail_link)?;
        let mut nodes = self.nodes.lock();
        let node = nodes.get_mut(&path).ok_or(Error::new(Errno::ENOENT))?;
        node.set_mode(mode & 0o7777);
        Ok(())
    }

    pub fn truncate(&self, path: &str, len: usize) -> Result<()> {
        let path = self.resolve_path(path)?;
        let nodes = self.nodes.lock();
        match nodes.get(&path) {
            Some(RootNode::File { data, .. }) => {
                data.lock().resize(len, 0);
                Ok(())
            }
            Some(RootNode::Directory { .. }) => Err(Error::new(Errno::EISDIR)),
            Some(_) => Err(Error::new(Errno::EINVAL)),
            None => Err(Error::new(Errno::ENOENT)),
        }
    }

    fn resolve_create_path_locked(
        &self,
        nodes: &BTreeMap<String, RootNode>,
        path: &str,
    ) -> Result<String> {
        let mut path = normalize_path(path);
        let mut symlink_depth = 0;

        loop {
            let components = path_components(&path);
            if components.is_empty() {
                return Err(Error::new(Errno::EISDIR));
            }

            let mut resolved_path = String::from("/");
            let mut restart_path = None;

            for (idx, component) in components.iter().enumerate() {
                let candidate_path = join_path(&resolved_path, component);
                let is_tail_component = idx + 1 == components.len();

                match nodes.get(&candidate_path) {
                    Some(RootNode::Symlink { target, .. }) => {
                        if symlink_depth >= MAX_SYMLINK_DEPTH {
                            return Err(Error::new(Errno::ELOOP));
                        }
                        symlink_depth += 1;

                        let mut target_path = if target.starts_with('/') {
                            normalize_path(target)
                        } else {
                            normalize_path(&join_parent(&candidate_path, target))
                        };

                        for remaining_component in components.iter().skip(idx + 1) {
                            target_path = join_path(&target_path, remaining_component);
                        }
                        restart_path = Some(target_path);
                        break;
                    }
                    Some(_) => resolved_path = candidate_path,
                    None if is_tail_component => return Ok(candidate_path),
                    None => return Err(Error::new(Errno::ENOENT)),
                }
            }

            match restart_path {
                Some(next_path) => path = next_path,
                None => return Err(Error::new(Errno::EEXIST)),
            }
        }
    }

    pub fn open_dir(&self, path: &str) -> Result<RootDir> {
        let nodes = self.nodes.lock();
        let resolved_path = self.resolve_path_with_tail_policy_locked(&nodes, path, true)?;
        let mode = match nodes.get(&resolved_path) {
            Some(RootNode::Directory { mode }) => *mode,
            Some(_) => return Err(Error::new(Errno::ENOTDIR)),
            None => return Err(Error::new(Errno::ENOENT)),
        };

        let mut children = BTreeMap::new();
        for (node_path, node) in nodes.iter() {
            let Some(name) = direct_child_name(&resolved_path, node_path) else {
                continue;
            };
            children.insert(
                name.to_string(),
                FileMetadata::from_node(&nodes, &path, node).kind,
            );
        }

        let mut entries = Vec::new();
        entries.push(RootDirEntry {
            name: String::from("."),
            kind: FileKind::Directory,
        });
        entries.push(RootDirEntry {
            name: String::from(".."),
            kind: FileKind::Directory,
        });
        for (name, kind) in children {
            entries.push(RootDirEntry { name, kind });
        }

        Ok(RootDir {
            path: resolved_path,
            entries: Arc::from(entries.into_boxed_slice()),
            mode,
        })
    }

    pub fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let resolved_path = self.resolve_path(path)?;
        self.metadata_at_resolved_path(&resolved_path)
    }

    /// Returns metadata for `path` without following a trailing symlink.
    pub fn metadata_no_follow(&self, path: &str) -> Result<FileMetadata> {
        let resolved_path = self.resolve_path_no_follow(path)?;
        self.metadata_at_resolved_path(&resolved_path)
    }

    fn metadata_at_resolved_path(&self, resolved_path: &str) -> Result<FileMetadata> {
        let nodes = self.nodes.lock();
        let node = nodes
            .get(resolved_path)
            .ok_or_else(|| Error::new(Errno::ENOENT))?;
        Ok(FileMetadata::from_node(&nodes, &resolved_path, node))
    }

    pub fn readlink(&self, path: &str) -> Result<String> {
        let path = self.resolve_path_no_follow(path)?;
        let nodes = self.nodes.lock();
        match nodes.get(&path) {
            Some(RootNode::Symlink { target, .. }) => Ok(target.clone()),
            Some(_) => Err(Error::new(Errno::EINVAL)),
            None => Err(Error::new(Errno::ENOENT)),
        }
    }

    fn resolve_path(&self, path: &str) -> Result<String> {
        self.resolve_path_with_tail_policy(path, true)
    }

    fn resolve_path_no_follow(&self, path: &str) -> Result<String> {
        self.resolve_path_with_tail_policy(path, false)
    }

    fn resolve_path_with_tail_policy(&self, path: &str, follow_tail_link: bool) -> Result<String> {
        let nodes = self.nodes.lock();
        self.resolve_path_with_tail_policy_locked(&nodes, path, follow_tail_link)
    }

    fn resolve_path_with_tail_policy_locked(
        &self,
        nodes: &BTreeMap<String, RootNode>,
        path: &str,
        follow_tail_link: bool,
    ) -> Result<String> {
        let mut path = normalize_path(path);
        let mut symlink_depth = 0;

        loop {
            let components = path_components(&path);
            if components.is_empty() {
                return Ok(String::from("/"));
            }

            let mut resolved_path = String::from("/");
            let mut restart_path = None;

            for (idx, component) in components.iter().enumerate() {
                let candidate_path = join_path(&resolved_path, component);
                let is_tail_component = idx + 1 == components.len();

                match nodes.get(&candidate_path) {
                    Some(RootNode::Symlink { target, .. })
                        if follow_tail_link || !is_tail_component =>
                    {
                        if symlink_depth >= MAX_SYMLINK_DEPTH {
                            return Err(Error::new(Errno::ELOOP));
                        }
                        symlink_depth += 1;

                        let mut target_path = if target.starts_with('/') {
                            normalize_path(target)
                        } else {
                            normalize_path(&join_parent(&candidate_path, target))
                        };

                        for remaining_component in components.iter().skip(idx + 1) {
                            target_path = join_path(&target_path, remaining_component);
                        }
                        restart_path = Some(target_path);
                        break;
                    }
                    Some(_) => resolved_path = candidate_path,
                    None => return Err(Error::new(Errno::ENOENT)),
                }
            }

            match restart_path {
                Some(next_path) => path = next_path,
                None => return Ok(resolved_path),
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct FileMetadata {
    pub mode: u16,
    pub size: usize,
    pub kind: FileKind,
    pub nlink: u32,
}

#[derive(Clone, Copy)]
pub struct RootFsStat {
    pub magic: u64,
    pub block_size: u64,
    pub blocks: u64,
    pub free_blocks: u64,
    pub available_blocks: u64,
    pub files: u64,
    pub free_files: u64,
    pub fsid: u64,
    pub name_max: u64,
    pub fragment_size: u64,
    pub flags: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Special,
}

impl FileMetadata {
    fn from_node(nodes: &BTreeMap<String, RootNode>, path: &str, node: &RootNode) -> Self {
        match node {
            RootNode::File { data, mode } => Self {
                mode: *mode,
                size: data.lock().len(),
                kind: FileKind::File,
                nlink: file_link_count(nodes, data),
            },
            RootNode::Directory { mode } => Self {
                mode: *mode,
                size: 0,
                kind: FileKind::Directory,
                nlink: directory_link_count(nodes, path),
            },
            RootNode::Symlink { target, mode } => Self {
                mode: *mode,
                size: target.len(),
                kind: FileKind::Symlink,
                nlink: 1,
            },
            RootNode::Special { mode } => Self {
                mode: *mode,
                size: 0,
                kind: FileKind::Special,
                nlink: 1,
            },
        }
    }
}

fn file_link_count(nodes: &BTreeMap<String, RootNode>, data: &Arc<SpinLock<Vec<u8>>>) -> u32 {
    let count = nodes
        .values()
        .filter(|node| {
            matches!(
                node,
                RootNode::File {
                    data: candidate,
                    ..
                } if Arc::ptr_eq(candidate, data)
            )
        })
        .count();
    link_count_from_usize(count)
}

fn directory_link_count(nodes: &BTreeMap<String, RootNode>, path: &str) -> u32 {
    let child_directory_count = nodes
        .iter()
        .filter(|(candidate_path, node)| {
            candidate_path.as_str() != path
                && matches!(node, RootNode::Directory { .. })
                && parent_path(candidate_path).is_some_and(|parent| parent == path)
        })
        .count();
    link_count_from_usize(child_directory_count.saturating_add(2))
}

fn link_count_from_usize(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn parent_path(path: &str) -> Option<&str> {
    let (parent, name) = path.rsplit_once('/')?;
    if name.is_empty() {
        return None;
    }
    if parent.is_empty() {
        Some("/")
    } else {
        Some(parent)
    }
}

fn direct_child_name<'a>(directory: &str, path: &'a str) -> Option<&'a str> {
    if path == directory {
        return None;
    }

    let rest = if directory == "/" {
        path.strip_prefix('/')?
    } else {
        path.strip_prefix(directory)?.strip_prefix('/')?
    };
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest)
}

fn directory_has_descendants(nodes: &BTreeMap<String, RootNode>, directory: &str) -> bool {
    nodes
        .keys()
        .any(|node_path| path_is_descendant(node_path, directory))
}

fn ensure_directory(nodes: &mut BTreeMap<String, RootNode>, path: &str, mode: u16) {
    if matches!(nodes.get(path), Some(RootNode::Directory { .. })) {
        return;
    }
    nodes.insert(path.to_string(), RootNode::Directory { mode });
}

fn path_is_descendant(path: &str, ancestor: &str) -> bool {
    if ancestor == "/" {
        return path != "/";
    }

    path.strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Normalizes an absolute or relative rootfs path.
pub fn normalize_path(path: &str) -> String {
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            components.pop();
            continue;
        }
        components.push(component);
    }

    if components.is_empty() {
        return String::from("/");
    }

    let mut normalized = String::new();
    for component in components {
        normalized.push('/');
        normalized.push_str(component);
    }
    normalized
}

fn path_components(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|component| !component.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Joins `path` against `base` and normalizes the result.
pub fn join_path(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        return normalize_path(path);
    }

    if base == "/" {
        normalize_path(&alloc::format!("/{path}"))
    } else {
        normalize_path(&alloc::format!("{base}/{path}"))
    }
}

fn join_parent(path: &str, target: &str) -> String {
    let parent = path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    if parent.is_empty() {
        alloc::format!("/{target}")
    } else {
        alloc::format!("{parent}/{target}")
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn rename_directory_moves_descendants() {
        let rootfs = test_rootfs();

        rootfs.rename("/tmp/dir", "/tmp/newdir").unwrap();

        assert!(matches!(
            rootfs.metadata("/tmp/newdir/child").unwrap().kind,
            FileKind::File
        ));
        assert_errno(rootfs.metadata("/tmp/dir/child"), Errno::ENOENT);
    }

    #[ktest]
    fn rename_directory_to_descendant_fails_without_mutation() {
        let rootfs = test_rootfs();

        assert_eq!(
            rootfs
                .rename("/tmp/dir", "/tmp/dir/child/new")
                .unwrap_err()
                .errno(),
            Errno::EINVAL
        );
        assert!(matches!(
            rootfs.metadata("/tmp/dir/child").unwrap().kind,
            FileKind::File
        ));
    }

    #[ktest]
    fn hard_link_shares_file_contents() {
        let rootfs = test_rootfs();
        let mut data = [0u8; 5];

        rootfs.link("/tmp/file", "/tmp/link", true).unwrap();
        rootfs
            .open_file("/tmp/link")
            .unwrap()
            .write_at(0, b"linked")
            .unwrap();
        rootfs
            .open_file("/tmp/file")
            .unwrap()
            .read_at(0, &mut data)
            .unwrap();

        assert_eq!(&data, b"linke");
    }

    #[ktest]
    fn hard_link_updates_metadata_link_count() {
        let rootfs = test_rootfs();

        rootfs.link("/tmp/file", "/tmp/link", true).unwrap();

        assert_eq!(rootfs.metadata("/tmp/file").unwrap().nlink, 2);
        assert_eq!(rootfs.metadata("/tmp/link").unwrap().nlink, 2);
    }

    #[ktest]
    fn statfs_counts_hard_linked_file_once() {
        let rootfs = test_rootfs();
        rootfs
            .open_file("/tmp/file")
            .unwrap()
            .truncate(ROOTFS_BLOCK_SIZE as usize)
            .unwrap();
        let before_link = rootfs.statfs();

        rootfs.link("/tmp/file", "/tmp/link", true).unwrap();
        let after_link = rootfs.statfs();

        assert_eq!(after_link.files, before_link.files);
        assert_eq!(after_link.blocks, before_link.blocks);
    }

    fn test_rootfs() -> RootFs {
        let rootfs = RootFs {
            nodes: Arc::new(SpinLock::new(BTreeMap::new())),
        };
        let mut nodes = rootfs.nodes.lock();
        nodes.insert(String::from("/"), RootNode::Directory { mode: 0o755 });
        nodes.insert(String::from("/tmp"), RootNode::Directory { mode: 0o777 });
        nodes.insert(
            String::from("/tmp/file"),
            RootNode::File {
                data: Arc::new(SpinLock::new(b"hello".to_vec())),
                mode: 0o644,
            },
        );
        nodes.insert(
            String::from("/tmp/dir"),
            RootNode::Directory { mode: 0o755 },
        );
        nodes.insert(
            String::from("/tmp/dir/child"),
            RootNode::File {
                data: Arc::new(SpinLock::new(b"child".to_vec())),
                mode: 0o644,
            },
        );
        drop(nodes);
        rootfs
    }

    fn assert_errno<T>(result: Result<T>, errno: Errno) {
        match result {
            Ok(_) => panic!("operation succeeded unexpectedly"),
            Err(error) => assert_eq!(error.errno(), errno),
        }
    }
}
