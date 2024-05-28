// SPDX-License-Identifier: MPL-2.0

use crate::{
    fs::{path::MountNode, rootfs::root_mount},
    prelude::*,
};

pub struct MntNamespace {
    root: Arc<MountNode>,
}

impl Default for MntNamespace {
    fn default() -> Self {
        Self {
            root: root_mount().clone(),
        }
    }
}

impl MntNamespace {
    pub fn new(mount_node: Arc<MountNode>) -> Arc<Self> {
        Arc::new(Self { root: mount_node })
    }

    pub fn root(&self) -> &Arc<MountNode> {
        &self.root
    }

    pub fn copy_mnt_ns(old_mnt_ns: &Arc<MntNamespace>) -> Arc<Self> {
        let old_mount_node = old_mnt_ns.root();
        let new_mount_node =
            old_mount_node.copy_mount_node_tree(old_mount_node.root_dentry().clone());
        new_mount_node.process_move();
        MntNamespace::new(new_mount_node)
    }
}
