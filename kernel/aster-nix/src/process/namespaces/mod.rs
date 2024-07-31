// SPDX-License-Identifier: MPL-2.0

// SPDX-License-Identifier: MPL-2.0

pub mod mnt_namespace;
pub mod net_namespace;
pub mod uts_namespace;

use net_namespace::NetNamespace;
use uts_namespace::UtsNamespace;

use crate::{prelude::*, process::namespaces::mnt_namespace::MntNamespace};
pub struct Namespaces {
    mnt_ns: Arc<MntNamespace>,
    uts_ns: Arc<UtsNamespace>,
    net_ns: Arc<Mutex<NetNamespace>>,
}

impl Default for Namespaces {
    fn default() -> Self {
        Self {
            mnt_ns: Arc::new(MntNamespace::default()),
            uts_ns: Arc::new(UtsNamespace::default()),
            net_ns: NetNamespace::default(),
        }
    }
}

impl Namespaces {
    pub fn new(
        mnt_ns: Arc<MntNamespace>,
        uts_ns: Arc<UtsNamespace>,
        net_ns: Arc<Mutex<NetNamespace>>,
    ) -> Self {
        Self {
            mnt_ns,
            uts_ns,
            net_ns,
        }
    }

    pub fn mnt_ns(&self) -> &Arc<MntNamespace> {
        &self.mnt_ns
    }

    pub fn uts_ns(&self) -> &Arc<UtsNamespace> {
        &self.uts_ns
    }

    pub fn net_ns(&self) -> &Arc<Mutex<NetNamespace>> {
        &self.net_ns
    }

    /// Reset the namespaces of the process.
    pub fn reset_namespaces(&mut self, namespaces: &Arc<Mutex<Namespaces>>) {
        let new_namespaces = namespaces.lock();
        self.mnt_ns = new_namespaces.mnt_ns().clone();
        self.uts_ns = new_namespaces.uts_ns().clone();
        self.net_ns = new_namespaces.net_ns().clone();
    }
}
