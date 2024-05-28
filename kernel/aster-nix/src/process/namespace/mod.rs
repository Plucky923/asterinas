// SPDX-License-Identifier: MPL-2.0

pub mod mnt_namespace;
pub mod net_namespace;
pub mod uts_namespace;

use crate::{
    prelude::*,
    process::namespace::{
        mnt_namespace::MntNamespace, net_namespace::NetNamespace, uts_namespace::UtsNamespace,
    },
};
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
    pub fn new(mnt: Arc<MntNamespace>, uts: Arc<UtsNamespace>, net: Arc<Mutex<NetNamespace>>) -> Self {
        Self {
            mnt_ns: mnt,
            uts_ns: uts,
            net_ns: net,
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

    pub fn set_namespaces(&mut self, namespaces: Arc<Mutex<Namespaces>>) {
        let new_namespaces = namespaces.lock();
        self.mnt_ns = new_namespaces.mnt_ns().clone();
        self.uts_ns = new_namespaces.uts_ns().clone();
        self.net_ns = new_namespaces.net_ns().clone();
    }
}
