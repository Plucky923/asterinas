use alloc::sync::{Arc, Weak};

use crate::{
    net::{
        iface::{Iface, IfaceLoopback},
        IFACES, INIT_NET,
    },
    prelude::*,
};
pub struct NetNamespace {
    ifaces: Vec<Weak<dyn Iface>>,
}

impl NetNamespace {
    pub fn default() -> Arc<Mutex<Self>> {
        INIT_NET.lock().clone()
    }

    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(NetNamespace { ifaces: Vec::new() }))
    }

    pub fn new_with_loopback() -> (Arc<Mutex<Self>>, Arc<IfaceLoopback>) {
        let net_ns = Arc::new(Mutex::new(NetNamespace { ifaces: Vec::new() }));
        let loopback = IfaceLoopback::new(&net_ns);
        IFACES.lock().push(loopback.clone());
        let weak: Weak<dyn Iface> = Arc::downgrade(&(loopback.clone() as Arc<dyn Iface>));
        net_ns.lock().add_iface(&weak);
        (net_ns, loopback)
    }

    pub fn add_iface(&mut self, ifce: &Weak<dyn Iface>) {
        self.ifaces.push(ifce.clone());
    }

    pub fn ifaces(&self) -> impl Iterator<Item = &Weak<dyn Iface>> {
        self.ifaces.iter()
    }
}
