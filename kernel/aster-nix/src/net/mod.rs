// SPDX-License-Identifier: MPL-2.0

use self::iface::spawn_background_poll_thread;
use crate::{
    net::iface::{Iface, IfaceLoopback, IfaceVirtio},
    prelude::*,
    process::namespace::net_namespace::NetNamespace,
};

lazy_static! {
    pub static ref IFACES: Mutex<Vec<Arc<dyn Iface>>> = Mutex::new(vec![]);
    pub static ref INIT_NET: Mutex<Arc<Mutex<NetNamespace>>> = Mutex::new(NetNamespace::new());
}

pub mod iface;
pub mod socket;

pub fn init() {
    let iface_virtio = IfaceVirtio::new(&INIT_NET.lock());
    let iface_loopback = IfaceLoopback::new(&INIT_NET.lock());
    IFACES.lock().push(iface_virtio.clone());
    IFACES.lock().push(iface_loopback.clone());
    INIT_NET
        .lock()
        .lock()
        .add_iface(&Arc::downgrade(&(iface_virtio as Arc<dyn Iface>)));
    INIT_NET
        .lock()
        .lock()
        .add_iface(&Arc::downgrade(&(iface_loopback as Arc<dyn Iface>)));

    for (name, _) in aster_network::all_devices() {
        aster_network::register_recv_callback(&name, || {
            // TODO: further check that the irq num is the same as iface's irq num
            let ifaces = IFACES.lock();
            let iface_virtio = &ifaces.get(0).unwrap();
            iface_virtio.poll();
        })
    }
    for ifaces in IFACES.lock().iter() {
        ifaces.poll();
    }
}

/// Lazy init should be called after spawning init thread.
pub fn lazy_init() {
    for iface in IFACES.lock().iter() {
        spawn_background_poll_thread(iface.clone());
    }
}

/// Poll iface
pub fn poll_ifaces() {
    for iface in current!().namespaces().lock().net_ns().lock().ifaces() {
        iface.upgrade().unwrap().poll();
    }
}
