// SPDX-License-Identifier: MPL-2.0

use core::slice::Iter;

use aster_bigtcp::{
    device::WithDevice,
    iface::{InterfaceFlags, InterfaceType},
    wire::Ipv4Address,
};
use aster_softirq::BottomHalfDisabled;
use spin::Once;

use super::{Iface, broadcast, poll::poll_ifaces, sched::PollScheduler};
use crate::prelude::*;

const FRAMEV_ADDRESS: Ipv4Address = Ipv4Address::new(192, 0, 2, 2);
const FRAMEV_ADDRESS_PREFIX_LEN: u8 = 24;
const FRAMEV_GATEWAY: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);

static IFACES: Once<Vec<Arc<Iface>>> = Once::new();
static FRAMEV_DEVICE_NAME: Once<Option<String>> = Once::new();

pub fn loopback_iface() -> &'static Arc<Iface> {
    &IFACES.get().unwrap()[0]
}

pub fn framev_iface() -> Option<&'static Arc<Iface>> {
    IFACES.get().unwrap().get(1)
}

pub fn iter_all_ifaces() -> Iter<'static, Arc<Iface>> {
    IFACES.get().unwrap().iter()
}

pub fn init() {
    let framev_device_name = framev_net_frontend::network_device_name().ok().flatten();
    FRAMEV_DEVICE_NAME.call_once(|| framev_device_name);

    IFACES.call_once(|| {
        let mut ifaces = Vec::with_capacity(2);
        ifaces.push(new_loopback());
        if let Some(iface_framev) = new_framev() {
            ifaces.push(iface_framev);
        }
        ifaces
    });

    if let (Some(iface_framev), Some(device_name)) =
        (framev_iface(), FRAMEV_DEVICE_NAME.get().unwrap().as_deref())
    {
        let callback = || iface_framev.poll();
        aster_network::register_recv_callback(device_name, callback);
        aster_network::register_send_callback(device_name, callback);
    }

    broadcast::init();
    poll_ifaces();
}

fn new_loopback() -> Arc<Iface> {
    use aster_bigtcp::{
        device::{Loopback, Medium},
        iface::IpIface,
        wire::{Ipv4Cidr, Ipv6Address, Ipv6Cidr},
    };

    const LOOPBACK_ADDRESS: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);
    const LOOPBACK_ADDRESS_PREFIX_LEN: u8 = 8;
    const LOOPBACK_IPV6_ADDRESS: Ipv6Address = Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1);
    const LOOPBACK_IPV6_PREFIX_LEN: u8 = 128;

    struct Wrapper(Mutex<Loopback>);

    impl WithDevice for Wrapper {
        type Device = Loopback;

        fn with<F, R>(&self, access_fn: F) -> R
        where
            F: FnOnce(&mut Self::Device) -> R,
        {
            let mut device = self.0.lock();
            access_fn(&mut device)
        }
    }

    let flags = InterfaceFlags::UP
        | InterfaceFlags::LOOPBACK
        | InterfaceFlags::RUNNING
        | InterfaceFlags::LOWER_UP;

    IpIface::new(
        Wrapper(Mutex::new(Loopback::new(Medium::Ip))),
        Ipv4Cidr::new(LOOPBACK_ADDRESS, LOOPBACK_ADDRESS_PREFIX_LEN),
        Some(Ipv6Cidr::new(
            LOOPBACK_IPV6_ADDRESS,
            LOOPBACK_IPV6_PREFIX_LEN,
        )),
        CString::new("lo").unwrap(),
        PollScheduler::new(),
        InterfaceType::LOOPBACK,
        flags,
    ) as Arc<Iface>
}

fn new_framev() -> Option<Arc<Iface>> {
    use aster_bigtcp::{
        iface::EtherIface,
        wire::{EthernetAddress, Ipv4Cidr},
    };
    use aster_network::AnyNetworkDevice;

    let device_name = FRAMEV_DEVICE_NAME.get().unwrap().as_deref()?;
    let framev_net = aster_network::get_device(device_name)?;
    let ethernet_address = framev_net.lock().mac_addr().0;

    struct Wrapper(Arc<SpinLock<dyn AnyNetworkDevice, BottomHalfDisabled>>);

    impl WithDevice for Wrapper {
        type Device = dyn AnyNetworkDevice;

        fn with<F, R>(&self, access_fn: F) -> R
        where
            F: FnOnce(&mut Self::Device) -> R,
        {
            let mut device = self.0.lock();
            access_fn(&mut *device)
        }
    }

    let flags = InterfaceFlags::UP
        | InterfaceFlags::BROADCAST
        | InterfaceFlags::RUNNING
        | InterfaceFlags::MULTICAST
        | InterfaceFlags::LOWER_UP;

    Some(EtherIface::new(
        Wrapper(framev_net),
        EthernetAddress(ethernet_address),
        Ipv4Cidr::new(FRAMEV_ADDRESS, FRAMEV_ADDRESS_PREFIX_LEN),
        FRAMEV_GATEWAY,
        CString::new("eth0").unwrap(),
        PollScheduler::new(),
        flags,
    ))
}
