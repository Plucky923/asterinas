//! Protocol scheduling model; device credit is controlled, not measured.

#[cfg(test)]
mod tests {
    use smoltcp::{
        iface::{Config, Interface, SocketSet},
        phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
        socket::udp,
        time::Instant,
        wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address},
    };

    struct LimitedDevice {
        credit: usize,
        packets: Vec<Vec<u8>>,
    }

    struct NeverReceive;
    impl RxToken for NeverReceive {
        fn consume<R, F>(self, _: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            unreachable!("model has no ingress")
        }
    }

    struct RecordTransmit<'a>(&'a mut Vec<Vec<u8>>);
    impl TxToken for RecordTransmit<'_> {
        fn consume<R, F>(self, length: usize, emit: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut packet = vec![0; length];
            let result = emit(&mut packet);
            self.0.push(packet);
            result
        }
    }

    impl Device for LimitedDevice {
        type RxToken<'a> = NeverReceive;
        type TxToken<'a> = RecordTransmit<'a>;

        fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            None
        }

        fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
            if self.credit == 0 {
                return None;
            }
            self.credit -= 1;
            Some(RecordTransmit(&mut self.packets))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut capabilities = DeviceCapabilities::default();
            capabilities.medium = Medium::Ip;
            capabilities.max_transmission_unit = 1500;
            capabilities
        }
    }

    #[test]
    fn exhausted_device_credit_must_not_starve_later_ready_sockets() {
        let mut device = LimitedDevice { credit: 0, packets: Vec::new() };
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip), &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1)), 24)).unwrap();
        });
        let mut sockets = SocketSet::new(Vec::new());
        for index in 0..4u16 {
            let receive = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0; 64]);
            let transmit = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 512]);
            let mut socket = udp::Socket::new(receive, transmit);
            socket.bind(49152 + index).unwrap();
            for _ in 0..8 {
                socket.send_slice(&[index as u8; 8],
                    (Ipv4Address::new(192, 0, 2, 2), 9000)).unwrap();
            }
            sockets.add(socket);
        }
        for tick in 1..=4 {
            device.credit = 1;
            interface.poll_egress(Instant::from_millis(tick), &mut device, &mut sockets);
        }
        let actual: Vec<_> = device.packets.iter().map(|packet| {
            assert_eq!(packet[9], 17, "actual emitted packet must be UDP");
            u16::from_be_bytes(packet[20..22].try_into().unwrap())
        }).collect();
        eprintln!("actual emitted source ports: {actual:?}");
        assert_eq!(actual, vec![49152, 49153, 49154, 49155],
            "restored device credit must reach each ready socket before returning to the prefix");
    }

    fn setup() -> (LimitedDevice, Interface, SocketSet<'static>) {
        let mut device = LimitedDevice { credit: 0, packets: Vec::new() };
        let mut interface = Interface::new(Config::new(HardwareAddress::Ip),
            &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1)), 24)).unwrap();
        });
        (device, interface, SocketSet::new(Vec::new()))
    }

    fn queued_socket(port: u16, count: usize) -> udp::Socket<'static> {
        let receive = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0; 64]);
        let transmit = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 1024]);
        let mut socket = udp::Socket::new(receive, transmit);
        socket.bind(port).unwrap();
        for _ in 0..count {
            socket.send_slice(&[1; 8], (Ipv4Address::new(192, 0, 2, 2), 9000)).unwrap();
        }
        socket
    }

    fn poll(interface: &mut Interface, device: &mut LimitedDevice,
            sockets: &mut SocketSet<'_>, credit: usize) {
        device.credit = credit;
        interface.poll_egress(Instant::from_millis(1), device, sockets);
    }

    fn ports(device: &LimitedDevice) -> Vec<u16> {
        device.packets.iter().map(|packet| {
            assert_eq!(packet[9], 17);
            u16::from_be_bytes(packet[20..22].try_into().unwrap())
        }).collect()
    }

    #[test]
    fn repeated_credit_windows_wrap_without_starvation() {
        let (mut device, mut interface, mut sockets) = setup();
        for port in 49152..49156 { sockets.add(queued_socket(port, 16)); }
        for _ in 0..12 { poll(&mut interface, &mut device, &mut sockets, 1); }
        assert_eq!(ports(&device), [49152,49153,49154,49155].repeat(3));
    }

    #[test]
    fn multiple_tokens_in_each_window_reach_all_ready_sockets() {
        let (mut device, mut interface, mut sockets) = setup();
        for port in 49152..49156 { sockets.add(queued_socket(port, 16)); }
        for _ in 0..4 { poll(&mut interface, &mut device, &mut sockets, 2); }
        assert_eq!(ports(&device), [49152,49153,49154,49155].repeat(2));
    }

    #[test]
    fn removed_slot_is_skipped_and_reused_slot_can_progress() {
        let (mut device, mut interface, mut sockets) = setup();
        sockets.add(queued_socket(49152, 16));
        let removed = sockets.add(queued_socket(49153, 16));
        sockets.add(queued_socket(49154, 16));
        poll(&mut interface, &mut device, &mut sockets, 1);
        sockets.remove(removed);
        poll(&mut interface, &mut device, &mut sockets, 1);
        let reused = sockets.add(queued_socket(49155, 16));
        assert_eq!(reused, removed);
        for _ in 0..3 { poll(&mut interface, &mut device, &mut sockets, 1); }
        assert_eq!(ports(&device), [49152,49154,49152,49155,49154]);
    }

    #[test]
    fn zero_credit_preserves_the_waiting_socket() {
        let (mut device, mut interface, mut sockets) = setup();
        for port in 49152..49155 { sockets.add(queued_socket(port, 16)); }
        poll(&mut interface, &mut device, &mut sockets, 1);
        for _ in 0..4 { poll(&mut interface, &mut device, &mut sockets, 0); }
        poll(&mut interface, &mut device, &mut sockets, 1);
        assert_eq!(ports(&device), [49152,49153]);
    }

    #[test]
    fn empty_set_and_inactive_sockets_do_not_block_ready_sockets() {
        let (mut device, mut interface, mut sockets) = setup();
        poll(&mut interface, &mut device, &mut sockets, 1);
        sockets.add(queued_socket(49152, 0));
        sockets.add(queued_socket(49153, 16));
        sockets.add(queued_socket(49154, 0));
        sockets.add(queued_socket(49155, 16));
        for _ in 0..4 { poll(&mut interface, &mut device, &mut sockets, 1); }
        assert_eq!(ports(&device), [49153,49155,49153,49155]);
    }

    #[test]
    fn replacing_a_large_set_with_a_smaller_set_normalizes_the_cursor() {
        let (mut device, mut interface, mut sockets) = setup();
        for port in 49152..49156 { sockets.add(queued_socket(port, 16)); }
        for _ in 0..3 { poll(&mut interface, &mut device, &mut sockets, 1); }
        let mut replacement = SocketSet::new(Vec::new());
        replacement.add(queued_socket(50000, 16));
        poll(&mut interface, &mut device, &mut replacement, 1);
        assert_eq!(ports(&device), [49152,49153,49154,50000]);
    }
}
