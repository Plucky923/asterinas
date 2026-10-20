// SPDX-License-Identifier: MPL-2.0

//! Bounded failure metadata, published after device and protocol guards end.

use aster_softirq::BottomHalfDisabled;
use ostd::{sync::SpinLock, timer::Jiffies};
use smoltcp::wire::{IpAddress, IpRepr, TcpControl, TcpRepr, TcpSeqNumber};

#[derive(Clone, Copy, Debug)]
pub(crate) enum AllocationContext {
    Tcp {
        source: IpAddress,
        destination: IpAddress,
        source_port: u16,
        destination_port: u16,
        control: TcpControl,
        sequence: TcpSeqNumber,
        acknowledgement: Option<TcpSeqNumber>,
        window: u16,
    },
    Udp,
    Arp,
    IcmpUnreachable,
}

impl AllocationContext {
    pub(crate) fn tcp(ip: &IpRepr, tcp: &TcpRepr<'_>) -> Self {
        Self::Tcp {
            source: ip.src_addr(),
            destination: ip.dst_addr(),
            source_port: tcp.src_port,
            destination_port: tcp.dst_port,
            control: tcp.control,
            sequence: tcp.seq_number,
            acknowledgement: tcp.ack_number,
            window: tcp.window_len,
        }
    }
}

#[derive(Clone, Copy)]
struct Record {
    event: usize,
    boot_ms: u128,
    payload_bytes: usize,
    error: ostd::Error,
    context: AllocationContext,
}

struct Ring {
    slots: [Option<Record>; 32],
    accepted: usize,
    suppressed: usize,
    suppression_reported: bool,
}

static RECORDS: SpinLock<Ring, BottomHalfDisabled> = SpinLock::new(Ring {
    slots: [None; 32],
    accepted: 0,
    suppressed: 0,
    suppression_reported: false,
});

pub(crate) fn record(context: AllocationContext, payload_bytes: usize, error: ostd::Error) {
    let boot_ms = Jiffies::elapsed().as_duration().as_millis();
    let mut ring = RECORDS.lock();
    if ring.accepted >= 64 {
        ring.suppressed = ring.suppressed.saturating_add(1);
        return;
    }
    let Some(index) = ring.slots.iter().position(Option::is_none) else {
        ring.suppressed = ring.suppressed.saturating_add(1);
        return;
    };
    ring.accepted += 1;
    ring.slots[index] = Some(Record {
        event: ring.accepted,
        boot_ms,
        payload_bytes,
        error,
        context,
    });
}

pub(crate) fn flush() {
    // Move only one compact record at a time. No large record array is copied
    // onto a service or interrupt stack, and logging owns no diagnostic guard.
    for _ in 0..32 {
        let record = {
            let mut ring = RECORDS.lock();
            ring.slots.iter_mut().find_map(Option::take)
        };
        let Some(record) = record else {
            break;
        };
        ostd::error!(
            "kernelet TCP allocation_failure version=1 event={} boot_ms={} payload_bytes={} error={:?} context={:?}",
            record.event,
            record.boot_ms,
            record.payload_bytes,
            record.error,
            record.context,
        );
    }
    let suppressed = {
        let mut ring = RECORDS.lock();
        if ring.suppressed != 0 && !ring.suppression_reported {
            ring.suppression_reported = true;
            Some(ring.suppressed)
        } else {
            None
        }
    };
    if let Some(suppressed) = suppressed {
        ostd::error!(
            "kernelet TCP allocation_failure_limit version=1 captured_max=64 suppressed_at_first_notice={}",
            suppressed,
        );
    }
}
