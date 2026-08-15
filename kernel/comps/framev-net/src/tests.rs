// SPDX-License-Identifier: MPL-2.0

use alloc::vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::*;

static RELEASED_TOKEN: AtomicUsize = AtomicUsize::new(0);
static RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn record_release(token: usize) {
    RELEASED_TOKEN.store(token, Ordering::Release);
    RELEASE_COUNT.fetch_add(1, Ordering::Release);
}

fn unrelated_release(_token: usize) {}

#[test]
fn config_layout_matches_the_revision_one_pci_abi() {
    assert_eq!(size_of::<FrameVNetConfig>(), 16);
    assert_eq!(align_of::<FrameVNetConfig>(), 4);
}

#[test]
fn config_rejects_non_unicast_mac_addresses() {
    assert_eq!(
        FrameVNetConfig::new(
            [0x01, 0, 0, 0, 0, 1],
            FRAMEV_NET_MTU,
            FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES,
            16,
        ),
        Err(FrameVNetConfigError::MulticastMacAddress)
    );
}

#[test]
fn config_rejects_non_revision_one_values() {
    assert_eq!(
        FrameVNetConfig::new(
            [0x02, 0, 0, 0, 0, 1],
            1_400,
            FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES,
            16,
        ),
        Err(FrameVNetConfigError::InvalidMtu(1_400))
    );
    assert_eq!(
        FrameVNetConfig::new([0x02, 0, 0, 0, 0, 1], FRAMEV_NET_MTU, 1_500, 16),
        Err(FrameVNetConfigError::InvalidMaximumFrameBytes(1_500))
    );
}

#[test]
fn owned_network_buffer_exposes_its_original_storage() {
    let mut buffer = OwnedNetworkBuffer::new(vec![1, 2, 3]);

    buffer.as_mut_bytes()[1] = 4;

    assert_eq!(buffer.as_bytes(), [1, 4, 3]);
}

#[test]
fn owned_network_buffer_releases_a_cross_domain_guard_by_token() {
    RELEASED_TOKEN.store(0, Ordering::Release);
    RELEASE_COUNT.store(0, Ordering::Release);
    let guard = BufferDropGuard::new(37, record_release);
    let buffer = OwnedNetworkBuffer::from_boxed_slice_with_drop_guard(
        vec![0; 4].into_boxed_slice(),
        guard,
    );

    drop(buffer);

    assert_eq!(RELEASED_TOKEN.load(Ordering::Acquire), 37);
    assert_eq!(RELEASE_COUNT.load(Ordering::Acquire), 1);
}

#[test]
fn owned_network_buffer_authenticates_its_guard_owner() {
    let buffer = OwnedNetworkBuffer::from_boxed_slice_with_drop_guard(
        vec![0; 4].into_boxed_slice(),
        BufferDropGuard::new(37, record_release),
    );

    assert_eq!(buffer.token_if_released_by(record_release), Some(37));
    assert_eq!(buffer.token_if_released_by(unrelated_release), None);
}
