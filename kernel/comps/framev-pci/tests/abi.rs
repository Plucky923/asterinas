// SPDX-License-Identifier: MPL-2.0

use framev_blk_common::FRAMEV_BLK_SECTOR_SIZE;
use framev_console_common::{MAX_INPUT_CHUNK_BYTES, QUEUED_INPUT_CAPACITY_BYTES};
use framev_pci_common::{
    AssignedFunction, BlockConfig, BlockConfigFlags, ConfigError, ConsoleConfig, FRAMEV_PCI_CLASS,
    FRAMEV_PCI_PROGRAMMING_INTERFACE, FRAMEV_PCI_REVISION, FRAMEV_PCI_SUBCLASS,
    FRAMEV_PCI_VENDOR_ID, FrameVFunctionFamily, FrameVPciIdentity, FrameVPciLayout, IdentityError,
    LayoutError, NetConfig, RngConfig, SockConfig, SyntheticFunction, TopologyError,
    TopologyFunction, VirtualPciBdf, allocate_topology,
};
use framev_rng_common::MAX_FILL_BYTES;

#[test]
fn identity_values_match_revision_one() {
    assert_eq!(FRAMEV_PCI_VENDOR_ID, 0xa57e);
    assert_eq!(FRAMEV_PCI_REVISION, 1);
    assert_eq!(FRAMEV_PCI_CLASS, 0xff);
    assert_eq!(FRAMEV_PCI_SUBCLASS, 0);
    assert_eq!(FRAMEV_PCI_PROGRAMMING_INTERFACE, 0);
    for (device_id, family) in [
        (1, FrameVFunctionFamily::Console),
        (2, FrameVFunctionFamily::Sock),
        (3, FrameVFunctionFamily::Rng),
        (4, FrameVFunctionFamily::Block),
        (5, FrameVFunctionFamily::Net),
    ] {
        assert_eq!(family.device_id(), device_id);
        assert_eq!(
            FrameVFunctionFamily::from_device_id(device_id),
            Some(family)
        );
    }
    assert_eq!(FrameVFunctionFamily::from_device_id(0), None);

    let identity = FrameVPciIdentity::decode(0xa57e, 4, 1, 0xff, 0, 0).unwrap();
    assert_eq!(identity.family(), FrameVFunctionFamily::Block);
    assert_eq!(
        FrameVPciIdentity::decode(0xa57e, 4, 2, 0xff, 0, 0),
        Err(IdentityError::UnsupportedRevision)
    );
}

#[test]
fn family_configs_roundtrip_and_reject_reserved_bytes() {
    let console = ConsoleConfig {
        max_input_chunk_bytes: 256,
        queued_input_capacity_bytes: 4096,
    };
    assert_eq!(
        ConsoleConfig::decode(console.encode().unwrap()),
        Ok(console)
    );

    let rng = RngConfig {
        max_fill_bytes: 256,
    };
    assert_eq!(RngConfig::decode(rng.encode().unwrap()), Ok(rng));

    let block = BlockConfig {
        capacity_sectors: 4096,
        sector_size_bytes: 512,
        max_segments: 32,
        flags: BlockConfigFlags::READ_ONLY,
    };
    assert_eq!(BlockConfig::decode(block.encode().unwrap()), Ok(block));

    let sock = SockConfig {
        guest_cid: 3,
        receive_queue_count: 4,
        state_vector_count: 1,
        max_packet_bytes: 64 * 1024,
        receive_queue_capacity: 256,
    };
    assert_eq!(SockConfig::decode(sock.encode().unwrap()), Ok(sock));

    let net = NetConfig {
        mac_address: [0x02, 0, 0, 0, 0, 1],
        mtu: NetConfig::MTU,
        max_frame_bytes: NetConfig::MAX_FRAME_BYTES,
        max_posted_receive_buffers: 256,
    };
    assert_eq!(NetConfig::decode(net.encode().unwrap()), Ok(net));

    let mut invalid_console = console.encode().unwrap();
    invalid_console[8] = 1;
    assert_eq!(
        ConsoleConfig::decode(invalid_console),
        Err(ConfigError::ReservedNotZero)
    );
}

#[test]
fn family_configs_reject_values_outside_shared_limits() {
    let console = ConsoleConfig {
        max_input_chunk_bytes: u32::try_from(MAX_INPUT_CHUNK_BYTES).unwrap() + 1,
        queued_input_capacity_bytes: u32::try_from(QUEUED_INPUT_CAPACITY_BYTES).unwrap(),
    };
    assert_eq!(console.encode(), Err(ConfigError::InvalidFixedValue));

    let console = ConsoleConfig {
        max_input_chunk_bytes: u32::try_from(MAX_INPUT_CHUNK_BYTES).unwrap(),
        queued_input_capacity_bytes: u32::try_from(QUEUED_INPUT_CAPACITY_BYTES).unwrap() + 1,
    };
    assert_eq!(console.encode(), Err(ConfigError::InvalidFixedValue));

    let rng = RngConfig {
        max_fill_bytes: u32::try_from(MAX_FILL_BYTES).unwrap() + 1,
    };
    assert_eq!(rng.encode(), Err(ConfigError::InvalidFixedValue));

    let block = BlockConfig {
        capacity_sectors: 4096,
        sector_size_bytes: FRAMEV_BLK_SECTOR_SIZE as u32 - 1,
        max_segments: 32,
        flags: BlockConfigFlags::EMPTY,
    };
    assert_eq!(block.encode(), Err(ConfigError::InvalidFixedValue));

    let block = BlockConfig {
        capacity_sectors: 4096,
        sector_size_bytes: FRAMEV_BLK_SECTOR_SIZE as u32,
        max_segments: 31,
        flags: BlockConfigFlags::EMPTY,
    };
    assert_eq!(block.encode(), Err(ConfigError::InvalidFixedValue));

    let block = BlockConfig {
        capacity_sectors: 4096,
        sector_size_bytes: FRAMEV_BLK_SECTOR_SIZE as u32,
        max_segments: 33,
        flags: BlockConfigFlags::EMPTY,
    };
    assert_eq!(block.encode(), Err(ConfigError::InvalidFixedValue));
}

#[test]
fn sock_config_reports_zero_and_range_errors_separately() {
    let zero_queue_count = SockConfig {
        guest_cid: 3,
        receive_queue_count: 0,
        state_vector_count: 1,
        max_packet_bytes: 64 * 1024,
        receive_queue_capacity: 256,
    };
    assert_eq!(zero_queue_count.encode(), Err(ConfigError::ZeroValue));

    let too_many_queues = SockConfig {
        receive_queue_count: SockConfig::MAX_RECEIVE_QUEUES + 1,
        ..zero_queue_count
    };
    assert_eq!(too_many_queues.encode(), Err(ConfigError::InvalidValue));

    let wrong_state_vector_count = SockConfig {
        receive_queue_count: 1,
        state_vector_count: 2,
        ..zero_queue_count
    };
    assert_eq!(
        wrong_state_vector_count.encode(),
        Err(ConfigError::InvalidValue)
    );
}

#[test]
fn block_unknown_flags_and_invalid_net_configurations_are_rejected() {
    let mut block = [0; 0x20];
    block[0..8].copy_from_slice(&1_u64.to_le_bytes());
    block[8..12].copy_from_slice(&512_u32.to_le_bytes());
    block[12..14].copy_from_slice(&1_u16.to_le_bytes());
    block[14..16].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(BlockConfig::decode(block), Err(ConfigError::UnknownFlags));

    let net = NetConfig {
        mac_address: [0x02, 0, 0, 0, 0, 1],
        mtu: 9000,
        max_frame_bytes: NetConfig::MAX_FRAME_BYTES,
        max_posted_receive_buffers: 1,
    };
    assert_eq!(net.encode(), Err(ConfigError::InvalidFixedValue));

    let net = NetConfig {
        mac_address: [0x02, 0, 0, 0, 0, 1],
        mtu: NetConfig::MTU,
        max_frame_bytes: 1_500,
        max_posted_receive_buffers: 1,
    };
    assert_eq!(net.encode(), Err(ConfigError::InvalidFixedValue));

    let net = NetConfig {
        mac_address: [0; 6],
        mtu: NetConfig::MTU,
        max_frame_bytes: NetConfig::MAX_FRAME_BYTES,
        max_posted_receive_buffers: 1,
    };
    assert_eq!(net.encode(), Err(ConfigError::InvalidMacAddress));

    let net = NetConfig {
        mac_address: [0x01, 0, 0, 0, 0, 1],
        mtu: NetConfig::MTU,
        max_frame_bytes: NetConfig::MAX_FRAME_BYTES,
        max_posted_receive_buffers: 1,
    };
    assert_eq!(net.encode(), Err(ConfigError::InvalidMacAddress));
}

#[test]
fn msix_layout_matches_each_family() {
    let console = FrameVPciLayout::new(FrameVFunctionFamily::Console, 1).unwrap();
    assert_eq!(console.table_offset_bytes(), Some(0x10));
    assert_eq!(console.pba_offset_bytes(), Some(0x20));
    assert_eq!(console.bar_size_bytes(), 0x40);

    let sock = FrameVPciLayout::new(FrameVFunctionFamily::Sock, 5).unwrap();
    assert_eq!(sock.table_offset_bytes(), Some(0x20));
    assert_eq!(sock.pba_offset_bytes(), Some(0x70));
    assert_eq!(sock.bar_size_bytes(), 0x80);

    let block = FrameVPciLayout::new(FrameVFunctionFamily::Block, 0).unwrap();
    assert_eq!(block.table_offset_bytes(), None);
    assert_eq!(block.bar_size_bytes(), 0x20);
}

#[test]
fn impossible_vector_inventory_is_rejected() {
    assert_eq!(
        FrameVPciLayout::new(FrameVFunctionFamily::Console, 0),
        Err(LayoutError::InvalidVectorCount)
    );
    assert_eq!(
        FrameVPciLayout::new(FrameVFunctionFamily::Block, 1),
        Err(LayoutError::InvalidVectorCount)
    );
    assert_eq!(
        FrameVPciLayout::new(FrameVFunctionFamily::Sock, 1),
        Err(LayoutError::InvalidVectorCount)
    );
    assert_eq!(
        FrameVPciLayout::new(FrameVFunctionFamily::Sock, 6),
        Err(LayoutError::InvalidVectorCount)
    );
}

#[test]
fn topology_is_family_then_stable_id_then_physical_bdf_ordered() {
    let mut functions = [
        TopologyFunction::Assigned(AssignedFunction {
            physical_bdf: VirtualPciBdf::new(2, 1, 0).unwrap(),
        }),
        TopologyFunction::Synthetic(SyntheticFunction {
            family: FrameVFunctionFamily::Sock,
            stable_id: 0,
        }),
        TopologyFunction::Synthetic(SyntheticFunction {
            family: FrameVFunctionFamily::Block,
            stable_id: 9,
        }),
        TopologyFunction::Synthetic(SyntheticFunction {
            family: FrameVFunctionFamily::Console,
            stable_id: 0,
        }),
        TopologyFunction::Assigned(AssignedFunction {
            physical_bdf: VirtualPciBdf::new(1, 31, 7).unwrap(),
        }),
        TopologyFunction::Synthetic(SyntheticFunction {
            family: FrameVFunctionFamily::Block,
            stable_id: 2,
        }),
    ];

    let allocated = allocate_topology(&mut functions).unwrap();
    assert_eq!(
        allocated
            .iter()
            .map(|(bdf, _)| (bdf.bus(), bdf.device(), bdf.function()))
            .collect::<Vec<_>>(),
        vec![
            (0, 1, 0),
            (0, 2, 0),
            (0, 3, 0),
            (0, 4, 0),
            (0, 5, 0),
            (0, 6, 0)
        ]
    );
    assert!(matches!(
        allocated[0].1,
        TopologyFunction::Synthetic(SyntheticFunction {
            family: FrameVFunctionFamily::Console,
            ..
        })
    ));
    assert!(matches!(
        allocated[1].1,
        TopologyFunction::Synthetic(SyntheticFunction {
            family: FrameVFunctionFamily::Block,
            stable_id: 2
        })
    ));
    assert!(matches!(allocated[4].1, TopologyFunction::Assigned(_)));
}

#[test]
fn topology_rejects_duplicates_and_exhaustion() {
    let duplicate = TopologyFunction::Synthetic(SyntheticFunction {
        family: FrameVFunctionFamily::Block,
        stable_id: 7,
    });
    assert_eq!(
        allocate_topology(&mut [duplicate, duplicate]),
        Err(TopologyError::DuplicateSyntheticIdentity)
    );

    let mut too_many = vec![duplicate; 32];
    assert_eq!(
        allocate_topology(&mut too_many),
        Err(TopologyError::TooManyFunctions)
    );
}
