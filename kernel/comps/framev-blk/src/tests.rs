use crate::*;

#[test]
fn config_rejects_unknown_flags() {
    assert_eq!(
        FrameVBlkConfig::from_bits(1, FRAMEV_BLK_SECTOR_SIZE as u32, 1 << 31),
        Err(FrameVBlkConfigError::UnknownFlags(1 << 31))
    );
}

#[test]
fn config_abi_is_fixed() {
    assert_eq!(size_of::<FrameVBlkConfig>(), 16);
    assert_eq!(align_of::<FrameVBlkConfig>(), 8);
}

#[test]
fn status_values_match_virtio_blk() {
    assert_eq!(FrameVBlkStatus::Ok as u8, 0);
    assert_eq!(FrameVBlkStatus::IoErr as u8, 1);
    assert_eq!(FrameVBlkStatus::Unsupported as u8, 2);
}
