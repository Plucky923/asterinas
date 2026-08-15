use super::MAX_FILL_BYTES;

#[test]
fn direct_fill_limit_is_nonzero() {
    assert_ne!(MAX_FILL_BYTES, 0);
}
