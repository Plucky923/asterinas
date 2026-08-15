use super::ConsoleInput;
use crate::MAX_INPUT_CHUNK_BYTES;

#[test]
fn console_input_moves_its_original_allocation() {
    let bytes = alloc::vec![1, 2, 3];
    let pointer = bytes.as_ptr();
    let input = ConsoleInput::new(bytes).unwrap();

    assert_eq!(input.bytes().len(), 3);
    assert_eq!(input.bytes(), &[1, 2, 3]);

    let bytes = input.into_bytes();
    assert_eq!(bytes.as_ptr(), pointer);
}

#[test]
fn console_input_rejects_empty_values() {
    assert!(ConsoleInput::new(alloc::vec![]).is_none());
}

#[test]
fn console_input_rejects_oversized_values() {
    assert!(ConsoleInput::new(alloc::vec![0; MAX_INPUT_CHUNK_BYTES + 1]).is_none());
}
