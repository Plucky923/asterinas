// SPDX-License-Identifier: MPL-2.0

//! Strict decoding of linked x86 disassembly.

use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(super) struct Instruction {
    pub(super) address: u64,
    pub(super) size: u64,
    pub(super) operation: String,
    pub(super) operands: Vec<String>,
}

pub(super) fn parse(text: &str) -> Result<BTreeMap<u64, Instruction>, String> {
    let mut instructions = BTreeMap::new();
    for line in text.lines() {
        let Some((address, text)) = line.trim().split_once(':') else {
            continue;
        };
        let Ok(address) = u64::from_str_radix(address, 16) else {
            continue;
        };
        let mut words = text.split_whitespace().peekable();
        let mut size = 0;
        while words
            .peek()
            .is_some_and(|word| word.len() == 2 && u8::from_str_radix(word, 16).is_ok())
        {
            words.next();
            size += 1;
        }
        if size == 0 {
            return Err("objdump omitted instruction bytes".into());
        }
        let mut operation = words.next().ok_or("objdump omitted mnemonic")?.to_string();
        if operation == "lock" && words.peek().is_some() {
            operation = words.next().ok_or("bare lock prefix")?.into()
        }
        let arguments = words.collect::<Vec<_>>().join(" ");
        let arguments = arguments.split('#').next().unwrap();
        let mut operands = Vec::new();
        let mut start = 0;
        let mut parentheses = 0;
        for (position, character) in arguments.char_indices() {
            match character {
                '(' => parentheses += 1,
                ')' => parentheses -= 1,
                ',' if parentheses == 0 => {
                    operands.push(arguments[start..position].trim().to_string());
                    start = position + 1;
                }
                _ => {}
            }
        }
        if !arguments[start..].trim().is_empty() {
            operands.push(arguments[start..].trim().to_string())
        }
        if instructions
            .insert(
                address,
                Instruction {
                    address,
                    size,
                    operation,
                    operands,
                },
            )
            .is_some()
        {
            return Err(format!("duplicate disassembly at {address:#x}"));
        }
    }
    Ok(instructions)
}
