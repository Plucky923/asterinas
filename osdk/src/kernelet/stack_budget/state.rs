// SPDX-License-Identifier: MPL-2.0

//! Tracks register provenance, constants, and stack effects.

use std::collections::{HashMap, HashSet};

use super::disassembly::Instruction;

#[derive(Clone)]
pub(super) struct State {
    pub(super) depth: u64,
    constants: HashMap<String, u64>,
    zero: Option<bool>,
    pub(super) stack_aliases: HashSet<String>,
    // The zero-argument root must not dereference incoming Image register
    // values. Callees conservatively receive the same treatment; only an
    // explicit overwrite establishes a usable Host pointer or scalar.
    incoming: HashSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            depth: 0,
            constants: HashMap::new(),
            zero: None,
            stack_aliases: HashSet::new(),
            incoming: [
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12",
                "r13", "r14", "r15",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

fn register(name: &str) -> Option<(String, u32)> {
    let name = name.strip_prefix('%')?;
    const ALIASES: [[&str; 4]; 8] = [
        ["rax", "eax", "ax", "al"],
        ["rbx", "ebx", "bx", "bl"],
        ["rcx", "ecx", "cx", "cl"],
        ["rdx", "edx", "dx", "dl"],
        ["rsi", "esi", "si", "sil"],
        ["rdi", "edi", "di", "dil"],
        ["rbp", "ebp", "bp", "bpl"],
        ["rsp", "esp", "sp", "spl"],
    ];
    for aliases in ALIASES {
        if let Some(index) = aliases.iter().position(|alias| *alias == name) {
            return Some((aliases[0].into(), [64, 32, 16, 8][index]));
        }
    }
    let (base, bits) = if let Some(base) = name.strip_suffix('d') {
        (base, 32)
    } else if let Some(base) = name.strip_suffix('w') {
        (base, 16)
    } else if let Some(base) = name.strip_suffix('b') {
        (base, 8)
    } else {
        (name, 64)
    };
    (8..=15)
        .any(|index| base == format!("r{index}"))
        .then(|| (base.into(), bits))
}

fn mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

#[derive(Clone, Copy, PartialEq)]
enum PlainOperation {
    Move,
    ExtendedMove,
    Compare,
    Binary,
    Unary,
    Multiply,
    Set,
    ConditionalMove,
    Lea,
}

impl PlainOperation {
    fn decode(instruction: &Instruction) -> Result<Self, String> {
        let operation = instruction.operation.as_str();
        let operands = &instruction.operands;
        let exact_move = matches!(operation, "movq" | "movl" | "movw" | "movb" | "movabsq");
        let extended_move = matches!(
            operation,
            "movzbl"
                | "movzwl"
                | "movzbq"
                | "movzwq"
                | "movsbq"
                | "movswq"
                | "movslq"
                | "movsbl"
                | "movswl"
        );
        let comparison = matches!(
            operation,
            "cmpq" | "cmpl" | "cmpw" | "cmpb" | "testq" | "testl" | "testw" | "testb"
        );
        let binary = matches!(
            operation,
            "addq"
                | "addl"
                | "subq"
                | "subl"
                | "andq"
                | "andl"
                | "andb"
                | "adcq"
                | "orq"
                | "orl"
                | "xorq"
                | "xorl"
                | "xorw"
                | "xorb"
                | "shrq"
                | "shrl"
                | "shlq"
                | "shll"
                | "sarq"
                | "sarl"
        );
        let unary = matches!(
            operation,
            "incq" | "incl" | "decq" | "decl" | "negq" | "negl" | "notq" | "notl"
        );
        let multiply = matches!(operation, "imulq" | "imull");
        let conditions = [
            "a", "ae", "b", "be", "e", "g", "ge", "l", "le", "na", "nae", "nb", "nbe", "ne", "ng",
            "nge", "nl", "nle", "no", "np", "ns", "nz", "o", "p", "pe", "po", "s", "z",
        ];
        let set = operation
            .strip_prefix("set")
            .is_some_and(|suffix| conditions.contains(&suffix));
        let conditional_move = operation.strip_prefix("cmov").is_some_and(|suffix| {
            suffix
                .strip_suffix(['q', 'l', 'w'])
                .is_some_and(|condition| conditions.contains(&condition))
        });
        let lea = matches!(operation, "leaq" | "leal");
        let arity_ok = if unary || set {
            operands.len() == 1
        } else if multiply {
            matches!(operands.len(), 2 | 3)
        } else {
            operands.len() == 2
        };
        if !(exact_move
            || extended_move
            || comparison
            || binary
            || unary
            || multiply
            || set
            || conditional_move
            || lea)
            || !arity_ok
        {
            return Err(format!(
                "unsupported instruction or operand arity: {operation} at {:#x}",
                instruction.address
            ));
        }
        Ok(if exact_move {
            PlainOperation::Move
        } else if extended_move {
            PlainOperation::ExtendedMove
        } else if comparison {
            PlainOperation::Compare
        } else if binary {
            PlainOperation::Binary
        } else if unary {
            PlainOperation::Unary
        } else if multiply {
            PlainOperation::Multiply
        } else if set {
            PlainOperation::Set
        } else if conditional_move {
            PlainOperation::ConditionalMove
        } else {
            PlainOperation::Lea
        })
    }
}

impl State {
    pub(super) fn stack_operand(&self, operands: &[String]) -> Result<(), String> {
        if operands.len() != 1
            || !register(&operands[0])
                .is_some_and(|(register, bits)| bits == 64 && register != "rsp")
            || register(&operands[0])
                .is_some_and(|(register, _)| self.stack_aliases.contains(&register))
        {
            return Err("unsupported push/pop operand or stack-derived escape".into());
        }
        Ok(())
    }
    fn value(&self, operand: &str) -> Option<u64> {
        if let Some(immediate) = operand.strip_prefix('$') {
            let (negative, text) = immediate
                .strip_prefix('-')
                .map_or((false, immediate), |text| (true, text));
            let number = if let Some(hex) = text.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()?
            } else {
                text.parse::<u64>().ok()?
            };
            return Some(if negative {
                0u64.wrapping_sub(number)
            } else {
                number
            });
        }
        let (register, bits) = register(operand)?;
        self.constants
            .get(&register)
            .map(|value| value & mask(bits))
    }
    pub(super) fn forget(&mut self, operand: &str) {
        if let Some((register, _)) = register(operand) {
            self.constants.remove(&register);
            self.stack_aliases.remove(&register);
            self.incoming.insert(register);
        }
    }
    fn write(&mut self, operand: &str, value: Option<u64>) {
        let Some((register, bits)) = register(operand) else {
            return;
        };
        let value = if bits < 32 {
            value
                .zip(self.constants.get(&register).copied())
                .map(|(low, old)| (old & !mask(bits)) | (low & mask(bits)))
        } else {
            value.map(|value| value & mask(bits))
        };
        if let Some(value) = value {
            self.constants.insert(register, value);
        } else {
            self.constants.remove(&register);
        }
    }
    pub(super) fn after_call(&mut self) {
        // Do not assume preservation of callee-saved registers without a
        // machine-code proof of that property. Forget every register value.
        self.constants.clear();
        self.zero = None;
        self.incoming.extend(
            [
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12",
                "r13", "r14", "r15",
            ]
            .into_iter()
            .map(String::from),
        );
    }
    pub(super) fn branch(&self, operation: &str) -> Option<bool> {
        match operation {
            "je" | "jz" => self.zero,
            "jne" | "jnz" => self.zero.map(|zero| !zero),
            _ => None,
        }
    }
    fn operand_alias(&self, operand: &str) -> bool {
        operand
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '%'))
            .filter_map(register)
            .any(|(register, _)| {
                register == "rsp"
                    || self.stack_aliases.contains(&register)
                    || self.incoming.contains(&register)
            })
    }

    fn set_alias(&mut self, operand: &str, derived: bool) {
        if let Some((register, bits)) = register(operand) {
            let derived = derived
                || (bits < 32
                    && (self.stack_aliases.contains(&register)
                        || self.incoming.contains(&register)));
            self.incoming.remove(&register);
            if derived {
                self.stack_aliases.insert(register);
            } else {
                self.stack_aliases.remove(&register);
            }
        }
    }

    fn validate_operands(&self, operands: &[String]) -> Result<(), String> {
        for operand in operands {
            if matches!(operand.as_str(), "%ah" | "%bh" | "%ch" | "%dh") {
                return Err("unsupported high-byte register".into());
            }
            if operand.contains('(') && self.operand_alias(operand) {
                // Plain RSP-relative accesses are the only accepted stack
                // addresses. Derived aliases cannot escape to memory or calls.
                let displacement = operand
                    .strip_suffix("(%rsp)")
                    .ok_or("dereference of a stack-derived register or indexed RSP")?;
                let displacement = if displacement.is_empty() {
                    0
                } else {
                    self.value(&format!("${displacement}"))
                        .ok_or("unknown RSP displacement")?
                };
                if displacement > isize::MAX as u64 {
                    return Err("red-zone stack access".into());
                }
            }
            if operand.starts_with('%') && !operand.contains('(') && register(operand).is_none() {
                return Err("unsupported register class".into());
            }
        }
        Ok(())
    }

    fn constant_result(
        operation: &str,
        first: Option<u64>,
        last: Option<u64>,
        width: u32,
        same: bool,
    ) -> Option<u64> {
        match operation {
            "xorq" | "xorl" | "xorw" | "xorb" if same => Some(0),
            "addq" | "addl" => first
                .zip(last)
                .map(|(first, last)| last.wrapping_add(first)),
            "subq" | "subl" => first
                .zip(last)
                .map(|(first, last)| last.wrapping_sub(first)),
            "andq" | "andl" | "andb" => first.zip(last).map(|(first, last)| last & first),
            "orq" | "orl" => first.zip(last).map(|(first, last)| last | first),
            "xorq" | "xorl" => first.zip(last).map(|(first, last)| last ^ first),
            "shrq" | "shrl" => first
                .zip(last)
                .map(|(first, last)| last >> ((first as u32) & (width - 1))),
            "shlq" | "shll" => first
                .zip(last)
                .map(|(first, last)| last << ((first as u32) & (width - 1))),
            _ => None,
        }
        .map(|value| value & mask(width))
    }

    pub(super) fn plain(&mut self, instruction: &Instruction) -> Result<(), String> {
        let operation = instruction.operation.as_str();
        let operands = &instruction.operands;
        let destination = operands.last().map(String::as_str).unwrap_or("");
        // LLVM's AT&T printer represents LOCK as a separate prefix line.
        if operation == "lock" && operands.is_empty() {
            return Ok(());
        }
        self.validate_operands(operands)?;
        if matches!(operation, "nop" | "nopl" | "nopw" | "endbr64" | "cld") {
            return Ok(());
        }
        let kind = PlainOperation::decode(instruction)?;
        let exact_move = kind == PlainOperation::Move;
        let extended_move = kind == PlainOperation::ExtendedMove;
        let comparison = kind == PlainOperation::Compare;
        let lea = kind == PlainOperation::Lea;
        let set = kind == PlainOperation::Set;
        let conditional_move = kind == PlainOperation::ConditionalMove;
        if !comparison && register(destination).is_some_and(|(register, _)| register == "rsp") {
            if matches!(operation, "addq" | "subq") {
                let amount = self.value(&operands[0]).ok_or("dynamic stack adjustment")?;
                if amount > isize::MAX as u64 {
                    return Err("negative stack adjustment".into());
                }
                self.depth = if operation == "subq" {
                    self.depth.checked_add(amount)
                } else {
                    self.depth.checked_sub(amount)
                }
                .ok_or("invalid stack adjustment")?;
                self.zero = None;
                return Ok(());
            }
            return Err("unrecognized stack-pointer write".into());
        }
        let first = operands.first().and_then(|operand| self.value(operand));
        let last = self.value(destination);
        let width = match operation.as_bytes().last() {
            Some(b'b') => 8,
            Some(b'w') => 16,
            Some(b'l') => 32,
            _ => 64,
        };
        if !comparison && destination.ends_with("(%rsp)") {
            let displacement = destination.strip_suffix("(%rsp)").unwrap();
            let displacement = if displacement.is_empty() {
                0
            } else {
                self.value(&format!("${displacement}"))
                    .ok_or("unknown stack store offset")?
            };
            if displacement
                .checked_add((width / 8) as u64)
                .is_none_or(|end| end > self.depth)
            {
                return Err("stack store reaches the return address or caller frame".into());
            }
        }
        if comparison {
            self.zero = first.zip(last).map(|(first, last)| {
                let first = first & mask(width);
                let last = last & mask(width);
                if operation.starts_with("cmp") {
                    first == last
                } else {
                    first & last == 0
                }
            });
            return Ok(());
        }
        let source_alias = if lea {
            self.operand_alias(&operands[0])
        } else {
            operands[..operands.len().saturating_sub(1)]
                .iter()
                .any(|operand| {
                    (!operand.contains('(') && self.operand_alias(operand))
                        || operand.contains("(%rsp)")
                })
        };
        let old_alias = self.operand_alias(destination);
        if register(destination).is_none() && source_alias {
            return Err("stack-derived value escapes to memory".into());
        }
        let same =
            operands.len() == 2 && operands[0] == operands[1] && register(destination).is_some();
        if exact_move || extended_move || lea {
            self.write(destination, if exact_move { first } else { None });
            self.set_alias(destination, source_alias);
            return Ok(());
        }
        let old_zero = self.zero;
        let value = Self::constant_result(operation, first, last, width, same);
        self.write(destination, value);
        self.set_alias(
            destination,
            if same && operation.starts_with("xor") {
                false
            } else {
                source_alias || old_alias
            },
        );
        // SETcc, CMOVcc and NOT do not change flags. Other unmodeled flag
        // effects become unknown; stale flags must never prune a live branch.
        self.zero = if set || conditional_move || matches!(operation, "notq" | "notl") {
            old_zero
        } else if matches!(operation, "shrq" | "shrl" | "shlq" | "shll")
            && first.is_some_and(|count| count & (width as u64 - 1) == 0)
        {
            old_zero
        } else {
            value.map(|value| value == 0)
        };
        Ok(())
    }
}
