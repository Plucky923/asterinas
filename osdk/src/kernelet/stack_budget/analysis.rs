// SPDX-License-Identifier: MPL-2.0

//! Bounds live stack frames over the linked direct-call graph.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Command,
};

use super::{
    super::elf::{ElfImage, Symbol},
    disassembly,
    state::State,
};

pub(super) struct Analyzer<'a> {
    path: &'a Path,
    elf: &'a ElfImage<'a>,
    symbols: &'a [Symbol],
    strings: &'a [u8],
    frames: HashMap<u64, u64>,
    tool: PathBuf,
    cache: HashMap<u64, Result<u64, String>>,
    active: HashSet<u64>,
}

impl<'a> Analyzer<'a> {
    pub(super) fn new(
        path: &'a Path,
        elf: &'a ElfImage<'a>,
        symbols: &'a [Symbol],
        strings: &'a [u8],
        frames: HashMap<u64, u64>,
    ) -> Result<Self, String> {
        let output = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("rustc cannot identify the analysis toolchain".into());
        }
        let sysroot = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
        let tool =
            Path::new(sysroot.trim()).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump");
        if !tool.is_file() {
            return Err(
                "service budget analysis requires the pinned toolchain's llvm-tools component"
                    .into(),
            );
        }
        Ok(Self {
            path,
            elf,
            symbols,
            strings,
            frames,
            tool,
            cache: HashMap::new(),
            active: HashSet::new(),
        })
    }

    pub(super) fn bound(&mut self, address: u64) -> Result<u64, String> {
        if let Some(bound) = self.cache.get(&address) {
            return bound.clone();
        }
        if !self.active.insert(address) {
            return Err(format!("recursive call at {address:#x}"));
        }
        let result = self.function_bound(address);
        self.active.remove(&address);
        self.cache.insert(address, result.clone());
        result
    }

    fn function_bound(&mut self, address: u64) -> Result<u64, String> {
        let frame = *self
            .frames
            .get(&address)
            .ok_or_else(|| format!("missing .stack_sizes for {address:#x}"))?;
        let symbol = self
            .symbols
            .iter()
            .find(|symbol| symbol.value == address && symbol.info & 15 == 2 && symbol.size != 0)
            .ok_or_else(|| format!("unresolved function at {address:#x}"))?;
        let name = self.elf.symbol_name(self.strings, symbol)?;
        let output = Command::new(&self.tool)
            .arg(format!("--disassemble-symbols={name}"))
            .arg(self.path)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!("cannot disassemble {name}"));
        }
        let graph =
            disassembly::parse(&String::from_utf8(output.stdout).map_err(|e| e.to_string())?)?;
        let end = address
            .checked_add(symbol.size)
            .ok_or("function range overflow")?;
        let mut expected = address;
        for (&position, instruction) in graph.range(address..end) {
            if position != expected {
                return Err(format!("incomplete disassembly of {name}"));
            }
            expected = position
                .checked_add(instruction.size)
                .ok_or("instruction range overflow")?;
        }
        if expected != end {
            return Err(format!("incomplete disassembly of {name}"));
        }
        let mut work = vec![(address, State::default(), HashSet::new())];
        let mut peak = 0u64;
        let mut count = 0;
        while let Some((position, mut state, mut ancestors)) = work.pop() {
            count += 1;
            if count > 50_000 {
                return Err("control-flow analysis limit exceeded".into());
            }
            if !ancestors.insert(position) {
                return Err(format!("cyclic control flow in {name}"));
            }
            let instruction = graph
                .get(&position)
                .filter(|_| position >= address && position < end)
                .ok_or_else(|| format!("unresolved branch in {name} at {position:#x}"))?;
            let next = position + instruction.size;
            let operation = instruction.operation.as_str();
            let operands = &instruction.operands;
            match operation {
                "pushq" => {
                    state.stack_operand(operands)?;
                    state.depth = state.depth.checked_add(8).ok_or("stack bound overflow")?
                }
                "popq" => {
                    state.stack_operand(operands)?;
                    state.depth = state
                        .depth
                        .checked_sub(8)
                        .ok_or("pop above function entry")?;
                    if let Some(destination) = operands.first() {
                        state.forget(destination)
                    }
                }
                "retq" => {
                    if state.depth != 0 || !operands.is_empty() {
                        return Err(format!("unbalanced or non-SysV return in {name}"));
                    }
                    if !state.stack_aliases.is_empty() {
                        return Err("stack-derived register escapes through return".into());
                    }
                    continue;
                }
                "callq" => {
                    if !state.stack_aliases.is_empty() {
                        return Err("stack-derived register escapes across a call".into());
                    }
                    let target = branch_target(operands)?;
                    let callee = self.bound(target)?;
                    peak = peak.max(
                        state
                            .depth
                            .checked_add(8)
                            .and_then(|value| value.checked_add(callee))
                            .ok_or("call stack bound overflow")?,
                    );
                    state.after_call();
                }
                "jmp" | "jmpq" => {
                    let target = branch_target(operands)?;
                    if target < address || target >= end {
                        if !state.stack_aliases.is_empty() {
                            return Err("stack-derived register escapes across a tail call".into());
                        }
                        if state.depth != 0 {
                            return Err("tail call with live stack frame".into());
                        }
                        peak = peak.max(self.bound(target)?);
                        continue;
                    }
                    work.push((target, state, ancestors));
                    continue;
                }
                operation if operation.starts_with('j') => {
                    let target = branch_target(operands)?;
                    match state.branch(operation) {
                        Some(true) => {
                            work.push((target, state, ancestors));
                            continue;
                        }
                        Some(false) => {}
                        None => work.push((target, state.clone(), ancestors.clone())),
                    }
                }
                _ => state
                    .plain(instruction)
                    .map_err(|error| format!("{name} at {position:#x}: {error}"))?,
            }
            if state.depth > frame {
                return Err(format!("instructions exceed .stack_sizes for {name}"));
            }
            peak = peak.max(state.depth);
            work.push((next, state, ancestors));
        }
        Ok(peak)
    }
}

pub(super) fn branch_target(operands: &[String]) -> Result<u64, String> {
    let target = operands
        .first()
        .and_then(|operand| operand.split_whitespace().next())
        .ok_or("missing branch target")?;
    if target.starts_with('*') {
        return Err("indirect control flow".into());
    }
    u64::from_str_radix(target.trim_start_matches("0x"), 16)
        .map_err(|_| "unknown branch target".into())
}
