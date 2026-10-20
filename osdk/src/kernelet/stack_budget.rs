// SPDX-License-Identifier: MPL-2.0

//! Conservative final-ELF stack bounds for explicitly non-scheduling gates.
//!
//! LLVM frame metadata is necessary but insufficient: the analyzer also walks
//! the linked instruction graph, counts live frames at each direct call, and
//! rejects unknown instructions, recursion, cycles, indirect control flow and
//! dynamic stack adjustments. It never treats missing metadata as zero.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

mod analysis;
mod disassembly;
mod state;

use self::analysis::Analyzer;
use super::elf::{ElfImage, PF_W, PT_LOAD, Symbol};

pub(super) const HOST_STACK: u64 = u64::MAX;
const BOUNDED_BODY: &str = "kernelet_host_vcpu_on_spin_bounded_impl";

#[derive(Clone, Debug, Serialize)]
pub(super) struct Budget {
    pub service: String,
    pub required_space: u64,
    pub service_stack_use: Option<u64>,
    pub interrupt_entry_stack_use: u64,
    pub reason: String,
}

/// Writes a separate, packaging-ready ELF without relinking or changing code.
/// Cargo's original linked artifact remains unchanged for incremental builds.
pub(crate) fn generate_host_budgets(path: &Path) -> Result<PathBuf, String> {
    let original = fs::read(path).map_err(|error| error.to_string())?;
    let elf = ElfImage::parse(&original)?;
    // Validate code before deriving the interrupt bound or admitting a body.
    super::host_audit::audit_host_services_unfilled(path)?;
    let budgets = analyze(path, &elf)?;
    let mut generated = original.clone();
    let symbols = elf.symbols(&elf.section_headers()?)?;
    let strings = elf.symbol_string_table(&elf.section_headers()?)?;
    let segments = elf.program_headers()?;
    let mut changed_ranges = Vec::new();
    for budget in &budgets {
        let name = format!("kernelet_service_{}_budget", budget.service);
        let symbol = find_symbol(&elf, &symbols, &strings, &name)?;
        let end = symbol
            .value
            .checked_add(8)
            .ok_or("budget address overflow")?;
        let segment = segments
            .iter()
            .find(|segment| {
                segment.typ == PT_LOAD
                    && segment.flags & PF_W == 0
                    && segment.covers_vaddr_range(symbol.value, end)
            })
            .ok_or_else(|| format!("{name} is not read-only loadable data"))?;
        let offset = usize::try_from(
            segment
                .offset
                .checked_add(symbol.value - segment.vaddr)
                .ok_or("budget file offset overflow")?,
        )
        .map_err(|_| "budget file offset exceeds usize")?;
        let file_end = offset.checked_add(8).ok_or("budget file range overflow")?;
        generated
            .get_mut(offset..file_end)
            .ok_or("truncated budget cell")?
            .copy_from_slice(&budget.required_space.to_le_bytes());
        changed_ranges.push(offset..file_end);
    }
    // This stronger byte-level invariant also preserves all code, addresses,
    // section sizes, program headers, metadata and every unrelated data byte.
    for (index, (before, after)) in original.iter().zip(&generated).enumerate() {
        if before != after && !changed_ranges.iter().any(|range| range.contains(&index)) {
            return Err(format!(
                "budget generation changed unrelated byte {index:#x}"
            ));
        }
    }
    let output = path.with_extension("budgets.elf");
    if fs::read(&output).ok().as_deref() != Some(generated.as_slice()) {
        fs::write(&output, &generated).map_err(|error| error.to_string())?;
    }
    fs::write(
        output.with_extension("stack-budgets.json"),
        serde_json::to_vec_pretty(&budgets).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    // Recompute the proof from the packaged bytes rather than trusting a
    // mutable sidecar report. The final audit also verifies every cell value.
    super::host_audit::audit_host_services(&output)?;
    for budget in &budgets {
        info!(
            "Host service stack budget: {} = {} ({})",
            budget.service,
            if budget.required_space == HOST_STACK {
                "HOST_STACK".into()
            } else {
                budget.required_space.to_string()
            },
            budget.reason
        );
    }
    Ok(output)
}

pub(super) fn analyze(path: &Path, elf: &ElfImage<'_>) -> Result<Vec<Budget>, String> {
    let sections = elf.section_headers()?;
    let symbols = elf.symbols(&sections)?;
    let strings = elf.symbol_string_table(&sections)?;
    let frames = read_stack_sizes(elf, &sections, &fs::read(path).map_err(|e| e.to_string())?)?;
    let mut analyzer = Analyzer::new(path, elf, &symbols, &strings, frames)?;
    // The strict trap audit establishes 15 GPR saves and two vector/error
    // words before handoff. Hardware adds five words and at most 15 alignment
    // bytes. Interrupt gates mask IRQs; one NMI may nest before the handoff.
    // NMI blocking prevents a second simultaneous NMI on this stack. Once
    // switched, subsequent handler frames belong to the separate safe stack.
    let entry = interrupt_entry_bound(15, 2, 5, 15, 2)?;
    let mut budgets = Vec::new();
    for symbol in &symbols {
        let name = elf.symbol_name(&strings, symbol)?;
        let Some(service) = name
            .strip_prefix("kernelet_service_")
            .and_then(|name| name.strip_suffix("_budget"))
        else {
            continue;
        };
        let result = if service == "vcpu_on_spin" {
            find_symbol(elf, &symbols, &strings, BOUNDED_BODY)
                .map(|symbol| symbol.value)
                .and_then(|address| analyzer.bound(address))
                // The audited gate subtracts 8 alignment bytes and CALL
                // pushes 8 bytes. The bounded return writes no Image-stack
                // data; rejection switches to HOST_RSP before cleanup.
                .and_then(|body| body.checked_add(16).ok_or("service bound overflow".into()))
        } else {
            Err("no audited non-scheduling boundary for this service".into())
        };
        let (required_space, service_stack_use, reason) = match result {
            Ok(body) => match body.checked_add(entry) {
                Some(total) => (
                    total,
                    Some(body),
                    "linked finite direct-call graph and bounded assembly entry/return".into(),
                ),
                None => (HOST_STACK, None, "combined stack bound overflow".into()),
            },
            Err(reason) => (HOST_STACK, None, reason),
        };
        budgets.push(Budget {
            service: service.into(),
            required_space,
            service_stack_use,
            interrupt_entry_stack_use: entry,
            reason,
        });
    }
    budgets.sort_by(|left, right| left.service.cmp(&right.service));
    Ok(budgets)
}

fn interrupt_entry_bound(
    registers: u64,
    software_words: u64,
    hardware_words: u64,
    alignment: u64,
    nesting: u64,
) -> Result<u64, String> {
    registers
        .checked_add(software_words)
        .and_then(|words| words.checked_add(hardware_words))
        .and_then(|words| words.checked_mul(8))
        .and_then(|bytes| bytes.checked_add(alignment))
        .and_then(|bytes| bytes.checked_mul(nesting))
        .ok_or("interrupt-entry stack bound overflow".into())
}

fn find_symbol<'a>(
    elf: &ElfImage<'_>,
    symbols: &'a [Symbol],
    strings: &[u8],
    name: &str,
) -> Result<&'a Symbol, String> {
    symbols
        .iter()
        .find(|symbol| elf.symbol_name(strings, symbol).ok() == Some(name))
        .ok_or_else(|| format!("linked Host lacks {name}"))
}

fn read_stack_sizes(
    elf: &ElfImage<'_>,
    sections: &[super::elf::SectionHeader],
    bytes: &[u8],
) -> Result<HashMap<u64, u64>, String> {
    let mut frames = HashMap::new();
    for (index, section) in sections.iter().enumerate() {
        if elf.section_name(sections, index)? != ".stack_sizes" {
            continue;
        }
        let start =
            usize::try_from(section.offset).map_err(|_| "stack metadata offset overflow")?;
        let end = usize::try_from(
            section
                .offset
                .checked_add(section.size)
                .ok_or("stack metadata range overflow")?,
        )
        .map_err(|_| "stack metadata range overflow")?;
        let mut data = bytes.get(start..end).ok_or("truncated stack metadata")?;
        while !data.is_empty() {
            let address = u64::from_le_bytes(
                data.get(..8)
                    .ok_or("truncated stack address")?
                    .try_into()
                    .unwrap(),
            );
            data = &data[8..];
            let size = uleb(&mut data)?;
            if frames.insert(address, size).is_some_and(|old| old != size) {
                return Err(format!("conflicting stack metadata for {address:#x}"));
            }
        }
    }
    Ok(frames)
}

fn uleb(data: &mut &[u8]) -> Result<u64, String> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = data.split_first().ok_or("truncated stack size")?;
        *data = rest;
        if shift == 63 && byte > 1 {
            return Err("stack size overflow".into());
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("stack size overflow".into())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{state::State, *};
    #[test]
    #[ignore = "requires KERNELET_LINKED_HOST naming an optimized unfilled Host ELF"]
    fn optimized_host_has_a_numeric_spin_budget() {
        let path = PathBuf::from(
            std::env::var_os("KERNELET_LINKED_HOST").expect("set KERNELET_LINKED_HOST"),
        );
        let output = generate_host_budgets(&path).unwrap();
        let bytes = fs::read(&output).unwrap();
        let elf = ElfImage::parse(&bytes).unwrap();
        let budgets = analyze(&output, &elf).unwrap();
        let spin = budgets
            .iter()
            .find(|budget| budget.service == "vcpu_on_spin")
            .unwrap();
        assert_ne!(spin.required_space, HOST_STACK, "{}", spin.reason);
        eprintln!("{}: {spin:?}", output.display());
    }
    #[test]
    fn metadata_rejects_truncation_and_overflow() {
        assert_eq!(uleb(&mut &[0x80, 0x01][..]).unwrap(), 128);
        assert!(uleb(&mut &[0x80][..]).is_err());
        assert!(uleb(&mut &[0xff; 10][..]).is_err());
        assert!(interrupt_entry_bound(u64::MAX, 2, 5, 15, 2).is_err());
        assert_eq!(interrupt_entry_bound(15, 2, 5, 15, 2).unwrap(), 382);
    }
    #[test]
    fn linked_constant_arithmetic_prunes_impossible_error_branch() {
        let graph=disassembly::parse("100: 48 c7 c0 00 b0 33 89 movq $-0x76cc5000, %rax\n107: 48 c7 c1 a8 b8 33 89 movq $-0x76cc4758, %rcx\n10e: 48 29 c1 subq %rax, %rcx\n111: 48 c1 e9 20 shrq $0x20, %rcx\n115: 75 01 jne 0x118").unwrap();
        let mut state = State::default();
        for instruction in graph.values().take(4) {
            state.plain(instruction).unwrap();
        }
        assert_eq!(state.branch("jne"), Some(false));
        state.after_call();
        assert_eq!(state.branch("jne"), None);
    }
    #[test]
    fn refuses_dynamic_adjustments_red_zone_and_unknown_instructions() {
        for text in [
            "100: 48 29 c4 subq %rax, %rsp",
            "100: 48 89 44 24 f8 movq %rax, -0x8(%rsp)",
            "100: 0f 05 syscall",
        ] {
            let graph = disassembly::parse(text).unwrap();
            assert!(State::default().plain(&graph[&0x100]).is_err());
        }
        assert!(analysis::branch_target(&["*%rax".into()]).is_err());
    }

    #[test]
    fn linked_graph_counts_peak_calls_and_rejects_unproved_paths() {
        let directory = tempfile::tempdir().unwrap();
        let assembly = directory.path().join("paths.S");
        let object = directory.path().join("paths.o");
        let path = directory.path().join("paths.elf");
        fs::write(
            &assembly,
            r#"
.text
.macro function name, frame
.global \name
.type \name,@function
\name:
.pushsection .stack_sizes,"",@progbits
.quad \name
.uleb128 \frame
.popsection
.endm
.macro end name
.size \name,.-\name
.endm
function finite,8
pushq %rbx
call leaf
popq %rbx
ret
end finite
function sequential,8
pushq %rax
call leaf
call leaf
popq %rax
ret
end sequential
function conditional,32
testq %rdi,%rdi
je 1f
subq $32,%rsp
call leaf
addq $32,%rsp
ret
1: call leaf
ret
end conditional
function tail,0
jmp leaf
end tail
function leaf,24
subq $24,%rsp
addq $24,%rsp
ret
end leaf
function recursive,0
call recursive
ret
end recursive
function indirect,0
call *%rax
ret
end indirect
function cyclic,0
1: jmp 1b
end cyclic
function dynamic,0
subq %rax,%rsp
ret
end dynamic
function underreported,8
subq $16,%rsp
addq $16,%rsp
ret
end underreported
function unbalanced,8
subq $8,%rsp
ret
end unbalanced
function cmp_width,4096
movl $0xffffffff,%eax
cmpl $-1,%eax
je 1f
ret
1: subq $4096,%rsp
addq $4096,%rsp
ret
end cmp_width
function memory_pop,8
pushq %rax
popq -4096(%rsp)
ret
end memory_pop
function frame_alias,8
pushq %rbp
movq %rsp,%rbp
movq %rax,-4096(%rbp)
popq %rbp
ret
end frame_alias
function replace_sp,8
pushq %rax
popq %rsp
ret
end replace_sp
function cmp_exchange,4096
movl $2,%eax
movl $1,%ebx
movl $2,%ecx
cmpxchgq %rbx,%rcx
je 1f
ret
1: subq $4096,%rsp
addq $4096,%rsp
ret
end cmp_exchange
function implicit_multiply,4096
movl $1,%eax
movl $4096,%edi
imulq %rdi
subq %rax,%rsp
addq %rax,%rsp
ret
end implicit_multiply
function high_byte,4097
movq $1,%rax
movb $16,%ah
subq %rax,%rsp
addq %rax,%rsp
ret
end high_byte
function restore_flags,4096
xorl %eax,%eax
pushq $0
popfq
je 1f
subq $4096,%rsp
addq $4096,%rsp
1: ret
end restore_flags
function alias_call,0
movq %rsp,%rdi
call alias_leaf
ret
end alias_call
function alias_leaf,0
movq $0,-4096(%rdi)
ret
end alias_leaf
function returned_pointer,8
pushq %rax
call pointer_leaf
movq (%rax),%rax
popq %rcx
ret
end returned_pointer
function pointer_leaf,0
movq $0x10000,%rax
ret
end pointer_leaf
function alias_escape,0
leaq 8(%rsp),%rax
subq $4096,%rax
movq %rax,(%rdi)
ret
end alias_escape
function alias_return,0
movq %rsp,%rax
ret
end alias_return
function incoming_frame,0
movq $0,-4096(%rbp)
ret
end incoming_frame
function replace_return,0
movabsq $leaf,%rax
movq %rax,(%rsp)
ret
end replace_return
function clobbered_callee_saved,4096
movq $1,%rbx
call clobber
subq %rbx,%rsp
addq %rbx,%rsp
ret
end clobbered_callee_saved
function clobber,0
movq $4096,%rbx
ret
end clobber
function unknown_carry,4096
movq $0,%rax
cmpq $0,%rdi
adcq $4095,%rax
subq %rax,%rsp
addq %rax,%rsp
ret
end unknown_carry
function byte_logic,4096
movl $255,%edi
andb $0,%dil
jne 1f
ret
1: subq $4096,%rsp
addq $4096,%rsp
ret
end byte_logic
.global missing
.type missing,@function
missing: ret
end missing
"#,
        )
        .unwrap();
        assert!(
            Command::new("as")
                .arg("--64")
                .arg(&assembly)
                .arg("-o")
                .arg(&object)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ld")
                .arg("-e")
                .arg("finite")
                .arg(&object)
                .arg("-o")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let bytes = fs::read(&path).unwrap();
        let elf = ElfImage::parse(&bytes).unwrap();
        let sections = elf.section_headers().unwrap();
        let symbols = elf.symbols(&sections).unwrap();
        let strings = elf.symbol_string_table(&sections).unwrap();
        let frames = read_stack_sizes(&elf, &sections, &bytes).unwrap();
        let mut analyzer = Analyzer::new(&path, &elf, &symbols, &strings, frames).unwrap();
        for (name, expected) in [
            ("finite", 40),
            ("sequential", 40),
            ("conditional", 64),
            ("tail", 24),
            ("cmp_width", 4096),
            ("byte_logic", 0),
        ] {
            let symbol = find_symbol(&elf, &symbols, &strings, name).unwrap();
            assert_eq!(analyzer.bound(symbol.value).unwrap(), expected, "{name}");
        }
        for name in [
            "recursive",
            "indirect",
            "cyclic",
            "dynamic",
            "underreported",
            "unbalanced",
            "missing",
            "memory_pop",
            "frame_alias",
            "replace_sp",
            "cmp_exchange",
            "implicit_multiply",
            "high_byte",
            "restore_flags",
            "alias_call",
            "returned_pointer",
            "alias_escape",
            "alias_return",
            "incoming_frame",
            "replace_return",
            "clobbered_callee_saved",
            "unknown_carry",
        ] {
            let symbol = find_symbol(&elf, &symbols, &strings, name).unwrap();
            assert!(analyzer.bound(symbol.value).is_err(), "admitted {name}");
        }
    }
}
