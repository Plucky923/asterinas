---
date: 2026-09-09
mode: diff
base: 437365615
head: 005cb59ec
branch: framevm
title: "FrameVM feature branch (10 commits over main)"
---

# Summary

The branch adds the complete FrameVM stack in 10 commits over `main` (~1,084 files, +187k lines): OSTD service-loading support, shared ABI contracts, the FrameVisor host runtime (`kernel/comps/framevisor`), kernel integration (`/dev/framevm`, VMM lifecycle, assigned-PCI fault containment), the trimmed-kernel service fork (`services/aster-framevm`, ~648 files with a recorded upstream baseline and three-way-merge sync tooling), OSDK build integration, regression suites, and architecture documentation.

**What the code does well.** The design discipline is unusually high for a change of this size: the ioctl boundary validates every field with explicit errno mapping (`ioctl_defs.rs`); artifact authorization is TOCTOU-safe by sharing the boot-authorized image instead of the checked file; the wait-queue enqueue-then-check protocol and the RAII spin-lock wrapper are correct; `unsafe` stays confined to `ostd/` with documented `# Safety` contracts; the massive service fork is an explicitly documented decision backed by `UPSTREAM.toml`, `tools/sync_framevm_from_main.sh`, and an architecture-gate checker wired into `make check`; ktest coverage accompanies the trickiest primitives (fault ring buffer, control state machine, memory admission).

**Top issues by severity.**

1. *(major, process)* The branch ends in a WIP commit `005cb59ec` whose subject is `1`, mixing debug scaffolding, `CLAUDE.md` (containing a machine-specific `/home/ubuntu/...` path), `Components.toml` reordering, and assorted fixes — it must be split before merge.
2. *(major, docs/ABI)* Two documented ABI contracts diverge from the implementation: the console fd is documented "nonblocking" but created blocking, and `FRAMEVM_ADD_BLOCK` is documented as `device_id == 0` only while the code and `framevmm` use IDs 0–15.
3. *(major, observability)* Logging conventions are violated branch-wide: `early_println!` after the logger is up, third-party `log::` crate macros in `kernel/comps/framevisor` and the new `ostd` loader, and manual `[FrameVM]`/`[framevisor]`/`[Loader]` bracket prefixes instead of `__log_prefix`.
4. *(minor)* Scattered items: the user-visible `-5` exit code is an unnamed magic number repeated at three sites; `start()` holds the draft mutex across the whole start transaction while sibling ioctls follow an `EBUSY` contract; a BAR-invariant `.expect()` sits on the guest-reachable emulation path; unattributable DMA faults panic the Host without a documented fail-stop rationale; the new book pages ignore the repo's semantic-line-breaks convention.

**Structural recommendation.** The single biggest long-term cost is the `services/aster-framevm` fork (538 upstream counterpart files, only 31 still byte-identical). The recorded-baseline + three-way-merge + `make check` gate is the right mitigation; consider also scheduling periodic syncs into the regular workflow so drift stays mechanical rather than semantic. Secondarily, the `/dev/framevm` glue (~1.7k lines) inside `aster-core` deserves either extraction to `kernel/comps/` or a comment justifying its placement.

**Coverage note.** Reviewed at `HEAD` (`005cb59ec`) against merge-base `437365615`: all 10 commit messages; deep read of the control device, VMM lifecycle, console, artifact authorization, assigned-PCI fault containment, framevisor sync/scheduler-exit paths, and the OSTD loader's unsafe surface; targeted scans (unwrap/panic reachability, lock policy, log macros, doc/code contract diffs) across `framevisor`, `osdk`, `tools`, and the service fork's FrameVM-specific deltas. The service fork's inherited-from-`main` code (~507 adapted files) was reviewed structurally, not line-by-line.

## Maintainability

### `CLAUDE.md` line 14

> ```diff
> +Use for task triage the engineering triage skill in
> +`/home/ubuntu/.agents/skills/engineering/triage/SKILL.md`.
> ```

Machine-specific absolute path committed to the repo (major): The committed `CLAUDE.md` references `/home/ubuntu/.agents/skills/engineering/triage/SKILL.md`, a path that only exists on one developer machine. Committing per-machine agent configuration leaks environment details and will be stale or broken for every other contributor.

**Fix.** Drop `CLAUDE.md` from the branch (it duplicates `AGENTS.md`, which it merely points to), or rewrite it with only repository-relative references and no personal absolute paths.

### `Components.toml` line 31

> ```diff
> +nix = { name = "aster-nix" }
> +virtio = { name = "aster-virtio" }
> +framevisor = { name = "aster-framevisor" }
> +input = { name = "aster-input" }
>  block = { name = "aster-block" }
> ```

`consistency` (nit): The new component entries abandon the file's alphabetical ordering: `nix`, `virtio`, `framevisor`, `input` are prepended before `block`, and the `framevm_*`/`framev_*` block is appended after `softirq`.

**Fix.** Re-sort all entries alphabetically (as the file was before) so the next contributor can find and diff entries predictably.

### `commit 005cb59ec message`

> ```diff
> commit 005cb59ec
> 
>     1
> ```

`imperative-subject` (major): The commit subject is `1`: not imperative, not descriptive, and it hides a large catch-all change (debug scaffolding in `kernel/core/src/init.rs`, `CLAUDE.md`, `Components.toml` reordering, fixes across `framevisor`, `framev-net`, `Makefile`).

**Fix.** Before merging, split this WIP commit with `git rebase -i` into focused commits with imperative subjects (e.g. `Fix ...`, `Clean up ...`), each carrying one logical change.

### `kernel/core/src/device/misc/framevm/ioctl_defs.rs` line 60

> ```diff
> +    if request.flags() & !FRAMEVM_CREATE_KNOWN_FLAGS != 0 {
> +        return_errno_with_message!(Errno::EINVAL, "unknown FrameVM create flags");
> +    }
> +    if !request.flags_are_zero() {
> +        return_errno_with_message!(Errno::EINVAL, "nonzero FrameVM create flags");
> +    }
> ```

`dry` (nit): `validate_create` checks `request.flags() & !FRAMEVM_CREATE_KNOWN_FLAGS != 0` and then `!request.flags_are_zero()`; since `FRAMEVM_CREATE_KNOWN_FLAGS` is `0`, both branches reject the same inputs with two different error messages.

**Fix.** Keep a single check — the `flags_are_zero()` one if zero-flags is the actual contract — and delete the redundant mask test (or derive the mask check from a non-empty known-flags set when one actually exists).

### `kernel/core/src/device/misc/framevm/mod.rs` line 14

> ```diff
> +mod artifact;
> +mod console_file;
> +mod controller;
> +mod ioctl_defs;
> +mod vm_file;
> ```

`layered-kernel-crates` (minor): The `/dev/framevm` control-device subsystem (~1.7k lines across seven files) lives directly inside `aster-core` (`kernel/core/src/device/misc/framevm/`), while the guideline says new subsystems go into separate `kernel/comps/` crates by default and `aster-core` only when necessary.

**Fix.** If the VFS/file-table coupling does not truly require living in `aster-core`, move the device into its own `kernel/comps/` crate depending on `aster-core`'s public surface; otherwise add a short comment here stating why this subsystem must live in `aster-core`.

### `kernel/core/src/device/misc/framevm/vm_file.rs` line 304

> ```diff
> +    fn start(&self) -> Result<i32> {
> +        let mut inner = self.try_lock_inner()?;
> +        ...
> +        match crate::vmm::start_framevm(config, self.control.clone(), self.task_group.clone()) {
> ```

Long lock hold across the whole start transaction (minor): `start()` holds the `VmInner` mutex across the entire VM start (ELF load, PCI claim, vCPU startup), while sibling ioctls deliberately use `try_lock_inner()` and an `EBUSY` contract. `memory_status()` and `dump_proc_fdinfo()` instead take a blocking `lock()`, so those calls stall for the whole multi-second transaction — an inconsistent locking contract that the next reader must rediscover.

**Fix.** Either snapshot the immutable draft fields before the long section and release the mutex during `start_framevm`, or make `memory_status`/`dump_proc_fdinfo` use `try_lock_inner()` with a documented fallback, so every ioctl follows one locking contract. Shared with the `vm_file.rs` line 589 comment in Correctness — same root cause: the `VmInner` locking contract is split between `try_lock` + `EBUSY` and blocking `lock()`.

### `kernel/core/src/device/misc/framevm/vm_file.rs` line 580

> ```diff
> +        let exit_code = if assigned_pci_failed { -5 } else { 0 };
> ```

`no-magic-number` (minor): The exit code `-5` for assigned-PCI failure is repeated as a bare literal here and in `kernel/core/src/vmm/mod.rs` (`set_pending_failure(-5)` and `complete_terminal_framevm_cleanup`'s `-5`), and it is user-visible through `FRAMEVM_GET_STATUS`'s `code` field, yet nothing names or documents it.

**Fix.** Introduce one named constant (e.g. `FRAMEVM_EXIT_ASSIGNED_DEVICE_FAILURE: i32 = -5`) in `framevm-abi` or `ioctl_defs`, use it at all three sites, and document the Host exit-code convention in the ABI doc.

## Correctness

### `kernel/comps/framevisor/src/lib.rs` line 93

> ```diff
> +        ::log::info!("[framevisor] Initializing FrameVisor subsystems...");
> ```

`ostd-log-only` (major): `framevisor` declares `log = { workspace = true }` and calls the third-party `::log::info!`/`::log::debug!` macros directly (also `vm/instance.rs:1071`). First-party kernel crates must use the OSTD logging macros (`host_ostd` re-exports here); the `log`-crate path only exists to bridge third-party code and skips the `__log_prefix` mechanism.

**Fix.** Drop the `log` dependency and route all host-side logging in `kernel/comps/framevisor` through the OSTD macros (e.g. `host_ostd::info!`), keeping the crate-internal `log` module only for the service facade if needed. Shared with the other logging comments on this branch (`kernel/core/src/init.rs` line 252, `kernel/core/src/device/misc/framevm/vm_file.rs` line 299, `ostd/src/loader/parser.rs` line 19).

### `kernel/comps/framevisor/src/pci.rs` line 535

> ```diff
> +    let size_mask = !(u64::try_from(bar.size).expect("validated BAR size fits u64") - 1);
> ```

Reachable panic via invariant-carrying expect (minor): `assigned_bar_probe_value` panics via `.expect("validated BAR size fits u64")` if the earlier BAR validation is ever violated. It is called from the guest-facing config-space emulation path, so a future validation regression turns into a Host kernel panic instead of an error.

**Fix.** Make the function fallible (return `Result<u32, ...>` mapped to a guest fault/ignore) or validate once at `AssignedBar` construction so the invariant is enforced where the data enters, keeping this path total.

### `kernel/core/src/device/misc/framevm/vm_file.rs` line 299

> ```diff
> +            error!("[FrameVM] VM fd operation lock is already held");
> ```

`log-prefix` (major): Log messages throughout the new code embed manual bracket prefixes — `[FrameVM]` (`vm_file.rs`, `vmm/mod.rs`, `assigned_pci_fault.rs`), `[framevisor]` (`framevisor/src/lib.rs`), `[Loader]` (`ostd/src/loader/*`), `[kernel]` (`init.rs`). The `__log_prefix` mechanism exists precisely to replace manual prefixes, so these double up the source tag and defeat uniform filtering.

**Fix.** Remove the bracket prefixes from the message strings and rely on `__log_prefix` (e.g. a `"framevm: "` prefix macro for the relevant module); keep the message text itself. Shared with the other logging comments on this branch (`kernel/core/src/init.rs` line 252, `kernel/comps/framevisor/src/lib.rs` line 93, `ostd/src/loader/parser.rs` line 19).

### `kernel/core/src/device/misc/framevm/vm_file.rs` line 589

> ```diff
> +    fn memory_status(&self) -> ioctl_defs::FrameVmMemoryStatus {
> +        let inner = self.inner.lock();
> ```

Inconsistent locking contract for status ioctls (nit): `memory_status()` takes `self.inner.lock()` (blocking) while all configuration ioctls use `try_lock_inner()` with `EBUSY`; during a concurrent `FRAMEVM_START` the memory-status ioctl therefore blocks indefinitely instead of returning the documented busy result. `dump_proc_fdinfo` has the same shape.

**Fix.** Use `try_lock_inner()` in `memory_status`/`dump_proc_fdinfo` and fall back to the draft's configured limits (the `None` arm already does exactly that) when the lock is contended. Shared with the `vm_file.rs` line 304 comment in Maintainability — same root cause: the `VmInner` locking contract is split between `try_lock` + `EBUSY` and blocking `lock()`.

### `kernel/core/src/init.rs` line 252

> ```diff
> +    ostd::early_println!("[kernel] kthread init: components");
> +    component::init_all(InitStage::Kthread, component::parse_metadata!()).unwrap();
> +    ostd::early_println!("[kernel] kthread init: work queue");
> ```

`ostd-log-only` (major): Added `ostd::early_println!("[kernel] kthread init: ...")` tracing in `init_in_first_kthread`. The early-boot exception does not apply here: by the first kthread the driver/console initialization has run, so the OSTD logger is available. These read like leftover boot-profiling scaffolding from the WIP commit, and they also bypass log-level filtering.

**Fix.** Delete these lines, or convert them to `debug!`/`info!` (with the crate's `__log_prefix`) if boot-stage tracing is genuinely wanted. Shared with the other logging comments on this branch (`kernel/comps/framevisor/src/lib.rs` line 93, `kernel/core/src/device/misc/framevm/vm_file.rs` line 299, `ostd/src/loader/parser.rs` line 19): one cleanup pass should route every new log site through the OSTD macros and the `__log_prefix` mechanism.

### `kernel/core/src/vmm/assigned_pci_fault.rs` line 114

> ```diff
> +        .unwrap_or_else(|error| {
> +            panic!(
> +                "unattributed Host DMA-remapping fault: source={:#06x}, ...",
> ```

Kernel panic on unattributable DMA-remapping fault (minor): `process_pending_faults` panics when a fault's requester cannot be quarantined (`unwrap_or_else(|error| panic!(...))` at line 111-119) and `contain_fault_record_overflow` asserts active assignments are non-empty (line 138). A work-item panic takes down the Host. Fail-stop may be the intended containment posture for a DMA source the kernel cannot attribute, but nothing states that policy where it happens.

**Fix.** Document the fail-stop decision in a comment (or the design doc) citing why an unattributable DMA fault must halt the Host, or degrade to quarantining all assigned groups plus `emerg!`-level logging if a safe fallback exists.

### `ostd/src/loader/parser.rs` line 19

> ```diff
> +    log::info!("[Loader] Loading service sections...");
> ```

`ostd-log-only` (major): The new OSTD loader logs through the third-party `log` crate (`log::info!` in `parser.rs`, `mod.rs:351,413,424,445`) instead of OSTD's own macros, unlike the rest of `ostd/src`.

**Fix.** Use the crate's own logging macros so loader messages go through the OSTD logger with the proper prefix and level filtering. Shared with the other logging comments on this branch (`kernel/core/src/init.rs` line 252, `kernel/comps/framevisor/src/lib.rs` line 93, `kernel/core/src/device/misc/framevm/vm_file.rs` line 299).

## Security

### `kernel/core/src/device/misc/framevm/mod.rs` line 52

> ```diff
> +    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
> +        // TODO: Reject non-`O_RDWR` opens with `EINVAL` once device `open`
> +        // callbacks receive the requested access mode.
> +        Ok(Box::new(controller::FrameVmControllerFile))
> +    }
> ```

`validate-at-boundaries` (minor): `FrameVmDevice::open` ignores the requested open flags (the `TODO` notes `O_RDWR` cannot be rejected yet), so the control device accepts any access mode. The device node is `u+rw`, which bounds practical exposure, but the open mode is the natural first validation point for a privileged control surface and the gap is only tracked in a code comment.

**Fix.** Extend the device `open` callback to receive the access mode (or filter in the misc-device layer) and reject non-`O_RDWR` opens with `EINVAL`, closing the boundary-validation gap the TODO records.

## Documentation

### `book/src/kernel/vm-based-containers/framevm.md` line 3

> ```diff
> +FrameVM exposes a Host-side control device at `/dev/framevm`. User space opens
> +this device to create an immutable-version VM draft, configures resources on
> +the returned VM file descriptor, and commits the draft with `FRAMEVM_START`.
> ```

`semantic-line-breaks` (major): The new book pages are hard-wrapped at a fixed width with mid-sentence breaks ("User space opens / this device to create..."), unlike the rest of `book/src`, which breaks prose at sentence/clause boundaries. `framevm-architecture.md` is additionally inconsistent, mixing 74 lines over 100 chars with wrapped paragraphs.

**Fix.** Reflow the prose in the five new `vm-based-containers` pages to semantic line breaks (one sentence or clause per line), matching the existing book convention.

### `book/src/kernel/vm-based-containers/framevm.md` line 41

> ```diff
> +| `FRAMEVM_GET_CONSOLE_FD` | `_IO` | `0x04` | VM fd | Returns an independent nonblocking console fd. |
> ```

`linux-compat-docs` (major): The ABI table documents `FRAMEVM_GET_CONSOLE_FD` as returning "an independent nonblocking console fd", but `FrameVmConsoleFile::new` builds the fd with `StatusFlags::empty()` — a blocking fd (`kernel/core/src/device/misc/framevm/console_file.rs:39`). A client that trusts the doc and reads the fd directly (without `poll`) can block indefinitely.

**Fix.** Pick one side of the contract and align the other: either create the console fd with `StatusFlags::O_NONBLOCK` to match the documented behavior, or change the doc to describe a blocking fd used with readiness polling (as `framevmm` does).

### `book/src/kernel/vm-based-containers/framevm.md` line 86

> ```diff
> +Version 1 supports only `device_id == 0`. `FRAMEVM_BLOCK_READ_ONLY` (`1 << 0`)
> +is the only flag.
> ```

`linux-compat-docs` (major): The `FRAMEVM_ADD_BLOCK` section says "Version 1 supports only `device_id == 0`", but the implementation accepts `device_id` 0..15 (`FRAMEVM_MAX_BLOCK_DEVICES = 16` with a contiguity check at start), and the shipped `framevmm` itself stages secondary drives with `device_id` 1+. The "Version 1" wording also collides with the management ABI being version 2.

**Fix.** Update the section to state the actual contract: up to 16 block devices, IDs must form a contiguous range starting at 0, checked atomically at `FRAMEVM_START`; drop the stale "Version 1" sentence.
