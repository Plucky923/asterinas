# FrameVM Service Check

`framevm-service-check` is the architecture gate for the FrameVM reference
service trim.

## Upstream synchronization

`services/aster-framevm` is an independently editable downstream fork of
`kernel/core/src`. Its recorded main baseline is in
`services/aster-framevm/UPSTREAM.toml`. It is deliberately a source fork, not
a live path dependency: FrameVM needs VM-scoped OSTD, task, memory, and device
adaptations that must not change the Host kernel by accident.

Before changing the service, first verify that the fork is current:

```bash
tools/sync_framevm_from_main.sh --check
```

To carry a newer `main` revision into the fork, commit or stash the
service-tree work, then run:

```bash
tools/sync_framevm_from_main.sh --apply main
make framevm_service_check
```

The synchronizer performs a file-level three-way merge from the recorded base
to `main`. It leaves the working tree unchanged if any file conflicts, and it
advances `UPSTREAM.toml` only after all merges succeed. Both `make
framevm_service_check` and `cargo osdk framevm` run the synchronization check,
so a FrameVM object cannot be built against an out-of-date main baseline.

The final source classification is path based:

- `services/aster-framevm/src/lib.rs` and `src/init.rs` are entry-trim files.
- Every other Rust file under `services/aster-framevm/src/**` is retained
  kernel source and maps to `kernel/core/src/<same relative path>`.
- Rust files under `services/aster-framevm/src/service/**` are forbidden in the
  completed architecture.
- Service-local module aliases such as `scheduler`, `fd_table`, `fs_context`,
  and `rootfs` are forbidden once their behavior is migrated to kernel-shaped
  paths.
- Service-side trimmed comps under `services/aster-framevm/comps/<name>` map to
  `kernel/core/comps/<name>` unless they are FrameV frontend comps.

Intentional retained-source differences are recorded in
`trim-manifest.toml`. Entries are file-specific and use one of:
`entry-trim`, `unsupported-feature-trim`, `mechanical-adaptation`,
`provider-substitution`, or `test-only-or-doc`.

`source_trim_enforcement = "final"` makes final-architecture violations hard
failures. Use `"migration"` only while legacy service-local paths are still
being migrated.
