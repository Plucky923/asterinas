# FrameVM Service Check

`framevm-service-check` is the architecture gate for the FrameVM reference
service trim.

The final source classification is path based:

- `services/aster-framevm/src/lib.rs` and `src/init.rs` are entry-trim files.
- Every other Rust file under `services/aster-framevm/src/**` is retained
  kernel source and maps to `kernel/src/<same relative path>`.
- Rust files under `services/aster-framevm/src/service/**` are forbidden in the
  completed architecture.
- Service-local module aliases such as `scheduler`, `fd_table`, `fs_context`,
  and `rootfs` are forbidden once their behavior is migrated to kernel-shaped
  paths.
- Service-side trimmed comps under `services/aster-framevm/comps/<name>` map to
  `kernel/comps/<name>` unless they are FrameV frontend comps.

Intentional retained-source differences are recorded in
`trim-manifest.toml`. Entries are file-specific and use one of:
`entry-trim`, `unsupported-feature-trim`, `mechanical-adaptation`,
`provider-substitution`, or `test-only-or-doc`.

`source_trim_enforcement = "migration"` keeps the checker runnable while the
legacy service-local paths still exist. Switching to `"final"` makes those
final-architecture violations hard failures.
