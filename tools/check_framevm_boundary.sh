#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
framevm_dir="$repo_root/kernel/comps/framevm"
framevm_src="$framevm_dir/src"
framevm_syscall_dir="$framevm_src/syscall"
framevm_manifest="$framevm_dir/Cargo.toml"
framevm_console_dir="$repo_root/kernel/comps/framevm-console"
framevm_console_manifest="$framevm_console_dir/Cargo.toml"
framevm_console_transport_dir="$repo_root/kernel/comps/framevm-console-transport"
framevm_console_transport_lib="$framevm_console_transport_dir/src/lib.rs"
framevm_service_srcs=("$framevm_src")
if [ -d "$framevm_console_dir/src" ]; then
    framevm_service_srcs+=("$framevm_console_dir/src")
fi
framevm_service_manifests=("$framevm_manifest")
if [ -f "$framevm_console_manifest" ]; then
    framevm_service_manifests+=("$framevm_console_manifest")
fi
framevisor_src="$repo_root/kernel/comps/framevisor/src"
framevisor_lib="$framevisor_src/lib.rs"
framevisor_manifest="$repo_root/kernel/comps/framevisor/Cargo.toml"
framevisor_service_domain="$framevisor_src/service_domain.rs"
framevisor_service_iht="$framevisor_src/service_iht.rs"
framevisor_task_scheduler="$framevisor_src/task/scheduler.rs"
framevisor_macros_src="$repo_root/kernel/comps/framevisor/macros/src"
framevisor_macros_lib="$framevisor_macros_src/lib.rs"
kernel_syscall_dir="$repo_root/kernel/src/syscall"
kernel_vmm_src="$repo_root/kernel/src/vmm/mod.rs"
exchangeable_src="$repo_root/kernel/comps/framevisor/exchangeable/src/lib.rs"
framevsock_ring_src="$repo_root/kernel/comps/framevsock/src/ring.rs"
framevsock_lib="$repo_root/kernel/comps/framevsock/src/lib.rs"
host_framevsock_dir="$repo_root/kernel/src/net/socket/framevsock"
host_framevsock_mod="$host_framevsock_dir/mod.rs"
host_framevsock_backend="$host_framevsock_dir/backend.rs"
initramfs_default_nix="$repo_root/test/initramfs/nix/default.nix"
initramfs_nix="$repo_root/test/initramfs/nix/initramfs.nix"
framevm_rootfs_image="$repo_root/test/initramfs/nix/framevm-rootfs-image.nix"
framevm_busybox_smoke_script="$repo_root/test/initramfs/src/framevm_busybox_smoke.sh"
framevm_obj="${FRAMEVM_OBJ_PATH:-$repo_root/build/framevm/framevm.o}"

require_safe_rust_crate() {
    local crate_name="$1"
    local crate_root="$2"
    local crate_src="$3"

    if ! grep -q '^#!\[deny(unsafe_code)\]' "$crate_root"; then
        echo "error: $crate_name must deny unsafe code at the crate root" >&2
        exit 1
    fi

    local unsafe_pattern='\bunsafe[[:space:]]*(\{|fn|trait|impl)'
    local matches
    if command -v rg >/dev/null 2>&1; then
        matches="$(rg -n "$unsafe_pattern" "$crate_src" || true)"
    else
        matches="$(grep -RInE "$unsafe_pattern" "$crate_src" || true)"
    fi

    if [ -n "$matches" ]; then
        echo "$matches"
        echo "error: $crate_name runtime code must stay pure safe Rust" >&2
        exit 1
    fi
}

require_no_low_level_runtime_escape() {
    local crate_name="$1"
    local crate_src="$2"
    local forbidden_pattern='asm!|global_asm!|extern[[:space:]]+"|#\[[^]]*(no_mangle|export_name|link_section)'
    local matches

    if command -v rg >/dev/null 2>&1; then
        matches="$(rg -n "$forbidden_pattern" "$crate_src" || true)"
    else
        matches="$(grep -RInE "$forbidden_pattern" "$crate_src" || true)"
    fi

    if [ -n "$matches" ]; then
        echo "$matches"
        echo "error: $crate_name runtime code must not use inline asm, FFI/linkage entrypoints, or custom link sections" >&2
        exit 1
    fi
}

require_ostd_surface_regex() {
    local framevisor_file="$1"
    local host_file="$2"
    local pattern="$3"
    local label="$4"

    local grep_args=(-Eq)
    if [ -d "$host_file" ]; then
        grep_args=(-REq)
    fi

    if ! grep "${grep_args[@]}" "$pattern" "$host_file"; then
        echo "error: Host OSTD is missing expected API shape for $label" >&2
        exit 1
    fi

    grep_args=(-Eq)
    if [ -d "$framevisor_file" ]; then
        grep_args=(-REq)
    fi

    if ! grep "${grep_args[@]}" "$pattern" "$framevisor_file"; then
        echo "error: FrameVisor OSTD-compatible surface changed API shape for $label" >&2
        exit 1
    fi
}

require_host_only_module() {
    local module="$1"

    if ! awk -v module="$module" '
        $0 == "#[cfg(feature = \"host-api\")]" {
            expect_host_public = 1
            expect_payload_private = 0
            next
        }
        $0 == "#[cfg(not(feature = \"host-api\"))]" {
            expect_payload_private = 1
            expect_host_public = 0
            next
        }
        expect_payload_private && $0 ~ /^#\[path[[:space:]]*=/ {
            next
        }
        expect_host_public && $0 == "pub mod " module ";" {
            found_host_public = 1
        }
        expect_payload_private && $0 == "mod " module ";" {
            found_payload_private = 1
        }
        {
            expect_host_public = 0
            expect_payload_private = 0
        }
        END {
            exit !(found_host_public && found_payload_private)
        }
    ' "$framevisor_lib"; then
        echo "error: FrameVisor module $module must be public only for host-api and private for service-payload" >&2
        exit 1
    fi
}

require_private_service_module_has_no_public_surface() {
    local module_file="$1"
    local module_label="$2"
    local matches
    local public_pattern='^pub[[:space:]]+(const|enum|fn|mod|static|struct|trait|type|use)[[:space:]]'

    if command -v rg >/dev/null 2>&1; then
        matches="$(rg -n "$public_pattern" "$module_file" || true)"
    else
        matches="$(grep -nE "$public_pattern" "$module_file" || true)"
    fi

    if [ -n "$matches" ]; then
        echo "$matches"
        echo "error: $module_label internals must stay crate-private and reachable only through OSTD-shaped APIs" >&2
        exit 1
    fi
}

syscall_file_is_explicitly_unsupported() {
    local syscall_file="$1"

    grep -q "Errno::ENOSYS" "$syscall_file" \
        && ! grep -Eq 'Ok[[:space:]]*\(|SyscallReturn::(Return|NoReturn)' "$syscall_file"
}

require_syscall_pattern_or_unsupported() {
    local syscall_file="$1"
    local pattern="$2"
    local message="$3"

    if grep -q "$pattern" "$syscall_file"; then
        return
    fi

    if syscall_file_is_explicitly_unsupported "$syscall_file"; then
        return
    fi

    echo "error: $message" >&2
    exit 1
}

require_syscall_patterns_or_unsupported() {
    local syscall_file="$1"
    local message="$2"
    shift 2

    local pattern
    for pattern in "$@"; do
        if ! grep -q "$pattern" "$syscall_file"; then
            if syscall_file_is_explicitly_unsupported "$syscall_file"; then
                return
            fi

            echo "error: $message" >&2
            exit 1
        fi
    done
}

require_no_successful_placeholder_syscalls() {
    local matches

    if command -v rg >/dev/null 2>&1; then
        matches="$(
            rg -l 'stub|placeholder|fake success|not implemented|unimplemented' \
                "$framevm_syscall_dir" \
                | while IFS= read -r syscall_file; do
                    if rg -q 'Ok[[:space:]]*\([[:space:]]*0[[:space:]]*\)|SyscallReturn::Return[[:space:]]*\([[:space:]]*0[[:space:]]*\)' "$syscall_file"; then
                        printf '%s\n' "$syscall_file"
                    fi
                done
        )"
    else
        matches="$(
            grep -RIlE 'stub|placeholder|fake success|not implemented|unimplemented' \
                "$framevm_syscall_dir" \
                | while IFS= read -r syscall_file; do
                    if grep -Eq 'Ok[[:space:]]*\([[:space:]]*0[[:space:]]*\)|SyscallReturn::Return[[:space:]]*\([[:space:]]*0[[:space:]]*\)' "$syscall_file"; then
                        printf '%s\n' "$syscall_file"
                    fi
                done
        )"
    fi

    if [ -n "$matches" ]; then
        echo "$matches"
        echo "error: FrameVM syscall placeholders must return ENOSYS/EOPNOTSUPP instead of success" >&2
        exit 1
    fi
}

require_service_scheduler_surface_matches_ostd() {
    if ! awk '
        /^pub trait Scheduler/ {
            in_scheduler = 1
            saw_scheduler = 1
            next
        }
        in_scheduler && /^}/ {
            in_scheduler = 0
            cfg_host_api = 0
            next
        }
        /^pub trait LocalRunQueue/ {
            in_local_rq = 1
            saw_local_rq = 1
            next
        }
        in_local_rq && /^}/ {
            in_local_rq = 0
            cfg_host_api = 0
            next
        }
        in_scheduler && /fn[[:space:]]+(local_rq_with_cpu|mut_local_rq_with_cpu)[[:space:]]*\(/ {
            print FILENAME ":" FNR ":" $0
            failed = 1
            next
        }
        in_local_rq && /fn[[:space:]]+ensure_current[[:space:]]*\(/ {
            print FILENAME ":" FNR ":" $0
            failed = 1
            next
        }
        END {
            if (!saw_scheduler || !saw_local_rq) {
                failed = 1
            }
            exit failed
        }
    ' "$framevisor_task_scheduler"; then
        echo "error: service-facing scheduler traits must match OSTD and must not add CPU-directed helper methods" >&2
        exit 1
    fi
}

require_no_framevm_object_leaks() {
    if [ "${FRAMEVM_CHECK_OBJECT:-0}" != "1" ] && [ ! -f "$framevm_obj" ]; then
        return
    fi

    if [ ! -f "$framevm_obj" ]; then
        echo "error: FrameVM dynamic object does not exist: $framevm_obj" >&2
        exit 1
    fi

    if ! command -v strings >/dev/null 2>&1; then
        echo "error: strings is required to check FrameVM dynamic object boundaries" >&2
        exit 1
    fi

    local forbidden_pattern='host_ostd|host-ostd|ostd::vm|ostd::iht|ostd::vsock|ostd::rref|aster_framevisor_exchangeable|aster-framevisor-exchangeable|RRef|RRefId|DomainId|Exchangeable|FrameTaskGroup|FrameTaskGroupId|VmId|Iht|IHT|FrameVisor|backend-api|host-api'
    local matches
    matches="$(strings "$framevm_obj" | grep -En "$forbidden_pattern" || true)"
    if [ -n "$matches" ]; then
        echo "$matches"
        echo "error: FrameVM dynamic object leaks FrameVisor host-private API names" >&2
        exit 1
    fi
}

require_framevsock_rref_is_backend_only() {
    if ! awk '
        /#\[cfg\(feature = "backend-api"\)\]/ {
            backend_api_budget = 40
            next
        }
        /^[[:space:]]*\/\// {
            next
        }
        /(^|[^[:alnum:]_])(RRef|RRefId|DomainId|Exchangeable)([^[:alnum:]_]|$)/ {
            if (backend_api_budget <= 0) {
                print FILENAME ":" FNR ":" $0
                failed = 1
            }
        }
        {
            if (backend_api_budget > 0) {
                backend_api_budget--
            }
        }
        END {
            exit failed
        }
    ' "$framevsock_lib"; then
        echo "error: service-visible FrameVsock API must not expose RRef/exchangeable types" >&2
        exit 1
    fi
}

require_framevm_has_no_rref_surface() {
    local forbidden_pattern='aster_framevisor::|aster_framevisor_|framevisor::|aster_framevisor_exchangeable|aster-framevisor-exchangeable|(^|[^[:alnum:]_])(RRef|RRefId|DomainId|Exchangeable)([^[:alnum:]_]|$)|exchangeable::|rref_registry'
    local matches

    if command -v rg >/dev/null 2>&1; then
        matches="$(rg -n "$forbidden_pattern" "${framevm_service_srcs[@]}" || true)"
    else
        matches="$(grep -RInE "$forbidden_pattern" "${framevm_service_srcs[@]}" || true)"
    fi

    if [ -n "$matches" ]; then
        echo "$matches"
        echo "error: FrameVM may use FrameVsock protocol APIs, but must not access RRef/exchangeable internals" >&2
        exit 1
    fi
}

require_console_transport_has_no_private_surface() {
    local forbidden_pattern='aster_framevisor::|aster_framevisor_|framevisor::|aster_framevisor_exchangeable|aster-framevisor-exchangeable|(^|[^[:alnum:]_])(RRef|RRefId|DomainId|Exchangeable)([^[:alnum:]_]|$)|FrameTaskGroup|FrameTaskGroupId|VmId|Iht|IHT|backend-api|host-api|host_api|ostd::vm|ostd::iht|ostd::vsock|ostd::rref|exchangeable::|rref_registry'
    local matches

    if command -v rg >/dev/null 2>&1; then
        matches="$(rg -n "$forbidden_pattern" "$framevm_console_transport_dir/src" || true)"
    else
        matches="$(grep -RInE "$forbidden_pattern" "$framevm_console_transport_dir/src" || true)"
    fi

    if [ -n "$matches" ]; then
        echo "$matches"
        echo "error: FrameVM console transport must not expose FrameVisor or RRef internals" >&2
        exit 1
    fi
}

require_safe_rust_crate "FrameVM" "$framevm_src/lib.rs" "$framevm_src"
require_safe_rust_crate "FrameVisor" "$framevisor_lib" "$framevisor_src"
require_safe_rust_crate "FrameVisor exchangeable" "$exchangeable_src" \
    "$repo_root/kernel/comps/framevisor/exchangeable/src"
require_safe_rust_crate "FrameVisor macros" "$framevisor_macros_lib" "$framevisor_macros_src"
require_no_low_level_runtime_escape "FrameVM" "$framevm_src"
require_no_low_level_runtime_escape "FrameVisor" "$framevisor_src"
require_no_low_level_runtime_escape "FrameVisor exchangeable" \
    "$repo_root/kernel/comps/framevisor/exchangeable/src"
require_no_successful_placeholder_syscalls
require_service_scheduler_surface_matches_ostd

recovery_api_pattern='handle_recovery|RecoveryContext|FaultRecovery|RecoveryHandler|pub[[:space:]]+trait[[:space:]]+.*Recovery|pub[[:space:]]+struct[[:space:]]+.*Recovery'
if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$recovery_api_pattern" "$framevm_src" "$framevisor_src" || true)"
else
    matches="$(grep -RInE "$recovery_api_pattern" "$framevm_src" "$framevisor_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM/FrameVisor first phase must not expose fault-recovery APIs" >&2
    exit 1
fi

if [ -d "$framevm_console_dir/src" ]; then
    require_safe_rust_crate "FrameVM console facade" \
        "$framevm_console_dir/src/lib.rs" "$framevm_console_dir/src"
    require_no_low_level_runtime_escape "FrameVM console facade" "$framevm_console_dir/src"
fi
if [ -d "$repo_root/kernel/comps/framevm-console-transport/src" ]; then
    require_safe_rust_crate "FrameVM console transport" \
        "$repo_root/kernel/comps/framevm-console-transport/src/lib.rs" \
        "$repo_root/kernel/comps/framevm-console-transport/src"
    require_no_low_level_runtime_escape "FrameVM console transport" \
        "$repo_root/kernel/comps/framevm-console-transport/src"
fi

service_public_modules="$(
    awk '
        $0 ~ /#\[cfg\(not\(feature = "host-api"\)\)\]/ { host_api_next = 0; next }
        $0 ~ /#\[cfg\(.*feature = "host-api"/ { host_api_next = 1; next }
        $0 ~ /^#\[/ { next }
        $0 ~ /^pub[[:space:]]+mod[[:space:]]+[[:alnum:]_]+;/ && !host_api_next {
            module = $0
            sub(/^pub[[:space:]]+mod[[:space:]]+/, "", module)
            sub(/;.*/, "", module)
            print module
        }
        { host_api_next = 0 }
    ' "$framevisor_lib"
)"

service_allowed_modules='arch boot console cpu irq log mm panic power prelude sync task timer user util'

for service_module in $service_public_modules; do
    if ! printf '%s\n' $service_allowed_modules | grep -qx "$service_module"; then
        echo "error: service-facing ostd::$service_module is outside the approved OSTD-like root module surface" >&2
        exit 1
    fi
done

for required_service_module in $service_allowed_modules; do
    if ! printf '%s\n' $service_public_modules | grep -qx "$required_service_module"; then
        echo "error: service-facing ostd::$required_service_module disappeared from the approved OSTD-like root module surface" >&2
        exit 1
    fi
done

host_public_modules="$(
    awk '
        $0 ~ /^pub[[:space:]]+mod[[:space:]]+[[:alnum:]_]+;/ {
            module = $0
            sub(/^pub[[:space:]]+mod[[:space:]]+/, "", module)
            sub(/;.*/, "", module)
            print module
        }
    ' "$repo_root/ostd/src/lib.rs"
)"

for service_module in $service_public_modules; do
    if ! echo "$host_public_modules" | grep -qx "$service_module"; then
        echo "error: service-facing ostd::$service_module is not a Host OSTD root module" >&2
        exit 1
    fi
done

if ! grep -Eq 'ostd[[:space:]]*=[[:space:]]*\{[^}]*package[[:space:]]*=[[:space:]]*"aster-framevisor"' "$framevm_manifest"; then
    echo "error: FrameVM must bind FrameVisor through the ostd crate name" >&2
    exit 1
fi

if ! grep -Eq 'ostd[[:space:]]*=[[:space:]]*\{[^}]*path[[:space:]]*=[[:space:]]*"\.\.\/framevisor"' "$framevm_manifest"; then
    echo "error: FrameVM ostd binding must come from the FrameVisor package" >&2
    exit 1
fi

if ! grep -Eq 'ostd[[:space:]]*=[[:space:]]*\{[^}]*default-features[[:space:]]*=[[:space:]]*false' "$framevm_manifest"; then
    echo "error: FrameVM ostd binding must disable FrameVisor default features" >&2
    exit 1
fi

if ! grep -Eq 'ostd[[:space:]]*=[[:space:]]*\{[^}]*features[[:space:]]*=[[:space:]]*\[[[:space:]]*"service-payload"[[:space:]]*\]' "$framevm_manifest"; then
    echo "error: FrameVM ostd binding must select only FrameVisor service-payload mode" >&2
    exit 1
fi

if awk '
    /^\[lib\]/ { in_lib = 1; next }
    /^\[/ { in_lib = 0 }
    in_lib && /^name[[:space:]]*=[[:space:]]*"ostd"/ { found = 1 }
    END { exit found == 1 ? 0 : 1 }
' "$framevisor_manifest"; then
    echo "error: do not hide FrameVisor by renaming its library crate to ostd; this creates two dynamic OSTD symbol namespaces" >&2
    exit 1
fi

if grep -Eq '^aster-console[[:space:]]*=' "$framevm_manifest" \
    && ! grep -Eq '^aster-console[[:space:]]*=[[:space:]]*\{[^\n]*package[[:space:]]*=[[:space:]]*"aster-console-service"' "$framevm_manifest"; then
    echo "error: FrameVM must bind aster-console to the virtual console facade, not the host component" >&2
    exit 1
fi

if grep -Eq '^(aster-framevisor|aster-framevisor-exchangeable|aster-framevisor-macros|framevisor)[[:space:]]*=' "$framevm_manifest"; then
    echo "error: FrameVM must not depend on FrameVisor internals outside the ostd crate binding" >&2
    exit 1
fi

for service_manifest in "${framevm_service_manifests[@]}"; do
    if grep -Eq 'aster-framevisor-exchangeable|package[[:space:]]*=[[:space:]]*"aster-framevisor-exchangeable"|framevisor/exchangeable' "$service_manifest"; then
        echo "error: FrameVM service-side manifest $service_manifest must not depend on RRef/exchangeable internals" >&2
        exit 1
    fi

    if grep -q 'host-api' "$service_manifest"; then
        echo "error: FrameVM service-side manifest $service_manifest must not enable FrameVisor host-api" >&2
        exit 1
    fi

    if grep -Eq '^[[:space:]]*(host-api|host_api|guest-payload|guest_payload|service-payload|service_payload)[[:space:]]*=' "$service_manifest"; then
        echo "error: FrameVM service-side manifest $service_manifest must not define implementation-mode features" >&2
        exit 1
    fi

    if grep -q 'ostd/' "$service_manifest"; then
        echo "error: FrameVM service-side manifest $service_manifest must not select OSTD implementation features" >&2
        exit 1
    fi

    ostd_dependency="$(
        awk '
            /^\[dependencies\.ostd\]/ { in_ostd = 1; next }
            /^\[/ { in_ostd = 0 }
            in_ostd || /^ostd[[:space:]]*=/
        ' "$service_manifest"
    )"

    if ! echo "$ostd_dependency" | grep -q 'package[[:space:]]*=[[:space:]]*"aster-framevisor"'; then
        echo "error: FrameVM service-side manifest $service_manifest must bind ostd to the FrameVisor package" >&2
        exit 1
    fi

    if ! echo "$ostd_dependency" | grep -q 'default-features[[:space:]]*=[[:space:]]*false'; then
        echo "error: FrameVM service-side manifest $service_manifest must disable FrameVisor default features on ostd" >&2
        exit 1
    fi

    if ! echo "$ostd_dependency" | grep -q 'features[[:space:]]*=[[:space:]]*\[[[:space:]]*"service-payload"[[:space:]]*\]'; then
        echo "error: FrameVM service-side manifest $service_manifest must select only FrameVisor service-payload mode on ostd" >&2
        exit 1
    fi

    if echo "$ostd_dependency" | grep -q 'host-api'; then
        echo "error: FrameVM service-side manifest $service_manifest must not enable FrameVisor host-api" >&2
        exit 1
    fi

    framevsock_dependency="$(
        awk '
            /^\[dependencies\.aster-framevsock\]/ || /^\[dependencies\.framevsock\]/ { in_framevsock = 1; next }
            /^\[/ { in_framevsock = 0 }
            in_framevsock || /^(aster-framevsock|framevsock)[[:space:]]*=/
        ' "$service_manifest"
    )"

    if echo "$framevsock_dependency" | grep -q 'backend-api'; then
        echo "error: FrameVM may use FrameVsock only through the service-safe API, not backend-api/RRef APIs" >&2
        exit 1
    fi

    if grep -Eq '^[[:space:]]*spin[[:space:]]*=' "$service_manifest" \
        || grep -Eq '^\[dependencies\.spin\]' "$service_manifest"; then
        echo "error: FrameVM service-side manifest $service_manifest must use ostd::sync instead of depending on spin directly" >&2
        exit 1
    fi
done

if ! grep -q 'aster-framevsock = { workspace = true }' "$framevm_manifest" \
    || ! grep -q 'HOST_CID as VSOCK_HOST_CID' "$framevm_src/net/socket/vsock/addr.rs" \
    || ! grep -q 'VMADDR_CID_ANY as VSOCK_CID_ANY' "$framevm_src/net/socket/vsock/addr.rs" \
    || ! grep -q 'VMADDR_PORT_ANY as VSOCK_PORT_ANY' "$framevm_src/net/socket/vsock/addr.rs"; then
    echo "error: FrameVM vsock must use the service-safe FrameVsock protocol constants without backend/RRef access" >&2
    exit 1
fi

if command -v cargo >/dev/null 2>&1; then
    framevsock_default_tree="$(
        cargo tree -q -p aster-framevsock --target x86_64-unknown-none \
            -e normal 2>/dev/null || true
    )"
    if echo "$framevsock_default_tree" \
        | grep -Eq '(^|[[:space:]])(exchangeable|ostd)[[:space:]]+v'; then
        echo "$framevsock_default_tree" | grep -E '(exchangeable|ostd)' >&2
        echo "error: service-safe aster-framevsock default build must not depend on exchangeable/RRef or Host OSTD" >&2
        exit 1
    fi

    framevm_framevsock_features="$(
        cargo tree -q -p aster-framevm --target x86_64-unknown-none \
            -e features -i aster-framevsock 2>/dev/null || true
    )"
    if echo "$framevm_framevsock_features" | grep -q 'backend-api'; then
        echo "$framevm_framevsock_features"
        echo "error: FrameVM dynamic build must not enable aster-framevsock/backend-api" >&2
        exit 1
    fi

    framevm_dependency_tree="$(
        cargo tree -q -p aster-framevm --target x86_64-unknown-none \
            -e normal 2>/dev/null || true
    )"
    if echo "$framevm_dependency_tree" \
        | grep -Eq '(^|[[:space:]])(aster-framevisor-exchangeable|exchangeable)[[:space:]]+v'; then
        echo "$framevm_dependency_tree" \
            | grep -E '(aster-framevisor-exchangeable|exchangeable)' >&2
        echo "error: FrameVM must not depend on RRef/exchangeable internals" >&2
        exit 1
    fi

    if echo "$framevm_dependency_tree" | grep -Eq '(^|[[:space:]])aster-console[[:space:]]+v'; then
        echo "$framevm_dependency_tree" | grep -E '(^|[[:space:]])aster-console[[:space:]]+v' >&2
        echo "error: FrameVM dynamic build must use the service console facade, not the host console component" >&2
        exit 1
    fi

    framevm_framevisor_features="$(
        cargo tree -q -p aster-framevm --target x86_64-unknown-none \
            -e features -i aster-framevisor 2>/dev/null || true
    )"
    if echo "$framevm_framevisor_features" | grep -Eq '"host-api"|host-api'; then
        echo "$framevm_framevisor_features" | grep -E 'host-api' >&2
        echo "error: FrameVM dynamic build must not enable FrameVisor host-api" >&2
        exit 1
    fi
    if ! echo "$framevm_framevisor_features" | grep -Eq '"service-payload"|service-payload'; then
        echo "$framevm_framevisor_features" >&2
        echo "error: FrameVM dynamic build must enable FrameVisor service-payload mode" >&2
        exit 1
    fi
fi

for backend_module in notify ring trace tuning; do
    if ! grep -B1 "^pub mod $backend_module;" "$framevsock_lib" \
        | grep -q '#\[cfg(feature = "backend-api")\]'; then
        echo "error: aster-framevsock::$backend_module must be backend-api only" >&2
        exit 1
    fi
done

require_framevsock_rref_is_backend_only

require_framevm_has_no_rref_surface

if ! awk '
    /^#\[cfg\(feature = "backend-api"\)\]/ {
        backend_api_budget = 32
        next
    }
    /^pub[[:space:]]+(fn|type|struct|enum|trait|const)[[:space:]].*RRef/ ||
    /^\)[[:space:]]*->[[:space:]]*RRef/ {
        if (backend_api_budget <= 0) {
            print FILENAME ":" FNR ":" $0
            failed = 1
        }
    }
    {
        if (backend_api_budget > 0) {
            backend_api_budget--
        }
    }
    END {
        exit failed
    }
' "$framevsock_lib"; then
    echo "error: service-visible FrameVsock API must not expose RRef transfer types" >&2
    exit 1
fi

if ! grep -q 'crate::net::socket::vsock' "$host_framevsock_mod" \
    || ! grep -q 'backend is the only carrier-specific' "$host_framevsock_mod" \
    || ! grep -q 'Linux socket or syscall semantics' "$host_framevsock_mod"; then
    echo "error: host FrameVsock must document that it follows virtio-vsock and keeps carrier differences in the backend" >&2
    exit 1
fi

if ! grep -q 'DEFAULT_CONNECT_TIMEOUT: Duration' "$repo_root/kernel/src/net/socket/framevsock/transport/mod.rs" \
    || ! grep -q 'Duration::from_secs(2)' "$repo_root/kernel/src/net/socket/framevsock/transport/mod.rs" \
    || ! grep -q 'MAX_BACKLOG: usize = 4096' "$repo_root/kernel/src/net/socket/framevsock/transport/mod.rs" \
    || ! grep -q 'Poller::new(Some(&DEFAULT_CONNECT_TIMEOUT))' "$repo_root/kernel/src/net/socket/framevsock/stream/socket.rs" \
    || ! grep -q 'backlog.min(MAX_BACKLOG)' "$repo_root/kernel/src/net/socket/framevsock/transport/listener.rs"; then
    echo "error: host FrameVsock must preserve kernel vsock connect timeout and listen backlog semantics" >&2
    exit 1
fi

if ! grep -q 'self.pollee.notify(IoEvents::OUT)' "$repo_root/kernel/src/net/socket/framevsock/stream/connecting.rs" \
    || ! grep -q 'IoEvents::OUT | IoEvents::ERR | IoEvents::HUP' "$repo_root/kernel/src/net/socket/framevsock/stream/connecting.rs" \
    || ! grep -q 'IoEvents::OUT' "$repo_root/kernel/src/net/socket/framevsock/stream/init.rs"; then
    echo "error: host FrameVsock poll readiness must follow kernel vsock OUT readiness for init/connect completion" >&2
    exit 1
fi

framevsock_connection_dir="$repo_root/kernel/src/net/socket/framevsock/transport/connection"
if grep -R -q 'local_shutdown' "$framevsock_connection_dir" \
    || ! grep -q 'local_read_shutdown' "$framevsock_connection_dir/mod.rs" \
    || ! grep -q 'local_write_shutdown' "$framevsock_connection_dir/mod.rs" \
    || ! grep -q 'cmd.shut_read()' "$framevsock_connection_dir/shutdown.rs" \
    || ! grep -q 'cmd.shut_write()' "$framevsock_connection_dir/shutdown.rs" \
    || ! grep -q 'Errno::EPIPE' "$framevsock_connection_dir/send.rs"; then
    echo "error: host FrameVsock shutdown must preserve kernel vsock read/write half-close semantics" >&2
    exit 1
fi

if grep -q 'let _ = connected.reset();' "$repo_root/kernel/src/net/socket/framevsock/stream/socket.rs" \
    || ! grep -q 'connected.shutdown(SockShutdownCmd::SHUT_RDWR)' "$repo_root/kernel/src/net/socket/framevsock/stream/socket.rs" \
    || ! grep -q 'let should_remove = connected.on_shutdown_received' "$repo_root/kernel/src/net/socket/framevsock/transport/space.rs" \
    || ! grep -q 'self.remove_connected_socket(&conn_id);' "$repo_root/kernel/src/net/socket/framevsock/transport/space.rs" \
    || ! grep -q 'self.send_rst_to_guest(dst_addr, src_addr);' "$repo_root/kernel/src/net/socket/framevsock/transport/space.rs"; then
    echo "error: host FrameVsock close/drop must follow kernel vsock shutdown-and-remove lifecycle, not reset normal closes" >&2
    exit 1
fi

if grep -Eq 'fn[[:space:]]+(connect|accept|sendmsg|recvmsg|bind|listen)[[:space:]]*\(|FileDesc|RawFileDesc|SyscallReturn|syscall::' \
    "$host_framevsock_backend"; then
    echo "error: host FrameVsock backend must not contain Linux socket, fd, or syscall semantics" >&2
    exit 1
fi

for host_only_module in iht; do
    require_host_only_module "$host_only_module"
done

require_private_service_module_has_no_public_surface \
    "$framevisor_service_iht" "service-payload IHT"
require_private_service_module_has_no_public_surface \
    "$framevisor_service_domain" "service-payload execution-domain"

if ! grep -B1 -E '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+vm[[:space:]]*;' "$framevisor_lib" \
    | grep -q '#\[cfg(feature = "host-api")\]' \
    || grep -Eq '^[[:space:]]*mod[[:space:]]+vm[[:space:]]*;' "$framevisor_lib"; then
    echo "error: FrameVisor vm internals must be host-api only and absent from service-payload" >&2
    exit 1
fi

require_no_framevm_object_leaks

require_console_transport_has_no_private_surface

if grep -Eq '^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+vsock[[:space:]]*;' "$framevisor_lib" \
    && ! grep -B1 -E '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+vsock[[:space:]]*;' "$framevisor_lib" \
        | grep -q '#\[cfg(feature = "host-api")\]'; then
    echo "error: FrameVisor vsock backend must be host-api only and must not enter the service-facing OSTD facade" >&2
    exit 1
fi

if grep -B1 -E '^[[:space:]]*mod[[:space:]]+vsock[[:space:]]*;' "$framevisor_lib" \
    | grep -q '#\[cfg(not(feature = "host-api"))\]'; then
    echo "error: FrameVisor vsock backend must not compile privately into the service-payload OSTD facade" >&2
    exit 1
fi

if grep -Eq 'public service-facing API|Service-visible socket transport surface' \
    "$repo_root/kernel/comps/framevisor/src/vsock/mod.rs"; then
    echo "error: FrameVisor vsock RRef transport must be documented as host-only, not service-visible" >&2
    exit 1
fi

if ! grep -Eq 'Host-private dynamic transport relay|host-only dynamic transport relay' \
    "$repo_root/kernel/comps/framevisor/src/vsock/mod.rs"; then
    echo "error: FrameVisor vsock transport docs must preserve the host-only boundary" >&2
    exit 1
fi

if grep -Eq '(^|[[:space:]])pub[[:space:]]+mod[[:space:]]+console_transport[[:space:]]*;' "$framevisor_lib"; then
    echo "error: FrameVisor must not expose console_transport through the OSTD-compatible service surface" >&2
    exit 1
fi

if grep -q 'host-api' "$framevm_manifest"; then
    echo "error: FrameVM must not enable FrameVisor host-api" >&2
    exit 1
fi

if grep -Eq '^[[:space:]]*(host-api|host_api|guest-payload|guest_payload|service-payload|service_payload)[[:space:]]*=' "$framevm_manifest"; then
    echo "error: FrameVM must not define implementation-mode features; it only sees the ostd crate binding" >&2
    exit 1
fi

if grep -q 'ostd/' "$framevm_manifest"; then
    echo "error: FrameVM features must not select FrameVisor or Host OSTD implementation features" >&2
    exit 1
fi

ostd_dependency="$(
    awk '
        /^\[dependencies\.ostd\]/ { in_ostd = 1; next }
        /^\[/ { in_ostd = 0 }
        in_ostd || /^ostd[[:space:]]*=/
    ' "$framevm_manifest"
)"

if ! echo "$ostd_dependency" | grep -q 'package[[:space:]]*=[[:space:]]*"aster-framevisor"'; then
    echo "error: FrameVM must bind ostd to the FrameVisor package" >&2
    exit 1
fi

if ! echo "$ostd_dependency" | grep -q 'features[[:space:]]*=[[:space:]]*\[[[:space:]]*"service-payload"[[:space:]]*\]'; then
    echo "error: FrameVM must select FrameVisor service-payload mode on the ostd binding" >&2
    exit 1
fi

if echo "$ostd_dependency" | grep -q 'host-api'; then
    echo "error: FrameVM must not enable FrameVisor host-api" >&2
    exit 1
fi

if awk '
    /^\[features\]/ { in_features = 1; next }
    /^\[/ { in_features = 0 }
    in_features && /^default[[:space:]]*=/ && /host-api|backend-api|aster-framevsock|aster-framevisor-exchangeable/ { bad = 1 }
    END { exit bad ? 0 : 1 }
' "$framevisor_manifest"; then
    echo "error: FrameVisor default features must not expose host/RRef/FrameVsock backend APIs to service builds" >&2
    exit 1
fi

if ! grep -q 'aster-framevisor-macros = { workspace = true }' "$framevisor_manifest"; then
    echo "error: the service-facing OSTD provider must expose #[ostd::main] through the OSTD service macro crate" >&2
    exit 1
fi

if grep -q '^libflate[[:space:]]*=' "$framevm_manifest"; then
    echo "error: FrameVM rootfs gzip decoding must stay in the host artifact loader" >&2
    exit 1
fi

if ! grep -q 'framevm-rootfs-image = pkgs.callPackage ./framevm-rootfs-image.nix' \
        "$initramfs_default_nix" \
    || ! grep -q 'framevmRootfs = framevm-rootfs-image' "$initramfs_default_nix" \
    || ! grep -q 'install -Dm644 ${framevmRootfs} $out/framevm/rootfs.cpio.gz' \
        "$initramfs_nix"; then
    echo "error: initramfs must install an independent FrameVM BusyBox rootfs artifact" >&2
    exit 1
fi

if ! grep -q 'open_framevm_artifact("/framevm/rootfs.cpio.gz")' "$kernel_vmm_src" \
    || ! grep -q 'open_framevm_artifact("/framevm/rootfs.cpio")' "$kernel_vmm_src" \
    || ! grep -q 'decode_framevm_rootfs(rootfs_data)' "$kernel_vmm_src" \
    || ! grep -q 'GZipDecoder::new(rootfs_data.as_slice())' "$kernel_vmm_src" \
    || ! grep -q 'boot::set_boot_info_with_extra(rootfs_data' "$kernel_vmm_src"; then
    echo "error: host loader must read FrameVM rootfs from /framevm and inject decoded cpio bytes through BootInfo" >&2
    exit 1
fi

if ! grep -q 'RootFs::install_from_boot_info()' "$framevm_src/lib.rs" \
    || ! grep -q 'ostd::boot::boot_info()' "$framevm_src/rootfs.rs" \
    || ! grep -q '\.initramfs' "$framevm_src/rootfs.rs" \
    || ! grep -q 'Self::from_cpio_image(initramfs)' "$framevm_src/rootfs.rs"; then
    echo "error: FrameVM must install its own rootfs from the virtual OSTD BootInfo initramfs" >&2
    exit 1
fi

if ! grep -q 'fn sync_data(&self) -> Result<()> {' "$repo_root/kernel/comps/framevm/src/fd_table.rs" \
    || ! grep -q 'file.sync_data()?' "$repo_root/kernel/comps/framevm/src/syscall/fsync.rs"; then
    echo "error: FrameVM fdatasync must dispatch through a file data-sync operation, matching kernel syscall shape" >&2
    exit 1
fi

if ! grep -q 'const IOV_MAX: usize = 1024' "$framevm_src/syscall/write.rs" \
    || ! grep -q 'current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?' "$framevm_src/syscall/write.rs" \
    || ! grep -q 'checked_mul(IOV_ENTRY_SIZE)' "$framevm_src/syscall/write.rs" \
    || ! grep -q 'total_len > isize::MAX as usize' "$framevm_src/syscall/write.rs" \
    || ! grep -q 'Err(_) if total > 0 => break' "$framevm_src/syscall/write.rs" \
    || ! grep -q 'write_len < buffer.len()' "$framevm_src/syscall/write.rs"; then
    echo "error: FrameVM writev must keep kernel-compatible iovec validation and partial-write behavior" >&2
    exit 1
fi

if ! grep -q 'EMSGSIZE = 90' "$framevm_src/error.rs" \
    || ! grep -q 'Errno::EMSGSIZE' "$framevm_src/syscall/sendmsg.rs" \
    || ! grep -q 'Errno::EMSGSIZE' "$framevm_src/syscall/recvmsg.rs" \
    || ! grep -q 'checked_mul(IOV_ENTRY_SIZE)' "$framevm_src/syscall/sendmsg.rs" \
    || [ "$(grep -c 'checked_mul(IOV_ENTRY_SIZE)' "$framevm_src/syscall/recvmsg.rs")" -lt 2 ]; then
    echo "error: FrameVM sendmsg/recvmsg must keep kernel-compatible iovec limit errno and checked address calculation" >&2
    exit 1
fi

if ! grep -q 'Self::from_bits_truncate(bits)' "$framevm_src/net/socket/mod.rs"; then
    echo "error: FrameVM socket send/recv flag parsing must truncate unknown bits like the kernel syscall layer" >&2
    exit 1
fi

if ! grep -q 'process_resource_limits_for_pid' "$framevm_src/task.rs" \
    || ! grep -q 'pid == 0 || pid == current_process.pid() as usize' "$framevm_src/syscall/prlimit64.rs" \
    || ! grep -q 'task::process_resource_limits_for_pid(pid)' "$framevm_src/syscall/prlimit64.rs" \
    || ! grep -q 'fn check_rlimit_perm' "$framevm_src/syscall/prlimit64.rs" \
    || grep -q 'pid != 0 && pid != current_user_tid' "$framevm_src/syscall/prlimit64.rs"; then
    echo "error: FrameVM prlimit64 must target process IDs and check permissions like the kernel syscall layer" >&2
    exit 1
fi

if ! grep -q 'fn owner_pid_from_arg' "$framevm_src/syscall/fcntl.rs" \
    || ! grep -q 'set_owner(owner_pid)' "$framevm_src/syscall/fcntl.rs" \
    || ! grep -q 'owner().unwrap_or(0)' "$framevm_src/syscall/fcntl.rs" \
    || ! grep -q 'owner: AtomicU32' "$framevm_src/fd_table.rs" \
    || grep -q 'owner: AtomicI32' "$framevm_src/fd_table.rs"; then
    echo "error: FrameVM fcntl F_SETOWN/F_GETOWN must store owner process IDs like the kernel file table" >&2
    exit 1
fi

if ! grep -q 'nofile_limit: u64' "$framevm_src/fd_table.rs" \
    || ! grep -q 'next_available_fd(ceil_fd, nofile_limit)' "$framevm_src/fd_table.rs" \
    || grep -q 'next_available_fd_unbounded' "$framevm_src/fd_table.rs" \
    || ! grep -q 'current_nofile_limit()?' "$framevm_src/syscall/dup.rs" \
    || ! grep -q 'current_nofile_limit()?' "$framevm_src/syscall/fcntl.rs"; then
    echo "error: FrameVM dup/F_DUPFD paths must enforce RLIMIT_NOFILE during fd allocation" >&2
    exit 1
fi

if ! grep -q '!self.permitted_capset.contains(permitted)' "$framevm_src/process.rs" \
    || ! grep -q '!permitted.contains(effective)' "$framevm_src/process.rs" \
    || ! grep -q 'capability(CAP_SETPCAP)' "$framevm_src/process.rs" \
    || ! grep -q 'union(self.bounding_capset)' "$framevm_src/process.rs" \
    || ! grep -q 'credentials.set_capsets(capsets.permitted, capsets.effective, capsets.inheritable)' \
        "$framevm_src/syscall/capset.rs"; then
    echo "error: FrameVM capset must preserve kernel capability containment and CAP_SETPCAP checks" >&2
    exit 1
fi

if ! grep -q 'fn validate_tmpfile_flags' "$repo_root/kernel/comps/framevm/src/syscall/open.rs" \
    || ! grep -q 'creation_flags.contains(CreationFlags::O_TMPFILE)' "$repo_root/kernel/comps/framevm/src/syscall/open.rs" \
    || ! grep -q 'status_flags.contains(StatusFlags::O_PATH)' "$repo_root/kernel/comps/framevm/src/syscall/open.rs"; then
    echo "error: FrameVM open must validate O_TMPFILE flags before returning unsupported, matching kernel OpenArgs shape" >&2
    exit 1
fi

if ! grep -q 'flags & StatusFlags::O_DIRECT.bits() != 0' "$repo_root/kernel/comps/framevm/src/syscall/pipe.rs"; then
    echo "error: FrameVM pipe2 must reject unsupported O_DIRECT packet mode like the kernel pipe implementation" >&2
    exit 1
fi

if ! grep -q 'fn check_pipe_status_flags' "$repo_root/kernel/comps/framevm/src/fd_table.rs" \
    || ! grep -q 'status_flags.contains(StatusFlags::O_DIRECT)' "$repo_root/kernel/comps/framevm/src/fd_table.rs"; then
    echo "error: FrameVM pipe file objects must reject unsupported O_DIRECT status updates like the kernel pipe implementation" >&2
    exit 1
fi

if ! grep -q 'fn sanitize_signal_action_flags' "$repo_root/kernel/comps/framevm/src/signal.rs" \
    || ! grep -q 'sanitize_signal_action_flags(read_u32_from_user' "$repo_root/kernel/comps/framevm/src/syscall/signal_sys.rs"; then
    echo "error: FrameVM rt_sigaction must discard unknown action flags like kernel SigActionFlags::from_bits_truncate" >&2
    exit 1
fi

if grep -Eq 'pub[[:space:]]+fn[[:space:]]+(read|write|acquire_input|release_input|has_input|clear_input|is_active)\b' \
    "$repo_root/ostd/src/console/mod.rs"; then
    echo "error: Host OSTD console must not grow service-only FrameVM console APIs" >&2
    exit 1
fi

for console_api in clear_output_log output_log_snapshot; do
    if grep -q "^pub fn $console_api" "$framevisor_src/console.rs" \
        && ! grep -B1 "^pub fn $console_api" "$framevisor_src/console.rs" \
            | grep -q '#\[cfg(feature = "host-api")\]'; then
        echo "error: FrameVisor console::$console_api must stay host-api only" >&2
        exit 1
    fi
done

if grep -q '^\[\[bin\]\]' "$framevm_manifest" || [ -e "$framevm_dir/src/main.rs" ]; then
    echo "error: FrameVM must be built only as a dynamically loaded library image" >&2
    exit 1
fi

if ! grep -q 'cargo rustc -p aster-framevm --lib' "$repo_root/Makefile" \
    || grep -Eq 'cargo (build|rustc) --workspace.*aster-framevm|cargo (build|rustc).*-p aster-kernel.*aster-framevm' "$repo_root/Makefile"; then
    echo "error: make framevm must build FrameVM as an isolated dynamic library package" >&2
    exit 1
fi

if ! grep -q '^ENABLE_KVM ?= 1' "$repo_root/Makefile" \
    || ! grep -q -- '--qemu-args="-accel kvm"' "$repo_root/Makefile"; then
    echo "error: make framevm must default to KVM acceleration on x86_64" >&2
    exit 1
fi

if ! grep -q '^framevm: CONSOLE = ttyS0' "$repo_root/Makefile" \
    || ! grep -q 'STDIO_SERIAL_ONLY=on cargo osdk run $(CARGO_OSDK_BUILD_ARGS)' "$repo_root/Makefile" \
    || ! grep -q 'Start FrameVM from Asterinas with: echo 1 > /proc/framevm' "$repo_root/Makefile" \
    || ! grep -q -- '--init-args="--no-script $(FRAMEVM_INTERACTIVE_INIT)"' "$repo_root/Makefile"; then
    echo "error: make framevm must boot Asterinas first and leave serial stdio for /proc/framevm-driven FrameVM" >&2
    exit 1
fi

matches="$(
    find "$repo_root/kernel" -name Cargo.toml ! -path "$framevm_manifest" -print0 \
        | xargs -0 grep -nE '^[[:space:]]*(aster-framevm|framevm)[[:space:]]*=|^\[dependencies\.(aster-framevm|framevm)\]|package[[:space:]]*=[[:space:]]*"aster-framevm"' \
        || true
)"

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: host kernel crates must not statically depend on FrameVM; load /framevm/framevm.o dynamically" >&2
    exit 1
fi

if command -v rg >/dev/null 2>&1; then
    matches="$(
        rg -n 'aster_framevisor::console|framevisor::console' \
            "$repo_root/kernel/src" \
            "$repo_root/kernel/comps" \
            --glob '!framevisor/**' \
            --glob '!framevm/**' \
            || true
    )"
else
    matches="$(
        grep -RInE 'aster_framevisor::console|framevisor::console' \
            "$repo_root/kernel/src" \
            "$repo_root/kernel/comps" \
            2>/dev/null \
            | grep -v '/kernel/comps/framevisor/' \
            | grep -v '/kernel/comps/framevm/' \
            || true
    )"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: ordinary kernel code must not branch on FrameVisor console internals" >&2
    exit 1
fi

banned_source_pattern='host_ostd|host-ostd|aster_framevisor|aster-framevisor|aster_framevisor_exchangeable|aster-framevisor-exchangeable|FrameVisor|FrameVM|framevisor|AF_FRAMEVSOCK|FRAMEVSOCK|PRIVATE_VSOCK|LEGACY_PRIVATE_VSOCK|LEGACY_PRIVATE_FAMILY|FrameTaskGroup|FrameTaskGroupId|VmId|Iht|IHT|RRef|RRefId|DomainId|Exchangeable|backend-api|host-api|host_api|ostd::vm|ostd::iht|ostd::vsock|ostd::rref|ostd::framevm_|exchangeable::|rref_registry|SpinLockRef|kernel_logln|activate_safe_vm_space|inject_irq|inject_vsock|__init_current_service|__shutdown_current_service|enter_current_service|shutdown_current_service|dispatch_pre_schedule|dispatch_post_schedule|dispatch_pre_user_run|dispatch_user_page_fault|TaskCreatorFn|TaskGroupBinderFn|PriorityBoosterFn|inject_task_creator|inject_task_group_binder|inject_priority_booster|bind_ostd_task_to_frame_task_group|ostd_tasks_in_frame_task_group|bind_current_task_to_frame_task_group|clear_current_frame_task_group|current_frame_task_group_id|init_framevisor|create_framevm|destroy_framevm|start_framevm|stop_framevm|default_frame_task_group|validate_frame_task_group_share|set_frame_task_group_share|reset_frame_task_group_accounting|frame_task_group_|framevm\.mode|framevm\.duration_ms'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$banned_source_pattern" "${framevm_service_srcs[@]}" || true)"
else
    matches="$(grep -RInE "$banned_source_pattern" "${framevm_service_srcs[@]}" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM service-side source leaks FrameVisor host implementation details" >&2
    exit 1
fi

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n '\bmod[[:space:]]+ostd_compat\b|\bostd_compat::' "$framevm_src" || true)"
else
    matches="$(grep -RInE '\bmod[[:space:]]+ostd_compat\b|\bostd_compat::' "$framevm_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM must use the ostd crate binding directly, not an ostd_compat facade" >&2
    exit 1
fi

namespace_pattern='\b(NsProxy|[A-Za-z0-9_]*Namespace|namespace)\b'
if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$namespace_pattern" "${framevm_service_srcs[@]}" "$framevisor_src" || true)"
else
    matches="$(grep -RInE "$namespace_pattern" "${framevm_service_srcs[@]}" "$framevisor_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM and FrameVisor must not introduce namespace abstractions" >&2
    exit 1
fi

if command -v rg >/dev/null 2>&1; then
    matches="$(rg --files "$framevm_src" "$framevisor_src" | rg -n '(^|/)(namespace|namespaces|nsproxy|ns_proxy)(/|\.|$)' || true)"
else
    matches="$(find "$framevm_src" "$framevisor_src" -type f | grep -En '(^|/)(namespace|namespaces|nsproxy|ns_proxy)(/|\.|$)' || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM and FrameVisor must not add namespace modules or placeholder files" >&2
    exit 1
fi

if ! grep -q "ENOPROTOOPT = 92" "$framevm_src/error.rs" \
    || ! grep -q "EOPNOTSUPP = 95" "$framevm_src/error.rs" \
    || ! grep -q "validate_socket_option(level, optname, SocketOptionAccess::Set)" \
        "$framevm_src/syscall/setsockopt.rs" \
    || ! grep -q "validate_socket_option(level, optname, SocketOptionAccess::Get)" \
        "$framevm_src/syscall/getsockopt.rs"; then
    echo "error: FrameVM socket option handling must keep kernel-compatible ENOPROTOOPT paths" >&2
    exit 1
fi

if grep -q "optval is null pointer" "$framevm_src/syscall/getsockopt.rs"; then
    echo "error: FrameVM getsockopt must let optval write faults follow the kernel user-copy path" >&2
    exit 1
fi

if grep -RIn "ENOTSUP" "$framevm_src" >/tmp/framevm_boundary_enotsup.$$ 2>/dev/null; then
    cat /tmp/framevm_boundary_enotsup.$$
    rm -f /tmp/framevm_boundary_enotsup.$$
    echo "error: FrameVM must use kernel-compatible EOPNOTSUPP naming for errno 95" >&2
    exit 1
fi
rm -f /tmp/framevm_boundary_enotsup.$$

if grep -q 'write_to_user' "$framevm_src/syscall/arch_prctl.rs" \
    || ! grep -q 'task_data.fs_base() as isize' "$framevm_src/syscall/arch_prctl.rs" \
    || ! grep -q 'task_data.gs_base(&guard) as isize' "$framevm_src/syscall/arch_prctl.rs"; then
    echo "error: FrameVM arch_prctl GET paths must keep kernel-compatible return-value semantics" >&2
    exit 1
fi

if grep -q "CPU-time clocks are not supported yet" "$framevm_src/syscall/clock_gettime.rs" \
    || ! grep -q 'ClockId::CLOCK_PROCESS_CPUTIME_ID => read_process_cpu_clock()' \
        "$framevm_src/syscall/clock_gettime.rs" \
    || ! grep -q 'ClockId::CLOCK_THREAD_CPUTIME_ID => read_thread_cpu_clock()' \
        "$framevm_src/syscall/clock_gettime.rs" \
    || ! grep -q 'DynamicClockIdInfo' "$framevm_src/syscall/clock_gettime.rs" \
    || ! grep -q 'read_process_cpu_clock_by_pid' "$framevm_src/syscall/clock_gettime.rs" \
    || ! grep -q 'thread_cpu_time_cycles_for_tid' "$framevm_src/task.rs" \
    || [ "$(grep -c '\.record_cpu_time_schedule_out();' "$framevm_src/task.rs")" -lt 2 ] \
    || ! grep -q 'record_cpu_time_cycles' "$framevm_src/process.rs"; then
    echo "error: FrameVM clock_gettime CPU clocks must follow kernel success semantics with task CPU accounting" >&2
    exit 1
fi

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n '\b(SYS_UNSHARE|SYS_SETNS|sys_unshare|sys_setns)\b' "$framevm_src" || true)"
else
    matches="$(grep -RInE '\b(SYS_UNSHARE|SYS_SETNS|sys_unshare|sys_setns)\b' "$framevm_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM must not carry namespace syscall stubs" >&2
    exit 1
fi

for clone_namespace_flag in \
    CLONE_NEWTIME \
    CLONE_NEWNS \
    CLONE_NEWCGROUP \
    CLONE_NEWUTS \
    CLONE_NEWIPC \
    CLONE_NEWUSER \
    CLONE_NEWPID \
    CLONE_NEWNET
do
    if ! grep -q "$clone_namespace_flag" "$framevm_src/task.rs"; then
        echo "error: FrameVM clone must name and reject $clone_namespace_flag instead of adding namespace state" >&2
        exit 1
    fi
done

if ! grep -q 'const UNSUPPORTED_CLONE_FLAGS' "$framevm_src/task.rs" \
    || ! grep -q 'flags & UNSUPPORTED_CLONE_FLAGS != 0' "$framevm_src/task.rs" \
    || ! grep -q 'validate_clone_flags(flags)?' "$framevm_src/task.rs"; then
    echo "error: FrameVM clone must reject CLONE_NEW* flags at the syscall boundary" >&2
    exit 1
fi

if grep -RIn "downcast_ref::<usize>" "$framevisor_src/iht" "$framevisor_src/task" >/tmp/framevm_boundary_raw_task_ext.$$ 2>/dev/null; then
    cat /tmp/framevm_boundary_raw_task_ext.$$
    rm -f /tmp/framevm_boundary_raw_task_ext.$$
    echo "error: FrameVisor must not recover vCPU identity from raw usize task extensions" >&2
    exit 1
fi
rm -f /tmp/framevm_boundary_raw_task_ext.$$

framevm_direct_console_pattern='ostd::console::(read|write|acquire_input|release_input|has_input|clear_input|is_active)|ostd::console_transport::'
if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevm_direct_console_pattern" "$framevm_src" "$framevm_console_dir/src" || true)"
else
    matches="$(grep -RInE "$framevm_direct_console_pattern" "$framevm_src" "$framevm_console_dir/src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM must not call service-only console transport through ostd" >&2
    exit 1
fi

if grep -Eq '^FRAMEVM_BUNDLED_RLIBS[[:space:]]*:=[^\n]*aster_console_transport' "$repo_root/Makefile"; then
    echo "error: FrameVM console transport ABI must remain host-resolved, not bundled into framevm.o" >&2
    exit 1
fi

if grep -q 'send_to_guest_control(vcpu_id: usize, packet: RRef<ControlPacket>) -> Result<(), ()>' \
    "$framevisor_src/vsock/mod.rs"; then
    echo "error: FrameVisor host-to-guest control send must return the original RRef on failure" >&2
    exit 1
fi

if ! grep -q 'Result<(), RRef<ControlPacket>>' "$framevisor_src/vsock/mod.rs"; then
    echo "error: FrameVisor host-to-guest control send must preserve RRef ownership in its error type" >&2
    exit 1
fi

if ! grep -q 'fn submit_service_data(packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>>' \
    "$framevisor_src/vsock/mod.rs" \
    || ! grep -q 'fn submit_service_control(packet: RRef<ControlPacket>) -> Result<(), RRef<ControlPacket>>' \
        "$framevisor_src/vsock/mod.rs" \
    || [ "$(grep -c 'try_transfer_to(DomainId::Host)' "$framevisor_src/vsock/mod.rs")" -lt 2 ] \
    || [ "$(grep -c 'return Err(error.into_rref())' "$framevisor_src/vsock/mod.rs")" -lt 2 ]; then
    echo "error: FrameVisor service-to-host FrameVsock submit must transfer ownership fallibly and return the original RRef on failure" >&2
    exit 1
fi

if grep -q 'registered:[[:space:]]*false' "$exchangeable_src" \
    || ! grep -q 'pub fn try_new_with_owner(value: T, owner: DomainId) -> Result<Self, RegistryError>' \
        "$exchangeable_src" \
    || ! grep -q 'return Err(RegistryError::NotInitialized)' "$exchangeable_src" \
    || ! grep -q 'RRef registry must be initialized before creating RRefs' "$exchangeable_src"; then
    echo "error: RRef construction must require registry metadata instead of creating unregistered RRefs" >&2
    exit 1
fi

for task_hook_api in \
    inject_pre_schedule_handler \
    inject_post_schedule_handler \
    inject_pre_user_run_handler
do
    if grep -R "ostd::task::$task_hook_api" "$framevm_src" >/dev/null 2>&1 \
        && ! grep -q "pub fn $task_hook_api" "$repo_root/ostd/src/task/mod.rs"; then
        echo "error: FrameVM uses ostd::task::$task_hook_api, but Host OSTD does not provide it" >&2
        exit 1
    fi
done

for scheduler_api in inject_scheduler enable_preemption_on_cpu; do
    if grep -R "ostd::task::scheduler::$scheduler_api" "$framevm_src" >/dev/null 2>&1 \
        && ! grep -q "pub fn $scheduler_api" "$repo_root/ostd/src/task/scheduler/mod.rs"; then
        echo "error: FrameVM uses ostd::task::scheduler::$scheduler_api, but Host OSTD does not provide it" >&2
        exit 1
    fi
done

if grep -q "pub fn inject_timer_tick_handler" "$repo_root/ostd/src/task/scheduler/mod.rs" \
    || grep -q "pub fn inject_timer_tick_handler" "$framevisor_src/task/scheduler.rs" \
    || grep -R "inject_timer_tick_handler" "$framevm_src" >/dev/null 2>&1; then
    echo "error: virtual timer ticks must use real OSTD scheduler/timer APIs, not a service-only inject_timer_tick_handler helper" >&2
    exit 1
fi

if grep -R "ostd::task::scheduler::current_cpu" "$framevm_src" >/dev/null 2>&1; then
    echo "error: FrameVM must use ostd::cpu::CpuId::current_racy(), not a service-only scheduler::current_cpu helper" >&2
    exit 1
fi

if grep -q '^pub fn current_cpu' "$framevisor_src/task/scheduler.rs"; then
    echo "error: FrameVisor scheduler::current_cpu must stay crate-private and must not enter the OSTD-shaped service API" >&2
    exit 1
fi

if grep -R "ostd::timer::register_callback_on_cpu" "$framevm_src" >/dev/null 2>&1 \
    && ! grep -q "pub fn register_callback_on_cpu" "$repo_root/ostd/src/timer/mod.rs"; then
    echo "error: FrameVM uses ostd::timer::register_callback_on_cpu, but Host OSTD does not provide it" >&2
    exit 1
fi

require_ostd_surface_regex \
    "$framevisor_src/sync/mod.rs" \
    "$repo_root/ostd/src/sync/mod.rs" \
    'pub[[:space:]]+use[[:space:]]+::spin::Once' \
    'ostd::sync::Once'
require_ostd_surface_regex \
    "$framevisor_src/task/scheduler.rs" \
    "$repo_root/ostd/src/task/scheduler/mod.rs" \
    'pub[[:space:]]+fn[[:space:]]+inject_scheduler\(scheduler:[[:space:]]*&'\''static[[:space:]]+dyn[[:space:]]+Scheduler<Task>\)' \
    'ostd::task::scheduler::inject_scheduler'
require_ostd_surface_regex \
    "$framevisor_src/task/scheduler.rs" \
    "$repo_root/ostd/src/task/scheduler/mod.rs" \
    'pub[[:space:]]+fn[[:space:]]+enable_preemption_on_cpu\(\)' \
    'ostd::task::scheduler::enable_preemption_on_cpu'
require_ostd_surface_regex \
    "$framevisor_src/task/scheduler.rs" \
    "$repo_root/ostd/src/task/scheduler/mod.rs" \
    'pub[[:space:]]+trait[[:space:]]+Scheduler<T[[:space:]]*=[[:space:]]*Task>:[[:space:]]*(Sync[[:space:]]*\+[[:space:]]*Send|Send[[:space:]]*\+[[:space:]]*Sync)' \
    'ostd::task::scheduler::Scheduler'
require_ostd_surface_regex \
    "$framevisor_src/task/scheduler.rs" \
    "$repo_root/ostd/src/task/scheduler/mod.rs" \
    'fn[[:space:]]+enqueue\(&self,[[:space:]]+runnable:[[:space:]]+Arc<T>,[[:space:]]+flags:[[:space:]]+EnqueueFlags\)[[:space:]]+->[[:space:]]+Option<CpuId>;' \
    'ostd::task::scheduler::Scheduler::enqueue'
require_ostd_surface_regex \
    "$framevisor_src/task/scheduler.rs" \
    "$repo_root/ostd/src/task/scheduler/mod.rs" \
    'fn[[:space:]]+local_rq_with\(&self,[[:space:]]+f:[[:space:]]+&mut[[:space:]]+dyn[[:space:]]+FnMut\(&dyn[[:space:]]+LocalRunQueue<T>\)\);' \
    'ostd::task::scheduler::Scheduler::local_rq_with'
require_ostd_surface_regex \
    "$framevisor_src/task/scheduler.rs" \
    "$repo_root/ostd/src/task/scheduler/mod.rs" \
    'fn[[:space:]]+mut_local_rq_with\(&self,[[:space:]]+f:[[:space:]]+&mut[[:space:]]+dyn[[:space:]]+FnMut\(&mut[[:space:]]+dyn[[:space:]]+LocalRunQueue<T>\)\);' \
    'ostd::task::scheduler::Scheduler::mut_local_rq_with'
require_ostd_surface_regex \
    "$framevisor_src/task/scheduler.rs" \
    "$repo_root/ostd/src/task/scheduler/mod.rs" \
    'pub[[:space:]]+trait[[:space:]]+LocalRunQueue<T[[:space:]]*=[[:space:]]*Task>' \
    'ostd::task::scheduler::LocalRunQueue'
for scheduler_rq_api in \
    'fn[[:space:]]+current\(&self\)[[:space:]]+->[[:space:]]+Option<&Arc<T>>;' \
    'fn[[:space:]]+update_current\(&mut[[:space:]]+self,[[:space:]]+flags:[[:space:]]+UpdateFlags\)[[:space:]]+->[[:space:]]+bool;' \
    'fn[[:space:]]+pick_next\(&mut[[:space:]]+self\)[[:space:]]+->[[:space:]]+&Arc<T>' \
    'fn[[:space:]]+try_pick_next\(&mut[[:space:]]+self\)[[:space:]]+->[[:space:]]+Option<&Arc<T>>;' \
    'fn[[:space:]]+dequeue_current\(&mut[[:space:]]+self\)[[:space:]]+->[[:space:]]+Option<Arc<T>>;'
do
    require_ostd_surface_regex \
        "$framevisor_src/task/scheduler.rs" \
        "$repo_root/ostd/src/task/scheduler/mod.rs" \
        "$scheduler_rq_api" \
        "ostd::task::scheduler::LocalRunQueue method $scheduler_rq_api"
done
for scheduler_enum_api in \
    'pub[[:space:]]+enum[[:space:]]+EnqueueFlags' \
    'Spawn' \
    'Wake' \
    'pub[[:space:]]+enum[[:space:]]+UpdateFlags' \
    'Tick' \
    'Wait' \
    'Yield' \
    'Exit'
do
    require_ostd_surface_regex \
        "$framevisor_src/task/scheduler.rs" \
        "$repo_root/ostd/src/task/scheduler/mod.rs" \
        "$scheduler_enum_api" \
        "ostd::task::scheduler enum item $scheduler_enum_api"
done
for task_api in \
    'pub[[:space:]]+fn[[:space:]]+inject_pre_schedule_handler\(handler:[[:space:]]+fn\(&DisabledLocalIrqGuard\)\)' \
    'pub[[:space:]]+fn[[:space:]]+inject_post_schedule_handler\(handler:[[:space:]]+fn\(\)[[:space:]]+->[[:space:]]+bool\)' \
    'pub[[:space:]]+fn[[:space:]]+inject_pre_user_run_handler\(handler:[[:space:]]+fn\(&DisabledLocalIrqGuard\)\)' \
    'pub[[:space:]]+struct[[:space:]]+Task' \
    'pub[[:space:]]+struct[[:space:]]+TaskOptions' \
    'pub[[:space:]]+fn[[:space:]]+current\(\)[[:space:]]+->[[:space:]]+Option<CurrentTask>' \
    'pub[[:space:]]+fn[[:space:]]+yield_now\(\)' \
    'pub[[:space:]]+fn[[:space:]]+run\(self:[[:space:]]+&Arc<Self>\)' \
    'pub[[:space:]]+fn[[:space:]]+wake_up\(self:[[:space:]]+&Arc<Self>\)' \
    'pub[[:space:]]+fn[[:space:]]+data\(&self\)[[:space:]]+->[[:space:]]+&Box<dyn[[:space:]]+Any[[:space:]]+\+[[:space:]]+Send[[:space:]]+\+[[:space:]]+Sync>' \
    'pub[[:space:]]+fn[[:space:]]+extension\(&self\)[[:space:]]+->[[:space:]]+&Box<dyn[[:space:]]+Any[[:space:]]+\+[[:space:]]+Send[[:space:]]+\+[[:space:]]+Sync>' \
    'pub[[:space:]]+fn[[:space:]]+schedule_info\(&self\)[[:space:]]+->[[:space:]]+&TaskScheduleInfo'
do
    require_ostd_surface_regex \
        "$framevisor_src/task/mod.rs" \
        "$repo_root/ostd/src/task/mod.rs" \
        "$task_api" \
        "ostd::task item $task_api"
done
require_ostd_surface_regex \
    "$framevisor_src/timer.rs" \
    "$repo_root/ostd/src/timer/mod.rs" \
    'pub[[:space:]]+const[[:space:]]+TIMER_FREQ:[[:space:]]+u64[[:space:]]+=' \
    'ostd::timer::TIMER_FREQ'
require_ostd_surface_regex \
    "$framevisor_src/cpu/id.rs" \
    "$repo_root/ostd/src/cpu/id.rs" \
    'pub[[:space:]]+fn[[:space:]]+current_racy\(\)[[:space:]]+->[[:space:]]+Self' \
    'ostd::cpu::CpuId::current_racy'
require_ostd_surface_regex \
    "$framevisor_src/arch.rs" \
    "$repo_root/ostd/src/arch" \
    'pub[[:space:]]+use[[:space:]].*if_tdx_enabled' \
    'ostd::arch::if_tdx_enabled'
require_ostd_surface_regex \
    "$framevisor_src/timer.rs" \
    "$repo_root/ostd/src/timer/mod.rs" \
    'pub[[:space:]]+fn[[:space:]]+register_callback_on_cpu<F>\(func:[[:space:]]+F\)' \
    'ostd::timer::register_callback_on_cpu'
for irq_api in \
    'pub[[:space:]]+fn[[:space:]]+disable_local\(\)[[:space:]]+->[[:space:]]+DisabledLocalIrqGuard' \
    'pub[[:space:]]+struct[[:space:]]+DisabledLocalIrqGuard' \
    'pub[[:space:]]+enum[[:space:]]+InterruptLevel' \
    'pub[[:space:]]+fn[[:space:]]+current\(\)[[:space:]]+->[[:space:]]+Self' \
    'pub[[:space:]]+fn[[:space:]]+as_u8\(&self\)[[:space:]]+->[[:space:]]+u8' \
    'pub[[:space:]]+fn[[:space:]]+is_task_context\(&self\)[[:space:]]+->[[:space:]]+bool' \
    'pub[[:space:]]+fn[[:space:]]+is_interrupt_context\(&self\)[[:space:]]+->[[:space:]]+bool' \
    'pub[[:space:]]+fn[[:space:]]+register_bottom_half_handler_l1\(' \
    'func:[[:space:]]+fn\(DisabledLocalIrqGuard,[[:space:]]+u8\)[[:space:]]+->[[:space:]]+DisabledLocalIrqGuard' \
    'pub[[:space:]]+fn[[:space:]]+register_bottom_half_handler_l2\(func:[[:space:]]+fn\(u8\)\)' \
    'pub[[:space:]]+type[[:space:]]+IrqCallbackFunction[[:space:]]+=' \
    'pub[[:space:]]+struct[[:space:]]+IrqLine' \
    'pub[[:space:]]+fn[[:space:]]+alloc\(\)[[:space:]]+->[[:space:]]+Result<Self>' \
    'pub[[:space:]]+fn[[:space:]]+alloc_specific\(irq_num:[[:space:]]+u8\)[[:space:]]+->[[:space:]]+Result<Self>' \
    'pub[[:space:]]+fn[[:space:]]+num\(&self\)[[:space:]]+->[[:space:]]+u8' \
    'pub[[:space:]]+fn[[:space:]]+on_active<F>\(&mut[[:space:]]+self,[[:space:]]+callback:[[:space:]]+F\)' \
    'F:[[:space:]]+Fn\(&TrapFrame\)[[:space:]]+\+[[:space:]]+Sync[[:space:]]+\+[[:space:]]+Send[[:space:]]+\+[[:space:]]+'\''static' \
    'pub[[:space:]]+fn[[:space:]]+is_empty\(&self\)[[:space:]]+->[[:space:]]+bool' \
    'pub[[:space:]]+fn[[:space:]]+remapping_index\(&self\)[[:space:]]+->[[:space:]]+Option<u16>'
do
    require_ostd_surface_regex \
        "$framevisor_src/irq/mod.rs" \
        "$repo_root/ostd/src/irq" \
        "$irq_api" \
        "ostd::irq item $irq_api"
done

if grep -R "ostd::arch::trap::inject_user_page_fault_handler" "$framevm_src" >/dev/null 2>&1; then
    if command -v rg >/dev/null 2>&1; then
        matches="$(rg -n "pub fn inject_user_page_fault_handler" "$repo_root/ostd/src/arch" || true)"
    else
        matches="$(grep -RIn "pub fn inject_user_page_fault_handler" "$repo_root/ostd/src/arch" || true)"
    fi
    if [ -z "$matches" ]; then
        echo "error: FrameVM uses ostd::arch::trap::inject_user_page_fault_handler, but Host OSTD does not provide it" >&2
        exit 1
    fi
fi

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n '\bspin::|use[[:space:]]+spin::' "${framevm_service_srcs[@]}" || true)"
else
    matches="$(grep -RInE '\bspin::|use[[:space:]]+spin::' "${framevm_service_srcs[@]}" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM service synchronization must go through the ostd::sync facade, not the spin crate directly" >&2
    exit 1
fi

if grep -q 'pub use spin_lock::{[^}]*SpinLockRef' "$framevisor_src/sync/mod.rs"; then
    echo "error: FrameVisor sync facade must not expose SpinLockRef" >&2
    exit 1
fi

framevisor_sync_host_lock_leak_pattern='pub[[:space:]]+use[[:space:]]+ostd::sync::.*(Mutex|MutexGuard|RwLock|RwLockReadGuard|RwLockWriteGuard|RwLockUpgradeableGuard|SpinGuardian|GuardTransfer)|pub[[:space:]]+type[[:space:]]+(Mutex|MutexGuard|RwLock|RwLockReadGuard|RwLockWriteGuard|RwLockUpgradeableGuard|SpinGuardian|GuardTransfer).*ostd::sync'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_sync_host_lock_leak_pattern" "$framevisor_src/sync/mod.rs" || true)"
else
    matches="$(grep -nE "$framevisor_sync_host_lock_leak_pattern" "$framevisor_src/sync/mod.rs" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor sync facade must expose its own OSTD-shaped lock types and guard traits" >&2
    exit 1
fi

framevisor_user_leak_pattern='pub[[:space:]]+use[[:space:]]+ostd::user|pub[[:space:]]+use[[:space:]]+ostd::\{[^}]*user'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_user_leak_pattern" "$framevisor_src" || true)"
else
    matches="$(grep -RInE "$framevisor_user_leak_pattern" "$framevisor_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor must expose user mode through its own OSTD-compatible facade" >&2
    exit 1
fi

framevisor_timer_leak_pattern='pub[[:space:]]+use[[:space:]]+ostd::timer|pub[[:space:]]+use[[:space:]]+ostd::\{[^}]*timer'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_timer_leak_pattern" "$framevisor_src" || true)"
else
    matches="$(grep -RInE "$framevisor_timer_leak_pattern" "$framevisor_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor must expose timer through its own OSTD-compatible facade" >&2
    exit 1
fi

if ! grep -q "pub fn register_callback_on_cpu" "$framevisor_src/timer.rs"; then
    echo "error: FrameVisor timer facade is missing OSTD timer::register_callback_on_cpu" >&2
    exit 1
fi

framevisor_root_print_leak_pattern='pub[[:space:]]+use[[:space:]]+ostd::prelude::println'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_root_print_leak_pattern" "$framevisor_lib" || true)"
else
    matches="$(grep -nE "$framevisor_root_print_leak_pattern" "$framevisor_lib" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor root service surface must not expose Host OSTD println" >&2
    exit 1
fi

framevisor_power_leak_pattern='pub[[:space:]]+use[[:space:]]+ostd::power|pub[[:space:]]+type[[:space:]]+.*=[[:space:]]*ostd::power'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_power_leak_pattern" "$framevisor_src/power.rs" || true)"
else
    matches="$(grep -nE "$framevisor_power_leak_pattern" "$framevisor_src/power.rs" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor power facade must not expose Host OSTD power operations" >&2
    exit 1
fi

framevisor_arch_physical_leak_pattern='pub[[:space:]]+use[[:space:]]+ostd::arch::(irq|device)|pub[[:space:]]+mod[[:space:]]+(irq|device)[[:space:]]*\{'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_arch_physical_leak_pattern" "$framevisor_src/arch.rs" || true)"
else
    matches="$(grep -nE "$framevisor_arch_physical_leak_pattern" "$framevisor_src/arch.rs" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor arch facade must not expose physical IRQ or device modules" >&2
    exit 1
fi

framevisor_arch_host_reexport_pattern='pub[[:space:]]+use[[:space:]]+host_ostd::arch::.*::\*|pub[[:space:]]+mod[[:space:]]+(cpuid|extension|serial)[[:space:]]*\{'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_arch_host_reexport_pattern" "$framevisor_src/arch.rs" || true)"
else
    matches="$(grep -nE "$framevisor_arch_host_reexport_pattern" "$framevisor_src/arch.rs" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor arch facade must not expose broad Host OSTD arch re-exports to services" >&2
    exit 1
fi

framevisor_service_leak_pattern='pub[[:space:]]+const[[:space:]]+FRAMEVSOCK'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_service_leak_pattern" "$framevisor_src" || true)"
else
    matches="$(grep -RInE "$framevisor_service_leak_pattern" "$framevisor_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor service-facing API must not expose FrameVisor-specific IRQ constants" >&2
    exit 1
fi

for private_mod in iht vm vsock; do
    if grep -q "^pub mod $private_mod;" "$framevisor_lib" \
        && ! grep -B1 "^pub mod $private_mod;" "$framevisor_lib" \
            | grep -q '#\[cfg(feature = "host-api")\]'; then
        echo "error: FrameVisor::$private_mod must be public only with host-api" >&2
        exit 1
    fi
done

if grep -q '^pub mod error;' "$framevisor_lib"; then
    echo "error: FrameVisor must match Host OSTD by exporting Error/Result, not ostd::error" >&2
    exit 1
fi

if grep -q '^pub use vm::' "$framevisor_lib" \
    && ! grep -B1 '^pub use vm::' "$framevisor_lib" \
        | grep -q '#\[cfg(feature = "host-api")\]'; then
    echo "error: FrameVisor VM identifiers must not be exported on the service-facing surface" >&2
    exit 1
fi

if grep -q "pub fn init" "$framevisor_src/irq/mod.rs"; then
    echo "error: FrameVisor irq::init must not be part of the OSTD-compatible service surface" >&2
    exit 1
fi

for irq_api in register_bottom_half_handler_l1 register_bottom_half_handler_l2; do
    if ! grep -q "pub fn $irq_api" "$framevisor_src/irq/mod.rs"; then
        echo "error: FrameVisor irq facade is missing OSTD irq::$irq_api" >&2
        exit 1
    fi
done

for irq_type in InterruptLevel IrqLine IrqCallbackFunction DisabledLocalIrqGuard; do
    if ! grep -q "pub .* $irq_type" "$framevisor_src/irq/mod.rs"; then
        echo "error: FrameVisor irq facade is missing OSTD irq::$irq_type" >&2
        exit 1
    fi
done

if ! grep -q "pub fn remapping_index" "$framevisor_src/irq/mod.rs"; then
    echo "error: FrameVisor IrqLine facade is missing OSTD IrqLine::remapping_index" >&2
    exit 1
fi

for task_api in stack_bottom stack_top schedule_info; do
    if ! grep -q "pub fn $task_api" "$framevisor_src/task/mod.rs"; then
        echo "error: FrameVisor task facade is missing OSTD Task::$task_api" >&2
        exit 1
    fi
done

for task_hook_api in inject_pre_schedule_handler inject_post_schedule_handler inject_pre_user_run_handler; do
    if grep -q "pub fn $task_hook_api" "$framevisor_src/task/mod.rs" \
        && ! grep -q "pub fn $task_hook_api" "$repo_root/ostd/src/task/mod.rs"; then
        echo "error: FrameVisor task::$task_hook_api must exist in Host OSTD task first" >&2
        exit 1
    fi
done

if ! grep -q "pub mod info" "$framevisor_src/task/scheduler.rs"; then
    echo "error: FrameVisor scheduler facade must expose OSTD scheduler::info" >&2
    exit 1
fi

for scheduler_info_api in \
    'pub[[:space:]]+struct[[:space:]]+TaskScheduleInfo' \
    'pub[[:space:]]+cpu:[[:space:]]+AtomicCpuId' \
    'pub[[:space:]]+struct[[:space:]]+AtomicCpuId\(AtomicU32\);' \
    'pub[[:space:]]+fn[[:space:]]+set_if_is_none\(&self,[[:space:]]+cpu_id:[[:space:]]+CpuId\)[[:space:]]+->[[:space:]]+Result<\(\),[[:space:]]+CpuId>' \
    'pub[[:space:]]+fn[[:space:]]+set_anyway\(&self,[[:space:]]+cpu_id:[[:space:]]+CpuId\)' \
    'pub[[:space:]]+fn[[:space:]]+set_to_none\(&self\)' \
    'pub[[:space:]]+fn[[:space:]]+get\(&self\)[[:space:]]+->[[:space:]]+Option<CpuId>' \
    'impl[[:space:]]+Default[[:space:]]+for[[:space:]]+AtomicCpuId' \
    'pub[[:space:]]+trait[[:space:]]+CommonSchedInfo' \
    'fn[[:space:]]+cpu\(&self\)[[:space:]]+->[[:space:]]+&AtomicCpuId;'
do
    require_ostd_surface_regex \
        "$framevisor_src/task/scheduler/info.rs" \
        "$repo_root/ostd/src/task/scheduler/info.rs" \
        "$scheduler_info_api" \
        "ostd::task::scheduler::info item $scheduler_info_api"
done

if ! grep -q "task::clear_service_hooks_for_vm(vm_id)" "$framevisor_src/boot.rs"; then
    echo "error: service shutdown must clear task hooks before unloading dynamic code" >&2
    exit 1
fi

if ! grep -q "timer::clear_callbacks_for_vm(vm_id)" "$framevisor_src/boot.rs"; then
    echo "error: service shutdown must clear timer callbacks before unloading dynamic code" >&2
    exit 1
fi

if ! grep -q "console::clear_transport_input_callbacks()" "$framevisor_src/boot.rs"; then
    echo "error: service shutdown must clear console input callbacks before unloading dynamic code" >&2
    exit 1
fi

if grep -RIn "dispatch_timer_callbacks" "$framevisor_src/task/scheduler.rs" "$framevisor_src/timer.rs" >/dev/null 2>&1; then
    grep -RIn "dispatch_timer_callbacks" "$framevisor_src/task/scheduler.rs" "$framevisor_src/timer.rs"
    echo "error: virtual scheduler ticks must not be dispatched through a generic timer callback queue" >&2
    exit 1
fi

for timer_tick_api in advance_timer_ticks dispatch_registered_callbacks; do
    if ! grep -q "$timer_tick_api" "$framevisor_src/task/scheduler.rs"; then
        echo "error: virtual scheduler tick dispatch must explicitly separate $timer_tick_api from scheduler accounting" >&2
        exit 1
    fi
done

if ! grep -q "update_current(UpdateFlags::Tick)" "$framevisor_src/task/scheduler.rs"; then
    echo "error: virtual scheduler ticks must update the injected scheduler directly" >&2
    exit 1
fi

timer_callback_jiffies_update="$(
    awk '
        /fn dispatch_registered_callbacks/ { in_fn = 1 }
        in_fn && /advance_jiffies/ { print FILENAME ":" FNR ":" $0 }
        in_fn && /^}/ { in_fn = 0 }
    ' "$framevisor_src/timer.rs"
)"

if [ -n "$timer_callback_jiffies_update" ]; then
    echo "$timer_callback_jiffies_update"
    echo "error: registered timer callbacks must not own virtual tick accounting" >&2
    exit 1
fi

service_internal_public_pattern='^pub[[:space:]]+(use[[:space:]].*init_cpu_id|fn[[:space:]]+(init_cpu|init_cpu_id|init_error|init_mm|init_vm_space|init_frame|init_frame_allocator|init_preempt|activate_safe_vm_space)\b)'
service_internal_files=(
    "$framevisor_src/cpu/mod.rs"
    "$framevisor_src/cpu/id.rs"
    "$framevisor_src/error.rs"
    "$framevisor_src/mm/mod.rs"
    "$framevisor_src/mm/vm_space.rs"
    "$framevisor_src/mm/frame/mod.rs"
    "$framevisor_src/mm/frame/allocator.rs"
    "$framevisor_src/task/preempt/mod.rs"
    "$framevisor_src/task/preempt/guard.rs"
)

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$service_internal_public_pattern" "${service_internal_files[@]}" || true)"
else
    matches="$(grep -nE "$service_internal_public_pattern" "${service_internal_files[@]}" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor internal initialization must not be part of the OSTD-compatible service surface" >&2
    exit 1
fi

framevisor_mm_extra_pattern='^pub[[:space:]]+(struct|fn|type)[[:space:]]+(MappedRamRange|mapped_ram_ranges|read_mapped_ram|vmspace)\b|^pub[[:space:]]+use[[:space:]]+vm_space::.*MappedRamRange'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_mm_extra_pattern" "$framevisor_src/mm" || true)"
else
    matches="$(grep -RInE "$framevisor_mm_extra_pattern" "$framevisor_src/mm" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor mm facade must use Host OSTD-shaped cursor/query APIs, not private mapping helpers" >&2
    exit 1
fi

framevm_mm_extra_pattern='ostd::mm::(MappedRamRange|mapped_ram_ranges|read_mapped_ram)|\.(mapped_ram_ranges|read_mapped_ram)\('

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevm_mm_extra_pattern" "$framevm_src" || true)"
else
    matches="$(grep -RInE "$framevm_mm_extra_pattern" "$framevm_src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM must query mappings through OSTD VmSpace cursors, not FrameVisor private helpers" >&2
    exit 1
fi

service_facade_files=(
    "$framevisor_src/arch.rs"
    "$framevisor_src/boot.rs"
    "$framevisor_src/console.rs"
    "$framevisor_src/cpu/id.rs"
    "$framevisor_src/cpu/mod.rs"
    "$framevisor_src/error.rs"
    "$framevisor_src/irq/mod.rs"
    "$framevisor_src/log.rs"
    "$framevisor_src/mm/io.rs"
    "$framevisor_src/mm/mod.rs"
    "$framevisor_src/mm/page_prop.rs"
    "$framevisor_src/mm/page_table/mod.rs"
    "$framevisor_src/mm/vm_space.rs"
    "$framevisor_src/mm/frame/allocator.rs"
    "$framevisor_src/mm/frame/meta.rs"
    "$framevisor_src/mm/frame/mod.rs"
    "$framevisor_src/mm/frame/segment.rs"
    "$framevisor_src/mm/frame/untyped.rs"
    "$framevisor_src/panic.rs"
    "$framevisor_src/power.rs"
    "$framevisor_src/prelude.rs"
    "$framevisor_src/sync/guard.rs"
    "$framevisor_src/sync/mod.rs"
    "$framevisor_src/sync/spin_lock.rs"
    "$framevisor_src/sync/wait_queue.rs"
    "$framevisor_src/task/atomic_mode.rs"
    "$framevisor_src/task/mod.rs"
    "$framevisor_src/task/preempt/mod.rs"
    "$framevisor_src/task/preempt/guard.rs"
    "$framevisor_src/task/scheduler.rs"
    "$framevisor_src/timer.rs"
    "$framevisor_src/user.rs"
)

service_public_backing_leak_pattern='^[[:space:]]*pub[[:space:]]+(use|type|fn|struct|enum|trait|const|static)[[:space:]].*(OstdTask|OstdCurrentTask|ostd::task|FrameTaskGroupId|VmId|IhtTaskData|FrameVm|TaskGroupRuntimeBinding|VirtualInterruptToken|RRef)|^[[:space:]]*pub[[:space:]]+fn[[:space:]]+(ostd_task|current_frame_task_group_id|bind_ostd_task_to_frame_task_group|ostd_tasks_in_frame_task_group)\b'

if command -v awk >/dev/null 2>&1; then
    matches="$(
        awk '
            $0 ~ /#\[cfg\(not\(feature = "host-api"\)\)\]/ { host_api_next = 0; next }
            $0 ~ /#\[cfg\(.*feature = "host-api"/ { host_api_next = 1; next }
            $0 ~ /^#\[/ { next }
            $0 ~ pattern && !host_api_next { print FILENAME ":" FNR ":" $0 }
            { host_api_next = 0 }
        ' pattern="$service_public_backing_leak_pattern" "${service_facade_files[@]}"
    )"
else
    matches=""
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor service-facing public APIs must not expose backing or host-control types" >&2
    exit 1
fi

service_facade_doc_leak_pattern='^[[:space:]]*//[/!].*(FrameVisor|FrameVM|FrameTaskGroup|IHT)'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$service_facade_doc_leak_pattern" "${service_facade_files[@]}" || true)"
else
    matches="$(grep -nE "$service_facade_doc_leak_pattern" "${service_facade_files[@]}" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: OSTD-compatible service facade docs must not expose FrameVisor implementation names" >&2
    exit 1
fi

framevisor_mm_inner_leak_pattern='^[[:space:]]+pub[[:space:]]+fn[[:space:]]+(new_with_inner|inner)\b'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_mm_inner_leak_pattern" "$framevisor_src/mm" || true)"
else
    matches="$(grep -RInE "$framevisor_mm_inner_leak_pattern" "$framevisor_src/mm" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor mm facade must not expose Host OSTD inner conversion methods" >&2
    exit 1
fi

for service_mod in log panic; do
    if ! grep -q "^pub mod $service_mod;" "$framevisor_lib"; then
        echo "error: FrameVisor service surface is missing OSTD::$service_mod" >&2
        exit 1
    fi
done

for service_macro in early_print early_println log log_enabled emerg alert crit error warn notice info debug; do
    if ! grep -RIn "macro_rules! $service_macro" "$framevisor_src" >/dev/null 2>&1; then
        echo "error: FrameVisor service surface is missing OSTD macro $service_macro" >&2
        exit 1
    fi
done

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n 'pub[[:space:]]+use[[:space:]]+ostd::prelude' "$framevisor_src/prelude.rs" \
        | grep -v 'prelude::ktest' || true)"
else
    matches="$(grep -nE 'pub[[:space:]]+use[[:space:]]+ostd::prelude' "$framevisor_src/prelude.rs" \
        | grep -v 'prelude::ktest' || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor prelude must re-export its own virtualized macros, not Host OSTD prelude" >&2
    exit 1
fi

framevisor_public_host_leak_pattern='^pub[[:space:]]+(mod|use|fn|struct|enum|type|trait|const|static)[[:space:]].*(FrameVM|framevm|FrameTaskGroup|VmId|vsock|iht|rref|vm::)|^pub[[:space:]]+mod[[:space:]]+(vm|vsock|iht)[[:space:]]*;'

if command -v awk >/dev/null 2>&1; then
    matches="$(
        awk '
            $0 ~ /#\[cfg\(not\(feature = "host-api"\)\)\]/ { host_api_next = 0; next }
            $0 ~ /#\[cfg\(.*feature = "host-api"/ { host_api_next = 1; next }
            $0 ~ /^#\[/ { next }
            $0 ~ pattern && !host_api_next { print FILENAME ":" FNR ":" $0 }
            { host_api_next = 0 }
        ' pattern="$framevisor_public_host_leak_pattern" "$framevisor_lib"
    )"
else
    matches=""
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor host-control names must not be public without host-api" >&2
    exit 1
fi

framevisor_task_extra_pattern='^pub[[:space:]]+(type|fn)[[:space:]]+(DisabledLocalIrqGuard|PreScheduleHandler|PreUserRunHandler|UserPageFaultHandler|init_task)\b'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$framevisor_task_extra_pattern" "$framevisor_src/task/mod.rs" || true)"
else
    matches="$(grep -nE "$framevisor_task_extra_pattern" "$framevisor_src/task/mod.rs" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor task facade must not expose non-OSTD helper names to FrameVM" >&2
    exit 1
fi

host_api_only_public_pattern='^pub[[:space:]]+(fn|type|enum|struct)[[:space:]]+(BootMode|set_boot_info|set_boot_info_with_mode|set_boot_info_with_cmdline|clear_boot_info|enter_current_service|shutdown_current_service|clear_output_log|output_log_snapshot|TaskCreatorFn|TaskGroupBinderFn|PriorityBoosterFn|inject_task_creator|inject_task_group_binder|inject_priority_booster|bind_ostd_task_to_frame_task_group|ostd_tasks_in_frame_task_group|dispatch_pre_schedule|dispatch_post_schedule|dispatch_pre_user_run|dispatch_user_page_fault|inject_irq|make_synthetic_trapframe|VsockIrqDebugStats|vsock_irq_debug_stats|reset_vsock_irq_debug_stats|inject_vsock_rx_interrupt_for_vm|inject_vsock_rx_interrupt)\b'
host_api_only_files=(
    "$framevisor_src/boot.rs"
    "$framevisor_src/console.rs"
    "$framevisor_src/irq/mod.rs"
    "$framevisor_src/task/mod.rs"
)

if command -v awk >/dev/null 2>&1; then
    matches="$(
        awk '
            $0 ~ /#\[cfg\(not\(feature = "host-api"\)\)\]/ { host_api_next = 0; next }
            $0 ~ /#\[cfg\(.*feature = "host-api"/ { host_api_next = 1; next }
            $0 ~ /^#\[/ { next }
            $0 ~ pattern && !host_api_next { print FILENAME ":" FNR ":" $0 }
            { host_api_next = 0 }
        ' pattern="$host_api_only_public_pattern" "${host_api_only_files[@]}"
    )"
else
    matches=""
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVisor host glue must stay behind host-api" >&2
    exit 1
fi

if ! grep -q 'all(feature = "host-api", feature = "service-payload")' "$framevisor_lib"; then
    echo "error: FrameVisor must reject builds that combine host-api and guest payload mode" >&2
    exit 1
fi

macro_lifecycle_leak_pattern='ostd::boot::|__init_current_service|__shutdown_current_service|enter_current_service|shutdown_current_service'

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$macro_lifecycle_leak_pattern" "$repo_root/kernel/comps/framevisor/macros/src" || true)"
else
    matches="$(grep -RInE "$macro_lifecycle_leak_pattern" "$repo_root/kernel/comps/framevisor/macros/src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: #[ostd::main] for FrameVM must not expand host lifecycle calls into service code" >&2
    exit 1
fi

if ! grep -q '__ostd_main' "$repo_root/kernel/comps/framevisor/macros/src/lib.rs"; then
    echo "error: #[ostd::main] must export the generic service-module entry symbol" >&2
    exit 1
fi

if grep -q 'fn __ostd_main() -> ()' "$repo_root/kernel/comps/framevisor/macros/src/lib.rs"; then
    echo "error: #[ostd::main] must keep Host OSTD's non-returning __ostd_main shape" >&2
    exit 1
fi

if ! grep -q 'fn __ostd_main() -> !' "$repo_root/kernel/comps/framevisor/macros/src/lib.rs"; then
    echo "error: #[ostd::main] must export __ostd_main as a non-returning OSTD entry" >&2
    exit 1
fi

if ! grep -q '__ostd_dynamic_main' "$repo_root/ostd/src/loader/symbol.rs"; then
    echo "error: dynamic modules must use a generic loader trampoline instead of changing __ostd_main" >&2
    exit 1
fi

if grep -RIn '__framevm_main' "$repo_root/ostd/src/loader" "$repo_root/kernel/comps/framevisor/macros/src" >/dev/null 2>&1; then
    echo "error: the dynamic module system must not use FrameVM-specific entry symbols" >&2
    exit 1
fi

if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n 'aster_framevisor|FrameVisor|FrameVM|framevisor|framevm' "$repo_root/ostd/src" || true)"
else
    matches="$(grep -RInE 'aster_framevisor|FrameVisor|FrameVM|framevisor|framevm' "$repo_root/ostd/src" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: Host OSTD must not hard-code FrameVisor or FrameVM dynamic-module policy" >&2
    exit 1
fi

if ! grep -q 'symbols::add_crate_alias("ostd", "aster_framevisor")' "$framevisor_lib"; then
    echo "error: FrameVisor host initialization must privately register its service OSTD symbol alias" >&2
    exit 1
fi

alias_lookup_line="$(
    grep -n 'for (import_crate, target_crates) in crate_aliases' \
        "$repo_root/ostd/src/symbols/mod.rs" \
        | head -n1 \
        | cut -d: -f1
)"
generic_crate_lookup_line="$(
    grep -n 'normalize_rust_v0_mangled_crate_disambiguators(name)' \
        "$repo_root/ostd/src/symbols/mod.rs" \
        | head -n1 \
        | cut -d: -f1
)"
if [ -z "$alias_lookup_line" ] \
    || [ -z "$generic_crate_lookup_line" ] \
    || [ "$alias_lookup_line" -ge "$generic_crate_lookup_line" ]; then
    echo "error: dynamic ostd crate alias lookup must run before generic crate-path fallback" >&2
    exit 1
fi

if grep -RIn 'set_current_domain(DomainId::FrameVM' "$framevisor_src" >/dev/null 2>&1; then
    grep -RIn 'set_current_domain(DomainId::FrameVM' "$framevisor_src"
    echo "error: FrameVM domains must be inferred from private task binding, not global domain mutation" >&2
    exit 1
fi

if grep -RIn 'set_current_domain' "$framevisor_src/boot.rs" >/dev/null 2>&1; then
    grep -RIn 'set_current_domain' "$framevisor_src/boot.rs"
    echo "error: service boot/shutdown must not expose or mutate RRef domain state" >&2
    exit 1
fi

if grep -RIn 'set_current_domain' "$framevisor_src" >/dev/null 2>&1; then
    grep -RIn 'set_current_domain' "$framevisor_src"
    echo "error: FrameVisor must derive RRef domains from private task binding, not global domain mutation" >&2
    exit 1
fi

if ! grep -q 'init_current_domain_provider(current_domain)' "$framevisor_src/rref_registry.rs"; then
    echo "error: RRef ownership must use the FrameVisor-private current-domain provider" >&2
    exit 1
fi

if grep -q 'default_task_group_id' "$framevisor_src/rref_registry.rs"; then
    echo "error: RRef current-domain provider must not infer service ownership from the default VM" >&2
    exit 1
fi

if ! grep -q "pub type RRefDropFn" "$exchangeable_src"; then
    echo "error: RRef metadata must record a typed drop entry for RedLeaf-style reclaim" >&2
    exit 1
fi

if ! grep -q "fn run_registered_drop_entry" "$exchangeable_src" \
    || ! grep -q "self.run_registered_drop_entry(registry)" "$exchangeable_src" \
    || ! grep -q "fn unregister(&self, id: RRefId) -> RRefMetadata" "$exchangeable_src"; then
    echo "error: RRef Drop must go through the typed drop metadata entry before unregistering" >&2
    exit 1
fi

if grep -q 'core::mem::forget(value)' "$exchangeable_src" \
    || ! grep -q 'rref_drop_unregisters_metadata_even_from_non_owner_domain' "$framevisor_src/rref_registry.rs"; then
    echo "error: RRef Drop must release typed metadata even when the current executing domain is not the owner" >&2
    exit 1
fi

if ! grep -q 'rref_borrow_blocked_transfer_returns_original_token' "$framevisor_src/rref_registry.rs" \
    || ! grep -q 'RegistryError::TransferBlocked' "$framevisor_src/rref_registry.rs"; then
    echo "error: RRef borrowed-transfer failure must return the original token and preserve ownership" >&2
    exit 1
fi

if ! grep -q "fn take_registered_metadata_for_value_return" "$exchangeable_src" \
    || ! grep -q "self.take_registered_metadata_for_value_return()" "$exchangeable_src"; then
    echo "error: RRef try_into_inner must remove metadata without running the typed drop entry" >&2
    exit 1
fi

if grep -Eq '^pub fn (register|unregister|begin_borrow|end_borrow|reclaim_domain)\(' \
    "$framevisor_src/rref_registry.rs"; then
    echo "error: RRef registry mutating operations must not be exposed as module-level helpers" >&2
    exit 1
fi

if ! grep -q "allocation_addr" "$exchangeable_src"; then
    echo "error: RRef metadata must record an allocation address or exchange-heap handle" >&2
    exit 1
fi

if ! grep -q "value: Option<Box<T>>" "$exchangeable_src"; then
    echo "error: RRef must own a stable exchange allocation, not inline movable token data" >&2
    exit 1
fi

if grep -q 'pub fn transfer_to(self' "$exchangeable_src"; then
    echo "error: RRef ownership transfer must be fallible and return the original RRef on failure" >&2
    exit 1
fi

if grep -q 'pub fn into_inner' "$exchangeable_src" \
    || grep -q 'pub fn try_into_inner(mut self) -> Option<T>' "$exchangeable_src"; then
    echo "error: RRef consuming accessors must be fallible and return the original RRef on failure" >&2
    exit 1
fi

if grep -q 'pub fn is_consumed' "$exchangeable_src"; then
    echo "error: RRef must not expose an empty-token state as part of the public API" >&2
    exit 1
fi

if grep -q 'pub auto trait Exchangeable' "$exchangeable_src" \
    || grep -q '#!\[feature(auto_traits)\]' "$exchangeable_src" \
    || grep -q '#!\[feature(negative_impls)\]' "$exchangeable_src"; then
    echo "error: Exchangeable must be an explicit marker trait, not an auto trait" >&2
    exit 1
fi

if ! grep -q 'pub trait Exchangeable: Send' "$exchangeable_src"; then
    echo "error: Exchangeable values must be Send because RRef moves them across execution contexts" >&2
    exit 1
fi

exchangeable_impl_pattern='impl[[:space:]]*(<[^>]+>)?[[:space:]]+Exchangeable[[:space:]]+for'
if command -v rg >/dev/null 2>&1; then
    matches="$(
        rg -n "$exchangeable_impl_pattern" "$repo_root/kernel" \
            | grep -vE 'kernel/comps/framevisor/exchangeable/src/lib\.rs|kernel/comps/framevsock/src/lib\.rs' \
            || true
    )"
else
    matches="$(
        grep -RInE "$exchangeable_impl_pattern" "$repo_root/kernel" \
            | grep -vE 'kernel/comps/framevisor/exchangeable/src/lib\.rs|kernel/comps/framevsock/src/lib\.rs' \
            || true
    )"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: Exchangeable implementations must stay in the exchange registry and FrameVsock protocol types" >&2
    exit 1
fi

if grep -Eq 'impl[[:space:]]*<[^>]+>[[:space:]]+Exchangeable[[:space:]]+for[[:space:]]+Box[[:space:]]*<' \
    "$exchangeable_src"; then
    grep -En 'impl[[:space:]]*<[^>]+>[[:space:]]+Exchangeable[[:space:]]+for[[:space:]]+Box[[:space:]]*<' \
        "$exchangeable_src"
    echo "error: Exchangeable must not have a blanket Box<T> impl that can smuggle private heaps across domains" >&2
    exit 1
fi

if ! awk '
    /^\[features\]/ { in_features = 1; next }
    /^\[/ { in_features = 0 }
    in_features && /^default[[:space:]]*=[[:space:]]*\[\]/ { found = 1 }
    END { exit !found }
' "$repo_root/kernel/comps/framevsock/Cargo.toml"; then
    echo "error: FrameVsock must default to the service-safe API without backend/RRef exposure" >&2
    exit 1
fi

if ! grep -q 'ostd = { workspace = true, optional = true }' \
    "$repo_root/kernel/comps/framevsock/Cargo.toml" \
    || ! grep -q 'exchangeable = { package = "aster-framevisor-exchangeable", path = "../framevisor/exchangeable", optional = true, default-features = false }' \
        "$repo_root/kernel/comps/framevsock/Cargo.toml" \
    || ! grep -q 'backend-api = \["dep:exchangeable"\]' \
        "$repo_root/kernel/comps/framevsock/Cargo.toml" \
    || ! grep -q 'ostd-clock = \["dep:ostd"\]' \
        "$repo_root/kernel/comps/framevsock/Cargo.toml"; then
    echo "error: FrameVsock default API must not depend on Host OSTD or exchangeable/RRef internals, and backend carrier must be testable without OSTD" >&2
    exit 1
fi

if command -v cargo >/dev/null 2>&1; then
    framevsock_default_dependency_tree="$(
        cargo tree -q -p aster-framevsock --no-default-features -e normal 2>/dev/null || true
    )"
    if echo "$framevsock_default_dependency_tree" \
        | grep -Eq '(^|[[:space:]])(exchangeable|ostd)[[:space:]]+v'; then
        echo "$framevsock_default_dependency_tree" \
            | grep -E '(^|[[:space:]])(exchangeable|ostd)[[:space:]]+v' >&2
        echo "error: FrameVsock service-safe default dependency tree must not include RRef or Host OSTD dependencies" >&2
        exit 1
    fi
fi

if ! grep -q 'aster-framevisor-exchangeable = { workspace = true, optional = true }' \
    "$repo_root/kernel/comps/framevisor/Cargo.toml" \
    || ! grep -q 'aster-framevsock = { workspace = true, features = \["backend-api", "ostd-clock"\], optional = true }' \
        "$repo_root/kernel/comps/framevisor/Cargo.toml"; then
    echo "error: FrameVisor RRef/FrameVsock backend dependencies must be host-api-only" >&2
    exit 1
fi

if ! grep -q 'ostd = { workspace = true, optional = true }' \
    "$repo_root/kernel/comps/framevisor/exchangeable/Cargo.toml" \
    || ! grep -q 'default = \["ostd-domain"\]' \
        "$repo_root/kernel/comps/framevisor/exchangeable/Cargo.toml" \
    || ! grep -q 'ostd-domain = \["dep:ostd"\]' \
        "$repo_root/kernel/comps/framevisor/exchangeable/Cargo.toml"; then
    echo "error: RRef exchangeable must keep OSTD domain tracking as the default while allowing backend carrier tests without OSTD" >&2
    exit 1
fi

if grep -q 'pub use exchangeable::RRef' "$repo_root/kernel/comps/framevsock/src/lib.rs"; then
    echo "error: FrameVsock must not re-export RRef to service consumers" >&2
    exit 1
fi

if grep -En 'FrameVM|FrameVisor|framevm|framevisor' "$repo_root/kernel/comps/framevsock/src/lib.rs"; then
    echo "error: service-visible FrameVsock protocol API must stay OS-service generic" >&2
    exit 1
fi

if ! awk '
    /^#\[cfg\(feature = "backend-api"\)\]/ {
        backend_gated = 1
        next
    }
    backend_gated && /^[[:space:]]*(\/\/\/|#\[inline\]|$)/ {
        next
    }
    /pub (const|fn) (GUEST_CID_BASE|is_guest_cid|cid_to_vm_id|vm_id_to_cid)([[:space:]:\(]|$)/ {
        if (!backend_gated) {
            print FILENAME ":" FNR ":" $0
            failed = 1
        }
    }
    {
        backend_gated = 0
    }
    END { exit failed ? 1 : 0 }
' "$repo_root/kernel/comps/framevsock/src/lib.rs"; then
    echo "error: FrameVsock VM-ID routing helpers must be backend-api only" >&2
    exit 1
fi

if ! grep -q '#\[cfg(feature = "backend-api")\]' "$repo_root/kernel/comps/framevsock/src/lib.rs" \
    || ! grep -q 'pub mod ring' "$repo_root/kernel/comps/framevsock/src/lib.rs" \
    || ! grep -q 'features = \["backend-api", "ostd-clock"\]' "$repo_root/kernel/comps/framevisor/Cargo.toml" \
    || ! grep -q 'features = \["backend-api", "ostd-clock"\]' "$repo_root/kernel/Cargo.toml"; then
    echo "error: FrameVsock RRef queue APIs must be gated behind backend-api and enabled only by host/backend crates" >&2
    exit 1
fi

if grep -Eq '^[[:space:]]*pub[[:space:]]+fn[[:space:]]+(push|push_batch|push_batch_optimized|push_with)[[:space:]]*\(' \
    "$framevsock_ring_src"; then
    grep -En '^[[:space:]]*pub[[:space:]]+fn[[:space:]]+(push|push_batch|push_batch_optimized|push_with)[[:space:]]*\(' \
        "$framevsock_ring_src"
    echo "error: FrameVsock ring must not expose push APIs that bypass fallible RRef ownership transfer" >&2
    exit 1
fi

if ! grep -q 'pub fn push_transfer_to(&self, packet: RRef<T>, owner: DomainId) -> Result<(), RRef<T>>' \
    "$framevsock_ring_src" \
    || ! grep -q 'try_transfer_to(owner)' "$framevsock_ring_src" \
    || ! grep -q 'fn push_with' "$framevsock_ring_src" \
    || ! grep -q 'RingSlot::Hole' "$framevsock_ring_src" \
    || ! grep -q 'push_prepare_failed' "$framevsock_ring_src" \
    || ! grep -q 'pop_hole' "$framevsock_ring_src"; then
    echo "error: FrameVsock ring must preserve RRef ownership on failed transfer and publish ordered holes after reserved-slot failures" >&2
    exit 1
fi

control_drain_reserved_uses="$(
    grep -c 'control_queue_reserved_len()' "$framevisor_src/vsock/mod.rs" || true
)"
control_drain_notify_uses="$(
    grep -c 'notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);' \
        "$framevisor_src/vsock/mod.rs" || true
)"
if ! grep -q 'control_queue_reserved_len' "$framevisor_src/vsock/queues.rs" \
    || [ "$control_drain_reserved_uses" -lt 4 ] \
    || [ "$control_drain_notify_uses" -lt 8 ]; then
    echo "error: FrameVsock control queue drains must notify host senders just like data queue drains" >&2
    exit 1
fi

require_syscall_patterns_or_unsupported \
    "$framevm_src/syscall/madvise.rs" \
    "FrameVM madvise must match kernel DONTNEED and dummy-advice semantics" \
    "discard_range(vm_space, addr, len)" \
    "is_user_range_fully_mapped"

while IFS= read -r syscall_file; do
    syscall_rel="${syscall_file#"$framevm_syscall_dir"/}"
    kernel_syscall_rels=("$syscall_rel")

    case "$syscall_rel" in
        futex_sys.rs)
            kernel_syscall_rels=("futex.rs")
            ;;
        getrlimit.rs | setrlimit.rs)
            kernel_syscall_rels=("prlimit64.rs")
            ;;
        preadwrite.rs)
            kernel_syscall_rels=("pread64.rs" "pwrite64.rs")
            ;;
        rseq.rs)
            if ! grep -q "Errno::ENOSYS" "$syscall_file"; then
                echo "error: FrameVM rseq has no kernel syscall source and must remain unsupported" >&2
                exit 1
            fi
            kernel_syscall_rels=()
            ;;
        signal_sys.rs)
            kernel_syscall_rels=("rt_sigaction.rs" "rt_sigprocmask.rs")
            ;;
    esac

    for kernel_syscall_rel in "${kernel_syscall_rels[@]}"; do
        if [ ! -f "$kernel_syscall_dir/$kernel_syscall_rel" ]; then
            echo "error: FrameVM syscall module $syscall_rel has no kernel syscall source $kernel_syscall_rel" >&2
            echo "error: copy/source-reuse kernel syscall behavior, or add an explicit boundary-check alias for a justified grouping" >&2
            exit 1
        fi
    done
done < <(find "$framevm_syscall_dir" -type f -name '*.rs' | sort)

require_syscall_patterns_or_unsupported \
    "$framevm_src/syscall/chdir.rs" \
    "FrameVM chdir must update per-thread cwd state" \
    "with_current_fs_info" \
    "\.chdir"

require_syscall_patterns_or_unsupported \
    "$framevm_src/syscall/getcwd.rs" \
    "FrameVM getcwd must read per-thread cwd state and match the kernel write length rule" \
    "current_working_directory" \
    "size.min(bytes.len())"

if ! grep -q "SyscallReturn::NoReturn" "$framevm_src/syscall/execve.rs" \
    || ! grep -q "thread_name_from_executable_path" "$framevm_src/task.rs" \
    || ! grep -q "executable_path: &str" "$framevm_src/task.rs" \
    || ! grep -q "Ok(SyscallReturn::NoReturn) => {}" "$framevm_src/syscall.rs"; then
    echo "error: FrameVM execve must follow the kernel NoReturn path and executable-derived thread names" >&2
    exit 1
fi

if grep -q "dumpable" "$framevm_src/process.rs" \
    || ! grep -q "PR_GET_DUMPABLE => Ok(SyscallReturn::Return(0))" "$framevm_src/syscall/prctl.rs" \
    || ! grep -q "matches!(dumpable, 0 | 1)" "$framevm_src/syscall/prctl.rs"; then
    echo "error: FrameVM prctl dumpable behavior must match the current kernel implementation" >&2
    exit 1
fi

if ! grep -q "parse_parent_death_signal" "$framevm_src/syscall/prctl.rs" \
    || ! grep -q "(arg as u8) as u32" "$framevm_src/syscall/prctl.rs" \
    || ! grep -q "(1..=64).contains(&signal)" "$framevm_src/syscall/prctl.rs" \
    || ! grep -q "(1..=64).contains(&signal)" "$framevm_src/process.rs"; then
    echo "error: FrameVM prctl parent-death signal parsing must match the kernel SigNum range and u8 truncation" >&2
    exit 1
fi

if ! grep -q "parse_keep_capabilities" "$framevm_src/syscall/prctl.rs" \
    || ! grep -q "arg as u32" "$framevm_src/syscall/prctl.rs" \
    || ! grep -q "parse_securebits" "$framevm_src/syscall/prctl.rs" \
    || ! grep -q "arg as u16" "$framevm_src/syscall/prctl.rs"; then
    echo "error: FrameVM prctl keepcaps and securebits parsing must match current kernel truncation semantics" >&2
    exit 1
fi

if ! grep -q "thread_name_write_len" "$framevm_src/syscall/prctl.rs"; then
    echo "error: FrameVM prctl GET_NAME must write the kernel-style C string length" >&2
    exit 1
fi

if grep -q "aster-time" "$framevm_src/../Cargo.toml" \
    || grep -q "framevm.realtime_base_ns" "$framevm_src/time.rs" \
    || grep -q "framevm.monotonic_base_ns" "$framevm_src/time.rs" \
    || ! grep -q "kernel.realtime_base_ns" "$repo_root/kernel/src/vmm/mod.rs" \
    || ! grep -q "kernel.monotonic_base_ns" "$repo_root/kernel/src/vmm/mod.rs" \
    || ! grep -q "kernel.realtime_base_ns" "$framevm_src/time.rs" \
    || ! grep -q "kernel.monotonic_base_ns" "$framevm_src/time.rs" \
    || ! grep -q "set_boot_info_with_extra" "$repo_root/kernel/src/vmm/mod.rs" \
    || ! grep -q "set_boot_info_with_mode_and_extra" "$repo_root/kernel/src/vmm/mod.rs"; then
    echo "error: FrameVM realtime must be injected through the OSTD boot surface, not by linking kernel time" >&2
    exit 1
fi

if ! grep -q "pub fn realtime_ns" "$framevm_src/time.rs" \
    || ! grep -q "parse_realtime_base_from_cmdline" "$framevm_src/time.rs" \
    || ! grep -q "monotonic_deadline_from_realtime_ns" "$framevm_src/time.rs" \
    || ! grep -q "time::realtime_ns" "$framevm_src/syscall/gettimeofday.rs" \
    || ! grep -q "read_realtime_clock" "$framevm_src/syscall/clock_gettime.rs" \
    || ! grep -q "CLOCK_REALTIME" "$framevm_src/syscall/nanosleep.rs"; then
    echo "error: FrameVM realtime syscalls must use the injected realtime base instead of monotonic time" >&2
    exit 1
fi

if grep -q "^    keep_capabilities: bool," "$framevm_src/process.rs" \
    || ! grep -q "SECUREBITS_LOCK_MASK" "$framevm_src/process.rs" \
    || ! grep -q "SECUREBITS_VALID_MASK" "$framevm_src/process.rs" \
    || ! grep -q "SECUREBIT_KEEP_CAPS" "$framevm_src/process.rs" \
    || ! grep -q "SECUREBIT_NO_SETUID_FIXUP" "$framevm_src/process.rs" \
    || ! grep -q "fn no_setuid_fixup" "$framevm_src/process.rs" \
    || ! grep -q "self.no_setuid_fixup()" "$framevm_src/process.rs" \
    || ! grep -q "CAP_SETPCAP" "$framevm_src/process.rs" \
    || ! grep -q "try_store_securebits" "$framevm_src/process.rs"; then
    echo "error: FrameVM securebits must follow kernel KEEP_CAPS, NO_SETUID_FIXUP, and locked-bit semantics" >&2
    exit 1
fi

if grep -q "fn is_privileged" "$framevm_src/process.rs" \
    || grep -q "self.is_privileged()" "$framevm_src/process.rs"; then
    echo "error: FrameVM credential changes must use kernel capability checks, not euid-root shortcuts" >&2
    exit 1
fi

if ! grep -q "& Self::all().0" "$framevm_src/process.rs"; then
    echo "error: FrameVM capability ABI import must truncate unknown bits like the kernel" >&2
    exit 1
fi

if ! grep -q "ctx.process.set_groups(groups);" "$framevm_src/syscall/setgroups.rs"; then
    echo "error: FrameVM setgroups must match the current kernel collection update semantics" >&2
    exit 1
fi

if ! grep -q "O_NOFOLLOW" "$framevm_src/syscall/open.rs" \
    || ! grep -q "metadata_no_follow" "$framevm_src/syscall/open.rs" \
    || ! grep -q "Errno::ELOOP" "$framevm_src/syscall/open.rs"; then
    echo "error: FrameVM open must implement O_NOFOLLOW tail-symlink semantics" >&2
    exit 1
fi

if ! grep -q "Errno::ENOENT" "$framevm_src/syscall/symlink.rs" \
    || ! grep -q "target.is_empty()" "$framevm_src/syscall/symlink.rs"; then
    echo "error: FrameVM symlink must reject empty targets like the kernel" >&2
    exit 1
fi

if ! syscall_file_is_explicitly_unsupported "$framevm_src/syscall/getrandom.rs" \
    && { ! grep -q "device::getrandom" "$framevm_src/syscall/getrandom.rs" \
        || ! grep -q "device::geturandom" "$framevm_src/syscall/getrandom.rs" \
        || ! grep -q "fn read_seed_from_hardware" "$framevm_src/device.rs" \
        || ! grep -q "ostd::arch::read_random" "$framevm_src/device.rs" \
        || ! grep -q "fn read_seed_from_timestamp" "$framevm_src/device.rs" \
        || ! grep -q "ostd::arch::read_tsc" "$framevm_src/device.rs"; }; then
    echo "error: FrameVM getrandom must follow kernel random-source structure and prefer hardware entropy" >&2
    exit 1
fi

require_syscall_pattern_or_unsupported \
    "$framevm_src/syscall/mprotect.rs" \
    "protect_range(vm_space, addr, len" \
    "FrameVM mprotect must change VM mappings or stay unsupported"

require_syscall_pattern_or_unsupported \
    "$framevm_src/syscall/munmap.rs" \
    "unmap_range(vm_space, addr, len)" \
    "FrameVM munmap must change VM mappings or stay unsupported"

require_syscall_patterns_or_unsupported \
    "$framevm_src/syscall/poll.rs" \
    "FrameVM poll must use file readiness and poller state, not unconditional readiness" \
    "Poller::new(timeout)?" \
    "file.poll_revents(poll_fd.events, poller)" \
    "Err(_) => poll_fd.revents_for_missing_file()" \
    "let ready_count = do_poll(&mut poll_fds, timeout.as_ref());" \
    "Ok(ready_count? as isize)"

if ! grep -q "time::sleep_until_ns" "$framevm_src/syscall/nanosleep.rs" \
    || ! grep -q "TimeoutRegistration::new" "$framevm_src/pollee.rs" \
    || ! grep -q "Poller::new(timeout)?" "$framevm_src/syscall/poll.rs"; then
    echo "error: FrameVM sleep and poll timeouts must use virtual timer wakeups and propagate deadline errors" >&2
    exit 1
fi

if grep -Eq 'Task::yield_now\(\)|timeout_expired|unwrap_or\(u64::MAX\)' \
    "$framevm_src/syscall/nanosleep.rs" \
    "$framevm_src/pollee.rs" \
    "$framevm_src/time.rs"; then
    grep -En 'Task::yield_now\(\)|timeout_expired|unwrap_or\(u64::MAX\)' \
        "$framevm_src/syscall/nanosleep.rs" \
        "$framevm_src/pollee.rs" \
        "$framevm_src/time.rs"
    echo "error: FrameVM timeout paths must not busy-wait or silently extend invalid deadlines" >&2
    exit 1
fi

if grep -q "for task_group_id in vm::active_task_group_ids()" \
    "$framevisor_src/task/scheduler.rs"; then
    echo "error: FrameVisor virtual timer must not broadcast ticks to unrelated task groups" >&2
    exit 1
fi

if grep -q "let _ = scheduler;" "$framevisor_src/task/scheduler.rs" \
    || grep -q "BTreeSet<VmId>" "$framevisor_src/task/scheduler.rs" \
    || grep -q "then_some(HostSchedulerAdapter" "$framevisor_src/task/scheduler.rs" \
    || grep -q "struct HostSchedulerAdapter" "$framevisor_src/task/scheduler.rs" \
    || grep -q "struct HostTimerRunQueue" "$framevisor_src/task/scheduler.rs" \
    || ! grep -q "BTreeMap<VmId, &'static dyn Scheduler<Task>>" "$framevisor_src/task/scheduler.rs" \
    || ! grep -q "service_schedulers.insert(vm_id, scheduler).is_none()" "$framevisor_src/task/scheduler.rs"; then
    echo "error: FrameVisor must retain and use the service-injected scheduler, not a dummy host adapter" >&2
    exit 1
fi

if ! grep -q "ostd::task::scheduler::inject_scheduler(scheduler())" \
        "$framevm_src/scheduler.rs" \
    || ! grep -q "ostd::task::scheduler::enable_preemption_on_cpu()" \
        "$framevm_src/scheduler.rs"; then
    echo "error: FrameVM must use the standard OSTD scheduler injection path" >&2
    exit 1
fi

if ! grep -q "inject_virtual_timer_tick_for_current_task_group()" \
        "$framevisor_src/task/scheduler.rs" \
    || ! grep -q "current_task_group_for_timer_tick()" \
        "$framevisor_src/task/scheduler.rs" \
    || ! grep -q "task_group.inject_timer_tick()" \
        "$framevisor_src/task/scheduler.rs" \
    || ! grep -q "current_task_group_for_virtual_interrupt()" \
        "$framevisor_src/task/scheduler.rs" \
    || ! grep -q "VIRTUAL_TIMER_DRIVER_CPUS" \
        "$framevisor_src/task/scheduler.rs" \
    || ! grep -q "frame_task_group_should_run_iht" \
        "$repo_root/kernel/src/sched/sched_class/mod.rs" \
    || ! grep -q "frame_group_needs_iht" \
        "$repo_root/kernel/src/sched/sched_class/mod.rs" \
    || ! grep -q "timer_work_tracks_scheduler_ticks" \
        "$framevisor_src/vm/task_group.rs"; then
    echo "error: FrameVisor virtual timer dispatch must target the current task group and let host scheduling drive IHT" >&2
    exit 1
fi

if ! awk '
/fn drain_timer_ticks\(&self\)/ { in_fn = 1 }
    in_fn && /take_pending_timer_ticks\(\)/ { took_ticks = 1 }
    in_fn && /dispatch_timer_ticks\(self\.task_group_id, ticks\)/ { dispatched = 1 }
    in_fn && /^    }/ { in_fn = 0 }
END { exit !(took_ticks && dispatched) }
' "$framevisor_src/iht/mod.rs"; then
    echo "error: host IHT must drain coalesced virtual timer ticks in task context" >&2
    exit 1
fi

if grep -q "VIRTUAL_TIMER_DRIVER_REGISTERED" "$framevisor_src/task/scheduler.rs"; then
    echo "error: FrameVisor virtual timer driver registration must be per host CPU, not a global once" >&2
    exit 1
fi

if ! awk '
/pub\(crate\) fn dispatch_timer_ticks/ { inside = 1 }
inside && /crate::timer::advance_timer_ticks\(task_group_id, ticks\)/ { advance = NR }
inside && /let Some\(scheduler\) = scheduler_for_vm\(task_group_id.vm_id\(\)\)/ { scheduler = NR }
inside && /CpuId::from_raw\(task_group_id.vcpu_id\(\) as u32\)/ { target_cpu = NR }
inside && /scheduler.mut_local_rq_with\(/ { target_rq = NR }
inside && /^fn enter_virtual_cpu_override/ { inside = 0 }
END {
    exit !(advance && scheduler && target_cpu && target_rq && advance < scheduler && scheduler < target_rq)
}
' "$framevisor_src/task/scheduler.rs"; then
    echo "error: FrameVisor timer callbacks must update the injected OSTD-shaped scheduler through mut_local_rq_with" >&2
    exit 1
fi

if grep -q "current_vm_id().or_else(default_vm_id)" "$framevisor_src/timer.rs" \
    || grep -q "fn default_vm_id()" "$framevisor_src/timer.rs"; then
    echo "error: FrameVisor service jiffies must not fall back to a default VM/vCPU" >&2
    exit 1
fi

if grep -q "default_task_group_id" "$framevisor_src/boot.rs"; then
    echo "error: FrameVisor service boot/lifecycle entry must require an explicit current task-group binding" >&2
    exit 1
fi

if grep -q 'flags & !TIMER_ABSTIME' "$framevm_src/syscall/nanosleep.rs"; then
    echo "error: FrameVM clock_nanosleep must match Linux and ignore unknown flag bits" >&2
    exit 1
fi

if grep -q 'remove_if_present(raw_fd)' "$framevm_src/syscall/close.rs"; then
    echo "error: FrameVM close must report EBADF for descriptors that are already closed" >&2
    exit 1
fi

if grep -R -n 'ensure_stdio_handle\|write_stdio' "$framevm_src" \
    || ! grep -q "sys_fcntl(raw_fd: RawFileDesc, cmd: i32, arg: u64)" "$framevm_src/syscall/fcntl.rs" \
    || ! grep -q "F_GETLK | F_SETLK | F_SETLKW | F_ADD_SEALS | F_GET_SEALS" "$framevm_src/syscall/fcntl.rs"; then
    echo "error: FrameVM stdio descriptors must stay fd-table objects after close" >&2
    exit 1
fi

if grep -q '(0..=2).contains(&fd)' "$framevm_src/syscall.rs" \
    || grep -q '(0..=2).contains(&fd)' "$framevm_src/syscall/ioctl.rs"; then
    echo "error: FrameVM fd metadata/ioctl paths must not synthesize closed stdio descriptors" >&2
    exit 1
fi

if grep -R -n 'Task::yield_now()' "$framevm_src"; then
    echo "error: FrameVM runtime must not use host task yield to drive service scheduling" >&2
    exit 1
fi

if ! grep -q "close_allocated_pipe_fds" "$framevm_src/syscall/pipe.rs"; then
    echo "error: FrameVM pipe must close allocated descriptors if fd writeback faults" >&2
    exit 1
fi

if ! grep -q "checked_user_page_range(addr, len, false, Errno::EINVAL)" "$framevm_src/vm.rs"; then
    echo "error: FrameVM munmap overflow/out-of-user ranges must return EINVAL like the kernel" >&2
    exit 1
fi

if ! grep -q "SUPPORTED_OPTIONS" "$framevm_src/syscall/wait4.rs" \
    || ! grep -q "write_empty_rusage" "$framevm_src/syscall/wait4.rs" \
    || ! grep -q "args\\[3\\]" "$framevm_src/syscall/arch/x86.rs"; then
    echo "error: FrameVM wait4 must validate option bits and handle the rusage argument" >&2
    exit 1
fi

if ! grep -q "ResourceType::FileSize" "$framevm_src/syscall/truncate.rs" \
    || ! grep -q "current_resource_limits" "$framevm_src/syscall/truncate.rs" \
    || ! grep -q "Errno::EFBIG" "$framevm_src/syscall/truncate.rs"; then
    echo "error: FrameVM truncate/ftruncate must enforce RLIMIT_FSIZE like the kernel syscall" >&2
    exit 1
fi

if grep -q "backlog.max(0)" "$framevm_src/syscall/listen.rs" \
    || ! grep -q "listen(backlog as usize)" "$framevm_src/syscall/listen.rs"; then
    echo "error: FrameVM listen syscall glue must pass backlog like the kernel syscall" >&2
    exit 1
fi

if ! grep -q "inject_frame_task_group_share_updater(update_frame_task_group_sched_policy)" \
    "$repo_root/kernel/src/thread/framevm_task.rs" \
    || ! grep -q "pub(crate) fn update_frame_task_group_share" "$framevisor_src/task/mod.rs" \
    || ! grep -q "task::update_frame_task_group_share(self.id)" "$framevisor_src/vm/task_group.rs"; then
    echo "error: runtime FrameVM share updates must refresh existing host scheduler state from every FrameTaskGroup share setter" >&2
    exit 1
fi

if ! grep -q "task_group.update_weight(scheduler_weight_for_frame_task_group(task_group_id))" \
    "$repo_root/kernel/src/thread/framevm_task.rs" \
    || ! grep -q "ostd_tasks_in_frame_task_group(task_group_id)" \
        "$repo_root/kernel/src/thread/framevm_task.rs" \
    || ! grep -q "thread.set_task_group(task_group.clone())" \
        "$repo_root/kernel/src/thread/framevm_task.rs"; then
    echo "error: FrameVM share updater must update TaskGroup weight and rebind existing scheduler tasks" >&2
    exit 1
fi

if ! grep -q "is_framevm_task_priority_boosted(&task)" \
    "$repo_root/kernel/src/thread/framevm_task.rs"; then
    echo "error: FrameVM share updater must preserve IRQ-disabled priority boosts" >&2
    exit 1
fi

if grep -q "update_frame_task_group_sched_policy(snapshot.id())" \
    "$repo_root/kernel/src/vmm/mod.rs"; then
    echo "error: FrameVM share updates must not rely on per-call-site manual host scheduler refreshes" >&2
    exit 1
fi

framevm_share_test_script="$repo_root/test/initramfs/src/framevm_share_test.sh"
if ! grep -q "share_test: passed=1" "$framevm_share_test_script" \
    || ! grep -q '\^state: completed\$' "$framevm_share_test_script" \
    || ! grep -q '\^vm_count: 0\$' "$framevm_share_test_script" \
    || ! grep -q "dynamic_share_update=1" "$framevm_share_test_script" \
    || ! grep -q "host_scheduler_path_exercised=1" "$framevm_share_test_script" \
    || ! grep -q "host_weight_matches_share=1" "$framevm_share_test_script" \
    || ! grep -q 'group0_share=${group0_share}' "$framevm_share_test_script" \
    || ! grep -q 'group1_share=${group1_share}' "$framevm_share_test_script" \
    || ! grep -q "group0_host_weight=" "$framevm_share_test_script" \
    || ! grep -q "group1_host_weight=" "$framevm_share_test_script" \
    || ! grep -q "group0_actual_host_weight=" "$framevm_share_test_script" \
    || ! grep -q "group1_actual_host_weight=" "$framevm_share_test_script" \
    || ! grep -q "group0_runtime_cycles=" "$framevm_share_test_script" \
    || ! grep -q "group1_runtime_cycles=" "$framevm_share_test_script" \
    || ! grep -q "group0_loops=" "$framevm_share_test_script" \
    || ! grep -q "group1_loops=" "$framevm_share_test_script" \
    || ! grep -q "expected_group1_per_mille=" "$framevm_share_test_script" \
    || ! grep -q "actual_runtime_group1_per_mille=" "$framevm_share_test_script" \
    || ! grep -q "actual_loop_group1_per_mille=" "$framevm_share_test_script" \
    || ! grep -q "tolerance_per_mille=" "$framevm_share_test_script"; then
    echo "error: FrameVM share test must require completion, VM exit, dynamic share update, host scheduler weight evidence, and full ratio-report fields" >&2
    exit 1
fi

if grep -q "raising hard resource limits is not supported yet" "$framevm_src/resource.rs" \
    || ! grep -q "CAP_SYS_RESOURCE" "$framevm_src/process.rs" \
    || ! grep -q "has_sys_resource" "$framevm_src/process.rs" \
    || ! grep -q "can_raise_hard_limit" "$framevm_src/resource.rs" \
    || ! grep -q "has_sys_resource" "$framevm_src/syscall/prlimit64.rs"; then
    echo "error: FrameVM resource-limit updates must follow kernel CAP_SYS_RESOURCE semantics" >&2
    exit 1
fi

if grep -q "StatusFlags::O_PATH).*EOPNOTSUPP" "$framevm_src/syscall/open.rs" \
    || ! grep -q "alloc_path" "$framevm_src/syscall/open.rs"; then
    echo "error: FrameVM open must support O_PATH using a service-local path file" >&2
    exit 1
fi

if grep -q "metadata.kind != FileKind::Special" "$framevm_src/syscall/access.rs" \
    || ! grep -q "metadata.mode & 0o222" "$framevm_src/syscall/access.rs"; then
    echo "error: FrameVM access must honor ordinary rootfs write permission bits" >&2
    exit 1
fi

if grep -q "/bin/syscall-smoke" "$framevm_src/lib.rs" \
    || ! grep -q "kernel-busybox-rootfs ok" "$framevm_src/lib.rs" \
    || ! grep -q "kernel-busybox-smoke passed" "$framevm_src/lib.rs" \
    || ! grep -q "cat /proc/mounts" "$framevm_src/lib.rs"; then
    echo "error: FrameVM BusyBox smoke must cover rootfs/shell startup without requiring full syscall smoke" >&2
    exit 1
fi

if ! grep -q "/bin/vsock-probe" "$framevm_src/lib.rs" \
    || ! grep -q "vsock-probe passed" "$framevm_rootfs_image" \
    || ! grep -q "found_vsock_probe" "$repo_root/kernel/src/vmm/mod.rs" \
    || ! grep -q "found_vsock_probe=1" "$framevm_busybox_smoke_script" \
    || ! grep -q "AF_VSOCK" "$framevm_rootfs_image" \
    || ! grep -q "ENOTCONN" "$framevm_rootfs_image" \
    || ! grep -q "ECONNREFUSED" "$framevm_rootfs_image"; then
    echo "error: FrameVM BusyBox smoke must run a targeted AF_VSOCK guest regression without exposing FrameVisor internals" >&2
    exit 1
fi

framevm_foreground_smoke_script="$repo_root/test/initramfs/src/framevm_foreground_smoke.sh"
if ! grep -q "framevm_foreground_smoke" "$repo_root/Makefile" \
    || ! grep -q "framevm_foreground_smoke" "$repo_root/test/initramfs/nix/initramfs.nix" \
    || ! grep -q "FrameVM foreground smoke test passed" "$framevm_foreground_smoke_script" \
    || ! grep -q "require_status \"~ # ls /\"" "$framevm_foreground_smoke_script" \
    || ! grep -q "require_status \"~ # exit\"" "$framevm_foreground_smoke_script" \
    || ! grep -q "require_status \"bin\"" "$framevm_foreground_smoke_script" \
    || ! grep -q "require_status \"etc\"" "$framevm_foreground_smoke_script" \
    || ! grep -q "require_status \"proc\"" "$framevm_foreground_smoke_script" \
    || ! grep -q "require_status \"tmp\"" "$framevm_foreground_smoke_script" \
    || ! grep -q "parse_console_input_request" "$repo_root/kernel/src/fs/fs_impls/procfs/framevm.rs"; then
    echo "error: FrameVM foreground /proc control path must have an automated shell-entry smoke test" >&2
    exit 1
fi

guest_artifact_leak_pattern='AF_FRAMEVSOCK|FRAMEVSOCK|PRIVATE_VSOCK|LEGACY_PRIVATE_VSOCK|LEGACY_PRIVATE_FAMILY|FrameVisor|FrameTaskGroup|FrameTaskGroupId|VmId|Iht|IHT|RRef|RRefId|DomainId|Exchangeable|ostd::vsock|ostd::vm|ostd::iht|ostd::rref'
if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n "$guest_artifact_leak_pattern" "$framevm_rootfs_image" || true)"
else
    matches="$(grep -nE "$guest_artifact_leak_pattern" "$framevm_rootfs_image" || true)"
fi

if [ -n "$matches" ]; then
    echo "$matches"
    echo "error: FrameVM rootfs smoke leaks FrameVisor implementation names" >&2
    exit 1
fi

if ! grep -R -q "is_connect_done" "$framevm_src/net/socket/vsock/stream" \
    || ! grep -R -q "Errno::EALREADY" "$framevm_src/net/socket/vsock/stream" \
    || ! grep -R -q "last_connect_error" "$framevm_src/net/socket/vsock/stream" \
    || ! grep -q "struct BoundPort" "$framevm_src/net/socket/vsock/port.rs" \
    || ! grep -q "alloc_ephemeral_port" "$framevm_src/net/socket/vsock/port.rs" \
    || ! grep -q "Errno::EADDRINUSE" "$framevm_src/net/socket/vsock/port.rs" \
    || ! grep -q "SocketAddr::Unix(_) => Err(Error::new(Errno::EINVAL))" "$framevm_src/net/socket/vsock/addr.rs" \
    || ! grep -q "mod connecting;" "$framevm_src/net/socket/vsock/stream/mod.rs" \
    || ! grep -q "VsockStreamState::Connecting" "$framevm_src/net/socket/vsock/stream/mod.rs" \
    || ! grep -q "Self::new_connect_failed(bound_port, error)" "$framevm_src/net/socket/vsock/stream/init.rs" \
    || ! grep -q "Errno::ECONNREFUSED" "$framevm_src/net/socket/vsock/stream/connecting.rs" \
    || ! grep -q "test_and_clear_error(&self.pollee)" "$framevm_src/net/socket/vsock/stream/mod.rs"; then
    echo "error: FrameVM vsock stream must preserve the kernel-shaped failed-connect state machine" >&2
    exit 1
fi

echo "FrameVM boundary check passed."
