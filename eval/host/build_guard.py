"""Build isolation checks, source/artifact freshness verification, and RunManifest archival."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from typing import Any

from .schema import RunManifest


REQUIRED_BASE_OPTIONS: dict[str, str] = {
    "CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE": "y",
    "CONFIG_ADVISE_SYSCALLS": "y",
    "CONFIG_PERF_EVENTS": "y",
    "CONFIG_KERNELET": "y",
    "CONFIG_VM_EVENT_COUNTERS": "y",
    "CONFIG_TMPFS": "y",
    "CONFIG_SHMEM": "y",
    "CONFIG_CGROUPS": "y",
    "CONFIG_MODULES": "y",
    "CONFIG_MODULE_UNLOAD": "y",
    "CONFIG_KALLSYMS": "y",
}

FORBIDDEN_PERF_OPTIONS: tuple[str, ...] = (
    "CONFIG_CC_OPTIMIZE_FOR_SIZE",
    "CONFIG_INIT_STACK_ALL_ZERO",
    "CONFIG_DEBUG_ATOMIC_SLEEP",
    "CONFIG_SCHEDSTATS",
    "CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS",
    "CONFIG_X86_VSYSCALL_EMULATION",
)

_IGNORED_PARTS = {".git", ".build", "target", "__pycache__", "results"}
_IGNORED_SUFFIXES = (".o", ".ko", ".cmd", ".mod", ".a", ".pyc")


def parse_kernel_config(config_text: str) -> dict[str, str]:
    """Parse a Linux .config file into option -> value ('y', 'm', 'n', or string)."""
    options: dict[str, str] = {}
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key = line[2 : -len(" is not set")].strip()
            options[key] = "n"
            continue
        if line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        options[key.strip()] = val.strip()
    return options


def check_kernel_config_text(config_text: str, profile: str = "perf-base") -> list[str]:
    """Return a list of config violations for the given profile ('perf-base' or 'perf-pti')."""
    if profile not in ("perf-base", "perf-pti"):
        raise ValueError(f"unknown kernel config profile: {profile!r}")

    opts = parse_kernel_config(config_text)
    errors: list[str] = []

    for key, expected in REQUIRED_BASE_OPTIONS.items():
        actual = opts.get(key)
        if actual != expected:
            errors.append(f"{key}: expected {expected!r}, got {actual!r}")

    for key in FORBIDDEN_PERF_OPTIONS:
        if opts.get(key) in ("y", "m"):
            errors.append(f"{key}: forbidden in perf build (got {opts.get(key)!r})")

    if profile == "perf-base":
        for key in ("CONFIG_CPU_MITIGATIONS", "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION"):
            if opts.get(key) == "y":
                errors.append(f"{key}: must be disabled in perf-base")
    elif profile == "perf-pti":
        for key in ("CONFIG_CPU_MITIGATIONS", "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION"):
            if opts.get(key) != "y":
                errors.append(f"{key}: expected 'y' in perf-pti, got {opts.get(key)!r}")

    return errors


def check_kernel_config(config_path: Path, profile: str = "perf-base") -> list[str]:
    """Read and validate a Linux .config file; raises FileNotFoundError if missing."""
    return check_kernel_config_text(config_path.read_text(encoding="utf-8"), profile=profile)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Compute hex SHA-256 of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _hash_sorted_files(repo_root: Path, paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(set(paths), key=lambda x: str(x)):
        if not p.is_file():
            continue
        rel = p.relative_to(repo_root).as_posix() if p.is_relative_to(repo_root) else str(p)
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        with p.open("rb") as f:
            h.update(hashlib.file_digest(f, "sha256").digest())
        h.update(b"\0")
    return h.hexdigest()


def _walk_source_paths(roots: tuple[Path, ...]) -> list[Path]:
    files: list[Path] = []
    for p in roots:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = sorted(d for d in dirnames if d not in _IGNORED_PARTS and not d.startswith("."))
                for fname in sorted(filenames):
                    if fname.startswith(".") or fname.endswith(_IGNORED_SUFFIXES):
                        continue
                    files.append(Path(dirpath) / fname)
    return sorted(set(files), key=lambda x: str(x))


def _collect_source_files(repo_root: Path) -> list[Path]:
    """Collect participating source, patch, config, and build files relative to repo_root."""
    rel_roots = (
        "prototype/linux/patches/0001-carrier-hooks.patch",
        "poc/Cargo.toml",
        "poc/Cargo.lock",
        "poc/OSDK.toml",
        "poc/rust-toolchain.toml",
        "poc/eval/Makefile",
        "poc/eval/configs",
        "poc/eval/guest",
        "poc/eval/host",
        "poc/eval/nix",
        "poc/eval/patches",
        "poc/eval/scripts",
        "poc/linux/endovisor",
        "poc/linux/runner",
        "poc/kernel",
        "poc/osdk",
        "poc/ostd",
    )
    return _walk_source_paths(tuple(repo_root / rel for rel in rel_roots))


def _cmd_version(cmd: list[str], *, extra_path_dirs: tuple[Path, ...] = (), cwd: Path | None = None) -> str:
    env = os.environ.copy()
    prefix = [str(d) for d in extra_path_dirs if d.is_dir()]
    if prefix:
        env["PATH"] = os.pathsep.join(prefix + ([env["PATH"]] if env.get("PATH") else []))
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            env=env,
            cwd=str(cwd) if cwd is not None and cwd.is_dir() else None,
        )
        first = (res.stdout or "").splitlines()
        return first[0].strip() if first else "unknown"
    except OSError:
        return "missing"


def compute_component_input_hash(
    repo_root: Path,
    build_dir: Path,
    component: str,
    *,
    payload_mode: str = "native",
) -> str:
    """Compute a deterministic input+toolchain SHA-256 for a single build component."""
    repo_root = repo_root.resolve()
    build_dir = build_dir.resolve()
    eval_dir = repo_root / "poc" / "eval"
    h = hashlib.sha256()
    extra_tokens: list[str] = []
    paths: list[Path] = []

    if component == "linux_src":
        paths.extend(_walk_source_paths((
            repo_root / "reference" / "linux-6.12",
            repo_root / "prototype" / "linux" / "patches" / "0001-carrier-hooks.patch",
        )))
    elif component in ("linux_perf_base", "linux_perf_pti"):
        paths.extend(_walk_source_paths((
            repo_root / "reference" / "linux-6.12",
            repo_root / "prototype" / "linux" / "patches" / "0001-carrier-hooks.patch",
            eval_dir / "configs" / "linux-perf-base.fragment",
        )))
        if component == "linux_perf_pti":
            paths.append(eval_dir / "configs" / "linux-perf-pti.fragment")
        extra_tokens.append(_cmd_version(["gcc", "--version"]))
    elif component in ("endovisor", "endovisor_pti"):
        kprof = "linux-perf-pti" if component == "endovisor_pti" else "linux-perf-base"
        paths.extend(_walk_source_paths((repo_root / "poc" / "linux" / "endovisor",)))
        for kdep in ("Module.symvers", ".config"):
            kp = build_dir / kprof / kdep
            if kp.exists():
                paths.append(kp)
            else:
                extra_tokens.append(f"missing:{kprof}/{kdep}")
        extra_tokens.append(_cmd_version(["gcc", "--version"]))
    elif component == "run_kernelet":
        paths.extend(_walk_source_paths((
            repo_root / "poc" / "linux" / "runner",
            repo_root / "poc" / "linux" / "endovisor" / "uapi" / "endovisor.h",
        )))
        extra_tokens.append(_cmd_version(["gcc", "--version"]))
    elif component == "asterinas":
        paths.extend(_walk_source_paths((
            repo_root / "poc" / "Cargo.toml",
            repo_root / "poc" / "Cargo.lock",
            repo_root / "poc" / "OSDK.toml",
            repo_root / "poc" / "rust-toolchain.toml",
            repo_root / "poc" / "kernel",
            repo_root / "poc" / "osdk",
            repo_root / "poc" / "ostd",
        )))
        vdso_dir = Path(os.environ.get("VDSO_LIBRARY_DIR", str(Path.home() / ".local/share/asterinas/linux_vdso")))
        vdso = vdso_dir / "vdso_x86_64.so"
        if vdso.exists():
            paths.append(vdso)
        rust_path_dirs = (
            build_dir / "osdk-bin" / "bin",
            Path.home() / ".cargo" / "bin",
        )
        poc_dir = repo_root / "poc"
        extra_tokens.append(_cmd_version(["rustc", "--version"], extra_path_dirs=rust_path_dirs, cwd=poc_dir))
        extra_tokens.append(_cmd_version(["cargo", "osdk", "--version"], extra_path_dirs=rust_path_dirs, cwd=poc_dir))
    elif component == "payload":
        paths.extend(_walk_source_paths((
            eval_dir / "configs" / "payload-sources.json",
            eval_dir / "patches",
            eval_dir / "guest",
            eval_dir / "nix",
            eval_dir / "scripts" / "build_native_payload.sh",
            eval_dir / "scripts" / "build_nix_payload.sh",
            eval_dir / "scripts" / "build_payload_deps.sh",
        )))
        for art_name in ("endovisor.ko", "endovisor-pti.ko", "run-kernelet", "kernelet-image.elf"):
            ap = build_dir / art_name
            if ap.exists():
                paths.append(ap)
        extra_tokens.append(f"payload_mode={payload_mode}")
        extra_tokens.append(_cmd_version(["gcc", "--version"]))
        if payload_mode == "nix":
            extra_tokens.append(_cmd_version(["nix-build", "--version"]))
    else:
        raise ValueError(f"unknown build component: {component!r}")

    h.update(_hash_sorted_files(repo_root, paths).encode("ascii"))
    for tok in extra_tokens:
        h.update(b"\0")
        h.update(tok.encode("utf-8"))
    return h.hexdigest()


def write_component_receipt(
    build_dir: Path,
    component: str,
    input_sha256: str,
    toolchain: str,
    outputs: dict[str, Path],
) -> Path:
    """Write a per-component receipt JSON binding inputs + toolchain to output SHA-256s."""
    build_dir = build_dir.resolve()
    receipts_dir = build_dir / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    out_hashes: dict[str, str] = {}
    out_paths: dict[str, str] = {}
    for key, p in sorted(outputs.items()):
        rp = p.resolve()
        if not rp.exists():
            raise FileNotFoundError(f"component {component!r} missing output {key}={rp}")
        out_hashes[key] = sha256_file(rp)
        out_paths[key] = rp.relative_to(build_dir).as_posix() if rp.is_relative_to(build_dir) else str(rp)
    rec = {
        "component": component,
        "input_sha256": input_sha256,
        "toolchain": toolchain,
        "outputs_sha256": out_hashes,
        "outputs_rel": out_paths,
        "built_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    rpath = receipts_dir / f"{component}.json"
    rpath.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    return rpath


def collect_sources_sha256(repo_root: Path) -> dict[str, str]:
    """Compute repo-relative SHA-256 map for all participating source/patch/config files."""
    out: dict[str, str] = {}
    for p in _collect_source_files(repo_root):
        out[p.relative_to(repo_root).as_posix()] = sha256_file(p)
    return out


def _expected_build_artifacts(build_dir: Path, *, require_pti: bool = False) -> dict[str, Path]:
    base = {
        "linux_perf_base_bzimage": build_dir / "linux-perf-base" / "arch" / "x86" / "boot" / "bzImage",
        "linux_perf_base_system_map": build_dir / "linux-perf-base" / "System.map",
        "linux_perf_base_config": build_dir / "linux-perf-base" / ".config",
        "linux_perf_base_symvers": build_dir / "linux-perf-base" / "Module.symvers",
        "endovisor_ko": build_dir / "endovisor.ko",
        "run_kernelet": build_dir / "run-kernelet",
        "asterinas_native_bzimage": build_dir / "asterinas-native.bzImage",
        "kernelet_image_elf": build_dir / "kernelet-image.elf",
        "eval_payload_cpio": build_dir / "eval-payload.cpio",
        "host_eval_initramfs": build_dir / "host-eval-initramfs.cpio.gz",
    }
    if require_pti or (build_dir / "receipts" / "linux_perf_pti.json").exists():
        base.update({
            "linux_perf_pti_bzimage": build_dir / "linux-perf-pti" / "arch" / "x86" / "boot" / "bzImage",
            "linux_perf_pti_system_map": build_dir / "linux-perf-pti" / "System.map",
            "linux_perf_pti_config": build_dir / "linux-perf-pti" / ".config",
            "linux_perf_pti_symvers": build_dir / "linux-perf-pti" / "Module.symvers",
            "endovisor_pti_ko": build_dir / "endovisor-pti.ko",
            "host_eval_initramfs_pti": build_dir / "host-eval-initramfs-pti.cpio.gz",
        })
    return base


def verify_component_receipts(
    repo_root: Path,
    build_dir: Path,
    *,
    require_pti: bool = False,
) -> dict[str, Any]:
    """Verify every required component's receipt matches current inputs, toolchain, and outputs."""
    repo_root = repo_root.resolve()
    build_dir = build_dir.resolve()
    receipts_dir = build_dir / "receipts"
    required = ["linux_perf_base", "endovisor", "run_kernelet", "asterinas", "payload"]
    if require_pti or (receipts_dir / "linux_perf_pti.json").exists() or (build_dir / "endovisor-pti.ko").exists():
        required.extend(["linux_perf_pti", "endovisor_pti"])

    verified: dict[str, Any] = {}
    for comp in required:
        rpath = receipts_dir / f"{comp}.json"
        if not rpath.exists():
            raise RuntimeError(
                f"missing component receipt {rpath}; rebuild with 'make build-kernels build-payload'"
            )
        rec = json.loads(rpath.read_text(encoding="utf-8"))
        pmode = "nix" if str(rec.get("toolchain", "")).startswith("nix:") else "native"
        want_sha = compute_component_input_hash(repo_root, build_dir, comp, payload_mode=pmode)
        if rec.get("input_sha256") != want_sha:
            raise RuntimeError(
                f"stale component {comp!r}: receipt input_sha256 ({rec.get('input_sha256')}) "
                f"!= current inputs/toolchain ({want_sha}); rebuild affected component"
            )
        out_hashes = rec.get("outputs_sha256", {})
        out_rels = rec.get("outputs_rel", {})
        if not out_hashes or set(out_hashes) != set(out_rels):
            raise RuntimeError(f"corrupt outputs in receipt {rpath}")
        for key, rel in out_rels.items():
            target = build_dir / rel
            if not target.exists():
                raise RuntimeError(f"missing output {target} listed in receipt {rpath}")
            actual = sha256_file(target)
            if actual != out_hashes[key]:
                raise RuntimeError(
                    f"artifact {target} modified outside build ({actual} != {out_hashes[key]})"
                )
        verified[comp] = rec
    return verified


def synthesize_build_manifest(
    repo_root: Path,
    build_dir: Path,
    *,
    require_pti: bool = False,
    remove_on_stale: bool = True,
) -> Path:
    """Emit build-inputs.json ONLY after verifying all component receipts match current inputs."""
    repo_root = repo_root.resolve()
    build_dir = build_dir.resolve()
    manifest_path = build_dir / "build-inputs.json"
    try:
        receipts = verify_component_receipts(repo_root, build_dir, require_pti=require_pti)
    except Exception:
        if remove_on_stale and manifest_path.exists():
            manifest_path.unlink()
        raise

    artifacts: dict[str, str] = {}
    for name, path in sorted(_expected_build_artifacts(build_dir, require_pti=require_pti).items()):
        if not path.exists():
            if remove_on_stale and manifest_path.exists():
                manifest_path.unlink()
            raise FileNotFoundError(f"missing built artifact for build-inputs manifest: {path}")
        artifacts[name] = sha256_file(path)

    payload = {
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sources_sha256": collect_sources_sha256(repo_root),
        "artifacts_sha256": artifacts,
        "component_receipts": receipts,
    }
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def write_build_inputs_manifest(repo_root: Path, build_dir: Path) -> Path:
    """Write .build/build-inputs.json (verifies receipts when present)."""
    if (build_dir / "receipts").is_dir():
        return synthesize_build_manifest(repo_root, build_dir)
    artifacts: dict[str, str] = {}
    for name, path in sorted(_expected_build_artifacts(build_dir).items()):
        if not path.exists():
            raise FileNotFoundError(f"missing built artifact for build-inputs manifest: {path}")
        artifacts[name] = sha256_file(path)
    payload = {
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sources_sha256": collect_sources_sha256(repo_root),
        "artifacts_sha256": artifacts,
    }
    out_path = build_dir / "build-inputs.json"
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out_path


def verify_build_freshness(
    repo_root: Path,
    build_dir: Path,
    *,
    require_pti: bool = False,
) -> dict[str, Any]:
    """Fail-closed check that built artifacts match current sources, patches, configs, and receipts."""
    repo_root = repo_root.resolve()
    build_dir = build_dir.resolve()
    manifest_path = build_dir / "build-inputs.json"
    if not manifest_path.exists():
        raise RuntimeError(
            f"missing build freshness manifest {manifest_path}; run 'make build-kernels build-payload'"
        )
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (build_dir / "receipts").is_dir() or "component_receipts" in data:
        verify_component_receipts(repo_root, build_dir, require_pti=require_pti)

    recorded_sources = data.get("sources_sha256", {})
    recorded_artifacts = data.get("artifacts_sha256", {})

    current_sources = collect_sources_sha256(repo_root)
    changed_sources = sorted(
        k for k in set(recorded_sources) | set(current_sources)
        if recorded_sources.get(k) != current_sources.get(k)
    )
    if changed_sources:
        sample = ", ".join(changed_sources[:6])
        raise RuntimeError(
            f"stale build artifacts: {len(changed_sources)} source/patch/config file(s) changed "
            f"since build ({sample}); rebuild with 'make build-kernels build-payload'"
        )

    for name, path in sorted(_expected_build_artifacts(build_dir, require_pti=require_pti).items()):
        if not path.exists():
            raise RuntimeError(f"missing required build artifact: {path}")
        actual = sha256_file(path)
        expected = recorded_artifacts.get(name)
        if actual != expected:
            raise RuntimeError(
                f"build artifact {path} SHA-256 ({actual}) does not match build-inputs.json ({expected})"
            )
    return data


def extract_cpio_member_hashes(
    cpio_or_gz_path: Path,
    members: tuple[str, ...],
) -> dict[str, str]:
    """Hash selected archive inputs using GNU gzip and cpio."""
    raw = subprocess.run(
        ["gzip", "--decompress", "--stdout", "--force", "--", str(cpio_or_gz_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout
    listing = subprocess.run(
        ["cpio", "--list", "--quiet"], input=raw,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    names = {
        name.removeprefix("./"): name
        for name in listing.stdout.decode("utf-8").splitlines()
    }
    hashes: dict[str, str] = {}
    for member in members:
        if member not in names:
            continue
        content = subprocess.run(
            ["cpio", "--extract", "--to-stdout", "--quiet", "--", names[member]],
            input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
        if not content:
            raise ValueError(f"{cpio_or_gz_path}: empty required artifact {member}")
        hashes[member] = sha256_bytes(content)
    return hashes


def verify_shared_payload(
    *,
    payload_path: Path,
    host_initrd_path: Path | None,
    targets: list[str],
) -> tuple[str, dict[str, str]]:
    """Verify external payload SHA-256 matches the embedded payload in host initrd."""
    ext_hash = sha256_file(payload_path)
    embedded_hashes: dict[str, str] = {}
    if any(t != "A" for t in targets):
        if host_initrd_path is None or not host_initrd_path.exists():
            raise FileNotFoundError(f"missing host initramfs: {host_initrd_path}")
        members = ("payload/eval-payload.cpio",)
        if any(t.startswith("K") for t in targets):
            members += ("modules/endovisor.ko", "bin/run-kernelet", "kernelet-image.elf")
        embedded_hashes = extract_cpio_member_hashes(host_initrd_path, members)
        embedded_payload = embedded_hashes.get("payload/eval-payload.cpio")
        if embedded_payload is None:
            raise ValueError(f"{host_initrd_path}: missing embedded payload/eval-payload.cpio")
        if embedded_payload != ext_hash:
            raise ValueError(
                f"embedded payload SHA-256 ({embedded_payload}) != external payload ({ext_hash})"
            )
        if any(t.startswith("K") for t in targets):
            for required in ("modules/endovisor.ko", "bin/run-kernelet", "kernelet-image.elf"):
                if required not in embedded_hashes:
                    raise ValueError(f"{host_initrd_path}: missing required Kernelet artifact {required}")
    return ext_hash, embedded_hashes


def _git_info(repo_dir: Path) -> tuple[str, bool, str, list[str]]:
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        status = subprocess.check_output(
            ["git", "-C", str(repo_dir), "status", "--porcelain"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        diff = subprocess.check_output(
            ["git", "-C", str(repo_dir), "diff", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        untracked_raw = subprocess.check_output(
            ["git", "-C", str(repo_dir), "ls-files", "--others", "--exclude-standard"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        untracked = [
            line.strip()
            for line in untracked_raw.splitlines()
            if line.strip()
            and not any(part in _IGNORED_PARTS for part in Path(line.strip()).parts)
        ]
        return commit, bool(status), diff, untracked
    except Exception:
        return "unknown", False, "", []


def _write_source_snapshot(repo_root: Path, out_path: Path) -> None:
    """Archive all participating source/patch/config files (including poc/kernel, ostd, osdk untracked files) into tar.gz."""
    files = _collect_source_files(repo_root)
    with tarfile.open(out_path, "w:gz") as tf:
        for f in files:
            tf.add(f, arcname=f.relative_to(repo_root).as_posix())


def _host_cpu_info() -> tuple[str, int, list[str], list[dict[str, Any]]]:
    model = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    cpu_dirs = sorted(
        (p for p in Path("/sys/devices/system/cpu").glob("cpu[0-9]*") if p.name[3:].isdigit()),
        key=lambda p: int(p.name[3:]),
    )
    governors: list[str] = []
    topology: list[dict[str, Any]] = []
    for cpu_dir in cpu_dirs:
        cpu_id = int(cpu_dir.name[3:])
        entry: dict[str, Any] = {"cpu": cpu_id}
        sib = cpu_dir / "topology" / "thread_siblings_list"
        if sib.exists():
            entry["thread_siblings"] = sib.read_text(encoding="utf-8").strip()
        core_id = cpu_dir / "topology" / "core_id"
        if core_id.exists():
            entry["core_id"] = core_id.read_text(encoding="utf-8").strip()
        gov_file = cpu_dir / "cpufreq" / "scaling_governor"
        if gov_file.exists():
            gov = gov_file.read_text(encoding="utf-8").strip()
            governors.append(gov)
            entry["scaling_governor"] = gov
        cur_freq = cpu_dir / "cpufreq" / "scaling_cur_freq"
        if cur_freq.exists():
            entry["scaling_cur_freq"] = cur_freq.read_text(encoding="utf-8").strip()
        topology.append(entry)
    return model, len(cpu_dirs), sorted(set(governors)), topology


def generate_and_write_archive(
    *,
    run_id: str,
    out_dir: Path,
    repo_root: Path,
    targets: list[str],
    rounds: int,
    seed: int,
    payload_path: Path,
    host_initrd_path: Path | None,
    artifacts: dict[str, Path],
    kernel_configs: dict[str, tuple[Path, str]],
    cases_path: Path | None = None,
    build_dir: Path | None = None,
    build_inputs_verified: bool = False,
) -> RunManifest:
    """Verify artifacts, archive patches/configs/untracked sources, and write manifest.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    payload_hash, embedded_hashes = verify_shared_payload(
        payload_path=payload_path,
        host_initrd_path=host_initrd_path,
        targets=targets,
    )

    root_commit, root_dirty, root_diff, root_untracked = _git_info(repo_root)
    poc_dir = repo_root / "poc"
    poc_commit, poc_dirty, poc_diff, poc_untracked = _git_info(poc_dir)

    if root_diff:
        (out_dir / "root_git_diff.patch").write_text(root_diff, encoding="utf-8")
    if poc_diff:
        (out_dir / "poc_git_diff.patch").write_text(poc_diff, encoding="utf-8")

    cases_sha = ""
    if cases_path is not None and cases_path.exists():
        cases_sha = sha256_file(cases_path)
        shutil.copy2(cases_path, out_dir / "cases.toml")

    if build_dir is not None and (build_dir / "build-inputs.json").exists():
        shutil.copy2(build_dir / "build-inputs.json", out_dir / "build-inputs.json")

    snapshot_name = "source_snapshot.tar.gz"
    _write_source_snapshot(repo_root, out_dir / snapshot_name)
    sources_sha = collect_sources_sha256(repo_root)

    untracked_all = sorted(
        set(root_untracked) | {f"poc/{u}" for u in poc_untracked}
    )

    artifact_hashes: dict[str, str] = {}
    for name, path in sorted(artifacts.items()):
        if path.exists():
            artifact_hashes[name] = sha256_file(path)

    config_checks: dict[str, list[str]] = {}
    for name, (cfg_path, profile) in sorted(kernel_configs.items()):
        if cfg_path.exists():
            config_checks[name] = check_kernel_config(cfg_path, profile)
            shutil.copy2(cfg_path, out_dir / f"{name}.config")
        else:
            config_checks[name] = [f"missing config: {cfg_path}"]

    cpu_model, cpu_count, governors, topology = _host_cpu_info()
    manifest = RunManifest(
        run_id=run_id,
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        git_commit=root_commit,
        git_dirty=root_dirty,
        poc_git_commit=poc_commit,
        poc_git_dirty=poc_dirty,
        targets=list(targets),
        rounds=rounds,
        seed=seed,
        payload_sha256=payload_hash,
        artifacts_sha256=artifact_hashes,
        embedded_artifacts_sha256=embedded_hashes,
        kernel_config_checks=config_checks,
        host_cpu_model=cpu_model,
        host_cpu_count=cpu_count,
        host_governors=governors,
        host_cpu_topology=topology,
        cases_sha256=cases_sha,
        sources_sha256=sources_sha,
        build_inputs_verified=build_inputs_verified,
        source_snapshot_file=snapshot_name,
        untracked_files=untracked_all,
    )
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    return manifest
