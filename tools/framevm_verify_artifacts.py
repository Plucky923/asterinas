#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Verifies FrameVM build/loading artifacts produced by OSDK."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


SYMBOLS_MAGIC = b"FVSYMTB\0"
SYMBOLS_HEADER_SIZE = 64
SYMBOLS_FORMAT_VERSION = 1
SYMBOLS_ENDIAN_LITTLE = 1
SYMBOLS_WORD_SIZE_64 = 8

META_MAGIC = b"FVMETA\0\0"
META_SIZE = 128
META_FORMAT_VERSION = 1
META_ENDIAN_LITTLE = 1
META_WORD_SIZE_64 = 8
META_VALIDATION_PASSED = 1
META_TARGET_X86_64 = 1
META_RELOCATABLE_ELF = 1
META_ENTRY_RETURNS = 1

CONTRACT = "framevm-service-build-loading"


class Verifier:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.build_dir = self.root / "build" / "framevm"
        self.bundle_dir = self.root / "target" / "osdk" / "aster-kernel"
        self.failures: list[str] = []
        self.report: dict[str, Any] = {}

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.failures.append(message)

    def require_file(self, path: Path) -> None:
        self.check(path.is_file(), f"required file is missing: {path}")

    def run(self) -> None:
        required = [
            self.build_dir / "framevm.o",
            self.build_dir / "framevm.meta",
            self.build_dir / "framevm.symbols",
            self.build_dir / "actual-imports-report.json",
            self.build_dir / "final-host-validation-report.json",
            self.build_dir / "framevm.export-request",
            self.build_dir / "framevm-export-manifest.json",
            self.build_dir / "build-index.json",
            self.build_dir / "build-object-report.json",
            self.build_dir / "make_framevm-timings-report.json",
            self.build_dir / "make_run_framevm-timings-report.json",
            self.bundle_dir / "bundle.toml",
            self.bundle_dir / "framevm.symbols",
        ]
        for path in required:
            self.require_file(path)
        if self.failures:
            return

        actual_imports = read_json(self.build_dir / "actual-imports-report.json")
        host_validation = read_json(self.build_dir / "final-host-validation-report.json")
        export_request = read_json(self.build_dir / "framevm.export-request")
        export_manifest = read_json(self.build_dir / "framevm-export-manifest.json")
        build_index = read_json(self.build_dir / "build-index.json")
        build_object = read_json(self.build_dir / "build-object-report.json")
        bundle = read_toml(self.bundle_dir / "bundle.toml")
        symbols = parse_framevm_symbols(self.build_dir / "framevm.symbols")
        metadata = parse_framevm_metadata(self.build_dir / "framevm.meta")

        self.verify_actual_imports(actual_imports)
        self.verify_symbols(symbols, actual_imports, host_validation)
        self.verify_host_validation(host_validation, actual_imports)
        self.verify_export_request(export_request, actual_imports)
        self.verify_export_manifest(export_manifest, actual_imports, host_validation)
        self.verify_identity_and_hashes(build_index, bundle, symbols, metadata, actual_imports)
        self.verify_metadata(metadata, build_index, build_object)
        self.verify_source_structure()
        self.verify_synthetic_import_evidence()
        self.verify_rust_symbol_identity()
        self.verify_timing_reports()
        self.report["baseline"] = self.collect_baseline(build_object)

    def verify_actual_imports(self, actual_imports: dict[str, Any]) -> None:
        imports = actual_imports.get("imports", [])
        import_hex = [entry["raw_symbol_name_hex"] for entry in imports]
        self.check(
            len(import_hex) == actual_imports.get("import_count"),
            "actual import count does not match import entries",
        )
        self.check(import_hex == sorted(import_hex), "actual imports are not sorted by raw bytes")
        self.check(len(import_hex) == len(set(import_hex)), "actual imports contain duplicates")
        for entry in imports:
            locations = entry.get("relocation_locations", [])
            self.check(
                len(locations) <= 16,
                f"relocation diagnostics exceed 16 locations for {entry['raw_symbol_name']}",
            )
            self.check(
                entry.get("relocation_count", 0) >= len(locations),
                f"relocation count is smaller than recorded locations for {entry['raw_symbol_name']}",
            )

        self.report["actual_imports"] = {
            "count": len(import_hex),
            "all_sorted": import_hex == sorted(import_hex),
            "all_unique": len(import_hex) == len(set(import_hex)),
        }

    def verify_symbols(
        self,
        symbols: dict[str, Any],
        actual_imports: dict[str, Any],
        host_validation: dict[str, Any],
    ) -> None:
        import_hex = [entry["raw_symbol_name_hex"] for entry in actual_imports["imports"]]
        symbol_hex = [entry["raw_name_hex"] for entry in symbols["entries"]]
        self.check(symbol_hex == import_hex, "framevm.symbols names do not equal actual imports")
        self.check(
            symbols["symbol_count"] == len(import_hex),
            "framevm.symbols symbol count does not match actual imports",
        )
        self.check(
            symbols["sorted_names"] == sorted(symbols["sorted_names"]),
            "framevm.symbols name_seqs are not sorted",
        )
        self.check(
            len(symbols["sorted_names"]) == len(set(symbols["sorted_names"])),
            "framevm.symbols contains duplicate sorted names",
        )

        values_by_name = {
            entry["raw_name_hex"]: entry["value"] for entry in symbols["entries"]
        }
        for match in host_validation["matches"]:
            name_hex = match["import_name"]["raw_symbol_name_hex"]
            self.check(
                values_by_name.get(name_hex) == match["value"],
                f"framevm.symbols value mismatch for {match['import_name']['raw_symbol_name']}",
            )

        self.report["symbols"] = {
            "count": symbols["symbol_count"],
            "payload_size_bytes": symbols["payload_size"],
            "sha256": symbols["sha256"],
            "names_match_actual_imports": symbol_hex == import_hex,
        }

    def verify_host_validation(
        self,
        host_validation: dict[str, Any],
        actual_imports: dict[str, Any],
    ) -> None:
        self.check(host_validation.get("exact_match") is True, "host validation is not exact")
        self.check(host_validation.get("missing_count") == 0, "host validation has missing imports")
        self.check(
            host_validation.get("ambiguous_count") == 0,
            "host validation has ambiguous imports",
        )
        self.check(
            "alias_candidates" not in host_validation,
            "host validation report still exposes alias fallback candidates",
        )
        self.check(
            "unresolved_alias_imports" not in host_validation,
            "host validation report still exposes alias fallback misses",
        )
        self.check(
            host_validation.get("matched_count") == actual_imports.get("import_count"),
            "matched host import count does not match actual imports",
        )
        for match in host_validation.get("matches", []):
            import_hex = match["import_name"]["raw_symbol_name_hex"]
            exported_hex = match["exported_name"]["raw_symbol_name_hex"]
            self.check(
                import_hex == exported_hex,
                f"host validation accepted non-exact exported name for {match['import_name']['raw_symbol_name']}",
            )

        self.report["host_validation"] = {
            "exact_match": host_validation.get("exact_match"),
            "matched_count": host_validation.get("matched_count"),
        }

    def verify_export_request(
        self,
        export_request: dict[str, Any],
        actual_imports: dict[str, Any],
    ) -> None:
        self.check(export_request.get("contract") == CONTRACT, "export request contract mismatch")
        request_names = [entry["raw_symbol_name"] for entry in export_request.get("entries", [])]
        actual_names = [entry["raw_symbol_name"] for entry in actual_imports["imports"]]
        self.check(request_names == actual_names, "export request is not derived from actual imports")
        for entry in export_request.get("entries", []):
            self.check(
                entry["raw_symbol_name"]
                == entry["exported_symbol_name"]
                == entry["origin_framevm_import"],
                f"export request contains a non-exact runtime lookup key for {entry['origin_framevm_import']}",
            )

    def verify_export_manifest(
        self,
        export_manifest: dict[str, Any],
        actual_imports: dict[str, Any],
        host_validation: dict[str, Any],
    ) -> None:
        self.check(export_manifest.get("contract") == CONTRACT, "export manifest contract mismatch")
        manifest_entries = export_manifest.get("entries", [])
        self.check(
            len(manifest_entries) == actual_imports.get("import_count"),
            "export manifest entry count does not match actual imports",
        )
        for manifest_entry, host_match in zip(manifest_entries, host_validation["matches"]):
            origin = manifest_entry["origin_framevm_import"]
            exported = manifest_entry["exported_symbol_name"]
            self.check(
                origin["raw_symbol_name_hex"] == exported["raw_symbol_name_hex"],
                f"export manifest accepted non-exact exported symbol for {origin['raw_symbol_name']}",
            )
            self.check(
                origin["raw_symbol_name_hex"]
                == host_match["import_name"]["raw_symbol_name_hex"],
                f"export manifest order or name mismatch for {origin['raw_symbol_name']}",
            )
        compatibility = export_manifest.get("raw_symbol_compatibility", {})
        self.check(
            compatibility.get("symbol_mangling_version") == "v0",
            "raw-symbol compatibility does not record rust v0 mangling",
        )
        self.check(
            bool(compatibility.get("rust_metadata")),
            "raw-symbol compatibility is missing rust metadata",
        )
        self.check(
            "exact raw symbols" in compatibility.get("provider_identity_rule", ""),
            "provider identity rule does not state exact raw-symbol matching",
        )

    def verify_identity_and_hashes(
        self,
        build_index: dict[str, Any],
        bundle: dict[str, Any],
        symbols: dict[str, Any],
        metadata: dict[str, Any],
        actual_imports: dict[str, Any],
    ) -> None:
        artifact_set = bundle.get("framevm_artifact_set", {})
        index_artifact_set = build_index.get("framevm_artifact_set", {})
        self.check(artifact_set == index_artifact_set, "bundle artifact-set metadata differs from build index")
        self.check(build_index.get("transaction_hash_algorithm") == "sha256", "transaction hash algorithm is not sha256")

        computed_transaction_id = compute_transaction_id(build_index["transaction_hash_inputs"])
        self.check(
            computed_transaction_id == build_index.get("transaction_id"),
            "transaction id does not match transaction_hash_inputs",
        )
        self.check(
            artifact_set.get("transaction_id") == metadata["transaction_id"],
            "bundle transaction id does not match metadata",
        )
        self.check(
            artifact_set.get("framevm_symbols_hash") == metadata["framevm_symbols_hash"],
            "bundle framevm_symbols_hash does not match metadata",
        )
        self.check(
            artifact_set.get("framevm_export_manifest_hash") == metadata["export_manifest_hash"],
            "bundle export manifest hash does not match metadata",
        )

        actual_imports_hash = compute_actual_imports_hash(actual_imports)
        self.check(
            artifact_set.get("actual_imports_hash") == actual_imports_hash,
            "actual_imports_hash does not match actual import report",
        )
        self.check(
            build_index.get("framevm_symbols_hash") == symbols["sha256"],
            "build index framevm_symbols_hash does not match payload",
        )
        self.check(
            artifact_set.get("framevm_symbols_hash") == sha256_file(self.bundle_dir / "framevm.symbols"),
            "bundle framevm.symbols payload hash mismatch",
        )
        self.check(
            symbols["sha256"] == sha256_file(self.bundle_dir / "framevm.symbols"),
            "published framevm.symbols differs from build artifact",
        )
        self.check(
            artifact_set.get("framevm_o_hash") == sha256_file(self.build_dir / "framevm.o"),
            "framevm_o_hash does not match final framevm.o",
        )
        self.check(
            artifact_set.get("framevm_metadata_hash") == sha256_file(self.build_dir / "framevm.meta"),
            "framevm_metadata_hash does not match framevm.meta",
        )
        self.check(
            artifact_set.get("framevm_export_manifest_hash")
            == sha256_file(self.build_dir / "framevm-export-manifest.json"),
            "framevm export manifest hash mismatch",
        )

        forbidden_input_names = {"framevm_metadata_hash", "framevm_symbols_hash", "framevm_o_hash"}
        hash_input_names = {entry["name"] for entry in build_index["transaction_hash_inputs"]}
        self.check(
            forbidden_input_names.isdisjoint(hash_input_names),
            "transaction id contains generated artifact hash inputs",
        )
        for entry in build_index["transaction_hash_inputs"]:
            value = entry["value"]
            self.check(not contains_unstable_path(value), f"unstable path in transaction input {entry['name']}")

        for name, value in flatten_json_strings(build_index):
            self.check(not contains_unstable_path(value), f"unstable path in build index field {name}")

        self.report["identity"] = {
            "transaction_id": build_index.get("transaction_id"),
            "transaction_inputs": len(build_index["transaction_hash_inputs"]),
            "actual_imports_hash": actual_imports_hash,
        }

    def verify_metadata(
        self,
        metadata: dict[str, Any],
        build_index: dict[str, Any],
        build_object: dict[str, Any],
    ) -> None:
        self.check(metadata["format_version"] == META_FORMAT_VERSION, "metadata format version mismatch")
        self.check(metadata["endianness"] == META_ENDIAN_LITTLE, "metadata endian mismatch")
        self.check(metadata["word_size"] == META_WORD_SIZE_64, "metadata word size mismatch")
        self.check(metadata["validation_status"] == META_VALIDATION_PASSED, "metadata validation status is not passed")
        self.check(metadata["target_arch"] == META_TARGET_X86_64, "metadata target arch mismatch")
        self.check(metadata["artifact_format"] == META_RELOCATABLE_ELF, "metadata artifact format mismatch")
        self.check(metadata["entry_point"] == META_ENTRY_RETURNS, "metadata entry-point assumption mismatch")
        self.check(metadata["loadable_payload_size"] > 0, "metadata loadable payload size is zero")

        retained_rlibs = build_object.get("retained_rlibs", [])
        bundled_object_count = sum(entry.get("object_count", 0) for entry in retained_rlibs)
        self.check(
            metadata["retained_rlib_count"] == len(retained_rlibs),
            "metadata retained_rlib_count does not match build-object report",
        )
        self.check(
            metadata["bundled_object_count"] == bundled_object_count,
            "metadata bundled_object_count does not match build-object report",
        )
        self.check(
            build_index.get("framevm_metadata_size_bytes") == META_SIZE,
            "build index metadata size is not 128 bytes",
        )

        section_report = readelf_sections(self.build_dir / "framevm.o")
        meta_sections = [
            section for section in section_report["sections"] if section["name"] == ".framevm.meta"
        ]
        self.check(bool(meta_sections), "framevm.o is missing .framevm.meta")
        for section in meta_sections:
            flags = section.get("flags", "")
            self.check("A" not in flags and "X" not in flags, ".framevm.meta is allocatable or executable")

        self.report["metadata"] = {
            "loadable_payload_size": metadata["loadable_payload_size"],
            "retained_rlib_count": metadata["retained_rlib_count"],
            "bundled_object_count": metadata["bundled_object_count"],
        }

    def verify_source_structure(self) -> None:
        host_rs = read_text(self.root / "osdk" / "src" / "framevm" / "host.rs")
        transaction_rs = read_text(self.root / "osdk" / "src" / "framevm" / "transaction.rs")
        relocation_rs = read_text(self.root / "ostd" / "src" / "loader" / "relocation.rs")
        framevm_symbols_rs = read_text(self.root / "ostd" / "src" / "symbols" / "framevm.rs")
        command_rs = read_text(self.root / "osdk" / "src" / "commands" / "framevm.rs")
        loader_mod_rs = read_text(self.root / "ostd" / "src" / "loader" / "mod.rs")
        framevmctl_rs = read_text(self.root / "kernel" / "src" / "device" / "misc" / "framevm" / "mod.rs")

        self.check("apply_symbol_aliases" not in host_rs, "OSDK host validation still has the old alias fallback")
        self.check(
            "publish_exact_import_aliases" in host_rs and "publish_exact_import_aliases" in transaction_rs,
            "OSDK does not route generated host aliases through an explicit exact-publish stage",
        )
        alias_publish_pos = transaction_rs.find("publish_exact_import_aliases")
        final_report_pos = transaction_rs.find("write_final_host_validation_report")
        self.check(
            alias_publish_pos != -1 and final_report_pos != -1 and alias_publish_pos < final_report_pos,
            "OSDK writes final host validation before exact host aliases are revalidated",
        )
        self.check("KernelSymbolsModule::Omit" in transaction_rs, "FrameVM host build does not omit full kernel symbols")
        self.check("framevm_symbol_addr_by_name" in relocation_rs, "loader does not use FrameVM exact lookup API")
        self.check(
            re.search(r"(?<!framevm_)symbol_addr_by_name", relocation_rs) is None,
            "loader calls permissive full-kernel symbol lookup",
        )
        for forbidden in ["for_each_framevm_symbol", "framevm_symbol_by_addr", "lookup_by_addr"]:
            self.check(forbidden not in relocation_rs, f"loader uses diagnostic symbol API {forbidden}")
        self.check("boot_info().symbols" not in relocation_rs, "loader reads full kernel boot symbols")
        self.check("HashMap" not in framevm_symbols_rs and "BTreeMap" not in framevm_symbols_rs, "OSTD FrameVM symbol table uses a resident map")
        self.check("while left < right" in framevm_symbols_rs, "OSTD FrameVM symbol lookup is not binary search shaped")
        self.check("ServiceObject::parse" in loader_mod_rs, "loader does not parse a per-load ServiceObject")
        self.check("load_service_module" in loader_mod_rs and "relocate_sections" in loader_mod_rs, "loader boundary entry points are missing")
        self.check("ElfFile" not in command_rs, "OSDK command parses ELF directly")
        self.check("framevm.symbols" not in framevmctl_rs, "framevmctl parses or references framevm.symbols")

        build_plan_pos = relocation_rs.find("build_relocation_plan")
        apply_plan_pos = relocation_rs.find("apply_relocation_plan")
        self.check(
            build_plan_pos != -1 and apply_plan_pos != -1 and build_plan_pos < apply_plan_pos,
            "relocation application is not separated from relocation planning",
        )
        self.check(
            "cannot resolve" in relocation_rs and "before relocation" in relocation_rs,
            "missing import aggregation does not report before relocation",
        )

        self.report["source_structure"] = {
            "final_host_validation_exact": "apply_symbol_aliases" not in host_rs,
            "loader_uses_exact_framevm_lookup": "framevm_symbol_addr_by_name" in relocation_rs,
            "symbol_table_has_no_resident_map": "HashMap" not in framevm_symbols_rs and "BTreeMap" not in framevm_symbols_rs,
        }

    def verify_synthetic_import_evidence(self) -> None:
        assembler = shutil.which("as")
        readelf = shutil.which("readelf")
        nm = shutil.which("nm")
        if not assembler or not readelf or not nm:
            self.report["synthetic_import_evidence"] = {"skipped": "missing binutils"}
            return

        with tempfile.TemporaryDirectory(prefix="framevm-import-evidence-") as tmp:
            tmp_dir = Path(tmp)
            asm = tmp_dir / "import-evidence.S"
            obj = tmp_dir / "import-evidence.o"
            asm.write_text(
                """
.text
.global framevm_probe
framevm_probe:
    call host_used
    ret
.globl host_unused
""".lstrip(),
                encoding="utf-8",
            )
            subprocess.run([assembler, "-o", obj, asm], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            nm_output = subprocess.check_output([nm, "-u", obj], text=True)
            relocation_output = subprocess.check_output([readelf, "-r", "-W", obj], text=True)

        nm_imports = sorted(
            line.split()[-1] for line in nm_output.splitlines() if line.split()
        )
        relocation_imports = sorted(set(re.findall(r"\b(host_[A-Za-z0-9_]+)\b", relocation_output)))
        self.check("host_used" in relocation_imports, "synthetic relocation import is missing host_used")
        self.check("host_unused" in nm_imports, "synthetic nm output is missing unreferenced undefined symbol")
        self.check("host_unused" not in relocation_imports, "relocation evidence includes unreferenced weak symbol")
        self.report["synthetic_import_evidence"] = {
            "nm_undefined": nm_imports,
            "relocation_referenced": relocation_imports,
        }

    def verify_rust_symbol_identity(self) -> None:
        rustc = shutil.which("rustc")
        nm = shutil.which("nm")
        if not rustc or not nm:
            self.report["rust_symbol_identity"] = {"skipped": "missing rustc or nm"}
            return

        with tempfile.TemporaryDirectory(prefix="framevm-rust-symbols-") as tmp:
            tmp_dir = Path(tmp)
            source = tmp_dir / "lib.rs"
            source.write_text(
                """
#![no_std]

#[inline(never)]
pub extern "Rust" fn retained_provider_item() -> usize {
    7
}
""".lstrip(),
                encoding="utf-8",
            )
            symbols = [
                self.compile_symbol_with_metadata(rustc, nm, source, tmp_dir / "a.o", "stable_a"),
                self.compile_symbol_with_metadata(rustc, nm, source, tmp_dir / "b.o", "stable_a"),
                self.compile_symbol_with_metadata(rustc, nm, source, tmp_dir / "c.o", "stable_b"),
            ]

        if any(symbol is None for symbol in symbols):
            return
        first, second, changed = symbols
        self.check(first == second, "identical rustc identity inputs produced different raw symbols")
        self.check(first != changed, "changing -C metadata did not change the raw Rust symbol")
        self.report["rust_symbol_identity"] = {
            "same_metadata_symbol": first,
            "changed_metadata_symbol": changed,
            "same_metadata_stable": first == second,
            "metadata_changes_symbol": first != changed,
        }

    def compile_symbol_with_metadata(
        self,
        rustc: str,
        nm: str,
        source: Path,
        output: Path,
        metadata: str,
    ) -> str | None:
        command = [
            rustc,
            "--target",
            "x86_64-unknown-none",
            "--crate-type",
            "lib",
            "--emit=obj",
            "-C",
            "symbol-mangling-version=v0",
            "-C",
            f"metadata={metadata}",
            "-o",
            str(output),
            str(source),
        ]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            self.check(False, f"rustc raw-symbol spike failed: {result.stderr.strip()}")
            return None
        nm_output = subprocess.check_output([nm, "--defined-only", output], text=True)
        for line in nm_output.splitlines():
            if "retained_provider_item" in line:
                return line.split()[-1]
        self.check(False, "rustc raw-symbol spike did not emit retained_provider_item")
        return None

    def verify_timing_reports(self) -> None:
        expected_stages = {
            "make_framevm": {
                "framevm_object_build_and_link",
                "final_host_artifact_stage",
                "final_host_validation",
                "symbol_table_generation",
                "metadata_embedding",
                "final_initramfs_packaging",
                "boot_symbol_packaging",
            },
            "make_run_framevm": {
                "qemu_launch_until_success",
            },
        }
        timing_reports = {}
        for workflow, stages in expected_stages.items():
            path = self.build_dir / f"{workflow}-timings-report.json"
            timing_report = read_json(path)
            self.check(timing_report.get("contract") == CONTRACT, f"{workflow} timing contract mismatch")
            self.check(timing_report.get("workflow") == workflow, f"{workflow} timing workflow mismatch")
            stage_entries = timing_report.get("stages", [])
            stage_names = {entry.get("stage") for entry in stage_entries}
            self.check(stages.issubset(stage_names), f"{workflow} timing report is missing required stages")
            self.check(bool(stage_entries), f"{workflow} timing report has no stages")
            self.check(
                timing_report.get("total_elapsed_ms", 0) >= 0,
                f"{workflow} timing report has invalid total elapsed time",
            )
            for entry in stage_entries:
                self.check(entry.get("elapsed_ms", -1) >= 0, f"{workflow} stage has invalid elapsed time")
            timing_reports[workflow] = {
                "total_elapsed_ms": timing_report.get("total_elapsed_ms"),
                "stages": stage_entries,
            }
        self.report["timings"] = timing_reports

    def collect_baseline(self, build_object: dict[str, Any]) -> dict[str, Any]:
        object_path = self.build_dir / "framevm.o"
        section_report = readelf_sections(object_path)
        relocation_count = readelf_relocation_count(object_path)
        undefined_symbols = readelf_undefined_symbols(object_path)
        nm_undefined = nm_undefined_symbols(object_path)
        retained_rlibs = sorted(
            (
                {
                    "crate_name": entry["crate_name"],
                    "object_count": entry.get("object_count", 0),
                    "rlib": entry.get("rlib", ""),
                }
                for entry in build_object.get("retained_rlibs", [])
            ),
            key=lambda entry: entry["object_count"],
            reverse=True,
        )
        baseline = {
            "object_size_bytes": object_path.stat().st_size,
            "section_count": section_report["section_count"],
            "top_sections_by_size": section_report["top_sections_by_size"],
            "section_size_by_class": section_report["section_size_by_class"],
            "relocation_count": relocation_count,
            "undefined_symbol_count": len(undefined_symbols),
            "nm_undefined_symbol_count": len(nm_undefined),
            "retained_rlib_count": len(retained_rlibs),
            "bundled_object_count": sum(entry["object_count"] for entry in retained_rlibs),
            "retained_rlibs_by_object_count": retained_rlibs,
        }
        self.check(baseline["object_size_bytes"] > 0, "baseline framevm.o size is zero")
        self.check(baseline["relocation_count"] > 0, "baseline relocation count is zero")
        self.check(baseline["undefined_symbol_count"] > 0, "baseline undefined symbol count is zero")
        return baseline


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_framevm_symbols(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    if len(payload) < SYMBOLS_HEADER_SIZE:
        raise ValueError(f"framevm.symbols is too small: {len(payload)}")
    magic = payload[:8]
    version = struct.unpack_from("<H", payload, 8)[0]
    endian = payload[10]
    word_size = payload[11]
    symbol_count = struct.unpack_from("<I", payload, 16)[0]
    values_offset = struct.unpack_from("<I", payload, 20)[0]
    name_seqs_offset = struct.unpack_from("<I", payload, 24)[0]
    name_offsets_offset = struct.unpack_from("<I", payload, 28)[0]
    raw_names_offset = struct.unpack_from("<I", payload, 32)[0]
    raw_names_size = struct.unpack_from("<I", payload, 36)[0]
    payload_size = struct.unpack_from("<I", payload, 40)[0]

    assert magic == SYMBOLS_MAGIC, "framevm.symbols magic mismatch"
    assert version == SYMBOLS_FORMAT_VERSION, "framevm.symbols format version mismatch"
    assert endian == SYMBOLS_ENDIAN_LITTLE, "framevm.symbols endian mismatch"
    assert word_size == SYMBOLS_WORD_SIZE_64, "framevm.symbols word size mismatch"
    assert payload_size == len(payload), "framevm.symbols payload size mismatch"

    values_end = checked_range(values_offset, symbol_count, 8, payload_size, "values")
    name_seqs_end = checked_range(name_seqs_offset, symbol_count, 4, payload_size, "name_seqs")
    name_offsets_end = checked_range(name_offsets_offset, symbol_count, 4, payload_size, "name_offsets")
    raw_names_end = raw_names_offset + raw_names_size
    assert raw_names_end <= payload_size, "raw-name stream exceeds payload"
    assert (
        values_offset == SYMBOLS_HEADER_SIZE
        and values_end <= name_seqs_offset
        and name_seqs_end <= name_offsets_offset
        and name_offsets_end <= raw_names_offset
        and raw_names_end == payload_size
    ), "framevm.symbols table layout is not canonical"

    values = [struct.unpack_from("<Q", payload, values_offset + seq * 8)[0] for seq in range(symbol_count)]
    name_seqs = [struct.unpack_from("<I", payload, name_seqs_offset + seq * 4)[0] for seq in range(symbol_count)]
    name_offsets = [struct.unpack_from("<I", payload, name_offsets_offset + seq * 4)[0] for seq in range(symbol_count)]

    entries = []
    for seq, offset in enumerate(name_offsets):
        assert offset < raw_names_size, f"raw-name offset {offset} is out of bounds"
        length_offset = raw_names_offset + offset
        name_len = struct.unpack_from("<H", payload, length_offset)[0]
        assert name_len > 0, f"raw name for sequence {seq} is empty"
        name_start = length_offset + 2
        name_end = name_start + name_len
        assert name_end <= raw_names_end, f"raw name for sequence {seq} exceeds raw-name stream"
        name = payload[name_start:name_end]
        entries.append(
            {
                "sequence": seq,
                "value": values[seq],
                "raw_name": name.decode("utf-8", errors="replace"),
                "raw_name_hex": name.hex(),
            }
        )

    sorted_names = []
    for sorted_index, seq in enumerate(name_seqs):
        assert seq < symbol_count, f"name_seqs entry {sorted_index} is out of range"
        sorted_names.append(entries[seq]["raw_name_hex"])
    assert sorted_names == sorted(sorted_names), "name_seqs are not sorted by raw name"
    assert len(sorted_names) == len(set(sorted_names)), "duplicate names in name_seqs"

    return {
        "symbol_count": symbol_count,
        "payload_size": payload_size,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "entries": entries,
        "sorted_names": sorted_names,
    }


def parse_framevm_metadata(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    assert len(payload) == META_SIZE, f"framevm.meta must be {META_SIZE} bytes"
    assert payload[:8] == META_MAGIC, "framevm.meta magic mismatch"
    return {
        "format_version": struct.unpack_from("<H", payload, 8)[0],
        "endianness": payload[10],
        "word_size": payload[11],
        "validation_status": payload[12],
        "target_arch": payload[13],
        "artifact_format": payload[14],
        "entry_point": payload[15],
        "transaction_id": payload[16:48].hex(),
        "framevm_symbols_hash": payload[48:80].hex(),
        "export_manifest_hash": payload[80:112].hex(),
        "loadable_payload_size": struct.unpack_from("<Q", payload, 112)[0],
        "retained_rlib_count": struct.unpack_from("<I", payload, 120)[0],
        "bundled_object_count": struct.unpack_from("<I", payload, 124)[0],
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def checked_range(offset: int, count: int, entry_size: int, payload_size: int, name: str) -> int:
    end = offset + count * entry_size
    assert end <= payload_size, f"{name} exceeds payload size"
    return end


def compute_transaction_id(inputs: list[dict[str, str]]) -> str:
    hasher = hashlib.sha256()
    for entry in inputs:
        update_hash_field(hasher, entry["name"], entry["value"].encode())
    return hasher.hexdigest()


def compute_actual_imports_hash(actual_imports: dict[str, Any]) -> str:
    hasher = hashlib.sha256()
    update_hash_field(hasher, "contract", CONTRACT.encode())
    update_hash_field(hasher, "kind", b"actual-import-set")
    for entry in actual_imports["imports"]:
        update_hash_field(hasher, "raw_symbol_name", bytes.fromhex(entry["raw_symbol_name_hex"]))
    return hasher.hexdigest()


def update_hash_field(hasher: Any, label: str, value: bytes) -> None:
    hasher.update(struct.pack("<I", len(label)))
    hasher.update(label.encode())
    hasher.update(struct.pack("<Q", len(value)))
    hasher.update(value)


def contains_unstable_path(value: str) -> bool:
    return any(
        marker in value
        for marker in [
            "/home/",
            "/tmp/",
            ".framevm-staging-",
            "\\home\\",
            "\\tmp\\",
        ]
    )


def flatten_json_strings(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    strings: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            strings.extend(flatten_json_strings(child, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            strings.extend(flatten_json_strings(child, f"{prefix}[{index}]"))
    elif isinstance(value, str):
        strings.append((prefix, value))
    return strings


def readelf_sections(path: Path) -> dict[str, Any]:
    output = subprocess.check_output(["readelf", "-S", "-W", path], text=True)
    first_line = output.splitlines()[0]
    count_match = re.search(r"There are (\d+) section headers", first_line)
    section_count = int(count_match.group(1)) if count_match else 0
    sections = []
    class_sizes: dict[str, int] = {}
    for line in output.splitlines():
        match = re.match(
            r"\s*\[\s*(\d+)\]\s+(\S*)\s+(\S+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s*(\S*)",
            line,
        )
        if not match:
            continue
        name = match.group(2)
        size = int(match.group(4), 16)
        flags = match.group(5)
        section = {
            "index": int(match.group(1)),
            "name": name,
            "type": match.group(3),
            "size": size,
            "flags": flags,
        }
        sections.append(section)
        class_name = section_class(name)
        class_sizes[class_name] = class_sizes.get(class_name, 0) + size
    top_sections = sorted(sections, key=lambda section: section["size"], reverse=True)[:20]
    return {
        "section_count": section_count,
        "sections": sections,
        "section_size_by_class": dict(sorted(class_sizes.items())),
        "top_sections_by_size": [
            {"name": section["name"], "size": section["size"], "flags": section["flags"]}
            for section in top_sections
        ],
    }


def section_class(name: str) -> str:
    if name.startswith(".rela") or name.startswith(".rel"):
        return "relocation"
    if name.startswith(".text"):
        return "text"
    if name.startswith(".rodata"):
        return "rodata"
    if name.startswith(".data"):
        return "data"
    if name.startswith(".bss"):
        return "bss"
    if name.startswith(".debug"):
        return "debug"
    if name.startswith(".comment"):
        return "comment"
    if name == ".framevm.meta":
        return "framevm_metadata"
    return "other"


def readelf_relocation_count(path: Path) -> int:
    output = subprocess.check_output(["readelf", "-r", "-W", path], text=True)
    return sum(int(match.group(1)) for match in re.finditer(r"contains (\d+) entries", output))


def readelf_undefined_symbols(path: Path) -> list[str]:
    output = subprocess.check_output(["readelf", "-s", "-W", path], text=True)
    symbols = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[6] == "UND":
            symbols.add(parts[7])
    return sorted(symbols)


def nm_undefined_symbols(path: Path) -> list[str]:
    output = subprocess.check_output(["nm", "-u", path], text=True)
    return sorted({line.split()[-1] for line in output.splitlines() if line.split()})


def write_report(verifier: Verifier, output_path: Path) -> None:
    report = dict(verifier.report)
    report["status"] = "failed" if verifier.failures else "passed"
    report["failures"] = verifier.failures
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("build/framevm/verification-report.json"),
    )
    args = parser.parse_args()

    verifier = Verifier(args.root)
    try:
        verifier.run()
    except AssertionError as error:
        verifier.failures.append(str(error))
    except subprocess.CalledProcessError as error:
        verifier.failures.append(f"command failed: {' '.join(map(str, error.cmd))}: {error.stderr or error}")
    except Exception as error:  # noqa: BLE001 - command-line verifier must report every failure.
        verifier.failures.append(f"unexpected verifier error: {error}")

    output_path = args.output if args.output.is_absolute() else verifier.root / args.output
    write_report(verifier, output_path)
    if verifier.failures:
        for failure in verifier.failures:
            print(f"framevm verification failed: {failure}", file=sys.stderr)
        print(f"wrote {output_path}", file=sys.stderr)
        return 1
    print(f"framevm verification passed: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
