"""Prepare an uninstalled DEV-only Alex evolution experiment.

This laboratory build combines the client Awake gate with a candidate native
evolution rule. It deliberately does not add the new skill or automatic boss
targeting. Do not treat this as a release or perform an evolution on a valuable
save. Device use remains subject to the repository's code-cave validation gates.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import zipfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

import core.apk_tooling as apk_tooling
import fwt_patcher
from core.core_patches import PatchOptions, PatchResult
from core.dex_smali import ResourceContract
from core.elf_mapping import read_load_segments, translate_vaddr
from core.version import APP_VERSION
from tools.lab_alex_awake_gate import _PATH, _patch_gate
from tools.lab_alex_server_flow import _candidate_in_memory
from tools.lab_alex_server_rule import _BACKWALK_CAVE, _BACKWALK_STRIDE, BACKWALK_SPECS


def _evolution_only(reference: bytes, patched: bytes) -> bytes:
    """Compose only the tested evolution model over compatible patch output."""
    candidate = _candidate_in_memory(reference)
    if len(patched) != len(reference):
        raise ValueError("Unexpected patched server length")
    elf = ELFFile(io.BytesIO(reference))
    segments = list(elf.iter_segments())
    final = [index for index, segment in enumerate(segments)
             if segment["p_type"] == "PT_LOAD" and int(segment["p_flags"]) & 2
             and int(segment["p_vaddr"]) + int(segment["p_memsz"]) == 0xBE6268]
    if len(final) != 1:
        raise ValueError("Unexpected server writable-segment layout")
    ph_offset = int(elf.header["e_phoff"]) + final[0] * int(elf.header["e_phentsize"]) + 40
    loads = read_load_segments(reference)
    ranges = (
        (ph_offset, 8),
        (translate_vaddr(loads, 0x9029B8, 4), 4),
        (translate_vaddr(loads, 0xB34D44, 196), 196),
        (translate_vaddr(loads, _BACKWALK_CAVE, len(BACKWALK_SPECS) * _BACKWALK_STRIDE),
         len(BACKWALK_SPECS) * _BACKWALK_STRIDE),
        *((translate_vaddr(loads, site, 4), 4) for _name, site, *_rest in BACKWALK_SPECS),
    )
    output = bytearray(patched)
    for offset, length in ranges:
        if patched[offset:offset + length] != reference[offset:offset + length]:
            raise ValueError(f"Evolution candidate overlaps an existing patch at {offset:#x}")
        output[offset:offset + length] = candidate[offset:offset + length]
    if struct.unpack_from("<Q", output, ph_offset)[0] != int(segments[final[0]]["p_memsz"]) + 96:
        raise ValueError("Evolution candidate segment size did not round-trip")
    return bytes(output)


def verify_compatibility(reference_path: Path, apk_path: Path) -> None:
    """Check composition against an existing build, entirely in memory."""
    reference = reference_path.read_bytes()
    with zipfile.ZipFile(apk_path) as archive:
        patched = archive.read("lib/arm64-v8a/libfwt_local_server.so")
    candidate = _evolution_only(reference, patched)
    loads = read_load_segments(reference)
    skill_offset = translate_vaddr(loads, 0x6DAE10, 4)
    if candidate[skill_offset:skill_offset + 4] != patched[skill_offset:skill_offset + 4]:
        raise ValueError("Evolution-only candidate unexpectedly changes Alex's skill")
    hook_offset = translate_vaddr(loads, 0x9029B8, 4)
    conflict = bytearray(patched)
    conflict[hook_offset] ^= 1
    try:
        _evolution_only(reference, bytes(conflict))
    except ValueError:
        pass
    else:
        raise ValueError("Evolution candidate failed to reject an overlapping patch")
    print("Evolution-only composition passed; conflicts rejected; no assets written.")


def verify_artifact(reference_path: Path, release_path: Path, lab_path: Path) -> None:
    """Verify the saved lab server against independently composed bytes."""
    reference = reference_path.read_bytes()
    with zipfile.ZipFile(release_path) as archive:
        baseline = archive.read("lib/arm64-v8a/libfwt_local_server.so")
        with archive.open("assets/fwt_resources_v1.zip") as source, zipfile.ZipFile(source) as resources:
            original_gate = resources.read(_PATH)
    with zipfile.ZipFile(lab_path) as archive:
        actual = archive.read("lib/arm64-v8a/libfwt_local_server.so")
        identity = json.loads(archive.read("assets/fwt_re_patched_build_type.txt"))
        with archive.open("assets/fwt_resources_v1.zip") as source, zipfile.ZipFile(source) as resources:
            actual_gate = resources.read(_PATH)
    if identity.get("identity") != "dev":
        raise ValueError("Laboratory artifact is not marked DEV")
    if actual != _evolution_only(reference, baseline):
        raise ValueError("Laboratory server differs from expected evolution-only composition")
    if actual_gate != _patch_gate(original_gate):
        raise ValueError("Laboratory evolution table differs from expected fixture")
    print("DEV identity, server and client evolution fixture verified against release.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--server", type=Path)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--verify-artifact", type=Path)
    lab_args = parser.parse_args()
    if lab_args.verify_only:
        if lab_args.server is None or lab_args.apk is None:
            parser.error("--verify-only requires --server and --apk")
        if lab_args.verify_artifact is None:
            verify_compatibility(lab_args.server, lab_args.apk)
        else:
            verify_artifact(lab_args.server, lab_args.apk, lab_args.verify_artifact)
        return 0
    if lab_args.server is not None or lab_args.apk is not None or lab_args.verify_artifact is not None:
        parser.error("--server, --apk and --verify-artifact require --verify-only")
    fwt_patcher._load_env_file()
    output = f"output/FWT-Reborn-Alex-Evolution-Lab-{APP_VERSION}-dev.apk"
    args = fwt_patcher.build_parser().parse_args(
        ["--all", "--dev", "--dev-keep-version", "--output", output]
    )
    original_resources = apk_tooling._patch_resources_zip_file
    original_patches = apk_tooling.apply_all_patches

    def lab_resources(raw_zip: Path, options: Any, *, work_dir: Path,
                      log_fn: Any = None) -> tuple[Path, ResourceContract | None]:
        patched, _ = original_resources(raw_zip, options, work_dir=work_dir, log_fn=log_fn)
        with zipfile.ZipFile(patched) as archive:
            replacement = _patch_gate(archive.read(_PATH))
        lab_path = work_dir / "fwt_resources_alex_evolution_lab.zip"
        apk_tooling._rewrite_zip_entries_to_file(patched, {_PATH: replacement}, lab_path)
        if log_fn:
            log_fn("LAB ONLY: Alex evolution fixture; original Awake skill is not implemented")
        return lab_path, ResourceContract.from_archive_path(lab_path)

    def lab_patches(so_bytes: bytes, dex_bytes: bytes, options: PatchOptions, *,
                    resource_contract: ResourceContract | None = None,
                    apktool_jar: str | Path | None = None,
                    log_fn: Callable[[str], None] | None = None) -> PatchResult:
        result = original_patches(so_bytes, dex_bytes, options,
                                  resource_contract=resource_contract,
                                  apktool_jar=apktool_jar, log_fn=log_fn)
        modified = _evolution_only(so_bytes, result.so_bytes)
        return replace(result, so_bytes=modified, so_sha256=hashlib.sha256(modified).hexdigest(),
                       warnings=[*result.warnings,
                                 "LAB ONLY: Alex evolution model; not a complete feature"])

    apk_tooling._patch_resources_zip_file = lab_resources
    apk_tooling.apply_all_patches = lab_patches
    try:
        return fwt_patcher.run_cli(args)
    finally:
        apk_tooling._patch_resources_zip_file = original_resources
        apk_tooling.apply_all_patches = original_patches


if __name__ == "__main__":
    raise SystemExit(main())
