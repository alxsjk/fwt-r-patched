"""Build an uninstalled, incomplete Alex skill integration laboratory APK.

This fixture includes experimental boss targeting and limited diagnostic logs.
The targeting, effects, animation, cooldown and server rules are not fully
validated. Never distribute it as a release or treat it as a completed feature.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
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
from tools.lab_alex_evolution_build import _evolution_only
from tools.lab_alex_server_flow import _candidate_in_memory
from tools.lab_alex_server_rule import _BACKWALK_CAVE, _BACKWALK_STRIDE, BACKWALK_SPECS
from tools.lab_alex_skill_client import (
    CLIENT_CAVE_START,
    RELEASE_LATE_HOOK_EXPECTED,
    RELEASE_LATE_HOOK_SITE,
    assemble_client_cave,
)
from tools.lab_alex_skill_records import prepare_assets
from tools.lab_alex_skill_server import _CANDIDATE_COST, CANDIDATE_COST_ROW


def _client_ranges(reference: bytes) -> list[tuple[int, int]]:
    late_branch, cave_bytes = assemble_client_cave()
    loads = read_load_segments(reference)
    return [
        (translate_vaddr(loads, CLIENT_CAVE_START, len(cave_bytes)), len(cave_bytes)),
        (translate_vaddr(loads, RELEASE_LATE_HOOK_SITE, len(late_branch)), len(late_branch)),
    ]


def _server_ranges(reference: bytes) -> list[tuple[int, int]]:
    elf = ELFFile(io.BytesIO(reference))
    segments = list(elf.iter_segments())
    writable = [i for i, segment in enumerate(segments)
                if segment["p_type"] == "PT_LOAD" and int(segment["p_flags"]) & 2
                and int(segment["p_vaddr"]) + int(segment["p_memsz"]) == 0xBE6268]
    if len(writable) != 1:
        raise ValueError("Unexpected writable segment")
    ph_offset = int(elf.header["e_phoff"]) + writable[0] * int(elf.header["e_phentsize"]) + 40
    loads = read_load_segments(reference)
    specs = [
        (0x9029B8, 4), (0xB34D44, 288), (0x6DADFC, 24),
        (0x8C39D0, 4), (0x800E00, 4),
        (_CANDIDATE_COST, len(CANDIDATE_COST_ROW) * 4),
        (_BACKWALK_CAVE, len(BACKWALK_SPECS) * _BACKWALK_STRIDE),
        *((site, 4) for _name, site, *_rest in BACKWALK_SPECS),
    ]
    return [(ph_offset, 8)] + [
        (translate_vaddr(loads, address, size), size)
        for address, size in specs
    ]


def _compose_server(reference: bytes, patched: bytes) -> bytes:
    """Compose the full synthetic fixture, rejecting overlapping patch ranges."""
    if len(reference) != len(patched):
        raise ValueError("Unexpected patched server length")
    candidate = _candidate_in_memory(reference)
    ranges = _server_ranges(reference)
    output = bytearray(patched)
    for offset, size in ranges:
        if patched[offset:offset + size] != reference[offset:offset + size]:
            raise ValueError(f"Skill fixture overlaps existing patch at {offset:#x}")
        output[offset:offset + size] = candidate[offset:offset + size]
    late_branch, cave_bytes = assemble_client_cave()
    (cave_off, cave_size), (late_off, late_size) = _client_ranges(reference)
    if patched[cave_off:cave_off + cave_size] != reference[cave_off:cave_off + cave_size]:
        raise ValueError(f"Client cave overlaps existing patch at {cave_off:#x}")
    if patched[late_off:late_off + late_size] != reference[late_off:late_off + late_size]:
        raise ValueError(f"Client hook overlaps existing patch at {late_off:#x}")
    if patched[late_off:late_off + late_size] != RELEASE_LATE_HOOK_EXPECTED:
        raise ValueError(f"Unexpected post-AppSealing call at {late_off:#x}")
    output[cave_off:cave_off + cave_size] = cave_bytes
    output[late_off:late_off + late_size] = late_branch
    return bytes(output)


def verify_artifact(reference_apk: Path, release_apk: Path, lab_apk: Path) -> None:
    """Verify the skill fixture independently of the build process."""
    library = "lib/arm64-v8a/libfwt_local_server.so"
    resources = "assets/fwt_resources_v1.zip"
    with zipfile.ZipFile(reference_apk) as source:
        reference = source.read(library)
    with zipfile.ZipFile(release_apk) as release:
        baseline = release.read(library)
        with release.open(resources) as stream, zipfile.ZipFile(stream) as archive:
            expected_assets = prepare_assets(archive)
            expected_assets[_PATH] = _patch_gate(archive.read(_PATH))
    expected_server = _compose_server(reference, baseline)
    ranges = _server_ranges(reference)
    all_ranges = ranges + _client_ranges(reference)
    with zipfile.ZipFile(lab_apk) as lab:
        identity = json.loads(lab.read("assets/fwt_re_patched_build_type.txt"))
        if identity.get("identity") != "dev":
            raise ValueError("Artifact is not identified as a development build")
        actual = lab.read(library)
        for offset, size in all_ranges:
            if actual[offset:offset + size] != expected_server[offset:offset + size]:
                raise ValueError(f"Unexpected fixture bytes at {offset:#x}")
        with lab.open(resources) as stream, zipfile.ZipFile(stream) as archive:
            for path, expected in expected_assets.items():
                if archive.read(path) != expected:
                    raise ValueError(f"Unexpected fixture asset: {path}")
    conflict = bytearray(baseline)
    conflict[ranges[-1][0]] ^= 1
    try:
        _compose_server(reference, bytes(conflict))
    except ValueError:
        pass
    else:
        raise ValueError("Server composition did not reject a conflict")
    print("DEV identity, 27 client assets, server/client fixtures and conflict guard verified.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--creature-only", action="store_true",
                        help="isolate creature tables; still not a playable skill")
    parsed = parser.parse_args()
    name = "Creature-Isolation" if parsed.creature_only else "Skill-Integration"
    output_path = Path(f"output/FWT-Reborn-Alex-{name}-Lab-{APP_VERSION}-dev.apk")
    if parsed.verify:
        if parsed.creature_only:
            parser.error("--verify currently covers only the full integration fixture")
        verify_artifact(Path("source/fwt_0.682_offline_v1574.apk"),
                        Path(f"output/FWT-Reborn-Patched-{APP_VERSION}-release.apk"), output_path)
        return 0
    fwt_patcher._load_env_file()
    args = fwt_patcher.build_parser().parse_args(
        ["--all", "--dev", "--dev-keep-version", "--dev-marker", "--output", str(output_path)]
    )
    original_resources = apk_tooling._patch_resources_zip_file
    original_patches = apk_tooling.apply_all_patches

    def lab_resources(raw_zip: Path, options: Any, *, work_dir: Path,
                      log_fn: Any = None) -> tuple[Path, ResourceContract | None]:
        patched, _ = original_resources(raw_zip, options, work_dir=work_dir, log_fn=log_fn)
        with zipfile.ZipFile(patched) as archive:
            replacement = prepare_assets(archive)
            if parsed.creature_only:
                replacement = {path: asset for path, asset in replacement.items()
                               if path.rsplit("/", 1)[-1].startswith("creaturedata")}
            replacement[_PATH] = _patch_gate(archive.read(_PATH))
        lab_path = work_dir / "fwt_resources_alex_skill_integration_lab.zip"
        apk_tooling._rewrite_zip_entries_to_file(patched, replacement, lab_path)
        if log_fn:
            log_fn("LAB ONLY: experimental Alex skill and boss targeting; device validation pending")
        return lab_path, ResourceContract.from_archive_path(lab_path)

    def lab_patches(so_bytes: bytes, dex_bytes: bytes, options: PatchOptions, *,
                    resource_contract: ResourceContract | None = None,
                    apktool_jar: str | Path | None = None,
                    log_fn: Callable[[str], None] | None = None) -> PatchResult:
        result = original_patches(so_bytes, dex_bytes, options,
                                  resource_contract=resource_contract,
                                  apktool_jar=apktool_jar, log_fn=log_fn)
        modified = (_evolution_only(so_bytes, result.so_bytes) if parsed.creature_only
                    else _compose_server(so_bytes, result.so_bytes))
        return replace(result, so_bytes=modified, so_sha256=hashlib.sha256(modified).hexdigest(),
                       warnings=[*result.warnings,
                                 "LAB ONLY: experimental skill and boss targeting; validation pending"])

    apk_tooling._patch_resources_zip_file = lab_resources
    apk_tooling.apply_all_patches = lab_patches
    try:
        return fwt_patcher.run_cli(args)
    finally:
        apk_tooling._patch_resources_zip_file = original_resources
        apk_tooling.apply_all_patches = original_patches


if __name__ == "__main__":
    raise SystemExit(main())
