"""Emulation unit tests for the Alex 5th skill server/client lab hooks."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from core.alex_awakening import apply_alex_awakening, inspect_alex_awakening_native
from core.alex_awakening_assets import _PATH as REBIRTH_PATH
from core.alex_awakening_assets import _patch_gate as core_gate
from core.alex_awakening_assets import inspect_alex_awakening_assets
from core.alex_awakening_assets import prepare_assets as core_assets
from core.alex_awakening_client import assemble_client_cave as core_client
from core.alex_awakening_native import _candidate_in_memory as core_candidate
from core.core_patches import PatchOptions, apply_all_patches, validate_patch_options
from core.elf_mapping import read_load_segments, translate_vaddr
from core.patch_inspector import inspect_native_so
from tools.lab_alex_awake_gate import _patch_gate as lab_gate
from tools.lab_alex_server_flow import _candidate_in_memory as lab_candidate
from tools.lab_alex_skill_build import _compose_server as lab_compose
from tools.lab_alex_skill_client import assemble_client_cave as lab_client
from tools.lab_alex_skill_client import exercise as exercise_client
from tools.lab_alex_skill_records import prepare_assets as lab_assets
from tools.lab_alex_skill_server import CANDIDATE_COST_ROW, make_candidate_cost_row
from tools.lab_alex_skill_server import exercise as exercise_server


def test_skill_cost_row_scales_10_to_90_genes() -> None:
    assert CANDIDATE_COST_ROW == (0x100185, 10, 20, 30, 40, 50, 60, 70, 80, 90, -1)
    assert len(make_candidate_cost_row()) == 44


def test_skill_server_emulation() -> None:
    exercise_server()


def test_skill_client_hooks_emulation_zero_and_aslr_base() -> None:
    exercise_client(base=0)
    exercise_client(base=0x4000000000)


def test_skill_client_hook_install_failure_is_reported() -> None:
    exercise_client(base=0x4000000000, failed_hook=1)


def test_release_client_hooks_emulation_without_diagnostics() -> None:
    exercise_client(base=0, diagnostics=False)
    exercise_client(base=0x4000000000, diagnostics=False)


def test_core_client_preserves_tested_diagnostic_build_and_disables_release_logging() -> None:
    diagnostic_branch, diagnostic = core_client(diagnostics=True)
    release_branch, release = core_client()
    assert (diagnostic_branch, diagnostic) == lab_client()
    assert release_branch == diagnostic_branch
    assert len(release) == len(diagnostic)
    assert b"FWT-ALEX-LAB" in diagnostic
    assert b"FWT-ALEX-LAB" not in release
    assert b"player_auto_skill=%d" not in release


@pytest.mark.integration
def test_core_native_matches_emulated_fixture_and_rejects_unknown_reference(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    original, _ = reference_buffers
    assert core_candidate(original) == lab_candidate(original)
    modified = bytearray(original)
    modified[0] ^= 1
    with pytest.raises(ValueError, match="supported original"):
        core_candidate(bytes(modified))


@pytest.mark.integration
def test_core_composition_matches_device_fixture_and_rejects_overlap(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    original, _ = reference_buffers
    assert apply_alex_awakening(original, original, diagnostics=True) == lab_compose(original, original)
    release = apply_alex_awakening(original, original)
    assert b"FWT-ALEX-LAB" not in release
    assert inspect_alex_awakening_native(release)
    assert not inspect_alex_awakening_native(original)
    incomplete = bytearray(release)
    incomplete[translate_vaddr(read_load_segments(release), 0xA3608C, 4)] ^= 1
    assert not inspect_alex_awakening_native(incomplete)
    conflict = bytearray(original)
    conflict[translate_vaddr(read_load_segments(original), 0xB34D44, 4)] ^= 1
    with pytest.raises(ValueError, match="overlaps"):
        apply_alex_awakening(original, bytes(conflict))


def test_alex_requires_exact_reference_even_with_force() -> None:
    with pytest.raises(ValueError, match="exact reference"):
        validate_patch_options(PatchOptions(alex_awakening=True, allow_unknown=True))


@pytest.mark.integration
def test_core_engine_applies_and_inspects_alex(reference_buffers: tuple[bytes, bytes]) -> None:
    original, dex = reference_buffers
    result = apply_all_patches(original, dex, PatchOptions(alex_awakening=True))
    assert result.counts["alex_awakening"] == 1
    assert inspect_native_so(result.so_bytes)["alex_awakening"].active


@pytest.mark.integration
def test_core_assets_match_round_tripped_laboratory_fixture(reference_apk: Path) -> None:
    with (zipfile.ZipFile(reference_apk) as outer,
          outer.open("assets/fwt_resources_v1.zip") as stream,
          zipfile.ZipFile(stream) as resources):
        gate = core_gate(resources.read(REBIRTH_PATH))
        assert gate == lab_gate(resources.read(REBIRTH_PATH))
        assets = core_assets(resources)
        assert assets == lab_assets(resources)
        assert not inspect_alex_awakening_assets(resources)[0]
        with io.BytesIO() as buffer:
            with zipfile.ZipFile(buffer, "w") as patched:
                for path, data in {**assets, REBIRTH_PATH: gate}.items():
                    patched.writestr(path, data)
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as patched:
                assert inspect_alex_awakening_assets(patched)[0]
