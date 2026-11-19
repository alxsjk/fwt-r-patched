"""Checks for the experimental complete costume package patch."""
from __future__ import annotations

from pathlib import Path

import pytest

from core.costume_packages import CAVES, HOOKS, apply_costume_packages, inspect_costume_packages
from core.elf_mapping import read_load_segments, translate_vaddr


@pytest.fixture
def reference() -> bytearray:
    path = Path(__file__).resolve().parent.parent / "output/costume-124-original-lab.so"
    if not path.exists():
        pytest.skip("isolated emulator lab library not available")
    return bytearray(path.read_bytes())


def _offset(buf: bytearray):
    segments = read_load_segments(buf)
    return lambda address: translate_vaddr(segments, address)


def test_patch_is_complete_and_idempotent(reference: bytearray) -> None:
    offset = _offset(reference)
    assert not inspect_costume_packages(reference)
    assert apply_costume_packages(reference, offset) == 10
    assert inspect_costume_packages(reference)
    once = bytes(reference)
    assert apply_costume_packages(reference, offset) == 0
    assert bytes(reference) == once


@pytest.mark.parametrize("address", [row[0] for row in CAVES] + [row[0] for row in HOOKS])
def test_unknown_code_is_rejected_without_any_mutation(reference: bytearray, address: int) -> None:
    offset = _offset(reference)
    reference[offset(address)] ^= 1
    before = bytes(reference)
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_costume_packages(reference, offset)
    assert bytes(reference) == before
    assert not inspect_costume_packages(reference)


def test_generated_code_matches_frozen_payload() -> None:
    pytest.importorskip("keystone")
    from tools.gen_costume_claim_hook_v3 import generate as claim
    from tools.gen_owned_costume_caves import generate as rewards

    assert tuple(row[1] for row in CAVES) == (*rewards(), b"".join(claim()))

@pytest.mark.parametrize("rune_upgrade", [False, True])
def test_reference_engine_and_inspector(
    reference_buffers: tuple[bytes, bytes], rune_upgrade: bool
) -> None:
    from core.core_patches import PatchOptions, apply_all_patches
    from core.patch_inspector import inspect_native_so

    so, dex = reference_buffers
    result = apply_all_patches(
        so, dex, PatchOptions(costume_packages_all=True, rune_upgrade_discount=rune_upgrade)
    )
    assert result.counts["costume_packages_all"] == 10
    assert inspect_native_so(result.so_bytes)["costume_packages_all"].active


def test_reference_composes_with_event_shop_options(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    from core.core_patches import PatchOptions, apply_all_patches
    from core.patch_inspector import inspect_native_so

    so, dex = reference_buffers
    result = apply_all_patches(
        so, dex, PatchOptions(costume_packages_all=True, mythical_stone_shop=True,
                              event_discount=True, event_limits_daily=True,
                              rune_upgrade_discount=True)
    )
    reports = inspect_native_so(result.so_bytes)
    assert reports["costume_packages_all"].active
    assert reports["mythical_stone_shop"].active
    assert reports["event_limits_daily"].active
