"""Tests for the equipment tier patch and its dependencies."""
from __future__ import annotations

import pytest

from core.core_patches import PatchOptions, apply_all_patches
from core.equipment_tier_upgrades import CAVES, HOOKS, apply_equipment_tiers
from core.patch_inspector import inspect_native_so


@pytest.mark.parametrize("black", [False, True])
@pytest.mark.parametrize("success", [False, True])
def test_option_composes_with_existing_features(
    reference_buffers: tuple[bytes, bytes], black: bool, success: bool
) -> None:
    so, dex = reference_buffers
    result = apply_all_patches(so, dex, PatchOptions(
        equipment_tier_upgrades=True,
        single_black_hammer=black,
        upgrade_no_fail_above_20=success,
    ))
    assert result.counts["equipment_tier_upgrades"] == 4
    reports = inspect_native_so(result.so_bytes)
    assert reports["equipment_tier_upgrades"].active
    assert reports["single_black_hammer"].active
    assert reports["upgrade_no_fail_above_20"].active

    again = apply_all_patches(result.so_bytes, dex, PatchOptions(
        equipment_tier_upgrades=True, single_black_hammer=black,
        upgrade_no_fail_above_20=success, allow_unknown=True,
    ))
    assert again.counts["equipment_tier_upgrades"] == 0
    assert again.so_bytes == result.so_bytes


def test_generated_payloads_match_frozen_code() -> None:
    pytest.importorskip("keystone")
    from tools.gen_equipment_tier_client_lab import generate as client
    from tools.gen_equipment_tier_lab import generate as server

    assert tuple(row[1] for row in CAVES) == (server(), client())


@pytest.mark.parametrize("address", [row[0] for row in CAVES] + [row[0] for row in HOOKS])
def test_invalid_bytes_rejected_before_mutation(reference_buffers: tuple[bytes, bytes], address: int) -> None:
    from core.elf_mapping import read_load_segments, translate_vaddr

    buf = bytearray(reference_buffers[0])
    segments = read_load_segments(buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    buf[offset(address)] ^= 1
    before = bytes(buf)
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_equipment_tiers(buf, offset)
    assert bytes(buf) == before
