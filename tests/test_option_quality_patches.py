"""Byte-level regression tests for the option and rune quality patches.

Both patches are plain instruction swaps, so the test pins the encodings and the
disassembly of the replacement: a wrong word would otherwise only show up as a
crash (or a silent no-op) on the device.
"""

import struct

import pytest

capstone = pytest.importorskip("capstone")
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from core.core_patches import (
    OPTION_BONUS_BOOL_ORIGINAL,
    OPTION_BONUS_BOOL_SITE,
    OPTION_BONUS_MASTERY_ORIGINAL,
    OPTION_BONUS_MASTERY_SITE,
    RANDOPTION_QUALITY_SITE,
    RANDOPTION_TOP_QUALITY,
    RUNE_OPTION_MASTERY_ORIGINAL,
    RUNE_OPTION_MASTERY_REPLACEMENT,
    RUNE_OPTION_MASTERY_SITE,
    RUNE_OPTION_ROW_COUNT,
    RUNE_OPTION_ROW_SIZE,
    RUNE_OPTION_TABLE_VADDR,
    _randoption_rows,
    apply_option_max_attributes,
    apply_rune_option_quality,
    apply_rune_quality_factor,
    randoption_top_quality_state,
    seg_offset,
)
from core.patch_inspector import inspect_native_so

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def _disasm(blob: bytes, addr: int) -> list[str]:
    return [f"{i.mnemonic} {i.op_str}" for i in MD.disasm(blob, addr)]


def _option_pools(so_bytes: bytes) -> dict[tuple[int, int], list[tuple[int, int, int]]]:
    """Maps each (attribute, equipment grade) pool to its (id, weight, quality) rows."""
    pools: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
    for _index, option_id, pool_key, weights, quality in _randoption_rows(so_bytes):
        for column, weight in enumerate(weights):
            if weight > 0:
                pools.setdefault((pool_key, column), []).append(
                    (option_id, weight, quality)
                )
    return pools


def test_option_max_quality_leaves_only_the_top_rows_weighted(reference_buffers):
    original, _ = reference_buffers
    before = _option_pools(original)
    buf = bytearray(original)
    assert apply_option_max_attributes(buf) > 0
    after = _option_pools(bytes(buf))
    assert set(after) == set(before)
    assert len(after) == 180, "one pool per attribute and equipment grade"
    for key, members in after.items():
        best = max(quality for _id, _weight, quality in members)
        assert best == RANDOPTION_TOP_QUALITY
        assert all(quality == best for _id, _weight, quality in members)
        assert sum(weight for _id, weight, _quality in members) == sum(
            weight for _id, weight, _quality in before[key]
        ), "the attribute must keep the odds it had"


def test_option_max_quality_is_idempotent_and_keeps_the_picker_stock(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    assert apply_option_max_attributes(buf) > 0
    patched = bytes(buf)
    assert randoption_top_quality_state(patched) == ({}, 180)
    assert apply_option_max_attributes(buf) == 0
    assert bytes(buf) == patched
    # The old quality-bias words stay stock: the mastery picker bypasses locked
    # attributes, so the bias must come from the table instead.
    for site, word in (
        (OPTION_BONUS_BOOL_SITE, OPTION_BONUS_BOOL_ORIGINAL),
        (OPTION_BONUS_MASTERY_SITE, OPTION_BONUS_MASTERY_ORIGINAL),
    ):
        offset = seg_offset(site)
        assert bytes(buf[offset:offset + len(word)]) == word


def test_option_max_quality_refuses_a_mismatched_quality_table(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    offset = seg_offset(RANDOPTION_QUALITY_SITE)
    buf[offset] = 1  # the parallel table must name the same option ids
    before = bytes(buf)
    with pytest.raises(ValueError, match="names option"):
        apply_option_max_attributes(buf)
    assert bytes(buf) == before


def test_rune_mastery_replacement_is_max_level_and_keeps_the_flow():
    # bl mastery_level_in_state -> mov x0, #0xf
    assert len(RUNE_OPTION_MASTERY_REPLACEMENT) == 4
    assert _disasm(RUNE_OPTION_MASTERY_REPLACEMENT, RUNE_OPTION_MASTERY_SITE) == [
        "mov x0, #0xf"  # the clamp at 0xa2e718 still caps it, and x0 is read right after
    ]
    assert _disasm(RUNE_OPTION_MASTERY_ORIGINAL, RUNE_OPTION_MASTERY_SITE)[0].startswith("bl ")


def test_apply_rune_quality_writes_the_site_once(reference_buffers):
    source, _ = reference_buffers
    buf = bytearray(source)
    offset = seg_offset(RUNE_OPTION_MASTERY_SITE)
    assert apply_rune_option_quality(buf) == 1
    assert bytes(buf[offset : offset + 4]) == RUNE_OPTION_MASTERY_REPLACEMENT
    assert apply_rune_option_quality(buf) == 0


def test_rune_pink_keeps_only_top_quality_rows_weighted(reference_buffers):
    source, _ = reference_buffers
    buf = bytearray(source)
    start = seg_offset(RUNE_OPTION_TABLE_VADDR)

    def _pools(data: bytes) -> dict[tuple[int, int, int, int, int], list[tuple[int, int, int]]]:
        grouped: dict[tuple[int, int, int, int, int], list[tuple[int, int, int]]] = {}
        for index in range(RUNE_OPTION_ROW_COUNT):
            offset = start + index * RUNE_OPTION_ROW_SIZE
            option_id, kind, _condition, value_type, grade = struct.unpack_from("<5i", data, offset)
            slot, fourth = struct.unpack_from("<2i", data, offset + 0x18)
            weight = struct.unpack_from("<i", data, offset + 0x20)[0]
            quality = struct.unpack_from("<i", data, offset + 0x24)[0]
            grouped.setdefault((kind, grade, slot, fourth, value_type), []).append(
                (option_id, quality, weight)
            )
        return grouped

    before = _pools(source)
    assert apply_rune_quality_factor(buf, 10) == 1
    assert apply_rune_option_quality(buf) == 1
    after = _pools(bytes(buf))
    for key, rows in after.items():
        if key[4] == 1:
            assert all(weight == 0 for _option_id, _quality, weight in rows)
            continue
        source_total = sum(weight for _option_id, _quality, weight in before[key])
        if source_total == 0:
            continue
        best = max(quality for _option_id, quality, _weight in rows)
        weighted = [entry for entry in rows if entry[2] > 0]
        assert weighted
        assert all(quality == best for _option_id, quality, _weight in weighted)
        assert sum(weight for _option_id, _quality, weight in rows) == source_total
    assert inspect_native_so(bytes(buf))["rune_option_quality"].active




def test_rune_percent_only_preserves_eligible_rolls_and_rejects_damage(reference_buffers):
    source, _ = reference_buffers
    buf = bytearray(source)
    start = seg_offset(RUNE_OPTION_TABLE_VADDR)
    assert apply_rune_quality_factor(buf, 10) == 1
    eligible: dict[tuple[int, int, int], set[int]] = {}
    flat_count = 0
    for index in range(RUNE_OPTION_ROW_COUNT):
        offset = start + index * RUNE_OPTION_ROW_SIZE
        before = struct.unpack_from("<12i", source, offset)
        after = struct.unpack_from("<12i", buf, offset)
        if before[3] == 1:
            flat_count += 1
            assert after[8] == 0
        else:
            assert after == before
            if before[3] in (2, 4) and before[8] > 0:
                for slot in (1, 2, 3):
                    if before[6] in (0, slot):
                        eligible.setdefault((before[4], slot, before[7]), set()).add(before[1])
    assert flat_count == 420
    for grade in range(1, 7):
        for slot in (1, 2, 3):
            assert len(eligible[grade, slot, 0]) >= 4
            if grade >= 3 or slot != 3:
                assert len(eligible[grade, slot, 1]) >= 4
    assert apply_rune_quality_factor(buf, 10) == 0
    assert inspect_native_so(bytes(buf))["rune_quality_factor"].active
    buf[start + 12] ^= 1
    assert not inspect_native_so(bytes(buf))["rune_quality_factor"].active
    with pytest.raises(ValueError, match="Unexpected rune option table"):
        apply_rune_quality_factor(buf, 10)
