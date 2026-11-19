"""Tests for the unexposed server-side rune upgrade building block."""

import struct

import pytest

from core.apk_tooling import _patch_rune_upgrade_rows
from core.core_patches import (
    RUNE_DECIDED_COST_ORIGINAL,
    RUNE_DECIDED_COST_PATCHED,
    RUNE_DECIDED_COST_SITE,
    RUNE_UPGRADE_ROW_COUNT,
    RUNE_UPGRADE_ROW_SIZE,
    RUNE_UPGRADE_TABLE_VADDR,
    apply_rune_upgrade_server_only,
    seg_offset,
)


def test_rune_upgrade_server_targets_only_requested_levels(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    assert apply_rune_upgrade_server_only(buf) == 2
    offset = seg_offset(RUNE_UPGRADE_TABLE_VADDR)
    for level in range(RUNE_UPGRADE_ROW_COUNT):
        row = offset + level * RUNE_UPGRADE_ROW_SIZE
        before = struct.unpack_from("<19i", original, row)
        after = struct.unpack_from("<19i", buf, row)
        assert after[:7] == before[:7]
        if level < 12:
            assert after == before
        else:
            assert after[7:13] == (0,) * 6
            assert after[13:19] == tuple(value // 10 for value in before[13:19])
    assert apply_rune_upgrade_server_only(buf) == 0


def test_rune_upgrade_server_rejects_unknown_layout_without_writes(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    buf[seg_offset(RUNE_DECIDED_COST_SITE)] ^= 1
    before = bytes(buf)
    with pytest.raises(ValueError, match="Unexpected rune decided cost"):
        apply_rune_upgrade_server_only(buf)
    assert bytes(buf) == before


def test_rune_decided_discount_divides_rounded_cost_by_ten():
    unicorn = pytest.importorskip("unicorn")
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X8,
        UC_ARM64_REG_X9,
        UC_ARM64_REG_X10,
    )

    def run(code: bytes, rounded_units: int) -> int:
        uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        uc.mem_map(0x10000, 0x1000)
        uc.mem_write(0x10000, code)
        uc.reg_write(UC_ARM64_REG_X8, 0)
        uc.reg_write(UC_ARM64_REG_X9, 100)
        uc.reg_write(UC_ARM64_REG_X10, rounded_units)
        uc.emu_start(0x10000, 0x10000 + len(code))
        return int(uc.reg_read(UC_ARM64_REG_X0))

    for rounded_units in (0, 1, 10, 9506, 27266):
        original = run(RUNE_DECIDED_COST_ORIGINAL, rounded_units)
        discounted = run(RUNE_DECIDED_COST_PATCHED, rounded_units)
        assert original == rounded_units * 100
        assert discounted == original // 10


def test_zero_failure_weight_guarantees_success(reference_buffers):
    unicorn = pytest.importorskip("unicorn")
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
    )

    original, _ = reference_buffers
    start = 0xA17284
    end = 0xA173AC
    code = original[seg_offset(start):seg_offset(end)]
    for mastery in (0, 450, 900):
        uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        uc.mem_map(0xA17000, 0x1000)
        uc.mem_map(0x20000, 0x1000)
        uc.mem_write(start, code)
        uc.reg_write(UC_ARM64_REG_X0, 0x20000)  # empty seed string
        uc.reg_write(UC_ARM64_REG_X1, 30000)
        uc.reg_write(UC_ARM64_REG_X2, 0)
        uc.reg_write(UC_ARM64_REG_X3, mastery)
        uc.reg_write(UC_ARM64_REG_LR, 0xA17FFC)
        uc.emu_start(start, 0xA17FFC)
        assert uc.reg_read(UC_ARM64_REG_X0) == 1


def test_rune_upgrade_client_rows_are_idempotent_and_fail_closed():
    rows = []
    for level, failures, costs in (
        (12, (5188, 5707, 6278, 9414, 10986, 12555),
         (8500, 17000, 34000, 59500, 74800, 136000)),
        (13, (5707, 6278, 6906, 10355, 12085, 13811),
         (9200, 18400, 36800, 64400, 80960, 147200)),
        (14, (6278, 6906, 7597, 11391, 13294, 15192),
         (9950, 19900, 39800, 69650, 87560, 159200)),
    ):
        row = {"_baseRuneEnchant": level}
        for grade in range(1, 7):
            row[f"_successProb{grade}"] = 30000
            row[f"_failProb{grade}"] = failures[grade - 1]
            row["_goldCost" if grade == 1 else f"_goldCost{grade}"] = costs[grade - 1]
        rows.append(row)
    other = {"_baseRuneEnchant": 11, "_goldCost": 7850, "_failProb1": 4716}
    rows.append(other)
    assert _patch_rune_upgrade_rows(rows) == 3
    assert rows[0]["_goldCost"] == 850
    assert rows[1]["_goldCost6"] == 14720
    assert all(row[f"_failProb{grade}"] == 0 for row in rows[:3] for grade in range(1, 7))
    assert other == {"_baseRuneEnchant": 11, "_goldCost": 7850, "_failProb1": 4716}
    assert _patch_rune_upgrade_rows(rows) == 0
    rows[1]["_goldCost"] += 1
    with pytest.raises(ValueError, match="unexpected rune upgrade client row"):
        _patch_rune_upgrade_rows(rows)
