"""Tests for the hero limit-break (Awake) cost discount and the soulgear enchant verdict.

Both live in the embedded server: the limit-break cost table is data in ``.rodata`` that
``CREATURE_TRANSCEND`` reads for the affordability check *and* for the charge, and the
soulgear enchant verdict is the single ``cset`` that materialises a hashed roll.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from core.core_patches import (
    LIMIT_BREAK_COST_TENTH_SHA256,
    LIMIT_BREAK_GOLD_FIELD_OFFSET,
    LIMIT_BREAK_GOLD_ROW_SIZE,
    LIMIT_BREAK_GOLD_ROWS,
    LIMIT_BREAK_GOLD_TABLE,
    LIMIT_BREAK_MATERIAL_FIELD_OFFSET,
    SOULGEAR_ENCHANT_ORIGINAL,
    SOULGEAR_ENCHANT_SITE,
    apply_limit_break_cost_tenth,
    apply_soulgear_enchant_always,
    seg_offset,
)

TABLE_SIZE = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS


def _table(buf: bytes | bytearray) -> bytes:
    start = seg_offset(LIMIT_BREAK_GOLD_TABLE)
    return bytes(buf[start:start + TABLE_SIZE])


def test_reference_cells_are_positive_multiples_of_ten(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    table = _table(so_bytes)
    for index in range(LIMIT_BREAK_GOLD_ROWS):
        for field_offset in (LIMIT_BREAK_MATERIAL_FIELD_OFFSET, LIMIT_BREAK_GOLD_FIELD_OFFSET):
            value = struct.unpack_from(
                "<i", table, index * LIMIT_BREAK_GOLD_ROW_SIZE + field_offset
            )[0]
            assert value > 0, f"row {index} field {field_offset} = {value}"
            assert value % 10 == 0, f"row {index} field {field_offset} = {value}"


def test_discount_rewrites_every_cell(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    changed = apply_limit_break_cost_tenth(buf)

    assert changed == LIMIT_BREAK_GOLD_ROWS
    for index in range(LIMIT_BREAK_GOLD_ROWS):
        row = LIMIT_BREAK_GOLD_TABLE + index * LIMIT_BREAK_GOLD_ROW_SIZE
        for field_offset in (LIMIT_BREAK_MATERIAL_FIELD_OFFSET, LIMIT_BREAK_GOLD_FIELD_OFFSET):
            offset = seg_offset(row + field_offset)
            before = struct.unpack_from("<i", so_bytes, offset)[0]
            after = struct.unpack_from("<i", buf, offset)[0]
            assert after == before // 10, f"row {index} field {field_offset}"


def test_discount_is_idempotent(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_limit_break_cost_tenth(buf) == LIMIT_BREAK_GOLD_ROWS
    once = bytes(buf)
    assert apply_limit_break_cost_tenth(buf) == 0
    assert bytes(buf) == once


def test_patched_table_matches_the_recorded_hash(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_limit_break_cost_tenth(buf)
    assert hashlib.sha256(_table(buf)).hexdigest() == LIMIT_BREAK_COST_TENTH_SHA256


def test_discount_refuses_a_foreign_table(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    offset = seg_offset(LIMIT_BREAK_GOLD_TABLE + LIMIT_BREAK_GOLD_FIELD_OFFSET)
    struct.pack_into("<i", buf, offset, 12_345)
    with pytest.raises(ValueError, match="Unexpected limit break cost table"):
        apply_limit_break_cost_tenth(buf)


def test_soulgear_enchant_is_forced_to_succeed(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_soulgear_enchant_always(buf) == 1

    offset = seg_offset(SOULGEAR_ENCHANT_SITE)
    assert so_bytes[offset : offset + 4] == SOULGEAR_ENCHANT_ORIGINAL
    (before,) = Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(
        SOULGEAR_ENCHANT_ORIGINAL, SOULGEAR_ENCHANT_SITE
    )
    assert before.mnemonic == "cset"

    (after,) = Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(
        bytes(buf[offset : offset + 4]), SOULGEAR_ENCHANT_SITE
    )
    assert after.mnemonic == "mov"
    assert after.op_str == "w8, #1"


def test_soulgear_enchant_patch_is_idempotent(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_soulgear_enchant_always(buf)
    once = bytes(buf)
    assert apply_soulgear_enchant_always(buf) == 0
    assert bytes(buf) == once
