"""Regression tests for the flat hero limit-break price (feature 06.09).

The feature rewrites ``kFwtCreatureLimitBreakCosts`` (45 rows) so every step
charges 1,000,000 gold and 100 materials, and it must also win over any discount
profile that ran first.  The checks below pin the table bytes, the profile hash
used by the client ``limitbreakcost.unity3d`` patch and the refusal behaviour on
an unknown layout.
"""

import hashlib
import struct

import pytest

from core.apk_tooling import LIMIT_BREAK_CLIENT_PROFILE_SHA256
from core.core_patches import (
    LIMIT_BREAK_COST_FIXED_SHA256,
    LIMIT_BREAK_COST_TENTH_SHA256,
    LIMIT_BREAK_FIXED_GOLD,
    LIMIT_BREAK_FIXED_MATERIAL,
    LIMIT_BREAK_GOLD_ROW_SIZE,
    LIMIT_BREAK_GOLD_ROWS,
    LIMIT_BREAK_GOLD_TABLE,
    LIMIT_BREAK_ITEM_CATEGORY,
    apply_limit_break_cost_fixed,
    apply_limit_break_cost_tenth,
)

ROW = LIMIT_BREAK_GOLD_ROW_SIZE


def _rows(buf: bytes | bytearray) -> list[tuple[int, int, int, int, int, int]]:
    return [
        struct.unpack_from("<6i", buf, LIMIT_BREAK_GOLD_TABLE + index * ROW)
        for index in range(LIMIT_BREAK_GOLD_ROWS)
    ]


def _table_digest(buf: bytes | bytearray) -> str:
    size = ROW * LIMIT_BREAK_GOLD_ROWS
    return hashlib.sha256(bytes(buf[LIMIT_BREAK_GOLD_TABLE:LIMIT_BREAK_GOLD_TABLE + size])).hexdigest()


def test_fixed_price_replaces_every_row_and_is_idempotent(reference_buffers):
    original, _ = reference_buffers
    stock = _rows(original)
    buf = bytearray(original)
    assert apply_limit_break_cost_fixed(buf) == LIMIT_BREAK_GOLD_ROWS
    assert _table_digest(buf) == LIMIT_BREAK_COST_FIXED_SHA256
    for index, row in enumerate(_rows(buf)):
        level, next_level, category, item_code, material, gold = row
        assert category == LIMIT_BREAK_ITEM_CATEGORY
        # the level ladder, the material item and its category stay stock
        assert (level, next_level, item_code) == (
            stock[index][0],
            stock[index][1],
            stock[index][3],
        )
        assert material == LIMIT_BREAK_FIXED_MATERIAL
        assert gold == LIMIT_BREAK_FIXED_GOLD
    assert apply_limit_break_cost_fixed(buf) == 0
    assert _table_digest(buf) == LIMIT_BREAK_COST_FIXED_SHA256


def test_fixed_price_supersedes_the_ninety_percent_profile(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    assert apply_limit_break_cost_tenth(buf) == LIMIT_BREAK_GOLD_ROWS
    assert _table_digest(buf) == LIMIT_BREAK_COST_TENTH_SHA256
    assert apply_limit_break_cost_fixed(buf) == LIMIT_BREAK_GOLD_ROWS
    assert _table_digest(buf) == LIMIT_BREAK_COST_FIXED_SHA256
    # A discount applied after the flat price is a no-op: the flat price wins.
    assert apply_limit_break_cost_tenth(buf) == 0
    assert _table_digest(buf) == LIMIT_BREAK_COST_FIXED_SHA256


def test_fixed_price_refuses_an_unknown_table(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    buf[LIMIT_BREAK_GOLD_TABLE + 8] ^= 1  # material category no longer 17
    before = bytes(buf)
    with pytest.raises(ValueError, match="Unexpected limit break cost table"):
        apply_limit_break_cost_fixed(buf)
    assert bytes(buf) == before


def test_client_profile_hash_matches_the_flat_price():
    pairs = [(LIMIT_BREAK_FIXED_GOLD, LIMIT_BREAK_FIXED_MATERIAL)] * LIMIT_BREAK_GOLD_ROWS
    digest = hashlib.sha256(repr(pairs).encode("ascii")).hexdigest()
    assert LIMIT_BREAK_CLIENT_PROFILE_SHA256[digest] == "limit_break_cost_fixed"


def test_flat_price_and_ninety_percent_profile_cannot_be_combined():
    from core.core_patches import PatchOptions, validate_patch_options

    with pytest.raises(ValueError, match="mutually exclusive"):
        validate_patch_options(
            PatchOptions(limit_break_cost_tenth=True, limit_break_cost_fixed=True)
        )
    validate_patch_options(PatchOptions(limit_break_cost_fixed=True))
    validate_patch_options(PatchOptions(limit_break_cost_tenth=True))
