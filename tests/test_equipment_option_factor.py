"""Equipment option quality scaling and the rune-box type roll.

Both patches are pure data/code replacements on the reference library, so the
tests pin the two things that can silently go wrong: the site the patch claims to
own (validated against the reference bytes, so a re-encoded instruction is caught)
and the arithmetic that turns a factor into the constant the picker sees.
"""

from __future__ import annotations

import struct

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from core.core_patches import (
    EQUIPMENT_LOCK_FIX_NOP,
    EQUIPMENT_LOCK_FIX_ORIGINAL,
    EQUIPMENT_LOCK_FIX_SITE,
    EQUIPMENT_OPTION_BONUS_BASE,
    EQUIPMENT_OPTION_BONUS_CAP,
    EQUIPMENT_OPTION_BONUS_ORIGINALS,
    EQUIPMENT_OPTION_BONUS_REGISTERS,
    EQUIPMENT_OPTION_BONUS_SITES,
    RUNE_BOX_TYPE_GROUP,
    RUNE_BOX_TYPE_REWRITES,
    RUNE_QUALITY_BONUS_BASE,
    RUNE_QUALITY_BONUS_CAP,
    RUNE_QUALITY_BONUS_ORIGINAL,
    RUNE_QUALITY_BONUS_REGISTER,
    RUNE_QUALITY_BONUS_SITE,
    RUNE_REWARD_TYPE_STRIDE,
    RUNE_REWARD_TYPE_TABLE,
    apply_equipment_lock_fix,
    apply_equipment_option_factor,
    apply_rune_box_random_type,
    apply_rune_quality_factor,
    equipment_option_bonus,
    rune_quality_bonus,
    seg_offset,
)


def test_bonus_scales_linearly_from_the_maximum_mastery():
    assert equipment_option_bonus(0) == 0
    assert equipment_option_bonus(1) == EQUIPMENT_OPTION_BONUS_BASE
    assert equipment_option_bonus(10) == 10 * EQUIPMENT_OPTION_BONUS_BASE


def test_bonus_saturates_at_the_games_own_ceiling():
    # The picker clamps the resulting probability at 10000, so a factor past the
    # ceiling must not produce a bigger immediate than the picker can represent.
    assert equipment_option_bonus(1000) == EQUIPMENT_OPTION_BONUS_CAP
    with pytest.raises(ValueError, match="must be >= 0"):
        equipment_option_bonus(-1)


def test_factor_zero_reports_no_changes():
    assert apply_equipment_option_factor(bytearray(64), 0) == 0


def _movz_target(word: bytes) -> int:
    """Decodes ``movz w<d>, #imm`` to its immediate (capstone aliases it as mov)."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    (ins,) = md.disasm(word, 0)
    assert ins.mnemonic in ("movz", "mov"), ins.mnemonic
    return int(ins.op_str.split("#")[-1], 0)


def test_every_bonus_site_is_rewritten_with_the_scaled_constant(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    changed = apply_equipment_option_factor(buf, 10)
    assert changed == len(EQUIPMENT_OPTION_BONUS_SITES)
    for site, original, _register in zip(
        EQUIPMENT_OPTION_BONUS_SITES,
        EQUIPMENT_OPTION_BONUS_ORIGINALS,
        EQUIPMENT_OPTION_BONUS_REGISTERS,
        strict=True,
    ):
        offset = seg_offset(site)
        assert so_bytes[offset : offset + 4] == original
        # The picker now reads the argument the caller hands over, so the boost has to
        # live in the caller's gate instead of inside this function.
        word = bytes(buf[offset : offset + 4])
        assert word != original
        assert _movz_target(word) == 10 * EQUIPMENT_OPTION_BONUS_BASE
        (ins,) = Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(word, site)
        assert ins.op_str.startswith(f"w{_register},")


def test_option_factor_is_idempotent(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_equipment_option_factor(buf, 10)
    once = bytes(buf)
    assert apply_equipment_option_factor(buf, 10) == 0
    assert bytes(buf) == once
    # Everything that differs must fall inside the four hooked instructions or the two
    # lock-gate caves -- nothing else in the library may move.
    allowed: set[int] = set()
    for site in EQUIPMENT_OPTION_BONUS_SITES:
        allowed.update(range(seg_offset(site), seg_offset(site) + 4))
    differing = {i for i, (a, b) in enumerate(zip(so_bytes, once, strict=True)) if a != b}
    assert differing <= allowed, f"bytes changed outside the patch: {sorted(differing - allowed)}"
    assert len(differing) == 4 * len(EQUIPMENT_OPTION_BONUS_SITES)


def test_rune_box_rows_become_a_three_type_group(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_rune_box_random_type(buf) == len(RUNE_BOX_TYPE_REWRITES)
    types, weights = [], []
    for row, _expected, _replacement in RUNE_BOX_TYPE_REWRITES:
        site = RUNE_REWARD_TYPE_TABLE + row * RUNE_REWARD_TYPE_STRIDE
        offset = seg_offset(site)
        group, weight, rune_type, slot_only = struct.unpack_from("<4i", buf, offset)
        assert group == RUNE_BOX_TYPE_GROUP
        assert slot_only == 0
        types.append(rune_type)
        weights.append(weight)
        # The stock bytes must be what the reference actually holds.
        assert struct.unpack_from("<4i", so_bytes, offset) == _expected
    # A fair roll among the three basic types, which is exactly group 0's shape.
    assert types == [0, 1, 2]
    assert len(set(weights)) == 1


def test_rune_box_patch_is_idempotent(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_rune_box_random_type(buf)
    assert apply_rune_box_random_type(buf) == 0


def test_rune_quality_factor_scales_the_same_bonus(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_rune_quality_factor(buf, 10) == 1
    offset = seg_offset(RUNE_QUALITY_BONUS_SITE)
    assert so_bytes[offset : offset + 4] == RUNE_QUALITY_BONUS_ORIGINAL
    word = bytes(buf[offset : offset + 4])
    (ins,) = Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(word, RUNE_QUALITY_BONUS_SITE)
    assert ins.mnemonic in ("movz", "mov"), ins.mnemonic
    assert ins.op_str.startswith(f"x{RUNE_QUALITY_BONUS_REGISTER},")
    assert int(ins.op_str.split("#")[-1], 0) == 10 * RUNE_QUALITY_BONUS_BASE


def test_rune_quality_bonus_ceiling_matches_the_equipment_one():
    assert rune_quality_bonus(0) == 0
    assert rune_quality_bonus(1) == RUNE_QUALITY_BONUS_BASE
    assert rune_quality_bonus(1000) == RUNE_QUALITY_BONUS_CAP
    with pytest.raises(ValueError, match="must be >= 0"):
        rune_quality_bonus(-1)


def test_rune_quality_factor_is_idempotent(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_rune_quality_factor(buf, 10)
    assert apply_rune_quality_factor(buf, 10) == 0


def test_rune_box_patch_refuses_foreign_bytes(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    row = RUNE_BOX_TYPE_REWRITES[0][0]
    offset = seg_offset(RUNE_REWARD_TYPE_TABLE + row * RUNE_REWARD_TYPE_STRIDE)
    buf[offset : offset + 4] = b"\xde\xad\xbe\xef"
    with pytest.raises(ValueError, match="Unexpected rune reward type row"):
        apply_rune_box_random_type(buf)


def test_lock_fix_skips_the_pre_lock_reroll(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_equipment_lock_fix(buf) == 1
    offset = seg_offset(EQUIPMENT_LOCK_FIX_SITE)
    assert so_bytes[offset : offset + 4] == EQUIPMENT_LOCK_FIX_ORIGINAL
    assert bytes(buf[offset : offset + 4]) == EQUIPMENT_LOCK_FIX_NOP == bytes.fromhex("1f2003d5")
    (ins,) = Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(
        bytes(buf[offset : offset + 4]), EQUIPMENT_LOCK_FIX_SITE
    )
    assert ins.mnemonic == "nop"


def test_lock_fix_is_idempotent(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_equipment_lock_fix(buf)
    once = bytes(buf)
    assert apply_equipment_lock_fix(buf) == 0
    assert bytes(buf) == once
