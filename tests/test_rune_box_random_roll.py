"""Tests for the rune-box slot/type RNG restore.

The Korean dev's ``stable_reward_roll_text`` hashes fixed strings, so a shop rune
box used to grant the same rune every time (nine purchases, nine identical codes).
Measured on device afterwards: rerouting the ``-slot`` roll is what makes the slot
vary, and the type-table loop does not read any of the rolls -- it uses whatever
``x0`` already holds -- so the type is seeded right at the loop entry.
"""

from __future__ import annotations

import hashlib

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from core.core_patches import (
    RUNE_ROLL_CAVE_LEN,
    RUNE_ROLL_CAVE_SHA256,
    RUNE_ROLL_CAVE_VA,
    RUNE_ROLL_COUNTER_OFFSET,
    RUNE_ROLL_DETERMINISTIC_SITES,
    RUNE_ROLL_SITES,
    RUNE_ROLL_TEXT_VA,
    RUNE_TYPE_CAVE_OFFSET,
    RUNE_TYPE_LOOP_BODY,
    RUNE_TYPE_LOOP_ENTER,
    RUNE_TYPE_SEED_OFFSET,
    apply_rune_box_random_roll,
    encode_arm64_branch,
    encode_ldp_post_index,
    encode_stp_pre_index,
    rune_roll_cave_blob,
    rune_type_seed_cave_blob,
    seg_offset,
)

# The bytes the reference library holds where the cave goes.
CAVE_REFERENCE = bytes.fromhex(
    "3f2303d5fd7bbea9f44f01a9fd03009128a440a9f30301aaf40300aa0a0500915f0109eb8901005408850f9129f97fd33f0108eb600240f92181889a610a00f9053a0094"
)


def _buffer() -> bytearray:
    """A sparse stand-in for the 13 MB library holding only what the patch reads."""
    size = seg_offset(RUNE_ROLL_CAVE_VA) + 0x1000
    buf = bytearray(size)
    cave_off = seg_offset(RUNE_ROLL_CAVE_VA)
    buf[cave_off:cave_off + len(CAVE_REFERENCE)] = CAVE_REFERENCE
    for site in RUNE_ROLL_SITES + RUNE_ROLL_DETERMINISTIC_SITES:
        off = seg_offset(site)
        buf[off:off + 4] = encode_arm64_branch(site, RUNE_ROLL_TEXT_VA, link=True)
    loop_off = seg_offset(RUNE_TYPE_LOOP_ENTER)
    buf[loop_off:loop_off + 4] = encode_arm64_branch(RUNE_TYPE_LOOP_ENTER, RUNE_TYPE_LOOP_BODY)
    return buf


def test_cave_is_the_documented_size() -> None:
    assert len(rune_roll_cave_blob()) == RUNE_ROLL_CAVE_LEN == 68
    assert len(rune_type_seed_cave_blob()) == 32


def test_roll_mixer_disassembles_into_the_intended_program() -> None:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cave = rune_roll_cave_blob()[:RUNE_TYPE_CAVE_OFFSET]
    seen = [(ins.mnemonic, ins.op_str) for ins in md.disasm(cave, RUNE_ROLL_CAVE_VA)]
    assert [m for m, _ in seen] == [
        "stp",
        "bl",
        "adrp",
        "ldr",
        "add",
        "str",
        "eor",
        "ldp",
        "ret",
    ]
    assert seen[0][1].endswith("!")
    assert "0x987454" in seen[1][1], "the cave must still call the original roll"
    assert seen[6] == ("eor", "x0, x0, x10")


def test_type_seed_disassembles_into_the_intended_program() -> None:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    seed_va = RUNE_ROLL_CAVE_VA + RUNE_TYPE_CAVE_OFFSET
    seen = [(ins.mnemonic, ins.op_str) for ins in md.disasm(rune_type_seed_cave_blob(), seed_va)]
    assert [m for m, _ in seen] == ["adrp", "ldr", "add", "eor", "eor", "eor", "str", "b"]
    assert seen[0][1].startswith("x6"), "x6 is the scratch register"
    assert seen[1][1].startswith("w0"), "the loop reads the seeded value from w0"
    assert seen[3][1] == "w0, w0, w0, lsl #13", "xorshift32 must be a real mix"
    assert seen[5][1] == "w0, w0, w0, lsl #5"
    assert seen[7][1] == f"#0x{RUNE_TYPE_LOOP_BODY:x}"


def test_counters_sit_in_writable_padding() -> None:
    # .data ends at 0xbe2f68 and .bss starts at 0xbe2f70: the two 4-byte counters live
    # in that alignment gap, inside the RW segment and owned by no section.
    assert RUNE_ROLL_COUNTER_OFFSET == 0xF68
    assert RUNE_TYPE_SEED_OFFSET == 0xF6C
    assert hashlib.sha256(CAVE_REFERENCE).hexdigest() == RUNE_ROLL_CAVE_SHA256


def test_reroutes_only_the_slot_and_seeds_the_type_loop() -> None:
    buf = _buffer()
    changed = apply_rune_box_random_roll(buf)

    assert changed == 1 + len(RUNE_ROLL_SITES) + 1 == 3
    for site in RUNE_ROLL_SITES:
        off = seg_offset(site)
        assert bytes(buf[off:off + 4]) == encode_arm64_branch(
            site, RUNE_ROLL_CAVE_VA, link=True
        )
    for site in RUNE_ROLL_DETERMINISTIC_SITES:
        off = seg_offset(site)
        assert bytes(buf[off:off + 4]) == encode_arm64_branch(
            site, RUNE_ROLL_TEXT_VA, link=True
        ), "grade/quality must keep the dev's deterministic roll"
    loop_off = seg_offset(RUNE_TYPE_LOOP_ENTER)
    assert bytes(buf[loop_off:loop_off + 4]) == encode_arm64_branch(
        RUNE_TYPE_LOOP_ENTER, RUNE_ROLL_CAVE_VA + RUNE_TYPE_CAVE_OFFSET
    )


def test_is_idempotent() -> None:
    buf = _buffer()
    assert apply_rune_box_random_roll(buf) == 3
    cave_off = seg_offset(RUNE_ROLL_CAVE_VA)
    snapshot = bytes(buf[cave_off:cave_off + 64])
    assert apply_rune_box_random_roll(buf) == 0
    assert bytes(buf[cave_off:cave_off + 64]) == snapshot


def test_refuses_a_buffer_it_does_not_recognise() -> None:
    buf = _buffer()
    off = seg_offset(RUNE_ROLL_CAVE_VA)
    buf[off:off + 4] = b"\x00\x00\x00\x00"
    with pytest.raises(ValueError, match="refusing|Unexpected|mismatch|cave"):
        apply_rune_box_random_roll(buf)


def test_stack_frame_encoders_round_trip() -> None:
    assert encode_stp_pre_index(29, 30, -16) == bytes.fromhex("fd7bbfa9")
    assert encode_ldp_post_index(29, 30, 16) == bytes.fromhex("fd7bc1a8")
