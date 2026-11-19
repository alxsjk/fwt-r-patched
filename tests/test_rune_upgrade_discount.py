"""Tests for the +12..+15 rune upgrade discount (04.05)."""

import hashlib
import struct

import pytest

from core.apk_tooling import _patch_rune_upgrade_rows, _rune_upgrade_profile_from_rows
from core.core_patches import (
    RUNE_DECIDED_COST_PATCHED,
    RUNE_DECIDED_COST_SITE,
    RUNE_UPGRADE_CAVE_BYTES,
    RUNE_UPGRADE_CAVE_VADDR,
    RUNE_UPGRADE_CLIENT_REPLACEMENT,
    RUNE_UPGRADE_INSTALL_ORIGINAL,
    RUNE_UPGRADE_INSTALL_SITE,
    RUNE_UPGRADE_ROW_COUNT,
    RUNE_UPGRADE_ROW_SIZE,
    RUNE_UPGRADE_TABLE_PATCHED_SHA256,
    RUNE_UPGRADE_TABLE_VADDR,
    apply_rune_upgrade_discount,
    encode_arm64_branch,
    seg_offset,
)


def test_cave_ends_with_the_client_word_pair():
    code, data = RUNE_UPGRADE_CAVE_BYTES[:0x44], RUNE_UPGRADE_CAVE_BYTES[0x44:]
    assert len(code) == 0x44
    assert data[:4] == bytes.fromhex("890c8052")  # mov w9, #0x64
    assert data[4:] == RUNE_UPGRADE_CLIENT_REPLACEMENT  # mov w9, #0x0a


def test_cave_replays_the_install_site_instruction_and_returns(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    assert apply_rune_upgrade_discount(buf) == 4
    install = seg_offset(RUNE_UPGRADE_INSTALL_SITE)
    assert bytes(buf[install:install + 4]) == encode_arm64_branch(
        RUNE_UPGRADE_INSTALL_SITE, RUNE_UPGRADE_CAVE_VADDR
    )
    cave = seg_offset(RUNE_UPGRADE_CAVE_VADDR)
    assert bytes(buf[cave:cave + len(RUNE_UPGRADE_CAVE_BYTES)]) == RUNE_UPGRADE_CAVE_BYTES
    # The displaced instruction is executed before the branch back.
    assert code_tail_chain(RUNE_UPGRADE_CAVE_BYTES) is True


def code_tail_chain(blob: bytes) -> bool:
    """Checks the cave tail: ldp x26, x25, [sp, #0x20] then a branch."""
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    instructions = list(md.disasm(blob[:0x44], RUNE_UPGRADE_CAVE_VADDR))
    tail = instructions[-2:]
    replayed = tail[0].mnemonic == "ldp" and tail[0].op_str == "x26, x25, [sp, #0x20]"
    return bool(replayed and tail[1].mnemonic == "b")


def test_apply_patches_server_table_and_client_hook(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    assert apply_rune_upgrade_discount(buf) == 4
    table = seg_offset(RUNE_UPGRADE_TABLE_VADDR)
    size = RUNE_UPGRADE_ROW_SIZE * RUNE_UPGRADE_ROW_COUNT
    assert hashlib.sha256(bytes(buf[table:table + size])).hexdigest() == (
        RUNE_UPGRADE_TABLE_PATCHED_SHA256
    )
    decided = seg_offset(RUNE_DECIDED_COST_SITE)
    assert bytes(buf[decided:decided + 8]) == RUNE_DECIDED_COST_PATCHED
    # Every level keeps its identity fields and the first twelve rows stay stock.
    for level in range(12):
        row = table + level * RUNE_UPGRADE_ROW_SIZE
        assert bytes(buf[row:row + RUNE_UPGRADE_ROW_SIZE]) == original[row:row + RUNE_UPGRADE_ROW_SIZE]
    for level in range(12, RUNE_UPGRADE_ROW_COUNT):
        row = table + level * RUNE_UPGRADE_ROW_SIZE
        before = struct.unpack_from("<19i", original, row)
        after = struct.unpack_from("<19i", buf, row)
        assert after[7:13] == (0,) * 6
        assert after[13:19] == tuple(value // 10 for value in before[13:19])


def test_apply_is_idempotent(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    assert apply_rune_upgrade_discount(buf) == 4
    assert apply_rune_upgrade_discount(buf) == 0


def test_apply_rejects_a_foreign_cave_without_writing(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    cave = seg_offset(RUNE_UPGRADE_CAVE_VADDR)
    buf[cave] ^= 0xFF
    before = bytes(buf)
    with pytest.raises(ValueError, match="Unexpected rune upgrade cave"):
        apply_rune_upgrade_discount(buf)
    assert bytes(buf) == before


def test_install_site_must_be_the_expected_instruction(reference_buffers):
    original, _ = reference_buffers
    buf = bytearray(original)
    install = seg_offset(RUNE_UPGRADE_INSTALL_SITE)
    assert bytes(buf[install:install + 4]) == RUNE_UPGRADE_INSTALL_ORIGINAL
    buf[install:install + 4] = b"\x00\x00\x00\x00"
    with pytest.raises(ValueError, match="Unexpected rune upgrade install site"):
        apply_rune_upgrade_discount(buf)


def _client_rows() -> list[dict[str, object]]:
    stock = {
        12: ((5188, 5707, 6278, 9414, 10986, 12555),
             (8500, 17000, 34000, 59500, 74800, 136000)),
        13: ((5707, 6278, 6906, 10355, 12085, 13811),
             (9200, 18400, 36800, 64400, 80960, 147200)),
        14: ((6278, 6906, 7597, 11391, 13294, 15192),
             (9950, 19900, 39800, 69650, 87560, 159200)),
    }
    rows: list[dict[str, object]] = []
    for level, (failures, costs) in stock.items():
        row: dict[str, object] = {"_baseRuneEnchant": level}
        for grade in range(1, 7):
            row[f"_successProb{grade}"] = 30000
            row[f"_failProb{grade}"] = failures[grade - 1]
            row["_goldCost" if grade == 1 else f"_goldCost{grade}"] = costs[grade - 1]
        rows.append(row)
    return rows


def test_client_rows_lose_the_failure_weight_and_a_tenth_of_the_gold():
    rows = _client_rows()
    assert _rune_upgrade_profile_from_rows(rows)[0] == "stock"
    assert _patch_rune_upgrade_rows(rows) == 3
    assert _rune_upgrade_profile_from_rows(rows)[0] == "patched"
    expected_costs = {12: (850, 13600), 13: (920, 14720), 14: (995, 15920)}
    for row in rows:
        for grade in range(1, 7):
            assert row[f"_failProb{grade}"] == 0
        level = int(str(row["_baseRuneEnchant"]))
        first, sixth = expected_costs[level]
        assert row["_goldCost"] == first
        assert row["_goldCost6"] == sixth
    assert _patch_rune_upgrade_rows(rows) == 0


def test_client_rows_with_an_unexpected_success_weight_are_rejected():
    rows = _client_rows()
    rows[0]["_successProb3"] = 12345
    with pytest.raises(ValueError, match="unexpected rune upgrade success weights"):
        _patch_rune_upgrade_rows(rows)
