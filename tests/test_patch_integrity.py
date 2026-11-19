from __future__ import annotations

import hashlib

import pytest

from core.core_patches import (
    CAMPAIGN_CAVE_BASE,
    CAMPAIGN_XP_FLAG,
    DELTA_TEXT,
    DIMENSION_CAVE_VADDR,
    DIMENSION_GENE_CAVE_VADDR,
    EVENT_COIN_CAVE_VADDR,
    EVENT_DISCOUNT_FLAG,
    EXPECTED_PATCH_COUNTS,
    EXPEDITION_CAVE_VADDR,
    EXPEDITION_LEGACY_RESTORATIONS,
    IDEMPOTENT_PATCHES,
    PATCH_FLAG_SIZE,
    PATCH_FLAG_VADDR,
    WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
    PatchOptions,
    _has_flag,
    _write_bytes,
    _write_checked_cave,
    apply_all_patches,
    apply_campaign_gold_and_drops,
    apply_campaign_xp,
    apply_event_coin_x10,
    apply_event_discount,
    apply_expeditions,
    apply_gene_priority,
    apply_mode_drops_x10,
    seg_offset,
    validate_cave_layout,
)


def test_write_bytes_refuses_to_resize_the_library():
    buf = bytearray(16)
    with pytest.raises(ValueError, match="outside the library"):
        _write_bytes(buf, 12, b"12345678", "test")
    assert len(buf) == 16


def test_patch_flag_gap_is_registered():
    validate_cave_layout()
    assert PATCH_FLAG_SIZE == 16


def test_idempotent_set_covers_the_second_pass_patches():
    expected = {
        "expedition_bonus",
        "gene_priority",
        "campaign_xp",
        "campaign_gold",
        "event_discount",
        "campaign_shop_discount",
        "mode_drops_x10",
        "gold_cylinder_x10",
        "mana_cylinder_x10",
        "no_win_box",
        "hero_exp_cap",
        "gem_mining_x10",
        "gem_mining_types",
        "gem_level6",
        "recycle_six_star",
        "guild_raid_reward_x10",
    }
    assert expected <= IDEMPOTENT_PATCHES
    assert EXPECTED_PATCH_COUNTS["gold_cylinder_x10"] == 2
    assert EXPECTED_PATCH_COUNTS["mana_cylinder_x10"] == 2


def test_write_checked_cave_is_idempotent_and_rejects_mismatch():
    cave_addr = 0xB33314
    off = seg_offset(cave_addr)
    orig = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    orig_sha = hashlib.sha256(orig).hexdigest()
    blob = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"

    buf = bytearray(off + 16)
    buf[off : off + len(orig)] = orig
    assert _write_checked_cave(buf, cave_addr, blob, orig_sha, label="test cave") == 1
    assert bytes(buf[off : off + len(blob)]) == blob
    assert _write_checked_cave(buf, cave_addr, blob, orig_sha, label="test cave") == 0

    broken = bytearray(off + 16)
    broken[off : off + len(orig)] = b"\x99" * len(orig)
    with pytest.raises(ValueError, match="Unexpected test cave contents"):
        _write_checked_cave(broken, cave_addr, blob, orig_sha, label="test cave")


def test_result_hashes_are_computed_from_the_output(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes, dex_bytes, PatchOptions(campaign_xp=True)
    )
    assert result.input_so_sha256 == hashlib.sha256(so_bytes).hexdigest()
    assert result.input_dex_sha256 == hashlib.sha256(dex_bytes).hexdigest()
    assert result.so_sha256 == hashlib.sha256(result.so_bytes).hexdigest()
    assert result.dex_sha256 == hashlib.sha256(result.dex_bytes).hexdigest()
    assert result.so_sha256 != result.input_so_sha256


def test_expeditions_second_pass_is_a_noop(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_expeditions(buf) > 0
    snapshot = bytes(buf)
    assert apply_expeditions(buf) == 0
    assert bytes(buf) == snapshot


def test_campaign_gold_second_pass_is_a_noop(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_campaign_gold_and_drops(buf) > 0
    snapshot = bytes(buf)
    assert apply_campaign_gold_and_drops(buf) == 0
    assert bytes(buf) == snapshot


def test_campaign_xp_flag_makes_the_second_pass_a_noop(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_campaign_xp(buf) > 0
    assert _has_flag(buf, CAMPAIGN_XP_FLAG)
    snapshot = bytes(buf)
    assert apply_campaign_xp(buf) == 0
    assert bytes(buf) == snapshot


def test_event_discount_patches_a_full_size_buffer_even_without_a_space_marker():
    # A full library-sized buffer gets the explicit flag; whitespace in the
    # source JSON must not be mistaken for "already discounted".
    buf = bytearray(PATCH_FLAG_VADDR - DELTA_TEXT + PATCH_FLAG_SIZE)
    payload = b'{"idx":1,"shop_content":2,"price_count": 1000}'
    buf[: len(payload)] = payload
    assert apply_event_discount(buf) == 1
    assert b'"price_count":  100' in buf
    assert _has_flag(buf, EVENT_DISCOUNT_FLAG)
    assert apply_event_discount(buf) == 0


def test_gene_priority_second_pass_is_a_noop(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_gene_priority(buf) == EXPECTED_PATCH_COUNTS["gene_priority"]
    snapshot = bytes(buf)
    assert apply_gene_priority(buf) == 0
    assert bytes(buf) == snapshot

    first = apply_all_patches(so_bytes, dex_bytes, PatchOptions(gene_priority=True))
    second = apply_all_patches(
        first.so_bytes,
        first.dex_bytes,
        PatchOptions(gene_priority=True, allow_unknown=True),
    )
    assert second.counts["gene_priority"] == 0
    assert second.so_bytes == first.so_bytes


def test_cave_slots_reject_unknown_original_bytes(reference_buffers):
    so_bytes, _dex = reference_buffers
    cases = [
        (EXPEDITION_CAVE_VADDR, apply_expeditions, "expedition cave"),
        (CAMPAIGN_CAVE_BASE, apply_campaign_gold_and_drops, "campaign cave"),
        (DIMENSION_CAVE_VADDR, apply_mode_drops_x10, "dimension cave"),
        (
            WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
            apply_mode_drops_x10,
            "world boss daily kraken cave",
        ),
        (DIMENSION_GENE_CAVE_VADDR, apply_mode_drops_x10, "dimension gene cave"),
        (EVENT_COIN_CAVE_VADDR, apply_event_coin_x10, "event coin cave"),
    ]
    for cave_va, fn, match in cases:
        buf = bytearray(so_bytes)
        off = seg_offset(cave_va)
        buf[off : off + 4] = b"\xde\xad\xbe\xef"
        with pytest.raises(ValueError, match=match):
            fn(buf)


def test_legacy_restorations_do_not_inflate_forward_counts(reference_buffers):
    so_bytes, _dex = reference_buffers

    exp_buf = bytearray(so_bytes)
    for addr, (legacy_word, _orig_word) in EXPEDITION_LEGACY_RESTORATIONS.items():
        off = seg_offset(addr)
        exp_buf[off : off + 4] = legacy_word
    assert apply_expeditions(exp_buf) == EXPECTED_PATCH_COUNTS["expedition_bonus"]
    for addr, (_legacy_word, orig_word) in EXPEDITION_LEGACY_RESTORATIONS.items():
        off = seg_offset(addr)
        assert bytes(exp_buf[off : off + 4]) == orig_word
