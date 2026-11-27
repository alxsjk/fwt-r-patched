from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
from collections import defaultdict
from pathlib import Path

import pytest

from core.core_patches import (
    ARENA_DEFENCE_COUNT_REPLACEMENT,
    ARENA_DEFENCE_COUNT_SITE,
    ARENA_DEFENCE_SIZE_REPLACEMENT,
    ARENA_DEFENCE_SIZE_SITE,
    ARENA_EMPTY_SLOT_REPLACEMENT,
    ARENA_EMPTY_SLOT_SITE,
    ARENA_SCHEMA_GATE_REPLACEMENT,
    ARENA_SCHEMA_GATE_SITE,
    ARENA_WEEK_STATE_SITES,
    BATTLE_ARENA_SAVE_CAVE_BYTES,
    BATTLE_ARENA_SAVE_CAVE_VADDR,
    BATTLE_ARENA_SAVE_LATE_SITE,
    CAMPAIGN_CAVE_BASE,
    CAMPAIGN_CAVE_LAYOUT,
    CAMPAIGN_HOOKS,
    COOCOO_EXP_X2_REPLACEMENT,
    COOCOO_EXP_X2_SITE,
    COOCOO_STAGE_LEVEL_OFFSET,
    COOCOO_STAGE_LEVELS,
    COOCOO_STAGE_ROW_SIZE,
    COOCOO_STAGE_TABLE_OFFSET,
    CRYSTAL_SKILL_COST_REPLACEMENT,
    CRYSTAL_SKILL_COST_SITE,
    DEVIL_BOOST_MULTIPLIER_PATCHED,
    DEVIL_BOOST_MULTIPLIER_SITE,
    DIMENSION_CAVE_VADDR,
    DIMENSION_DROP_SITE,
    DIMENSION_GENE_CAVE_VADDR,
    DIMENSION_GENE_COUNT_SITE,
    DIMENSION_GENE_GUARANTEE_REPLACEMENT,
    DIMENSION_GENE_GUARANTEE_SITE,
    ENERGY_FLASK_STAMINA_ORIGINAL,
    ENERGY_FLASK_STAMINA_REPLACEMENT,
    ENERGY_FLASK_STAMINA_SITE,
    EQUIPMENT_UPGRADE_10_FAIL_ORIGINAL,
    EQUIPMENT_UPGRADE_10_FAIL_REPLACEMENT,
    EQUIPMENT_UPGRADE_10_FAIL_SITE,
    EVENT_COIN_CAVE_SIZE,
    EVENT_COIN_CAVE_VADDR,
    EVENT_GENE_ITEM_CATEGORY,
    EVENT_LIMIT_TYPE_PATTERN,
    EVENT_SHOP_TYPE_4_PATTERN,
    EXPECTED_EVENT_GENE_ROWS,
    EXPECTED_EVENT_LIMIT_ROWS,
    GEM_LEVEL6_STRINGS,
    GEM_MINING_CAVE_BYTES,
    GEM_MINING_CAVE_VADDR,
    GEM_MINING_COUNT_SITE,
    GEM_MINING_TYPES_CAVE_BYTES,
    GEM_MINING_TYPES_CAVE_VADDR,
    GEM_MINING_TYPES_HOOK,
    GEM_UPGRADE_GOLD_ORIGINAL,
    GEM_UPGRADE_GOLD_REPLACEMENT,
    GEM_UPGRADE_GOLD_SITE,
    GOLD_CYLINDER_X10_CAVE_VADDR,
    GOLD_CYLINDER_X10_SITE,
    GUILD_RAID_CLIENT_CAVE,
    GUILD_RAID_CLIENT_CAVE_BYTES,
    GUILD_RAID_DAILY_REWARD_TABLE,
    GUILD_RAID_DAILY_REWARDS,
    GUILD_RAID_INSTALL_SITE,
    GUILD_RAID_MERCENARY_CAVE_BYTES,
    GUILD_RAID_MERCENARY_CAVE_VADDR,
    GUILD_RAID_MERCENARY_SITE,
    GUILD_RAID_SENTINEL_CAVE,
    GUILD_RAID_SENTINEL_CAVE_BYTES,
    GUILD_RAID_START_SITE,
    GUILD_RAID_WEEKLY_REWARD_TABLE,
    GUILD_RAID_WEEKLY_REWARDS,
    HONOR_COIN_COUNT_REPLACEMENT,
    HONOR_COIN_COUNT_SITE,
    HONOR_POINTS_CAVE_BYTES,
    HONOR_POINTS_CAVE_VADDR,
    HONOR_POINTS_DELTA_SITE,
    INFINITE_TRANSCEND_SUCCESS_TABLE,
    ITEM_CAVE_FIRST_SIZE,
    ITEM_CAVE_VADDR,
    LIMIT_BREAK_GOLD_ROWS,
    MANA_CYLINDER_X10_SITES,
    PVP_TEAM_COMPACT_ATTACK_CAVE_BYTES,
    PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR,
    PVP_TEAM_COMPACT_ATTACK_HOOK,
    PVP_TEAM_COMPACT_DEFENSE_CAVE_BYTES,
    PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR,
    PVP_TEAM_COMPACT_DEFENSE_HOOK,
    RANDOPTION_FALLBACK_REPLACEMENT,
    RANDOPTION_FALLBACK_SITE,
    RANDOPTION_SERVER_FLAT_GROUPS,
    RANDOPTION_SERVER_ROW_COUNT,
    RANDOPTION_SERVER_ROW_SIZE,
    RANDOPTION_SERVER_SITE,
    RANDOPTION_SERVER_WEIGHT_OFFSET,
    RECYCLE_COMPLETION_CAVE_BYTES,
    RECYCLE_COMPLETION_CAVE_TAIL_BYTES,
    RECYCLE_COMPLETION_CAVE_TAIL_VADDR,
    RECYCLE_COMPLETION_CAVE_VADDR,
    RECYCLE_COMPLETION_HOOK,
    RECYCLE_GRADE_CAVE_BYTES,
    RECYCLE_GRADE_CAVE_VADDR,
    RECYCLE_GRADE_HOOK,
    RECYCLE_PICK_CAVE_BYTES,
    RECYCLE_PICK_CAVE_VADDR,
    RECYCLE_PICK_HOOK,
    RECYCLE_REWARD_FLAG_CAVE_BYTES,
    RECYCLE_REWARD_FLAG_CAVE_VADDR,
    RECYCLE_REWARD_FLAG_HOOK,
    RECYCLE_SIX_STAR_ENTRY_SIZE,
    RECYCLE_SIX_STAR_EXPECTED_ROWS,
    RECYCLE_SIX_STAR_GROUP_SLOT,
    RECYCLE_SIX_STAR_GROUPS,
    RECYCLE_SIX_STAR_ROW_COUNT,
    RECYCLE_SIX_STAR_SLOT_SETS,
    RECYCLE_SIX_STAR_TABLE,
    REFERENCE_DEX_SHA256,
    REFERENCE_SO_SHA256,
    RIDDLE_TABLE_OFFSET,
    RUNE_BOX_TYPE_REWRITES,
    RUNE_ROLL_SITES,
    SELECT_ALL_CAVE_ORIGINAL_SHA256,
    SELECT_ALL_CAVE_RESERVED_SIZE,
    SELECT_ALL_CLIENT_CAVE,
    SELECT_ALL_STUB_VADDR,
    SHIP_PART_COST_FIELD_SIZE,
    SHIP_PART_COST_TABLES,
    SINGLE_BLACK_HAMMER_REPLACEMENT,
    SINGLE_BLACK_HAMMER_SITE,
    SINGLE_GEM_FANG_REPLACEMENT,
    SINGLE_GEM_FANG_SITE,
    SINGLE_MOD_STONE_CAVE_BYTES,
    SINGLE_MOD_STONE_CAVE_SIZE,
    SINGLE_MOD_STONE_CAVE_VADDR,
    SINGLE_MOD_STONE_CLIENT_REPLACEMENT,
    SINGLE_MOD_STONE_INSTALL_SITE,
    SINGLE_MOD_STONE_SERVER_REPLACEMENT,
    SINGLE_MOD_STONE_SERVER_SITE,
    STAGE_EQUIP_WEIGHT,
    STAGE_ROW_COUNT,
    STAGE_ROW_SIZE,
    STAGE_TABLE_OFFSET,
    STAMINA_HALF_REPLACEMENT,
    STAMINA_HALF_SITE,
    STAMINA_POTION_1000_REPLACEMENT,
    STAMINA_POTION_1000_SITE,
    SUMMON_POOLS,
    SUMMON_TARGETS_50_30_20,
    WORLDBOSS_CYCLE_REWARD_PATCHED_SHA256,
    WORLDBOSS_CYCLE_REWARD_TARGET_COUNT,
    WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES,
    WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
    WORLDBOSS_DAILY_KRAKEN_SITE,
    WORLDBOSS_EVENT_REWARD_ORIGINAL,
    WORLDBOSS_EVENT_REWARD_REPLACEMENT,
    WORLDBOSS_EVENT_REWARD_SITE,
    PatchOptions,
    apply_all_patches,
    apply_battle_arena_fix,
    apply_battle_arena_save_fix,
    apply_campaign_gold_and_drops,
    apply_campaign_shop_discount,
    apply_coocoo_level_x2,
    apply_crystal_skill_90_off,
    apply_devil_boost_x10,
    apply_energy_flask_x10,
    apply_english_localization_dex,
    apply_equipment_percent_options,
    apply_equipment_upgrade_10_guarantee,
    apply_event_coin_x10,
    apply_event_discount,
    apply_event_gene_unlimited,
    apply_event_limits_daily,
    apply_gem_level6,
    apply_gem_mining_types,
    apply_gem_mining_x10,
    apply_gem_upgrade_gold_half,
    apply_guild_raid_reward_x10,
    apply_guild_raid_score_fix,
    apply_guild_raid_self_mercenary,
    apply_high_upgrade_no_fail,
    apply_mode_drops_x10,
    apply_no_equip_drops,
    apply_recycle_six_star,
    apply_recycle_ticket_rewards,
    apply_select_all_4_5,
    apply_ship_parts_90_off,
    apply_ship_parts_half,
    apply_single_black_hammer,
    apply_single_gem_fang,
    apply_summon_rates,
    apply_worldboss_full_ship_repair,
    encode_arm64_branch,
    seg_offset,
    validate_cave_layout,
    worldboss_cycle_reward_rows,
)
from core.dex_smali import (
    REFERENCE_CRITICAL_FILE_HASHES,
    REFERENCE_RESOURCE_FILE_COUNT,
    REFERENCE_RESOURCE_SHA256,
    REFERENCE_RESOURCE_UNCOMPRESSED_BYTES,
    ResourceContract,
    _patch_resource_contract,
    _replace_smali_strings,
    find_apktool_jar,
    find_java_executable,
    read_dex_strings,
    verify_dex_string_order,
)
from core.patch_inspector import inspect_dex, inspect_native_so, verify_dex_checksums


def test_branch_encoding_and_alignment():
    encoded = encode_arm64_branch(0x1000, 0x1010)
    assert len(encoded) == 4
    assert encoded != b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="Unaligned"):
        encode_arm64_branch(0x1000, 0x1002)


def test_branch_out_of_range_is_rejected():
    with pytest.raises(ValueError, match="out of range"):
        encode_arm64_branch(0x1000, 0x10000000)


def test_cave_layout_is_disjoint_and_no_longer_uses_egl_function():
    validate_cave_layout()
    ranges = [(name, start, start + size) for name, start, size in CAMPAIGN_CAVE_LAYOUT]
    ranges.append(
        (
            "event_coin",
            EVENT_COIN_CAVE_VADDR,
            EVENT_COIN_CAVE_VADDR + EVENT_COIN_CAVE_SIZE,
        )
    )
    ranges.append(
        (
            "guild_raid_sentinel",
            GUILD_RAID_SENTINEL_CAVE,
            GUILD_RAID_SENTINEL_CAVE + len(GUILD_RAID_SENTINEL_CAVE_BYTES),
        )
    )
    ranges.append(
        (
            "guild_raid_client",
            GUILD_RAID_CLIENT_CAVE,
            GUILD_RAID_CLIENT_CAVE + len(GUILD_RAID_CLIENT_CAVE_BYTES),
        )
    )
    ranges.sort(key=lambda item: item[1])
    for previous, current in zip(ranges, ranges[1:], strict=False):
        assert previous[2] <= current[1], f"{previous} overlaps {current}"

    assert CAMPAIGN_CAVE_BASE == 0xB33314
    assert EVENT_COIN_CAVE_VADDR == CAMPAIGN_CAVE_BASE + 0xC8
    assert GUILD_RAID_CLIENT_CAVE == CAMPAIGN_CAVE_BASE + 0x110
    assert GUILD_RAID_SENTINEL_CAVE == CAMPAIGN_CAVE_BASE + 0x2B0
    assert not (0xAA6BFC <= CAMPAIGN_CAVE_BASE < 0xAA6D2C)
    # Every hook and cave address must be in the new safe region, not the EGL function.
    for address in CAMPAIGN_HOOKS:
        assert not (0xAA6BFC <= address < 0xAA6D2C) or address < 0xAA6BFC


def test_wrong_reference_is_rejected_before_writing():
    with pytest.raises(ValueError, match="not the supported reference"):
        apply_all_patches(
            bytes(0x1000),
            bytes(0x1000),
            PatchOptions(event_coin_x10=True),
        )


def test_reference_hashes_are_stable(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    import hashlib

    assert hashlib.sha256(so_bytes).hexdigest() == REFERENCE_SO_SHA256
    assert hashlib.sha256(dex_bytes).hexdigest() == REFERENCE_DEX_SHA256


def test_event_discount_synthetic_json():
    payload = (
        b'{"idx":1,"shop_code":"1","shop_content":2,"price_count":1000}\n'
        b'{"idx":2,"shop_code":"2","shop_content":2,"price_count":501}\n'
    )
    buf = bytearray(payload)
    assert apply_event_discount(buf) == 2
    # The patcher preserves the original string length with leading spaces.
    assert b'"price_count": 100' in buf
    assert b'"price_count": 51' in buf
    # Second pass must be idempotent and not discount prices again.
    assert apply_event_discount(buf) == 0
    assert b'"price_count": 100' in buf
    assert b'"price_count": 51' in buf


def test_event_discount_ignores_patched_campaign_rows():
    payload = (
        b'{"idx":1,"shop_code":"1","shop_content":1,"price_count": 10}\n'
        b'{"idx":2,"shop_code":"2","shop_content":2,"price_count":1000}\n'
    )
    buf = bytearray(payload)
    assert apply_event_discount(buf) == 1
    assert b'"price_count": 100' in buf
    assert b'"price_count": 10' in buf


def test_no_equip_drops_removes_and_redistributes(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    weight_fields = (4, 7, 10, 14, 22, 26, 31)
    before: dict[int, int] = {}
    for index in range(STAGE_ROW_COUNT):
        at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
        row = struct.unpack_from("<35i", buf, at)
        if row[STAGE_EQUIP_WEIGHT] > 0:
            before[index] = sum(row[field] for field in weight_fields if row[field] > 0)

    assert apply_no_equip_drops(buf) == 431
    for index in range(STAGE_ROW_COUNT):
        at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
        row = struct.unpack_from("<35i", buf, at)
        assert row[STAGE_EQUIP_WEIGHT] <= 0
        if index in before:
            assert sum(row[field] for field in weight_fields if row[field] > 0) == before[index]
    assert apply_no_equip_drops(buf) == 0


def test_recycle_ticket_rewards(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_recycle_ticket_rewards(buf) == 9

    for site, cave, link in (
        (RECYCLE_COMPLETION_HOOK, RECYCLE_COMPLETION_CAVE_VADDR, True),
        (RECYCLE_REWARD_FLAG_HOOK, RECYCLE_REWARD_FLAG_CAVE_VADDR, True),
        (RECYCLE_GRADE_HOOK, RECYCLE_GRADE_CAVE_VADDR, False),
        (RECYCLE_PICK_HOOK, RECYCLE_PICK_CAVE_VADDR, False),
    ):
        offset = site - 0x4000
        assert bytes(buf[offset:offset + 4]) == encode_arm64_branch(
            site, cave, link=link
        )

    for cave, blob in (
        (RECYCLE_COMPLETION_CAVE_VADDR, RECYCLE_COMPLETION_CAVE_BYTES),
        (RECYCLE_COMPLETION_CAVE_TAIL_VADDR, RECYCLE_COMPLETION_CAVE_TAIL_BYTES),
        (RECYCLE_REWARD_FLAG_CAVE_VADDR, RECYCLE_REWARD_FLAG_CAVE_BYTES),
        (RECYCLE_GRADE_CAVE_VADDR, RECYCLE_GRADE_CAVE_BYTES),
        (RECYCLE_PICK_CAVE_VADDR, RECYCLE_PICK_CAVE_BYTES),
    ):
        offset = cave - 0x4000
        assert bytes(buf[offset:offset + len(blob)]) == blob

    assert apply_recycle_ticket_rewards(buf) == 0

    # A corrupted cave slot must fail instead of silently producing an APK that
    # grants nothing.
    broken = bytearray(so_bytes)
    completion_cave_off = RECYCLE_COMPLETION_CAVE_VADDR - 0x4000
    broken[completion_cave_off:completion_cave_off + 4] = b"\xff\xff\xff\xff"
    with pytest.raises(ValueError, match="recycle"):
        apply_recycle_ticket_rewards(broken)


def test_upgrade_no_fail_above_20(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_high_upgrade_no_fail(buf) == 5
    assert struct.unpack_from("<6i", buf, INFINITE_TRANSCEND_SUCCESS_TABLE) == (
        100,
        100,
        100,
        100,
        100,
        100,
    )
    assert apply_high_upgrade_no_fail(buf) == 0


def test_summon_patch_is_idempotent(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_summon_rates(buf) == 228
    assert apply_summon_rates(buf) == 0


def test_summon_rates_50_30_20_profile(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_summon_rates(buf, SUMMON_TARGETS_50_30_20) == 228
    assert apply_summon_rates(buf, SUMMON_TARGETS_50_30_20) == 0

    for _name, start, count, expected in SUMMON_POOLS:
        totals = dict.fromkeys(expected, 0)
        for index in range(count):
            weight, category, _rotation = struct.unpack_from("<iii", buf, start + index * 40)
            totals[category] += weight
        assert totals[3] == 500_000
        assert totals[4] == 300_000
        assert totals[5] == 200_000
        assert totals.get(1, 0) == 0
        assert totals.get(2, 0) == 0


def test_summon_profiles_are_mutually_exclusive(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    with pytest.raises(ValueError, match="mutually exclusive"):
        apply_all_patches(
            so_bytes,
            dex_bytes,
            PatchOptions(summon_rates=True, summon_rates_50_30_20=True),
        )


def test_lab_cylinder_x10(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(gold_cylinder_x10=True, mana_cylinder_x10=True),
    )
    assert result.counts == {
        "gold_cylinder_x10": 2,
        "mana_cylinder_x10": 2,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
    }
    hook_offset = GOLD_CYLINDER_X10_SITE - 0x4000
    assert result.so_bytes[hook_offset:hook_offset + 4] == encode_arm64_branch(
        GOLD_CYLINDER_X10_SITE, GOLD_CYLINDER_X10_CAVE_VADDR
    )
    cave_offset = GOLD_CYLINDER_X10_CAVE_VADDR - 0x4000
    assert result.so_bytes[cave_offset:cave_offset + 8] == bytes.fromhex(
        "08d490522800a072"
    )
    for address, _original, replacement in MANA_CYLINDER_X10_SITES:
        assert (
            struct.unpack_from("<I", result.so_bytes, address - 0x4000)[0]
            == replacement
        )


@pytest.mark.parametrize("daily_limits", [False, True])
def test_surprise_transcendence_package_isolates_the_offer(reference_buffers, daily_limits):
    from core.surprise_transcendence_package import apply_surprise_transcendence_package

    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    if daily_limits:
        apply_event_limits_daily(buf)
    baseline = bytes(buf)
    assert not inspect_native_so(buf)["surprise_transcendence_package"].active
    assert apply_surprise_transcendence_package(buf, seg_offset) == 6
    assert apply_surprise_transcendence_package(buf, seg_offset) == 0
    assert inspect_native_so(buf)["surprise_transcendence_package"].active

    def record(address: int, size: int) -> dict:
        start = seg_offset(address)
        data: dict = json.loads(buf[start:start + size])
        return data

    for address in (0x32589A, 0x51F76D):
        offer = record(address, 943)
        assert (offer["shop_code"], offer["price_jewelry"], offer["package_code"]) == (
            "75103", 500, "103899"
        )
        assert offer["limit_type"] == (1 if daily_limits else 4)
    for address in (0x218A72, 0x298AD3):
        assert record(address, 187)["shop_code"] == ["65024", "65026"]
    assert [record(0x2F14E4, 788)[k] for k in ("item_code", "item_count")] == ["130006", 10]
    assert [record(0x2F17F9, 790)[k] for k in ("item_code", "item_count")] == ["130000", 10]

    for address, size in ((0x24FCF3, 187), (0x4ED014, 187), (0x449A63, 822), (0x449D9A, 777)):
        start = seg_offset(address)
        assert buf[start:start + size] == baseline[start:start + size]


def test_equipment_percent_options_zeroes_server_flat_weights(reference_buffers):
    so_bytes, _dex_bytes = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_equipment_percent_options(buf) == 597
    assert apply_equipment_percent_options(buf) == 0
    table_offset = seg_offset(RANDOPTION_SERVER_SITE)
    flat_rows = 0
    for index in range(RANDOPTION_SERVER_ROW_COUNT):
        row_offset = table_offset + index * RANDOPTION_SERVER_ROW_SIZE
        (option_id,) = struct.unpack_from("<I", buf, row_offset)
        weights = struct.unpack_from(
            "<6I", buf, row_offset + RANDOPTION_SERVER_WEIGHT_OFFSET
        )
        if option_id // 1000 in RANDOPTION_SERVER_FLAT_GROUPS:
            flat_rows += 1
            assert weights == (0, 0, 0, 0, 0, 0)
    assert flat_rows == 596
    fallback_offset = seg_offset(RANDOPTION_FALLBACK_SITE)
    assert (
        bytes(buf[fallback_offset:fallback_offset + 4])
        == RANDOPTION_FALLBACK_REPLACEMENT
    )


def test_equipment_upgrade_10_guarantee_zeroes_the_plus_nine_fail_row(
    reference_buffers,
):
    so_bytes, _dex_bytes = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_equipment_upgrade_10_guarantee(buf) == 1
    assert apply_equipment_upgrade_10_guarantee(buf) == 0
    offset = seg_offset(EQUIPMENT_UPGRADE_10_FAIL_SITE)
    assert (
        bytes(buf[offset:offset + len(EQUIPMENT_UPGRADE_10_FAIL_ORIGINAL)])
        == EQUIPMENT_UPGRADE_10_FAIL_REPLACEMENT
    )


def test_equipment_single_mod_stone(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(equipment_single_mod_stone=True),
    )
    assert result.counts == {
        "equipment_single_mod_stone": 3,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
    }
    server_offset = SINGLE_MOD_STONE_SERVER_SITE - 0x4000
    assert (
        result.so_bytes[server_offset:server_offset + 4]
        == SINGLE_MOD_STONE_SERVER_REPLACEMENT
    )
    install_offset = SINGLE_MOD_STONE_INSTALL_SITE - 0x4000
    assert result.so_bytes[install_offset:install_offset + 4] == encode_arm64_branch(
        SINGLE_MOD_STONE_INSTALL_SITE, SINGLE_MOD_STONE_CAVE_VADDR
    )
    cave_offset = SINGLE_MOD_STONE_CAVE_VADDR - 0x4000
    assert (
        result.so_bytes[cave_offset:cave_offset + SINGLE_MOD_STONE_CAVE_SIZE]
        == SINGLE_MOD_STONE_CAVE_BYTES
    )
    # The client hook carries the mov w1,wzr replacement bytes.
    assert SINGLE_MOD_STONE_CLIENT_REPLACEMENT in SINGLE_MOD_STONE_CAVE_BYTES


def test_energy_flask_x10(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    offset = ENERGY_FLASK_STAMINA_SITE - 0x4000
    assert bytes(buf[offset:offset + 4]) == ENERGY_FLASK_STAMINA_ORIGINAL
    assert apply_energy_flask_x10(buf) == 1
    assert bytes(buf[offset:offset + 4]) == ENERGY_FLASK_STAMINA_REPLACEMENT
    # add x0, x19, #0x3e8 (1000) keeps the free-stamina grant at x10.
    assert bytes.fromhex("60a20f91") == ENERGY_FLASK_STAMINA_REPLACEMENT

    broken = bytearray(so_bytes)
    broken[offset:offset + 4] = b"\xff\xff\xff\xff"
    with pytest.raises(ValueError, match="Unexpected"):
        apply_energy_flask_x10(broken)


def test_guild_raid_reward_x10(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    daily_offset = GUILD_RAID_DAILY_REWARD_TABLE + 0x18
    weekly_offset = GUILD_RAID_WEEKLY_REWARD_TABLE + 0x1C
    assert struct.unpack_from("<i", buf, daily_offset)[0] == GUILD_RAID_DAILY_REWARDS[0][0]
    assert apply_guild_raid_reward_x10(buf) == 32
    assert struct.unpack_from("<i", buf, daily_offset)[0] == GUILD_RAID_DAILY_REWARDS[0][0] * 10
    assert struct.unpack_from("<i", buf, weekly_offset)[0] == GUILD_RAID_WEEKLY_REWARDS[0][1] * 10
    assert apply_guild_raid_reward_x10(buf) == 0

    broken = bytearray(so_bytes)
    struct.pack_into("<i", broken, weekly_offset, 1)
    with pytest.raises(ValueError, match="Unexpected guild raid"):
        apply_guild_raid_reward_x10(broken)


def test_recycle_six_star_rewards(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    original_weight = {
        group: sum(
            struct.unpack_from(
                "<i",
                buf,
                RECYCLE_SIX_STAR_TABLE + index * RECYCLE_SIX_STAR_ENTRY_SIZE + 4,
            )[0]
            for index in range(RECYCLE_SIX_STAR_ROW_COUNT)
            if struct.unpack_from(
                "<i", buf, RECYCLE_SIX_STAR_TABLE + index * RECYCLE_SIX_STAR_ENTRY_SIZE
            )[0]
            == group
        )
        for group in RECYCLE_SIX_STAR_GROUPS
    }
    assert apply_recycle_six_star(buf) == RECYCLE_SIX_STAR_EXPECTED_ROWS
    assert apply_recycle_six_star(buf) == 0

    patched = 0
    seen = set()
    groups: dict[int, list[tuple[int, int]]] = {
        group: [] for group in RECYCLE_SIX_STAR_GROUPS
    }
    for index in range(RECYCLE_SIX_STAR_ROW_COUNT):
        offset = RECYCLE_SIX_STAR_TABLE + index * RECYCLE_SIX_STAR_ENTRY_SIZE
        group, weight, code = struct.unpack_from("<iii", buf, offset)
        if group not in groups:
            continue
        groups[group].append((weight, code))
        patched += 1
    assert patched == RECYCLE_SIX_STAR_EXPECTED_ROWS

    for group, entries in groups.items():
        slot = RECYCLE_SIX_STAR_GROUP_SLOT[group]
        sets = RECYCLE_SIX_STAR_SLOT_SETS[slot]
        code_to_set = {
            code: set_id for set_id, codes in sets for code in codes
        }
        weight_by_set: dict[int, int] = defaultdict(int)
        for weight, code in entries:
            assert code in code_to_set
            weight_by_set[code_to_set[code]] += weight
        assert set(weight_by_set) == {set_id for set_id, _codes in sets}
        totals = list(weight_by_set.values())
        assert max(totals) - min(totals) <= 1
        assert sum(totals) == original_weight[group]
        # Every piece of every selected set must be reachable with the same
        # chance: after the per-piece split, all code totals differ by <= 1.
        code_totals: dict[int, int] = defaultdict(int)
        for weight, code in entries:
            code_totals[code] += weight
        assert len(code_totals) == sum(len(codes) for _sid, codes in sets)
        values = sorted(code_totals.values())
        assert values[-1] - values[0] <= 1
        seen.add(slot)
    assert seen == {1, 2, 3, 4, 5}



def test_event_gene_unlimited_only_touches_gene_rows(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_event_gene_unlimited(buf) == EXPECTED_EVENT_GENE_ROWS
    assert apply_event_gene_unlimited(buf) == 0
    assert buf.count(b'"limit_type":255,"limit_max":9') == EXPECTED_EVENT_GENE_ROWS
    # The five non-gene rows with limit_max 100 must remain untouched.
    assert buf.count(b'"limit_max":100') == 5

    modified = 0
    cursor = 0
    seen: set[int] = set()
    while True:
        marker = buf.find(EVENT_GENE_ITEM_CATEGORY, cursor)
        if marker < 0:
            break
        row_start = buf.rfind(b"{", 0, marker)
        row_end = buf.find(b"}", marker)
        if row_start not in seen:
            seen.add(row_start)
            if b'"limit_type":255,"limit_max":9' in buf[row_start:row_end + 1]:
                modified += 1
        cursor = marker + len(EVENT_GENE_ITEM_CATEGORY)
    assert modified == EXPECTED_EVENT_GENE_ROWS


def test_event_limits_daily_converts_only_event_rows(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert len(EVENT_LIMIT_TYPE_PATTERN.findall(buf)) == 1224
    assert len(EVENT_SHOP_TYPE_4_PATTERN.findall(buf)) == 199
    assert (
        len(EVENT_LIMIT_TYPE_PATTERN.findall(buf))
        + len(EVENT_SHOP_TYPE_4_PATTERN.findall(buf))
        == EXPECTED_EVENT_LIMIT_ROWS
    )
    assert apply_event_limits_daily(buf) == EXPECTED_EVENT_LIMIT_ROWS + 3
    assert apply_event_limits_daily(buf) == 0
    assert len(EVENT_LIMIT_TYPE_PATTERN.findall(buf)) == 0
    assert len(EVENT_SHOP_TYPE_4_PATTERN.findall(buf)) == 0
    # The gem-upgrade row (limit 3/event) is now daily with the same limit.
    row = re.search(rb'\{[^{}]*?"item_code":"2060051"[^{}]*?\}', buf)
    assert row is not None
    assert b'"limit_type":1,"limit_max":3' in row.group()
    # An Event Shop row that used the Honor period is now daily too.
    row = re.search(rb'\{[^{}]*?"item_code":"130001"[^{}]*?\}', buf)
    assert row is not None
    assert b'"limit_type":1,"limit_max":1' in row.group()


def test_bootstrap_smali_translation_replaces_literals() -> None:
    source = (
        '.method private static demo()V\n'
        '    const-string v1, "\\ub0b4\\uc7a5 \\ub9ac\\uc18c\\uc2a4\\ub97c '
        '\\ud655\\uc778\\ud558\\ub294 \\uc911\\uc785\\ub2c8\\ub2e4\\u2026"\n'
        '    const-string v2, "\\ub2e4\\uc2dc \\uc2dc\\ub3c4"\n'
        '    return-void\n'
        '.end method\n'
    )
    translated, counts = _replace_smali_strings(
        source,
        {
            "내장 리소스를 확인하는 중입니다…": "Checking game resources...",
            "다시 시도": "Retry",
        },
    )
    assert counts == {
        "내장 리소스를 확인하는 중입니다…": 1,
        "다시 시도": 1,
    }
    assert "Checking game resources..." in translated
    assert "Retry" in translated
    assert "내장" not in translated


def test_resource_contract_updates_fields_strings_and_bytecode() -> None:
    critical_path = "Resources/datatable/equipselectlist.unity3d"
    old_critical = REFERENCE_CRITICAL_FILE_HASHES[critical_path]
    new_critical = "CD" * 32
    contract = ResourceContract(
        sha256_hex="AB" * 32,
        file_count=8700,
        uncompressed_bytes=870_500_000,
        critical_hashes=((critical_path, new_critical),),
    )
    source = (
        f'.field private static final ARCHIVE_SHA256:Ljava/lang/String; = '
        f'"{REFERENCE_RESOURCE_SHA256}"\n'
        '.field private static final EXPECTED_FILE_COUNT:J = 0x21f9L\n'
        '.field private static final EXPECTED_UNCOMPRESSED_BYTES:J = 0x33e23c58L\n'
        f'.field private static final MARKER_CONTENT:Ljava/lang/String; = '
        f'"{REFERENCE_RESOURCE_SHA256}\\nfiles={REFERENCE_RESOURCE_FILE_COUNT}\\n'
        f'bytes={REFERENCE_RESOURCE_UNCOMPRESSED_BYTES}\\n"\n'
        '    const-wide/16 v2, 0x21f9\n'
        '    const-wide/32 v16, 0x33e23c58\n'
        f'    const-string v3, "{old_critical}"\n'
    )
    patched, changes = _patch_resource_contract(source, contract)
    assert changes >= 6
    assert contract.sha256_hex in patched
    assert REFERENCE_RESOURCE_SHA256 not in patched
    assert "files=8700" in patched
    assert "bytes=870500000" in patched
    assert "0x21f9" not in patched
    assert "0x33e23c58" not in patched
    assert new_critical in patched
    assert old_critical not in patched


def test_resource_contract_from_archive() -> None:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("files/a.bin", b"abc")
        archive.writestr("files/b.bin", b"de")
        archive.writestr(
            "files/Resources/datatable/equipselectlist.unity3d", b"selection"
        )
    contract = ResourceContract.from_archive(buffer.getvalue())
    assert contract.file_count == 3
    assert contract.uncompressed_bytes == 14
    assert len(contract.sha256_hex) == 64
    critical = dict(contract.critical_hashes)
    assert "Resources/datatable/equipselectlist.unity3d" in critical
    assert len(critical["Resources/datatable/equipselectlist.unity3d"]) == 64


def _require_dex_tools() -> Path:
    jar = find_apktool_jar()
    if jar is None:
        pytest.skip("apktool jar not available; set FWT_APKTOOL_JAR to run this test")
    if find_java_executable() is None:
        pytest.skip("Java runtime not found; install a JRE/JDK or set JAVA_HOME to run this test")
    return jar


def test_find_java_executable_checks_path_and_java_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.delenv("JAVA_HOME", raising=False)
    assert find_java_executable() is None

    java_home = tmp_path / "jdk"
    java_bin = java_home / "bin"
    java_bin.mkdir(parents=True)
    exe = java_bin / ("java.exe" if os.name == "nt" else "java")
    exe.write_text("", encoding="utf-8")
    monkeypatch.setenv("JAVA_HOME", str(java_home))
    assert find_java_executable() == exe


@pytest.mark.integration
def test_english_dex_rebuild_checksums_and_detection(reference_buffers):
    _, dex_bytes = reference_buffers
    jar = _require_dex_tools()
    verify_dex_string_order(dex_bytes)
    buf = bytearray(dex_bytes)
    assert apply_english_localization_dex(buf, apktool_jar=jar) == 52
    verify_dex_string_order(bytes(buf))
    ok, message = verify_dex_checksums(buf)
    assert ok, message
    strings = set(read_dex_strings(bytes(buf)))
    assert "Checking game resources..." in strings
    assert "Could not prepare game resources." in strings
    assert "Retry" in strings
    assert "리소스 준비에 실패했습니다." not in strings
    assert inspect_dex(buf)["dex_status_string"].active


def test_event_coin_patch_does_not_touch_items_cave(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_event_coin_x10(buf)
    # The old EGL/items region must remain original; event coin is elsewhere.
    assert bytes(buf[0xAA6CAC - 0x4000:0xAA6CB4 - 0x4000]) == bytes(
        so_bytes[0xAA6CAC - 0x4000:0xAA6CB4 - 0x4000]
    )
    cave = bytes(
        buf[
            EVENT_COIN_CAVE_VADDR - 0x4000:
            EVENT_COIN_CAVE_VADDR - 0x4000 + EVENT_COIN_CAVE_SIZE
        ]
    )
    assert cave[:12] == bytes.fromhex("48018052737e089be00313aa")
    # Old cleanup branch must be restored to its original target.
    assert bytes(buf[0x8D05B8 - 0x4000:0x8D05B8 - 0x4000 + 4]) == bytes.fromhex("02000014")


def test_event_coin_rejects_unknown_hook(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    buf[0x8D05B8 - 0x4000:0x8D05B8 - 0x4000 + 4] = b"\x00\x00\x00\x00"
    with pytest.raises(ValueError, match="old event coin hook"):
        apply_event_coin_x10(buf)

    buf = bytearray(so_bytes)
    buf[0x8D05C0 - 0x4000:0x8D05C0 - 0x4000 + 4] = b"\x00\x00\x00\x00"
    with pytest.raises(ValueError, match="event coin hook"):
        apply_event_coin_x10(buf)


def test_campaign_gold_table_and_cave(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(so_bytes, dex_bytes, PatchOptions(campaign_gold=True))
    row0 = struct.unpack_from("<6i", result.so_bytes, STAGE_TABLE_OFFSET)
    assert row0[2] == 2000  # base gold multiplied by 10x
    assert row0[5] == 200  # grade min/max untouched
    gold_cave = result.so_bytes[
        CAMPAIGN_CAVE_BASE - 0x4000: CAMPAIGN_CAVE_BASE - 0x4000 + 48
    ]
    assert b"\xe8\x87\x9f\x1a" in gold_cave  # cset w8, ls
    assert b"\xea\x03\x40\x39" in gold_cave  # ldrb w10, [sp]
    assert b"\xd6\xfa\x7f\xd3" in gold_cave  # lsl x22, x22, #1


def test_guild_raid_score_fix_branches_and_caves(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes, dex_bytes, PatchOptions(guild_raid_score_fix=True)
    )
    assert result.counts == {
        "guild_raid_score_fix": 2,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
    }

    start = result.so_bytes[
        GUILD_RAID_START_SITE - 0x4000:GUILD_RAID_START_SITE - 0x4000 + 8
    ]
    assert start[:4] == encode_arm64_branch(
        GUILD_RAID_START_SITE, GUILD_RAID_SENTINEL_CAVE
    )
    assert start[4:] == bytes.fromhex("1f2003d5")  # nop

    install = result.so_bytes[
        GUILD_RAID_INSTALL_SITE - 0x4000:GUILD_RAID_INSTALL_SITE - 0x4000 + 4
    ]
    assert install == encode_arm64_branch(GUILD_RAID_INSTALL_SITE, GUILD_RAID_CLIENT_CAVE)

    sentinel = result.so_bytes[
        GUILD_RAID_SENTINEL_CAVE - 0x4000:
        GUILD_RAID_SENTINEL_CAVE - 0x4000 + len(GUILD_RAID_SENTINEL_CAVE_BYTES)
    ]
    assert sentinel == GUILD_RAID_SENTINEL_CAVE_BYTES
    # cmp w10,w11 against the client trampoline's `ldr x16,#8` word.
    assert sentinel[0x2C:0x34] == bytes.fromhex("0b0a80520b00ab72")

    client = result.so_bytes[
        GUILD_RAID_CLIENT_CAVE - 0x4000:
        GUILD_RAID_CLIENT_CAVE - 0x4000 + len(GUILD_RAID_CLIENT_CAVE_BYTES)
    ]
    assert client == GUILD_RAID_CLIENT_CAVE_BYTES
    assert b"\x0c\xf3\xfd\x17" in client  # b 0xAB00DC (continue the patch loop)


def test_single_material_features_patch_exact_sites(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(single_black_hammer=True, single_gem_fang=True),
    )
    assert result.counts == {
        "single_black_hammer": 1,
        "single_gem_fang": 5,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
    }
    assert (
        result.so_bytes[
            SINGLE_BLACK_HAMMER_SITE - 0x4000:
            SINGLE_BLACK_HAMMER_SITE - 0x4000 + 4
        ]
        == SINGLE_BLACK_HAMMER_REPLACEMENT
    )
    assert (
        result.so_bytes[
            SINGLE_GEM_FANG_SITE - 0x4000:SINGLE_GEM_FANG_SITE - 0x4000 + 4
        ]
        == SINGLE_GEM_FANG_REPLACEMENT
    )


def test_single_material_features_reject_unknown_sites(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    buf[SINGLE_BLACK_HAMMER_SITE - 0x4000:SINGLE_BLACK_HAMMER_SITE - 0x4000 + 4] = bytes(4)
    with pytest.raises(ValueError, match="single black hammer"):
        apply_single_black_hammer(buf)

    buf = bytearray(so_bytes)
    buf[SINGLE_GEM_FANG_SITE - 0x4000:SINGLE_GEM_FANG_SITE - 0x4000 + 4] = bytes(4)
    with pytest.raises(ValueError, match="single gem fang"):
        apply_single_gem_fang(buf)


def test_stamina_potion_1000_site(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(stamina_potion_1000=True),
    )
    assert result.counts == {
        "stamina_potion_1000": 1,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
    }
    offset = STAMINA_POTION_1000_SITE - 0x4000
    assert result.so_bytes[offset:offset + len(STAMINA_POTION_1000_REPLACEMENT)] == (
        STAMINA_POTION_1000_REPLACEMENT
    )


def test_coocoo_exp_x2_and_stamina_half_sites(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(coocoo_exp_x2=True, stamina_cost_half=True),
    )
    assert result.counts == {
        "coocoo_exp_x2": 1,
        "stamina_cost_half": 1,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
    }
    for site, replacement in (
        (COOCOO_EXP_X2_SITE, COOCOO_EXP_X2_REPLACEMENT),
        (STAMINA_HALF_SITE, STAMINA_HALF_REPLACEMENT),
    ):
        offset = site - 0x4000
        assert result.so_bytes[offset:offset + len(replacement)] == replacement


def test_coocoo_level_x2_doubles_all_garden_and_pit_stages(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert len(COOCOO_STAGE_LEVELS) == 30
    assert apply_coocoo_level_x2(buf) == len(COOCOO_STAGE_LEVELS)
    for index, original in enumerate(COOCOO_STAGE_LEVELS):
        offset = (
            COOCOO_STAGE_TABLE_OFFSET
            + index * COOCOO_STAGE_ROW_SIZE
            + COOCOO_STAGE_LEVEL_OFFSET
        )
        assert struct.unpack_from("<2i", buf, offset) == (original * 2, original * 2)
        if index >= 20:
            row_offset = COOCOO_STAGE_TABLE_OFFSET + index * COOCOO_STAGE_ROW_SIZE
            expected_code = (
                0x702010,
                0x702020,
                0x702030,
                0x702040,
                0x702050,
                0x702060,
                0x702070,
                0x702080,
                0x702090,
                0x702100,
            )[index - 20]
            assert struct.unpack_from("<i", buf, row_offset)[0] == expected_code
    assert apply_coocoo_level_x2(buf) == 0


def test_ship_parts_90_off_and_crystal_skill_cost(reference_buffers):
    assert apply_ship_parts_half is apply_ship_parts_90_off
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)

    expected_ship_changes = sum(
        1 for _offset, values in SHIP_PART_COST_TABLES for value in values if value
    )
    assert apply_ship_parts_90_off(buf) == expected_ship_changes
    assert apply_crystal_skill_90_off(buf) == 1

    for table_offset, values in SHIP_PART_COST_TABLES:
        for index, original in enumerate(values):
            offset = table_offset + index * SHIP_PART_COST_FIELD_SIZE
            expected = 0 if original == 0 else max(1, (original + 9) // 10)
            assert struct.unpack_from("<q", buf, offset)[0] == expected

    crystal_offset = CRYSTAL_SKILL_COST_SITE - 0x4000
    assert (
        bytes(buf[crystal_offset:crystal_offset + len(CRYSTAL_SKILL_COST_REPLACEMENT)])
        == CRYSTAL_SKILL_COST_REPLACEMENT
    )

    assert apply_ship_parts_90_off(buf) == 0
    assert apply_crystal_skill_90_off(buf) == 0


def test_worldboss_full_ship_repair_instructions(reference_buffers):
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    key = "worldboss_full_ship_repair"
    assert not inspect_native_so(buf)[key].active
    assert apply_worldboss_full_ship_repair(buf) == 3
    assert apply_worldboss_full_ship_repair(buf) == 0
    assert inspect_native_so(buf)[key].active

    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for site, expected in (
        (0x976048, ("mov", "x24, x21")),
        (0x849D60, ("fmov", "d1, #1.00000000")),
        (0x97704C, ("fmov", "d1, #1.00000000")),
    ):
        offset = seg_offset(site)
        assert list(decoder.disasm_lite(bytes(buf[offset:offset + 4]), site))[0][2:] == expected

    offset = seg_offset(0x97704C)
    buf[offset:offset + 4] = so_bytes[offset:offset + 4]
    assert not inspect_native_so(buf)[key].active

    corrupt = bytearray(so_bytes)
    corrupt[offset:offset + 4] = b"\x00" * 4
    before = bytes(corrupt)
    with pytest.raises(ValueError, match="Unexpected ship repair instruction"):
        apply_worldboss_full_ship_repair(corrupt)
    assert bytes(corrupt) == before


def test_gem_mining_x10(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_gem_mining_x10(buf) == 1
    hook_off = GEM_MINING_COUNT_SITE - 0x4000
    cave_off = GEM_MINING_CAVE_VADDR - 0x4000
    assert bytes(buf[hook_off:hook_off + 4]) == encode_arm64_branch(
        GEM_MINING_COUNT_SITE,
        GEM_MINING_CAVE_VADDR,
        link=True,
    )
    assert (
        bytes(buf[cave_off:cave_off + len(GEM_MINING_CAVE_BYTES)])
        == GEM_MINING_CAVE_BYTES
    )
    assert apply_gem_mining_x10(buf) == 0


def test_gem_mining_types(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_gem_mining_types(buf) == 2
    hook_off = GEM_MINING_TYPES_HOOK - 0x4000
    cave_off = GEM_MINING_TYPES_CAVE_VADDR - 0x4000
    assert bytes(buf[hook_off:hook_off + 4]) == encode_arm64_branch(
        GEM_MINING_TYPES_HOOK,
        GEM_MINING_TYPES_CAVE_VADDR,
    )
    assert (
        bytes(buf[cave_off:cave_off + len(GEM_MINING_TYPES_CAVE_BYTES)])
        == GEM_MINING_TYPES_CAVE_BYTES
    )
    assert apply_gem_mining_types(buf) == 0


def test_battle_arena_save_fix(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_battle_arena_save_fix(buf) == 1
    site_off = BATTLE_ARENA_SAVE_LATE_SITE - 0x4000
    assert bytes(buf[site_off:site_off + 4]) == encode_arm64_branch(
        BATTLE_ARENA_SAVE_LATE_SITE, BATTLE_ARENA_SAVE_CAVE_VADDR
    )
    cave_off = BATTLE_ARENA_SAVE_CAVE_VADDR - 0x4000
    assert (
        bytes(buf[cave_off:cave_off + len(BATTLE_ARENA_SAVE_CAVE_BYTES)])
        == BATTLE_ARENA_SAVE_CAVE_BYTES
    )
    assert apply_battle_arena_save_fix(buf) == 0


def test_gem_level6(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_gem_level6(buf) == 9
    assert apply_gem_level6(buf) == 0
    for addr in GEM_LEVEL6_STRINGS:
        assert bytes(buf[addr + 4:addr + 5]) == b"6"


def test_gem_upgrade_gold_half(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    offset = GEM_UPGRADE_GOLD_SITE - 0x4000
    assert bytes(buf[offset:offset + 4]) == GEM_UPGRADE_GOLD_ORIGINAL
    assert apply_gem_upgrade_gold_half(buf) == 1
    assert bytes(buf[offset:offset + 4]) == GEM_UPGRADE_GOLD_REPLACEMENT
    assert apply_gem_upgrade_gold_half(buf) == 0
    assert bytes(buf[offset:offset + 4]) == GEM_UPGRADE_GOLD_REPLACEMENT


def test_guild_raid_score_fix_rejects_unknown_sites(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    buf[GUILD_RAID_START_SITE - 0x4000:GUILD_RAID_START_SITE - 0x4000 + 8] = bytes(8)
    with pytest.raises(ValueError, match="guild raid start site"):
        apply_guild_raid_score_fix(buf)

    buf = bytearray(so_bytes)
    buf[GUILD_RAID_INSTALL_SITE - 0x4000:GUILD_RAID_INSTALL_SITE - 0x4000 + 4] = bytes(4)
    with pytest.raises(ValueError, match="guild raid installer site"):
        apply_guild_raid_score_fix(buf)


@pytest.mark.integration
def test_reference_all_patch_counts_and_egl_integrity(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    jar = _require_dex_tools()
    options = PatchOptions(
        campaign_gold=True,
        campaign_xp=True,
        no_equip_drops=True,
        gene_priority=True,
        summon_rates_50_30_20=True,
        expedition_bonus=True,
        english_localization=True,
        event_discount=True,
        event_gene_unlimited=True,
        event_limits_daily=True,
        recycle_six_star=True,
        energy_flask_x10=True,
        gold_cylinder_x10=True,
        mana_cylinder_x10=True,
        event_coin_x10=True,
        guild_raid_score_fix=True,
        single_black_hammer=True,
        single_gem_fang=True,
        upgrade_no_fail_above_20=True,
        battle_arena_save_fix=True,
        sacred_lands_restore=True,
        limit_break_cost_fixed=True,
        coocoo_exp_x2=True,
        coocoo_level_x2=True,
        ship_parts_90_off=True,
        worldboss_full_ship_repair=True,
        crystal_skill_90_off=True,
        gem_mining_x10=True,
        gem_mining_types=True,
        gem_level6=True,
        gem_upgrade_gold_half=True,
        stamina_cost_half=True,
        stamina_potion_1000=True,
        campaign_shop_discount=True,
        mode_drops_x10=True,
        devil_boost_x10=True,
        battle_arena_fix=True,
        guild_raid_mercenary=True,
        guild_raid_reward_x10=True,
        option_max_attributes=True,
        rune_box_random_type=True,
        rune_quality_factor=10,
        rune_box_random_roll=True,
        equipment_lock_fix=True,
        equipment_single_mod_stone=True,
        equipment_percent_options=True,
        equipment_upgrade_10_guarantee=True,
        soulgear_enchant_always=True,
        rune_option_quality=True,
        lan_redirect=True,
        server_ip="192.168.10.25",
        server_port=8020,
        align_16k=True,
    )
    result = apply_all_patches(so_bytes, dex_bytes, options, apktool_jar=jar)
    assert result.counts == {
        "summon_rates_50_30_20": 228,
        "expedition_bonus": 24,
        "gene_priority": 141,
        "no_equip_drops": 431,
        "campaign_xp": 381,
        "campaign_gold": 381,
        "event_discount": 122,
        "event_gene_unlimited": EXPECTED_EVENT_GENE_ROWS,
        "event_limits_daily": EXPECTED_EVENT_LIMIT_ROWS + 3,
        "recycle_six_star": RECYCLE_SIX_STAR_EXPECTED_ROWS,
        "limit_break_cost_fixed": LIMIT_BREAK_GOLD_ROWS,
        "coocoo_exp_x2": 1,
        "coocoo_level_x2": len(COOCOO_STAGE_LEVELS),
        "ship_parts_90_off": 41,
        "worldboss_full_ship_repair": 3,
        "crystal_skill_90_off": 1,
        "gem_mining_x10": 1,
        "gem_mining_types": 2,
        "gem_level6": 9,
        "gem_upgrade_gold_half": 1,
        "stamina_cost_half": 1,
        "stamina_potion_1000": 1,
        "energy_flask_x10": 1,
        "gold_cylinder_x10": 2,
        "mana_cylinder_x10": 2,
        "option_max_attributes": RANDOPTION_SERVER_ROW_COUNT,
        "rune_box_random_type": len(RUNE_BOX_TYPE_REWRITES),
        "rune_quality_factor": 1,
        "rune_box_random_roll": len(RUNE_ROLL_SITES) + 2,
        "equipment_lock_fix": 1,
        "equipment_single_mod_stone": 3,
        # The max-quality bias rewrites the same table first, so only the flat
        # rows it still weights (35 of the 296) are left for this pass, plus
        # the zero-weight picker fallback branch.
        "equipment_percent_options": 66,
        "equipment_upgrade_10_guarantee": 1,
        "soulgear_enchant_always": 1,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
        "rune_option_quality": 1,
        "event_coin_x10": 1,
        "guild_raid_score_fix": 2,
        "single_black_hammer": 1,
        "single_gem_fang": 5,
        "upgrade_no_fail_above_20": 5,
        "battle_arena_save_fix": 1,
        "campaign_shop_discount": 104,
        "mode_drops_x10": 392,
        "devil_boost_x10": 1,
        "battle_arena_fix": 11,
        "guild_raid_mercenary": 4,
        "guild_raid_reward_x10": 32,
        "lan_redirect": 1,
        "english_localization": 4992,
    }
    # The EGL function must remain byte-for-byte original.
    assert result.so_bytes[0xAA6BFC - 0x4000:0xAA6D2C - 0x4000] == so_bytes[
        0xAA6BFC - 0x4000:0xAA6D2C - 0x4000
    ]
    # The legacy EGL/items region must remain original after relocation.
    assert result.so_bytes[0xAA6CAC - 0x4000:0xAA6CB4 - 0x4000] == so_bytes[
        0xAA6CAC - 0x4000:0xAA6CB4 - 0x4000
    ]
    items_tail = ITEM_CAVE_VADDR + ITEM_CAVE_FIRST_SIZE + 32
    assert result.so_bytes[items_tail - 0x4000:items_tail - 0x4000 + 4] == bytes.fromhex(
        "73fa7fd3"
    )
    assert (
        result.so_bytes[items_tail + 4 - 0x4000:items_tail + 8 - 0x4000]
        == encode_arm64_branch(items_tail + 4, 0xA2D6C8)
    )
    assert verify_dex_checksums(result.dex_bytes)[0]
    native_rep = inspect_native_so(result.so_bytes)
    dex_rep = inspect_dex(result.dex_bytes, so_bytes=result.so_bytes)
    assert dex_rep["dex_status_string"].active
    assert dex_rep["dex_backup_prompt"].active
    assert native_rep["network_mode"].active
    assert "192.168.10.25:8020" in native_rep["network_mode"].status
    for key in (
        "campaign_xp",
        "mode_drops_x10",
        "option_max_attributes",
        "gold_cylinder_x10",
        "mana_cylinder_x10",
        "rune_box_random_type",
        "rune_quality_factor",
        "rune_box_random_roll",
        "equipment_lock_fix",
        "soulgear_enchant_always",
        "no_win_box",
        "hero_exp_cap",
        "rune_option_quality",
        "limit_break_cost_fixed",
        "english_localization",
    ):
        assert native_rep[key].active, f"{key} unexpectedly inactive: {native_rep[key]}"


def test_reference_alternate_profile_and_no_cave_collisions(reference_buffers):
    """Covers mutually exclusive alternate flags alongside newer SO/DEX patches."""
    so_bytes, dex_bytes = reference_buffers
    options = PatchOptions(
        summon_rates=True,
        limit_break_cost_fixed=True,
        gold_cylinder_x10=True,
        mana_cylinder_x10=True,
        option_max_attributes=True,
        rune_box_random_type=True,
        rune_quality_factor=10,
        rune_box_random_roll=True,
        equipment_lock_fix=True,
        soulgear_enchant_always=True,
        rune_option_quality=True,
        lan_redirect=True,
        server_ip="10.0.0.42",
        server_port=8011,
    )
    result = apply_all_patches(so_bytes, dex_bytes, options)
    assert result.counts == {
        "summon_rates": 228,
        "limit_break_cost_fixed": LIMIT_BREAK_GOLD_ROWS,
        "option_max_attributes": RANDOPTION_SERVER_ROW_COUNT,
        "rune_box_random_type": len(RUNE_BOX_TYPE_REWRITES),
        "rune_quality_factor": 1,
        "rune_box_random_roll": len(RUNE_ROLL_SITES) + 2,
        "equipment_lock_fix": 1,
        "soulgear_enchant_always": 1,
        "no_win_box": 2,
        "hero_exp_cap": 4,
        "convert_hex_guard": 2,
        "dungeon_recom_info": 2,
        "rune_option_quality": 1,
        "gold_cylinder_x10": 2,
        "mana_cylinder_x10": 2,
        "lan_redirect": 1,
    }
    assert verify_dex_checksums(result.dex_bytes)[0]
    native_rep = inspect_native_so(result.so_bytes)
    dex_rep = inspect_dex(result.dex_bytes, so_bytes=result.so_bytes)
    assert dex_rep["dex_backup_prompt"].active
    assert not dex_rep["dex_status_string"].active
    assert native_rep["network_mode"].active
    assert "10.0.0.42:8011" in native_rep["network_mode"].status
    for key in (
        "summon_rates",
        "limit_break_cost_fixed",
        "gold_cylinder_x10",
        "mana_cylinder_x10",
        "option_max_attributes",
        "rune_box_random_type",
        "rune_quality_factor",
        "rune_box_random_roll",
        "equipment_lock_fix",
        "soulgear_enchant_always",
        "no_win_box",
        "hero_exp_cap",
        "rune_option_quality",
    ):
        assert native_rep[key].active, f"{key} unexpectedly inactive: {native_rep[key]}"


@pytest.mark.integration
def test_reference_apply_twice_is_rejected_by_reference_hash(reference_buffers):
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(so_bytes, dex_bytes, PatchOptions(campaign_xp=True))
    with pytest.raises(ValueError, match="not the supported reference"):
        apply_all_patches(result.so_bytes, result.dex_bytes, PatchOptions(campaign_xp=True))

    # With allow_unknown=True (--force), re-applying is idempotent and does not 4x values.
    second = apply_all_patches(
        result.so_bytes,
        result.dex_bytes,
        PatchOptions(campaign_xp=True, allow_unknown=True),
    )
    assert second.so_bytes == result.so_bytes


def test_no_duplicate_cave_keys():
    # CAMPAIGN_HOOKS includes 7 hook branches + 4 relocated cave bodies.
    assert len(CAMPAIGN_HOOKS) == 11
    assert len(set(CAMPAIGN_HOOKS)) == len(CAMPAIGN_HOOKS)


def test_campaign_shop_discount_idempotent(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_campaign_shop_discount(buf) == 104
    assert re.search(
        rb'"shop_code":"6A102"[^{}\x00]*?"price_coin": 2\x00', bytes(buf)
    )

    for code, price in ((b"69974", 1500), (b"6A101", 1750), (b"69973", 1000)):
        match = re.search(
            rb'"shop_code":"' + code + rb'"[^{}]*?"price_coin":\s*(\d+)', bytes(buf)
        )
        assert match is not None
        assert int(match.group(1)) == price

    for shop_code, expected in (
        (b"5202", 30),      # Ancient Coins, 300 -> 30
        (b"5209", 90000),   # Ancient Coins gold row, 900000 -> 90000
        (b"1107", 75),      # Battle of Honor, 750 -> 75
        (b"6102", 5),       # Unknown Paradise, 50 -> 5
        (b"5201", 1),       # minimum price stays at 1
    ):
        match = re.search(
            rb'"shop_code":"' + shop_code + rb'"[^{}]*?"price_count":\s*(\d+)',
            bytes(buf),
        )
        assert match is not None
        assert int(match.group(1)) == expected

    # Idempotent second pass must not discount again.
    assert apply_campaign_shop_discount(buf) == 0
    assert inspect_native_so(bytes(buf))["campaign_shop_discount"].active
    broken = bytearray(buf)
    coin = re.search(rb'"shop_code":"69974"[^{}]*?"price_coin":(\s*\d+)', bytes(broken))
    assert coin is not None
    broken[coin.start(1):coin.end(1)] = b"15000"
    assert not inspect_native_so(bytes(broken))["campaign_shop_discount"].active
    broken_fragment = bytearray(buf)
    fragment = re.search(
        rb'"shop_code":"6A102"[^{}\x00]*?"price_coin":( 2)\x00',
        bytes(broken_fragment),
    )
    assert fragment is not None
    broken_fragment[fragment.start(1):fragment.end(1)] = b"20"
    assert not inspect_native_so(bytes(broken_fragment))["campaign_shop_discount"].active
    for shop_code, expected in (
        (b"5202", 30),
        (b"5209", 90000),
        (b"1107", 75),
        (b"6102", 5),
    ):
        match = re.search(
            rb'"shop_code":"' + shop_code + rb'"[^{}]*?"price_count":\s*(\d+)',
            bytes(buf),
        )
        assert match is not None
        assert int(match.group(1)) == expected


def test_mode_drops_x10_sites_and_caves(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_mode_drops_x10(buf) == 392

    # Verify World Boss final cycle-end rank/grade rewards (22 rows -> 10x)
    wb_rows = worldboss_cycle_reward_rows(buf)
    assert len(wb_rows) == WORLDBOSS_CYCLE_REWARD_TARGET_COUNT
    assert (
        hashlib.sha256(repr(wb_rows).encode("ascii")).hexdigest()
        == WORLDBOSS_CYCLE_REWARD_PATCHED_SHA256
    )

    # Event 10002 stays its stock Mobile Repair Shop row (type == 2) so
    # WORLDBOSS_RESULT_EVENT keeps Instant Repair working; older patched builds
    # with the overwritten row are repaired back to stock.
    wb_ev_off = seg_offset(WORLDBOSS_EVENT_REWARD_SITE)
    assert (
        bytes(buf[wb_ev_off : wb_ev_off + len(WORLDBOSS_EVENT_REWARD_ORIGINAL)])
        == WORLDBOSS_EVENT_REWARD_ORIGINAL
    )
    repaired = bytearray(so_bytes)
    repaired[wb_ev_off : wb_ev_off + len(WORLDBOSS_EVENT_REWARD_REPLACEMENT)] = (
        WORLDBOSS_EVENT_REWARD_REPLACEMENT
    )
    assert apply_mode_drops_x10(repaired) == 393
    assert (
        bytes(repaired[wb_ev_off : wb_ev_off + len(WORLDBOSS_EVENT_REWARD_ORIGINAL)])
        == WORLDBOSS_EVENT_REWARD_ORIGINAL
    )

    # Verify World Boss daily Kraken Scale hook & cave
    wb_expected = encode_arm64_branch(
        WORLDBOSS_DAILY_KRAKEN_SITE, WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR
    )
    assert (
        bytes(
            buf[
                seg_offset(WORLDBOSS_DAILY_KRAKEN_SITE) : seg_offset(
                    WORLDBOSS_DAILY_KRAKEN_SITE
                )
                + 4
            ]
        )
        == wb_expected
    )
    assert (
        bytes(
            buf[
                seg_offset(WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR) : seg_offset(
                    WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR
                )
                + len(WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES)
            ]
        )
        == WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES
    )

    # Verify Dimension Breakthrough hook
    dim_expected = encode_arm64_branch(DIMENSION_DROP_SITE, DIMENSION_CAVE_VADDR)
    assert bytes(buf[DIMENSION_DROP_SITE - 0x4000:DIMENSION_DROP_SITE - 0x4000 + 4]) == dim_expected

    # Verify the Honor Coin grant is 60 and the gene path is guaranteed/x10.
    assert (
        bytes(
            buf[
                HONOR_COIN_COUNT_SITE - 0x4000:HONOR_COIN_COUNT_SITE - 0x4000 + 4
            ]
        )
        == HONOR_COIN_COUNT_REPLACEMENT
    )
    honor_points_expected = encode_arm64_branch(
        HONOR_POINTS_DELTA_SITE, HONOR_POINTS_CAVE_VADDR, link=True
    )
    assert (
        bytes(
            buf[
                HONOR_POINTS_DELTA_SITE
                - 0x4000:HONOR_POINTS_DELTA_SITE
                - 0x4000
                + 4
            ]
        )
        == honor_points_expected
    )
    assert (
        bytes(
            buf[
                HONOR_POINTS_CAVE_VADDR
                - 0x4000:HONOR_POINTS_CAVE_VADDR
                - 0x4000
                + len(HONOR_POINTS_CAVE_BYTES)
            ]
        )
        == HONOR_POINTS_CAVE_BYTES
    )
    assert (
        bytes(
            buf[
                DIMENSION_GENE_GUARANTEE_SITE
                - 0x4000:DIMENSION_GENE_GUARANTEE_SITE
                - 0x4000
                + 4
            ]
        )
        == DIMENSION_GENE_GUARANTEE_REPLACEMENT
    )
    gene_count_expected = encode_arm64_branch(
        DIMENSION_GENE_COUNT_SITE, DIMENSION_GENE_CAVE_VADDR
    )
    assert (
        bytes(
            buf[
                DIMENSION_GENE_COUNT_SITE - 0x4000:DIMENSION_GENE_COUNT_SITE - 0x4000 + 4
            ]
        )
        == gene_count_expected
    )

    # Verify Sky Library riddle col 5 is 10,000,000 (was 1,000,000)
    riddle0 = struct.unpack_from("<7i", buf, RIDDLE_TABLE_OFFSET)
    assert riddle0[5] == 10000000

    # Idempotent pass does not multiply again
    assert apply_mode_drops_x10(buf) == 0
    assert struct.unpack_from("<7i", buf, RIDDLE_TABLE_OFFSET)[5] == 10000000


def test_devil_boost_x10(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert struct.unpack_from("<f", buf, DEVIL_BOOST_MULTIPLIER_SITE)[0] == 2.0
    assert apply_devil_boost_x10(buf) == 1
    assert (
        struct.unpack_from("<f", buf, DEVIL_BOOST_MULTIPLIER_SITE)[0]
        == DEVIL_BOOST_MULTIPLIER_PATCHED
    )
    assert apply_devil_boost_x10(buf) == 0


def test_nephthys_item_cave_and_gold_multiplier(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_campaign_gold_and_drops(buf) == 381
    first_expected = encode_arm64_branch(0xA2D0D4, ITEM_CAVE_VADDR)
    second_expected = encode_arm64_branch(
        0xA2D6C4, ITEM_CAVE_VADDR + ITEM_CAVE_FIRST_SIZE
    )
    assert bytes(buf[0xA2D0D4 - 0x4000:0xA2D0D4 - 0x4000 + 4]) == first_expected
    assert bytes(buf[0xA2D6C4 - 0x4000:0xA2D6C4 - 0x4000 + 4]) == second_expected
    # The new cave stores the 0/1/2 flag on the stack and branches back.
    cave = bytes(buf[ITEM_CAVE_VADDR - 0x4000:ITEM_CAVE_VADDR - 0x4000 + 112])
    assert b"\xea\x03\x00\x39" in cave  # strb w10, [sp]
    assert cave.count(b"\x73\xfa\x7f\xd3") == 1  # lsl x19, x19, #1

    mode_buf = bytearray(so_bytes)
    assert apply_mode_drops_x10(mode_buf) == 392
    nephthys_row = 0x71D900 + 694 * 140
    assert struct.unpack_from("<i", mode_buf, nephthys_row + 8)[0] == 1000


def test_battle_arena_fix_sites(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_battle_arena_fix(buf) == 11

    for site, _orig, repl in ARENA_WEEK_STATE_SITES:
        assert bytes(buf[site - 0x4000:site - 0x4000 + len(repl)]) == repl

    slot_off = ARENA_EMPTY_SLOT_SITE - 0x4000
    assert bytes(buf[slot_off:slot_off + len(ARENA_EMPTY_SLOT_REPLACEMENT)]) == ARENA_EMPTY_SLOT_REPLACEMENT

    for site, repl in (
        (ARENA_DEFENCE_SIZE_SITE, ARENA_DEFENCE_SIZE_REPLACEMENT),
        (ARENA_DEFENCE_COUNT_SITE, ARENA_DEFENCE_COUNT_REPLACEMENT),
        (ARENA_SCHEMA_GATE_SITE, ARENA_SCHEMA_GATE_REPLACEMENT),
    ):
        off = site - 0x4000
        assert bytes(buf[off:off + len(repl)]) == repl

    for hook, cave, blob in (
        (
            PVP_TEAM_COMPACT_ATTACK_HOOK,
            PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR,
            PVP_TEAM_COMPACT_ATTACK_CAVE_BYTES,
        ),
        (
            PVP_TEAM_COMPACT_DEFENSE_HOOK,
            PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR,
            PVP_TEAM_COMPACT_DEFENSE_CAVE_BYTES,
        ),
    ):
        hook_off = hook - 0x4000
        cave_off = cave - 0x4000
        assert bytes(buf[hook_off:hook_off + 4]) == encode_arm64_branch(hook, cave)
        assert bytes(buf[cave_off:cave_off + len(blob)]) == blob

    assert apply_battle_arena_fix(buf) == 0


def test_guild_raid_self_mercenary_site(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_guild_raid_self_mercenary(buf) == 4
    merc_off = GUILD_RAID_MERCENARY_SITE - 0x4000
    assert bytes(buf[merc_off:merc_off + 4]) == encode_arm64_branch(
        GUILD_RAID_MERCENARY_SITE, GUILD_RAID_MERCENARY_CAVE_VADDR
    )
    cave_off = GUILD_RAID_MERCENARY_CAVE_VADDR - 0x4000
    assert (
        bytes(buf[cave_off:cave_off + len(GUILD_RAID_MERCENARY_CAVE_BYTES)])
        == GUILD_RAID_MERCENARY_CAVE_BYTES
    )


def test_select_all_rejects_unknown_stub_without_mutating_cave(reference_buffers):
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    stub_offset = SELECT_ALL_STUB_VADDR - 0x4000
    buf[stub_offset] ^= 0xFF
    with pytest.raises(ValueError, match="grade stub"):
        apply_select_all_4_5(buf)
    cave_offset = SELECT_ALL_CLIENT_CAVE - 0x4000
    assert (
        hashlib.sha256(
            buf[cave_offset:cave_offset + SELECT_ALL_CAVE_RESERVED_SIZE]
        ).hexdigest()
        == SELECT_ALL_CAVE_ORIGINAL_SHA256
    )


@pytest.mark.parametrize(
    "attr",
    [
        "GUILD_RAID_MERCENARY_CAVE_VADDR",
        "RUNE_ROLL_CAVE_VA",
        "SHIM_VADDR",
        "BATTLE_ARENA_SAVE_CAVE_VADDR",
        "GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR",
    ],
)
def test_validate_cave_layout_enforces_all_caves_and_slot_profiles(
    monkeypatch: pytest.MonkeyPatch, attr: str
):
    import core.core_patches as cp

    validate_cave_layout()
    monkeypatch.setattr(cp, attr, cp.ITEM_CAVE_VADDR)
    with pytest.raises(RuntimeError, match="Code cave overlap"):
        validate_cave_layout()


@pytest.mark.parametrize(
    ("attr", "bad_offset"),
    [
        ("RECYCLE_GRADE_OFFSET", 0xF68),       # collides with RUNE_ROLL_COUNTER_OFFSET
        ("RECYCLE_REWARD_FLAG_OFFSET", 0xF64), # inside libunwind::DwarfFDECache::_bufferEnd
    ],
)
def test_validate_cave_layout_detects_scratch_ram_overlap(
    monkeypatch: pytest.MonkeyPatch, attr: str, bad_offset: int
):
    import core.core_patches as cp

    monkeypatch.setattr(cp, attr, bad_offset)
    with pytest.raises(RuntimeError, match="Scratch RAM overlap"):
        validate_cave_layout()
