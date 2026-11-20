#!/usr/bin/env python3
"""FWT Reborn - Patch Verification and Inspection Engine.

Analyzes an APK or extracted binary buffers to detect and report exactly which
custom features, rates, localization gates, network modes, alignment, and
signatures are present.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import struct
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

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
    BATTLE_ARENA_SAVE_RVA,
    CAMPAIGN_HOOKS,
    CAMPAIGN_PREFIXES,
    CAMPAIGN_XP_FLAG,
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
    ENGLISH_SO_GATES,
    EQUIPMENT_LOCK_FIX_NOP,
    EQUIPMENT_LOCK_FIX_ORIGINAL,
    EQUIPMENT_LOCK_FIX_SITE,
    EQUIPMENT_UPGRADE_10_FAIL_ORIGINAL,
    EQUIPMENT_UPGRADE_10_FAIL_REPLACEMENT,
    EQUIPMENT_UPGRADE_10_FAIL_SITE,
    EVENT_COIN_CAVE_SIZE,
    EVENT_COIN_CAVE_VADDR,
    EVENT_COIN_HOOK_VADDR,
    EVENT_COIN_OLD_CAVE_VADDR,
    EVENT_COIN_OLD_HOOK_ORIGINAL,
    EVENT_COIN_OLD_HOOK_VADDR,
    EVENT_COIN_RETURN_VADDR,
    EVENT_GENE_ITEM_CATEGORY,
    EVENT_LIMIT_COUNT_CAVE_SIZE,
    EVENT_LIMIT_COUNT_CAVE_VADDR,
    EVENT_LIMIT_COUNT_HOOK_SITE,
    EVENT_LIMIT_PERIOD_SITE,
    EVENT_LIMIT_PERIOD_TARGET,
    EVENT_LIMIT_TYPE_PATTERN,
    EVENT_SHOP_TYPE_4_PATTERN,
    EXPECTED_EVENT_GENE_ROWS,
    EXPECTED_EVENT_LIMIT_ROWS,
    EXPECTED_PATCH_COUNTS,
    EXPEDITION_CALL_SITES,
    EXPEDITION_CAVE_VADDR,
    EXPEDITION_TABLE,
    GEM_LEVEL6_REPLACEMENT_CHAR,
    GEM_LEVEL6_STRINGS,
    GEM_MINING_CAVE_BYTES,
    GEM_MINING_CAVE_VADDR,
    GEM_MINING_COUNT_SITE,
    GEM_MINING_TYPES_CAVE_BYTES,
    GEM_MINING_TYPES_CAVE_VADDR,
    GEM_MINING_TYPES_HOOK,
    GEM_UPGRADE_GOLD_REPLACEMENT,
    GEM_UPGRADE_GOLD_SITE,
    GENE_OTHER_WEIGHT_COLS,
    GENE_PREFIXES,
    GOLD_CYLINDER_X10_CAVE_SIZE,
    GOLD_CYLINDER_X10_CAVE_VADDR,
    GOLD_CYLINDER_X10_ORIGINAL,
    GOLD_CYLINDER_X10_RETURN_VADDR,
    GOLD_CYLINDER_X10_SITE,
    GUILD_RAID_CLIENT_CAVE,
    GUILD_RAID_CLIENT_CAVE_BYTES,
    GUILD_RAID_DAILY_REWARD_TABLE,
    GUILD_RAID_DAILY_REWARDS,
    GUILD_RAID_INSTALL_SITE,
    GUILD_RAID_MERCENARY_CAVE_BYTES,
    GUILD_RAID_MERCENARY_CAVE_VADDR,
    GUILD_RAID_MERCENARY_CLIENT_CAVE_BYTES,
    GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR,
    GUILD_RAID_MERCENARY_CLIENT_HOOK,
    GUILD_RAID_MERCENARY_SITE,
    GUILD_RAID_REWARD_AMOUNT_OFFSETS,
    GUILD_RAID_REWARD_ENTRY_SIZE,
    GUILD_RAID_SENTINEL_CAVE,
    GUILD_RAID_SENTINEL_CAVE_BYTES,
    GUILD_RAID_START_SITE,
    GUILD_RAID_WEEKLY_REWARD_TABLE,
    GUILD_RAID_WEEKLY_REWARDS,
    HERO_EXP_CAP_CAVE_BYTES,
    HERO_EXP_CAP_CAVE_VADDR,
    HERO_EXP_CAP_EXPEDITION_SITE,
    HERO_EXP_CAP_EXPEDITION_TRAMPOLINE,
    HERO_EXP_CAP_INFINITY_SITE,
    HERO_EXP_CAP_INFINITY_TRAMPOLINE,
    HERO_EXP_CAP_STAGE_SITE,
    HERO_EXP_CAP_STAGE_TRAMPOLINE,
    HERO_LEVEL_MAX_FLOOR_ORIGINAL,
    HERO_LEVEL_MAX_FLOOR_PATCHED,
    HERO_LEVEL_MAX_FLOOR_SITE,
    HONOR_COIN_COUNT_REPLACEMENT,
    HONOR_COIN_COUNT_SITE,
    HONOR_POINTS_CAVE_BYTES,
    HONOR_POINTS_CAVE_VADDR,
    HONOR_POINTS_DELTA_SITE,
    INFINITE_TRANSCEND_SUCCESS_PATCHED,
    INFINITE_TRANSCEND_SUCCESS_TABLE,
    LIMIT_BREAK_COST_FIXED_SHA256,
    LIMIT_BREAK_COST_TENTH_SHA256,
    LIMIT_BREAK_FIXED_GOLD,
    LIMIT_BREAK_FIXED_MATERIAL,
    LIMIT_BREAK_GOLD_ROW_SIZE,
    LIMIT_BREAK_GOLD_ROWS,
    LIMIT_BREAK_GOLD_TABLE,
    LOOPBACK_CONNECT_STUB,
    LOST_ISLAND_STAGE_PREFIXES,
    MANA_CYLINDER_X10_SITES,
    NEPHTHYS_STAGE_PREFIXES,
    NO_WIN_BOX_ORIGINAL,
    NO_WIN_BOX_PATCHED,
    NO_WIN_BOX_SITE,
    PATCH_FLAG_SIZE,
    PATCH_FLAG_VADDR,
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
    RECYCLE_SIX_STAR_ENTRY_SIZE,
    RECYCLE_SIX_STAR_EXPECTED_ROWS,
    RECYCLE_SIX_STAR_GROUP_SLOT,
    RECYCLE_SIX_STAR_GROUPS,
    RECYCLE_SIX_STAR_ROW_COUNT,
    RECYCLE_SIX_STAR_TABLE,
    REFERENCE_DEX_SHA256,
    REFERENCE_SO_SHA256,
    RIDDLE_ROW_COUNT,
    RIDDLE_ROW_SIZE,
    RIDDLE_TABLE_OFFSET,
    RUNE_BOX_TYPE_GROUP,
    RUNE_BOX_TYPE_REWRITES,
    RUNE_DECIDED_COST_PATCHED,
    RUNE_DECIDED_COST_SITE,
    RUNE_OPTION_MASTERY_ORIGINAL,
    RUNE_OPTION_MASTERY_REPLACEMENT,
    RUNE_OPTION_MASTERY_SITE,
    RUNE_OPTION_ROW_COUNT,
    RUNE_OPTION_ROW_SIZE,
    RUNE_OPTION_TABLE_PERCENT_PINK_SHA256,
    RUNE_OPTION_TABLE_PERCENT_SHA256,
    RUNE_OPTION_TABLE_PINK_SHA256,
    RUNE_OPTION_TABLE_VADDR,
    RUNE_QUALITY_BONUS_ORIGINAL,
    RUNE_QUALITY_BONUS_REGISTER,
    RUNE_QUALITY_BONUS_SITE,
    RUNE_REWARD_TYPE_STRIDE,
    RUNE_REWARD_TYPE_TABLE,
    RUNE_ROLL_CAVE_LEN,
    RUNE_ROLL_CAVE_SHA256,
    RUNE_ROLL_CAVE_VA,
    RUNE_ROLL_DETERMINISTIC_SITES,
    RUNE_ROLL_SITES,
    RUNE_ROLL_TEXT_VA,
    RUNE_TYPE_CAVE_OFFSET,
    RUNE_TYPE_LOOP_ENTER,
    RUNE_UPGRADE_CAVE_BYTES,
    RUNE_UPGRADE_CAVE_VADDR,
    RUNE_UPGRADE_INSTALL_ORIGINAL,
    RUNE_UPGRADE_INSTALL_SITE,
    RUNE_UPGRADE_ROW_COUNT,
    RUNE_UPGRADE_ROW_SIZE,
    RUNE_UPGRADE_TABLE_PATCHED_SHA256,
    RUNE_UPGRADE_TABLE_VADDR,
    SHIM_MAGIC,
    SHIM_VADDR,
    SHIP_PART_COST_FIELD_SIZE,
    SHIP_PART_COST_TABLES,
    SINGLE_BLACK_HAMMER_REPLACEMENT,
    SINGLE_BLACK_HAMMER_SITE,
    SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES,
    SINGLE_GEM_FANG_ALL_HOLES_CAVE_SIZE,
    SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR,
    SINGLE_GEM_FANG_ALL_HOLES_SITE,
    SINGLE_GEM_FANG_CAVE_BYTES,
    SINGLE_GEM_FANG_CAVE_SIZE,
    SINGLE_GEM_FANG_CAVE_VADDR,
    SINGLE_GEM_FANG_INSTALL_SITE,
    SINGLE_GEM_FANG_REPLACEMENT,
    SINGLE_GEM_FANG_SITE,
    SINGLE_MOD_STONE_CAVE_BYTES,
    SINGLE_MOD_STONE_CAVE_SIZE,
    SINGLE_MOD_STONE_CAVE_VADDR,
    SINGLE_MOD_STONE_INSTALL_SITE,
    SINGLE_MOD_STONE_SERVER_REPLACEMENT,
    SINGLE_MOD_STONE_SERVER_SITE,
    SOULGEAR_ENCHANT_ORIGINAL,
    SOULGEAR_ENCHANT_REGISTER,
    SOULGEAR_ENCHANT_SITE,
    STAGE_EQUIP_WEIGHT,
    STAGE_ROW_COUNT,
    STAGE_ROW_SIZE,
    STAGE_TABLE_OFFSET,
    STAMINA_HALF_REPLACEMENT,
    STAMINA_HALF_SITE,
    STAMINA_POTION_1000_REPLACEMENT,
    STAMINA_POTION_1000_SITE,
    SUMMON_POOLS,
    SUMMON_TARGETS,
    SUMMON_TARGETS_50_30_20,
    SWEEP_GENE_BOX_PATCHED,
    SWEEP_GENE_BOX_SITE,
    WORLDBOSS_CYCLE_REWARD_PATCHED_SHA256,
    WORLDBOSS_CYCLE_REWARD_TARGET_COUNT,
    WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES,
    WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
    WORLDBOSS_DAILY_KRAKEN_SITE,
    WORLDBOSS_EVENT_REWARD_ORIGINAL,
    WORLDBOSS_EVENT_REWARD_SITE,
    WORLDBOSS_FULL_SHIP_REPAIR_SITES,
    PatchOptions,
    _build_dimension_cave,
    _build_dimension_gene_cave,
    _event_shop_count_cave_bytes,
    _stage_prefix,
    encode_arm64_branch,
    find_dev_build_marker,
    randoption_top_quality_state,
    recycle_six_star_assignment,
    rune_roll_cave_blob,
    seg_offset,
    worldboss_cycle_reward_rows,
)
from core.costume_packages import inspect_costume_packages
from core.dex_smali import read_dex_strings
from core.equipment_tier_upgrades import inspect_equipment_tiers
from core.guild_raid_fire_support import inspect_guild_raid_fire_support
from core.hero_shop_offers import inspect_hero_shop_offers
from core.mythical_shop import inspect_mythical_shop
from core.surprise_transcendence_package import inspect_surprise_transcendence_package

MIN_ELF_ALIGN = 16384
SIGNATURE_V2_ID = 0x7109871A
SIGNATURE_V3_ID = 0xF05368C0
SIGNATURE_V31_ID = 0x1B93AD61

# Original and patched values used for precise reference checks.
_CAMPAIGN_STAGE0_HERO_XP_ORIGINAL = 78
_CAMPAIGN_STAGE0_HERO_XP_PATCHED = 780
_CAMPAIGN_STAGE0_LORD_XP_ORIGINAL = 20
_CAMPAIGN_STAGE0_LORD_XP_PATCHED = 200
_CAMPAIGN_XP_PATCHED_SHA256 = (
    "62767ac2dd6aa99f0a94ba22ef4c40ed25ab851037bb56b2ad7d11784616fcd9"
)
_NEPHTHYS_GOLD_PATCHED_SHA256 = (
    "d5b6143ca170d809f8ae3e39396180d6101944d59cb8c5181c4c1291a3dea0c3"
)
_LOST_ISLAND_GOLD_PATCHED_SHA256 = (
    "22ae48fef6ad96832242ab97d0b187b02d8a2e49bea0b11a5909dc075c07e638"
)
_RIDDLE_PATCHED_SHA256 = (
    "a948559f5aafe435c55f3c12b4615d72fae961728f72a7e3c85305693a3113cc"
)
_EXPEDITION_ROW1_HERO_XP_PATCHED = 13200
_ITEMS_CAVE_TAIL = bytes.fromhex("73fa7fd3861afe17")
# Full Dalvik sequences surrounding the backup scheduler branch and call.
_DEX_BACKUP_ORIGINAL_SIGNATURES = (
    b"\x71\x10\xf0\x00\x00\x00\x0a\x00\x38\x00\x19\x00",
    b"\x62\x09\x6d\x00\x16\x05\x02\x00\x78\x07\xae\x01\x03\x00",
)
_LIMIT_BREAK_FEATURE_SPECS = (
    ("limit_break_cost_tenth", "Limit Break Cost (90% Off)"),
    ("limit_break_cost_fixed", "Limit Break Fixed Cost"),
)


def _decode_movz_imm(
    word: bytes, *, expected_reg: int, wide: bool = False
) -> int | None:
    """Decode ``movz w<reg>|x<reg>, #imm16`` (``hw=0``), or return ``None``."""
    if len(word) != 4:
        return None
    raw = int.from_bytes(word, "little")
    opcode = 0xD2800000 if wide else 0x52800000
    if (raw & 0xFFE0001F) != (opcode | expected_reg):
        return None
    return (raw >> 5) & 0xFFFF


@dataclass
class FeatureReport:
    name: str
    active: bool
    status: str
    details: str = ""
    value: object | None = None


@dataclass
class InspectionReport:
    file_path: str = ""
    file_size_mb: float = 0.0
    is_valid_apk: bool = False
    has_so: bool = False
    has_dex: bool = False
    so_sha256: str = ""
    dex_sha256: str = ""
    is_pristine_reference: bool = False
    is_pristine_dex: bool = False
    features: dict[str, FeatureReport] = field(default_factory=dict)
    alignment_16k: bool = False
    alignment_details: str = ""
    is_signed: bool = False
    signature_details: str = ""
    dex_checksum_valid: bool = False
    dex_checksum_details: str = ""
    cave_overlap: bool = False
    error_message: str = ""
    build_identity: str = "unknown"
    build_options: PatchOptions | None = None


def detect_cave_overlap(so_bytes: bytes | bytearray) -> bool:
    """Returns True if the legacy event-coin cave overlaps the items cave."""
    try:
        from core.core_patches import ELF_SEGMENTS
        from core.elf_mapping import canonicalize_segments

        so_bytes, _ = canonicalize_segments(so_bytes, ELF_SEGMENTS)
        items_tail = bytes(
            so_bytes[
                seg_offset(0xAA6CAC):seg_offset(0xAA6CB4)
            ]
        )
        return items_tail != _ITEMS_CAVE_TAIL and items_tail[:4] == bytes.fromhex("48018052")
    except Exception:
        return False


def verify_dex_checksums(dex_bytes: bytes | bytearray) -> tuple[bool, str]:
    """Validates the SHA-1 signature and Adler32 checksum of a DEX file."""
    if len(dex_bytes) < 0x70 or dex_bytes[:4] != b"dex\n":
        return False, "Invalid DEX header"
    stored_signature = bytes(dex_bytes[12:32])
    calculated_signature = hashlib.sha1(memoryview(dex_bytes)[32:]).digest()
    if stored_signature != calculated_signature:
        return False, "DEX SHA-1 signature mismatch"
    stored_checksum = struct.unpack_from("<I", dex_bytes, 8)[0]
    calculated_checksum = zlib.adler32(memoryview(dex_bytes)[12:]) & 0xFFFFFFFF
    if stored_checksum != calculated_checksum:
        return False, "DEX Adler32 checksum mismatch"
    return True, "DEX SHA-1 and Adler32 checksums are valid"


def _feature(
    reports: dict[str, FeatureReport],
    key: str,
    name: str,
    active: bool,
    status: str,
    details: str = "",
    value: object | None = None,
) -> None:
    reports[key] = FeatureReport(name=name, active=active, status=status, details=details, value=value)


def inspect_native_so(so_bytes: bytes | bytearray) -> dict[str, FeatureReport]:
    """Inspects native SO byte buffer and reports status of all patch features."""
    from core.core_patches import ELF_SEGMENTS
    from core.elf_mapping import canonicalize_segments

    raw_so = bytes(so_bytes)
    so_bytes, _ = canonicalize_segments(so_bytes, ELF_SEGMENTS)
    reports: dict[str, FeatureReport] = {}

    # 1. Summon Rates Check (70/20/10 or 50/30/20; 0% 1★-3★)
    try:
        pool_totals: list[tuple[str, Counter[int]]] = []
        for name, start, count, expected in SUMMON_POOLS:
            totals: Counter[int] = Counter()
            for index in range(count):
                offset = start + index * 40
                weight, category, _rotation = struct.unpack_from("<iii", so_bytes, offset)
                special = so_bytes[offset + 12]
                if category not in expected or weight < 0:
                    raise ValueError(f"invalid {name} pool row {index}")
                if special != (1 if category == 5 else 0):
                    raise ValueError(f"invalid {name} pool special flag at row {index}")
                totals[category] += weight
            pool_totals.append((name, totals))

        def matches_profile(profile: dict[int, int]) -> bool:
            if not pool_totals:
                return False
            return all(
                all(totals.get(category, 0) == target for category, target in profile.items())
                and all(totals.get(category, 0) == 0 for category in (1, 2))
                for _name, totals in pool_totals
            )

        bonus = dict(pool_totals[0][1])
        details = (
            f"4★={bonus.get(3, 0):,}, 5★={bonus.get(4, 0):,}, "
            f"6★={bonus.get(5, 0):,}"
        )
        classic = matches_profile(SUMMON_TARGETS)
        alternate = matches_profile(SUMMON_TARGETS_50_30_20)
        _feature(
            reports,
            "summon_rates",
            "Equipment Summon Rates (70/20/10)",
            classic,
            "Custom (70% 4★, 20% 5★, 10% 6★)" if classic else "Original / Inactive",
            details,
        )
        _feature(
            reports,
            "summon_rates_50_30_20",
            "Equipment Summon Rates (50/30/20)",
            alternate,
            "Custom (50% 4★, 30% 5★, 20% 6★)" if alternate else "Original / Inactive",
            details,
        )
    except Exception as exc:
        _feature(
            reports,
            "summon_rates",
            "Equipment Summon Rates (70/20/10)",
            False,
            "Unknown",
            str(exc),
        )
        _feature(
            reports,
            "summon_rates_50_30_20",
            "Equipment Summon Rates (50/30/20)",
            False,
            "Unknown",
            str(exc),
        )

    # 2. Expedition Bonus Check (all 5 call sites + table row)
    try:
        patched_calls = 0
        for address in EXPEDITION_CALL_SITES:
            offset = seg_offset(address)
            current = bytes(so_bytes[offset:offset + 4])
            expected_bl = encode_arm64_branch(address, EXPEDITION_CAVE_VADDR, link=True)
            if current == expected_bl:
                patched_calls += 1
        row1 = struct.unpack_from(
            "<6i", so_bytes, EXPEDITION_TABLE
        )  # row_id, region, duration, gold, hero_xp, lord_xp
        table_patched = row1[4] == _EXPEDITION_ROW1_HERO_XP_PATCHED
        active = patched_calls == len(EXPEDITION_CALL_SITES) and table_patched
        _feature(
            reports,
            "expedition_bonus",
            "10x Expedition Rewards",
            active,
            "Active (10x)" if active else "Original / Partial",
            f"{patched_calls}/{len(EXPEDITION_CALL_SITES)} call sites; row1 hero XP={row1[4]:,}",
        )
    except Exception as exc:
        _feature(
            reports, "expedition_bonus", "10x Expedition Rewards", False, "Unknown", str(exc)
        )

    # 3. Campaign Gene Priority Check
    try:
        changed = 0
        for index in range(STAGE_ROW_COUNT):
            at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
            row = struct.unpack_from("<35i", so_bytes, at)
            stage = f"{row[0]:06x}"
            gene_weight, gene_id = row[22], row[23]
            if not stage.startswith(GENE_PREFIXES) or gene_weight <= 0 or gene_id <= 0:
                continue
            highest_other = max(0, *(row[pos] for pos in GENE_OTHER_WEIGHT_COLS))
            if gene_weight > highest_other:
                changed += 1
        expected_gene_rows = EXPECTED_PATCH_COUNTS["gene_priority"]
        active = changed == expected_gene_rows
        _feature(
            reports,
            "gene_priority",
            "Hero Gene Drop Priority",
            active,
            "Active (Prioritized)" if active else "Original / Partial",
            f"{changed}/{expected_gene_rows} stage(s) with gene weight above other drops",
        )
    except Exception as exc:
        _feature(
            reports, "gene_priority", "Hero Gene Drop Priority", False, "Unknown", str(exc)
        )

    # 3b. Equipment-free stage drops
    try:
        equipment_stages = 0
        for index in range(STAGE_ROW_COUNT):
            at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
            row = struct.unpack_from("<35i", so_bytes, at)
            if row[STAGE_EQUIP_WEIGHT] > 0:
                equipment_stages += 1
        active = equipment_stages == 0
        _feature(
            reports,
            "no_equip_drops",
            "Remove Equipment Drops",
            active,
            "Active (No Equipment)" if active else "Original / Partial",
            f"{equipment_stages} stage(s) still have equipment drop weight",
        )
    except Exception as exc:
        _feature(
            reports, "no_equip_drops", "Remove Equipment Drops", False, "Unknown", str(exc)
        )

    # 4. Campaign 10x XP Check (all 381 campaign stage rows + FXP1 flag)
    try:
        campaign_rows: list[tuple[int, int, int]] = []
        for index in range(STAGE_ROW_COUNT):
            at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
            row_stage, row_hero_xp, _gold, row_lord_xp = struct.unpack_from(
                "<4i", so_bytes, at
            )
            if _stage_prefix(row_stage) in CAMPAIGN_PREFIXES:
                campaign_rows.append((row_stage, row_hero_xp, row_lord_xp))
        camp_stage0, camp_hero_xp0, camp_lord_xp0 = campaign_rows[0]
        camp_digest = hashlib.sha256(repr(campaign_rows).encode("ascii")).hexdigest()
        flag_base = seg_offset(PATCH_FLAG_VADDR)
        flag_slot, flag_magic = CAMPAIGN_XP_FLAG
        flag_off = flag_base + flag_slot
        has_flag = (
            len(so_bytes) >= flag_base + PATCH_FLAG_SIZE
            and bytes(so_bytes[flag_off : flag_off + len(flag_magic)]) == flag_magic
        )
        active = (
            camp_hero_xp0 == _CAMPAIGN_STAGE0_HERO_XP_PATCHED
            and camp_lord_xp0 == _CAMPAIGN_STAGE0_LORD_XP_PATCHED
            and len(campaign_rows) == EXPECTED_PATCH_COUNTS["campaign_xp"]
            and camp_digest == _CAMPAIGN_XP_PATCHED_SHA256
            and has_flag
        )
        _feature(
            reports,
            "campaign_xp",
            "10x Campaign XP",
            active,
            "Active (10x XP)" if active else "Original / Partial",
            f"Stage {camp_stage0}: Hero XP={camp_hero_xp0}, Lord XP={camp_lord_xp0}; "
            f"{len(campaign_rows)}/{EXPECTED_PATCH_COUNTS['campaign_xp']} stages "
            f"(sha {camp_digest[:12]}, flag={'set' if has_flag else 'unset'}; "
            f"original {_CAMPAIGN_STAGE0_HERO_XP_ORIGINAL}/{_CAMPAIGN_STAGE0_LORD_XP_ORIGINAL})",
        )
    except Exception as exc:
        _feature(reports, "campaign_xp", "10x Campaign XP", False, "Unknown", str(exc))

    # 5. Campaign 10x Gold & Drops Check (all hooks + cave blobs must match)
    try:
        matching = 0
        for hook_addr, expected_bytes in CAMPAIGN_HOOKS.items():
            offset = seg_offset(hook_addr)
            if bytes(so_bytes[offset:offset + len(expected_bytes)]) == expected_bytes:
                matching += 1
        active = matching == len(CAMPAIGN_HOOKS)
        _feature(
            reports,
            "campaign_gold",
            "10x Campaign Gold & Drops",
            active,
            "Active (10x Multiplier)" if active else "Original / Partial",
            f"{matching}/{len(CAMPAIGN_HOOKS)} hook/cave regions match",
        )
    except Exception as exc:
        _feature(
            reports, "campaign_gold", "10x Campaign Gold & Drops", False, "Unknown", str(exc)
        )

    # 6. English Localization Gates Check (both SO gates)
    try:
        matching = 0
        for src, dst in ENGLISH_SO_GATES:
            offset = seg_offset(src)
            if bytes(so_bytes[offset:offset + 4]) == encode_arm64_branch(src, dst):
                matching += 1
        active = matching == len(ENGLISH_SO_GATES)
        _feature(
            reports,
            "english_localization",
            "English Localization",
            active,
            "Active (Unlocked)" if active else "Original / Partial",
            f"{matching}/{len(ENGLISH_SO_GATES)} Korean localization gates bypassed",
        )
    except Exception as exc:
        _feature(
            reports, "english_localization", "English Localization", False, "Unknown", str(exc)
        )

    # 7. Event Shop 90% Discount Check
    try:
        pat = re.compile(
            rb'\{(?=[^{}]*?"shop_content":2)'
            rb'(?=[^{}]*?"price_count":(\s*\d+))[^{}]*\}'
        )
        matches = list(pat.finditer(so_bytes))
        sample_price = None
        sample_match = re.search(
            rb'\{"idx":35951224,[^{}]*?"shop_content":2'
            rb'[^{}]*?"price_count":(\s*\d+)[^{}]*?\}',
            so_bytes,
        )
        if sample_match is not None:
            sample_price = int(sample_match.group(1))
        active = len(matches) == EXPECTED_PATCH_COUNTS["event_discount"] and sample_price == 5
        if sample_price is None:
            details = f"{len(matches)} shop item(s) matched; sample item not found"
        else:
            details = f"{len(matches)} shop item(s) matched; sample item price={sample_price}"
        _feature(
            reports,
            "event_discount",
            "90% Event Shop Discount",
            active,
            "Active (90% Off)" if active else "Original / Partial",
            details,
        )
    except Exception as exc:
        _feature(
            reports, "event_discount", "90% Event Shop Discount", False, "Unknown", str(exc)
        )

    # 7aa. Recycling 6★ Equipment Reward Check
    try:
        groups: dict[int, list[tuple[int, int, int]]] = {
            group: [] for group in RECYCLE_SIX_STAR_GROUPS
        }
        for index in range(RECYCLE_SIX_STAR_ROW_COUNT):
            offset = RECYCLE_SIX_STAR_TABLE + index * RECYCLE_SIX_STAR_ENTRY_SIZE
            group, weight, code = struct.unpack_from("<iii", so_bytes, offset)
            if group in groups:
                groups[group].append((offset, weight, code))
        rows_total = sum(len(entries) for entries in groups.values())
        rows_patched = 0
        for group, entries in groups.items():
            targets = recycle_six_star_assignment(
                [(weight, code) for _offset, weight, code in entries],
                RECYCLE_SIX_STAR_GROUP_SLOT[group],
            )
            rows_patched += sum(
                1
                for (_offset, weight, code), target in zip(
                    entries, targets, strict=True
                )
                if (weight, code) == target
            )
        active = (
            rows_total == RECYCLE_SIX_STAR_EXPECTED_ROWS
            and rows_patched == rows_total
        )
        _feature(
            reports,
            "recycle_six_star",
            "Recycling Grants 6★ Equipment",
            active,
            "Active (always 6-star)" if active else "Original / Partial",
            f"{rows_patched}/{rows_total} reward rows use the 6-star pool",
        )
    except Exception as exc:
        _feature(
            reports,
            "recycle_six_star",
            "Recycling Grants 6★ Equipment",
            False,
            "Unknown",
            str(exc),
        )

    try:
        active = inspect_mythical_shop(so_bytes)
        _feature(reports, "mythical_stone_shop", "Mythical Stone Event Shop", active,
                 "Active" if active else "Original / Partial",
                 "Both offers and their daily limits verified" if active else "Offers not fully patched")
    except Exception as exc:
        _feature(reports, "mythical_stone_shop", "Mythical Stone Event Shop", False, "Unknown", str(exc))

    try:
        active = inspect_hero_shop_offers(so_bytes)
        _feature(reports, "hero_shop_offers", "Evan and Alex Shop Offers", active,
                 "Active" if active else "Original / Partial",
                 "Hero and diamond offers verified" if active else "Offers not fully patched")
    except Exception as exc:
        _feature(reports, "hero_shop_offers", "Evan and Alex Shop Offers", False, "Unknown", str(exc))

    active = inspect_surprise_transcendence_package(so_bytes, seg_offset)
    _feature(
        reports, "surprise_transcendence_package", "Surprise Transcendence Package 2", active,
        "Active (500 diamonds, 10 of each ticket)" if active else "Original / Partial",
        "Offer 75103 and both isolated ticket components",
    )

    try:
        from core.alex_awakening import inspect_alex_awakening_native

        active = inspect_alex_awakening_native(raw_so)
        _feature(reports, "alex_awakening", "Alex Awakening: Destiny Lance", active,
                 "Active" if active else "Original / Partial",
                 "Native and client hooks verified" if active else "Hooks not fully patched")
    except Exception as exc:
        _feature(reports, "alex_awakening", "Alex Awakening: Destiny Lance", False, "Unknown", str(exc))

    try:
        active = inspect_costume_packages(so_bytes, seg_offset)
        _feature(reports, "costume_packages_all", "Complete Costume Packages", active,
                 "Active" if active else "Original / Partial",
                 "Reward and Claim All hooks and daily limits verified" if active
                 else "Costume package patch not fully present")
    except Exception as exc:
        _feature(reports, "costume_packages_all", "Complete Costume Packages", False, "Unknown", str(exc))

    # 7b. Event Shop Daily Gene Limit Check
    try:
        patched = 0
        seen_rows: set[int] = set()
        cursor = 0
        while True:
            marker = so_bytes.find(EVENT_GENE_ITEM_CATEGORY, cursor)
            if marker < 0:
                break
            row_start = so_bytes.rfind(b"{", 0, marker)
            row_end = so_bytes.find(b"}", marker)
            if row_start < 0 or row_end < 0:
                raise ValueError("malformed Event Shop row")
            if row_start not in seen_rows:
                seen_rows.add(row_start)
                row_bytes = so_bytes[row_start:row_end + 1]
                if (
                    b'"limit_type":255,"limit_max":9' in row_bytes
                    or b'"limit_max":999' in row_bytes
                ):
                    patched += 1
            cursor = marker + len(EVENT_GENE_ITEM_CATEGORY)
        active = patched == EXPECTED_EVENT_GENE_ROWS
        _feature(
            reports,
            "event_gene_unlimited",
            "Unlimited Event Shop Genes",
            active,
            "Active (Unlimited)" if active else "Original / Partial",
            f"{patched}/{EXPECTED_EVENT_GENE_ROWS} gene rows unlocked",
        )
    except Exception as exc:
        _feature(
            reports,
            "event_gene_unlimited",
            "Unlimited Event Shop Genes",
            False,
            "Unknown",
            str(exc),
        )

    # 7c. Event Shop Daily Limits Check
    try:
        lifely_remaining = len(EVENT_LIMIT_TYPE_PATTERN.findall(so_bytes))
        honor_remaining = len(EVENT_SHOP_TYPE_4_PATTERN.findall(so_bytes))
        remaining = lifely_remaining + honor_remaining
        total_limit_rows = len(re.findall(rb'"limit_type":', so_bytes))
        period_off = seg_offset(EVENT_LIMIT_PERIOD_SITE)
        period_patched = (
            bytes(so_bytes[period_off : period_off + 4])
            == encode_arm64_branch(EVENT_LIMIT_PERIOD_SITE, EVENT_LIMIT_PERIOD_TARGET)
        )
        hook_off = seg_offset(EVENT_LIMIT_COUNT_HOOK_SITE)
        expected_hook = (
            encode_arm64_branch(
                EVENT_LIMIT_COUNT_HOOK_SITE, EVENT_LIMIT_COUNT_CAVE_VADDR
            )
            + struct.pack("<I", 0xD503201F)
        )
        hook_patched = (
            bytes(so_bytes[hook_off : hook_off + len(expected_hook)]) == expected_hook
        )
        cave_off = seg_offset(EVENT_LIMIT_COUNT_CAVE_VADDR)
        cave_patched = (
            bytes(so_bytes[cave_off : cave_off + EVENT_LIMIT_COUNT_CAVE_SIZE])
            == _event_shop_count_cave_bytes()
        )
        # Zero remaining rows is not enough: an unrelated/truncated SO would
        # pass vacuously.  Require the catalog population and all native hooks.
        active = (
            remaining == 0
            and total_limit_rows >= EXPECTED_EVENT_LIMIT_ROWS
            and period_patched
            and hook_patched
            and cave_patched
        )
        _feature(
            reports,
            "event_limits_daily",
            "Daily Event Shop Limits",
            active,
            "Active (daily resets)" if active else "Original / Partial",
            (
                f"{lifely_remaining} event-limited row(s) still use limit_type=3; "
                f"{honor_remaining} Event Shop row(s) still use limit_type=4; "
                f"{total_limit_rows}/{EXPECTED_EVENT_LIMIT_ROWS} limit rows present; "
                f"period={'patched' if period_patched else 'original'}, "
                f"count_hook={'patched' if hook_patched else 'original'}, "
                f"count_cave={'patched' if cave_patched else 'original'}"
            ),
        )
    except Exception as exc:
        _feature(
            reports,
            "event_limits_daily",
            "Daily Event Shop Limits",
            False,
            "Unknown",
            str(exc),
        )

    # 8c. Energy Flask x10 Stamina Check
    try:
        offset = seg_offset(ENERGY_FLASK_STAMINA_SITE)
        current = bytes(
            so_bytes[offset:offset + len(ENERGY_FLASK_STAMINA_REPLACEMENT)]
        )
        active = current == ENERGY_FLASK_STAMINA_REPLACEMENT
        _feature(
            reports,
            "energy_flask_x10",
            "Energy Flask x10 Stamina",
            active,
            "Active (1000 stamina)" if active else "Original (100 stamina)",
            (
                f"site 0x{ENERGY_FLASK_STAMINA_SITE:x}: "
                f"{current.hex()} "
                f"(original {ENERGY_FLASK_STAMINA_ORIGINAL.hex()})"
            ),
        )
    except Exception as exc:
        _feature(
            reports,
            "energy_flask_x10",
            "Energy Flask x10 Stamina",
            False,
            "Unknown",
            str(exc),
        )

    # 8a. Equipment option rolls keep the pool's top quality
    try:
        pending, pools = randoption_top_quality_state(so_bytes)
        active = pools > 0 and not pending
        _feature(
            reports,
            "option_max_attributes",
            "Option Max Quality Rolls",
            active,
            (
                "Active (every pool rolls top quality)"
                if active
                else ("Original (mixed quality values)" if pools else "Unknown")
            ),
            f"{pools} option pool(s); {len(pending)} row(s) below top quality weighted",
        )
    except Exception as exc:
        _feature(
            reports,
            "option_max_attributes",
            "Option Max Quality Rolls",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-bis. Rune option quality
    try:
        offset = seg_offset(RUNE_OPTION_MASTERY_SITE)
        current = bytes(so_bytes[offset:offset + len(RUNE_OPTION_MASTERY_REPLACEMENT)])
        table_start = seg_offset(RUNE_OPTION_TABLE_VADDR)
        table_end = table_start + RUNE_OPTION_ROW_COUNT * RUNE_OPTION_ROW_SIZE
        table_digest = hashlib.sha256(bytes(so_bytes[table_start:table_end])).hexdigest()
        pink_table = table_digest in (
            RUNE_OPTION_TABLE_PINK_SHA256,
            RUNE_OPTION_TABLE_PERCENT_PINK_SHA256,
        )
        instruction_ok = current == RUNE_OPTION_MASTERY_REPLACEMENT
        active = instruction_ok and pink_table
        _feature(
            reports,
            "rune_option_quality",
            "Rune Option Quality",
            active,
            "Active (mastery 15, top-quality weights)"
            if active
            else (
                "Original (player mastery)"
                if not instruction_ok and not pink_table
                else "Unknown / partial (instruction or table not patched)"
            ),
            f"site 0x{RUNE_OPTION_MASTERY_SITE:x}: {current.hex()} "
            f"(original {RUNE_OPTION_MASTERY_ORIGINAL.hex()}); table sha256 {table_digest}",
        )
    except Exception as exc:
        _feature(
            reports,
            "rune_option_quality",
            "Rune Option Quality",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-septies. Hero limit break (Awake) costs a tenth
    try:
        cost_offset = seg_offset(LIMIT_BREAK_GOLD_TABLE)
        cost_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
        cost_digest = hashlib.sha256(
            bytes(so_bytes[cost_offset:cost_offset + cost_size])
        ).hexdigest()
        cost_active = cost_digest == LIMIT_BREAK_COST_TENTH_SHA256
        _feature(
            reports,
            "limit_break_cost_tenth",
            "Limit Break Cost (90% Off)",
            cost_active,
            (
                f"Active (-90% gold and materials, {LIMIT_BREAK_GOLD_ROWS} rows)"
                if cost_active
                else "Original (or a different discount is applied)"
            ),
            f"table 0x{LIMIT_BREAK_GOLD_TABLE:x}, sha {cost_digest[:12]}",
        )
    except Exception as exc:
        _feature(
            reports,
            "limit_break_cost_tenth",
            "Limit Break Cost (90% Off)",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-octies. Hero limit break (Awake) charged at a flat price
    try:
        cost_offset = seg_offset(LIMIT_BREAK_GOLD_TABLE)
        cost_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
        cost_digest = hashlib.sha256(
            bytes(so_bytes[cost_offset:cost_offset + cost_size])
        ).hexdigest()
        fixed_active = cost_digest == LIMIT_BREAK_COST_FIXED_SHA256
        _feature(
            reports,
            "limit_break_cost_fixed",
            "Limit Break Fixed Cost",
            fixed_active,
            (
                f"Active (flat {LIMIT_BREAK_FIXED_GOLD:,} gold + "
                f"{LIMIT_BREAK_FIXED_MATERIAL} materials, {LIMIT_BREAK_GOLD_ROWS} rows)"
                if fixed_active
                else "Original (or another discount profile is applied)"
            ),
            f"table 0x{LIMIT_BREAK_GOLD_TABLE:x}, sha {cost_digest[:12]}",
        )
    except Exception as exc:
        _feature(
            reports,
            "limit_break_cost_fixed",
            "Limit Break Fixed Cost",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-rune. +12..+15 upgrades guaranteed and charged a tenth
    try:
        table_offset = seg_offset(RUNE_UPGRADE_TABLE_VADDR)
        table_size = RUNE_UPGRADE_ROW_SIZE * RUNE_UPGRADE_ROW_COUNT
        table_digest = hashlib.sha256(
            bytes(so_bytes[table_offset:table_offset + table_size])
        ).hexdigest()
        decided_offset = seg_offset(RUNE_DECIDED_COST_SITE)
        decided = bytes(so_bytes[decided_offset:decided_offset + len(RUNE_DECIDED_COST_PATCHED)])
        cave_offset = seg_offset(RUNE_UPGRADE_CAVE_VADDR)
        cave = bytes(so_bytes[cave_offset:cave_offset + len(RUNE_UPGRADE_CAVE_BYTES)])
        site_offset = seg_offset(RUNE_UPGRADE_INSTALL_SITE)
        site_word = bytes(so_bytes[site_offset:site_offset + 4])
        hook = site_word not in (RUNE_UPGRADE_INSTALL_ORIGINAL,)
        cave_ok = cave == RUNE_UPGRADE_CAVE_BYTES
        upgrade_active = (
            table_digest == RUNE_UPGRADE_TABLE_PATCHED_SHA256
            and decided == RUNE_DECIDED_COST_PATCHED
            and cave_ok
            and hook
        )
        _feature(
            reports,
            "rune_upgrade_discount",
            "Rune Upgrade +12..+15 (Guaranteed, 90% Off)",
            upgrade_active,
            (
                "Active (+12..+15 always succeed, gold -90%, client price hooked)"
                if upgrade_active
                else "Original (or only part of the rune upgrade patch is applied)"
            ),
            (
                f"table 0x{RUNE_UPGRADE_TABLE_VADDR:x} sha {table_digest[:12]}; "
                f"decided cost {'patched' if decided == RUNE_DECIDED_COST_PATCHED else 'stock'}; "
                f"client hook {'installed' if cave_ok and hook else 'absent'}"
            ),
        )
    except Exception as exc:
        _feature(
            reports,
            "rune_upgrade_discount",
            "Rune Upgrade +12..+15 (Guaranteed, 90% Off)",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-nonies. Win box advertisement off
    try:
        win_offset = seg_offset(NO_WIN_BOX_SITE)
        win_bytes = bytes(so_bytes[win_offset:win_offset + len(NO_WIN_BOX_ORIGINAL)])
        sweep_offset = seg_offset(SWEEP_GENE_BOX_SITE)
        sweep_active = so_bytes[sweep_offset:sweep_offset + len(SWEEP_GENE_BOX_PATCHED)] == SWEEP_GENE_BOX_PATCHED
        active = win_bytes == NO_WIN_BOX_PATCHED and sweep_active
        if active:
            win_state = "Active (battle advertisement and hero-gene sweep boxes off)"
        elif win_bytes == NO_WIN_BOX_PATCHED:
            win_state = "Partial (hero-gene sweep box gate missing)"
        elif win_bytes == NO_WIN_BOX_ORIGINAL:
            win_state = "Original (result payload may advertise an ungranted box)"
        else:
            win_state = f"Unknown bytes {win_bytes.hex()}"
        _feature(
            reports,
            "no_win_box",
            "Hide Phantom Win Boxes",
            active,
            win_state,
            f"battle guard 0x{NO_WIN_BOX_SITE:x}; sweep gate 0x{SWEEP_GENE_BOX_SITE:x}",
        )
    except Exception as exc:
        _feature(reports, "no_win_box", "Hide Phantom Win Boxes", False, "Unknown", str(exc))

    # 8a-decies. Hero EXP cap & un-transcended Limit Break floor
    try:
        floor_off = seg_offset(HERO_LEVEL_MAX_FLOOR_SITE)
        floor_bytes = bytes(so_bytes[floor_off:floor_off + len(HERO_LEVEL_MAX_FLOOR_ORIGINAL)])
        floor_ok = floor_bytes == HERO_LEVEL_MAX_FLOOR_PATCHED
        floor_orig = floor_bytes == HERO_LEVEL_MAX_FLOOR_ORIGINAL

        cave_off = seg_offset(HERO_EXP_CAP_CAVE_VADDR)
        cave_ok = (
            bytes(so_bytes[cave_off:cave_off + len(HERO_EXP_CAP_CAVE_BYTES)])
            == HERO_EXP_CAP_CAVE_BYTES
        )
        hook_specs = (
            (HERO_EXP_CAP_STAGE_SITE, HERO_EXP_CAP_STAGE_TRAMPOLINE),
            (HERO_EXP_CAP_INFINITY_SITE, HERO_EXP_CAP_INFINITY_TRAMPOLINE),
            (HERO_EXP_CAP_EXPEDITION_SITE, HERO_EXP_CAP_EXPEDITION_TRAMPOLINE),
        )
        hooks_ok = all(
            bytes(so_bytes[seg_offset(site):seg_offset(site) + 4])
            == encode_arm64_branch(site, target, link=True)
            for site, target in hook_specs
        )
        active = floor_ok and cave_ok and hooks_ok
        if active:
            exp_cap_state = "Active (battle/expedition EXP clamped; Lv70 LB floor)"
        elif floor_orig and not cave_ok and not hooks_ok:
            exp_cap_state = "Original (un-transcended Lv71 overflow possible)"
        else:
            exp_cap_state = "Partial / Unknown"
        _feature(
            reports,
            "hero_exp_cap",
            "Hero EXP Cap & Limit Break Floor",
            active,
            exp_cap_state,
            f"floor 0x{HERO_LEVEL_MAX_FLOOR_SITE:x}, cave 0x{HERO_EXP_CAP_CAVE_VADDR:x}",
        )
    except Exception as exc:
        _feature(
            reports,
            "hero_exp_cap",
            "Hero EXP Cap & Limit Break Floor",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-octies. Soulgear enchant always succeeds
    try:
        enchant_offset = seg_offset(SOULGEAR_ENCHANT_SITE)
        enchant_word = bytes(so_bytes[enchant_offset:enchant_offset + 4])
        if enchant_word == SOULGEAR_ENCHANT_ORIGINAL:
            enchant_active = False
            enchant_status = "Original (hashed 84.75%..6% roll)"
        else:
            enchant_imm = _decode_movz_imm(
                enchant_word, expected_reg=SOULGEAR_ENCHANT_REGISTER, wide=False
            )
            enchant_active = enchant_imm is not None
            enchant_status = (
                f"Active (w{SOULGEAR_ENCHANT_REGISTER}={enchant_imm})"
                if enchant_imm is not None
                else "Unknown / Invalid instruction"
            )
        _feature(
            reports,
            "soulgear_enchant_always",
            "Soulgear Enchant Always Succeeds",
            enchant_active,
            enchant_status,
            f"site 0x{SOULGEAR_ENCHANT_SITE:x}, original {SOULGEAR_ENCHANT_ORIGINAL.hex()}",
        )
    except Exception as exc:
        _feature(
            reports,
            "soulgear_enchant_always",
            "Soulgear Enchant Always Succeeds",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-quinquies-bis. Equipment option locks hold on the first roll
    try:
        lock_fix_offset = seg_offset(EQUIPMENT_LOCK_FIX_SITE)
        lock_fix_word = bytes(so_bytes[lock_fix_offset:lock_fix_offset + 4])
        lock_fix_active = lock_fix_word == EQUIPMENT_LOCK_FIX_NOP
        _feature(
            reports,
            "equipment_lock_fix",
            "Equipment Option Locks",
            lock_fix_active,
            (
                "Active (the pre-lock re-roll is skipped)"
                if lock_fix_active
                else "Original (locked lines re-roll on the first roll after the lock "
                "list changes)"
            ),
            f"site 0x{EQUIPMENT_LOCK_FIX_SITE:x}, original "
            f"{EQUIPMENT_LOCK_FIX_ORIGINAL.hex()}",
        )
    except Exception as exc:
        _feature(
            reports, "equipment_lock_fix", "Equipment Option Locks", False, "Unknown", str(exc)
        )

    # 8a-quinquies-ter. One Modification Stone per option change
    try:
        server_offset = seg_offset(SINGLE_MOD_STONE_SERVER_SITE)
        server_active = (
            bytes(so_bytes[server_offset:server_offset + 4])
            == SINGLE_MOD_STONE_SERVER_REPLACEMENT
        )
        install_offset = seg_offset(SINGLE_MOD_STONE_INSTALL_SITE)
        install_hook = bytes(so_bytes[install_offset:install_offset + 4]) == (
            encode_arm64_branch(SINGLE_MOD_STONE_INSTALL_SITE, SINGLE_MOD_STONE_CAVE_VADDR)
        )
        cave_offset = seg_offset(SINGLE_MOD_STONE_CAVE_VADDR)
        cave_ok = (
            bytes(so_bytes[cave_offset:cave_offset + SINGLE_MOD_STONE_CAVE_SIZE])
            == SINGLE_MOD_STONE_CAVE_BYTES
        )
        active = server_active and install_hook and cave_ok
        _feature(
            reports,
            "equipment_single_mod_stone",
            "One Modification Stone",
            active,
            "Active (1 stone regardless of locks)" if active else "Original / Partial",
            f"server 0x{SINGLE_MOD_STONE_SERVER_SITE:x}: "
            f"{'patched' if server_active else 'original'}; "
            f"client hook={'ok' if install_hook and cave_ok else 'missing'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "equipment_single_mod_stone",
            "One Modification Stone",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-quinquies-quater. Percent-only equipment options (server table)
    try:
        table_offset = seg_offset(RANDOPTION_SERVER_SITE)
        flat_weighted = 0
        percent_weighted = 0
        for index in range(RANDOPTION_SERVER_ROW_COUNT):
            row_offset = table_offset + index * RANDOPTION_SERVER_ROW_SIZE
            (option_id,) = struct.unpack_from("<I", so_bytes, row_offset)
            weights = struct.unpack_from(
                "<6I",
                so_bytes,
                row_offset + RANDOPTION_SERVER_WEIGHT_OFFSET,
            )
            if option_id // 1000 in RANDOPTION_SERVER_FLAT_GROUPS:
                flat_weighted += sum(1 for weight in weights if weight)
            else:
                percent_weighted += sum(1 for weight in weights if weight)
        active = flat_weighted == 0 and percent_weighted > 0
        fallback_offset = seg_offset(RANDOPTION_FALLBACK_SITE)
        fallback = bytes(
            so_bytes[fallback_offset:fallback_offset + len(RANDOPTION_FALLBACK_REPLACEMENT)]
        )
        fallback_patched = fallback == RANDOPTION_FALLBACK_REPLACEMENT
        active = active and fallback_patched
        _feature(
            reports,
            "equipment_percent_options",
            "Percent-only Equipment Options",
            active,
            "Active (percentage rows only)" if active else "Original / Partial",
            f"server randoption table: {flat_weighted} flat weight(s), "
            f"{percent_weighted} percentage weight(s); zero-weight fallback "
            f"{'patched' if fallback_patched else fallback.hex()}",
        )
    except Exception as exc:
        _feature(
            reports,
            "equipment_percent_options",
            "Percent-only Equipment Options",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-quinquies-quinquies. +10 equipment upgrade always succeeds
    try:
        fail_offset = seg_offset(EQUIPMENT_UPGRADE_10_FAIL_SITE)
        fail_value = bytes(
            so_bytes[fail_offset:fail_offset + len(EQUIPMENT_UPGRADE_10_FAIL_ORIGINAL)]
        )
        active = fail_value == EQUIPMENT_UPGRADE_10_FAIL_REPLACEMENT
        _feature(
            reports,
            "equipment_upgrade_10_guarantee",
            "+10 Upgrade Always Succeeds",
            active,
            "Active (+9 -> +10 is 100%)" if active else "Original / Partial",
            f"+9 fail probability at 0x{EQUIPMENT_UPGRADE_10_FAIL_SITE:x}: "
            f"{fail_value.hex()}",
        )
    except Exception as exc:
        _feature(
            reports,
            "equipment_upgrade_10_guarantee",
            "+10 Upgrade Always Succeeds",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-quater. 4-star random rune box type roll
    try:
        rewritten = 0
        for row_index, _stock_row, patched_row in RUNE_BOX_TYPE_REWRITES:
            site = RUNE_REWARD_TYPE_TABLE + row_index * RUNE_REWARD_TYPE_STRIDE
            offset = seg_offset(site)
            if bytes(so_bytes[offset:offset + 16]) == struct.pack("<4i", *patched_row):
                rewritten += 1
        active = rewritten == len(RUNE_BOX_TYPE_REWRITES)
        _feature(
            reports,
            "rune_box_random_type",
            "4★ Rune Box Random Type",
            active,
            f"Active ({rewritten}/{len(RUNE_BOX_TYPE_REWRITES)} rows on group "
            f"{RUNE_BOX_TYPE_GROUP})" if active else f"Original ({rewritten} rows rewritten)",
            f"table 0x{RUNE_REWARD_TYPE_TABLE:x}, rows "
            f"{', '.join(str(r) for r, _s, _p in RUNE_BOX_TYPE_REWRITES)}",
        )
    except Exception as exc:
        _feature(
            reports,
            "rune_box_random_type",
            "4★ Rune Box Random Type",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-quinquies. Rune attribute quality factor
    try:
        rune_offset = seg_offset(RUNE_QUALITY_BONUS_SITE)
        rune_word = bytes(so_bytes[rune_offset:rune_offset + 4])
        rune_imm = None
        if rune_word == RUNE_QUALITY_BONUS_ORIGINAL:
            rune_active = False
            rune_status = "Original (mastery bonus as rolled)"
        else:
            rune_imm = _decode_movz_imm(
                rune_word, expected_reg=RUNE_QUALITY_BONUS_REGISTER, wide=True
            )
            table_start = seg_offset(RUNE_OPTION_TABLE_VADDR)
            table_end = table_start + RUNE_OPTION_ROW_COUNT * RUNE_OPTION_ROW_SIZE
            table_ok = hashlib.sha256(so_bytes[table_start:table_end]).hexdigest() in (
                RUNE_OPTION_TABLE_PERCENT_SHA256,
                RUNE_OPTION_TABLE_PINK_SHA256,
                RUNE_OPTION_TABLE_PERCENT_PINK_SHA256,
            )
            rune_active = rune_imm is not None and table_ok
            rune_status = (
                f"Active (x{RUNE_QUALITY_BONUS_REGISTER}={rune_imm})"
                if rune_active
                else "Unknown / Invalid instruction or incomplete rune table"
            )
        _feature(
            reports,
            "rune_quality_factor",
            "Rune Attribute Quality Factor",
            rune_active,
            rune_status,
            f"site 0x{RUNE_QUALITY_BONUS_SITE:x}, original {RUNE_QUALITY_BONUS_ORIGINAL.hex()}",
            value=rune_imm,
        )
    except Exception as exc:
        _feature(
            reports,
            "rune_quality_factor",
            "Rune Attribute Quality Factor",
            False,
            "Unknown",
            str(exc),
        )

    # 8a-sexies. Rune box slot/type roll rerouted through the counter cave
    try:
        cave_off = seg_offset(RUNE_ROLL_CAVE_VA)
        cave_ok = (
            bytes(so_bytes[cave_off:cave_off + RUNE_ROLL_CAVE_LEN]) == rune_roll_cave_blob()
        )
        rerouted = 0
        for site in RUNE_ROLL_SITES:
            site_off = seg_offset(site)
            if bytes(so_bytes[site_off:site_off + 4]) == encode_arm64_branch(
                site, RUNE_ROLL_CAVE_VA, link=True
            ):
                rerouted += 1
        loop_off = seg_offset(RUNE_TYPE_LOOP_ENTER)
        seeded = bytes(so_bytes[loop_off:loop_off + 4]) == encode_arm64_branch(
            RUNE_TYPE_LOOP_ENTER, RUNE_ROLL_CAVE_VA + RUNE_TYPE_CAVE_OFFSET
        )
        deterministic = 0
        for site in RUNE_ROLL_DETERMINISTIC_SITES:
            site_off = seg_offset(site)
            if bytes(so_bytes[site_off:site_off + 4]) == encode_arm64_branch(
                site, RUNE_ROLL_TEXT_VA, link=True
            ):
                deterministic += 1
        roll_active = cave_ok and rerouted == len(RUNE_ROLL_SITES) and seeded
        _feature(
            reports,
            "rune_box_random_roll",
            "Rune Box Random Slot/Type",
            roll_active,
            (
                f"Active ({rerouted}/{len(RUNE_ROLL_SITES)} slot roll rerouted, type loop "
                f"seeded: {seeded}, grade/quality still deterministic: {deterministic}/"
                f"{len(RUNE_ROLL_DETERMINISTIC_SITES)})"
                if roll_active
                else f"Original ({rerouted}/{len(RUNE_ROLL_SITES)} rerouted, "
                f"cave {cave_ok}, seeded {seeded})"
            ),
            f"cave 0x{RUNE_ROLL_CAVE_VA:x} (sha {RUNE_ROLL_CAVE_SHA256[:12]}), "
            f"sites {', '.join(f'0x{s:x}' for s in RUNE_ROLL_SITES)}",
        )
    except Exception as exc:
        _feature(
            reports,
            "rune_box_random_roll",
            "Rune Box Random Slot/Type",
            False,
            "Unknown",
            str(exc),
        )

    # 8b. Laboratory cylinder x10 checks (Gold + Mana Stone)
    try:
        cave = (
            struct.pack("<I", 0x5290D408)   # movz w8, #0x86a0
            + struct.pack("<I", 0x72A00028)  # movk w8, #0x1, lsl #16
            + encode_arm64_branch(
                GOLD_CYLINDER_X10_CAVE_VADDR + 8, GOLD_CYLINDER_X10_RETURN_VADDR
            )
        )
        if len(cave) != GOLD_CYLINDER_X10_CAVE_SIZE:
            raise ValueError("gold cylinder cave layout mismatch")
        cave_off = seg_offset(GOLD_CYLINDER_X10_CAVE_VADDR)
        cave_ok = bytes(so_bytes[cave_off:cave_off + len(cave)]) == cave
        hook_off = seg_offset(GOLD_CYLINDER_X10_SITE)
        hook_ok = (
            bytes(so_bytes[hook_off:hook_off + 4])
            == encode_arm64_branch(
                GOLD_CYLINDER_X10_SITE, GOLD_CYLINDER_X10_CAVE_VADDR
            )
        )
        original_ok = (
            bytes(so_bytes[hook_off:hook_off + 4]) == GOLD_CYLINDER_X10_ORIGINAL
        )
        active = cave_ok and hook_ok
        _feature(
            reports,
            "gold_cylinder_x10",
            "Gold Cylinder x10 Gold",
            active,
            "Active (10x Gold)" if active else "Original / Partial",
            f"hook={'ok' if hook_ok else ('original' if original_ok else 'mismatch')}, "
            f"cave={'ok' if cave_ok else 'mismatch'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "gold_cylinder_x10",
            "Gold Cylinder x10 Gold",
            False,
            "Unknown",
            str(exc),
        )

    try:
        mana_changed = 0
        for mana_site, _mana_original, mana_replacement in MANA_CYLINDER_X10_SITES:
            offset = seg_offset(mana_site)
            if struct.unpack_from("<I", so_bytes, offset)[0] == mana_replacement:
                mana_changed += 1
        active = mana_changed == len(MANA_CYLINDER_X10_SITES)
        _feature(
            reports,
            "mana_cylinder_x10",
            "Mana Stone Compactor x10 Mana",
            active,
            "Active (10x Mana)" if active else "Original / Partial",
            f"{mana_changed}/{len(MANA_CYLINDER_X10_SITES)} reward base(s) scaled",
        )
    except Exception as exc:
        _feature(
            reports,
            "mana_cylinder_x10",
            "Mana Stone Compactor x10 Mana",
            False,
            "Unknown",
            str(exc),
        )

    # 9. Campaign Event Coin 10x Drop Check (common return path + new cave)
    try:
        old_off = seg_offset(EVENT_COIN_OLD_HOOK_VADDR)
        old_current = bytes(so_bytes[old_off:old_off + 4])
        old_legacy = encode_arm64_branch(EVENT_COIN_OLD_HOOK_VADDR, EVENT_COIN_OLD_CAVE_VADDR)
        old_hook_ok = old_current == EVENT_COIN_OLD_HOOK_ORIGINAL

        hook_off = seg_offset(EVENT_COIN_HOOK_VADDR)
        current_hook = bytes(so_bytes[hook_off:hook_off + 4])
        expected_hook = encode_arm64_branch(EVENT_COIN_HOOK_VADDR, EVENT_COIN_CAVE_VADDR)
        cave_off = seg_offset(EVENT_COIN_CAVE_VADDR)
        cave = bytes(so_bytes[cave_off:cave_off + EVENT_COIN_CAVE_SIZE])
        expected_cave = (
            struct.pack("<I", 0x52800148)  # mov w8, #10
            + struct.pack("<I", 0x9B087E73)  # mul x19, x19, x8
            + bytes.fromhex("e00313aa")      # mov x0, x19
            + encode_arm64_branch(EVENT_COIN_CAVE_VADDR + 12, EVENT_COIN_RETURN_VADDR)
        )
        active = old_hook_ok and current_hook == expected_hook and cave == expected_cave
        if old_current == old_legacy:
            status = "Legacy / Cleanup Path Only"
        elif active:
            status = "Active (10x Multiplier)"
        else:
            status = "Original / Partial"
        _feature(
            reports,
            "event_coin_x10",
            "10x Campaign Event Coin Drop",
            active,
            status,
            f"old_hook={'ok' if old_hook_ok else 'legacy/unknown'}, "
            f"return_hook={'ok' if current_hook == expected_hook else 'mismatch'}, "
            f"cave={'ok' if cave == expected_cave else 'mismatch'} at 0x{EVENT_COIN_CAVE_VADDR:x}",
        )
    except Exception as exc:
        _feature(
            reports, "event_coin_x10", "10x Campaign Event Coin Drop", False, "Unknown", str(exc)
        )

    # 10. Guild Raid 64-bit Score Transport Check
    try:
        start_expected = (
            encode_arm64_branch(GUILD_RAID_START_SITE, GUILD_RAID_SENTINEL_CAVE)
            + bytes.fromhex("1f2003d5")
        )
        start_off = seg_offset(GUILD_RAID_START_SITE)
        start_ok = (
            bytes(so_bytes[start_off:start_off + len(start_expected)]) == start_expected
        )
        install_expected = encode_arm64_branch(
            GUILD_RAID_INSTALL_SITE, GUILD_RAID_CLIENT_CAVE
        )
        install_off = seg_offset(GUILD_RAID_INSTALL_SITE)
        install_ok = (
            bytes(so_bytes[install_off:install_off + len(install_expected)])
            == install_expected
        )
        sentinel_off = seg_offset(GUILD_RAID_SENTINEL_CAVE)
        sentinel_ok = (
            bytes(
                so_bytes[
                    sentinel_off:sentinel_off + len(GUILD_RAID_SENTINEL_CAVE_BYTES)
                ]
            )
            == GUILD_RAID_SENTINEL_CAVE_BYTES
        )
        client_off = seg_offset(GUILD_RAID_CLIENT_CAVE)
        client_ok = (
            bytes(so_bytes[client_off:client_off + len(GUILD_RAID_CLIENT_CAVE_BYTES)])
            == GUILD_RAID_CLIENT_CAVE_BYTES
        )
        active = start_ok and install_ok and sentinel_ok and client_ok
        _feature(
            reports,
            "guild_raid_score_fix",
            "Guild Raid 64-bit Scores (>2.5B)",
            active,
            "Active (64-bit transport)" if active else "Original / Partial",
            f"server={'ok' if start_ok else 'mismatch'}, "
            f"installer={'ok' if install_ok else 'mismatch'}, "
            f"sentinel={'ok' if sentinel_ok else 'mismatch'}, "
            f"client_hook={'ok' if client_ok else 'mismatch'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "guild_raid_score_fix",
            "Guild Raid 64-bit Scores (>2.5B)",
            False,
            "Unknown",
            str(exc),
        )

    # 12o. Guild Raid Fire Support Check
    try:
        active = inspect_guild_raid_fire_support(so_bytes, seg_offset)
        _feature(
            reports,
            "guild_raid_fire_support",
            "Guild Raid Fire Support (100% HP + Odd Turns)",
            active,
            "Active (100% HP + odd-turn auto-cast hook)" if active else "Original",
            "0xAB335C -> 0xB2ABC0 runtime hook checked",
        )
    except Exception as exc:
        _feature(
            reports,
            "guild_raid_fire_support",
            "Guild Raid Fire Support (100% HP + Odd Turns)",
            False,
            "Unknown",
            str(exc),
        )

    # 11. Single Black Hammer Check
    try:
        active = (
            inspect_equipment_tiers(so_bytes, seg_offset)
            and bytes(so_bytes[seg_offset(SINGLE_BLACK_HAMMER_SITE):seg_offset(SINGLE_BLACK_HAMMER_SITE) + 4]) == SINGLE_BLACK_HAMMER_REPLACEMENT
            and struct.unpack_from("<6i", so_bytes, INFINITE_TRANSCEND_SUCCESS_TABLE) == INFINITE_TRANSCEND_SUCCESS_PATCHED
        )
        _feature(reports, "equipment_tier_upgrades", "One Hammer per Equipment Tier", active,
                 "Active" if active else "Original / Partial", "Native hooks and required hammer rules checked")
    except Exception as exc:
        _feature(reports, "equipment_tier_upgrades", "One Hammer per Equipment Tier", False, "Unknown", str(exc))

    # 11. Single Black Hammer Check
    try:
        offset = seg_offset(SINGLE_BLACK_HAMMER_SITE)
        active = (
            bytes(so_bytes[offset:offset + len(SINGLE_BLACK_HAMMER_REPLACEMENT)])
            == SINGLE_BLACK_HAMMER_REPLACEMENT
        )
        _feature(
            reports,
            "single_black_hammer",
            "Single Black Hammer (+16..+26)",
            active,
            "Active (1 per attempt)" if active else "Original / Partial",
            f"site 0x{SINGLE_BLACK_HAMMER_SITE:x}: "
            f"{'patched' if active else 'original'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "single_black_hammer",
            "Single Black Hammer (+16..+26)",
            False,
            "Unknown",
            str(exc),
        )

    # 12. Single Gem Fang Check (server 1-fang charge + all 3 holes + client gate)
    try:
        offset = seg_offset(SINGLE_GEM_FANG_SITE)
        server_active = (
            bytes(so_bytes[offset:offset + len(SINGLE_GEM_FANG_REPLACEMENT)])
            == SINGLE_GEM_FANG_REPLACEMENT
        )
        holes_hook_off = seg_offset(SINGLE_GEM_FANG_ALL_HOLES_SITE)
        all_holes_hook = bytes(so_bytes[holes_hook_off:holes_hook_off + 4]) == (
            encode_arm64_branch(
                SINGLE_GEM_FANG_ALL_HOLES_SITE,
                SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR,
                link=True,
            )
        )
        holes_cave_off = seg_offset(SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR)
        all_holes_cave = (
            bytes(
                so_bytes[
                    holes_cave_off:holes_cave_off + SINGLE_GEM_FANG_ALL_HOLES_CAVE_SIZE
                ]
            )
            == SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES
        )
        install_off = seg_offset(SINGLE_GEM_FANG_INSTALL_SITE)
        install_hook = bytes(so_bytes[install_off:install_off + 4]) == (
            encode_arm64_branch(SINGLE_GEM_FANG_INSTALL_SITE, SINGLE_GEM_FANG_CAVE_VADDR)
        )
        cave_off = seg_offset(SINGLE_GEM_FANG_CAVE_VADDR)
        cave_ok = (
            bytes(so_bytes[cave_off:cave_off + SINGLE_GEM_FANG_CAVE_SIZE])
            == SINGLE_GEM_FANG_CAVE_BYTES
        )
        active = (
            server_active
            and all_holes_hook
            and all_holes_cave
            and install_hook
            and cave_ok
        )
        _feature(
            reports,
            "single_gem_fang",
            "Single Dragon Fang Opens All 3 Gem Slots",
            active,
            "Active (1 fang opens all 3 slots, client gate relaxed)" if active else "Original / Partial",
            f"site 0x{SINGLE_GEM_FANG_SITE:x}: {'patched' if server_active else 'original'}; "
            f"all_holes={'ok' if all_holes_hook and all_holes_cave else 'missing'}; "
            f"client hook={'ok' if install_hook and cave_ok else 'missing'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "single_gem_fang",
            "Single Dragon Fang Opens All 3 Gem Slots",
            False,
            "Unknown",
            str(exc),
        )

    # 12a2. Paid Gem Mining x10 check
    try:
        hook_off = seg_offset(GEM_MINING_COUNT_SITE)
        cave_off = seg_offset(GEM_MINING_CAVE_VADDR)
        expected_hook = encode_arm64_branch(
            GEM_MINING_COUNT_SITE, GEM_MINING_CAVE_VADDR, link=True
        )
        hook_ok = bytes(so_bytes[hook_off:hook_off + 4]) == expected_hook
        cave_ok = (
            bytes(so_bytes[cave_off:cave_off + len(GEM_MINING_CAVE_BYTES)])
            == GEM_MINING_CAVE_BYTES
        )
        active = hook_ok and cave_ok
        _feature(
            reports,
            "gem_mining_x10",
            "Gems x10 (Mining)",
            active,
            "Active (10 per roll)" if active else "Original / Partial",
            f"hook={'present' if hook_ok else 'missing'}, "
            f"cave={'present' if cave_ok else 'missing'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "gem_mining_x10",
            "Gems x10 (Mining)",
            False,
            "Unknown",
            str(exc),
        )

    # 12a3. Gem mining type restriction check
    try:
        hook_off = seg_offset(GEM_MINING_TYPES_HOOK)
        cave_off = seg_offset(GEM_MINING_TYPES_CAVE_VADDR)
        expected_hook = encode_arm64_branch(
            GEM_MINING_TYPES_HOOK, GEM_MINING_TYPES_CAVE_VADDR
        )
        hook_ok = bytes(so_bytes[hook_off:hook_off + 4]) == expected_hook
        cave_ok = (
            bytes(so_bytes[cave_off:cave_off + len(GEM_MINING_TYPES_CAVE_BYTES)])
            == GEM_MINING_TYPES_CAVE_BYTES
        )
        active = hook_ok and cave_ok
        _feature(
            reports,
            "gem_mining_types",
            "Gem Type Restriction",
            active,
            "Active (MP/Counter/Dodge/Hit)" if active else "Original / Partial",
            f"hook={'present' if hook_ok else 'missing'}, "
            f"cave={'present' if cave_ok else 'missing'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "gem_mining_types",
            "Gem Type Restriction",
            False,
            "Unknown",
            str(exc),
        )

    # 12a3b. Gem level 6 check
    try:
        patched = 0
        for addr in GEM_LEVEL6_STRINGS:
            if bytes(so_bytes[addr + 4:addr + 5]) == GEM_LEVEL6_REPLACEMENT_CHAR:
                patched += 1
        active = patched == len(GEM_LEVEL6_STRINGS)
        _feature(
            reports,
            "gem_level6",
            "Gems Level 6",
            active,
            "Active (level 6)" if active else "Original / Partial",
            f"{patched}/{len(GEM_LEVEL6_STRINGS)} gem codes at level 6",
        )
    except Exception as exc:
        _feature(
            reports,
            "gem_level6",
            "Gems Level 6",
            False,
            "Unknown",
            str(exc),
        )

    # 12a4. Gem upgrade gold 50% discount check
    try:
        off = seg_offset(GEM_UPGRADE_GOLD_SITE)
        active = (
            bytes(so_bytes[off:off + len(GEM_UPGRADE_GOLD_REPLACEMENT)])
            == GEM_UPGRADE_GOLD_REPLACEMENT
        )
        _feature(
            reports,
            "gem_upgrade_gold_half",
            "50% Off Gem Upgrade Gold",
            active,
            "Active (50% Off)" if active else "Original",
            f"site 0x{GEM_UPGRADE_GOLD_SITE:x}: "
            f"{'patched' if active else 'original'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "gem_upgrade_gold_half",
            "50% Off Gem Upgrade Gold",
            False,
            "Unknown",
            str(exc),
        )

    # 12b1. Battle Arena Team Save Fix Check (client runtime installer)
    try:
        cave_off = seg_offset(BATTLE_ARENA_SAVE_CAVE_VADDR)
        cave_ok = (
            bytes(so_bytes[cave_off:cave_off + len(BATTLE_ARENA_SAVE_CAVE_BYTES)])
            == BATTLE_ARENA_SAVE_CAVE_BYTES
        )
        site_off = seg_offset(BATTLE_ARENA_SAVE_LATE_SITE)
        expected_site = encode_arm64_branch(
            BATTLE_ARENA_SAVE_LATE_SITE, BATTLE_ARENA_SAVE_CAVE_VADDR
        )
        site_ok = bytes(so_bytes[site_off:site_off + 4]) == expected_site
        active = cave_ok and site_ok
        _feature(
            reports,
            "battle_arena_save_fix",
            "Battle Arena Team Save Fix",
            active,
            "Active (client hook)" if active else "Original / Partial",
            f"installer={'ok' if site_ok else 'mismatch'}, "
            f"client_hook={'ok' if cave_ok else 'mismatch'} "
            f"(RVA 0x{BATTLE_ARENA_SAVE_RVA:x})",
        )
    except Exception as exc:
        _feature(
            reports,
            "battle_arena_save_fix",
            "Battle Arena Team Save Fix",
            False,
            "Unknown",
            str(exc),
        )

    # 12b2. High-level upgrade no-failure check
    try:
        values = struct.unpack_from("<6i", so_bytes, INFINITE_TRANSCEND_SUCCESS_TABLE)
        active = values == INFINITE_TRANSCEND_SUCCESS_PATCHED
        _feature(
            reports,
            "upgrade_no_fail_above_20",
            "No Upgrade Failure Above +20",
            active,
            "Active (100% Success)" if active else "Original / Partial",
            f"+21..+26 success percentages: {', '.join(str(value) for value in values)}",
        )
    except Exception as exc:
        _feature(
            reports,
            "upgrade_no_fail_above_20",
            "No Upgrade Failure Above +20",
            False,
            "Unknown",
            str(exc),
        )

    # 12d. Coocoo EXP x2 Check
    try:
        offset = seg_offset(COOCOO_EXP_X2_SITE)
        active = (
            bytes(so_bytes[offset:offset + len(COOCOO_EXP_X2_REPLACEMENT)])
            == COOCOO_EXP_X2_REPLACEMENT
        )
        _feature(
            reports,
            "coocoo_exp_x2",
            "Coocoo EXP x2 Always",
            active,
            "Active (x2 EXP)" if active else "Original / Partial",
            f"site 0x{COOCOO_EXP_X2_SITE:x}: {'patched' if active else 'original'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "coocoo_exp_x2",
            "Coocoo EXP x2 Always",
            False,
            "Unknown",
            str(exc),
        )

    # 12d2. Coocoo Garden level x2 Check
    try:
        doubled = 0
        total = len(COOCOO_STAGE_LEVELS)
        for index, original in enumerate(COOCOO_STAGE_LEVELS):
            offset = (
                COOCOO_STAGE_TABLE_OFFSET
                + index * COOCOO_STAGE_ROW_SIZE
                + COOCOO_STAGE_LEVEL_OFFSET
            )
            level_min, level_max = struct.unpack_from("<2i", so_bytes, offset)
            if level_min == original * 2 and level_max == original * 2:
                doubled += 1
        active = doubled == total
        _feature(
            reports,
            "coocoo_level_x2",
            "Coocoo Level x2",
            active,
            "Active (levels doubled)" if active else "Original / Partial",
            f"{doubled}/{total} Coocoo/Pit row(s) doubled",
        )
    except Exception as exc:
        _feature(
            reports,
            "coocoo_level_x2",
            "Coocoo Level x2",
            False,
            "Unknown",
            str(exc),
        )

    # 12d3. Unknown Paradise battleship part 90% discount
    try:
        discounted = 0
        total = 0
        for table_offset, values in SHIP_PART_COST_TABLES:
            for index, original in enumerate(values):
                if not original:
                    continue
                total += 1
                offset = table_offset + index * SHIP_PART_COST_FIELD_SIZE
                current = struct.unpack_from("<q", so_bytes, offset)[0]
                if current == max(1, (original + 9) // 10):
                    discounted += 1
        active = discounted == total
        _feature(
            reports,
            "ship_parts_90_off",
            "90% Off Battleship Parts",
            active,
            "Active (90% Off)" if active else "Original / Partial",
            f"{discounted}/{total} battleship part cost(s) discounted",
        )
    except Exception as exc:
        _feature(
            reports,
            "ship_parts_90_off",
            "90% Off Battleship Parts",
            False,
            "Unknown",
            str(exc),
        )

    repair_sites = sum(
        so_bytes[offset:offset + len(replacement)] == replacement
        for site, _, replacement in WORLDBOSS_FULL_SHIP_REPAIR_SITES
        for offset in (seg_offset(site),)
    )
    repair_active = repair_sites == len(WORLDBOSS_FULL_SHIP_REPAIR_SITES)
    _feature(
        reports,
        "worldboss_full_ship_repair",
        "Unknown Paradise Full Ship Repair",
        repair_active,
        "Active (Full HP)" if repair_active else "Original / Partial",
        f"{repair_sites}/{len(WORLDBOSS_FULL_SHIP_REPAIR_SITES)} repair paths patched",
    )

    # 12d4. Unknown Paradise crystal skill 90% discount
    try:
        offset = seg_offset(CRYSTAL_SKILL_COST_SITE)
        active = (
            bytes(so_bytes[offset:offset + len(CRYSTAL_SKILL_COST_REPLACEMENT)])
            == CRYSTAL_SKILL_COST_REPLACEMENT
        )
        _feature(
            reports,
            "crystal_skill_90_off",
            "90% Off Core Crystal Upgrades",
            active,
            "Active (50 -> 5 Kraken Scales)" if active else "Original / Partial",
            f"site 0x{CRYSTAL_SKILL_COST_SITE:x}: {'patched' if active else 'original'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "crystal_skill_90_off",
            "90% Off Core Crystal Upgrades",
            False,
            "Unknown",
            str(exc),
        )

    # 12e. 50% Dungeon Stamina Cost Check
    try:
        offset = seg_offset(STAMINA_HALF_SITE)
        active = (
            bytes(so_bytes[offset:offset + len(STAMINA_HALF_REPLACEMENT)])
            == STAMINA_HALF_REPLACEMENT
        )
        _feature(
            reports,
            "stamina_cost_half",
            "50% Dungeon Stamina Cost",
            active,
            "Active (50% Off)" if active else "Original / Partial",
            f"site 0x{STAMINA_HALF_SITE:x}: {'patched' if active else 'original'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "stamina_cost_half",
            "50% Dungeon Stamina Cost",
            False,
            "Unknown",
            str(exc),
        )

    # 12f. Stamina Potion 1000 Check
    try:
        offset = seg_offset(STAMINA_POTION_1000_SITE)
        active = (
            bytes(so_bytes[offset:offset + len(STAMINA_POTION_1000_REPLACEMENT)])
            == STAMINA_POTION_1000_REPLACEMENT
        )
        _feature(
            reports,
            "stamina_potion_1000",
            "Stamina Potion Restores 1000",
            active,
            "Active (1000 points)" if active else "Original / Partial",
            f"site 0x{STAMINA_POTION_1000_SITE:x}: {'patched' if active else 'original'}",
        )
    except Exception as exc:
        _feature(
            reports,
            "stamina_potion_1000",
            "Stamina Potion Restores 1000",
            False,
            "Unknown",
            str(exc),
        )

    # 12h. Campaign Shop 90% Discount Check
    try:
        pat_c = re.compile(rb'\{[^{}]*?"shop_content":\s*([1356])[^{}]*?"price_count":(\s*\d+)[^{}]*?\}')
        pat_f = re.compile(rb'\{[^{}]*?"price_friendship_point":(\s*[1-9]\d*)[^{}]*?\}')
        mc = list(pat_c.finditer(so_bytes))
        mf = list(pat_f.finditer(so_bytes))
        total = len(mc) + len(mf)
        priced = bool(mc or mf) and all(
            m.group(2).startswith(b" ") or int(m.group(2).strip()) == 1
            for m in mc
        ) and all(
            m.group(1).startswith(b" ") or int(m.group(1).strip()) == 1
            for m in mf
        )
        sentinels = {
            b"5202": 30,      # Ancient Coins, 300 -> 30
            b"5209": 90000,   # Ancient Coins gold row, 900000 -> 90000
            b"1107": 75,      # Battle of Honor, 750 -> 75
            b"6102": 5,       # Unknown Paradise, 50 -> 5
            b"5201": 1,       # minimum price stays at 1
        }
        sentinel_ok = True
        for sentinel_code, sentinel_price in sentinels.items():
            match = re.search(
                rb'"shop_code":"' + sentinel_code + rb'"[^{}]*?"price_count":\s*(\d+)',
                so_bytes,
            )
            if match is None or int(match.group(1)) != sentinel_price:
                sentinel_ok = False
                break
        coin_prices = {
            b"60305": 25, b"60306": 25, b"60307": 25,
            b"60401": 750, b"60402": 750, b"60403": 750,
            b"6A101": 1750, b"69973": 1000, b"69974": 1500,
        }
        coin_rows = re.findall(
            rb'\{[^{}\x00]*?"shop_code":"([^"\s]+)"[^{}\x00]*?"shop_kind":\s*6\s*,'
            rb'[^{}\x00]*?"price_coin":\s*([1-9]\d*)(?=\s*,)[^{}\x00]*?\}', so_bytes
        )
        coin_ok = len(coin_rows) == len(coin_prices) and all(
            code in coin_prices and int(price) == coin_prices[code]
            for code, price in coin_rows
        )
        fragment = re.findall(
            rb'"shop_code":"6A102"[^{}\x00]*?"price_coin":(20| 2)\x00', so_bytes
        )
        active = total == 94 and priced and sentinel_ok and coin_ok and fragment == [b" 2"]
        _feature(
            reports,
            "campaign_shop_discount",
            "90% Campaign Shop Discount",
            active,
            "Active (90% Off)" if active else "Original / Partial",
            f"{total} campaign, {len(coin_rows)} coin rows and {len(fragment)} coin fragment checked",
        )
    except Exception as exc:
        _feature(
            reports, "campaign_shop_discount", "90% Campaign Shop Discount", False, "Unknown", str(exc)
        )

    # 12i. Mode Drops 10x Check (hooks, cave bodies, and World Boss/Nephthys/Lost Island/Sky Library tables)
    try:
        wb_cycle_rows = worldboss_cycle_reward_rows(so_bytes)
        wb_cycle_ok = (
            len(wb_cycle_rows) == WORLDBOSS_CYCLE_REWARD_TARGET_COUNT
            and hashlib.sha256(repr(wb_cycle_rows).encode("ascii")).hexdigest()
            == WORLDBOSS_CYCLE_REWARD_PATCHED_SHA256
        )
        wb_event_off = seg_offset(WORLDBOSS_EVENT_REWARD_SITE)
        wb_event_ok = (
            bytes(
                so_bytes[
                    wb_event_off : wb_event_off
                    + len(WORLDBOSS_EVENT_REWARD_ORIGINAL)
                ]
            )
            == WORLDBOSS_EVENT_REWARD_ORIGINAL
        )
        wb_daily_expected = encode_arm64_branch(
            WORLDBOSS_DAILY_KRAKEN_SITE, WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR
        )
        wb_daily_off = seg_offset(WORLDBOSS_DAILY_KRAKEN_SITE)
        wb_daily_cave_off = seg_offset(WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR)
        wb_daily_kraken_ok = (
            bytes(so_bytes[wb_daily_off : wb_daily_off + 4]) == wb_daily_expected
            and bytes(
                so_bytes[
                    wb_daily_cave_off : wb_daily_cave_off
                    + len(WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES)
                ]
            )
            == WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES
        )
        dim_cave_expected = _build_dimension_cave(DIMENSION_CAVE_VADDR)
        dim_expected = encode_arm64_branch(DIMENSION_DROP_SITE, DIMENSION_CAVE_VADDR)
        dim_ok = (
            bytes(so_bytes[seg_offset(DIMENSION_DROP_SITE):seg_offset(DIMENSION_DROP_SITE) + 4])
            == dim_expected
            and bytes(
                so_bytes[
                    seg_offset(DIMENSION_CAVE_VADDR) : seg_offset(DIMENSION_CAVE_VADDR)
                    + len(dim_cave_expected)
                ]
            )
            == dim_cave_expected
        )
        honor_ok = (
            bytes(
                so_bytes[
                    seg_offset(HONOR_COIN_COUNT_SITE):seg_offset(HONOR_COIN_COUNT_SITE) + 4
                ]
            )
            == HONOR_COIN_COUNT_REPLACEMENT
        )
        honor_points_expected = encode_arm64_branch(
            HONOR_POINTS_DELTA_SITE, HONOR_POINTS_CAVE_VADDR, link=True
        )
        honor_points_ok = (
            bytes(
                so_bytes[
                    seg_offset(HONOR_POINTS_DELTA_SITE):seg_offset(HONOR_POINTS_DELTA_SITE)
                    + 4
                ]
            )
            == honor_points_expected
            and bytes(
                so_bytes[
                    seg_offset(HONOR_POINTS_CAVE_VADDR):seg_offset(HONOR_POINTS_CAVE_VADDR)
                    + len(HONOR_POINTS_CAVE_BYTES)
                ]
            )
            == HONOR_POINTS_CAVE_BYTES
        )
        gene_gate_ok = (
            bytes(
                so_bytes[
                    seg_offset(DIMENSION_GENE_GUARANTEE_SITE):seg_offset(DIMENSION_GENE_GUARANTEE_SITE)
                    + 4
                ]
            )
            == DIMENSION_GENE_GUARANTEE_REPLACEMENT
        )
        gene_cave_expected = _build_dimension_gene_cave(DIMENSION_GENE_CAVE_VADDR)
        gene_count_expected = encode_arm64_branch(
            DIMENSION_GENE_COUNT_SITE, DIMENSION_GENE_CAVE_VADDR
        )
        gene_count_ok = (
            bytes(
                so_bytes[
                    seg_offset(DIMENSION_GENE_COUNT_SITE):seg_offset(DIMENSION_GENE_COUNT_SITE) + 4
                ]
            )
            == gene_count_expected
            and bytes(
                so_bytes[
                    seg_offset(DIMENSION_GENE_CAVE_VADDR) : seg_offset(
                        DIMENSION_GENE_CAVE_VADDR
                    )
                    + len(gene_cave_expected)
                ]
            )
            == gene_cave_expected
        )
        nephthys_rows: list[tuple[int, int]] = []
        lost_island_rows: list[tuple[int, int]] = []
        for index in range(STAGE_ROW_COUNT):
            at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
            stage_id, _hero_xp, gold = struct.unpack_from("<3i", so_bytes, at)
            prefix = _stage_prefix(stage_id)
            if prefix in NEPHTHYS_STAGE_PREFIXES:
                nephthys_rows.append((stage_id, gold))
            elif prefix in LOST_ISLAND_STAGE_PREFIXES:
                lost_island_rows.append((stage_id, gold))
        nephthys_ok = (
            len(nephthys_rows) == 126
            and hashlib.sha256(repr(nephthys_rows).encode("ascii")).hexdigest()
            == _NEPHTHYS_GOLD_PATCHED_SHA256
        )
        lost_island_ok = (
            len(lost_island_rows) == 82
            and hashlib.sha256(repr(lost_island_rows).encode("ascii")).hexdigest()
            == _LOST_ISLAND_GOLD_PATCHED_SHA256
        )
        riddle_vals = [
            struct.unpack_from("<i", so_bytes, RIDDLE_TABLE_OFFSET + idx * RIDDLE_ROW_SIZE + 20)[0]
            for idx in range(RIDDLE_ROW_COUNT)
        ]
        riddle_ok = (
            len(riddle_vals) == RIDDLE_ROW_COUNT
            and hashlib.sha256(repr(riddle_vals).encode("ascii")).hexdigest()
            == _RIDDLE_PATCHED_SHA256
        )
        mode_checks = (
            ("wb_cycle_rewards", wb_cycle_ok),
            ("wb_event", wb_event_ok),
            ("wb_daily_kraken", wb_daily_kraken_ok),
            ("dimension_drops", dim_ok),
            ("honor_coins", honor_ok),
            ("honor_points", honor_points_ok),
            ("dimension_gene_gate", gene_gate_ok),
            ("dimension_gene_cave", gene_count_ok),
            ("nephthys_gold", nephthys_ok),
            ("lost_island_gold", lost_island_ok),
            ("sky_library_riddle", riddle_ok),
        )
        failed = [label for label, ok in mode_checks if not ok]
        active = not failed
        details = (
            "World Boss, Dimension (genes guaranteed x10), Nephthys, Lost Island, "
            "Sky Library and Battle of Honor (60 coins, rank points x2)"
            if active
            else "Unpatched or mismatched sub-checks: " + ", ".join(failed)
        )
        _feature(
            reports,
            "mode_drops_x10",
            "10x Mode Drops",
            active,
            "Active (10x Drops)" if active else "Original / Partial",
            details,
        )
    except Exception as exc:
        _feature(reports, "mode_drops_x10", "10x Mode Drops", False, "Unknown", str(exc))

    # 12i2. Devil's Soul EXP boost
    try:
        value = struct.unpack_from("<f", so_bytes, DEVIL_BOOST_MULTIPLIER_SITE)[0]
        active = value == DEVIL_BOOST_MULTIPLIER_PATCHED
        _feature(
            reports,
            "devil_boost_x10",
            "10x Devil's Soul EXP Boost",
            active,
            "Active (20x)" if active else "Original / Partial",
            f"EXP-synthesis multiplier: {value:g}x",
        )
    except Exception as exc:
        _feature(
            reports,
            "devil_boost_x10",
            "10x Devil's Soul EXP Boost",
            False,
            "Unknown",
            str(exc),
        )

    # 12j. Battle Arena Team Configuration Save Bug Fix Check
    try:
        arena_states_ok = bool(ARENA_WEEK_STATE_SITES) and all(
            bytes(so_bytes[seg_offset(site):seg_offset(site) + len(repl)]) == repl
            for site, _orig, repl in ARENA_WEEK_STATE_SITES
        )
        slot_off = seg_offset(ARENA_EMPTY_SLOT_SITE)
        arena_slot_ok = (
            bytes(so_bytes[slot_off:slot_off + len(ARENA_EMPTY_SLOT_REPLACEMENT)])
            == ARENA_EMPTY_SLOT_REPLACEMENT
        )
        arena_defence_ok = all(
            bytes(so_bytes[seg_offset(site):seg_offset(site) + len(repl)]) == repl
            for site, repl in (
                (ARENA_DEFENCE_SIZE_SITE, ARENA_DEFENCE_SIZE_REPLACEMENT),
                (ARENA_DEFENCE_COUNT_SITE, ARENA_DEFENCE_COUNT_REPLACEMENT),
                (ARENA_SCHEMA_GATE_SITE, ARENA_SCHEMA_GATE_REPLACEMENT),
            )
        )
        pvp_attack_hook_ok = bytes(
            so_bytes[
                seg_offset(PVP_TEAM_COMPACT_ATTACK_HOOK):seg_offset(PVP_TEAM_COMPACT_ATTACK_HOOK)
                + 4
            ]
        ) == encode_arm64_branch(
            PVP_TEAM_COMPACT_ATTACK_HOOK, PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR
        )
        pvp_attack_cave_ok = bytes(
            so_bytes[
                seg_offset(PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR):seg_offset(PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR)
                + len(PVP_TEAM_COMPACT_ATTACK_CAVE_BYTES)
            ]
        ) == PVP_TEAM_COMPACT_ATTACK_CAVE_BYTES
        pvp_defense_hook_ok = bytes(
            so_bytes[
                seg_offset(PVP_TEAM_COMPACT_DEFENSE_HOOK):seg_offset(PVP_TEAM_COMPACT_DEFENSE_HOOK)
                + 4
            ]
        ) == encode_arm64_branch(
            PVP_TEAM_COMPACT_DEFENSE_HOOK, PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR
        )
        pvp_defense_cave_ok = bytes(
            so_bytes[
                seg_offset(PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR):seg_offset(PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR)
                + len(PVP_TEAM_COMPACT_DEFENSE_CAVE_BYTES)
            ]
        ) == PVP_TEAM_COMPACT_DEFENSE_CAVE_BYTES
        active = (
            arena_states_ok
            and arena_slot_ok
            and arena_defence_ok
            and pvp_attack_hook_ok
            and pvp_attack_cave_ok
            and pvp_defense_hook_ok
            and pvp_defense_cave_ok
        )
        _feature(
            reports,
            "battle_arena_fix",
            "Battle Arena Team Save Fix",
            active,
            "Active (Fixed)" if active else "Original / Bugged",
            f"week state sites={'ok' if arena_states_ok else 'orig'}, "
            f"arena defence={'ok' if arena_defence_ok else 'orig'}, "
            f"empty slot={'ok' if arena_slot_ok else 'orig'}, "
            f"pvp attack={'ok' if pvp_attack_hook_ok and pvp_attack_cave_ok else 'missing'}, "
            f"pvp defense={'ok' if pvp_defense_hook_ok and pvp_defense_cave_ok else 'missing'}",
        )
    except Exception as exc:
        _feature(reports, "battle_arena_fix", "Battle Arena Team Save Fix", False, "Unknown", str(exc))

    # 12k. Guild Raid Offline Self-Mercenary Selection Check
    try:
        merc_off = seg_offset(GUILD_RAID_MERCENARY_SITE)
        merc_cave_off = seg_offset(GUILD_RAID_MERCENARY_CAVE_VADDR)
        merc_expected = encode_arm64_branch(
            GUILD_RAID_MERCENARY_SITE, GUILD_RAID_MERCENARY_CAVE_VADDR
        )
        site_ok = bytes(so_bytes[merc_off:merc_off + 4]) == merc_expected
        cave_ok = (
            bytes(
                so_bytes[
                    merc_cave_off:merc_cave_off
                    + len(GUILD_RAID_MERCENARY_CAVE_BYTES)
                ]
            )
            == GUILD_RAID_MERCENARY_CAVE_BYTES
        )
        client_cave_off = seg_offset(GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR)
        client_cave_ok = (
            bytes(
                so_bytes[
                    client_cave_off:client_cave_off
                    + len(GUILD_RAID_MERCENARY_CLIENT_CAVE_BYTES)
                ]
            )
            == GUILD_RAID_MERCENARY_CLIENT_CAVE_BYTES
        )
        client_hook_off = seg_offset(GUILD_RAID_MERCENARY_CLIENT_HOOK)
        client_hook_ok = bytes(
            so_bytes[client_hook_off:client_hook_off + 4]
        ) == encode_arm64_branch(
            GUILD_RAID_MERCENARY_CLIENT_HOOK,
            GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR,
        )
        active = site_ok and cave_ok and client_cave_ok and client_hook_ok
        _feature(
            reports,
            "guild_raid_mercenary",
            "Guild Raid Self-Mercenary",
            active,
            "Active (self projection + client filter)" if active else "Original (Guild-Only)",
            (
                f"hook={'ok' if site_ok else 'orig'}, "
                f"self_projection_cave={'ok' if cave_ok else 'missing'}, "
                f"client_filter_cave={'ok' if client_cave_ok else 'missing'}, "
                f"client_filter_hook={'ok' if client_hook_ok else 'orig'}"
            ),
        )
    except Exception as exc:
        _feature(
            reports, "guild_raid_mercenary", "Guild Raid Self-Mercenary", False, "Unknown", str(exc)
        )

    # 12m. Guild Raid Rank Reward x10 Check
    try:
        total = 0
        scaled = 0
        unexpected = 0
        for table, rows in (
            (GUILD_RAID_DAILY_REWARD_TABLE, GUILD_RAID_DAILY_REWARDS),
            (GUILD_RAID_WEEKLY_REWARD_TABLE, GUILD_RAID_WEEKLY_REWARDS),
        ):
            for index, amounts in enumerate(rows):
                for field_index, original in enumerate(amounts):
                    if original == 0:
                        continue
                    offset = (
                        table
                        + index * GUILD_RAID_REWARD_ENTRY_SIZE
                        + GUILD_RAID_REWARD_AMOUNT_OFFSETS[field_index]
                    )
                    current = struct.unpack_from("<i", so_bytes, offset)[0]
                    total += 1
                    if current == original * 10:
                        scaled += 1
                    elif current != original:
                        unexpected += 1
        active = total > 0 and scaled == total and unexpected == 0
        _feature(
            reports,
            "guild_raid_reward_x10",
            "Guild Raid Reward x10",
            active,
            f"Active ({scaled}/{total} amounts x10)" if active else "Original / Partial",
            (
                f"{scaled}/{total} rank reward amounts scaled"
                + (f"; {unexpected} unexpected value(s)" if unexpected else "")
            ),
        )
    except Exception as exc:
        _feature(
            reports,
            "guild_raid_reward_x10",
            "Guild Raid Reward x10",
            False,
            "Unknown",
            str(exc),
        )

    # 13. LAN Redirect Shim Check
    try:
        shim_off = seg_offset(SHIM_VADDR)
        magic = struct.unpack_from("<I", so_bytes, shim_off + 8)[0]
        boundary_off = seg_offset(0xAAD9F8)
        boundary_expected = encode_arm64_branch(0xAAD9F8, SHIM_VADDR + 4)
        boundary_ok = bytes(so_bytes[boundary_off:boundary_off + 4]) == boundary_expected
        loopback_off = seg_offset(0xAA6D70)
        loopback_ok = (
            bytes(so_bytes[loopback_off:loopback_off + 4]) == LOOPBACK_CONNECT_STUB[:4]
        )
        if magic == SHIM_MAGIC:
            ip_raw = bytes(so_bytes[shim_off + 12:shim_off + 16])
            port = struct.unpack_from(">H", so_bytes, shim_off + 16)[0]
            ip_str = str(ipaddress.IPv4Address(ip_raw))
            active = boundary_ok and loopback_ok
            _feature(
                reports,
                "network_mode",
                "Network Mode",
                active,
                f"LAN Redirect ({ip_str}:{port})" if active else "LAN Redirect (partial)",
                f"shim magic ok; boundary={'ok' if boundary_ok else 'missing'}, "
                f"loopback={'ok' if loopback_ok else 'missing'}",
                value=(ip_str, port),
            )
        else:
            _feature(
                reports,
                "network_mode",
                "Network Mode",
                False,
                "Offline Standalone",
                "Runs embedded 127.0.0.1:8010 offline server on device",
            )
    except Exception as exc:
        _feature(reports, "network_mode", "Network Mode", False, "Unknown", str(exc))

    # Dev build marker (phase 5): a dev APK announces which build produced it.
    try:
        dev_marker = find_dev_build_marker(so_bytes)
        if dev_marker:
            _feature(
                reports, "dev_build_marker", "Dev Build Marker", True, "Dev build", dev_marker
            )
        else:
            _feature(
                reports,
                "dev_build_marker",
                "Dev Build Marker",
                False,
                "Release build",
                "No dev instrumentation embedded",
            )
    except Exception as exc:
        _feature(
            reports, "dev_build_marker", "Dev Build Marker", False, "Unknown", str(exc)
        )

    return reports


def inspect_dex(
    dex_bytes: bytes | bytearray,
    so_bytes: bytes | bytearray | None = None,
) -> dict[str, FeatureReport]:
    """Inspects classes8.dex for bootstrap translation & backup prompt bypasses.

    ``so_bytes`` lets the backup-prompt check require the LAN shim: the DEX
    patch only exists in a LAN build, and a rebuilt DEX can shuffle the raw
    string-index bytes the check used to rely on.
    """
    reports: dict[str, FeatureReport] = {}
    try:
        strings = set(read_dex_strings(bytes(dex_bytes)))
        translation_markers = {
            "Preparing Fantasy War Tactics R",
            "Checking game resources...",
            "Could not prepare game resources.",
            "Retry",
        }
        korean_markers = {
            "판타지워택틱스R 오프라인 리소스 준비",
            "내장 리소스를 확인하는 중입니다…",
            "리소스 준비에 실패했습니다.",
        }
        status_ok = translation_markers <= strings and not (korean_markers & strings)
        if status_ok:
            _feature(
                reports,
                "dex_status_string",
                "Bootstrap Status String",
                True,
                "English (full bootstrap)",
                "Bootstrap titles, status, details and Retry button are English",
            )
        else:
            missing = sorted(translation_markers - strings)
            remaining = sorted(korean_markers & strings)
            _feature(
                reports,
                "dex_status_string",
                "Bootstrap Status String",
                False,
                "Original / Custom",
                f"missing={missing!r}, korean={remaining!r}",
            )

        # The LAN build removes the periodic backup scheduler invocation.  The
        # two original fragments are string-index/const payloads that a smali
        # rebuild can relocate, so only report "Bypassed" when the LAN shim is
        # present AND both fragments are gone; otherwise report Unknown.
        shim_ok = False
        if so_bytes is not None:
            if bytes(so_bytes[:4]) == b"\x7fELF":
                from core.core_patches import ELF_SEGMENTS
                from core.elf_mapping import canonicalize_segments

                so_bytes, _ = canonicalize_segments(so_bytes, ELF_SEGMENTS)
            shim_off = seg_offset(SHIM_VADDR)
            if len(so_bytes) >= shim_off + 12:
                shim_ok = struct.unpack_from("<I", so_bytes, shim_off + 8)[0] == SHIM_MAGIC
        dex_view = bytes(dex_bytes)
        originals_present = any(
            sig in dex_view for sig in _DEX_BACKUP_ORIGINAL_SIGNATURES
        )
        if so_bytes is None:
            backup_status = "Unknown (SO not supplied)"
            backup_ok = False
        elif shim_ok and not originals_present:
            backup_status = "Bypassed"
            backup_ok = True
        elif originals_present:
            backup_status = "Original"
            backup_ok = False
        else:
            backup_status = "Unknown (DEX rebuilt; marker not found)"
            backup_ok = False
        _feature(
            reports,
            "dex_backup_prompt",
            "Save Backup Dialog",
            backup_ok,
            backup_status,
            "Phone-local backup prompt disabled"
            if backup_ok
            else "Normal phone-local backup dialog enabled or not verifiable",
        )
    except Exception as exc:
        _feature(reports, "dex_error", "DEX Inspection", False, "Error", str(exc))
    return reports


def _elf_min_load_align(data: bytes) -> int:
    """Returns the minimum p_align of PT_LOAD segments in an ELF64 file."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("not an ELF64 file")
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    if e_phentsize < 56 or e_phoff + e_phnum * e_phentsize > len(data):
        raise ValueError("truncated ELF program headers")
    aligns = []
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        p_type = struct.unpack_from("<I", data, offset)[0]
        if p_type == 1:  # PT_LOAD
            aligns.append(struct.unpack_from("<Q", data, offset + 48)[0])
    return min(aligns) if aligns else 0


def check_apk_alignment(apk_path: Path) -> tuple[bool, str]:
    """Checks ZIP 16 KB alignment and ELF PT_LOAD p_align for every .so."""
    apk_path = Path(apk_path)
    with zipfile.ZipFile(apk_path, "r") as zf:
        so_entries = [info for info in zf.infolist() if info.filename.endswith(".so")]
        if not so_entries:
            return False, "No shared libraries found in APK"

        with open(apk_path, "rb") as fp:
            for info in so_entries:
                if info.compress_type != zipfile.ZIP_STORED:
                    return False, f"{Path(info.filename).name} is compressed (must be uncompressed/stored)"
                fp.seek(info.header_offset)
                hdr = fp.read(30)
                if len(hdr) < 30:
                    return False, f"Truncated ZIP header for {info.filename}"
                nlen, elen = struct.unpack_from("<HH", hdr, 26)
                data_offset = info.header_offset + 30 + nlen + elen
                if data_offset % MIN_ELF_ALIGN != 0:
                    return False, (
                        f"{Path(info.filename).name} ZIP data offset {data_offset} "
                        f"is not 16 KB aligned"
                    )

        # ELF p_align is a separate Android 16 requirement. Read only the ELF
        # header + program headers from each entry.
        for info in so_entries:
            with zf.open(info, "r") as stream:
                header = stream.read(64)
                if len(header) < 64:
                    return False, f"Truncated ELF header for {info.filename}"
                if header[:4] != b"\x7fELF" or header[4] != 2:
                    return False, f"{Path(info.filename).name} is not an ELF64 file"
                e_phoff = struct.unpack_from("<Q", header, 32)[0]
                e_phentsize = struct.unpack_from("<H", header, 54)[0]
                e_phnum = struct.unpack_from("<H", header, 56)[0]
                ph_size = e_phoff + e_phnum * e_phentsize
                if ph_size < 64:
                    return False, f"Invalid ELF program header size for {info.filename}"
                remaining = ph_size - len(header)
                body = header + (stream.read(remaining) if remaining > 0 else b"")
            try:
                min_align = _elf_min_load_align(body)
            except Exception as exc:
                return False, f"{Path(info.filename).name}: {exc}"
            if min_align < MIN_ELF_ALIGN:
                return False, (
                    f"{Path(info.filename).name} ELF PT_LOAD p_align=0x{min_align:x} "
                    f"(requires >= 0x{MIN_ELF_ALIGN:x})"
                )

    return True, (
        "All native libraries are uncompressed, ZIP 16 KB-aligned, and "
        "ELF PT_LOAD p_align >= 16 KB (Android 16 ready)"
    )


def _signing_block_ids(apk_path: Path) -> set[int]:
    """Returns APK Signing Block pair IDs (v2/v3/v3.1) without external tools."""
    ids: set[int] = set()
    try:
        with open(apk_path, "rb") as fp:
            file_len = fp.seek(0, 2)
            scan_size = min(65536, file_len)
            fp.seek(file_len - scan_size)
            tail = fp.read(scan_size)
            eocd_pos = tail.rfind(b"\x50\x4b\x05\x06")
            if eocd_pos == -1:
                return ids
            abs_eocd = file_len - scan_size + eocd_pos
            fp.seek(abs_eocd + 16)
            cd_offset = struct.unpack("<I", fp.read(4))[0]
            if cd_offset < 32:
                return ids
            fp.seek(cd_offset - 24)
            block_footer = fp.read(24)
            if len(block_footer) < 24:
                return ids
            size, magic = struct.unpack("<Q16s", block_footer)
            if magic != b"APK Sig Block 42":
                return ids
            block_start = cd_offset - 8 - size
            if block_start < 0:
                return ids
            fp.seek(block_start)
            block_header = fp.read(8)
            if len(block_header) < 8:
                return ids
            total_size = struct.unpack("<Q", block_header)[0]
            if total_size != size:
                return ids
            pos = block_start + 8
            end = cd_offset - 24
            while pos + 12 <= end:
                fp.seek(pos)
                pair_len_raw = fp.read(8)
                if len(pair_len_raw) < 8:
                    break
                pair_len = struct.unpack("<Q", pair_len_raw)[0]
                if pair_len < 4 or pos + 8 + pair_len > end:
                    break
                pair_id = struct.unpack("<I", fp.read(4))[0]
                ids.add(pair_id)
                pos += 8 + pair_len
    except Exception:
        pass
    return ids


def check_apk_signatures(apk_path: Path) -> tuple[bool, str]:
    """Verify APK signatures cryptographically before reporting signing schemes."""
    from core.apk_tooling import _run_tool, locate_tools

    apk_path = Path(apk_path).resolve()
    apksigner = locate_tools().apksigner
    if not apksigner:
        return False, "Signature verification unavailable: apksigner not found"
    try:
        # 1 GiB APKs over Windows SMB shares can exceed 180s during apksigner verification.
        _run_tool([apksigner, "verify", str(apk_path)], "apksigner verify", timeout=600)
    except RuntimeError as exc:
        return False, f"Signature verification failed: {exc}"
    with zipfile.ZipFile(apk_path, "r") as zf:
        names = zf.namelist()
        has_v1 = any(
            name.startswith("META-INF/")
            and (
                name.upper().endswith((".RSA", ".DSA", ".EC"))
                or Path(name.upper()).name.startswith("SIG-")
            )
            for name in names
        )

    ids = _signing_block_ids(apk_path)
    has_v2 = SIGNATURE_V2_ID in ids
    has_v3 = SIGNATURE_V3_ID in ids
    has_v31 = SIGNATURE_V31_ID in ids

    schemes: list[str] = []
    if has_v1:
        schemes.append("v1 JAR")
    if has_v2:
        schemes.append("v2")
    if has_v3:
        schemes.append("v3")
    if has_v31:
        schemes.append("v3.1")

    if schemes:
        return True, "Signed (" + " + ".join(schemes) + ")"
    return False, "Unsigned"


def _reconcile_limit_break_reports(
    features: dict[str, FeatureReport],
    *,
    client_profile: str | None,
    client_details: str,
    error_status: str = "Original / Partial",
) -> None:
    """Combines server-side limit-break status with client limitbreakcost.unity3d state."""
    for key, label in _LIMIT_BREAK_FEATURE_SPECS:
        so_report = features.get(key)
        if so_report is None:
            continue
        if so_report.active:
            matched = client_profile == key
            _feature(
                features,
                key,
                label,
                matched,
                so_report.status if matched else error_status,
                f"{client_details}; server: {so_report.details}",
            )
        elif client_profile == key:
            _feature(
                features,
                key,
                label,
                False,
                "Original / Partial",
                f"{client_details} (server table unpatched)",
            )


def _reconcile_so_and_resource_report(
    features: dict[str, FeatureReport],
    *,
    key: str,
    name: str,
    active_status: str,
    inner_zip: zipfile.ZipFile | None,
    inspector: Callable[[zipfile.ZipFile], tuple[bool, str]],
    missing_archive_detail: str,
    missing_status: str = "Original / Partial",
) -> None:
    """Combines server SO status with a bundled Unity asset check."""
    if inner_zip is None:
        if key in features:
            _feature(features, key, name, False, missing_status, missing_archive_detail)
        return
    try:
        resource_active, details = inspector(inner_zip)
        so_report = features.get(key)
        active = resource_active and bool(so_report and so_report.active)
        _feature(
            features,
            key,
            name,
            active,
            active_status if active else "Original / Partial",
            f"{details}; server: {so_report.details if so_report else 'original'}",
        )
    except Exception as exc:
        _feature(features, key, name, False, "Unknown", f"Resource archive check failed: {exc}")


def _inspect_apk_resources(
    inner_zip: zipfile.ZipFile | None,
    features: dict[str, FeatureReport],
    *,
    missing_status: str = "Original / Partial",
    missing_detail: str | None = None,
) -> None:
    """Audits all datatable bundles inside ``assets/fwt_resources_v1.zip``."""
    from core.alex_awakening_assets import inspect_alex_awakening_assets
    from core.alex_rebalance import inspect_alex_rebalance_assets
    from core.apk_tooling import (
        inspect_crystal_skill_cost_assets,
        inspect_equipment_percent_options_assets,
        inspect_equipment_upgrade_10_assets,
        inspect_guild_raid_boss_no_counter_assets,
        inspect_guild_raid_fire_support_assets,
        inspect_guild_raid_skills_max_assets,
        inspect_limit_break_cost_assets,
        inspect_mode_drops_assets,
        inspect_recycle_six_star_assets,
        inspect_rune_option_assets,
        inspect_rune_upgrade_assets,
        inspect_sacred_lands_assets,
        inspect_shop_assets,
    )

    _reconcile_so_and_resource_report(
        features,
        key="alex_awakening",
        name="Alex Awakening: Destiny Lance",
        active_status="Active",
        inner_zip=inner_zip,
        inspector=inspect_alex_awakening_assets,
        missing_archive_detail=missing_detail or "Alex Awakening resource archive missing",
        missing_status=missing_status,
    )

    shop_names = {
        "event_discount": "90% Event Shop Discount",
        "campaign_shop_discount": "90% Campaign Shop Discount",
        "event_gene_unlimited": "Unlimited Event Shop Genes",
        "event_limits_daily": "Daily Event Shop Limits",
    }
    shop_error: str | None = None
    try:
        shop_results = inspect_shop_assets(inner_zip) if inner_zip is not None else {}
    except Exception as exc:
        shop_error = f"client shop table check failed: {exc}"
        shop_results = dict.fromkeys(shop_names, (False, shop_error))
    for key, name in shop_names.items():
        native = features.get(key)
        fallback_msg = missing_detail or "client shop tables missing"
        client_active, details = shop_results.get(key, (False, fallback_msg))
        active = bool(native and native.active and client_active)
        if shop_error is not None or (inner_zip is None and missing_status == "Unknown"):
            status = "Unknown"
        else:
            status = "Active" if active else "Original / Partial"
        _feature(
            features,
            key,
            name,
            active,
            status,
            f"{details}; server: {native.details if native else 'original'}",
        )

    for key, name, status, inspector, missing in (
        (
            "equipment_percent_options",
            "Percent-only Equipment Options",
            "Active (percentage rows only)",
            inspect_equipment_percent_options_assets,
            "assets/fwt_resources_v1.zip is missing; randoptiontable.unity3d unchecked",
        ),
        (
            "rune_quality_factor",
            "Rune Attribute Quality x10 + Percent Only",
            "Active (percentage rows only)",
            inspect_rune_option_assets,
            "assets/fwt_resources_v1.zip is missing; runeoption.unity3d unchecked",
        ),
    ):
        if inner_zip is None:
            _feature(features, key, name, False, missing_status, missing_detail or missing)
            continue
        try:
            active, details = inspector(inner_zip)
            existing = features.get(key)
            if existing is not None:
                merged = existing.active and active
                _feature(
                    features,
                    key,
                    name,
                    merged,
                    status if merged else "Original / Partial",
                    f"{existing.details}; {details}",
                    value=existing.value,
                )
            else:
                _feature(
                    features,
                    key,
                    name,
                    active,
                    status if active else "Original / Partial",
                    details,
                )
        except Exception as exc:
            _feature(features, key, name, False, "Unknown", f"Resource archive check failed: {exc}")

    if inner_zip is not None:
        try:
            active, details = inspect_sacred_lands_assets(inner_zip)
            _feature(
                features,
                "sacred_lands_restore",
                "Sacred Lands Set Restored",
                active,
                "Active (grade 4 + tickets)" if active else "Original / Partial",
                details,
            )
        except Exception as exc:
            _feature(
                features,
                "sacred_lands_restore",
                "Sacred Lands Set Restored",
                False,
                "Unknown",
                f"Resource archive check failed: {exc}",
            )
    else:
        _feature(
            features,
            "sacred_lands_restore",
            "Sacred Lands Set Restored",
            False,
            missing_status,
            missing_detail or "assets/fwt_resources_v1.zip is missing; sacred lands tables unchecked",
        )

    _reconcile_so_and_resource_report(
        features,
        key="equipment_upgrade_10_guarantee",
        name="+10 Upgrade Always Succeeds",
        active_status="Active (+9 -> +10 is 100%)",
        inner_zip=inner_zip,
        inspector=inspect_equipment_upgrade_10_assets,
        missing_archive_detail=missing_detail or "assets/fwt_resources_v1.zip is missing; client upgrade table unchecked",
        missing_status=missing_status,
    )
    _reconcile_so_and_resource_report(
        features,
        key="crystal_skill_90_off",
        name="90% Off Core Crystal Upgrades",
        active_status="Active (50 -> 5 Kraken Scales)",
        inner_zip=inner_zip,
        inspector=inspect_crystal_skill_cost_assets,
        missing_archive_detail=missing_detail or "assets/fwt_resources_v1.zip is missing; client cost table unchecked",
        missing_status=missing_status,
    )
    _reconcile_so_and_resource_report(
        features,
        key="mode_drops_x10",
        name="10x Mode Drops",
        active_status="Active (10x Drops)",
        inner_zip=inner_zip,
        inspector=inspect_mode_drops_assets,
        missing_archive_detail=(
            missing_detail
            or "assets/fwt_resources_v1.zip is missing; honorreward/worldbossreward datatables unchecked"
        ),
        missing_status=missing_status,
    )
    _reconcile_so_and_resource_report(
        features,
        key="recycle_six_star",
        name="Recycling Grants 6★ Equipment",
        active_status="Active (always 6-star)",
        inner_zip=inner_zip,
        inspector=inspect_recycle_six_star_assets,
        missing_archive_detail=(
            missing_detail or "assets/fwt_resources_v1.zip is missing; equipreward*.unity3d unchecked"
        ),
        missing_status=missing_status,
    )

    _reconcile_so_and_resource_report(
        features,
        key="rune_upgrade_discount",
        name="Rune Upgrade +12..+15 (Guaranteed, 90% Off)",
        active_status="Active (+12..+15 always succeed, gold -90%)",
        inner_zip=inner_zip,
        inspector=inspect_rune_upgrade_assets,
        missing_archive_detail=(
            missing_detail or "assets/fwt_resources_v1.zip is missing; runeenchant.unity3d unchecked"
        ),
        missing_status=missing_status,
    )

    _reconcile_so_and_resource_report(
        features,
        key="guild_raid_fire_support",
        name="Guild Raid Fire Support (100% HP + Odd Turns)",
        active_status="Active (100% maxHp + odd-turn auto-cast)",
        inner_zip=inner_zip,
        inspector=inspect_guild_raid_fire_support_assets,
        missing_archive_detail=(
            missing_detail or "assets/fwt_resources_v1.zip is missing; guildskilldata.unity3d unchecked"
        ),
        missing_status=missing_status,
    )

    asset_only_specs = (
        (
            "guild_raid_skills_max",
            "Guild Raid Skills Maxed (1M / 100%)",
            "Active (1M Shelling, 100% DR/HP/MP, 20 Dispels)",
            inspect_guild_raid_skills_max_assets,
        ),
        (
            "guild_raid_boss_no_counter",
            "Guild Raid Boss 0% Counter Rate",
            "Active (all 70 Guild Raid bosses at 0% counter rate)",
            inspect_guild_raid_boss_no_counter_assets,
        ),
        (
            "alex_rebalance",
            "Alex Skill, Passive & Awake Rebalance",
            "Active (Skills 1-3, Passive & Awake Thornbush)",
            inspect_alex_rebalance_assets,
        ),
    )
    if inner_zip is not None:
        for asset_key, asset_name, active_label, inspector_fn in asset_only_specs:
            try:
                active, details = inspector_fn(inner_zip)
                _feature(
                    features,
                    asset_key,
                    asset_name,
                    active,
                    active_label if active else "Original / Partial",
                    details,
                )
            except Exception as exc:
                _feature(
                    features,
                    asset_key,
                    asset_name,
                    False,
                    "Unknown",
                    f"Resource archive check failed: {exc}",
                )
    else:
        for asset_key, asset_name, _active_label, _inspector_fn in asset_only_specs:
            _feature(
                features,
                asset_key,
                asset_name,
                False,
                missing_status,
                missing_detail or "assets/fwt_resources_v1.zip is missing; client tables unchecked",
            )

    if inner_zip is not None:
        try:
            lb_profile, lb_details = inspect_limit_break_cost_assets(inner_zip)
            _reconcile_limit_break_reports(
                features,
                client_profile=lb_profile,
                client_details=lb_details,
            )
        except Exception as exc:
            _reconcile_limit_break_reports(
                features,
                client_profile=None,
                client_details=f"Resource archive check failed: {exc}",
                error_status="Unknown",
            )
    else:
        _reconcile_limit_break_reports(
            features,
            client_profile=None,
            client_details=missing_detail or "assets/fwt_resources_v1.zip is missing; client limit-break table unchecked",
            error_status=missing_status,
        )


def inspect_apk(apk_path: Path | str) -> InspectionReport:
    """Performs a comprehensive inspection of an APK file."""
    from core.axml import read_manifest_info
    from core.core_patches import DevOptions, validate_patch_options
    from core.version import BUILD_IDENTITY_ENTRY

    path = Path(apk_path)
    report = InspectionReport(file_path=str(path))

    if not path.is_file():
        report.error_message = "File does not exist"
        report.alignment_details = report.error_message
        return report

    report.file_size_mb = path.stat().st_size / (1024 * 1024)

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            report.is_valid_apk = True

            if names.count(BUILD_IDENTITY_ENTRY) == 1:
                identity = zf.read(BUILD_IDENTITY_ENTRY)
                if identity == b"dev":
                    report.build_identity = "dev"
                else:
                    try:
                        payload = json.loads(identity)
                        kind = payload["identity"]
                        recorded = payload["options"]
                        defaults = asdict(PatchOptions())
                        if not isinstance(recorded, dict) or recorded.keys() != defaults.keys():
                            raise ValueError("Invalid build option fields")
                        for key, default in defaults.items():
                            value = recorded[key]
                            if key == "dev":
                                if (not isinstance(value, dict) or value.keys() != default.keys()
                                        or any(type(value[k]) is not type(default[k]) for k in default)):
                                    raise ValueError("Invalid development options")
                            elif type(value) is not type(default):
                                raise ValueError(f"Invalid build option type: {key}")
                        recorded["dev"] = DevOptions(**recorded["dev"])
                        options = PatchOptions(**recorded)
                        validate_patch_options(options)
                        if kind not in ("release", "dev", "unverified"):
                            raise ValueError("Invalid build identity")
                        if kind == "release" and (options.dev.enabled or options.dev.any_instrumentation):
                            raise ValueError("Release declares development instrumentation")
                        report.build_identity = kind
                        report.build_options = options
                    except (ValueError, TypeError, KeyError, AttributeError):
                        pass
            try:
                manifest = read_manifest_info(zf.read("AndroidManifest.xml"))
                version_name = manifest.get("versionName")
                if manifest.get("debuggable") or (
                    isinstance(version_name, str) and version_name.endswith("-dev")
                ):
                    report.build_identity = "dev"
            except (KeyError, ValueError, IndexError, struct.error):
                # A missing or malformed manifest cannot establish release identity.
                if report.build_identity == "release":
                    report.build_identity = "unknown"

            so_data: bytes | None = None
            so_name = "lib/arm64-v8a/libfwt_local_server.so"
            if so_name in names:
                report.has_so = True
                so_data = zf.read(so_name)
                report.so_sha256 = hashlib.sha256(so_data).hexdigest()
                report.is_pristine_reference = report.so_sha256 == REFERENCE_SO_SHA256
                report.cave_overlap = detect_cave_overlap(so_data)
                report.features.update(inspect_native_so(so_data))
                if find_dev_build_marker(so_data):
                    report.build_identity = "dev"

            dex_name = "classes8.dex"
            if dex_name in names:
                report.has_dex = True
                dex_data = zf.read(dex_name)
                report.dex_sha256 = hashlib.sha256(dex_data).hexdigest()
                report.is_pristine_dex = report.dex_sha256 == REFERENCE_DEX_SHA256
                report.dex_checksum_valid, report.dex_checksum_details = verify_dex_checksums(
                    dex_data
                )
                report.features.update(inspect_dex(dex_data, so_data))

            resources_name = "assets/fwt_resources_v1.zip"
            if resources_name in names:
                try:
                    with (
                        zf.open(resources_name) as inner_file,
                        zipfile.ZipFile(inner_file) as inner_zip,
                    ):
                        _inspect_apk_resources(inner_zip, report.features)
                except Exception as exc:
                    # An unreadable resource archive must invalidate every
                    # feature that depends on its client-side tables.
                    _inspect_apk_resources(
                        None,
                        report.features,
                        missing_status="Unknown",
                        missing_detail=f"Resource archive check failed: {exc}",
                    )
            else:
                _inspect_apk_resources(None, report.features)
    except Exception as exc:
        report.is_valid_apk = False
        report.error_message = f"Failed to read APK: {exc}"
        report.alignment_details = report.error_message
        return report

    if not report.has_so and not report.has_dex:
        report.error_message = "APK does not contain libfwt_local_server.so or classes8.dex"

    # Check 16 KB alignment
    try:
        aligned_16k, align_msg = check_apk_alignment(path)
        report.alignment_16k = aligned_16k
        report.alignment_details = align_msg
    except Exception as exc:
        report.alignment_16k = False
        report.alignment_details = f"Alignment check failed: {exc}"

    # Check signatures
    try:
        is_signed, sig_msg = check_apk_signatures(path)
        report.is_signed = is_signed
        report.signature_details = sig_msg
    except Exception as exc:
        report.is_signed = False
        report.signature_details = f"Signature check failed: {exc}"

    return report


def expected_feature_keys(options: PatchOptions) -> dict[str, str]:
    """Maps requested patch options to inspector feature keys."""
    expected: dict[str, str] = {}
    if options.campaign_gold:
        expected["campaign_gold"] = "10x Campaign Gold & Drops"
    if options.campaign_xp:
        expected["campaign_xp"] = "10x Campaign XP"
    if options.no_equip_drops:
        expected["no_equip_drops"] = "Remove Equipment Drops"
    if options.gene_priority:
        expected["gene_priority"] = "Hero Gene Drop Priority"
    if options.summon_rates:
        expected["summon_rates"] = "Equipment Summon Rates (70/20/10)"
    if options.summon_rates_50_30_20:
        expected["summon_rates_50_30_20"] = "Equipment Summon Rates (50/30/20)"
    if options.expedition_bonus:
        expected["expedition_bonus"] = "10x Expedition Rewards"
    if options.english_localization:
        expected["english_localization"] = "English Localization"
        expected["dex_status_string"] = "Bootstrap Status String"
    if options.event_discount:
        expected["event_discount"] = "90% Event Shop Discount"
    if options.event_gene_unlimited:
        expected["event_gene_unlimited"] = "Unlimited Event Shop Genes"
    if options.event_limits_daily:
        expected["event_limits_daily"] = "Daily Event Shop Limits"
    if options.mythical_stone_shop:
        expected["mythical_stone_shop"] = "Mythical Stone Event Shop"
    if options.hero_shop_offers:
        expected["hero_shop_offers"] = "Evan and Alex Shop Offers"
    if options.surprise_transcendence_package:
        expected["surprise_transcendence_package"] = "Surprise Transcendence Package 2"
    if options.alex_awakening:
        expected["alex_awakening"] = "Alex Awakening: Destiny Lance"
    if options.alex_rebalance:
        expected["alex_rebalance"] = "Alex Skill, Passive & Awake Rebalance"
    if options.costume_packages_all:
        expected["costume_packages_all"] = "Complete Costume Packages"
    if options.recycle_six_star:
        expected["recycle_six_star"] = "Recycling Grants 6★ Equipment"
    if options.energy_flask_x10:
        expected["energy_flask_x10"] = "Energy Flask x10 Stamina"
    if options.option_max_attributes:
        expected["option_max_attributes"] = "Option Max Quality Rolls"
    if options.equipment_lock_fix:
        expected["equipment_lock_fix"] = "Equipment Option Locks"
    if options.equipment_single_mod_stone:
        expected["equipment_single_mod_stone"] = "One Modification Stone"
    if options.equipment_percent_options:
        expected["equipment_percent_options"] = "Percent-only Equipment Options"
    if options.equipment_upgrade_10_guarantee:
        expected["equipment_upgrade_10_guarantee"] = "+10 Upgrade Always Succeeds"
    if options.limit_break_cost_tenth:
        expected["limit_break_cost_tenth"] = "Limit Break Cost (90% Off)"
    if options.limit_break_cost_fixed:
        expected["limit_break_cost_fixed"] = "Limit Break Fixed Cost"
    if options.soulgear_enchant_always:
        expected["soulgear_enchant_always"] = "Soulgear Enchant Always Succeeds"
    # Bug fixes applied to every build, not options.
    expected["no_win_box"] = "Hide Phantom Win Boxes"
    expected["hero_exp_cap"] = "Hero EXP Cap & Limit Break Floor"
    if options.rune_box_random_type:
        expected["rune_box_random_type"] = "4★ Rune Box Random Type"
    if options.rune_quality_factor:
        expected["rune_quality_factor"] = "Rune Attribute Quality Factor"
    if options.rune_box_random_roll:
        expected["rune_box_random_roll"] = "Rune Box Random Slot/Type"
    if options.rune_option_quality:
        expected["rune_option_quality"] = "Rune Option Quality"
    if options.rune_upgrade_discount:
        expected["rune_upgrade_discount"] = (
            "Rune Upgrade +12..+15 (Guaranteed, 90% Off)"
        )
    if options.gold_cylinder_x10:
        expected["gold_cylinder_x10"] = "Gold Cylinder x10 Gold"
    if options.mana_cylinder_x10:
        expected["mana_cylinder_x10"] = "Mana Stone Compactor x10 Mana"
    if options.event_coin_x10:
        expected["event_coin_x10"] = "10x Campaign Event Coin Drop"
    if options.campaign_shop_discount:
        expected["campaign_shop_discount"] = "90% Campaign Shop Discount"
    if options.mode_drops_x10:
        expected["mode_drops_x10"] = "10x Mode Drops"
    if options.devil_boost_x10:
        expected["devil_boost_x10"] = "10x Devil's Soul EXP Boost"
    if options.battle_arena_fix:
        expected["battle_arena_fix"] = "Battle Arena Team Save Fix"
    if options.guild_raid_mercenary:
        expected["guild_raid_mercenary"] = "Guild Raid Self-Mercenary"
    if options.guild_raid_reward_x10:
        expected["guild_raid_reward_x10"] = "Guild Raid Reward x10"
    if options.guild_raid_score_fix:
        expected["guild_raid_score_fix"] = "Guild Raid 64-bit Scores (>2.5B)"
    if options.guild_raid_fire_support:
        expected["guild_raid_fire_support"] = (
            "Guild Raid Fire Support (100% HP + Odd Turns)"
        )
    if options.guild_raid_skills_max:
        expected["guild_raid_skills_max"] = "Guild Raid Skills Maxed (1M / 100%)"
    if options.guild_raid_boss_no_counter:
        expected["guild_raid_boss_no_counter"] = "Guild Raid Boss 0% Counter Rate"
    if options.single_black_hammer:
        expected["single_black_hammer"] = "Single Black Hammer (+16..+26)"
    if options.equipment_tier_upgrades:
        expected["equipment_tier_upgrades"] = "One Hammer per Equipment Tier"
    if options.single_gem_fang:
        expected["single_gem_fang"] = "Single Dragon Fang Opens All 3 Gem Slots"
    if options.upgrade_no_fail_above_20:
        expected["upgrade_no_fail_above_20"] = "No Upgrade Failure Above +20"
    if options.battle_arena_save_fix:
        expected["battle_arena_save_fix"] = "Battle Arena Save Button (client hook)"
    if options.sacred_lands_restore:
        expected["sacred_lands_restore"] = "Sacred Lands Set Restored"
    if options.coocoo_exp_x2:
        expected["coocoo_exp_x2"] = "Coocoo EXP x2 Always"
    if options.coocoo_level_x2:
        expected["coocoo_level_x2"] = "Coocoo Level x2"
    if options.ship_parts_90_off:
        expected["ship_parts_90_off"] = "90% Off Battleship Parts"
    if options.worldboss_full_ship_repair:
        expected["worldboss_full_ship_repair"] = "Unknown Paradise Full Ship Repair"
    if options.crystal_skill_90_off:
        expected["crystal_skill_90_off"] = "90% Off Core Crystal Upgrades"
    if options.gem_mining_x10:
        expected["gem_mining_x10"] = "Gems x10 (Mining)"
    if options.gem_mining_types:
        expected["gem_mining_types"] = "Gem Type Restriction"
    if options.gem_level6:
        expected["gem_level6"] = "Gems Level 6"
    if options.gem_upgrade_gold_half:
        expected["gem_upgrade_gold_half"] = "50% Off Gem Upgrade Gold"
    if options.stamina_cost_half:
        expected["stamina_cost_half"] = "50% Dungeon Stamina Cost"
    if options.stamina_potion_1000:
        expected["stamina_potion_1000"] = "Stamina Potion Restores 1000"
    if options.lan_redirect:
        expected["network_mode"] = "Network Mode"
        expected["dex_backup_prompt"] = "Save Backup Dialog"
    return expected


def verify_report(report: InspectionReport, options: PatchOptions) -> list[str]:
    """Returns human-readable problems for a built output APK."""
    problems: list[str] = []
    if not report.is_valid_apk:
        problems.append(report.error_message or "Output is not a valid APK")
        return problems
    if not report.has_so or not report.has_dex:
        problems.append("Output APK is missing libfwt_local_server.so or classes8.dex")
    if report.cave_overlap:
        problems.append("Legacy code-cave overlap detected (event coin vs. items trampoline)")

    for key, name in expected_feature_keys(options).items():
        feature = report.features.get(key)
        if feature is None or not feature.active:
            detail = feature.status if feature else "feature not found"
            problems.append(f"Requested feature is not active: {name} ({detail})")

    if options.rune_quality_factor:
        from core.core_patches import rune_quality_bonus

        feature = report.features.get("rune_quality_factor")
        expected_bonus = rune_quality_bonus(options.rune_quality_factor)
        if feature and feature.active and feature.value != expected_bonus:
            problems.append(f"Rune quality bonus differs: expected {expected_bonus}, got {feature.value}")
    if options.lan_redirect:
        feature = report.features.get("network_mode")
        expected_endpoint = (options.server_ip, options.server_port)
        if feature and feature.active and feature.value != expected_endpoint:
            problems.append(f"LAN endpoint differs: expected {expected_endpoint}, got {feature.value}")

    if options.align_16k and not report.alignment_16k:
        problems.append(f"16 KB alignment check failed: {report.alignment_details}")
    if not report.is_signed:
        problems.append(f"Output APK is not signed: {report.signature_details}")
    if report.has_dex and not report.dex_checksum_valid:
        problems.append(f"DEX checksum invalid: {report.dex_checksum_details}")
    return problems


def verify_release_report(report: InspectionReport) -> list[str]:
    """Reject unverified, incomplete or development artifacts for release."""
    problems = verify_report(report, report.build_options or PatchOptions())
    if report.build_identity != "release":
        problems.append(f"APK build identity is {report.build_identity}, not release")
    if report.build_options is None:
        problems.append("APK build options are missing or invalid")
    if not report.alignment_16k:
        problems.append(f"Release requires 16 KB alignment: {report.alignment_details}")
    if report.is_valid_apk and not any(
        feature.active for key, feature in report.features.items()
        if key not in {"no_win_box", "hero_exp_cap", "dev_build_marker"}
    ):
        problems.append("APK appears unpatched (no active gameplay patches detected)")
    return problems
