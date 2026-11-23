#!/usr/bin/env python3
"""FWT Reborn - Binary Core Patch Engine.

Applies deterministic byte modifications to the 0.682 offline client's native
ELF server binary (`libfwt_local_server.so`) and DEX bytecode (`classes8.dex`).
All routines operate purely on bytearrays without requiring an external C compiler
or Android NDK.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import struct
import zlib
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from core.alex_heros_mark import (
    ALEX_MARK_CLIENT_CAVE_MAX_SIZE,
    ALEX_MARK_CLIENT_CAVE_VADDR,
    ALEX_MARK_SERVER_CAVE_SIZE,
    ALEX_MARK_SERVER_CAVE_VADDR,
    apply_alex_heros_mark_so,
)
from core.convert_hex_guard import (
    CAVE_SIZE as CONVERT_HEX_GUARD_CAVE_SIZE,
)
from core.convert_hex_guard import (
    CAVE_VADDR as CONVERT_HEX_GUARD_CAVE_VADDR,
)
from core.convert_hex_guard import apply_convert_hex_guard
from core.costume_packages import CAVES as COSTUME_PACKAGE_CAVES
from core.costume_packages import apply_costume_packages
from core.dex_smali import (
    ResourceContract,
    ensure_apktool_jar,
    rebuild_dex,
)
from core.dungeon_recom_info import (
    CAVE_SIZE as DUNGEON_RECOM_INFO_CAVE_SIZE,
)
from core.dungeon_recom_info import (
    CAVE_VADDR as DUNGEON_RECOM_INFO_CAVE_VADDR,
)
from core.dungeon_recom_info import apply_dungeon_recom_info
from core.elf_mapping import canonicalize_segments, project_segments
from core.equipment_tier_upgrades import CAVES as EQUIPMENT_TIER_CAVES
from core.equipment_tier_upgrades import apply_equipment_tiers
from core.guild_raid_fire_support import (
    CAVE_SIZE as GUILD_RAID_FIRE_SUPPORT_CAVE_SIZE,
)
from core.guild_raid_fire_support import (
    CAVE_VADDR as GUILD_RAID_FIRE_SUPPORT_CAVE_VADDR,
)
from core.guild_raid_fire_support import apply_guild_raid_fire_support
from core.guild_raid_protection_persist import (
    CAVE_SIZE as GUILD_RAID_PROTECTION_PERSIST_CAVE_SIZE,
)
from core.guild_raid_protection_persist import (
    CAVE_VADDR as GUILD_RAID_PROTECTION_PERSIST_CAVE_VADDR,
)
from core.guild_raid_protection_persist import apply_guild_raid_protection_persist
from core.hero_shop_offers import apply_hero_shop_offers
from core.merlin_auto_support import (
    CAVE_SIZE as MERLIN_AUTO_SUPPORT_CAVE_SIZE,
)
from core.merlin_auto_support import (
    CAVE_VADDR as MERLIN_AUTO_SUPPORT_CAVE_VADDR,
)
from core.merlin_auto_support import (
    PRIORITY_CAVE_SIZE as MERLIN_AUTO_SUPPORT_PRIORITY_CAVE_SIZE,
)
from core.merlin_auto_support import (
    PRIORITY_CAVE_VADDR as MERLIN_AUTO_SUPPORT_PRIORITY_CAVE_VADDR,
)
from core.merlin_auto_support import (
    TAIL_CAVE_SIZE as MERLIN_AUTO_SUPPORT_TAIL_CAVE_SIZE,
)
from core.merlin_auto_support import (
    TAIL_CAVE_VADDR as MERLIN_AUTO_SUPPORT_TAIL_CAVE_VADDR,
)
from core.merlin_auto_support import apply_merlin_auto_support
from core.mythical_shop import apply_mythical_shop
from core.surprise_transcendence_package import apply_surprise_transcendence_package
from core.version import APP_VERSION

REFERENCE_SO_SHA256 = "03ec76a1d50e2406cb1ecd6f8bfdb532a3bc06452873b76fc52878fa56d14fd9"
REFERENCE_DEX_SHA256 = "02b57e29e743822eda63d43a23d1b4ddd64cb773135714043d3a1facd9b900af"

# Canonical ranges used by existing patch offsets, as (start, end, bias).
# The input ELF's PT_LOAD headers determine the actual file offsets before
# patching; canonical results are projected back to those input offsets.
# The fourth load segment is not used by these patches.
ELF_SEGMENTS = (
    (0x000000, 0x7D6C78, 0x0000),
    (0x7DAC80, 0x7DAC80 + 0x36E170, 0x4000),
    (0xB4CDF0, 0xB4CDF0 + 0x91EC0, 0x8000),
)

# Legacy aliases kept for external scripts; internal code uses seg_offset().
DELTA_TEXT = 0x4000
DELTA_RODATA = 0x8000

# ---------------------------------------------------------------------------
# Dev build constants
# Every dev artifact must carry this suffix; tools/create_distribution_zip.py
# and the CLI/GUI refuse to emit or package a dev build under any other name.
# ---------------------------------------------------------------------------
DEV_OUTPUT_SUFFIX = "-dev"
DEV_LOG_TAG_PREFIX = "FWTR-DEV"

# Dev instrumentation the patch engine actually implements.  Features are wired
# in phase by phase; anything requested through DevOptions but missing here is a
# no-op and is surfaced as a warning, so a dev build never pretends to
# instrument something it does not.
IMPLEMENTED_DEV_INSTRUMENTATION: frozenset[str] = frozenset(
    {
        "debuggable",
        "log_dispatch",
        "hit_counters",
        "build_marker",
        "handler_timing",
        "log_responses",
        "dev_endpoint",
    }
)


def is_dev_output_path(path: str | Path) -> bool:
    """True when the file name carries the dev marker anywhere in its stem.

    The marker is checked anywhere (not just at the end) because
    ``versioned_output_path`` appends the app version after it, producing names
    like ``FWT-Reborn-Patched-dev-2.5.26.apk``.
    """
    return DEV_OUTPUT_SUFFIX in Path(path).stem


def seg_offset(vaddr: int) -> int:
    """Map an address to the canonical reference-buffer offset.

    This replaces the old per-call ``- DELTA_TEXT``/``- DELTA_RODATA``
    Runtime patching first translates the input ELF into this canonical layout;
    callers operating on a raw ELF must use its parsed PT_LOAD mapping instead.
    """
    for start, end, delta in ELF_SEGMENTS:
        if start <= vaddr < end:
            return vaddr - delta
    raise ValueError(f"Address 0x{vaddr:x} is not in a file-backed ELF segment")

# ---------------------------------------------------------------------------
# Summon Rates Configuration
# In client pools: Category 3 = 4★, Category 4 = 5★, Category 5 = 6★ (Special)
# Two mutually exclusive profiles are available:
#   70/20/10 -> 4★ 70%, 5★ 20%, 6★ 10%
#   50/30/20 -> 4★ 50%, 5★ 30%, 6★ 20%
# ---------------------------------------------------------------------------
SUMMON_POOLS = (
    ("bonus", seg_offset(0xB9DFD0), 84, {3: 40, 4: 42, 5: 2}),
    ("normal", seg_offset(0xB9ECF0), 144, {1: 15, 2: 45, 3: 40, 4: 42, 5: 2}),
)
SUMMON_TARGETS = {3: 700_000, 4: 200_000, 5: 100_000}
SUMMON_TARGETS_50_30_20 = {3: 500_000, 4: 300_000, 5: 200_000}

# ---------------------------------------------------------------------------
# Expedition Bonus Configuration
# ---------------------------------------------------------------------------
EXPEDITION_TABLE = seg_offset(0xBC42D0)
EXPEDITION_ROW_SIZE = 120
EXPEDITION_REGIONS = (
    257, 258, 259, 260, 261, 262, 263, 264, 265, 272,
    273, 275, 276, 277, 278, 279, 280, 281, 288,
)
# ---------------------------------------------------------------------------
# Campaign Common Table Configuration
# ---------------------------------------------------------------------------
STAGE_TABLE_OFFSET = 0x71D900
STAGE_ROW_SIZE = 140
STAGE_ROW_COUNT = 942
CAMPAIGN_PREFIXES = ("10", "11", "12")
GENE_PREFIXES = ("10", "11", "12", "80", "81")
GENE_OTHER_WEIGHT_COLS = (4, 7, 10, 12, 14, 26, 31)


def _stage_prefix(stage_id: int) -> str:
    """Returns the two-hex-digit map prefix of a stage id.

    ``f"{stage_id:06x}"`` does not truncate values wider than 24 bits, which
    made two features classify the same row differently.
    """
    return f"{(stage_id >> 16) & 0xFF:02x}"

# Field indexes in the 35-int stage row. The server builds a single weighted
# pool from these chances; removing equipment means redistributing its weight
# across the remaining eligible categories.
STAGE_GOLD_WEIGHT = 4
STAGE_MANASTONE_WEIGHT = 7
STAGE_EQUIP_WEIGHT = 10
STAGE_MONSTER_WEIGHT = 14
STAGE_MONSTER_TABLE = 16
STAGE_ITEM_WEIGHT = 26
STAGE_ITEM_TABLE = 28
STAGE_GENE_WEIGHT = 22
STAGE_GENE_ID = 23
STAGE_ENERGY_WEIGHT = 31
STAGE_ENERGY_VALUE = 32

# ---------------------------------------------------------------------------
# Campaign Gold & Drops Trampoline Hooks
# ---------------------------------------------------------------------------
# The old cave at 0xAA6BFC is NOT free: it is the entry of the exported
# fwt_egl_swap_buffers_clear_compat function, which Unity calls during
# startup. The trampolines now live in an unreferenced libc++ demangler
# function at 0xB33314 (size 0x538). Static analysis found no direct branch,
# ADRP+ADD reference, data pointer or vtable entry to this function. The
# reference SHA-256 check still guards version drift.
CAMPAIGN_CAVE_BASE = 0xB33314
# The item trampoline moved to the free tail of the demangler cave so it can
# hold the extra Nephthys/Lost Island prefix checks without overlapping the
# event-coin/expedition/dimension caves.
ITEM_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0x420
ITEM_CAVE_FIRST_SIZE = 72
ITEM_CAVE_SECOND_SIZE = 40
ITEM_CAVE_SIZE = ITEM_CAVE_FIRST_SIZE + ITEM_CAVE_SECOND_SIZE
CAMPAIGN_CAVE_LAYOUT = (
    ("gold", CAMPAIGN_CAVE_BASE + 0x00, 52),
    ("gene", CAMPAIGN_CAVE_BASE + 0x34, 36),
    ("mana", CAMPAIGN_CAVE_BASE + 0x58, 52),
    ("items", ITEM_CAVE_VADDR, ITEM_CAVE_SIZE),
)

# Free 16-byte gap between the mana cave (ends at +0x8C) and the Guild Raid
# client cave (+0x110).  Four words are used as explicit idempotence flags so a
# second pass over an already patched library is a no-op even for features that
# do not install a hook (campaign XP, shop discounts).
PATCH_FLAG_VADDR = CAMPAIGN_CAVE_BASE + 0x100
PATCH_FLAG_SIZE = 16
CAMPAIGN_XP_FLAG = (0x00, b"FXP1")
EVENT_DISCOUNT_FLAG = (0x04, b"FEV1")
CAMPAIGN_SHOP_FLAG = (0x08, b"FCS1")

# Jump targets: hook site -> offset inside CAMPAIGN_CAVE_BASE.
CAMPAIGN_HOOK_TARGETS = {
    0xA2C46C: 0x00,  # gold, first segment (sets stack flag)
    0xA2C9A0: 0x1C,  # gold, second segment (multiplies rolled gold by 10)
    0xA2CC44: 0x34,  # gene (multiplies rolled genes by 10)
    0xA2C644: 0x58,  # mana, first segment
    0xA2CAD0: 0x78,  # mana, second segment (multiplies rolled mana by 10)
    0xA2D0D4: ITEM_CAVE_VADDR - CAMPAIGN_CAVE_BASE,  # items, first segment
    0xA2D6C4: ITEM_CAVE_VADDR - CAMPAIGN_CAVE_BASE + ITEM_CAVE_FIRST_SIZE,  # items, second
}

# Original instructions at each campaign trampoline hook site. These are
# checked before overwriting so a non-reference binary fails loudly instead
# of silently corrupting unrelated code.
CAMPAIGN_HOOK_ORIGINALS = {
    0xA2C46C: bytes.fromhex("35eb4229"),
    0xA2C9A0: bytes.fromhex("36c1288b"),
    0xA2CC44: bytes.fromhex("77c69f9a"),
    0xA2C644: bytes.fromhex("356b4429"),
    0xA2CAD0: bytes.fromhex("36c1288b"),
    0xA2D0D4: bytes.fromhex("15017ab9"),
    0xA2D6C4: bytes.fromhex("33c1288b"),
}

# Reference-build SHA-256 digests of the free cave slots overwritten by the
# campaign 10x trampolines so --force on a mismatched binary fails loudly.
CAMPAIGN_CAVE_ORIGINAL_SHA256 = {
    CAMPAIGN_CAVE_BASE + 0x00: "ef11db5b3b960e661107579e1535eabd97c2039a999adaf0eb737310c57d06e5",
    CAMPAIGN_CAVE_BASE + 0x34: "532f9734ae423d9ae07f376535b2b0ce41979d45482e9a35a9a17bb0c655f254",
    CAMPAIGN_CAVE_BASE + 0x58: "f16fdfe873df95e00aabe45e6bf9bd9a773d8e02d2708e987c10e464a20f096f",
    ITEM_CAVE_VADDR: "13136a1995d0f551a0ffdc068ae35f42ad9fd5871ae0ead3fbd9cba1b707e6ea",
}

# Generated after encode_arm64_branch() is defined below.
CAMPAIGN_HOOKS: dict[int, bytes] = {}

# ---------------------------------------------------------------------------
# Laboratory Timers
# ---------------------------------------------------------------------------
# The laboratory has four tools.  Tool type 1 is the Gold Cylinder
# (single production, 21,600s / 6h).  Tool type 2 is the Mana Stone Compactor,
# which accumulates up to five charges and uses 7,200s (2h) per charge in the
# reference client.  Tool type 3 is the daily Energy Flask (fixed 3h windows)
# and type 4 is the Genetic Analyzer.  The historical "flask 3h" name is kept
# for compatibility, but the sites below target tool type 2 (Mana Stone).
# The original "flask 3h" patch changed the four 21,600s Gold sites, which made
# the Gold Cylinder show 50% after collection and left the 5-charge tool
# untouched.  The sites below change 7,200s to 10,800s (3h); the Gold sites are
# restored separately by gold_cylinder_fix.
FLASK_3H_SITES = (
    (0xA63904, 0x5283840C, 0x5285460C),  # refresh: mov w12, #7200 -> #10800
    (0xA6390C, 0x52838408, 0x52854608),  # refresh: mov w8, #7200 -> #10800
    (0xA6649C, 0x52838402, 0x52854602),  # use:     mov w2, #7200 -> #10800
)
GOLD_CYLINDER_SITES = (
    (0xA63708, 0x528A8C08, 0x52854608),  # refresh: mov w8, #21600 (Gold)
    (0xA6517C, 0x528A8C09, 0x52854609),  # use:     mov w9, #21600 (Gold)
    (0xA651E8, 0x528A8C08, 0x52854608),  # use:     mov w8, #21600 (Gold)
    (0xA653DC, 0x528A8C02, 0x52854602),  # use:     mov w2, #21600 (Gold)
)

# ---------------------------------------------------------------------------
# Laboratory cylinder yield x10
# ---------------------------------------------------------------------------
# ``laboratory_use_fields`` (0xA64D88) stores a per-level reward base and then
# prorates it by the elapsed charge time.  The Gold Cylinder path builds
# ``(level * 10000) + 10000`` at 0xA65178; the Mana Stone Compactor builds
# ``level * 20 + 60`` at 0xA65868/0xA6586C.  Scaling those constants multiplies
# the collected gold/mana by ten (the same value is also added to the tool's
# internal level XP, which levels the tool faster).
GOLD_CYLINDER_X10_SITE = 0xA65178
GOLD_CYLINDER_X10_ORIGINAL = bytes.fromhex("08e28452")  # mov w8, #0x2710
GOLD_CYLINDER_X10_CAVE_VADDR = 0xB34CD8
GOLD_CYLINDER_X10_CAVE_SIZE = 12
GOLD_CYLINDER_X10_CAVE_ORIGINAL_SHA256 = (
    "c403d4d2c3d39ed70ce58b51cbdcc6f52f23178d0da359cc81b64030c36bdb28"
)
GOLD_CYLINDER_X10_RETURN_VADDR = 0xA6517C

MANA_CYLINDER_X10_SITES = (
    (0xA6585C, 0x52800289, 0x52801909),  # mov w9, #0x14  -> #0xc8
    (0xA65868, 0x5280078B, 0x52804B0B),  # mov w11, #0x3c -> #0x258
)

# ---------------------------------------------------------------------------
# Event Shop Daily Gene Limit
# ---------------------------------------------------------------------------
# The embedded shop catalog restricts hero gene rows (item_category 18) to
# 100 purchases per day.  The client treats 255 as the "no limit" sentinel
# (the catalog already uses 255/255 for unlimited products).  The replacement
# keeps the JSON length identical; limit_max=9 is ignored for type 255.
EVENT_GENE_ITEM_CATEGORY = b'"item_category":18'
EVENT_GENE_LIMIT_PATTERN = re.compile(rb'"limit_type":\s*1,\s*"limit_max":\s*(?:100|999)')
EVENT_GENE_LIMIT_REPLACEMENT = b'"limit_type":255,"limit_max":9'
EXPECTED_EVENT_GENE_ROWS = 33

# Event Shop "Lifely" limits (limit_type=3) never reset.  Changing them to
# limit_type=1 (daily) preserves limit_max and makes the same quantity
# purchasable again after the daily reset.  Every type-4 row (event/Honor
# period) is converted too: those rows were previously left on the event
# cycle and kept blocking purchases after the shop refreshed.
EVENT_LIMIT_TYPE_PATTERN = re.compile(rb'"limit_type":3(?![0-9])')
EVENT_SHOP_TYPE_4_PATTERN = re.compile(rb'"limit_type":4(?![0-9])')
EVENT_LIMIT_TYPE_REPLACEMENT = b'"limit_type":1'
# The shop period key treats limit_type=4 as an event-period key that only
# advances with the event cycle.  Branching straight to the generic key path
# makes type 4 use the daily %Y-%m-%d key instead (types 1/2/3 are unchanged).
EVENT_LIMIT_PERIOD_SITE = 0x98B500
EVENT_LIMIT_PERIOD_ORIGINAL = bytes.fromhex("81090054")  # b.ne #0x98b630
EVENT_LIMIT_PERIOD_TARGET = 0x98B630
# ``shop_buy_counts`` is a lifetime counter: advancing the period key alone
# does not clear it.  The count lookup receives the shop/item code as a
# std::string; event-shop codes (699xx/703xx) return zero so a refreshed event
# row is purchasable again instead of staying at "limit reached" forever.
EVENT_LIMIT_COUNT_HOOK_SITE = 0x88091C
EVENT_LIMIT_COUNT_HOOK_ORIGINAL = bytes.fromhex("f30301aaf40300aa")
EVENT_LIMIT_COUNT_CAVE_VADDR = 0xB34CE4
EVENT_LIMIT_COUNT_CAVE_SIZE = 96
EVENT_LIMIT_COUNT_CAVE_ORIGINAL_SHA256 = (
    "1fc3cc2a221696c7a4ab83c8a454f56049264bcb1afe10be34218f3adcda49e4"
)
EXPECTED_EVENT_LIMIT_ROWS = 1224 + 199

# ---------------------------------------------------------------------------
# Campaign Event Coin 10x Trampoline Hook
# ---------------------------------------------------------------------------
# 0x8D05B8 is only the string-cleanup branch; the common return path is
# 0x8D05C0 (`mov x0, x19`). Hooking there makes the 10x apply unconditionally.
EVENT_COIN_HOOK_VADDR = 0x8D05C0
EVENT_COIN_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0xC8
EVENT_COIN_CAVE_SIZE = 16
EVENT_COIN_CAVE_ORIGINAL_SHA256 = (
    "40f349acb20167db05e6f12f53d49d23d23bc0b6afa49cbd0bbd79ca8968fa30"
)
EVENT_COIN_RETURN_VADDR = 0x8D05C4
EVENT_COIN_OLD_HOOK_VADDR = 0x8D05B8
EVENT_COIN_OLD_HOOK_ORIGINAL = bytes.fromhex("02000014")  # b 0x8D05C0
EVENT_COIN_OLD_CAVE_VADDR = 0xAA6CAC

# ---------------------------------------------------------------------------
# Expedition 10x Trampoline Cave & Call Sites
# ---------------------------------------------------------------------------
EXPEDITION_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0xD8
EXPEDITION_CAVE_SIZE = 28
EXPEDITION_CAVE_ORIGINAL_SHA256 = (
    "cef00669114ab5626ce4abde7ae5e5d1e9e8af5d1ecce62369833346196260ef"
)
EXPEDITION_CALL_SITES = (0x94595C, 0x945A48, 0x945AD8, 0x94606C, 0x946264)
EXPEDITION_LEGACY_RESTORATIONS = {
    0x945960: (bytes.fromhex("13f87fd3"), bytes.fromhex("f30300aa")),  # lsl x19, x19, #1 -> mov x19, x0
    0x945A4C: (bytes.fromhex("19f87fd3"), bytes.fromhex("f90300aa")),  # lsl x25, x25, #1 -> mov x25, x0
    0x945ADC: (bytes.fromhex("1af87fd3"), bytes.fromhex("fa0300aa")),  # lsl x26, x26, #1 -> mov x26, x0
    0x946070: (bytes.fromhex("02f87fd3"), bytes.fromhex("e20300aa")),  # lsl x2, x2, #1 -> mov x2, x0
    0x946268: (bytes.fromhex("02f87fd3"), bytes.fromhex("e20300aa")),  # lsl x2, x2, #1 -> mov x2, x0
}

# ---------------------------------------------------------------------------
# Mode Drops 10x (Dimension Breakthrough & World Boss)
# ---------------------------------------------------------------------------
DIMENSION_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0xF4
DIMENSION_CAVE_SIZE = 12
DIMENSION_CAVE_ORIGINAL_SHA256 = (
    "bd112a7ecf0e41eed7ff808031fd5973bbaf8592b63008ac535f826be2c213ea"
)
DIMENSION_DROP_SITE = 0x94B528
DIMENSION_DROP_ORIGINAL = bytes.fromhex("e00313aa")  # mov x0, x19

WORLDBOSS_CYCLE_REWARD_VADDR = 0x75EB90
WORLDBOSS_CYCLE_REWARD_ROW_SIZE = 48
WORLDBOSS_CYCLE_REWARD_ROW_COUNT = 58
WORLDBOSS_CYCLE_REWARD_TARGET_TYPES = frozenset({1, 2, 3})
WORLDBOSS_CYCLE_REWARD_TARGET_COUNT = 22
WORLDBOSS_CYCLE_REWARD_GOLD_RES = 2
WORLDBOSS_CYCLE_REWARD_ITEM_RES = 17
WORLDBOSS_CYCLE_REWARD_GOLD_STOCK_MAX = 5_000_000
WORLDBOSS_CYCLE_REWARD_ITEM_STOCK_MAX = 400
WORLDBOSS_CYCLE_REWARD_PATCHED_SHA256 = (
    "dd18a74807bc403b617782642c15a7872c84cc9c834700afac2e28252599c396"
)
WORLDBOSS_KRAKEN_SCALE_CODE = 280001

# Daily Unknown Paradise fixed Kraken Scale cave (apply_accepted_settlement
# 0x8E69F4 -> 0xB2AB00): grants 500x item 280001 per fight (500 + 500 = 1000/day)
# directly to inventory and writes FirstClearRewardPayload.reward_item so Days 1-4
# and 2nd attacks display the drop instead of an empty box.
WORLDBOSS_DAILY_KRAKEN_SITE = 0x8E69F4
WORLDBOSS_DAILY_KRAKEN_ORIGINAL = bytes.fromhex("e00313aa")  # mov x0, x19
WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR = 0xB2AB00
WORLDBOSS_DAILY_KRAKEN_CAVE_SIZE = 192
WORLDBOSS_DAILY_KRAKEN_CAVE_ORIGINAL_SHA256 = (
    "c95afef24992299e6aeb975fc415d5aedbcb739292164074fadf28d0b4c1d5a2"
)
WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES = bytes.fromhex(
    "d9050036ff0302d1fd7b06a9fd830191884186d20807a6f20806c6f22806e0f2"
    "e80300f9ffff00a988228dd288aeacf2a8edcbf268ecedf2a9ce8dd2890ea0f2"
    "e8a701a9ff1700f9c8a086d20806a6f2e81b00f9ffff03a9ffff04a9ff2f00f9"
    "e8230191e00313aae1030091823e805241acf897e0230191e1630091e2c30091"
    "2858f597c802433968000036c06a40f9d46c0094e82740f9e92b40f9ea2f40f9"
    "c8260ca9ca6a00f928008052c8220739fd7b46a9ff030291e00313aa8feff617"
)

WORLDBOSS_REWARD_CLIENT_ASSETS = (
    "files/Resources/datatable/worldbossreward.unity3d",
    "files/Resources/datatable/worldbossrewardchinese.unity3d",
    "files/Resources/datatable/worldbossrewardenglish.unity3d",
    "files/Resources/datatable/worldbossrewardgerman.unity3d",
    "files/Resources/datatable/worldbossrewardjapanese.unity3d",
    "files/Resources/datatable/worldbossrewardspanish.unity3d",
    "files/Resources/datatable/worldbossrewardthai.unity3d",
)

# Event 10002 at 0x75F6C0 is the Unknown Paradise Mobile Repair Shop row
# `(65538, 2, 255, -1, -1, -1)` (`row_type == 2`).  WORLDBOSS_RESULT_EVENT
# checks `row_type == 2` at 0x849328 to open `worldboss_travel_repair_offer`;
# overwriting it with a type-3 item reward locks Instant Repair and completes
# the event immediately, so keep this row untouched (and repair older builds).
WORLDBOSS_EVENT_REWARD_SITE = 0x75F6C0
WORLDBOSS_EVENT_REWARD_ORIGINAL = struct.pack("<6i", 65538, 2, 255, -1, -1, -1)
WORLDBOSS_EVENT_REWARD_REPLACEMENT = struct.pack("<6i", 65538, 3, 17, 2621441, 50, 100)

# PvP win reward: the embedded server grants and displays 6 Honor Coins from a
# hardcoded immediate in the result handler. The old asset-only patch changed
# the client preview table but not this server-side grant.
HONOR_COIN_COUNT_SITE = 0x83FCF0
HONOR_COIN_COUNT_ORIGINAL = bytes.fromhex("db008052")  # mov w27, #6
HONOR_COIN_COUNT_REPLACEMENT = bytes.fromhex("9b078052")  # mov w27, #60

# PvP rank points: pvp_score_delta returns the per-match score change.  A trampoline
# at its return instruction sets the delta to 100 for victories only.
HONOR_POINTS_DELTA_SITE = 0x95563C
HONOR_POINTS_DELTA_ORIGINAL = bytes.fromhex("2001781e")  # fcvtzs w0, d9
HONOR_POINTS_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0x524
HONOR_POINTS_CAVE_SIZE = 0x14
HONOR_POINTS_CAVE_ORIGINAL_SHA256 = (
    "54a4c5648dc0dcf3358a875aca813adb76ed0a4eb76f1961cba7bcbaf1f4ab79"
)
HONOR_POINTS_CAVE_BYTES = bytes.fromhex(
    "2001781e"  # fcvtzs w0, d9           (original score delta)
    "7f020072"  # tst  w19, #1            (win flag)
    "880c8052"  # mov  w8, #100
    "0011801a"  # csel w0, w8, w0, ne
    "7e87f817"  # b    0x955640
)

# Dimension Breakthrough genes: the native roll is very low. Skip the chance
# gate and multiply the rolled gene count by ten.
DIMENSION_GENE_GUARANTEE_SITE = 0x83C1E4
DIMENSION_GENE_GUARANTEE_ORIGINAL = bytes.fromhex("132d0036")  # tbz w19,#0,skip
DIMENSION_GENE_GUARANTEE_REPLACEMENT = bytes.fromhex("1f2003d5")  # nop
DIMENSION_GENE_COUNT_SITE = 0x83C25C
DIMENSION_GENE_COUNT_ORIGINAL = bytes.fromhex("e2031baa")  # mov x2, x27
DIMENSION_GENE_COUNT_RETURN_VADDR = 0x83C260
DIMENSION_GENE_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0x490
DIMENSION_GENE_CAVE_SIZE = 12
DIMENSION_GENE_CAVE_ORIGINAL_SHA256 = (
    "13dbe8ad663ee4d921538e515458c64809126dba39960853c80b83382e10f0af"
)

NEPHTHYS_STAGE_PREFIXES = ("70", "71")
LOST_ISLAND_STAGE_PREFIXES = ("80", "81")

RIDDLE_TABLE_OFFSET = 0x755564
RIDDLE_ROW_SIZE = 28
RIDDLE_ROW_COUNT = 156

# ---------------------------------------------------------------------------
# Battle Arena Save Bug Fix Sites
# ---------------------------------------------------------------------------
ARENA_WEEK_STATE_SITES = (
    (0x95C698, bytes.fromhex("140380b9"), bytes.fromhex("14278079")),  # ldrsw x20, [x24] -> ldrsh x20, [x24, #0x12]
    (0x95C750, bytes.fromhex("000340b9"), bytes.fromhex("00274079")),  # ldr w0, [x24] -> ldrh w0, [x24, #0x12]
    (0x95CAB0, bytes.fromhex("000340b9"), bytes.fromhex("00274079")),  # ldr w0, [x24] -> ldrh w0, [x24, #0x12]
)
ARENA_EMPTY_SLOT_SITE = 0x8B5288
ARENA_EMPTY_SLOT_ORIGINAL = bytes.fromhex("bf0600b160ffff54")  # cmn x21, #1; b.eq #0x8b5278
ARENA_EMPTY_SLOT_REPLACEMENT = bytes.fromhex("bf0200f16dffff54")  # cmp x21, #0; b.le #0x8b5278

# ARENA_SET_ATTACK_TEAM handler validation: the client sends eight attack
# members (four pairs) and four defence leaders, but the handler requires eight
# values for the defence vector both in the size check (cmp x8, #0x40 at
# 0x841BA0) and in valid_owned_team_json (w2=8 at 0x8425A0).  The mismatch made
# every arena save fail with ERROR_NOT_ENOUGH_JEWELRY (-101).
ARENA_DEFENCE_SIZE_SITE = 0x841BA0
ARENA_DEFENCE_SIZE_ORIGINAL = bytes.fromhex("1f0101f1")  # cmp x8, #0x40
ARENA_DEFENCE_SIZE_REPLACEMENT = bytes.fromhex("1f8100f1")  # cmp x8, #0x20
ARENA_DEFENCE_COUNT_SITE = 0x8425A0
ARENA_DEFENCE_COUNT_ORIGINAL = bytes.fromhex("02018052")  # mov w2, #8
ARENA_DEFENCE_COUNT_REPLACEMENT = bytes.fromhex("82008052")  # mov w2, #4
# ARENA_SET_ATTACK_TEAM also runs exact_json_object_field_set against an
# auth-only schema {CMD, packet_no, lord_idx, access_code}; the real request
# carries attack_teams/def_arena_force/defence_teams too, so the gate failed
# with -101 before the teams were parsed.  NOP the failure branch.
ARENA_SCHEMA_GATE_SITE = 0x841AC8
ARENA_SCHEMA_GATE_ORIGINAL = bytes.fromhex("a01f0036")  # tbz w0,#0,#0x841ebc
ARENA_SCHEMA_GATE_REPLACEMENT = bytes.fromhex("1f2003d5")  # nop

# The client sends the four PvP teams as eight members (four pairs), while the
# native server stores only the four team leaders.  Compact each 8-value vector
# to its leaders before the original length check.  This is the actual save
# path used by the Battle Arena / Battle of Honor team screen.
PVP_TEAM_COMPACT_ATTACK_HOOK = 0x83A384
PVP_TEAM_COMPACT_ATTACK_ORIGINAL = bytes.fromhex("e8bf44f9")  # ldr x8,[sp,#0x978]
PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR = 0xAC81B0
PVP_TEAM_COMPACT_ATTACK_CAVE_SIZE = 0x48
PVP_TEAM_COMPACT_ATTACK_CAVE_ORIGINAL_SHA256 = (
    "d5f5fe6a13755fc441bfdb3303da8d2a14568d1228d6869f0f5be34444af64a6"
)
PVP_TEAM_COMPACT_ATTACK_CAVE_BYTES = bytes.fromhex(
    "e8bf44f9"  # ldr  x8,[sp,#0x978]
    "e9bb44f9"  # ldr  x9,[sp,#0x970]
    "0a0109cb"  # sub  x10,x8,x9
    "5f0101f1"  # cmp  x10,#0x40
    "21010054"  # b.ne normal
    "2b0940f9"  # ldr  x11,[x9,#0x10]
    "2b0500f9"  # str  x11,[x9,#0x08]
    "2b1140f9"  # ldr  x11,[x9,#0x20]
    "2b0900f9"  # str  x11,[x9,#0x10]
    "2b1940f9"  # ldr  x11,[x9,#0x30]
    "2b0d00f9"  # str  x11,[x9,#0x18]
    "28810091"  # add  x8,x9,#0x20
    "e8bf04f9"  # str  x8,[sp,#0x978]
    "080109cb"  # normal: sub x8,x8,x9
    "1f8100f1"  # cmp  x8,#0x20
    "40000054"  # b.eq success
    "59cbf517"  # b    0x83AF54
    "69c8f517"  # success: b 0x83A398
)

PVP_TEAM_COMPACT_DEFENSE_HOOK = 0x83A21C
PVP_TEAM_COMPACT_DEFENSE_ORIGINAL = bytes.fromhex("e8534cf9")  # ldr x8,[sp,#0x18a0]
PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR = 0xAC8200
PVP_TEAM_COMPACT_DEFENSE_CAVE_SIZE = 0x38
PVP_TEAM_COMPACT_DEFENSE_CAVE_ORIGINAL_SHA256 = (
    "fe554a1da550f85472e9c02d33e98995256c4d21bc5c56c486ac6b19de3790d0"
)
PVP_TEAM_COMPACT_DEFENSE_CAVE_BYTES = bytes.fromhex(
    "e9574cf9"  # ldr  x9,[sp,#0x18a8]
    "e8534cf9"  # ldr  x8,[sp,#0x18a0]
    "2a0108cb"  # sub  x10,x9,x8
    "5f0101f1"  # cmp  x10,#0x40
    "21010054"  # b.ne check
    "0b0940f9"  # ldr  x11,[x8,#0x10]
    "0b0500f9"  # str  x11,[x8,#0x08]
    "0b1140f9"  # ldr  x11,[x8,#0x20]
    "0b0900f9"  # str  x11,[x8,#0x10]
    "0b1940f9"  # ldr  x11,[x8,#0x30]
    "0b0d00f9"  # str  x11,[x8,#0x18]
    "09810091"  # add  x9,x8,#0x20
    "e9570cf9"  # str  x9,[sp,#0x18a8]
    "fcc7f517"  # check: b 0x83A224
)

# ---------------------------------------------------------------------------
# Coocoo Garden / Pit of Nephthys Experience Creature Level
# ---------------------------------------------------------------------------
# The 30 coocoo reward stages (700010..700100, 701010..701100 and
# 702010..702100) store the dropped coocoo level in the stage table at row
# offsets +68/+72. The 702xxx tier is the Pit of Nephthys tier; leaving it
# untouched makes the post-reset reward fall back to level 220. The native
# level cap in the late stages is 220; doubling the stored min/max produces
# four level-440 coocoos on the final stage of every tier.
COOCOO_STAGE_TABLE_OFFSET = 0x735488
COOCOO_STAGE_ROW_SIZE = 140
COOCOO_STAGE_LEVEL_OFFSET = 68
COOCOO_STAGE_LEVELS = (
    2,
    4,
    8,
    20,
    60,
    100,
    130,
    150,
    185,
    220,
    2,
    4,
    8,
    20,
    60,
    100,
    130,
    150,
    185,
    220,
    2,
    4,
    8,
    20,
    60,
    100,
    130,
    150,
    185,
    220,
)

# ---------------------------------------------------------------------------
# Unknown Paradise: Battleship Parts & Core Crystal Upgrades
# ---------------------------------------------------------------------------
# Finish timed repair at max HP, restore a full HP bar at the shop (the
# setter clamps the result), and revive with 100% of the calculated max HP.
WORLDBOSS_FULL_SHIP_REPAIR_SITES = (
    (0x976048, bytes.fromhex("1801168b"), bytes.fromhex("f80315aa")),  # mov x24, x21
    (0x849D60, bytes.fromhex("01dd44fd"), bytes.fromhex("01106e1e")),  # fmov d1, #1.0
    (0x97704C, bytes.fromhex("01106a1e"), bytes.fromhex("01106e1e")),  # fmov d1, #1.0
)

# `worldboss_ship_part_gold_cost` (0x977FB8) reads three int64 cost arrays in
# .rodata.  .rodata has vaddr == file offset (delta 0), so the addresses below
# are also the byte offsets used by the patcher.
SHIP_PART_COST_TABLES = (
    (
        0x75F790,
        (
            5000,
            10000,
            15000,
            20000,
            25000,
            42000,
            59000,
            76000,
            93000,
            110000,
            161000,
            212000,
            263000,
            314000,
            365000,
            501000,
            637000,
            773000,
            909000,
            1045000,
            1317000,
            1589000,
            1861000,
            2134000,
            2405000,
            2949000,
            3493000,
            4037000,
            4580000,
            0,
        ),
    ),
    (
        0x75F880,
        (417000, 833000, 1250000, 2083000, 2917000, 3750000, 5000000, 6250000, 7500000, 0),
    ),
    (
        0x75F950,
        (2308000, 6923000, 20769000, 0),
    ),
)
SHIP_PART_COST_FIELD_SIZE = 8

# `WORLDBOSS_SHIP_SKILL_LEVELUP` charges 50 Kraken Scales (item code 280001)
# per crystal skill level.  The 90% discount reduces that immediate to 5.
CRYSTAL_SKILL_COST_SITE = 0x84A2C0
CRYSTAL_SKILL_COST_ORIGINAL = bytes.fromhex("42068052")  # mov w2, #0x32
CRYSTAL_SKILL_COST_REPLACEMENT = bytes.fromhex("a2008052")  # mov w2, #5

# ---------------------------------------------------------------------------
# Guild Raid Offline Self-Mercenary Selection
# ---------------------------------------------------------------------------
GUILD_RAID_MERCENARY_SITE = 0x930100
# 0x9302BC is `mov w8,#1 ; strb w8,[x19]` followed by the register restores, so jumping
# here both marks the projection valid and returns; 0x9302C4 is the bare epilogue and
# would leave valid == 0 (the handler then answers ERROR=-101).
GUILD_RAID_MERCENARY_EPILOGUE = 0x9302BC
GUILD_RAID_MERCENARY_FALLTHROUGH = 0x930104  # normal path continues here for real hires
GUILD_RAID_FRIEND_SOLDIER_JSON = 0xA6B304
GUILD_RAID_HIRED_IDENTITY_JSON = 0xA6AE64
GUILD_RAID_FRIEND_COSTUME_JSON = 0x8D9F68
GUILD_RAID_FRIEND_EQUIPS_JSON = 0x8DA1DC
GUILD_RAID_MERCENARY_ORIGINAL = bytes.fromhex("200e0054")  # b.eq #0x9302c4
# Self projection cave: unconditionally substitutes the player's own mercenary
# from the save (guild_hired_soldier_info.<weekday>_crs_idx), filtering live
# ownership lists; a missing or invalid hero uses the selected stock hire.
GUILD_RAID_MERCENARY_CAVE_VADDR = 0xB34860  # dead demangler function, 1816 B free
# The guild raid mercenary list skips the player: UpdateListMember compares the
# member lord with LordData.get_lordID and branches to the skip path
# (0x1EE5220: b.eq 0x1EE531C).  NOP it from a post-covault hook so the player
# shows up in the hire list.
GUILD_RAID_MERCENARY_CLIENT_HOOK = 0xAB3380
GUILD_RAID_MERCENARY_CLIENT_HOOK_ORIGINAL = bytes.fromhex("f44f45a9")  # ldp x20,x19,[sp,#0x50]
GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0x3C4  # 0xB336D8
GUILD_RAID_MERCENARY_CLIENT_CAVE_ORIGINAL_SHA256 = (
    "bf1883efcf2eb2d7f1adadd035e82cdfe114f34d3a5f330d2e2600c0ed746bc1"
)
GUILD_RAID_MERCENARY_CLIENT_CAVE_BYTES = bytes.fromhex(
    "ff0301d1"  # sub  sp, sp, #0x40
    "fd7b02a9"  # stp  x29, x30, [sp, #0x20]
    "88050090"  # adrp x8, #0xBE3000
    "00cd43f9"  # ldr  x0, [x8, #0x798]     (cached libil2cpp base)
    "01448a52"  # mov  w1, #0x5220
    "c13da072"  # movk w1, #0x1ee, lsl #16
    "22010010"  # adr  x2, #0xB33714        (expected client bytes)
    "23010010"  # adr  x3, #0xB33718        (replacement bytes)
    "24008052"  # mov  w4, #1
    "e5630091"  # add  x5, sp, #0x18        (status byte on the stack)
    "1708fe97"  # bl   0xAB575C
    "fd7b42a9"  # ldp  x29, x30, [sp, #0x20]
    "ff030191"  # add  sp, sp, #0x40
    "f44f45a9"  # ldp  x20, x19, [sp, #0x50]  (original instruction)
    "1dfffd17"  # b    0xAB3384
    "e0070054"  # expected: b.eq 0x1ee531c
    "1f2003d5"  # replacement: nop
)
GUILD_RAID_MERCENARY_CAVE_ORIGINAL_SHA256 = (
    "dfe2c5bfff86cd15eedf6c86105905d45ffd434809ef8e3f728d67859c2eff0b"
)
# GUILD_RAID_MERCENARY_CAVE_BYTES is built further down, once the encoders exist.

# ---------------------------------------------------------------------------
# Guild Raid Rank Reward x10
# ---------------------------------------------------------------------------
# The weekly settlement mails the daily and weekly guild-raid rank rewards from
# two 8-entry tables in .rodata (vaddr == file offset for this region).  Each
# entry is 0x28 bytes: reward id at +0x00 and three int32 amounts at +0x18
# (item 150001), +0x1c (gold) and +0x20 (secondary item).  Multiplying the
# non-zero amounts by 10 multiplies the delivered mails by 10.
GUILD_RAID_REWARD_ENTRY_SIZE = 0x28
GUILD_RAID_REWARD_AMOUNT_OFFSETS = (0x18, 0x1C, 0x20)
GUILD_RAID_DAILY_REWARD_TABLE = 0x758260
GUILD_RAID_WEEKLY_REWARD_TABLE = 0x7583A0
GUILD_RAID_DAILY_REWARDS = (
    (24000, 0, 0),
    (16800, 0, 0),
    (16000, 0, 0),
    (15200, 0, 0),
    (14400, 0, 0),
    (13600, 0, 0),
    (12800, 0, 0),
    (12000, 0, 0),
)
GUILD_RAID_WEEKLY_REWARDS = (
    (70000, 5000000, 10000),
    (50000, 4000000, 7500),
    (47000, 3500000, 7000),
    (44000, 3000000, 6500),
    (41000, 2500000, 6000),
    (39000, 1750000, 4500),
    (37000, 1500000, 4200),
    (35000, 1250000, 4000),
)

# ---------------------------------------------------------------------------
# Laboratory Flask 3h Branch Site
# ---------------------------------------------------------------------------
FLASK_3H_BRANCH_SRC = 0xA655C8
FLASK_3H_BRANCH_DST = 0xA655E4
FLASK_3H_BRANCH_ORIGINAL = bytes.fromhex("df0a0071")  # cmp w22, #2

# ---------------------------------------------------------------------------
# Energy Flask: 10x free stamina (100 -> 1000)
# ---------------------------------------------------------------------------
# ``laboratory_use_fields`` (0xA64D88) grants the daily Energy Flask's free
# stamina.  After reading the current ``stamina`` from the state it materializes
# the reward with ``add x0, x19, #0x64`` (100) at 0xA65648 and writes the sum
# back through ``set_top_level_value("stamina")``.  Changing the immediate to
# 0x3E8 makes every collection award 1000 stamina while keeping the native
# window guard intact (the server only accepts hours 12-15 and 18-21), so the
# original ``laboratorytimezone`` windows must be preserved.
ENERGY_FLASK_STAMINA_SITE = 0xA65648
ENERGY_FLASK_STAMINA_ORIGINAL = bytes.fromhex("60920191")  # add x0, x19, #0x64
ENERGY_FLASK_STAMINA_REPLACEMENT = bytes.fromhex("60a20f91")  # add x0, x19, #0x3e8

# ---------------------------------------------------------------------------
# Option-change potion: always the best attributes
# ---------------------------------------------------------------------------
# ``normalized_equipment_options_vector_json`` (0x9a08cc) takes a quality bias in
# its last two arguments: `bool` (whether the record should be re-rolled at all) and an
# `int` bonus of ``mastery_level * 30``.  Every path that grants or re-rolls gear passes
# the player's Lord mastery (skill code 20301, clamped to 15) — except the potion path,
# which calls it with `false` and `0`, so the potion ignores the mastery bonus entirely.
#
# 0xa16fec  mov w3, wzr   -> mov w3, #1        (re-roll with quality bias)
# 0xa16ff0  mov w4, wzr   -> mov w4, #0x1c2    (15 * 30 = the maximum mastery bonus)
OPTION_BONUS_BOOL_SITE = 0xA16FEC
OPTION_BONUS_BOOL_ORIGINAL = bytes.fromhex("e3031f2a")  # mov w3, wzr
OPTION_BONUS_BOOL_REPLACEMENT = bytes.fromhex("23008052")  # mov w3, #1
OPTION_BONUS_MASTERY_SITE = 0xA16FF0
OPTION_BONUS_MASTERY_ORIGINAL = bytes.fromhex("e4031f2a")  # mov w4, wzr
OPTION_BONUS_MASTERY_REPLACEMENT = bytes.fromhex("44388052")  # mov w4, #0x1c2

# ---------------------------------------------------------------------------
# Rune options: always roll with the maximum mastery bonus
# ---------------------------------------------------------------------------
# ``rolled_rune_options_json`` (0xa2e65c) reads the Lord mastery (skill code 20501),
# clamps it to 15 and indexes the 30-byte-per-row weight table at 0x719f10 with it, so the
# level decides how good the rolled rune attributes are.  Replacing the lookup with a
# constant 15 keeps the clamp and always uses the best row.
RUNE_OPTION_MASTERY_SITE = 0xA2E700
RUNE_OPTION_MASTERY_ORIGINAL = bytes.fromhex("89a1ff97")  # bl mastery_level_in_state
RUNE_OPTION_MASTERY_REPLACEMENT = bytes.fromhex("e00180d2")  # mov x0, #0xf (x0 is read at 0xa2e718)

# ---------------------------------------------------------------------------
# Equipment options: scale the Lord-mastery quality bias
# ---------------------------------------------------------------------------
# ``weighted_randoption_id_json`` (0x9a2790) turns the mastery bonus it receives
# into a probability in 1/10000 units:
#
#   den = total - max(acc, 0)                 ; remaining weight after the roll
#   num = total * bonus + den - 1
#   q   = min(10000, num / den)               ; 0x9a2b34 clamps at 0x2710
#   good = q > (hash % 10000)                 ; 0x9a2c78..0x9a2c84
#
# So the bonus is linear in the odds and the only ceiling is that clamp at 10000
# (100%).  Upstream every caller passes ``mastery_level * 30`` with the mastery
# clamped to 15, i.e. at most 450 (~4.5% per roll), and the option potion used to
# pass 0.  Both reads of the argument inside the picker are rewritten with a
# constant, which scales every path that reaches it (potion, grants, re-rolls)
# without touching any caller.
EQUIPMENT_OPTION_BONUS_SITES = (0x9A2AF4, 0x9A2B14)
EQUIPMENT_OPTION_BONUS_ORIGINALS = (
    bytes.fromhex("e80f40b9"),  # ldr w8, [sp, #0xc]
    bytes.fromhex("e90f40b9"),  # ldr w9, [sp, #0xc]
)
EQUIPMENT_OPTION_BONUS_REGISTERS = (8, 9)
EQUIPMENT_OPTION_BONUS_BASE = 450   # 15 * 30, the maximum Lord mastery bonus
EQUIPMENT_OPTION_BONUS_CAP = 10000  # ``q`` is clamped here upstream (100%)

# One Modification Stone per option change, regardless of locked lines.
# Server helper ``equipment_option_change_material_count_json`` (0x8A4DC8)
# returns 1 + the escalating lock cost; replacing the final ``csinc`` with
# ``mov x0,#1`` keeps every option change at one stone.  The client GUI shows
# the same value from ``EquipmentOptionChangeGUI.UpdateCostValue`` (RVA
# 0x1CF0528), whose ``mov w1,w23`` passes the lock count to the cost helper;
# the late hook rewrites that argument to zero so the dialog reads 1 and the
# client-side inventory check accepts one stone.
SINGLE_MOD_STONE_SERVER_SITE = 0x8A4F3C
SINGLE_MOD_STONE_SERVER_ORIGINAL = bytes.fromhex("00c59f9a")  # csinc x0, x8, xzr, gt
SINGLE_MOD_STONE_SERVER_REPLACEMENT = bytes.fromhex("200080d2")  # mov x0, #1
SINGLE_MOD_STONE_CLIENT_SITE = 0x1CF069C
SINGLE_MOD_STONE_CLIENT_ORIGINAL = bytes.fromhex("e103172a")  # mov w1, w23
SINGLE_MOD_STONE_CLIENT_REPLACEMENT = bytes.fromhex("e1031f2a")  # mov w1, wzr
SINGLE_MOD_STONE_INSTALL_SITE = 0xAB3388
SINGLE_MOD_STONE_INSTALL_ORIGINAL = bytes.fromhex("f85f43a9")  # ldp x24, x23, [sp, #0x30]
SINGLE_MOD_STONE_INSTALL_RETURN = 0xAB338C
SINGLE_MOD_STONE_CAVE_VADDR = 0xB337B4
SINGLE_MOD_STONE_CAVE_SIZE = 0x4C

# Server-side randoption table (fwt_randoption_rows(int&)::rows).  Each row is
# 40 bytes: id, attribute key, value type, six grade weights, sort order.
RANDOPTION_SERVER_SITE = 0x621E60
RANDOPTION_SERVER_ROW_SIZE = 40
RANDOPTION_SERVER_ROW_COUNT = 1856
# Groups map to client value types 1 (direct flat) and 4 (scaled flat).
# For example, type 4 option 43010 stores 0.0267 and displays +267 Counter Damage.
RANDOPTION_SERVER_FLAT_GROUPS = frozenset({1, 2, 3, 4, 5, 6, 21, 23, 25, 26, 39, 41, 43})
RANDOPTION_SERVER_WEIGHT_OFFSET = 0x0C
RANDOPTION_SERVER_GRADE_COUNT = 6
# Parallel table (12 bytes per row: option id, quality grade, combat power) that
# the picker reads at ``0x9a2a28`` to prefer the best option of a pool; its rows
# are in the same order as the option table above.
RANDOPTION_QUALITY_SITE = 0x634060
RANDOPTION_QUALITY_ROW_SIZE = 12
RANDOPTION_TOP_QUALITY = 5
# The picker sums the grade weights of the candidate rows and, when the total is
# zero, falls back to the best-quality row of the pool instead of returning no
# option.  With the flat rows unweighted that fallback keeps handing back a flat
# option, so the branch below the empty-list check is made unconditional: a
# zero-weight pool now yields an empty option id and the caller advances to the
# next attribute.
RANDOPTION_FALLBACK_SITE = 0x9A2AAC
RANDOPTION_FALLBACK_ORIGINAL = bytes.fromhex("00230054")  # b.eq 0x9A2F0C
RANDOPTION_FALLBACK_REPLACEMENT = bytes.fromhex("18010014")  # b 0x9A2F0C

# Server-side hero potential (Trait) tables (kFwtPotentialDataRows / kFwtPotentialGradeRows).
# Each data row is 68 bytes: potential_id, potential_type, and 15 int32 weights
# (5 slots x 3 phases).  Each grade row is 12 bytes: potential_id, grade (1..5),
# and combat_power.
POTENTIAL_DATA_TABLE_VADDR = 0x6CBBC8
POTENTIAL_DATA_ROW_SIZE = 68
POTENTIAL_DATA_ROW_COUNT = 393
POTENTIAL_DATA_WEIGHT_OFFSET = 0x08
POTENTIAL_DATA_WEIGHT_COUNT = 15
POTENTIAL_GRADE_TABLE_VADDR = 0x6D242C
POTENTIAL_GRADE_ROW_SIZE = 12
POTENTIAL_TOP_QUALITY = 5
# In choose_potential_code_json (0x8BFDF0), after splitting creature["potentials"],
# the empty-vector guard ``b.eq 0x8C00F0`` skips constructing the cross-slot
# excluded-types std::set.  Making that branch unconditional frees the vector
# cleanly and leaves the exclusion set empty so any slot can roll repeated types
# (e.g. multiple +Crit Rate slots) while keeping w4=1 current-slot exclusion intact.
POTENTIAL_DEDUP_SITE = 0x8BFF74
POTENTIAL_DEDUP_TARGET = 0x8C00F0
POTENTIAL_DEDUP_ORIGINAL = bytes.fromhex("e00b0054")  # b.eq #0x8c00f0
POTENTIAL_DEDUP_REPLACEMENT = bytes.fromhex("5f000014")  # b #0x8c00f0

# Feature 13.04: Unique attributes within a multi-roll (10x) Trait change batch
# (REQ_CHANGE_CREATURE_POTENTIAL loop 0x7FF69C..0x7FF904 -> choose_potential_code_json 0x8BFDF0).
POTENTIAL_BATCH_INIT_SITE = 0x7FF69C
POTENTIAL_BATCH_INIT_ORIGINAL = bytes.fromhex("38008052")  # mov w24, #1
POTENTIAL_BATCH_CALL_SITE = 0x7FF7F4
POTENTIAL_BATCH_CALL_ORIGINAL = bytes.fromhex("7f010394")  # bl #0x8bfdf0
POTENTIAL_FLAGS_STORE_SITE = 0x8BFE30
POTENTIAL_FLAGS_STORE_ORIGINAL = bytes.fromhex("e44300b9")  # str w4, [sp, #0x40]
POTENTIAL_FLAGS_STORE_REPLACEMENT = bytes.fromhex("e42300f9")  # str x4, [sp, #0x40]
POTENTIAL_PASS1_FILTER_SITE = 0x8C01E8
POTENTIAL_PASS1_FILTER_ORIGINAL = bytes.fromhex("a8035ff8")  # ldur x8, [x29, #-0x10]
POTENTIAL_PASS2_FILTER_SITE = 0x8C0524
POTENTIAL_PASS2_FILTER_ORIGINAL = bytes.fromhex("a8835df8")  # ldur x8, [x29, #-0x28]
POTENTIAL_PASS2_EMPTY_SITE = 0x8C07C8
POTENTIAL_PASS2_EMPTY_ORIGINAL = bytes.fromhex("5f031ceb")  # cmp x26, x28

POTENTIAL_MULTI_UNIQUE_CAVE_VADDR = 0xB2B530
POTENTIAL_MULTI_UNIQUE_BATCH_INIT_VADDR = 0xB2B530
POTENTIAL_MULTI_UNIQUE_BATCH_CALL_VADDR = 0xB2B53C
POTENTIAL_MULTI_UNIQUE_PASS1_FILTER_VADDR = 0xB2B5A0
POTENTIAL_MULTI_UNIQUE_PASS2_FILTER_VADDR = 0xB2B5CC
POTENTIAL_MULTI_UNIQUE_PASS2_EMPTY_VADDR = 0xB2B5F8
POTENTIAL_MULTI_UNIQUE_CAVE_BYTES = bytes.fromhex(
    "38008052fb031faac0035fd6fd7bbfa964fb7fd3840040b22a52f6971f0000f1"
    "4d02005409ddff9029212f912a3180528b0880d22c0140b99f01006ba0000054"
    "29010b8b4a05007161ffff54070000142c0540b99ff90071880000542d0080d2"
    "ad21cc9a7b030daafd7bc1a8c0035fd6e82340f908fd41d3c80000b4690640b9"
    "3ff90071680000540825c99a68000037a8035ff80a53f617f852f617e82340f9"
    "08fd41d3c80000b4a90640b93ff90071680000540825c99a68000037a8835df8"
    "ce53f617bc53f6175f031cebe1000054e82340f909fd41d3a90000b408014092"
    "e82300f9ad53f6176e54f617c255f617"
)
POTENTIAL_MULTI_UNIQUE_CAVE_SIZE = len(POTENTIAL_MULTI_UNIQUE_CAVE_BYTES)
POTENTIAL_MULTI_UNIQUE_CAVE_ORIGINAL_SHA256 = (
    "c382fe68af0ea2bf018f294e34594e004fe4166ce0bb2dd5fe38b1817b78fea9"
)

# Feature 13.05: Double immunity trait weights in Slots 3, 4, and 5
# (20,000 vs 10,000 normal stats, up from stock 335).
POTENTIAL_IMMUNITY_WEIGHT = 20000
POTENTIAL_IMMUNITY_ROWS: tuple[tuple[int, int, int, int, int], ...] = (
    # (row_index, potential_id, potential_type, column, original_weight)
    (300, 35001, 35, 6, 335),
    (301, 36001, 36, 12, 335),
    (302, 37001, 37, 9, 335),
)

# Equipment gradeup success/fail tables (indexed by current enchant level).
# Index 9 is the +9 -> +10 step: fail = 0 makes the deterministic roll return
# success without changing +0..+8 or +10 -> +11.
EQUIPMENT_UPGRADE_10_FAIL_SITE = 0x6BC160
EQUIPMENT_UPGRADE_10_FAIL_ORIGINAL = struct.pack("<q", 595082)
EQUIPMENT_UPGRADE_10_FAIL_REPLACEMENT = struct.pack("<q", 0)
SINGLE_MOD_STONE_CAVE_ORIGINAL_SHA256 = (
    "dc540697df3192cfa48a2c758dabd957075d6f99115b210309b7f544b7f6d147"
)

# ``EquipmentStateAccess::change_option`` (``0xa1832c``) rolls the options twice: the
# call to ``refresh_equipment_options_for_code_json`` (``0xa16fb8``) re-rolls them with no
# lock set and no mastery bonus and writes the result into the equipment record, and only
# afterwards does the handler read ``lock_list`` and roll again with the locks.  The
# locked lines are restored from the record that first roll just overwrote, which is why a
# locked attribute came back with a fresh value on the first roll after the lock list
# changed (measured on device: 10 violations in 17 transitions, 0 in 35 repeats).
# NOPing the refresh call leaves the locked preset intact and the single locked roll
# writes the record, so the lock holds from the very first roll.
EQUIPMENT_LOCK_FIX_SITE = 0xA18354
EQUIPMENT_LOCK_FIX_ORIGINAL = bytes.fromhex("19fbff97")  # bl refresh_equipment_options_for_code_json
EQUIPMENT_LOCK_FIX_NOP = bytes.fromhex("1f2003d5")      # nop

# ---------------------------------------------------------------------------
# 4-star random rune box: let the roll pick any of the three rune types
# ---------------------------------------------------------------------------
# ``pick_battle_rune_code`` (0x982c1c) indexes ``kFwtRuneRewardRows`` with the
# shop row's ``gacha_weight_no`` and then filters ``kFwtRuneRewardTypeRows`` by
# that row's ``typeWeight``.  Every "4-Star Random Rune Box" row (item_code 1131
# and 1132, shop_code 470008) carries ``gacha_weight_no = 9``, and group 9 in the
# type table holds a single row with ``runeType 8``.  The picker rejects
# ``runeType > 2`` (``cmp w19, #2; b.hi``), so the box can never roll one of the
# three real types.  Groups 9..14 already occupy rows 11..16 and none of them is
# reachable, so rows 11..13 are rewritten into a three-row group 9 with equal
# weights for types 0, 1 and 2 — the same shape group 0 uses for a fair roll.
RUNE_REWARD_TYPE_TABLE = 0x61E134
RUNE_REWARD_TYPE_STRIDE = 16
RUNE_BOX_TYPE_GROUP = 9
RUNE_BOX_TYPE_WEIGHT = 1000
RUNE_BOX_TYPE_REWRITES = (
    (11, (9, 10000, 8, 0), (9, 1000, 0, 0)),
    (12, (10, 10000, 9, 0), (9, 1000, 1, 0)),
    (13, (11, 10000, 10, 0), (9, 1000, 2, 0)),
)

# ---------------------------------------------------------------------------
# Rune attribute quality: scale the Lord-mastery bias
# ---------------------------------------------------------------------------
# ``rolled_rune_options_json`` (0xa2e65c) reads the Lord mastery (skill 0x5015),
# clamps it to 15 and multiplies by 30 (``lsl #5`` + ``sub …lsl #1``), then runs
# **the same probability math as the equipment picker**:
#
#   den = total - max(acc, 0)                 ; 0xa2eb9c
#   num = total * (mastery * 30) + den        ; 0xa2eba0
#   q   = min(10000, (num - 1) / den)         ; 0xa2ebac
#
# ``q < 1`` takes the ``:stock-pick`` path (0xa2ec0c); otherwise the mastery path
# runs.  So the ceiling is again 15 * 30 = 450 (~4.5%) and the value that feeds it
# is ``[sp, #0x10]``.  Replacing that load with a constant scales the odds without
# touching which rune types or which attribute slots are rolled (the dev's own
# behaviour stays).
RUNE_QUALITY_BONUS_SITE = 0xA2EB90
RUNE_QUALITY_BONUS_ORIGINAL = bytes.fromhex("e90b40f9")  # ldr x9, [sp, #0x10]
RUNE_QUALITY_BONUS_REGISTER = 9
RUNE_QUALITY_BONUS_BASE = 450    # 15 * 30, the maximum Lord mastery bonus
RUNE_QUALITY_BONUS_CAP = 10000   # ``q`` is clamped here upstream (100%)
RUNE_OPTION_TABLE_VADDR = 0x6ED510
RUNE_OPTION_ROW_SIZE = 48
RUNE_OPTION_ROW_COUNT = 3808
RUNE_OPTION_FLAT_COUNT = 420
RUNE_OPTION_TABLE_STOCK_SHA256 = "195f66874c630d6e369fb51baf545d1bef0deafcd8a98297b1c5dfbb42be7f6a"
RUNE_OPTION_TABLE_PERCENT_SHA256 = "34da2f3704aa6008433399f7fc7faa4937755f98578c8d44a0b25cf111e9dc71"
RUNE_OPTION_TABLE_PINK_SHA256 = "66a60c4ffc025bb2d891c605a2568d0f51e5f7683285cef0ef9f7209890a7b15"
RUNE_OPTION_TABLE_PERCENT_PINK_SHA256 = "ae14cf6b4c83c5378d4e9540f3308f2ca097d9eff4a7446492606985b5684811"

# Server-side building blocks for the planned rune-upgrade feature. They are not
# exposed as an option until the client price display is patched and verified.
RUNE_UPGRADE_TABLE_VADDR = 0x75797C
RUNE_UPGRADE_ROW_SIZE = 76
RUNE_UPGRADE_ROW_COUNT = 15
RUNE_UPGRADE_TABLE_STOCK_SHA256 = "a4e83db5706654ff70f066d396c2556c8185bff7cfabf9ca4b9c48ccc9689f28"
RUNE_UPGRADE_TABLE_PATCHED_SHA256 = "6bae63f3790ad33b18682b1a0bd7291206d1c5f2e8ccc53aabef6eb247705581"
RUNE_DECIDED_COST_SITE = 0x914F2C
RUNE_DECIDED_COST_ORIGINAL = bytes.fromhex("48fd488b007d099b")
RUNE_DECIDED_COST_PATCHED = bytes.fromhex("40090a8b00f87fd3")

# Client price display for the guaranteed one-step upgrade: ``RuneGradeUpPopup
# .GetEnchantCoast`` (RVA 0x1C5B258) sums the 72 ``runedecidedenchant`` rows,
# applies the active discount and then rounds the total down to a multiple of
# the constant in ``mov w9, #0x64`` at RVA 0x1C5B484.  Replacing 100 with 10
# makes the screen show exactly a tenth of the rounded total, matching the
# server's ``RUNE_DECIDED_COST_PATCHED`` division.  The client code is encrypted
# on disk, so the word is written at startup through ``patch_words`` from a cave
# hooked into the covault epilogue (install site 0xAB338C).
RUNE_UPGRADE_CLIENT_SITE = 0x1C5B484
RUNE_UPGRADE_CLIENT_ORIGINAL = bytes.fromhex("890c8052")  # mov w9, #0x64
RUNE_UPGRADE_CLIENT_REPLACEMENT = bytes.fromhex("49018052")  # mov w9, #0x0a
RUNE_UPGRADE_INSTALL_SITE = 0xAB338C
RUNE_UPGRADE_INSTALL_ORIGINAL = bytes.fromhex("fa6742a9")  # ldp x26, x25, [sp, #0x20]
RUNE_UPGRADE_INSTALL_RETURN = 0xAB3390
RUNE_UPGRADE_CAVE_VADDR = 0xB2A360
RUNE_UPGRADE_CAVE_SIZE = 0x4C

# ---------------------------------------------------------------------------
# Rune Box: Random Slot / Type Roll
# ---------------------------------------------------------------------------
# ``pick_battle_rune_code`` (0x982c1c) draws its rolls from
# ``stable_reward_roll_text`` (0x987454), a *deterministic* FNV-style hash of
# fixed strings.  The Korean dev introduced it to pin the runes' quality and the
# fourth attribute, and the side effect is that a shop rune box always grants the
# very same rune: nine 4★ box purchases produced nine identical codes (31402).
#
# Each roll is keyed by a literal written right before the call:
#
#   0x982d2c  "-grade"    0x982f04  "-slot"
#   0x983024  "-quality"  0x98314c  "-type"
#
# Only ``-slot`` and ``-type`` are rerouted, so the box rolls the rune's slot and
# type while ``-grade`` and ``-quality`` keep the dev's deterministic design.  The
# reroute goes through a small cave that calls the original function and mixes a
# per-call counter into the result.
RUNE_ROLL_TEXT_VA = 0x987454
RUNE_ROLL_SITE_GRADE = 0x982D2C     # "-grade"   (star comes from the row's weights)
RUNE_ROLL_SITE_SLOT = 0x982F04      # "-slot"    (rerouted: the slot does vary)
RUNE_ROLL_SITE_QUALITY = 0x983024   # "-quality"
RUNE_ROLL_SITE_TYPE = 0x98314C      # "-type"    (not reached on the box path)
# Measured on device: rerouting only "-slot" varied the slot (2, 3, 1, 2, 1) while
# every box still came out type 2, so the type does not read the "-type" roll here --
# that call sits in a branch the box path never takes and the type table picks with
# whatever value the previous roll left in x0.  Routing "-quality" as well is what
# makes the type follow.  "-grade" stays deterministic (it is the dev's star roll).
# Measured on device, in three purchase rounds: rerouting "-slot" made the slot vary
# (2, 3, 1, 2, 1) and the type never moved; rerouting all four rolls still left the
# type pinned at 2.  The type-table loop therefore does not read any of them -- it
# reads whatever x0 already holds.  So only "-slot" stays rerouted (the dev's
# deterministic grade/quality stay untouched) and the type is seeded at the loop.
RUNE_ROLL_DETERMINISTIC_SITES = (
    RUNE_ROLL_SITE_GRADE,
    RUNE_ROLL_SITE_QUALITY,
    RUNE_ROLL_SITE_TYPE,
)
RUNE_ROLL_SITES = (RUNE_ROLL_SITE_SLOT,)
# ``itanium_demangle::DtorName::printLeft``: local symbol with no branch, no
# materialized address, no RW pointer and no relocation aiming at it.  The
# demangler only runs when a type name is printed for an exception, so its 144
# bytes host the cave.  (``__stdinbuf<wchar_t>::imbue`` was the first pick and it
# *is* reached by the locale setup, which crashed the game at boot.)
RUNE_ROLL_CAVE_VA = 0xB3981C
# Type-table loop: the code builds the composite (slot << 16 | 0x1100 | type) and walks
# kFwtRuneRewardTypeRows from 0x61e134 up to the attrs base 0x61e244 with the weighted
# pick `remainder = x0 % total; remainder -= weight until negative`.  x0 is what the
# seed block overwrites, so the box cycles through the three rune types.
RUNE_TYPE_LOOP_ENTER = 0x983178     # b #0x98318c
RUNE_TYPE_LOOP_BODY = 0x98318C
RUNE_TYPE_SEED_OFFSET = 0xF6C       # second counter, right after the roll counter
RUNE_TYPE_SEED_REG = 6              # x6/x7 are unused by pick_battle_rune_code
RUNE_TYPE_CAVE_OFFSET = 36          # the seed block follows the roll mixer
RUNE_TYPE_SEED_ADVANCE = 0x9E3      # keeps the xorshift state away from zero
RUNE_ROLL_CAVE_LEN = 68
RUNE_ROLL_CAVE_SHA256 = "07080bc2e9aa21d1b0b328acf58be64654e095b3eabf2b7ceff26c540b39b60b"
# Padding between .data and .bss: inside the RW segment, zero-filled, no section.
RUNE_ROLL_COUNTER_PAGE = 0xBE2000
RUNE_ROLL_COUNTER_OFFSET = 0xF68
RUNE_ROLL_COUNTER_REG = 10
RUNE_ROLL_ADRP_REG = 9

# ---------------------------------------------------------------------------
# Soulgear enchant: always succeeds
# ---------------------------------------------------------------------------
# ``SoulgearGrowthStateAccess::apply`` decides the gold-paid enchant with an FNV-1a hash
# over ``lord:sg_idx:enchant_cnt:sg_code`` compared against the success/failure tables
# (``0x6bc0c0`` / ``0x6bc118``, 84.75% down to 6%).  ``cset w8, lo`` at ``0x8b3b4c``
# materialises that verdict into the flag the caller reads at ``+0x9e``; forcing it to 1
# makes every gold-paid enchant succeed.  SOULGEAR_UPGRADE has no roll at all, only a
# cost, and this binary has no ``hero mark`` opcode.
SOULGEAR_ENCHANT_SITE = 0x8B3B4C
SOULGEAR_ENCHANT_ORIGINAL = bytes.fromhex("e8279f1a")  # cset w8, lo
SOULGEAR_ENCHANT_REGISTER = 8

# ---------------------------------------------------------------------------
# Win Box (Cocoo Box) advertisement in the battle result payload
# ---------------------------------------------------------------------------
# battle_has_mapped_coocoo_box (0x8da77c) decides whether the result payload says the battle
# carried a cocoo box: its single caller (0x80f0d8) writes "is_win_box": and then true/false
# from the return value (the two literals live at 0x4d5da7 and 0x2f04e6).  The embedded
# battle result template leaves the box rewards empty, so true only advertises
# phantom slots. Forcing the function to return 0 affects its single caller.
NO_WIN_BOX_SITE = 0x8DA77C
NO_WIN_BOX_ORIGINAL = bytes.fromhex("e80300aa09b04239")  # mov x8, x0 ; ldrb w9, [x0, #0xac]
NO_WIN_BOX_PATCHED = bytes.fromhex("e0031f2ac0035fd6")  # mov w0, wzr ; ret
# Both Subjugation callers share this box gate after normal rewards are granted.
# Preserve the original signed >= 1 checks on both box mappings at 0xa4/0xa8.
# A nonnegative gene ID at 0x7c then takes the stock no-box exit at 0x8d01ac.
SWEEP_GENE_BOX_SITE = 0x8CFC7C
SWEEP_GENE_BOX_ORIGINAL = bytes.fromhex("c8a640b91f0500714b290054d5aa40b9bf060071eb280054")
SWEEP_GENE_BOX_PATCHED = bytes.fromhex("c8d654291f050071a8aa417a2b290054c97e40b9e928f836")

# ---------------------------------------------------------------------------
# Hero EXP Cap & Un-transcended Limit Break Floor (always-on bug fix)
# ---------------------------------------------------------------------------
# Battle and expedition EXP grants at 0x80963C (Stage), 0x81831C (Tower of
# Dawn), and 0x945E30 (Expedition) add reward EXP without calling
# creature_max_total_exp_for_level_json (0xA245DC), letting un-transcended
# heroes overflow to Lv71+ EXP.  When `"level_max"` < 70 on a 6★ hero,
# creature_level_max_value_json (0x901F00) then computes
# min(max(level_from_exp, crs_level, 70), 120) at 0x902008, returning 71
# instead of 70; LimitBreakCost (0x756CF0) only has even rows (70, 72..118),
# which permanently deadlocks Limit Break.  Clamp EXP to level_max and return
# 70 at 0x902008 so both new and existing Lv71 un-transcended heroes can break.
HERO_LEVEL_MAX_FLOOR_SITE = 0x902008
HERO_LEVEL_MAX_FLOOR_ORIGINAL = bytes.fromhex("cadcffd04ad12f91")
HERO_LEVEL_MAX_FLOOR_PATCHED = bytes.fromhex(
    "d40880522b000014"  # mov w20, #0x46 ; b 0x9020b8
)
HERO_LEVEL_MAX_FUNC = 0x901F00  # creature_level_max_value_json(creature_str*)
HERO_MAX_EXP_FUNC = 0xA245DC  # creature_max_total_exp_for_level_json(creature_str*, level)

HERO_EXP_CAP_CAVE_VADDR = 0xB2AD70
HERO_EXP_CAP_HELPER_SIZE = 0x40
HERO_EXP_CAP_TRAMPOLINE_STD_SIZE = 0x20
HERO_EXP_CAP_EXPEDITION_SIZE = 0x28
HERO_EXP_CAP_CAVE_SIZE = (
    HERO_EXP_CAP_HELPER_SIZE
    + HERO_EXP_CAP_TRAMPOLINE_STD_SIZE * 2
    + HERO_EXP_CAP_EXPEDITION_SIZE
)  # 168 bytes (0xB2AD70..0xB2AE18)
HERO_EXP_CAP_CAVE_ORIGINAL_SHA256 = (
    "1756839b63be2144cedb3e63806153be54d421c0ce5495329da96c55307d53ea"
)
HERO_EXP_CAP_STAGE_SITE = 0x80963C
HERO_EXP_CAP_STAGE_ORIGINAL = bytes.fromhex("9a021a8b")  # add x26, x20, x26
HERO_EXP_CAP_STAGE_TRAMPOLINE = HERO_EXP_CAP_CAVE_VADDR + HERO_EXP_CAP_HELPER_SIZE
HERO_EXP_CAP_INFINITY_SITE = 0x81831C
HERO_EXP_CAP_INFINITY_ORIGINAL = bytes.fromhex("fc02188b")  # add x28, x23, x24
HERO_EXP_CAP_INFINITY_TRAMPOLINE = (
    HERO_EXP_CAP_STAGE_TRAMPOLINE + HERO_EXP_CAP_TRAMPOLINE_STD_SIZE
)
HERO_EXP_CAP_EXPEDITION_SITE = 0x945E30
HERO_EXP_CAP_EXPEDITION_ORIGINAL = bytes.fromhex("1900098b")  # add x25, x0, x9
HERO_EXP_CAP_EXPEDITION_TRAMPOLINE = (
    HERO_EXP_CAP_INFINITY_TRAMPOLINE + HERO_EXP_CAP_TRAMPOLINE_STD_SIZE
)

# ---------------------------------------------------------------------------
# English Qty String in Native SO
# ---------------------------------------------------------------------------
ENGLISH_SO_QTY_OFFSET = 0x4D5BA3
ENGLISH_SO_QTY_ORIGINAL = b"\xec\x88\x98\xeb\x9f\x89\x00"
ENGLISH_SO_QTY_REPLACEMENT = b"Qty\x00\x00\x00\x00"

# ---------------------------------------------------------------------------
# Guild Raid 64-bit Score Fix
# ---------------------------------------------------------------------------
# The guild-raid start response declares `bonus_limit` as a signed 32-bit
# field.  Once the stored daily record exceeds 2,147,483,647 the client's JSON
# decoder cannot represent it and OnStartGuildRaid throws before the battle
# starts.  For out-of-range records the server now emits the sentinel -1 and
# the client hook below restores the real 64-bit value from rank_list[0].
#
# Server site 0x831CE4 previously clamped negatives to zero with
# `cmp x0,#0; csel x0,x0,xzr,gt`.  Client installer site 0xAB00D8 is the first
# patch_words call in patch_offline_convenience_flow; it installs 16-byte
# trampolines at the decrypted client text RVAs 0x158C744 (normal start) and
# 0x158CF94 (practice start).
GUILD_RAID_START_SITE = 0x831CE4
GUILD_RAID_START_ORIGINAL = bytes.fromhex("1f0000f100c09f9a")
GUILD_RAID_INSTALL_SITE = 0xAB00D8
GUILD_RAID_INSTALL_ORIGINAL = bytes.fromhex("a1150094")
GUILD_RAID_CLIENT_CAVE = CAMPAIGN_CAVE_BASE + 0x110
GUILD_RAID_SENTINEL_CAVE = CAMPAIGN_CAVE_BASE + 0x2B0
# patch_words writes a 16-byte trampoline at the client site:
#   ldr x16, #8 ; br x16 ; <8-byte hook address>
# The sentinel cave only needs to confirm the first instruction is present.
GUILD_RAID_CLIENT_TRAMPOLINE_WORD = 0x58000050
# Original bytes in the two free slots of the demangler cave.  They are
# checked so --force cannot silently overwrite unrelated code at these offsets.
GUILD_RAID_SENTINEL_SLOT_SHA256 = (
    "b66f873ae54ac6d9fb0cbf3041edba65ca429eb5aa1ebb05b6799da8a5db1b74"
)
GUILD_RAID_CLIENT_SLOT_SHA256 = (
    "2379da6a1ed98095c854bc05ff3e1a32dee59cf84fd92315a6598dc0b8464681"
)
# Sentinel cave prefix: cmp x0,#0; b.le zero; lsr x9,x0,#31; cbz x9,out;
# adrp x9,0xbe3000; ldr x9,[x9,#0x798]; cbz x9,zero; movz/movk x10,0x158c744;
# add x9,x9,x10; ldr w10,[x9].  The trampoline word and final branch are
# appended by _build_guild_raid_sentinel_cave().
GUILD_RAID_SENTINEL_PREFIX = bytes.fromhex(
    "1f0000f10d02005409fc5fd3e90100b4"
    "8905009029cd43f9690100b48ae898d2"
    "0a2ba0f229010a8b2a0140b9"
)
# Installer + client hook, assembled for the fixed cave address 0xB33424.
# The assembly source is documented in docs/SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md.
GUILD_RAID_CLIENT_CAVE_BYTES = bytes.fromhex(
    "ff4302d1fd7b07a9e00700a9cb08fe97e03300b9e00340f981e89852012ba07242090010e3030191090a80520900ab72"
    "e94300b909408052e9c3ba72e94700b969020010e92700f984008052e5080010ba08fe97e00340f981f29952012ba072"
    "c2070010e303019189010010e92700f984008052a5070010b008fe97e03340b9fd7b47a9ff4302910cf3fd1791ea98d2"
    "112ba0f20400001491f499d2112ba0f201000014fd7bbda9f10b00f969e240b93f050031a1010054696240f9290100b4"
    "2a1940b9ea000034290940f9a90000b4291140f9690000b4212940f904000014e1031faa0200001461e280b9e00f00f9"
    "e11300f9e30301aa8000805261030010a2030030e24b0094e00f40f9e11340f9e2031faa8905009029cd43f9905f83d2"
    "3031a0f23001108b00023fd68905009029cd43f9f00b40f93001108bfd7bc3a8e0031faa00021fd661e280b9e2031faa"
    "ec140c94e0031faa61e280b9e2031faad8120c94e0031faa4657544775696c64526169640073636f72654c696d69743d"
    "256c6c6400"
)

# ---------------------------------------------------------------------------
# Single-Material Features
# ---------------------------------------------------------------------------
# Equipment transcendence above +15 uses item 130006 (levels 15..19) and
# 130027 (levels 20..25) and computes the required count as `level - 14`
# for the first range.  Make both ranges use one hammer, matching the fixed
# single-material behavior of the lower-tier upgrade path.
SINGLE_BLACK_HAMMER_SITE = 0x8A7404
SINGLE_BLACK_HAMMER_ORIGINAL = bytes.fromhex("163900d1")  # sub x22, x8, #0xe
SINGLE_BLACK_HAMMER_REPLACEMENT = bytes.fromhex("36008052")  # mov w22, #1
# Opening gem slots spends Dragon Fang item 2060051.  The count is derived
# from the slot number (2 for slot 2, 3 for slot 3).  Force it to one.
SINGLE_GEM_FANG_SITE = 0x7F5148
SINGLE_GEM_FANG_ORIGINAL = bytes.fromhex("38159f9a")  # csinc x24, x9, xzr, ne
SINGLE_GEM_FANG_REPLACEMENT = bytes.fromhex("380080d2")  # mov x24, #1
# Inside GemStateAccess::mutate_equipment_hole (action == Open), hook the
# update_equipment_hole_json call at 0x8ADE80 to unlock all 3 holes (1, 2, 3)
# for that equipment in a single request while spending only 1 Dragon Fang and
# keeping any already-open hole's socketed gem intact.
SINGLE_GEM_FANG_ALL_HOLES_SITE = 0x8ADE80
SINGLE_GEM_FANG_ALL_HOLES_ORIGINAL = bytes.fromhex("1cb00594")  # bl 0xA19EF0
SINGLE_GEM_FANG_ALL_HOLES_TARGET = 0xA19EF0  # update_equipment_hole_json
SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR = 0xB2AD10
SINGLE_GEM_FANG_ALL_HOLES_CAVE_SIZE = 0x58
SINGLE_GEM_FANG_ALL_HOLES_CAVE_ORIGINAL_SHA256 = (
    "0dc01053ff0d6e0e2840de3c2b97152538ed9a9913c58e040e9cb50e91e2ce3d"
)
# Client-side gate: EquipmentGemsGUI.OnDragonFangButtonPressed compares the
# equipment slot index with the owned Dragon Fang count and refuses slot 2/3
# unless the player owns 2/3 fangs.  The server charges one after this patch;
# rewrite the conditional branch at 0x1DCACEC so the dialog opens regardless
# (the server still validates the owned item).
SINGLE_GEM_FANG_CLIENT_SITE = 0x1DCACEC
SINGLE_GEM_FANG_CLIENT_ORIGINAL = bytes.fromhex("8d040054")  # b.le 0x1DCAD7C
SINGLE_GEM_FANG_INSTALL_SITE = 0xAB3384
SINGLE_GEM_FANG_INSTALL_ORIGINAL = bytes.fromhex("f65744a9")  # ldp x22, x21, [sp, #0x40]
SINGLE_GEM_FANG_INSTALL_RETURN = 0xAB3388
SINGLE_GEM_FANG_CAVE_VADDR = 0xB3367C
SINGLE_GEM_FANG_CAVE_SIZE = 0x4C
SINGLE_GEM_FANG_CAVE_ORIGINAL_SHA256 = (
    "5bc6a6e66599788c5ecd0c6b1978c81cc2e8b7fee4d25682652f96fcb4e6cce8"
)

# ---------------------------------------------------------------------------
# Select All Includes 4★/5★ (client-side runtime hook)
# ---------------------------------------------------------------------------
# The multi-extraction "Block Disassemble" popup builds three grade filters
# (1★..3★) plus a Select All checkbox.  Its EquipmentMenuGUI.BlockSelect
# routine receives the bool array and only accepts grades 1..3.  The hook
# below patches the decrypted client at runtime through the existing
# patch_words installer: when the Select All flag is set, grades 4 and 5 are
# treated as grade 3 so they enter the selection bucket.  The client library
# is AppSealing-protected, so this must be installed after decryption.
SELECT_ALL_INSTALL_SITE = 0xAB0118  # second patch_words call in patch_offline_convenience_flow
SELECT_ALL_INSTALL_ORIGINAL = bytes.fromhex("91150094")  # bl 0xAB575C
SELECT_ALL_CLIENT_CAVE = CAMPAIGN_CAVE_BASE + 0x320
SELECT_ALL_CLIENT_RVA = 0x1CE93F8
# Installer at SELECT_ALL_CLIENT_CAVE. It performs the original patch_words
# call, installs the 4★/5★ grade trampoline, and then patches the quality
# filter at 0x1CE9420 so quality-4/5 equipment can enter the Epic bucket.
SELECT_ALL_CLIENT_CAVE_BYTES = bytes.fromhex(
    "ff4302d1fd7b07a9e00700a94708fe97e03300b9e00340f9017f9252c139a072"
    "22030010e3030191090a80520900ab72e94300b909408052e9c3ba72e94700b9"
    "090a0010e92700f984008052450200103608fe97e00340f901849252c139a072"
    "020200100302001024008052450100102e08fe97e03340b9fd7b47a9ff430291"
    "9af2fd17095d40396ada40b95f01096b6105005453656c656374416c6c343500"
    "0b5940396b008052"
)
# The 4★/5★ grade stub moved out of the installer blob so the installer could
# hold the second (quality) patch_words call. It runs from the free cave tail.
SELECT_ALL_STUB_VADDR = CAMPAIGN_CAVE_BASE + 0x4A0
SELECT_ALL_GRADE_STUB_BYTES = bytes.fromhex(
    "095d40396ada40b9ab0357f84b0100b46c1940b99f110071e10000546c8d4039"
    "ac0000343f11007163000054e9030a2a600080525f01096be10000548d050090"
    "adcd43f9108192d2d039a0f2b001108b00021fd68d050090adcd43f9109692d2"
    "d039a0f2b001108b00021fd6"
)
SELECT_ALL_CLIENT_CAVE_RANGE = (
    SELECT_ALL_CLIENT_CAVE,
    SELECT_ALL_CLIENT_CAVE + 0xF0,
)
SELECT_ALL_STUB_RANGE = (
    SELECT_ALL_STUB_VADDR,
    SELECT_ALL_STUB_VADDR + len(SELECT_ALL_GRADE_STUB_BYTES),
)
SELECT_ALL_CAVE_ORIGINAL_SHA256 = (
    "dbc388603820387d2f9e5e3d2cc468a5254bb2efdb931676ade7b21fa09b9fed"
)
SELECT_ALL_STUB_ORIGINAL_SHA256 = (
    "6fc087cdb9487a3feea30c14857846bdf1183af271bf7a598821c907aa3f94ff"
)
SELECT_ALL_CAVE_RESERVED_SIZE = 0xF0

# ---------------------------------------------------------------------------
# Battle Arena Team Save Fix (client runtime hook)
# ---------------------------------------------------------------------------
# ArenaAttackTeamListGUIInInventory.Init stores its team manager at +0x60 only
# when the il2cpp type-hierarchy check passes; a mismatch stores NULL and
# OnOKButtonPressed then throws a NullReferenceException on Save (the button
# silently does nothing offline).  The hook rewrites the `csel` at client RVA
# 0x1AA6FCC to `mov x8, x20`, forcing the manager to be stored.
#
# The page containing that RVA is protected by AppSealing: writing to it during
# the early startup trampoline (or even writing the same bytes) makes
# libcovault-appsec abort with SIGSEGV.  The patch is therefore applied *after*
# the "covault code permission finalization complete" step, from the epilogue
# of the finalization function (0xAB337C).  The client base is read from the
# server's cached global 0xBE3798 (set by patch_offline_convenience_flow), so no
# extra scratch is needed.  The cave lives in the same slot as select_all_4_5.
BATTLE_ARENA_SAVE_RVA = 0x1AA6FCC
BATTLE_ARENA_SAVE_ORIGINAL = bytes.fromhex("88029f9a")  # csel x8, x20, xzr, eq
BATTLE_ARENA_SAVE_REPLACEMENT = bytes.fromhex("e80314aa")  # mov x8, x20
BATTLE_ARENA_SAVE_CLIENT_BASE_GLOBAL = 0xBE3798
BATTLE_ARENA_SAVE_LATE_SITE = 0xAB337C
BATTLE_ARENA_SAVE_LATE_ORIGINAL = bytes.fromhex("ff433191")  # add sp, sp, #0xc50
BATTLE_ARENA_SAVE_CAVE_VADDR = SELECT_ALL_CLIENT_CAVE
# Guard covers only the bytes this cave owns: the guild-raid self-mercenary
# cave shares the tail of the same 0xF0 slot.
BATTLE_ARENA_SAVE_CAVE_ORIGINAL_SHA256 = (
    "ae4da00c7bb2e1872defcfd62ddd08ff97f92902298bc0bb58a9ffda0c939a0f"
)
BATTLE_ARENA_SAVE_CAVE_BYTES = bytes.fromhex(
    "ff0301d1"  # sub  sp, sp, #0x40
    "fd7b02a9"  # stp  x29, x30, [sp, #0x20]
    "88050090"  # adrp x8, #0xBE3000
    "00cd43f9"  # ldr  x0, [x8, #0x798]     (cached libil2cpp base)
    "81f98d52"  # mov  w1, #0x6fcc
    "4135a072"  # movk w1, #0x1aa, lsl #16
    "22010010"  # adr  x2, #0xB33670        (expected client bytes)
    "23010010"  # adr  x3, #0xB33674        (replacement bytes)
    "24008052"  # mov  w4, #1
    "e5630091"  # add  x5, sp, #0x18        (status byte on the stack)
    "4008fe97"  # bl   0xAB575C
    "fd7b42a9"  # ldp  x29, x30, [sp, #0x20]
    "ff030191"  # add  sp, sp, #0x40
    "ff433191"  # add  sp, sp, #0xc50       (original instruction)
    "45fffd17"  # b    0xAB3380
    "88029f9a"  # expected: csel x8, x20, xzr, eq
    "e80314aa"  # replacement: mov x8, x20
)

# ---------------------------------------------------------------------------
# Hero Limit Break 50% Gold Cost
# ---------------------------------------------------------------------------
# kFwtCreatureLimitBreakCosts is a 45-row table (24 bytes per row):
#   level (i32), next_level (i32), item_category (i32=17),
#   item_code (i32), item_count (i32), gold_cost (i32)
# Only the gold field is halved.  All reference values are even.
LIMIT_BREAK_GOLD_TABLE = 0x756CF0
LIMIT_BREAK_GOLD_ROW_SIZE = 24
LIMIT_BREAK_GOLD_ROWS = 45
LIMIT_BREAK_AFTER_FIELD_OFFSET = 4
LIMIT_BREAK_GOLD_FIELD_OFFSET = 20
LIMIT_BREAK_MATERIAL_FIELD_OFFSET = 16
LIMIT_BREAK_MAX_LEVEL = 120
LIMIT_BREAK_GOLD_TABLE_ORIGINAL_SHA256 = (
    "d79fe5e1c89b5ec6494d684dffe68b217e1ecfd0464acb330ad32ec1247bd917"
)
LIMIT_BREAK_GOLD_TABLE_PATCHED_SHA256 = (
    "e8feabccf80b99a5ad9e41c5dcce1d7d4d69a17670ce5caf42e67263af949c4a"
)
LIMIT_BREAK_COST_TABLE_PATCHED_SHA256 = (
    "1e90037000453c91d73bf2e42209233bc19d25f909939d61bff0da74f72193ed"
)
# Table with both the material and the gold column divided by ten (90% off).
LIMIT_BREAK_COST_TENTH_SHA256 = (
    "35d81b2810f97b246fb44f759d35062b3177dcf2a3e0a65d3c3161f30fcdace9"
)
# Flat price: every row charges the same 1,000,000 gold and 100 materials, so the
# cost stops growing with the level instead of only being discounted.
LIMIT_BREAK_ITEM_CATEGORY = 17
LIMIT_BREAK_FIXED_MATERIAL = 100
LIMIT_BREAK_FIXED_GOLD = 1_000_000
LIMIT_BREAK_COST_FIXED_SHA256 = (
    "fd6ade417ed0d6ff086613bb2d1e32b548fd1fc1dea5d0f943a63f12044de411"
)
_LIMIT_BREAK_KNOWN_COST_DIGESTS = (
    LIMIT_BREAK_GOLD_TABLE_ORIGINAL_SHA256,
    LIMIT_BREAK_GOLD_TABLE_PATCHED_SHA256,
    LIMIT_BREAK_COST_TABLE_PATCHED_SHA256,
    LIMIT_BREAK_COST_TENTH_SHA256,
    LIMIT_BREAK_COST_FIXED_SHA256,
)


def limit_break_step10_target(level_before: int) -> int:
    """Return the 10-level milestone cap for ``level_before`` (up to 120)."""
    return min(LIMIT_BREAK_MAX_LEVEL, ((level_before // 10) + 1) * 10)


def inspect_limit_break_table(table_bytes: bytes) -> tuple[str, str]:
    """Return ``(normalized_cost_sha256, step_mode)`` for ``kFwtCreatureLimitBreakCosts``.

    ``step_mode`` is ``"stock"`` when every row advances by +2, ``"step_10"`` when
    every row jumps to the next 10-level milestone up to 120, or ``"unknown"`` on a
    mixed or unrecognized ladder.  ``normalized_cost_sha256`` always normalizes valid
    ``+10`` ``level_after`` values back to stock ``level_before + 2`` so cost profiles
    are identified identically whether or not ``limit_break_step_10`` is applied.
    """
    expected_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
    if len(table_bytes) != expected_size:
        raise ValueError(
            f"Expected {expected_size} bytes for kFwtCreatureLimitBreakCosts, "
            f"got {len(table_bytes)}"
        )
    normalized = bytearray(table_bytes)
    all_stock = True
    all_step10 = True
    for index in range(LIMIT_BREAK_GOLD_ROWS):
        row_offset = index * LIMIT_BREAK_GOLD_ROW_SIZE
        level_before, level_after = struct.unpack_from("<2i", table_bytes, row_offset)
        stock_after = level_before + 2
        step10_after = limit_break_step10_target(level_before)
        if level_after != stock_after:
            all_stock = False
            struct.pack_into(
                "<i", normalized, row_offset + LIMIT_BREAK_AFTER_FIELD_OFFSET, stock_after
            )
        if level_after != step10_after:
            all_step10 = False
        if level_after not in (stock_after, step10_after):
            return hashlib.sha256(table_bytes).hexdigest(), "unknown"
    if all_stock and not all_step10:
        return hashlib.sha256(table_bytes).hexdigest(), "stock"
    if all_step10 and not all_stock:
        return hashlib.sha256(bytes(normalized)).hexdigest(), "step_10"
    return hashlib.sha256(table_bytes).hexdigest(), "unknown"


def limit_break_step10_state(buf: bytes | bytearray) -> tuple[bool, str]:
    """Return ``(active, detail)`` for the server limit-break +10 level progression."""
    table_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
    table_bytes = bytes(buf[LIMIT_BREAK_GOLD_TABLE:LIMIT_BREAK_GOLD_TABLE + table_size])
    cost_digest, step_mode = inspect_limit_break_table(table_bytes)
    if cost_digest not in _LIMIT_BREAK_KNOWN_COST_DIGESTS:
        return False, f"unexpected table sha {cost_digest[:12]}"
    if step_mode == "step_10":
        return True, f"table 0x{LIMIT_BREAK_GOLD_TABLE:x}, {LIMIT_BREAK_GOLD_ROWS} rows (+10 to Lv120)"
    if step_mode == "stock":
        return False, f"table 0x{LIMIT_BREAK_GOLD_TABLE:x} uses stock +2 level steps"
    return False, f"mixed or unknown level steps at 0x{LIMIT_BREAK_GOLD_TABLE:x}"

# ---------------------------------------------------------------------------
# High-level infinite transcendence success
# ---------------------------------------------------------------------------
# kSuccessPercent is indexed by the current enchant level for levels 20..25:
# 100, 90, 80, 70, 60, 50. Setting all entries to 100 makes +21..+26 attempts
# always succeed, so no insurance card is needed.
INFINITE_TRANSCEND_SUCCESS_TABLE = 0x6BAE64
INFINITE_TRANSCEND_SUCCESS_ORIGINAL = (100, 90, 80, 70, 60, 50)
INFINITE_TRANSCEND_SUCCESS_PATCHED = (100, 100, 100, 100, 100, 100)

# ---------------------------------------------------------------------------
# Devil's Soul EXP-synthesis boost
# ---------------------------------------------------------------------------
# When a Devil's Soul monster is used as an EXP synthesis material, the
# server multiplies the summed ingredient EXP by the float stored at
# ``0x6C49D8`` (originally 2.0). The new option raises that multiplier to
# 20.0, i.e. the boost itself is ten times stronger.
DEVIL_BOOST_MULTIPLIER_SITE = 0x6C49D8
DEVIL_BOOST_MULTIPLIER_ORIGINAL = 2.0
DEVIL_BOOST_MULTIPLIER_PATCHED = 20.0

# ---------------------------------------------------------------------------
# Equipment disassemble / alchemy item rewards
# ---------------------------------------------------------------------------
# Equipment recycling originally granted an equipment from kFwtEquipRewardRows
# when the alchemy bar completed.  The live service grants transcendence *items*
# instead:
#   130001..130005 = slot/class I..V equipment transcendence tickets
#   130006         = Ultimate Transcendence Ticket (+16..+20, black hammer)
#
# The bar-completion reward is replaced at 0x89D150.  A small flag cave at
# 0x89CEF8 saves the native table selector (w21: 0x65 = normal, 0x6A = final)
# in x20 before the reward pick.  The completion trampoline then grants:
#   * x20 == 0x6A  -> 130006 (Ultimate / black, final bar step)
#   * otherwise    -> 130001..130005 (class ticket matching alchemy grade w28)
# One item is granted per completion.  The trampoline writes the grant result
# into the native ItemInfo slot at ``sp+0x1e0`` and returns to 0x89D154 so the
# native response append (state+0x100) also publishes the ticket to the client;
# only the equipment grant itself is replaced.
RECYCLE_COMPLETION_HOOK = 0x89D150
RECYCLE_COMPLETION_ORIGINAL = bytes.fromhex("08030494")  # bl grant_equipment_json
RECYCLE_COMPLETION_RETURN = 0x89D238
RECYCLE_REWARD_FLAG_HOOK = 0x89CEF8
RECYCLE_REWARD_FLAG_ORIGINAL = bytes.fromhex("b6021c0b")  # add w22,w21,w28
RECYCLE_REWARD_FLAG_RETURN = 0x89CEFC

# Caves:
#   * 0x8C..0xC0 (52 bytes) completion body between mana and event-coin caves;
#   * 0x2FC..0x310 (20 bytes) completion tail after the Guild Raid sentinel;
#   * 0x50C..0x518 (12 bytes) reward-selector flag after the Select All stub.
RECYCLE_SCRATCH_PAGE = 0xBE2000
RECYCLE_REWARD_FLAG_OFFSET = 0xCBC  # unused 4-byte .data padding before __emutls
RECYCLE_GRADE_OFFSET = 0xF14        # unused 4-byte .data padding before __cxa_terminate_handler
RECYCLE_SCRATCH_SLOT_SIZE = 4
RECYCLE_COMPLETION_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0x8C
RECYCLE_COMPLETION_CAVE_SIZE = 0x3C
RECYCLE_COMPLETION_CAVE_TAIL_VADDR = CAMPAIGN_CAVE_BASE + 0x2FC
RECYCLE_COMPLETION_CAVE_TAIL_SIZE = 0x14
RECYCLE_REWARD_FLAG_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0x50C
RECYCLE_REWARD_FLAG_CAVE_SIZE = 0x10
# SHA-256 of the reference bytes in the free slots (guards version drift).
RECYCLE_COMPLETION_CAVE_ORIGINAL_SHA256 = (
    "c9a4980d0e33c4ee4fb6802eff14d8884ee672be56f6d514678c9bf82a4b130a"
)
RECYCLE_COMPLETION_CAVE_TAIL_ORIGINAL_SHA256 = (
    "a5c9fb5c662ab34e8dc4e5769bd9088e8c577aac9ff0997383572358e5812c1d"
)
RECYCLE_REWARD_FLAG_CAVE_ORIGINAL_SHA256 = (
    "f442597c4dc71d8983f7ff9f1d0f52d24bd86a9c6676cca9b88bbce9d798f3b2"
)

# Assembled with keystone-engine 0.9.2:
#   ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
RECYCLE_COMPLETION_CAVE_BYTES = bytes.fromhex(
    "660500f0"  # adrp x6, #0xBE2000
    "c6bc4cb9"  # ldr  w6, [x6, #0xCBC]    (saved reward selector)
    "a10304d1"  # sub  x1, x29, #0x100    (scratch string at sp+0x2C0)
    "670500f0"  # adrp x7, #0xBE2000
    "e4144fb9"  # ldr  w4, [x7, #0xF14]    (captured alchemy grade)
    "84c00011"  # add  w4, w4, #0x30       (class digit)
    "c3068052"  # mov  w3, #0x36           ('6')
    "dfa80171"  # cmp  w6, #0x6a           (final-table flag)
    "6300841a"  # csel w3, w3, w4, eq
    "85218652"  # mov  w5, #0x310c         (SSO flags + "13")
    "6506a672"  # movk x5, #0x3033, lsl #16 ("00")
    "0506c6f2"  # movk x5, #0x3030, lsl #32 ("00")
    "250000f9"  # str  x5, [x1]
    "23180039"  # strb w3, [x1, #6]
    "8e000014"  # b    0xB33610           (tail segment)
)
RECYCLE_COMPLETION_CAVE_TAIL_BYTES = bytes.fromhex(
    "e8830791"  # add  x8, sp, #0x1e0       (native ItemInfo result buffer)
    "220080d2"  # mov  x2, #1
    "9789f897"  # bl   grant_item_json
    "fb830691"  # add  x27, sp, #0x1a0      (restore the temp-string base)
    "cda6f517"  # b    0x89D154            (run the native response append)
)
RECYCLE_REWARD_FLAG_CAVE_BYTES = bytes.fromhex(
    "660500f0"  # adrp x6, #0xBE2000
    "d5bc0cb9"  # str  w21, [x6, #0xCBC]   (unused .data alignment gap)
    "b6021c0b"  # add  w22, w21, w28       (original instruction)
    "b4a5f517"  # b    0x89CEFC
)

# The old 2.5.2 implementation filled reward tables 102..111, but the native
# alchemy selector uses table ids such as 129/143 at runtime.  Filling the wrong
# tables corrupted unrelated rewards (Select All errors).  The replacement below
# captures the real 1..5 equipment grade at the start of the handler and forces
# the native reward pick to return a valid dummy row, so the completion cave can
# grant the class ticket without relying on the broken equipment reward lookup.
RECYCLE_GRADE_HOOK = 0x89CCD0
RECYCLE_GRADE_ORIGINAL = bytes.fromhex("1c3840b9")  # ldr w28,[x0,#0x38]
RECYCLE_GRADE_RETURN = 0x89CCD4
RECYCLE_GRADE_CAVE_VADDR = 0xAC8240
RECYCLE_GRADE_CAVE_SIZE = 0x10
RECYCLE_GRADE_CAVE_ORIGINAL_SHA256 = (
    "260e275ca67862a5af57d2a9eb68b63c4a07f49d9bdebaea8735a4e1fb209fdc"
)
RECYCLE_GRADE_CAVE_BYTES = bytes.fromhex(
    "1c3840b9"  # ldr  w28, [x0, #0x38]   (original grade load)
    "c60800d0"  # adrp x6, #0xBE2000
    "dc140fb9"  # str  w28, [x6, #0xF14]   (unused .data alignment gap)
    "a252f717"  # b    0x89CCD4
)

# pick_valid_battle_equip_reward fails in the offline server for the alchemy
# rows.  Redirect its shared failure path to a wrapper that only intervenes for
# the disassemble caller, writes a valid dummy row and returns success.
RECYCLE_PICK_HOOK = 0x9A3240
RECYCLE_PICK_ORIGINAL = bytes.fromhex("e0031f2a")  # mov w0,wzr
RECYCLE_PICK_CAVE_VADDR = 0xAC8290
RECYCLE_PICK_CAVE_SIZE = 0x38
RECYCLE_PICK_CAVE_ORIGINAL_SHA256 = (
    "88f7c7c9f44daaddc130cd84fc7f1300bcdcd8bb72926539fc54878811440573"
)
RECYCLE_PICK_CAVE_BYTES = bytes.fromhex(
    "a8eeffb0"  # adrp x8, #0x89D000
    "08110291"  # add  x8, x8, #0x84       (disassemble caller return address)
    "df0308eb"  # cmp  x30, x8
    "21010054"  # b.ne fail
    "9f7f00a9"  # stp  xzr, xzr, [x28]
    "9f7f01a9"  # stp  xzr, xzr, [x28, #0x10]
    "9f7f02a9"  # stp  xzr, xzr, [x28, #0x20]
    "c9208652"  # mov  w9, #0x3106
    "2920a072"  # movk w9, #0x101, lsl #16 ("01013106")
    "890b00b9"  # str  w9, [x28, #8]
    "20008052"  # mov  w0, #1
    "e46bfb17"  # b    0x9A324C
    "e0031f2a"  # fail: mov w0, wzr
    "e26bfb17"  # b    0x9A324C
)

# ---------------------------------------------------------------------------
# Recycling: 6★ equipment reward (native grant path)
# ---------------------------------------------------------------------------
# The native alchemy completion grants one equipment from
# ``kFwtEquipRewardRows`` (13,011 rows of {_weightNo, _weightValue,
# _equipCode}, 12 bytes each at .rodata 0x639760, vaddr == file offset).  The
# runtime selector is ``w21 + w28`` (0x65/0x6A + grade 1..5), i.e. groups
# 102..106 for normal bars and 107..111 for the final step.  Rewriting the
# ``_equipCode`` of those 873 rows keeps the native grant, response append and
# point accounting intact, unlike the ticket cave.
#
# 6★ equipment in this client is a grade-5 item with ``_secretegrade`` 3
# (e.g. 16864643 Absolute Gavel of Defense, grade 5 / secret 3).
RECYCLE_SIX_STAR_TABLE = 0x639760
RECYCLE_SIX_STAR_ROW_COUNT = 13011
RECYCLE_SIX_STAR_ENTRY_SIZE = 12
RECYCLE_SIX_STAR_CODE_OFFSET = 8
RECYCLE_SIX_STAR_GROUPS = (102, 103, 104, 105, 106, 107, 108, 109, 110, 111)
RECYCLE_SIX_STAR_EXPECTED_ROWS = 873
# The vanilla alchemy reward is a random piece (2★..6★) rolled by the client
# from these rows; the 6★ outcome is rare.  Distributing the game's own 6★ pool
# (the 30 grade-5/secret-3 pieces already present in group 106) across every
# reward row makes every roll a 6★ piece while keeping the random slot/set.
RECYCLE_SIX_STAR_GROUP_SLOT = {
    102: 1, 103: 2, 104: 3, 105: 4, 106: 5,
    107: 1, 108: 2, 109: 3, 110: 4, 111: 5,
}
# 6-star pieces (quality 5 + secret grade 3) grouped by the set they belong
# to, per equipment slot (grade 1..5).  Slot N pieces go to groups 0x65+N
# (normal) and 0x6A+N (final).  Each set has exactly three pieces.
RECYCLE_SIX_STAR_SLOT_SETS = {
    1: (
        (1004, (16848146, 33887506, 50795794)),
        (1003, (16848147, 33887505, 50861329)),
        (1014, (16848151, 33953044, 50795798)),
        (1017, (16848153, 33821986, 50926880)),
        (1101, (16848160, 33887509, 50926881)),
        (1109, (16848163, 33821992, 50795813)),
        (1110, (16848164, 33821993, 50861337)),
        (1011, (16913685, 33887507, 50795797)),
        (1102, (16913698, 33821988, 50926882)),
        (1108, (16979221, 33821991, 50926885)),
        (1111, (16979223, 33822001, 50795815)),
        (1112, (16979224, 33822002, 50861344)),
    ),
    2: (
        (2004, (16852242, 33891601, 50799892)),
        (2009, (16852244, 33957138, 50930961)),
        (2014, (16852246, 33957141, 50865429)),
        (2021, (16852260, 33826096, 50930981)),
        (2101, (16852261, 33826097, 50799908)),
        (2111, (16852263, 33826103, 50930994)),
        (2113, (16852264, 33826105, 50799912)),
        (2007, (16917778, 33826068, 50865426)),
        (2011, (16917780, 33891603, 50799894)),
        (2109, (16917793, 33957154, 50930992)),
        (2002, (16983313, 33826065, 50799890)),
        (2017, (16983321, 33826084, 50865440)),
        (2102, (16983329, 33826098, 50930983)),
        (2110, (16983334, 33826102, 50930993)),
        (2112, (16983335, 33826104, 50799911)),
    ),
    3: (
        (3003, (16856338, 33961235, 50803985)),
        (3017, (16856352, 33830181, 50935073)),
        (3021, (16856357, 33830193, 50804009)),
        (3121, (16856374, 33830225, 50804025)),
        (3129, (16856377, 33961252, 50869542)),
        (3011, (16921876, 33895698, 50803988)),
        (3105, (16921893, 33830208, 50804021)),
        (3122, (16921905, 33830226, 50935104)),
        (3130, (16921906, 33895719, 50869543)),
        (3005, (16987410, 33830161, 50803986)),
        (3014, (16987413, 33895699, 50935062)),
        (3123, (16987429, 33830227, 50935105)),
        (3106, (16987433, 33961250, 50869539)),
    ),
    4: (
        (4028, (16860423, 33834247, 50873607)),
        (4007, (16860436, 33834262, 50808085)),
        (4101, (16860451, 33834288, 50939172)),
        (4102, (16860452, 33834289, 50873619)),
        (4111, (16860454, 33965345, 50873622)),
        (4011, (16925973, 33834263, 50808086)),
        (4014, (16925974, 33899794, 50808088)),
        (4017, (16925984, 33834278, 50939171)),
        (4019, (16925985, 33834281, 50808102)),
        (4103, (16925986, 33965335, 50939173)),
        (4115, (16925992, 33834296, 50873623)),
        (4008, (16991505, 33965330, 50939154)),
        (4112, (16991524, 33834293, 50939176)),
        (4114, (16991525, 33834295, 50939177)),
        (4116, (16991526, 33834297, 50939184)),
    ),
    5: (
        (5009, (16864531, 33903890, 50877714)),
        (5103, (16864548, 33838385, 50943271)),
        (5003, (16930066, 33969425, 50812178)),
        (5014, (16930071, 33903893, 50877717)),
        (5101, (16930080, 33903905, 50943270)),
        (5102, (16930081, 33838384, 50812201)),
        (5011, (16995603, 33838358, 50812180)),
        (5017, (16995619, 33838376, 50877729)),
        (5020, (16995620, 33969442, 50943268)),
        (5110, (16995625, 33838388, 50943281)),
        (5111, (16995633, 33969445, 50943283)),
        (5112, (16995634, 33838389, 50943284)),
    ),
}
# Flattened view kept for the inspector/tests; order follows the set groups.
RECYCLE_SIX_STAR_SLOT_POOLS = {
    slot: tuple(code for _set_id, codes in sets for code in codes)
    for slot, sets in RECYCLE_SIX_STAR_SLOT_SETS.items()
}


def recycle_six_star_assignment(
    rows: list[tuple[int, int]],
    slot: int,
) -> list[tuple[int, int]]:
    """Returns (weight, code) for each alchemy row, equalizing set chances.

    The vanilla ``_weightValue`` column makes a few sets up to 31x more likely
    than the rest.  This distributes the group's original total weight evenly
    across the sets of the slot and spills each set's total evenly across the
    rows assigned to it.  The row order is preserved, so calling this on an
    already-equalized group produces identical output (idempotent).
    """
    sets = RECYCLE_SIX_STAR_SLOT_SETS[slot]
    row_count = len(rows)
    set_count = len(sets)
    if row_count == 0:
        return []
    total_weight = sum(max(0, weight) for weight, _code in rows) or row_count
    base_rows, extra_rows = divmod(row_count, set_count)
    base_weight, extra_weight = divmod(total_weight, set_count)
    result: list[tuple[int, int] | None] = [None] * row_count
    position = 0
    for index, (_set_id, codes) in enumerate(sets):
        assigned = base_rows + (1 if index < extra_rows else 0)
        if assigned == 0:
            continue
        set_total = base_weight + (1 if index < extra_weight else 0)
        pieces = len(codes)
        base_piece_rows, extra_piece_rows = divmod(assigned, pieces)
        base_piece_weight, extra_piece_weight = divmod(set_total, pieces)
        for piece in range(pieces):
            piece_rows = base_piece_rows + (1 if piece < extra_piece_rows else 0)
            if piece_rows == 0:
                continue
            piece_total = base_piece_weight + (1 if piece < extra_piece_weight else 0)
            row_weight, remainder = divmod(piece_total, piece_rows)
            for offset in range(piece_rows):
                weight = row_weight + (1 if offset < remainder else 0)
                result[position] = (weight, codes[piece])
                position += 1
    if position != row_count or any(item is None for item in result):
        raise RuntimeError("Internal recycling set assignment error")
    return [item for item in result if item is not None]
RECYCLE_SIX_STAR_CLIENT_ASSETS = (
    "files/Resources/datatable/equipreward.unity3d",
    "files/Resources/datatable/equiprewardjapan.unity3d",
)

# ---------------------------------------------------------------------------
# Gem Mining x10 (paid rolls)
# ---------------------------------------------------------------------------
# GemMiningStateAccess::mine calls change_gem_count_json with a hardcoded
# count of 1 at 0x8AB110.  Replacing it with 10 makes every gem-mining roll
# award ten gems of the same type, including the 20-crystal paid roll.
GEM_MINING_COUNT_SITE = 0x8AB110
GEM_MINING_COUNT_ORIGINAL = bytes.fromhex("22008052")  # mov w2,#1
GEM_MINING_COUNT_RETURN = 0x8AB114
GEM_MINING_CAVE_VADDR = CAMPAIGN_CAVE_BASE + 0x51C
GEM_MINING_CAVE_SIZE = 0x08
GEM_MINING_CAVE_ORIGINAL_SHA256 = (
    "d084764caf5b45de0c2299978b46f7c9eff2a952dabe0e53c732be1e73204e1b"
)
GEM_MINING_CAVE_BYTES = bytes.fromhex(
    "42018052"  # mov  w2, #10
    "38def517"  # b    0x8AB114
)

# Gem type restriction: the 20-crystal roll used to pick uniformly from the
# nine level-1 gem codes (attributes 1..9).  HP/ATK/DEF/CRIT (1/3/4/5) are sold
# directly in the Special Beginner Package, so remap the random index to the
# allowed pool: MP (2), Counter Rate (6), Counter Damage (7), Dodge (8) and
# Hit Rate (9).  Index -> attribute lookup: 1,5,6,7,8 (zero based).
GEM_MINING_TYPES_HOOK = 0x8AB08C
GEM_MINING_TYPES_ORIGINAL = bytes.fromhex("e81700b0")  # adrp x8,#0xba8000
GEM_MINING_TYPES_CAVE_VADDR = 0xAC8260
GEM_MINING_TYPES_CAVE_SIZE = 0x29
GEM_MINING_TYPES_CAVE_ORIGINAL_SHA256 = (
    "00576e04d07e5dad523931dc1c6b55116e1df65e064daabdddc2e549a0185735"
)
GEM_MINING_TYPES_CAVE_BYTES = bytes.fromhex(
    "a90080d2"  # mov  x9, #5
    "2a0bc99a"  # udiv x10, x25, x9
    "4be5099b"  # msub x11, x10, x9, x25   (random index % 5)
    "0c000090"  # adrp x12, #0xAC8000
    "8c110a91"  # add  x12, x12, #0x284
    "99696b38"  # ldrb w25, [x12, x11]     (allowed table index)
    "08070090"  # adrp x8, #0xBA8000
    "08e11191"  # add  x8, x8, #0x478
    "858bf717"  # b    0x8AB094
    "0105060708"  # allowed zero-based indices: 1,5,6,7,8
)

# ---------------------------------------------------------------------------
# Gem Level 6
# ---------------------------------------------------------------------------
# The lobby gem table at 0xBA8478 points to the nine level-1 gem code strings
# ("16781" .. "96781", attributes 1..9).  The gem level is the last digit of
# the code, so rewriting that digit to "6" makes every gem obtained or bought
# through the lobby gem screen a level-6 gem while keeping the attribute.
GEM_LEVEL6_STRINGS = (
    0x21BD6F,  # 16781 HP
    0x4D4F78,  # 26781 MP
    0x499897,  # 36781 ATK
    0x5FE5E8,  # 46781 DEF
    0x3B2D83,  # 56781 CRIT
    0x2A3B7E,  # 66781 Counter Rate
    0x41516C,  # 76781 Counter Damage
    0x546E6C,  # 86781 Dodge
    0x505EC3,  # 96781 Hit Rate
)
GEM_LEVEL6_ORIGINAL_CHAR = b"1"
GEM_LEVEL6_REPLACEMENT_CHAR = b"6"

# GemStateAccess::graft subtracts the client-provided fee_gold from the lord's
# gold at 0x8ACA6C.  Shifting the fee right by one halves the actual charge for
# every lobby gem upgrade without touching the duplicate cost.
GEM_UPGRADE_GOLD_SITE = 0x8ACA6C
GEM_UPGRADE_GOLD_ORIGINAL = bytes.fromhex("c0021acb")  # sub x0, x22, x26
GEM_UPGRADE_GOLD_REPLACEMENT = bytes.fromhex("c0065acb")  # sub x0, x22, x26, lsr #1

# ---------------------------------------------------------------------------
# Coocoo EXP x2 Always Active
# ---------------------------------------------------------------------------
# SUMEXP_CREATURE normally doubles the EXP only when one of the selected
# stuff items has item_category 4.  The flag is ORed in the per-item loop:
#   cmp w8, #4 ; cset w8, eq ; orr w9, w8, w9
# Replacing the cset with mov w8, #1 keeps the x2 multiplier active for any
# selected EXP material.
COOCOO_EXP_X2_SITE = 0x7FCF30
COOCOO_EXP_X2_ORIGINAL = bytes.fromhex("e8179f1a")  # cset w8, eq
COOCOO_EXP_X2_REPLACEMENT = bytes.fromhex("28008052")  # mov w8, #1

# ---------------------------------------------------------------------------
# 50% Dungeon Stamina Cost
# ---------------------------------------------------------------------------
# BattleSecondStartStateAccess::charge subtracts the client-validated stamina
# cost (x5/x28) from the current stamina.  The validation still uses the
# original full cost, so the client request remains accepted; only the
# deduction becomes half.  The same site covers normal, TOG, riddle,
# infinity, defense and collaboration/Lost Island battle starts.
STAMINA_HALF_SITE = 0x8D744C
STAMINA_HALF_ORIGINAL = bytes.fromhex("60031ccb")  # sub x0, x27, x28
STAMINA_HALF_REPLACEMENT = bytes.fromhex("60075ccb")  # sub x0, x27, x28, lsr #1

# ---------------------------------------------------------------------------
# Stamina Potion: 1000 points per use
# ---------------------------------------------------------------------------
# StaminaItemStateAccess::use_potion reads max_stamina and adds it to the
# current stamina.  The csinc below materializes max_stamina (clamped to 1);
# replacing it with mov x21, #1000 makes the normal (non-PVP) potion add 1000
# points instead of the current max stamina.
STAMINA_POTION_1000_SITE = 0x8EC1E8
STAMINA_POTION_1000_ORIGINAL = bytes.fromhex("15c49f9a")  # csinc x21, x0, xzr, gt
STAMINA_POTION_1000_REPLACEMENT = bytes.fromhex("157d80d2")  # mov x21, #1000

# ---------------------------------------------------------------------------
# English Localization Sites / DEX offsets
# ---------------------------------------------------------------------------
ENGLISH_SO_GATES = (
    (0xAA7CFC, 0xAA7D40),  # string table gate
    (0xAA7DB0, 0xAA7E24),  # message-box gate
)
ENGLISH_SO_GATE_ORIGINALS = {
    0xAA7CFC: bytes.fromhex("21020054"),
    0xAA7DB0: bytes.fromhex("a1030054"),
}
# The bootstrap strings are rewritten through smali (see core.dex_smali); the
# old fixed-offset DEX string patch violated ART's lexicographic string-table
# verification and is intentionally gone.

# LAN redirect DEX patches: (offset, length)
LAN_DEX_BACKUP_PATCHES = ((0x006148, 4), (0x005D7C, 6))

# Event-coin range is part of the same non-overlap validation.
EVENT_COIN_CAVE_RANGE = (EVENT_COIN_CAVE_VADDR, EVENT_COIN_CAVE_VADDR + EVENT_COIN_CAVE_SIZE)

# Expected reference-build change counts. These catch silent no-ops and
# version drift; non-reference inputs require allow_unknown=True.
EXPECTED_PATCH_COUNTS = {
    "summon_rates": 84 + 144,
    "summon_rates_50_30_20": 84 + 144,
    "expedition_bonus": len(EXPEDITION_REGIONS) + len(EXPEDITION_CALL_SITES),
    "gene_priority": 141,
    "no_equip_drops": 431,
    "campaign_xp": 381,
    "campaign_gold": 381,
    "campaign_shop_discount": 104,
    "mode_drops_x10": WORLDBOSS_CYCLE_REWARD_TARGET_COUNT + 1 + 1 + 126 + 82 + RIDDLE_ROW_COUNT + 3 + 1,
    "battle_arena_fix": len(ARENA_WEEK_STATE_SITES) + 1 + 4 + 3,
    "guild_raid_mercenary": 4,
    "guild_raid_reward_x10": 32,
    "event_discount": 122,
    "event_gene_unlimited": EXPECTED_EVENT_GENE_ROWS,
    "event_limits_daily": EXPECTED_EVENT_LIMIT_ROWS + 3,
    "mythical_stone_shop": 4,
    "hero_shop_offers": 6,
    "surprise_transcendence_package": 6,
    "alex_awakening": 1,
    "alex_heros_mark": 8,
    "costume_packages_all": 10,
    "equipment_tier_upgrades": 4,
    "recycle_six_star": RECYCLE_SIX_STAR_EXPECTED_ROWS,
    "gem_mining_x10": 1,
    "gem_mining_types": 2,
    "gem_level6": 9,
    "gem_upgrade_gold_half": 1,
    "rune_upgrade_discount": 4,
    "gold_cylinder_fix": 0,
    "energy_flask_x10": 1,
    "gold_cylinder_x10": 2,
    "mana_cylinder_x10": len(MANA_CYLINDER_X10_SITES),
    "event_coin_x10": 1,
    "guild_raid_score_fix": 2,
    "guild_raid_fire_support": 2,
    "guild_raid_protection_persist": 2,
    "single_black_hammer": 1,
    "single_gem_fang": 5,
    "upgrade_no_fail_above_20": 5,
    "devil_boost_x10": 1,
    "battle_arena_save_fix": 1,
    "coocoo_exp_x2": 1,
    "coocoo_level_x2": len(COOCOO_STAGE_LEVELS),
    "worldboss_full_ship_repair": len(WORLDBOSS_FULL_SHIP_REPAIR_SITES),
    "ship_parts_90_off": sum(
        1 for _offset, values in SHIP_PART_COST_TABLES for value in values if value
    ),
    "crystal_skill_90_off": 1,
    "stamina_cost_half": 1,
    "stamina_potion_1000": 1,
    # 51 translated bootstrap literals + the saveCopy English branch, plus the
    # two SO localization gates and the "Qty" rodata replacement.
    "english_localization": len(ENGLISH_SO_GATES) + 1 + 51 + 1,
    # One row per option-table entry: the bias rewrites the whole table so only
    # each attribute/grade pool's top-quality rows stay weighted.
    "option_max_attributes": 1856,
    "rune_box_random_type": len(RUNE_BOX_TYPE_REWRITES),
    "rune_quality_factor": 1,
    "rune_box_random_roll": len(RUNE_ROLL_SITES) + 2,
    "equipment_lock_fix": 1,
    "equipment_single_mod_stone": 3,
    "equipment_percent_options": 597,
    "equipment_upgrade_10_guarantee": 1,
    "limit_break_cost_tenth": LIMIT_BREAK_GOLD_ROWS,
    "limit_break_cost_fixed": LIMIT_BREAK_GOLD_ROWS,
    "limit_break_step_10": LIMIT_BREAK_GOLD_ROWS,
    "soulgear_enchant_always": 1,
    "no_win_box": 2,
    "hero_exp_cap": 4,
    "convert_hex_guard": 2,
    "dungeon_recom_info": 2,
    "merlin_auto_support": 4,
    "rune_option_quality": 1,
    "trait_max_quality": 130,
    "trait_allow_duplicates": 1,
    "trait_multi_unique": 7,
    "trait_immunity_weight_x2": 3,
    "lan_redirect": 1,
}

# Patches whose change count legitimately drops to zero when the same input is
# patched twice.  Declared once so a new idempotent patch cannot silently drift
# out of the list and abort the second pass.
IDEMPOTENT_PATCHES: frozenset[str] = frozenset({
    "summon_rates",
    "summon_rates_50_30_20",
    "option_max_attributes",
    "trait_max_quality",
    "trait_allow_duplicates",
    "trait_multi_unique",
    "trait_immunity_weight_x2",
    "rune_box_random_type",
    "rune_quality_factor",
    "rune_box_random_roll",
    "equipment_lock_fix",
    "equipment_single_mod_stone",
    "equipment_percent_options",
    "equipment_upgrade_10_guarantee",
    "limit_break_cost_tenth",
    "limit_break_cost_fixed",
    "limit_break_step_10",
    "soulgear_enchant_always",
    "rune_upgrade_discount",
    "gold_cylinder_fix",
    "no_win_box",
    "hero_exp_cap",
    "convert_hex_guard",
    "dungeon_recom_info",
    "merlin_auto_support",
    "rune_option_quality",
    "expedition_bonus",
    "gene_priority",
    "no_equip_drops",
    "campaign_xp",
    "campaign_gold",
    "campaign_shop_discount",
    "mode_drops_x10",
    "event_discount",
    "event_gene_unlimited",
    "event_limits_daily",
    "mythical_stone_shop",
    "hero_shop_offers",
    "surprise_transcendence_package",
    "costume_packages_all",
    "equipment_tier_upgrades",
    "event_coin_x10",
    "english_localization",
    "guild_raid_score_fix",
    "lan_redirect",
    "recycle_six_star",
    "gold_cylinder_x10",
    "mana_cylinder_x10",
    "gem_mining_x10",
    "gem_mining_types",
    "gem_level6",
    "gem_upgrade_gold_half",
    "single_black_hammer",
    "single_gem_fang",
    "energy_flask_x10",
    "stamina_cost_half",
    "stamina_potion_1000",
    "upgrade_no_fail_above_20",
    "devil_boost_x10",
    "coocoo_exp_x2",
    "coocoo_level_x2",
    "crystal_skill_90_off",
    "ship_parts_90_off",
    "worldboss_full_ship_repair",
    "battle_arena_fix",
    "battle_arena_save_fix",
    "guild_raid_mercenary",
    "guild_raid_reward_x10",
    "guild_raid_fire_support",
    "guild_raid_protection_persist",
    "alex_heros_mark",
    "dev_log_dispatch",
    "dev_build_marker",
    "dev_dispatch_hook",
    "dev_handler_timing",
})

# ---------------------------------------------------------------------------
# LAN Redirect Trampoline Shim
# ---------------------------------------------------------------------------
SHIM_VADDR = 0xAB6858
SHIM_MAX_BYTES = 0xAB7650 - SHIM_VADDR  # 3,576 bytes
SHIM_MAGIC = 0x4E414C46  # "FLAN"

EMBEDDED_SHIM_B64 = (
    "hQAAFAUAABRGTEFOwKhEZh9KAQAAAAAA/Xu+qeAHAan9AwCRCAAAlOAHQan9e8Ko/8MA0XD+/xAQ"
    "IkDREHI50QACH9b/gwHR/XsBqf1DAJH5EwD5+F8DqfZXBKn0TwWpgAQAtCj9/xAIFUB5KAQANPMD"
    "AKoIAED5yAMAtABFQPkBAACwCRlA+SEAAZEWxUH5oA8A+QBdQPkYNUL5FUFC+eAHAPngAxOqGUVC"
    "+ReRQ/kgAT/WwAAAtPQDAKrgAxOq4AI/1h8cAHIgAgBU4AMTqqEPQPn0T0Wp9ldEqfhfQ6n9e0Gp"
    "+RNA+f+DAZEgAB/W9E9FqfZXRKn4X0Op/XtBqfkTQPn/gwGRwANf1gIAALADAACwQkQBkWOoAZHg"
    "AxOq4QMUqqACP9bAAAC09QMAquADE6rgAj/WHxwAcsABAFTgAxOqoQ9A+SAAP9bgAxOq4QMUqvRP"
    "Ran2V0Sp+F9Dqf17QaniB0D5+RNA+f+DAZFAAB/W4AMTquEDFKriAxWqIAM/1uD9/7T1AwCq4AMT"
    "quACP9YfHAByQf3/VAIAALADAACwQvQBkWNQAZHgAxOq4QMUqsACP9bgAQC09gMAquADE6rgAj/W"
    "HxwAckEBAFTgAxOq4QMUquIDFqrjAxWqAAM/1uADE6rgAj/WHxwAcoAAAFTgAxOqoQ9A+SAAP9bg"
    "AxOq4QMVquIHQPlAAD/Wz///F//DAdH0Twap8wMAKiAAgBL9ewOp9yMA+f3DAJH2VwWpAQ4AtF8I"
    "AHHDDQBUow0AtCgAQHn0AwGqHykAceADAFQfCQBxIQcAVF9AAHEjCQBUoHMAkaFjAJHjBwD5vx8A"
    "ub8zAHllAACUiQZAuagfQLkqHQASX/0BcWAAAFQ/AQhrgQcAVIACwD3qQ4lS4AeAPeknQHnoFwC5"
    "PwEKa2EAAFSoM0B56CcAeeFDAJHgAxMqAgKAUkkAABRfcABxowUAVIkqQSmIWkIp4wcA+SkBCioq"
    "AQgqXwEAcQogoFLrF58a3wIKa+oXnxp1AQoK6QIANR9BQDGhAgBUoHMAkaFjAJHIHgASvx8AuR/9"
    "AXG/MwB59xefGjkAAJSoH0C53wIIa+gXnxoQAAAU4AMTKuEDFKr0T0ap9ldFqf17Q6n3I0D5/8MB"
    "kWAAH9agcwCRoWMAkb8fALm/MwB5KAAAlPcDHyroAx8qqQIXKokAADdoAAA1IACAEhsAABRgfkCT"
    "/xMAueNDAJEhBYBSQgOAUoQAgFIIGoBSAQAA1IkGQHkIAACwqjNAeexDiVJLAYBS4UMAkT8BDGsA"
    "DcA9SAGJGqkfQLngAxMqggOAUusjAHngQ4E86CcAeen/BCnjB0D5YAA/1vRPRqn2V0Wp/XtDqfcj"
    "QPn/wwGRwANf1v9DAtHL3/8QbAVAue0DAJEPwITSBQAAsOoDAaoMAAC56QMAqugDH6ouAIBSLwDA"
    "8mwRQHlQAYBSKwCAUrEZAJGkAUCypYADkfhfBqn2Vwep9E8IqSwAAHkEAAAU6wMfKigAgFKDGgA2"
    "qHiouOMDH6pgDICS4gMfqqEACIsIB4BSAQAA1OMDCyqg/v+3DHxAk+EDAJHgAwyq4guAUugHgFIB"
    "AADU6wMAquADDKooB4BSAQAA1H8FAPEr/f9U7AMfqr9pKzioaWw4wCHImh+BAHEIAA+KBJlA+qAA"
    "AFSMBQCRfwEM6wH//1TsAwuqaAEMyx8dAPFLAwBUqGlsOB+hAXHhAgBUiAENiwAFQDkf0AFxYQIA"
    "VAgJQDkf0QFxAQIAVIgBDYsADUA5H8ABcYEBAFQIEUA5H+kAcSEBAFSIAQ2LABVAOR+8AHGhAABU"
    "CBlAOYAdAJEfvQBxDACMmp8BC+vq9/9UpmlsOMjAAFEfJQBxaPf/VGABDMvoAx8qggUAkZQNAJGV"
    "FQCRLAIMixYYANEIGRAbCMEAUR/9A3FkkUL64PX/VKZpYjjgAxSq4QMVqucDDKrzAxaqQgQAkZQG"
    "AJG1BgCRjAUAkdYGANHXwABR/yYAcen9/1RMBADRnwEL6+rz/1TfuABxofP/VF8AC+tq8/9UtWli"
    "OKzCAFGfJQBx6PL/VOwDHyqMVRAbjMEAUZ/9A3FkkUD6IPL/VLVpYDjiAwGq5gMHqvQDE6oABACR"
    "IQQAkecEAJFzBgDRtsIAUd8mAHEp/v9UAQQA0T8AC+tq8P9Uv7oAcSHw/1QfAAvr6u//VLVpYDig"
    "wgBRHyQAcWjv/1ThAx8q9gMAkfcDC6rgAwKqIVQQGyHAAFE//ANxRJBX+kDu/1TVamI45wMGqvMD"
    "FKoABACR1gYAkfcGANHGBACRlAYA0bjCAFEfJwBxKf7/VAIEANFfAAvriuz/VL+6AHFB7P9UHwAL"
    "6wrs/1TmAx8q4gMfKvQAQDmVwgBRvyYAcYgBAFRCUBAbQsAAUV/8A3HI6v9UAAQAkcYEAFHnBACR"
    "cwYA8YH+/1TgAwuqAgAAFMbp/zSIHRgzKBwQM0gcCDNI6f80HwAL66oDAFSsaWA4n+kAcUEDAFQM"
    "BACRnwEL6+oCAFTiAyCq4QMfquwDHyqAAACLSwALiwJoYThGwABR3yQAcSgBAFSMCRAbjMEAUYJ9"
    "EFOi5v81IQQAkX8BAevB/v9UIQCAUqEAADSMAAA0iwnAWmt9EFNLAQB5KAEAufRPSKn2V0ep+F9G"
    "qf9DApHAA1/WAAAAAAAAAAAAAAAAAAAAAAAA//9qYXZhL3V0aWwvTG9jYWxlAFVTAChMamF2YS91"
    "dGlsL0xvY2FsZTspVgBMamF2YS91dGlsL0xvY2FsZTsAc2V0RGVmYXVsdAAvc2RjYXJkL0Rvd25s"
    "b2FkL2Z3dC9zZXJ2ZXIudHh0AC9zZGNhcmQvQW5kcm9pZC9kYXRhL2NvbS5uZXhvbi5md2FyL2Zp"
    "bGVzL3NlcnZlci50eHQAAAAAqP///8j///8="
)

ARM64_NOP = bytes.fromhex("1f2003d5")
ARM64_RET = bytes.fromhex("c0035fd6")
ARM64_MOV_W0_1 = bytes.fromhex("20008052")

SERVER_SPAWN_BL_VADDRS = (
    0xAADF34, 0xAADF3C, 0xAADF44,
    0xAADF54, 0xAADF5C, 0xAADF64,
    0xAAE014, 0xAAE01C, 0xAAE024,
    0xAAE06C, 0xAAE074, 0xAAE07C,
)

LAN_SITE_ORIGINALS = {
    0xAAD9F8: bytes.fromhex("ffc300d1"),  # sub sp, sp, #0x30
    0xAA6D70: bytes.fromhex("940300b4"),  # cbz x20, ...
    0xAB5D48: bytes.fromhex("b6460294"),  # bl ...
    0xAAE450: bytes.fromhex("fd7bbaa9"),  # stp x29, x30, ...
    0xAADE84: bytes.fromhex("6b600294"),  # bl ...
    0xAADFA0: bytes.fromhex("18600294"),  # bl ...
}

SERVER_SPAWN_ORIGINALS = {
    0xAADF34: bytes.fromhex("4fffff97"),
    0xAADF3C: bytes.fromhex("d5650294"),
    0xAADF44: bytes.fromhex("d7650294"),
    0xAADF54: bytes.fromhex("47ffff97"),
    0xAADF5C: bytes.fromhex("cd650294"),
    0xAADF64: bytes.fromhex("cf650294"),
    0xAAE014: bytes.fromhex("72040094"),
    0xAAE01C: bytes.fromhex("9d650294"),
    0xAAE024: bytes.fromhex("9f650294"),
    0xAAE06C: bytes.fromhex("5c040094"),
    0xAAE074: bytes.fromhex("87650294"),
    0xAAE07C: bytes.fromhex("89650294"),
}

LOOPBACK_CONNECT_STUB = bytes.fromhex(
    "e003152a"  # mov w0, w21          (sockfd)
    "e10314aa"  # mov x1, x20          (addr)
    "e203132a"  # mov w2, w19          (addrlen)
    "b73e0094"  # bl  0xab6858         (fwt_shim_header -> fwt_lan_connect_impl; x3 = real_connect)
    "1f080031"  # cmn w0, #2           (check -2 blocked sentinel)
    "e0020054"  # b.eq 0xaa6de0        (jump to existing ENETUNREACH block handler)
    "f44f42a9"  # ldp x20, x19, [sp, #32]
    "f65741a9"  # ldp x22, x21, [sp, #16]
    "fd7bc3a8"  # ldp x29, x30, [sp], #48
    "c0035fd6"  # ret
)


@dataclass
class DevOptions:
    """Dev-only instrumentation for reverse engineering the patched build.

    Nothing here is ever enabled by ``--all``: the master switch ``enabled``
    must be set explicitly (CLI ``--dev``, GUI Development card).  Two
    invariants are enforced elsewhere and must stay true:

    * a dev build is always written to a ``*-dev.apk`` path (CLI and GUI refuse
      any other name), so it can never be mistaken for a release artifact;
    * with every field left at its default the patched binaries are
      byte-identical to a release build (asserted in the test suite).
    """

    enabled: bool = False            # master switch, required by every other field
    debuggable: bool = False         # android:debuggable=true -> run-as/JDWP without root
    keep_version: bool = False       # leave android:versionName untouched on a dev build
    log_dispatch: bool = False       # log request/response of the JSON dispatcher
    log_body_limit: int = 1024       # bytes logged per message (0 = whole body)
    log_commands: str = ""           # CSV whitelist of commands; empty = every command
    hit_counters: bool = False       # per-cave execution counters
    build_marker: bool = False       # "FWTR-DEV <version> <sha8>" logged at boot
    log_responses: bool = False      # log the response body at the dispatcher exit
    handler_timing: bool = False     # cntvct_el0 timing around the JSON dispatcher
    state_snapshots: bool = False    # numbered state mirror for diffing
    dev_endpoint: bool = False       # DEV_DUMP command served by the embedded server
    lab_traps: bool = False          # brk #0 dead-code traps / AppSealing experiments

    _INSTRUMENTATION = (
        "debuggable",
        "log_dispatch",
        "hit_counters",
        "build_marker",
        "log_responses",
        "handler_timing",
        "state_snapshots",
        "dev_endpoint",
        "lab_traps",
    )

    def instrumentation(self) -> tuple[str, ...]:
        """Returns the enabled instrumentation names (master switch excluded)."""
        return tuple(name for name in self._INSTRUMENTATION if getattr(self, name))

    @property
    def any_instrumentation(self) -> bool:
        return bool(self.instrumentation())

    def validate(self) -> None:
        """Raises ValueError for inconsistent or unsupported dev combinations."""
        if self.any_instrumentation and not self.enabled:
            names = ", ".join(self.instrumentation())
            raise ValueError(
                f"dev instrumentation ({names}) requires the dev master switch; "
                "pass --dev (CLI) or enable the Development card (GUI)."
            )
        if self.log_body_limit < 0:
            raise ValueError("dev log_body_limit must be >= 0 (0 logs whole bodies)")


@dataclass
class PatchOptions:
    """User-selectable patch options."""
    campaign_gold: bool = False      # 10x Campaign Gold & Drops
    campaign_xp: bool = False        # 10x Campaign XP
    no_equip_drops: bool = False     # Remove equipment from stage drop pools
    gene_priority: bool = False      # Hero Gene Priority
    summon_rates: bool = False       # 70/20/10 Equipment Summon Rates (70% 4★, 20% 5★, 10% 6★)
    summon_rates_50_30_20: bool = False  # 50/30/20 Equipment Summon Rates (50% 4★, 30% 5★, 20% 6★)
    expedition_bonus: bool = False   # 10x Expedition Rewards
    english_localization: bool = False  # English UI & localization gates
    event_discount: bool = False     # 90% Event Shop Discount
    event_gene_unlimited: bool = False  # Remove daily Event Shop gene limit (unlimited)
    event_limits_daily: bool = False    # Convert event-limited shop rows to daily reset
    mythical_stone_shop: bool = False  # Mythical Stone and Balance Jade event offers
    hero_shop_offers: bool = False  # Evan and Alex genes, 100 Diamonds
    surprise_transcendence_package: bool = False  # Surprise Sale offer 75103
    alex_awakening: bool = False  # Original Alex Awakening and Destiny Lance
    alex_rebalance: bool = False  # Rebalance Alex Skills 1-3, Passive, and Awake Thornbush
    costume_packages_all: bool = False  # One copy of each eligible owned costume
    equipment_tier_upgrades: bool = False  # One hammer completes each tier
    recycle_six_star: bool = False        # Recycling grants a native 6★ equipment
    energy_flask_x10: bool = False   # Energy Flask awards 1000 stamina instead of 100
    option_max_attributes: bool = False  # option-change potion rolls the best attributes
    rune_box_random_type: bool = False   # 4★ random rune box rolls any of the three types
    rune_quality_factor: int = 0         # 0 = off; N scales the rune attribute-quality bonus
    rune_box_random_roll: bool = False   # rune box rolls slot/type again (quality stays fixed)
    equipment_lock_fix: bool = False     # locked option lines survive the first roll
    equipment_single_mod_stone: bool = False  # 1 modification stone regardless of locks
    equipment_percent_options: bool = False   # only percent equipment option rows roll
    equipment_upgrade_10_guarantee: bool = False  # +9 -> +10 upgrade always succeeds
    limit_break_cost_tenth: bool = False  # creature transcend costs 90% less
    limit_break_cost_fixed: bool = False  # every hero limit break costs 1M gold + 100 jade
    limit_break_step_10: bool = False     # limit break opens +10 levels per step (up to Lv120)
    soulgear_enchant_always: bool = False  # gold-paid soulgear enchant always works
    rune_option_quality: bool = False    # rune rolls use the maximum mastery bonus
    rune_upgrade_discount: bool = False  # +12..+15 always succeed and cost a tenth
    gold_cylinder_x10: bool = False  # Gold Cylinder yields 10x gold per collection
    mana_cylinder_x10: bool = False  # Mana Stone Compactor yields 10x mana per charge
    event_coin_x10: bool = False     # 10x Event Coin Drop on Campaign Stages
    guild_raid_score_fix: bool = False  # 64-bit Guild Raid scores above 2.5B
    single_black_hammer: bool = False   # 1 black hammer for +16..+26
    single_gem_fang: bool = False       # 1 Dragon Fang per gem slot
    upgrade_no_fail_above_20: bool = False  # 100% success for +21..+26
    battle_arena_save_fix: bool = False  # Fix the Battle Arena team Save button
    sacred_lands_restore: bool = False   # Restore Sacred Lands set grade and ticket lists
    coocoo_exp_x2: bool = False         # Always apply the x2 EXP bonus with coocoos
    coocoo_level_x2: bool = False       # Double the coocoo levels dropped by Coocoo Gardens
    ship_parts_90_off: bool = False     # 90% off Unknown Paradise battleship part upgrades
    worldboss_full_ship_repair: bool = False  # restore full HP on successful repair
    crystal_skill_90_off: bool = False  # 90% off Unknown Paradise core crystal upgrades
    gem_mining_x10: bool = False        # Paid gem mining rolls award 10 gems
    gem_mining_types: bool = False      # Restrict gem rolls to MP/Counter/Dodge/Hit
    gem_level6: bool = False            # Gems obtained/bought are level 6
    gem_upgrade_gold_half: bool = False  # 50% off the gold fee of lobby gem upgrades
    stamina_cost_half: bool = False     # 50% dungeon entry stamina cost (server-side; used by --all)
    stamina_potion_1000: bool = False   # Stamina potions restore 1000 points
    campaign_shop_discount: bool = False  # 90% discount across campaign shops
    mode_drops_x10: bool = False          # 10x drops across 6 game modes
    devil_boost_x10: bool = False         # 10x Devil's Soul EXP-synthesis boost
    battle_arena_fix: bool = False        # Battle Arena team configuration save and slot fix
    guild_raid_mercenary: bool = False    # Allow selecting own mercenary in Guild Raid
    guild_raid_reward_x10: bool = False   # 10x Guild Raid daily/weekly rank rewards
    guild_raid_fire_support: bool = False  # Fire Support 100% HP + minion-aware auto-cast
    guild_raid_skills_max: bool = False    # Max remaining 3 Guild Raid skills (1M/100%)
    guild_raid_boss_no_counter: bool = False  # Zero Guild Raid boss counter rate (0%)
    guild_raid_protection_persist: bool = False  # Absolute Protection DR covers all hits until expiry
    alex_heros_mark: bool = False  # Alex's Hero's Mark "The Unbroken Lance" (12.03)
    trait_max_quality: bool = False  # hero trait rolls always land on top quality (grade 5)
    trait_allow_duplicates: bool = False  # allow repeating the same trait type across slots
    trait_multi_unique: bool = False  # multi-roll trait batches never repeat attribute types
    trait_immunity_weight_x2: bool = False  # double slot 3..5 immunity trait weights (20000)
    merlin_auto_support: bool = False  # Merlin Slot-1 Auto Mode casts Magic infusion on Awake CD==1 ally
    lan_redirect: bool = False       # Redirect loopback to LAN server
    server_ip: str = "127.0.0.1"     # Target LAN IP (if lan_redirect enabled)
    server_port: int = 8010          # Target LAN port (if lan_redirect enabled)
    align_16k: bool = True           # Android 16 / 16 KB page-size alignment
    allow_unknown: bool = False      # Advanced: patch a non-reference APK
    dev: DevOptions = field(default_factory=DevOptions)  # Dev-only instrumentation

    def has_selected_feature(self) -> bool:
        """Return True if at least one patch feature or dev instrumentation flag is enabled."""
        non_feature = {"server_ip", "server_port", "align_16k", "allow_unknown", "dev"}
        for name, value in vars(self).items():
            if name in non_feature:
                continue
            if isinstance(value, bool):
                if value:
                    return True
            elif isinstance(value, int) and value > 0:
                return True
        return self.dev.any_instrumentation


@dataclass
class PatchResult:
    """Output and diagnostics from apply_all_patches()."""
    so_bytes: bytes
    dex_bytes: bytes
    so_sha256: str  # SHA-256 of the patched output library
    dex_sha256: str  # SHA-256 of the patched output DEX
    input_so_sha256: str = ""
    input_dex_sha256: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    applied: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def encode_arm64_branch(src_vaddr: int, dst_vaddr: int, *, link: bool = False) -> bytes:
    """Encodes a 32-bit ARM64 unconditional branch (`b` or `bl`)."""
    delta = dst_vaddr - src_vaddr
    if delta % 4 != 0:
        raise ValueError(f"Unaligned ARM64 branch delta: 0x{src_vaddr:x} -> 0x{dst_vaddr:x}")
    if not -(1 << 27) <= delta < (1 << 27):
        raise ValueError(
            f"ARM64 branch target out of range: 0x{src_vaddr:x} -> 0x{dst_vaddr:x} "
            f"(delta {delta:+#x}, max +/- 128 MiB)"
        )
    imm26 = (delta // 4) & 0x03FFFFFF
    opcode = (0x94000000 if link else 0x14000000) | imm26
    return struct.pack("<I", opcode)


# ---------------------------------------------------------------------------
# Minimal AArch64 encoders used by the dev-build caves
# ---------------------------------------------------------------------------
def encode_adrp(pc_vaddr: int, target_vaddr: int, rd: int) -> bytes:
    """Encodes ``adrp x<rd>, #page(target)``."""
    delta = (target_vaddr & ~0xFFF) - (pc_vaddr & ~0xFFF)
    if not -(1 << 32) <= delta < (1 << 32):
        raise ValueError(f"adrp target out of range: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    pages = delta >> 12
    immlo = pages & 0x3
    immhi = (pages >> 2) & 0x7FFFF
    return struct.pack("<I", 0x90000000 | (immlo << 29) | (immhi << 5) | rd)


def encode_adr(pc_vaddr: int, target_vaddr: int, rd: int) -> bytes:
    """Encodes ``adr x<rd>, target`` (PC-relative, +/-1 MiB)."""
    delta = target_vaddr - pc_vaddr
    if delta % 4 != 0:
        raise ValueError(f"unaligned adr target: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    if not -(1 << 20) <= delta < (1 << 20):
        raise ValueError(f"adr target out of range: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    immlo = delta & 0x3
    immhi = (delta >> 2) & 0x7FFFF
    return struct.pack("<I", 0x10000000 | (immlo << 29) | (immhi << 5) | rd)


def encode_add_imm(rd: int, rn: int, imm: int) -> bytes:
    """Encodes ``add x<rd>, x<rn>, #imm`` (64-bit, no shift)."""
    if not 0 <= imm < 0x1000:
        raise ValueError(f"add immediate out of range: {imm}")
    return struct.pack("<I", 0x91000000 | (imm << 10) | (rn << 5) | rd)


def encode_add_sp(imm: int) -> bytes:
    """Encodes ``add sp, sp, #imm``."""
    if not 0 <= imm < 0x1000:
        raise ValueError(f"add sp immediate out of range: {imm}")
    return struct.pack("<I", 0x91000000 | (imm << 10) | (31 << 5) | 31)


def encode_sub_sp(imm: int) -> bytes:
    """Encodes ``sub sp, sp, #imm``."""
    if not 0 <= imm < 0x1000:
        raise ValueError(f"sub sp immediate out of range: {imm}")
    return struct.pack("<I", 0xD1000000 | (imm << 10) | (31 << 5) | 31)


def encode_stp_sp(rt: int, rt2: int, imm: int) -> bytes:
    """Encodes ``stp x<rt>, x<rt2>, [sp, #imm]`` (64-bit, signed offset)."""
    if imm % 8 or not -512 <= imm <= 504:
        raise ValueError(f"stp offset must be a multiple of 8 in [-512, 504]: {imm}")
    scaled = (imm // 8) & 0x7F
    return struct.pack("<I", 0xA9000000 | (scaled << 15) | (rt2 << 10) | (31 << 5) | rt)


def encode_ldp_sp(rt: int, rt2: int, imm: int) -> bytes:
    """Encodes ``ldp x<rt>, x<rt2>, [sp, #imm]`` (64-bit, signed offset)."""
    if imm % 8 or not -512 <= imm <= 504:
        raise ValueError(f"ldp offset must be a multiple of 8 in [-512, 504]: {imm}")
    scaled = (imm // 8) & 0x7F
    return struct.pack("<I", 0xA9400000 | (scaled << 15) | (rt2 << 10) | (31 << 5) | rt)


def encode_str_sp(rt: int, imm: int) -> bytes:
    """Encodes ``str x<rt>, [sp, #imm]``."""
    if imm % 8 or not 0 <= imm <= 32760:
        raise ValueError(f"str offset must be a multiple of 8 in [0, 32760]: {imm}")
    return struct.pack("<I", 0xF9000000 | ((imm // 8) << 10) | (31 << 5) | rt)


def encode_ldr_sp(rt: int, imm: int) -> bytes:
    """Encodes ``ldr x<rt>, [sp, #imm]``."""
    if imm % 8 or not 0 <= imm <= 32760:
        raise ValueError(f"ldr offset must be a multiple of 8 in [0, 32760]: {imm}")
    return struct.pack("<I", 0xF9400000 | ((imm // 8) << 10) | (31 << 5) | rt)


def encode_movz_w(rd: int, imm: int) -> bytes:
    """Encodes ``movz w<rd>, #imm16``."""
    if not 0 <= imm <= 0xFFFF:
        raise ValueError(f"movz immediate out of range: {imm}")
    return struct.pack("<I", 0x52800000 | (imm << 5) | rd)


def encode_movk_w(rd: int, imm: int, shift: int = 0) -> bytes:
    """Encodes ``movk w<rd>, #imm, lsl #shift`` (shift must be 0 or 16)."""
    if shift not in (0, 16):
        raise ValueError(f"unsupported movk shift: {shift}")
    hw = 1 if shift == 16 else 0
    return struct.pack("<I", 0x72800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | rd)


def encode_movz_x(rd: int, imm: int) -> bytes:
    """Encodes ``movz x<rd>, #imm16``."""
    if not 0 <= imm <= 0xFFFF:
        raise ValueError(f"movz immediate out of range: {imm}")
    return struct.pack("<I", 0xD2800000 | (imm << 5) | rd)


def encode_mov_w(rd: int, rm: int) -> bytes:
    """Encodes ``mov w<rd>, w<rm>`` (as ``add w<rd>, w<rm>, #0``; capstone shows add)."""
    return encode_add_w_imm(rd, rm, 0)


def encode_add_w_imm(rd: int, rn: int, imm: int) -> bytes:
    """Encodes ``add w<rd>, w<rn>, #imm``."""
    if not 0 <= imm < 0x1000:
        raise ValueError(f"add immediate out of range: {imm}")
    return struct.pack("<I", 0x11000000 | (imm << 10) | (rn << 5) | rd)


def encode_ldr_w(rt: int, rn: int, imm: int) -> bytes:
    """Encodes ``ldr w<rt>, [x<rn>, #imm]``."""
    if imm % 4 or not 0 <= imm < 0x4000:
        raise ValueError(f"ldr offset must be a multiple of 4: {imm}")
    return struct.pack("<I", 0xB9400000 | ((imm // 4) << 10) | (rn << 5) | rt)


def encode_str_w(rt: int, rn: int, imm: int) -> bytes:
    """Encodes ``str w<rt>, [x<rn>, #imm]``."""
    if imm % 4 or not 0 <= imm < 0x4000:
        raise ValueError(f"str offset must be a multiple of 4: {imm}")
    return struct.pack("<I", 0xB9000000 | ((imm // 4) << 10) | (rn << 5) | rt)


def encode_ldrb(rt: int, rn: int, imm: int) -> bytes:
    """Encodes ``ldrb w<rt>, [x<rn>, #imm]``."""
    if not 0 <= imm < 0x1000:
        raise ValueError(f"ldrb offset out of range: {imm}")
    return struct.pack("<I", 0x39400000 | (imm << 10) | (rn << 5) | rt)


def encode_strb(rt: int, rn: int, imm: int) -> bytes:
    """Encodes ``strb w<rt>, [x<rn>, #imm]``."""
    if not 0 <= imm < 0x1000:
        raise ValueError(f"strb offset out of range: {imm}")
    return struct.pack("<I", 0x39000000 | (imm << 10) | (rn << 5) | rt)


def encode_cbnz_w(rt: int, pc_vaddr: int, target_vaddr: int) -> bytes:
    """Encodes ``cbnz w<rt>, #target``."""
    delta = target_vaddr - pc_vaddr
    if delta % 4:
        raise ValueError(f"Unaligned cbnz target: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    if not -(1 << 20) <= delta < (1 << 20):
        raise ValueError("cbnz target out of range")
    imm19 = (delta // 4) & 0x7FFFF
    return struct.pack("<I", 0x35000000 | (imm19 << 5) | rt)

def encode_stp_pre_index(rt: int, rt2: int, imm: int) -> bytes:
    """Encodes ``stp x<rt>, x<rt2>, [sp, #imm]!`` (pre-index, imm multiple of 8)."""
    if imm % 8 or not -(512) <= imm <= 504:
        raise ValueError(f"stp pre-index offset must be a multiple of 8 in range: {imm}")
    imm7 = (imm // 8) & 0x7F
    return struct.pack(
        "<I", 0xA9800000 | (imm7 << 15) | (rt2 << 10) | (31 << 5) | rt
    )


def encode_ldp_post_index(rt: int, rt2: int, imm: int) -> bytes:
    """Encodes ``ldp x<rt>, x<rt2>, [sp], #imm`` (post-index, imm multiple of 8)."""
    if imm % 8 or not 0 <= imm <= 504:
        raise ValueError(f"ldp post-index offset must be a multiple of 8 in [0, 504]: {imm}")
    imm7 = (imm // 8) & 0x7F
    return struct.pack(
        "<I", 0xA8C00000 | (imm7 << 15) | (rt2 << 10) | (31 << 5) | rt
    )


def encode_ldp_w_sp(rt: int, rt2: int, imm: int) -> bytes:
    """Encodes ``ldp w<rt>, w<rt2>, [sp, #imm]`` (32-bit, signed offset)."""
    if imm % 4 or not -256 <= imm <= 252:
        raise ValueError(f"ldp w offset must be a multiple of 4 in [-256, 252]: {imm}")
    imm7 = (imm // 4) & 0x7F
    return struct.pack("<I", 0x29400000 | (imm7 << 15) | (rt2 << 10) | (31 << 5) | rt)


def encode_ldur_x(rt: int, rn: int, imm: int) -> bytes:
    """Encodes ``ldur x<rt>, [x<rn>, #imm]`` (64-bit, unscaled, signed 9-bit)."""
    if not -256 <= imm <= 255:
        raise ValueError(f"ldur offset out of range: {imm}")
    return struct.pack("<I", 0xF8400000 | ((imm & 0x1FF) << 12) | (rn << 5) | rt)


def encode_cbnz_x(rt: int, pc_vaddr: int, target_vaddr: int) -> bytes:
    """Encodes ``cbnz x<rt>, #target``."""
    delta = target_vaddr - pc_vaddr
    if delta % 4 or not -(1 << 20) <= delta < (1 << 20):
        raise ValueError(f"Invalid cbnz x target: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    return struct.pack("<I", 0xB5000000 | (((delta // 4) & 0x7FFFF) << 5) | rt)


def encode_cbz_x(rt: int, pc_vaddr: int, target_vaddr: int) -> bytes:
    """Encodes ``cbz x<rt>, #target``."""
    delta = target_vaddr - pc_vaddr
    if delta % 4 or not -(1 << 20) <= delta < (1 << 20):
        raise ValueError(f"Invalid cbz x target: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    return struct.pack("<I", 0xB4000000 | (((delta // 4) & 0x7FFFF) << 5) | rt)


def encode_eor_w(rd: int, rn: int, rm: int, shift: int = 0, amount: int = 0) -> bytes:
    """Encodes ``eor w<rd>, w<rn>, w<rm, <shift> #<amount>`` (shift 0=LSL, 1=LSR)."""
    if shift not in (0, 1):
        raise ValueError(f"only LSL/LSR are encoded, got shift {shift}")
    if not 0 <= amount <= 31:
        raise ValueError(f"eor amount out of range: {amount}")
    return struct.pack(
        "<I", 0x4A000000 | (shift << 22) | (rm << 16) | (amount << 10) | (rn << 5) | rd
    )


def encode_eor_x(rd: int, rn: int, rm: int, lsl: int = 0) -> bytes:
    """Encodes ``eor x<rd>, x<rn>, x<rm, lsl #<lsl>``."""
    if not 0 <= lsl <= 63:
        raise ValueError(f"eor shift out of range: {lsl}")
    return struct.pack("<I", 0xCA000000 | (rm << 16) | (lsl << 10) | (rn << 5) | rd)


def encode_and_x_page_mask(rd: int, rn: int) -> bytes:
    """Encodes ``and x<rd>, x<rn>, #~0x3FFF`` (align an address down to 16 KB).

    Android 15 can run 16 KB pages, where ``mprotect`` rejects an address that is
    only 4 KB aligned. Aligning to 16 KB and covering 0x4000 bytes is valid on both
    4 KB and 16 KB page kernels. Bitmask immediate: N=1, immr=50, imms=49.
    """
    return struct.pack("<I", 0x92000000 | (1 << 22) | (50 << 16) | (49 << 10)
                       | (rn << 5) | rd)


def encode_tst_w_imm(rt: int, imm: int) -> bytes:
    """Encodes ``tst w<rt>, #imm`` for imm == 1 (bit test used by the SSO check)."""
    if imm != 1:
        raise ValueError("only the bit-0 test is encoded (imm == 1)")
    # 32-bit logical immediate: N=0, immr=0, imms=0 encodes 0x1.
    return struct.pack("<I", 0x72000000 | (rt << 5) | 31)


def encode_csel(rd: int, rn: int, rm: int, cond: int = 0) -> bytes:
    """Encodes ``csel x<rd>, x<rn>, x<rm, #<cond>`` (cond 0 = EQ)."""
    if not 0 <= cond <= 15:
        raise ValueError(f"condition code out of range: {cond}")
    return struct.pack("<I", 0x9A800000 | (rm << 16) | (cond << 12) | (rn << 5) | rd)


def encode_cbz_w(rt: int, pc_vaddr: int, target_vaddr: int) -> bytes:
    """Encodes ``cbz w<rt>, #target``."""
    delta = target_vaddr - pc_vaddr
    if delta % 4 or not -(1 << 20) <= delta < (1 << 20):
        raise ValueError(f"Invalid cbz target: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    return struct.pack("<I", 0x34000000 | (((delta // 4) & 0x7FFFF) << 5) | rt)


def encode_cmp_w_imm(rn: int, imm: int) -> bytes:
    """Encodes ``cmp w<rn>, #imm`` (SUBS wzr, w<rn>, #imm)."""
    if not 0 <= imm < 0x1000:
        raise ValueError(f"cmp immediate out of range: {imm}")
    return struct.pack("<I", 0x71000000 | (imm << 10) | (rn << 5) | 31)


def encode_cmp_x(rn: int, rm: int) -> bytes:
    """Encodes ``cmp x<rn>, x<rm>`` (SUBS xzr, xrn, xrm)."""
    return struct.pack("<I", 0xEB00001F | (rm << 16) | (rn << 5))


def encode_b_cond(pc_vaddr: int, target_vaddr: int, cond: int) -> bytes:
    """Encodes ``b.<cond> #target`` (0=EQ, 1=NE, 2=CS, 3=CC, ...)."""
    delta = target_vaddr - pc_vaddr
    if delta % 4:
        raise ValueError(f"Unaligned conditional branch: 0x{pc_vaddr:x} -> 0x{target_vaddr:x}")
    if not -(1 << 20) <= delta < (1 << 20):
        raise ValueError("conditional branch target out of range")
    imm19 = (delta // 4) & 0x7FFFF
    return struct.pack("<I", 0x54000000 | (imm19 << 5) | (cond & 0xF))


def encode_ret() -> bytes:
    """Encodes ``ret`` (returns to x30)."""
    return struct.pack("<I", 0xD65F03C0)


def encode_movk_x(rd: int, imm: int, shift: int = 0) -> bytes:
    """Encodes ``movk x<rd>, #imm16, lsl #<shift>`` (shift must be 0/16/32/48)."""
    if not 0 <= imm <= 0xFFFF:
        raise ValueError(f"movk immediate out of range: {imm}")
    if shift not in (0, 16, 32, 48):
        raise ValueError(f"movk shift must be 0/16/32/48: {shift}")
    return struct.pack(
        "<I", 0xF2800000 | ((shift // 16) << 21) | (imm << 5) | rd
    )


def encode_mrs_cntvct(rt: int) -> bytes:
    """Encodes ``mrs x<rt>, cntvct_el0`` (the virtual counter)."""
    return struct.pack("<I", 0xD53BE040 | rt)


def encode_mrs_cntfrq(rt: int) -> bytes:
    """Encodes ``mrs x<rt>, cntfrq_el0`` (counter frequency in Hz)."""
    return struct.pack("<I", 0xD53BE000 | rt)


def encode_mul(rd: int, rn: int, rm: int) -> bytes:
    """Encodes ``mul x<rd>, x<rn>, x<rm>``."""
    return struct.pack("<I", 0x9B007C00 | (rm << 16) | (rn << 5) | rd)


def encode_udiv(rd: int, rn: int, rm: int) -> bytes:
    """Encodes ``udiv x<rd>, x<rn>, x<rm>`` (dividing by zero yields zero)."""
    return struct.pack("<I", 0x9AC00800 | (rm << 16) | (rn << 5) | rd)


def encode_sub_x(rd: int, rn: int, rm: int) -> bytes:
    """Encodes ``sub x<rd>, x<rn>, x<rm>``."""
    return struct.pack("<I", 0xCB000000 | (rm << 16) | (rn << 5) | rd)


def encode_ldr_x(rt: int, rn: int, imm: int) -> bytes:
    """Encodes ``ldr x<rt>, [x<rn>, #imm]``."""
    if imm % 8 or not 0 <= imm < 0x8000:
        raise ValueError(f"ldr x offset must be a multiple of 8: {imm}")
    return struct.pack("<I", 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt)


def encode_str_x(rt: int, rn: int, imm: int) -> bytes:
    """Encodes ``str x<rt>, [x<rn>, #imm]``."""
    if imm % 8 or not 0 <= imm < 0x8000:
        raise ValueError(f"str x offset must be a multiple of 8: {imm}")
    return struct.pack("<I", 0xF9000000 | ((imm // 8) << 10) | (rn << 5) | rt)


# ---------------------------------------------------------------------------
# Dev build · phase 3 · dispatch log cave
#
# The embedded server's JSON entry point is `fwt_stub_handle_json(config, json)`
# (extern "C", unstripped). Its first instruction is `sub sp, sp, #0x90` and **x1
# carries the NUL-terminated JSON payload**, which is exactly what the dispatch
# log needs: no buffer copy and no length computation — `%.*s` truncates.
#
# The cave itself is carved inside `itanium_demangle::AbstractManglingParser`
# (4,572 B of assumed-dead code, `docs/CODE_CAVES.md`), the same family the
# shipped campaign caves already overwrite at 0xb33314.
# ---------------------------------------------------------------------------
DEV_LOG_HOOK_VADDR = 0x7E4030
DEV_LOG_HOOK_ORIGINAL = bytes.fromhex("fd7bbaa9")  # stp x29, x30, [sp, #-0x60]!
# x1 points at the std::string holding the JSON body. Measured from this binary
# (json_escape at 0xa356dc): byte0 bit0 set -> long, with size at [x1+8] and the data
# pointer at [x1+0x10]; otherwise the size is byte0>>1 and the characters live inline
# at x1+1.
DEV_LOG_PAYLOAD_REG = 1
DEV_LOG_PLT_PRINT = 0xB464B0  # PLT stub of __android_log_print (GOT 0xbdd810)
DEV_LOG_PLT_MPROTECT = 0xB476D0  # PLT stub of mprotect (GOT 0xbde120)
DEV_LOG_CAVE_VADDR = 0xB29EBC
DEV_LOG_CAVE_SIZE = 0x300
DEV_TIMING_CAVE_VADDR = 0xB2A1BC
DEV_TIMING_CAVE_SIZE = 0x1A0  # the dead function it lives in has room to 0xB2B098
DEV_TIMING_TAG = "FWTR-DEV-T"
DEV_RESPONSE_TAG = "FWTR-DEV-R"
# The single `ret` of `dispatch_json_impl` (0x7e4030), found by disassembly: the
# function has exactly one exit, preceded by the full register restore.
DEV_TIMING_HOOK_SITES = (0x7ECD68,)
DEV_TIMING_RET = bytes.fromhex("c0035fd6")
TIMING_MICROS = 1_000_000
DEV_LOG_CAVE_MAGIC = b"FDVL"
ANDROID_LOG_INFO = 4
PROT_READ_WRITE_EXEC = 7
DEV_COUNTER_MAGIC = 0x5A
DEV_MARKER_TAG = "FWTR-DEV-BUILD"
DEV_MARKER_PREFIX = "FWTR-DEV v"

# Offsets inside the cave, relative to its base: strings first, state at the end.
DEV_COUNTER_MAGIC_OFFSET = 0x280  # byte: "page made writable"
DEV_COUNTER_VALUE_OFFSET = 0x284  # u32: dispatch counter
DEV_MARKER_MAGIC_OFFSET = 0x288  # byte: "marker already logged"
DEV_START_TICK_OFFSET = 0x290  # u64: cntvct_el0 sampled at dispatch entry
DEV_SRET_OFFSET = 0x298  # u64: the result buffer the caller passed in x8
DEV_DUMP_FLAG_OFFSET = 0x2A0  # byte: the current request is a DEV_DUMP command
DEV_DUMP_MAGIC = b'{"CMD":"DEV_DUMP'
DEV_DUMP_RESPONSE = b'{"ERROR":0,"DUMP":1}'  # 20 bytes: fits a libc++ short string
DEV_DUMP_TAG = "DEV_DUMP"


def dev_log_tag(version: str = "") -> str:
    """Logcat tag for the dispatch log (`FWTR-DEV` or `FWTR-DEV-v2.5.26`)."""
    return f"{DEV_LOG_TAG_PREFIX}-v{version}" if version else DEV_LOG_TAG_PREFIX


def dev_build_marker(
    version: str, instrumentation: tuple[str, ...] = (), patch_count: int = 0
) -> str:
    """Builds the identity string a dev build logs (and that `--inspect` finds).

    The fingerprint hashes the *recipe* — version, enabled instrumentation and the
    number of applied patches — so two APKs built differently never share a
    marker, and rebuilding the same way always reproduces it exactly.
    """
    flags = ",".join(sorted(instrumentation)) or "none"
    recipe = f"{version}|{patch_count}|{flags}"
    fingerprint = hashlib.sha256(recipe.encode("utf-8")).hexdigest()[:8]
    return f"{DEV_MARKER_PREFIX}{version} fp={fingerprint} n={patch_count} flags={flags}"


def find_dev_build_marker(so_bytes: bytes | bytearray) -> str | None:
    """Returns the dev marker embedded in a patched `.so`, or None for a release."""
    raw = bytes(so_bytes)
    start = raw.find(DEV_MARKER_PREFIX.encode("ascii"))
    if start < 0:
        return None
    end = raw.find(b"\x00", start)
    return raw[start : end if end > 0 else len(raw)].decode("ascii", "replace")


def _build_dev_log_cave(
    base: int,
    *,
    limit: int = 1024,
    tag: str = "",
    version: str = "",
    counters: bool = True,
    log: bool = True,
    marker: str = "",
    timing: bool = False,
    capture_sret: bool = False,
    dev_dump: bool = False,
) -> bytes:
    """Builds the instrumentation cave installed at `DEV_LOG_CAVE_VADDR`.

    The cave does three things, in this order, all optional:

    * makes **its own page** writable once per process through the library's
      imported ``mprotect`` (needed by the counter and the marker; this binary has
      no free writable memory — `.bss` is packed to its last byte, `.data` is fully
      covered by symbols and the `.data.rel.ro` gaps are relocation tables);
    * logs the JSON payload of every dispatch, prefixed by the hit counter;
    * logs the **build marker** a single time per process (``--dev-marker``), so a
      logcat capture always says which build produced it.

    ``limit`` is the maximum number of payload bytes logged; ``0`` logs the whole
    body (``%s``), otherwise ``%.*s`` with ``limit`` as the precision argument.
    """
    wants_page = counters or bool(marker) or timing or capture_sret
    log_tag_bytes = (tag or dev_log_tag(version)).encode("utf-8") + b"\x00"
    prefix = b"%u " if counters else b""
    log_fmt_bytes = prefix + (b"%.*s\x00" if limit else b"%s\x00")
    marker_tag_bytes = DEV_MARKER_TAG.encode("ascii") + b"\x00"
    marker_fmt_bytes = b"%s\x00"
    marker_text_bytes = marker.encode("utf-8") + b"\x00"
    magic_addr = base + DEV_COUNTER_MAGIC_OFFSET
    counter_addr = base + DEV_COUNTER_VALUE_OFFSET
    sret_addr = base + DEV_SRET_OFFSET

    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str, int, bool]] = []  # (index, target key, reg, link)

    def emit(blob: bytes) -> int:
        position = len(code)
        code.extend(blob)
        return position // 4

    def emit_const64(reg: int, value: int) -> None:
        emit(encode_movz_x(reg, value & 0xFFFF))
        for shift in (16, 32, 48):
            part = (value >> shift) & 0xFFFF
            if part:
                emit(encode_movk_x(reg, part, shift))

    def emit_payload_pointer(target: int) -> None:
        """Loads the JSON characters into x<target> from the saved x1 (std::string)."""
        # x9 is scratch: x1/x2 already hold the tag and the format string here.
        emit(encode_ldr_x(9, 31, 0x08))  # x9 = &std::string (saved by the frame)
        emit(encode_ldrb(5, 9, 0))  # byte 0: bit 0 == is_long
        emit(encode_tst_w_imm(5, 1))
        emit(encode_ldr_x(6, 9, 0x10))  # long: data pointer lives at +16
        emit(encode_add_imm(7, 9, 1))  # short: characters inline at +1
        emit(encode_csel(target, 7, 6, 0))  # EQ (short) -> x7, else x6

    def emit_string_adrp(reg: int, addr_key: str) -> None:
        position = emit(encode_adrp(base + len(code), base + len(code), reg))
        emit(encode_add_imm(reg, reg, 0))  # placeholder, patched with the low bits
        fixups.append((position, addr_key, reg, False))

    # 1. Own frame. x30 and x19 must survive the `bl` calls; x19 holds the state base
    #    because every x0-x18 is caller-saved and the libc is free to clobber them.
    #    The last 0x20 bytes of the frame double as the fallback state block when
    #    mprotect refuses the page.
    emit(encode_sub_sp(0x90))
    emit(encode_stp_sp(0, 1, 0x00))
    emit(encode_stp_sp(2, 3, 0x10))
    emit(encode_stp_sp(4, 5, 0x20))
    emit(encode_stp_sp(8, 9, 0x30))
    emit(encode_str_sp(30, 0x40))
    emit(encode_stp_sp(12, 13, 0x50))
    emit(encode_str_x(19, 31, 0x60))

    # 2. Make the pages holding the state block writable, once per process.
    #    The cave base and its state block can land in different pages (base is at
    #    +0x000, the state at +0x280), so the range has to cover both — and it must
    #    be 16 KB aligned for Android 15 devices with 16 KB pages.
    cbnz_page = -1
    cbnz_noslot = -1
    mprotect_bl = -1
    good_branch = -1
    if wants_page:
        emit(encode_adrp(base + len(code), magic_addr, 9))
        emit(encode_add_imm(9, 9, magic_addr & 0xFFF))
        emit(encode_ldrb(8, 9, 0))
        cbnz_page = emit(encode_cbnz_w(8, base + len(code), base + len(code)))
        emit(encode_adrp(base + len(code), base, 0))
        emit(encode_and_x_page_mask(0, 0))
        emit(encode_movz_x(1, 0x4000))
        emit(encode_movz_w(2, PROT_READ_WRITE_EXEC))
        mprotect_bl = emit(
            encode_arm64_branch(base + len(code), DEV_LOG_PLT_MPROTECT, link=True)
        )
        cbnz_noslot = emit(encode_cbnz_w(0, base + len(code), base + len(code)))
        emit(encode_movz_w(8, DEV_COUNTER_MAGIC))
        emit(encode_strb(8, 9, 0))

        # Writable: x19 = &counter, so the marker magic is x19+4 and the tick x19+0xC.
        labels["have_slot"] = len(code) // 4
        emit(encode_adrp(base + len(code), counter_addr, 19))
        emit(encode_add_imm(19, 19, counter_addr & 0xFFF))
        good_branch = emit(
            encode_arm64_branch(base + len(code), base + len(code))
        )  # placeholder -> ready

        # mprotect refused (unexpected kernel/page size): point x19 at scratch inside
        # our own frame. Counters and the marker become meaningless, but nothing dies.
        labels["no_slot"] = len(code) // 4
        emit(encode_add_imm(19, 31, 0x70))  # add x19, sp, #0x70
        labels["ready"] = len(code) // 4

    # 3a0. Remember where the caller wants the returned std::string. The callee does
    # NOT restore x0 with it (nothing in the epilogue touches x0), so the exit cave
    # cannot rely on x0 — it has to read this slot.
    if capture_sret:
        emit(encode_ldr_x(9, 31, 0x30))  # saved x8 = destination buffer
        emit(encode_adrp(base + len(code), sret_addr, 10))
        emit(encode_add_imm(10, 10, sret_addr & 0xFFF))
        emit(encode_str_x(9, 10, 0))

    # 3a. Sample the virtual counter so the exit cave can compute the handler time.
    if timing:
        tick_delta = DEV_START_TICK_OFFSET - DEV_COUNTER_VALUE_OFFSET
        emit(encode_mrs_cntvct(11))
        emit(encode_add_imm(13, 19, tick_delta))  # not 8-byte aligned: address first
        emit(encode_str_x(11, 13, 0))

    # 3b. Counter++ (used by dispatch log lines, response correlation, and
    # standalone --dev-counters).
    if counters:
        emit(encode_ldr_w(11, 19, 0))
        emit(encode_add_w_imm(11, 11, 1))
        emit(encode_str_w(11, 19, 0))

    # 4. __android_log_print(INFO, tag, "%u %.*s", counter, limit, payload).
    log_bl = -1
    dump_skips: list[int] = []
    if log or dev_dump:
        emit_payload_pointer(5)  # x5 = the JSON characters

    if dev_dump:
        # Is this a DEV_DUMP command? Compare the two leading qwords; anything else
        # leaves the flag clear and the request runs untouched.
        cmd_prefix = int.from_bytes(DEV_DUMP_MAGIC[:8], "little")
        cmd_name = int.from_bytes(DEV_DUMP_MAGIC[8:16], "little")
        emit(encode_ldr_x(6, 5, 0))
        emit_const64(7, cmd_prefix)
        emit(encode_cmp_x(6, 7))
        dump_skips.append(
            emit(encode_b_cond(base + len(code), base + len(code), 1))  # b.ne
        )
        emit(encode_ldr_x(6, 5, 8))
        emit_const64(7, cmd_name)
        emit(encode_cmp_x(6, 7))
        dump_skips.append(
            emit(encode_b_cond(base + len(code), base + len(code), 1))
        )
        # The command name has to end where DEV_DUMP ends: the closing quote, so a
        # prefix like DEV_DUMPX does not match.
        emit(encode_ldrb(6, 5, len(DEV_DUMP_MAGIC)))
        emit(encode_cmp_w_imm(6, 0x22))
        dump_skips.append(
            emit(encode_b_cond(base + len(code), base + len(code), 1))
        )
        emit(encode_movz_w(8, 1))
        flag_delta = DEV_DUMP_FLAG_OFFSET - DEV_COUNTER_VALUE_OFFSET
        emit(encode_strb(8, 19, flag_delta))
        labels["dump_done"] = len(code) // 4

    if log:
        emit(encode_movz_w(0, ANDROID_LOG_INFO))
        emit_string_adrp(1, "log_tag")
        emit_string_adrp(2, "log_fmt")
        if counters:
            emit(encode_mov_w(3, 11))
            if limit:
                emit(encode_movz_w(4, limit))
            else:
                emit(encode_mov_w(4, 5))
        elif limit:
            emit(encode_movz_w(3, limit))
            emit(encode_mov_w(4, 5))
        else:
            emit(encode_mov_w(3, 5))
        log_bl = emit(encode_arm64_branch(base + len(code), DEV_LOG_PLT_PRINT, link=True))

    # 5. Build marker: once per process, guarded by its own magic byte.
    if marker:
        marker_delta = DEV_MARKER_MAGIC_OFFSET - DEV_COUNTER_VALUE_OFFSET
        emit(encode_ldrb(13, 19, marker_delta))
        cbnz_marker = emit(encode_cbnz_w(13, base + len(code), base + len(code)))
        # Latch before the call: x12/x13 are caller-saved and the log call is free to
        # clobber them (only x19-x28 survive), so nothing may be written afterwards.
        emit(encode_movz_w(13, 1))
        emit(encode_strb(13, 19, marker_delta))
        emit(encode_movz_w(0, ANDROID_LOG_INFO))
        emit_string_adrp(1, "marker_tag")
        emit_string_adrp(2, "marker_fmt")
        emit_string_adrp(3, "marker_text")
        emit(encode_arm64_branch(base + len(code), DEV_LOG_PLT_PRINT, link=True))
        labels["marker_done"] = len(code) // 4

    # 6. Restore, replay the displaced instruction, return to the function body.
    emit(encode_ldp_sp(0, 1, 0x00))
    emit(encode_ldp_sp(2, 3, 0x10))
    emit(encode_ldp_sp(4, 5, 0x20))
    emit(encode_ldp_sp(8, 9, 0x30))
    emit(encode_ldr_sp(30, 0x40))
    emit(encode_ldp_sp(12, 13, 0x50))
    emit(encode_ldr_x(19, 31, 0x60))
    emit(encode_add_sp(0x90))
    emit(DEV_LOG_HOOK_ORIGINAL)
    back_index = emit(encode_arm64_branch(base + len(code), DEV_LOG_HOOK_VADDR + 4))

    # 7. Data area: strings, then the state block at the very end.
    strings: dict[str, int] = {}
    for key, payload, enabled in (
        ("log_tag", log_tag_bytes, log),
        ("log_fmt", log_fmt_bytes, log),
        ("marker_tag", marker_tag_bytes, bool(marker)),
        ("marker_fmt", marker_fmt_bytes, bool(marker)),
        ("marker_text", marker_text_bytes, bool(marker)),
    ):
        if not enabled:
            continue
        strings[key] = base + len(code)
        code.extend(payload)
        while len(code) % 4:
            code.extend(b"\x00")
    if base + len(code) > magic_addr:
        raise ValueError(
            f"cave strings grew into the state block: {base + len(code):x} > {magic_addr:x}"
        )
    code.extend(b"\x00" * (magic_addr - (base + len(code))))
    code.extend(b"\x00" * 4)  # magic byte (0 = page not writable yet) + padding
    code.extend(b"\x00" * 4)  # hit counter starts at zero
    code.extend(b"\x00" * 4)  # marker magic byte (0 = marker not logged yet)
    code.extend(b"\x00" * 4)  # padding up to the 8-byte tick slot
    code.extend(b"\x00" * 8)  # start tick (cntvct_el0 at entry)
    code.extend(b"\x00" * 8)  # sret destination buffer (x8 at entry)
    code.extend(b"\x00" * 8)  # DEV_DUMP flag + padding
    if len(code) > DEV_LOG_CAVE_SIZE:
        raise ValueError(
            f"dev log cave is {len(code)} bytes, budget is {DEV_LOG_CAVE_SIZE}"
        )

    blob = bytearray(code)

    def place_adrp(index: int, target: int, reg: int) -> None:
        blob[index * 4 : index * 4 + 4] = encode_adrp(base + index * 4, target, reg)

    def place_call(index: int, target: int) -> None:
        blob[index * 4 : index * 4 + 4] = encode_arm64_branch(
            base + index * 4, target, link=True
        )

    def place_jump(index: int, target: int) -> None:
        blob[index * 4 : index * 4 + 4] = encode_arm64_branch(base + index * 4, target)

    for position, addr_key, reg, _link in fixups:
        place_adrp(position, strings[addr_key], reg)
        blob[position * 4 + 4 : position * 4 + 8] = encode_add_imm(
            reg, reg, strings[addr_key] & 0xFFF
        )
    if wants_page:
        blob[cbnz_page * 4 : cbnz_page * 4 + 4] = encode_cbnz_w(
            8, base + cbnz_page * 4, base + labels["have_slot"] * 4
        )
        blob[cbnz_noslot * 4 : cbnz_noslot * 4 + 4] = encode_cbnz_w(
            0, base + cbnz_noslot * 4, base + labels["no_slot"] * 4
        )
        blob[good_branch * 4 : good_branch * 4 + 4] = encode_arm64_branch(
            base + good_branch * 4, base + labels["ready"] * 4
        )
        place_call(mprotect_bl, DEV_LOG_PLT_MPROTECT)
    for skip in dump_skips:
        blob[skip * 4 : skip * 4 + 4] = encode_b_cond(
            base + skip * 4, base + labels["dump_done"] * 4, 1
        )
    if log:
        place_call(log_bl, DEV_LOG_PLT_PRINT)
    if marker:
        blob[cbnz_marker * 4 : cbnz_marker * 4 + 4] = encode_cbnz_w(
            13, base + cbnz_marker * 4, base + labels["marker_done"] * 4
        )
    place_jump(back_index, DEV_LOG_HOOK_VADDR + 4)
    return bytes(blob)


def _build_dev_timing_cave(
    base: int,
    *,
    tag: str = "",
    version: str = "",
    response_tag: str = "",
    limit: int = 0,
    dev_dump: bool = False,
) -> bytes:
    """Builds the exit cave that reports how long the JSON handler took.

    Every `ret` of `fwt_stub_handle_json` branches here. The entry cave sampled
    ``cntvct_el0`` into the state block, so the cave computes
    ``(now - start) * 1_000_000 / cntfrq_el0`` and logs it in microseconds, then
    replays the displaced ``ret``.

    Only x0/x1 (the return value) and x30 (the return address) must survive the log
    call, so a 0x40-byte frame is enough. ``udiv`` by zero yields zero, so a device
    reporting ``cntfrq_el0 == 0`` logs 0 instead of trapping.
    """
    tag_bytes = (
        tag or (f"{DEV_TIMING_TAG}-v{version}" if version else DEV_TIMING_TAG)
    ).encode("utf-8") + b"\x00"
    fmt_bytes = b"%lu us\x00"
    wants_response = bool(response_tag)
    resp_tag_bytes = (response_tag or "").encode("utf-8") + b"\x00"
    resp_fmt_bytes = (b"%u %.*s\x00" if limit else b"%u %s\x00")
    counter_addr = DEV_LOG_CAVE_VADDR + DEV_COUNTER_VALUE_OFFSET
    tick_addr = DEV_LOG_CAVE_VADDR + DEV_START_TICK_OFFSET
    sret_slot = DEV_LOG_CAVE_VADDR + DEV_SRET_OFFSET

    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str, int]] = []

    def emit(blob: bytes) -> int:
        position = len(code)
        code.extend(blob)
        return position // 4

    def emit_addr(reg: int, key: str) -> None:
        position = emit(encode_adrp(base + len(code), base + len(code), reg))
        emit(encode_add_imm(reg, reg, 0))
        fixups.append((position, key, reg))

    emit(encode_sub_sp(0x40))
    emit(encode_str_x(0, 31, 0x00))
    emit(encode_str_x(1, 31, 0x08))
    emit(encode_str_x(30, 31, 0x10))

    emit_addr(10, "tick")  # x10 = &start tick
    emit(encode_ldr_x(10, 10, 0))
    emit(encode_mrs_cntvct(11))
    emit(encode_sub_x(12, 11, 10))  # delta in ticks
    emit(encode_mrs_cntfrq(13))
    emit(encode_movz_x(14, TIMING_MICROS & 0xFFFF))
    emit(encode_movk_x(14, (TIMING_MICROS >> 16) & 0xFFFF, 16))
    emit(encode_mul(12, 12, 14))
    emit(encode_udiv(12, 12, 13))  # microseconds

    emit(encode_movz_w(0, ANDROID_LOG_INFO))
    emit_addr(1, "tag")
    emit_addr(2, "fmt")
    emit(encode_add_imm(3, 12, 0))  # 64-bit: the format is %lu
    log_bl = emit(encode_arm64_branch(base + len(code), DEV_LOG_PLT_PRINT, link=True))

    dump_skips: list[int] = []
    if dev_dump:
        payload_len = len(DEV_DUMP_RESPONSE)
        flag_addr = DEV_LOG_CAVE_VADDR + DEV_DUMP_FLAG_OFFSET
        emit(encode_adrp(base + len(code), flag_addr, 10))
        emit(encode_add_imm(10, 10, flag_addr & 0xFFF))
        emit(encode_ldrb(11, 10, 0))
        dump_skips.append(emit(encode_cbz_w(11, base + len(code), base + len(code))))
        emit(encode_strb(31, 10, 0))  # clear the flag: one dump per request
        emit(encode_adrp(base + len(code), sret_slot, 10))
        emit(encode_add_imm(10, 10, sret_slot & 0xFFF))
        emit(encode_ldr_x(9, 10, 0))  # the destination std::string
        emit(encode_ldrb(5, 9, 0))
        emit(encode_tst_w_imm(5, 1))
        # b.ne: bit0 set means long mode, so NE jumps to the long path
        long_branch = emit(encode_b_cond(base + len(code), base + len(code), 1))
        # short (SSO): characters inline at +1, size as len<<1 in byte 0
        emit(encode_add_imm(6, 9, 1))
        emit(encode_movz_w(7, payload_len << 1))
        emit(encode_strb(7, 9, 0))
        after_mode = emit(encode_arm64_branch(base + len(code), base + len(code)))
        labels["dump_long"] = len(code) // 4
        emit(encode_ldr_x(6, 9, 0x10))  # long: the heap buffer
        emit(encode_movz_x(7, payload_len))
        emit(encode_str_x(7, 9, 0x08))  # std::string size
        labels["dump_write"] = len(code) // 4
        emit_addr(8, "dump_text")
        emit(encode_ldr_x(7, 8, 0))
        emit(encode_str_x(7, 6, 0))
        emit(encode_ldr_x(7, 8, 8))
        emit(encode_str_x(7, 6, 8))
        emit(encode_ldr_w(7, 8, 16))
        emit(encode_str_w(7, 6, 16))
        # NUL right after the payload: std::string guarantees a terminated buffer, and
        # without it the %.s log line would print the leftover tail of the original body
        emit(encode_strb(31, 6, payload_len))
        labels["dump_done"] = len(code) // 4

    if wants_response:
        # The dispatcher returns a std::string by value: x8 points at the destination
        # and x0 holds it back, so at the `ret` x0 is a std::string* — same layout the
        # entry cave reads from its second argument.
        emit(encode_adrp(base + len(code), sret_slot, 10))
        emit(encode_add_imm(10, 10, sret_slot & 0xFFF))
        emit(encode_ldr_x(9, 10, 0))  # the destination buffer remembered at entry
        emit(encode_ldrb(5, 9, 0))
        emit(encode_tst_w_imm(5, 1))
        emit(encode_ldr_x(6, 9, 0x10))
        emit(encode_add_imm(7, 9, 1))
        emit(encode_csel(5, 7, 6, 0))  # EQ (short) -> inline, else the data pointer
        emit(encode_adrp(base + len(code), counter_addr, 10))
        emit(encode_add_imm(10, 10, counter_addr & 0xFFF))
        emit(encode_ldr_w(11, 10, 0))
        emit(encode_movz_w(0, ANDROID_LOG_INFO))
        emit_addr(1, "resp_tag")
        emit_addr(2, "resp_fmt")
        emit(encode_mov_w(3, 11))
        if limit:
            emit(encode_movz_w(4, limit))
        else:
            emit(encode_add_imm(4, 5, 0))
        emit(encode_arm64_branch(base + len(code), DEV_LOG_PLT_PRINT, link=True))

    emit(encode_ldr_x(0, 31, 0x00))
    emit(encode_ldr_x(1, 31, 0x08))
    emit(encode_ldr_x(30, 31, 0x10))
    emit(encode_add_sp(0x40))
    emit(DEV_TIMING_RET)

    strings: dict[str, int] = {}
    entries = [("tag", tag_bytes), ("fmt", fmt_bytes)]
    if dev_dump:
        entries.append(("dump_text", DEV_DUMP_RESPONSE + b"\x00"))
    if wants_response:
        entries += [("resp_tag", resp_tag_bytes), ("resp_fmt", resp_fmt_bytes)]
    for key, payload in entries:
        strings[key] = base + len(code)
        code.extend(payload)
        while len(code) % 4:
            code.extend(b"\x00")
    strings["tick"] = tick_addr
    if len(code) > DEV_TIMING_CAVE_SIZE:
        raise ValueError(
            f"dev timing cave is {len(code)} bytes, budget is {DEV_TIMING_CAVE_SIZE}"
        )

    blob = bytearray(code)
    if dev_dump:
        for skip in dump_skips:
            blob[skip * 4 : skip * 4 + 4] = encode_cbz_w(
                11, base + skip * 4, base + labels["dump_done"] * 4
            )
        blob[long_branch * 4 : long_branch * 4 + 4] = encode_b_cond(
            base + long_branch * 4, base + labels["dump_long"] * 4, 1
        )
        blob[after_mode * 4 : after_mode * 4 + 4] = encode_arm64_branch(
            base + after_mode * 4, base + labels["dump_write"] * 4
        )
    for position, key, reg in fixups:
        blob[position * 4 : position * 4 + 4] = encode_adrp(
            base + position * 4, strings[key], reg
        )
        blob[position * 4 + 4 : position * 4 + 8] = encode_add_imm(
            reg, reg, strings[key] & 0xFFF
        )
    blob[log_bl * 4 : log_bl * 4 + 4] = encode_arm64_branch(
        base + log_bl * 4, DEV_LOG_PLT_PRINT, link=True
    )
    return bytes(blob)


def apply_dev_handler_timing(
    buf: bytearray,
    *,
    version: str = "",
    tag: str = "",
    response_tag: str = "",
    limit: int = 0,
    dev_dump: bool = False,
) -> int:
    """Installs the exit cave and branches to it from every `ret` of the handler.

    Returns the number of patched `ret` sites, or 0 when the cave is already in
    place. The sites are validated first: a drifted build must fail loudly instead
    of branching out of an unrelated instruction.
    """
    branch = encode_arm64_branch(DEV_TIMING_HOOK_SITES[0], DEV_TIMING_CAVE_VADDR)
    first = seg_offset(DEV_TIMING_HOOK_SITES[0])
    if bytes(buf[first : first + 4]) == branch:
        return 0
    for site in DEV_TIMING_HOOK_SITES:
        current = bytes(buf[seg_offset(site) : seg_offset(site) + 4])
        if current != DEV_TIMING_RET:
            raise ValueError(
                f"timing hook site 0x{site:x} holds {current.hex()}, "
                f"expected {DEV_TIMING_RET.hex()} (ret)"
            )
    cave = _build_dev_timing_cave(
        DEV_TIMING_CAVE_VADDR,
        tag=tag,
        version=version,
        response_tag=response_tag,
        limit=limit,
        dev_dump=dev_dump,
    )
    _write_bytes(buf, seg_offset(DEV_TIMING_CAVE_VADDR), cave, "dev timing cave")
    for site in DEV_TIMING_HOOK_SITES:
        _write_bytes(
            buf,
            seg_offset(site),
            encode_arm64_branch(site, DEV_TIMING_CAVE_VADDR),
            "dev timing hook",
        )
    return len(DEV_TIMING_HOOK_SITES)


def apply_dev_dispatch_log(
    buf: bytearray,
    *,
    limit: int = 1024,
    tag: str = "",
    version: str = "",
    counters: bool | None = None,
    log: bool = True,
    marker: str = "",
    timing: bool = False,
    capture_sret: bool = False,
    dev_dump: bool = False,
) -> int:
    """Installs the instrumentation cave. Returns 1, or 0 when already installed.

    ``counters`` defaults to ``log`` when omitted so bare
    ``apply_dev_dispatch_log(buf)`` enables dispatch counters without
    implicitly turning them on when ``log=False``; pass ``counters=True`` to
    install standalone hit counters. ``log=False`` with a non-empty
    ``marker`` announces the build once per process (``--dev-marker`` on its
    own). ``timing=True`` samples ``cntvct_el0`` at entry for the exit cave
    installed by :func:`apply_dev_handler_timing`.
    """
    use_counters = log if counters is None else counters
    if (
        not log
        and not use_counters
        and not marker
        and not timing
        and not capture_sret
        and not dev_dump
    ):
        raise ValueError(
            "dev cave needs at least one of: dispatch log, hit counters, build marker, "
            "handler timing, response capture"
        )
    branch = encode_arm64_branch(DEV_LOG_HOOK_VADDR, DEV_LOG_CAVE_VADDR)
    hook_offset = seg_offset(DEV_LOG_HOOK_VADDR)
    current = bytes(buf[hook_offset : hook_offset + 4])
    if current == branch:
        return 0
    if current != DEV_LOG_HOOK_ORIGINAL:
        raise ValueError(
            f"dev log hook site at 0x{DEV_LOG_HOOK_VADDR:x} holds {current.hex()}, "
            f"expected {DEV_LOG_HOOK_ORIGINAL.hex()} (sub sp, sp, #0x90)"
        )
    cave = _build_dev_log_cave(
        DEV_LOG_CAVE_VADDR,
        limit=limit,
        tag=tag,
        version=version,
        counters=use_counters,
        log=log,
        marker=marker,
        timing=timing,
        capture_sret=capture_sret,
        dev_dump=dev_dump,
    )
    _write_bytes(buf, seg_offset(DEV_LOG_CAVE_VADDR), cave, "dev log cave")
    _write_bytes(buf, hook_offset, branch, "dev log hook")
    return 1


def encode_add_imm_lsl12(rd: int, rn: int, imm12: int) -> bytes:
    """Encodes ``add x<rd>, x<rn>, #imm12, lsl #12``."""
    if not 0 <= imm12 < 0x1000:
        raise ValueError(f"add lsl12 immediate out of range: {imm12}")
    return struct.pack("<I", 0x91400000 | (imm12 << 10) | (rn << 5) | rd)


def encode_mov_x(rd: int, rm: int) -> bytes:
    """Encodes ``mov x<rd>, x<rm>`` (ORR with the zero register)."""
    return struct.pack("<I", 0xAA0003E0 | (rm << 16) | rd)


def encode_stur_q(rt: int, rn: int, imm9: int) -> bytes:
    """Encodes ``stur q<rt>, [x<rn>, #imm9]`` (unscaled, any 16-byte multiple)."""
    return struct.pack("<I", 0x3C800000 | ((imm9 & 0x1FF) << 12) | (rn << 5) | rt)


def encode_ldur_q(rt: int, rn: int, imm9: int) -> bytes:
    """Encodes ``ldur q<rt>, [x<rn>, #imm9]`` (unscaled, any 16-byte multiple)."""
    return struct.pack("<I", 0x3CC00000 | ((imm9 & 0x1FF) << 12) | (rn << 5) | rt)


GUILD_RAID_SELF_ROW_OFFSET = 0x176A0  # self mirror row inside the global roster
GUILD_RAID_ROSTER_PTR_GOT = 0xBDCCA8  # *(0xbdc000 + 0xca8) holds the roster base


# The cave is generated from AArch64 assembly by ``tools/gen_merc_cave.py``: it reads the
# player's own mercenary out of the save (``guild_hired_soldier_info.<weekday>_crs_idx``
# or falls back to the selected stock hire, and filters ownership lists by ``crs_idx`` to fill
# all seven projection slots.  The assembly / ELF cave behavior is verified by ``tests/test_self_merc_cave.py``.
GUILD_RAID_MERCENARY_CAVE_BYTES = bytes.fromhex(
    "ff0306d1fd7b16a9fd030091f36700f909200091e96300f9ff630339ff670339"
    "e0630091e1c1fff021ec3591c99df297e0c30091e1cbff9021d03c91c59df297"
    "e0830391e1d4ffb021183991c19df297e8430491e06340f9e1830391e827f697"
    "e06340f90719f5970a308ad22a00a0f20b08ca9a6b110091ec0080d26d09cc9a"
    "aead0c9b6f000010ef090e8be0011fd607000014090000140b0000140d000014"
    "0f000014110000141300001401b3fff021e002911200001401c1fff021583191"
    "0f000014a1b5ff90212002910c00001461d3ffb021280f910900001401c7fff0"
    "21cc37910600001461d3ffb021580f910300001461bafff0210c2091e0e30391"
    "949df297e0430491e1e3039102008092d2aff297e06b00f9e0e30391f091fe97"
    "e0430491ee91fe97e06b40f91f0400f10b150054e06b00f9eaa304916b4f8452"
    "6b4cae724b4500b86bee8b522b8dac724b4500b80bef8b528b2dad724b4500b8"
    "6b8e8e524b44a7724b4500b86b0b80524b150038ec630591ed6b40f94e018052"
    "0f008052b009ce9a11b60e9b31c2009191692f38ef050091ed0310aa4dffffb5"
    "ef0500d191696f3851150038afffffb5ab0b80524b150038ab0f80524b150038"
    "5f010039e0a30291e1a30491619df29729008052e9630339e023019141d2ffd0"
    "21ec14915b9df297e8830191e06340f9e1230191e2630091e36b40f92e8df597"
    "e0230191b691fe97e9834139e90d0034e06740f900200091e18301914d98fe97"
    "e0830191ae91fe97e023019181b5fff0216c3b91479df297e8830191e06340f9"
    "e1230191e2630091e36b40f91a8df597e0230191a291fe97e983413909010034"
    "e06740f900800091e18301913998fe97e08301919a91fe9703000014e0830191"
    "9791fe97e0230191e1cdffd021982b91309df297e8e30191e06340f9e1230191"
    "d316f597e02301918d91fe97e8430291e0e30191e1a30291e2c30091e3630091"
    "0c75f797e0e301918591fe97e06740f900e00091e14302911e98fe97e0430291"
    "7f91fe97e023019101b3ffd021a43f91189df297e8e30191e06340f9e1230191"
    "bb16f597e02301917591fe97e8430291e0e30191e1a30291e2c30091e3630091"
    "f474f797e0e301916d91fe97e06740f900400191e14302910698fe97e0430291"
    "6791fe97e023019101b3ffd021083a91009df297e8e30191e06340f9e1230191"
    "a316f597e02301915d91fe97e8430291e0e30191e1a30291e2c30091e3630091"
    "dc74f797e0e301915591fe97e06740f900000291e1430291ee97fe97e0430291"
    "4f91fe9781b5fff0216c3b91020d80d21f00009401b3ffd021083a91021380d2"
    "1b00009405000014e08301914491fe9729008052e9670339e06300914091fe97"
    "e0c300913e91fe97e08303913c91fe97e963433969000034e0a302913891fe97"
    "e9674339e06340f9002000d1fd7b56a9ff030691a9000034081040f91f0117eb"
    "20b2fd5420edf7178dedf717feaf00f9e2b300f9e0230191c69cf297e8e30191"
    "e06340f9e12301916916f597e02301912391fe97e06740f9e2b340f90000028b"
    "e1e30191bb97fe97e0e301911c91fe97feaf40f9c0035fd6"
)


def _write_bytes(buf: bytearray, offset: int, blob: bytes, label: str) -> None:
    """Writes a blob at a file offset, refusing to resize the ELF.

    Python slice assignment silently grows a bytearray when the target is past
    EOF.  On a drifted (``--force``) library that would append bytes and leave
    the program headers inconsistent, so every raw write goes through here.
    """
    end = offset + len(blob)
    if offset < 0 or end > len(buf):
        raise ValueError(
            f"{label} write at file offset 0x{offset:x} ({len(blob)} bytes) "
            f"is outside the library (size 0x{len(buf):x})"
        )
    buf[offset:end] = blob


def _write_checked_cave(
    buf: bytearray,
    vaddr: int,
    blob: bytes,
    original_sha256: str,
    label: str = "cave",
) -> int:
    """Installs a trampoline cave after verifying existing or already-patched bytes.

    Returns 1 when the cave was written and 0 when it was already present, so
    callers stay idempotent while refusing to clobber unknown binaries.
    """
    offset = seg_offset(vaddr)
    end = offset + len(blob)
    if offset < 0 or end > len(buf):
        raise ValueError(
            f"{label} write at file offset 0x{offset:x} ({len(blob)} bytes) "
            f"is outside the library (size 0x{len(buf):x})"
        )
    current = bytes(buf[offset:end])
    if current == blob:
        return 0
    if hashlib.sha256(current).hexdigest() != original_sha256:
        raise ValueError(f"Unexpected {label} contents at 0x{vaddr:x}: {current.hex()}")
    _write_bytes(buf, offset, blob, label)
    return 1


def _flags_supported(buf: bytearray) -> bool:
    """True when the buffer is a full library that contains the flag gap."""
    return len(buf) >= seg_offset(PATCH_FLAG_VADDR) + PATCH_FLAG_SIZE


def _has_flag(buf: bytearray, flag: tuple[int, bytes]) -> bool:
    """True when the explicit idempotence flag for a patch is present."""
    if not _flags_supported(buf):
        return False
    slot, magic = flag
    offset = seg_offset(PATCH_FLAG_VADDR) + slot
    return bytes(buf[offset:offset + len(magic)]) == magic


def _set_flag(buf: bytearray, flag: tuple[int, bytes]) -> None:
    """Records that a flag-only patch has been applied.

    The four flag words live in a validated free gap and are used only to make
    a second pass a no-op; the game never reads them.  Small synthetic buffers
    used by unit tests do not contain the gap and are left untouched.
    """
    if not _flags_supported(buf):
        return
    slot, magic = flag
    _write_bytes(buf, seg_offset(PATCH_FLAG_VADDR) + slot, magic, "patch flag")


def _build_guild_raid_sentinel_cave() -> bytes:
    """Builds the server-side `bonus_limit` sentinel trampoline.

    The cave keeps the original nonnegative clamp, then checks whether the
    value exceeds INT32_MAX.  For out-of-range values it only emits -1 when the
    client hook trampoline is present at 0x158C744; otherwise it falls back to
    zero (the old lab workaround) so an unexpected client build can still enter
    the raid without receiving a value it cannot parse.
    """
    word = GUILD_RAID_CLIENT_TRAMPOLINE_WORD
    low = word & 0xFFFF
    high = (word >> 16) & 0xFFFF
    blob = bytearray(GUILD_RAID_SENTINEL_PREFIX)
    blob += struct.pack("<I", 0x5280000B | (low << 5))       # movz w11, #low
    blob += struct.pack("<I", 0x72A0000B | (high << 5))      # movk w11, #high, lsl #16
    blob += bytes.fromhex("5f010b6b610000540000809202000014e0031faa")
    blob += encode_arm64_branch(GUILD_RAID_SENTINEL_CAVE + len(blob), 0x831CEC)
    if len(blob) != 76:
        raise RuntimeError("Internal guild raid sentinel cave layout error")
    return bytes(blob)


GUILD_RAID_SENTINEL_CAVE_BYTES = _build_guild_raid_sentinel_cave()
GUILD_RAID_SENTINEL_CAVE_RANGE = (
    GUILD_RAID_SENTINEL_CAVE,
    GUILD_RAID_SENTINEL_CAVE + len(GUILD_RAID_SENTINEL_CAVE_BYTES),
)
GUILD_RAID_CLIENT_CAVE_RANGE = (
    GUILD_RAID_CLIENT_CAVE,
    GUILD_RAID_CLIENT_CAVE + len(GUILD_RAID_CLIENT_CAVE_BYTES),
)


def _assert_disjoint_intervals(ranges: list[tuple[str, int, int]], kind: str) -> None:
    """Raises if any interval in ``ranges`` overlaps another."""
    ordered = sorted(ranges, key=lambda item: item[1])
    for previous, current in zip(ordered, ordered[1:], strict=False):
        if current[1] < previous[2]:
            raise RuntimeError(
                f"{kind} overlap: {previous[0]} 0x{previous[1]:x}..0x{previous[2]:x} "
                f"overlaps {current[0]} 0x{current[1]:x}..0x{current[2]:x}"
            )


def _assert_disjoint_caves(ranges: list[tuple[str, int, int]]) -> None:
    """Raises if any cave interval in ``ranges`` overlaps another."""
    _assert_disjoint_intervals(ranges, "Code cave")


def _assert_disjoint_scratch_ram(ranges: list[tuple[str, int, int]]) -> None:
    """Raises if any writable scratch RAM slot overlaps another or a reserved symbol."""
    _assert_disjoint_intervals(ranges, "Scratch RAM")


def validate_cave_layout() -> None:
    """Raises if any code cave overlaps another across compatible option profiles."""
    common_ranges = [
        (name, start, start + size) for name, start, size in CAMPAIGN_CAVE_LAYOUT
    ]
    common_ranges.append(("patch_flags", PATCH_FLAG_VADDR, PATCH_FLAG_VADDR + PATCH_FLAG_SIZE))
    common_ranges.append(("event_coin", *EVENT_COIN_CAVE_RANGE))
    common_ranges.append(
        ("expedition_x10", EXPEDITION_CAVE_VADDR, EXPEDITION_CAVE_VADDR + EXPEDITION_CAVE_SIZE)
    )
    common_ranges.append(
        ("dimension_x10", DIMENSION_CAVE_VADDR, DIMENSION_CAVE_VADDR + DIMENSION_CAVE_SIZE)
    )
    common_ranges.append(("guild_raid_client", *GUILD_RAID_CLIENT_CAVE_RANGE))
    common_ranges.append(("guild_raid_sentinel", *GUILD_RAID_SENTINEL_CAVE_RANGE))
    common_ranges.append((
        "guild_raid_mercenary",
        GUILD_RAID_MERCENARY_CAVE_VADDR,
        GUILD_RAID_MERCENARY_CAVE_VADDR + len(GUILD_RAID_MERCENARY_CAVE_BYTES),
    ))
    common_ranges.append((
        "gold_cylinder_x10",
        GOLD_CYLINDER_X10_CAVE_VADDR,
        GOLD_CYLINDER_X10_CAVE_VADDR + GOLD_CYLINDER_X10_CAVE_SIZE,
    ))
    common_ranges.append((
        "event_shop_count",
        EVENT_LIMIT_COUNT_CAVE_VADDR,
        EVENT_LIMIT_COUNT_CAVE_VADDR + EVENT_LIMIT_COUNT_CAVE_SIZE,
    ))
    # Reserved as whole intervals so later patches cannot silently reuse unused
    # bytes within Alex's client and server integration regions.
    common_ranges.append(("alex_awakening_client", 0xB2EA8C, 0xB2FAA0))
    common_ranges.append(("alex_awakening_server", 0xB34D44, 0xB34F50))
    common_ranges.append(("alex_awakening_scratch", 0xBE6268, 0xBE62C8))

    common_ranges.append((
        "randoption_table",
        RANDOPTION_SERVER_SITE,
        RANDOPTION_SERVER_SITE
        + RANDOPTION_SERVER_ROW_COUNT * RANDOPTION_SERVER_ROW_SIZE,
    ))
    common_ranges.append((
        "rune_option_table",
        RUNE_OPTION_TABLE_VADDR,
        RUNE_OPTION_TABLE_VADDR + RUNE_OPTION_ROW_COUNT * RUNE_OPTION_ROW_SIZE,
    ))
    common_ranges.append((
        "rune_upgrade_table",
        RUNE_UPGRADE_TABLE_VADDR,
        RUNE_UPGRADE_TABLE_VADDR + RUNE_UPGRADE_ROW_COUNT * RUNE_UPGRADE_ROW_SIZE,
    ))
    common_ranges.append((
        "single_mod_stone_client",
        SINGLE_MOD_STONE_CAVE_VADDR,
        SINGLE_MOD_STONE_CAVE_VADDR + SINGLE_MOD_STONE_CAVE_SIZE,
    ))
    common_ranges.append(("rune_roll", RUNE_ROLL_CAVE_VA, RUNE_ROLL_CAVE_VA + RUNE_ROLL_CAVE_LEN))
    common_ranges.append(("lan_shim", SHIM_VADDR, SHIM_VADDR + SHIM_MAX_BYTES))
    common_ranges.append((
        "wb_daily_kraken",
        WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
        WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR + WORLDBOSS_DAILY_KRAKEN_CAVE_SIZE,
    ))
    common_ranges.append((
        "dimension_gene_x10",
        DIMENSION_GENE_CAVE_VADDR,
        DIMENSION_GENE_CAVE_VADDR + DIMENSION_GENE_CAVE_SIZE,
    ))
    common_ranges.append((
        "recycle_completion_ticket",
        RECYCLE_COMPLETION_CAVE_VADDR,
        RECYCLE_COMPLETION_CAVE_VADDR + RECYCLE_COMPLETION_CAVE_SIZE,
    ))
    common_ranges.append((
        "recycle_completion_ticket_tail",
        RECYCLE_COMPLETION_CAVE_TAIL_VADDR,
        RECYCLE_COMPLETION_CAVE_TAIL_VADDR + RECYCLE_COMPLETION_CAVE_TAIL_SIZE,
    ))
    common_ranges.append((
        "recycle_reward_flag",
        RECYCLE_REWARD_FLAG_CAVE_VADDR,
        RECYCLE_REWARD_FLAG_CAVE_VADDR + RECYCLE_REWARD_FLAG_CAVE_SIZE,
    ))
    common_ranges.append((
        "gem_mining_x10",
        GEM_MINING_CAVE_VADDR,
        GEM_MINING_CAVE_VADDR + GEM_MINING_CAVE_SIZE,
    ))
    common_ranges.append((
        "honor_points_x2",
        HONOR_POINTS_CAVE_VADDR,
        HONOR_POINTS_CAVE_VADDR + HONOR_POINTS_CAVE_SIZE,
    ))
    common_ranges.append((
        "dev_dispatch_log",
        DEV_LOG_CAVE_VADDR,
        DEV_LOG_CAVE_VADDR + DEV_LOG_CAVE_SIZE,
    ))
    common_ranges.append((
        "dev_handler_timing",
        DEV_TIMING_CAVE_VADDR,
        DEV_TIMING_CAVE_VADDR + DEV_TIMING_CAVE_SIZE,
    ))
    common_ranges.extend(
        (f"costume_package_{index}", address, address + len(payload))
        for index, (address, payload, _digest) in enumerate(COSTUME_PACKAGE_CAVES)
    )
    common_ranges.extend(
        (f"equipment_tier_{index}", address, address + len(payload))
        for index, (address, payload, _digest) in enumerate(EQUIPMENT_TIER_CAVES)
    )
    common_ranges.append((
        "rune_upgrade_client",
        RUNE_UPGRADE_CAVE_VADDR,
        RUNE_UPGRADE_CAVE_VADDR + RUNE_UPGRADE_CAVE_SIZE,
    ))
    common_ranges.append((
        "pvp_team_compact_attack",
        PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR,
        PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR + PVP_TEAM_COMPACT_ATTACK_CAVE_SIZE,
    ))
    common_ranges.append((
        "pvp_team_compact_defense",
        PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR,
        PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR + PVP_TEAM_COMPACT_DEFENSE_CAVE_SIZE,
    ))
    common_ranges.append((
        "gem_mining_types",
        GEM_MINING_TYPES_CAVE_VADDR,
        GEM_MINING_TYPES_CAVE_VADDR + GEM_MINING_TYPES_CAVE_SIZE,
    ))
    common_ranges.append((
        "recycle_grade_capture",
        RECYCLE_GRADE_CAVE_VADDR,
        RECYCLE_GRADE_CAVE_VADDR + RECYCLE_GRADE_CAVE_SIZE,
    ))
    common_ranges.append((
        "recycle_pick_wrapper",
        RECYCLE_PICK_CAVE_VADDR,
        RECYCLE_PICK_CAVE_VADDR + RECYCLE_PICK_CAVE_SIZE,
    ))
    common_ranges.append((
        "guild_raid_fire_support",
        GUILD_RAID_FIRE_SUPPORT_CAVE_VADDR,
        GUILD_RAID_FIRE_SUPPORT_CAVE_VADDR + GUILD_RAID_FIRE_SUPPORT_CAVE_SIZE,
    ))
    common_ranges.append((
        "guild_raid_protection_persist",
        GUILD_RAID_PROTECTION_PERSIST_CAVE_VADDR,
        GUILD_RAID_PROTECTION_PERSIST_CAVE_VADDR + GUILD_RAID_PROTECTION_PERSIST_CAVE_SIZE,
    ))
    common_ranges.append((
        "alex_heros_mark_server",
        ALEX_MARK_SERVER_CAVE_VADDR,
        ALEX_MARK_SERVER_CAVE_VADDR + ALEX_MARK_SERVER_CAVE_SIZE,
    ))
    common_ranges.append((
        "alex_heros_mark_client",
        ALEX_MARK_CLIENT_CAVE_VADDR,
        ALEX_MARK_CLIENT_CAVE_VADDR + ALEX_MARK_CLIENT_CAVE_MAX_SIZE,
    ))
    common_ranges.append((
        "single_gem_fang_all_holes",
        SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR,
        SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR + SINGLE_GEM_FANG_ALL_HOLES_CAVE_SIZE,
    ))
    common_ranges.append((
        "hero_exp_cap",
        HERO_EXP_CAP_CAVE_VADDR,
        HERO_EXP_CAP_CAVE_VADDR + HERO_EXP_CAP_CAVE_SIZE,
    ))
    common_ranges.append((
        "convert_hex_guard",
        CONVERT_HEX_GUARD_CAVE_VADDR,
        CONVERT_HEX_GUARD_CAVE_VADDR + CONVERT_HEX_GUARD_CAVE_SIZE,
    ))
    common_ranges.append((
        "merlin_auto_support",
        MERLIN_AUTO_SUPPORT_CAVE_VADDR,
        MERLIN_AUTO_SUPPORT_CAVE_VADDR + MERLIN_AUTO_SUPPORT_CAVE_SIZE,
    ))
    common_ranges.append((
        "merlin_auto_support_tail",
        MERLIN_AUTO_SUPPORT_TAIL_CAVE_VADDR,
        MERLIN_AUTO_SUPPORT_TAIL_CAVE_VADDR + MERLIN_AUTO_SUPPORT_TAIL_CAVE_SIZE,
    ))
    common_ranges.append((
        "merlin_auto_support_priority",
        MERLIN_AUTO_SUPPORT_PRIORITY_CAVE_VADDR,
        MERLIN_AUTO_SUPPORT_PRIORITY_CAVE_VADDR + MERLIN_AUTO_SUPPORT_PRIORITY_CAVE_SIZE,
    ))
    common_ranges.append((
        "dungeon_recom_info",
        DUNGEON_RECOM_INFO_CAVE_VADDR,
        DUNGEON_RECOM_INFO_CAVE_VADDR + DUNGEON_RECOM_INFO_CAVE_SIZE,
    ))
    common_ranges.append((
        "trait_multi_unique",
        POTENTIAL_MULTI_UNIQUE_CAVE_VADDR,
        POTENTIAL_MULTI_UNIQUE_CAVE_VADDR + POTENTIAL_MULTI_UNIQUE_CAVE_SIZE,
    ))

    # The 0xB33634 client-patcher slot is shared between two mutually-exclusive
    # profiles; verify both against all permanent caves and against siblings.
    slot_profiles = (
        [
            (
                "battle_arena_save",
                BATTLE_ARENA_SAVE_CAVE_VADDR,
                BATTLE_ARENA_SAVE_CAVE_VADDR + len(BATTLE_ARENA_SAVE_CAVE_BYTES),
            ),
            (
                "guild_raid_mercenary_client",
                GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR,
                GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR
                + len(GUILD_RAID_MERCENARY_CLIENT_CAVE_BYTES),
            ),
            (
                "single_gem_fang_client",
                SINGLE_GEM_FANG_CAVE_VADDR,
                SINGLE_GEM_FANG_CAVE_VADDR + SINGLE_GEM_FANG_CAVE_SIZE,
            ),
        ],
    )
    for profile_ranges in slot_profiles:
        _assert_disjoint_caves([*common_ranges, *profile_ranges])

    scratch_ranges = [
        (
            "recycle_reward_flag",
            RECYCLE_SCRATCH_PAGE + RECYCLE_REWARD_FLAG_OFFSET,
            RECYCLE_SCRATCH_PAGE + RECYCLE_REWARD_FLAG_OFFSET + RECYCLE_SCRATCH_SLOT_SIZE,
        ),
        (
            "recycle_grade",
            RECYCLE_SCRATCH_PAGE + RECYCLE_GRADE_OFFSET,
            RECYCLE_SCRATCH_PAGE + RECYCLE_GRADE_OFFSET + RECYCLE_SCRATCH_SLOT_SIZE,
        ),
        (
            "rune_roll_counter",
            RUNE_ROLL_COUNTER_PAGE + RUNE_ROLL_COUNTER_OFFSET,
            RUNE_ROLL_COUNTER_PAGE + RUNE_ROLL_COUNTER_OFFSET + 4,
        ),
        (
            "rune_type_seed",
            RUNE_ROLL_COUNTER_PAGE + RUNE_TYPE_SEED_OFFSET,
            RUNE_ROLL_COUNTER_PAGE + RUNE_TYPE_SEED_OFFSET + 4,
        ),
        (
            "battle_arena_client_base",
            BATTLE_ARENA_SAVE_CLIENT_BASE_GLOBAL,
            BATTLE_ARENA_SAVE_CLIENT_BASE_GLOBAL + 8,
        ),
        # Reserved ELF .data globals bordering our scratch slots
        ("g_manual_setequip_rotation_pair", 0xBE2CB8, 0xBE2CBC),
        ("__emutls_weighted_summon_rng", 0xBE2CC0, 0xBE2CE0),
        ("ios_base_sync_previous_state", 0xBE2F10, 0xBE2F11),
        ("__cxa_terminate_handler", 0xBE2F18, 0xBE2F20),
        ("libunwind_DwarfFDECache", 0xBE2F50, 0xBE2F68),
        ("g_stub_state_transaction_mutex", 0xBE2F70, 0xBE2F98),
    ]
    _assert_disjoint_scratch_ram(scratch_ranges)


def _build_gold_cave(base: int) -> bytes:
    """Builds the campaign-gold trampoline multiplying rolled gold by 10x."""
    first = bytearray()
    first += bytes.fromhex("35eb4229")  # ldp w21, w26, [x25, #0x14]
    first += bytes.fromhex("28074079")  # ldrh w8, [x25, #2] (stage high 16 bits)
    first += bytes.fromhex("08410051")  # sub w8, w8, #0x10
    first += bytes.fromhex("1f090071")  # cmp w8, #2
    first += bytes.fromhex("e8879f1a")  # cset w8, ls
    first += bytes.fromhex("e8030039")  # strb w8, [sp] (campaign flag)
    first += encode_arm64_branch(base + 24, 0xA2C470)
    if len(first) != 28:
        raise RuntimeError("Internal gold cave layout error")

    second = bytearray()
    second += bytes.fromhex("ea034039")  # ldrb w10, [sp]
    second += bytes.fromhex("36c1288b")  # add x22, x9, w8, sxtw
    second += bytes.fromhex("6a000034")  # cbz w10, +12 (skip x10)
    second += bytes.fromhex("d60a168b")  # add x22, x22, x22, lsl #2 (x5)
    second += bytes.fromhex("d6fa7fd3")  # lsl x22, x22, #1 (x10)
    second += encode_arm64_branch(base + 0x1C + 20, 0xA2C9A4)
    if len(second) != 24:
        raise RuntimeError("Internal gold cave layout error")

    blob = bytes(first + second)
    if len(blob) != 52:
        raise RuntimeError("Internal gold cave layout error")
    return blob


def _build_gene_cave(base: int) -> bytes:
    """Builds the campaign-gene trampoline multiplying rolled genes by 10x."""
    blob = bytearray()
    blob += bytes.fromhex("77c69f9a")  # csinc x23, x19, xzr, gt
    blob += bytes.fromhex("280340b9")  # ldr w8, [x25]
    blob += bytes.fromhex("087d1053")  # lsr w8, w8, #16
    blob += bytes.fromhex("08410051")  # sub w8, w8, #0x10
    blob += bytes.fromhex("1f090071")  # cmp w8, #2
    blob += bytes.fromhex("68000054")  # b.hi +12 (skip x10)
    blob += bytes.fromhex("f70a178b")  # add x23, x23, x23, lsl #2
    blob += bytes.fromhex("f7fa7fd3")  # lsl x23, x23, #1
    blob += encode_arm64_branch(base + 32, 0xA2CC48)
    if len(blob) != 36:
        raise RuntimeError("Internal gene cave layout error")
    return bytes(blob)


def _build_mana_cave(base: int) -> bytes:
    """Builds the campaign-mana trampoline multiplying rolled mana by 10x."""
    first = bytearray()
    first += bytes.fromhex("356b4429")  # ldp w21, w26, [x25, #0x20]
    first += bytes.fromhex("280340b9")  # ldr w8, [x25]
    first += bytes.fromhex("087d1053")  # lsr w8, w8, #16
    first += bytes.fromhex("08410051")  # sub w8, w8, #0x10
    first += bytes.fromhex("1f090071")  # cmp w8, #2
    first += bytes.fromhex("48000054")  # b.hi +8
    first += bytes.fromhex("b50260b2")  # orr x21, x21, #0x100000000
    first += encode_arm64_branch(base + 28, 0xA2C648)
    if len(first) != 32:
        raise RuntimeError("Internal mana cave layout error")

    second = bytearray()
    second += bytes.fromhex("36c1288b")  # add x22, x9, w8, sxtw
    second += bytes.fromhex("750000b6")  # tbz x21, #0x20, +12
    second += bytes.fromhex("d60a168b")  # add x22, x22, x22, lsl #2
    second += bytes.fromhex("d6fa7fd3")  # lsl x22, x22, #1
    second += encode_arm64_branch(base + 32 + 16, 0xA2CAD4)
    if len(second) != 20:
        raise RuntimeError("Internal mana cave layout error")

    blob = bytes(first + second)
    if len(blob) != 52:
        raise RuntimeError("Internal mana cave layout error")
    return blob


def _build_items_cave(base: int) -> bytes:
    """Builds the item trampoline multiplying campaign/Nephthys drops by 10x.

    The first segment stores 0/1/2 in ``[sp]``: 0 = no multiplier, 1 = regular
    campaign (only category 2 items), 2 = Nephthys/Lost Island (all item
    rewards).  The second segment consumes that flag after the original
    ``add x19, x9, w8, sxtw``.
    """
    first = bytearray.fromhex(
        "15017ab9"  # ldr w21, [x8, #0x3a00]
        "290340b9"  # ldr w9, [x25]
        "297d1053"  # lsr w9, w9, #16
        "2b410051"  # sub w11, w9, #0x10
        "7f090071"  # cmp w11, #2
        "ea879f1a"  # cset w10, ls
        "2bc10151"  # sub w11, w9, #0x70
        "7f050071"  # cmp w11, #1
        "ec879f1a"  # cset w12, ls
        "8c791f53"  # lsl w12, w12, #1
        "4a010c2a"  # orr w10, w10, w12
        "2b010251"  # sub w11, w9, #0x80
        "7f050071"  # cmp w11, #1
        "ec879f1a"  # cset w12, ls
        "8c791f53"  # lsl w12, w12, #1
        "4a010c2a"  # orr w10, w10, w12
        "ea030039"  # strb w10, [sp]
    )
    first += encode_arm64_branch(base + ITEM_CAVE_FIRST_SIZE - 4, 0xA2D0D8)
    if len(first) != ITEM_CAVE_FIRST_SIZE:
        raise RuntimeError(
            f"Internal items cave first segment: {len(first)} bytes, expected {ITEM_CAVE_FIRST_SIZE}"
        )

    second = bytearray.fromhex(
        "33c1288b"  # add x19, x9, w8, sxtw
        "ea034039"  # ldrb w10, [sp]
        "ea000034"  # cbz w10, +28 (return)
        "5f050071"  # cmp w10, #1
        "61000054"  # b.ne +12 (multiply)
        "5f0b0071"  # cmp w26, #2
        "61000054"  # b.ne +12 (return)
        "730a138b"  # add x19, x19, x19, lsl #2
        "73fa7fd3"  # lsl x19, x19, #1
    )
    second += encode_arm64_branch(base + ITEM_CAVE_SIZE - 4, 0xA2D6C8)
    if len(second) != ITEM_CAVE_SECOND_SIZE:
        raise RuntimeError(
            f"Internal items cave second segment: {len(second)} bytes, expected {ITEM_CAVE_SECOND_SIZE}"
        )

    blob = bytes(first + second)
    if len(blob) != ITEM_CAVE_SIZE:
        raise RuntimeError(f"Internal items cave layout error: {len(blob)} bytes")
    return blob


def _build_dimension_gene_cave(base: int) -> bytes:
    """Builds the x10 gene-count trampoline for Dimension Breakthrough."""
    blob = bytearray()
    blob += bytes.fromhex("62f37dd3")  # lsl x2, x27, #3
    blob += bytes.fromhex("42041b8b")  # add x2, x2, x27, lsl #1
    blob += encode_arm64_branch(
        base + DIMENSION_GENE_CAVE_SIZE - 4, DIMENSION_GENE_COUNT_RETURN_VADDR
    )
    if len(blob) != DIMENSION_GENE_CAVE_SIZE:
        raise RuntimeError(
            f"Internal dimension gene cave: {len(blob)} bytes, "
            f"expected {DIMENSION_GENE_CAVE_SIZE}"
        )
    return bytes(blob)


def _build_expedition_cave(base: int) -> bytes:
    """Builds the expedition-bonus trampoline multiplying rolled rewards by 10x."""
    blob = bytearray()
    blob += bytes.fromhex("fd7bbfa9")  # stp x29, x30, [sp, #-16]!
    blob += bytes.fromhex("fd030091")  # mov x29, sp
    blob += encode_arm64_branch(base + 8, 0xA75904, link=True)  # bl 0xA75904
    blob += bytes.fromhex("0008008b")  # add x0, x0, x0, lsl #2
    blob += bytes.fromhex("00f87fd3")  # lsl x0, x0, #1
    blob += bytes.fromhex("fd7bc1a8")  # ldp x29, x30, [sp], #16
    blob += bytes.fromhex("c0035fd6")  # ret
    if len(blob) != 28:
        raise RuntimeError("Internal expedition cave layout error")
    return bytes(blob)


def _build_dimension_cave(base: int) -> bytes:
    """Builds the Dimension Breakthrough drop roll multiplier trampoline (10x)."""
    blob = bytearray()
    blob += bytes.fromhex("600a138b")  # add x0, x19, x19, lsl #2
    blob += bytes.fromhex("00f87fd3")  # lsl x0, x0, #1
    blob += encode_arm64_branch(base + 8, 0x94B52C)
    if len(blob) != 12:
        raise RuntimeError("Internal dimension cave layout error")
    return bytes(blob)


def worldboss_cycle_reward_rows(
    so_bytes: bytes | bytearray,
) -> list[tuple[int, int, int, int, int]]:
    """Returns `(row_id, reward_type, resource_type, val1, val2)` for final rank/grade rows."""
    base = seg_offset(WORLDBOSS_CYCLE_REWARD_VADDR)
    rows: list[tuple[int, int, int, int, int]] = []
    for index in range(WORLDBOSS_CYCLE_REWARD_ROW_COUNT):
        at = base + index * WORLDBOSS_CYCLE_REWARD_ROW_SIZE
        row_id, reward_type, _min_v, _max_v, resource_type, _pad, val1, val2 = (
            struct.unpack_from("<iiqqiiqq", so_bytes, at)
        )
        if reward_type in WORLDBOSS_CYCLE_REWARD_TARGET_TYPES:
            rows.append((row_id, reward_type, resource_type, val1, val2))
    return rows


def _build_campaign_hooks() -> dict[int, bytes]:
    """Builds hook sites + assembled 10x cave bodies at the safe cave base."""
    hooks: dict[int, bytes] = {}
    builders = {
        "gold": _build_gold_cave,
        "gene": _build_gene_cave,
        "mana": _build_mana_cave,
        "items": _build_items_cave,
    }
    for name, new_start, length in CAMPAIGN_CAVE_LAYOUT:
        blob = builders[name](new_start)
        if len(blob) != length:
            raise RuntimeError(
                f"Internal cave layout error for {name}: {len(blob)} bytes, expected {length}"
            )
        hooks[new_start] = blob
    for hook, offset in CAMPAIGN_HOOK_TARGETS.items():
        hooks[hook] = encode_arm64_branch(hook, CAMPAIGN_CAVE_BASE + offset)
    return hooks


CAMPAIGN_HOOKS = _build_campaign_hooks()


def _validate_reference_hashes(
    so_bytes: bytes,
    dex_bytes: bytes,
    *,
    allow_unknown: bool,
    needs_dex: bool,
) -> tuple[str, str, list[str]]:
    """Validates the input against the supported 0.682 v1574 reference."""
    so_sha = hashlib.sha256(so_bytes).hexdigest()
    dex_sha = hashlib.sha256(dex_bytes).hexdigest()
    warnings: list[str] = []

    if so_sha != REFERENCE_SO_SHA256:
        message = (
            "Input native library is not the supported reference build "
            f"(expected SHA-256 {REFERENCE_SO_SHA256}, got {so_sha})."
        )
        if not allow_unknown:
            raise ValueError(message + " Refusing to patch; use --force only for development.")
        warnings.append(message + " Continuing because allow_unknown/--force is enabled.")

    if needs_dex and dex_sha != REFERENCE_DEX_SHA256:
        message = (
            "Input classes8.dex is not the supported reference build "
            f"(expected SHA-256 {REFERENCE_DEX_SHA256}, got {dex_sha})."
        )
        if not allow_unknown:
            raise ValueError(message + " Refusing to patch; use --force only for development.")
        warnings.append(message + " Continuing because allow_unknown/--force is enabled.")

    return so_sha, dex_sha, warnings


def apply_summon_rates(
    buf: bytearray,
    targets: dict[int, int] | None = None,
) -> int:
    """Patches equipment summon pools to a weighted rarity profile.

    ``targets`` maps pool category to total weight; when omitted the original
    70/20/10 profile is used.  Idempotent: rows already at the target profile
    produce a zero change count.
    """
    if targets is None:
        targets = SUMMON_TARGETS

    changed = 0
    for name, start, count, expected in SUMMON_POOLS:
        rows = []
        for index in range(count):
            offset = start + index * 40
            weight, category, rotation = struct.unpack_from("<iii", buf, offset)
            special = buf[offset + 12]
            target = targets.get(category, 0)
            if category not in expected or weight < 0 or special != (1 if category == 5 else 0):
                raise ValueError(f"Invalid {name} summon pool row {index} at offset 0x{offset:x}")
            if target > 0 and weight == 0:
                raise ValueError(
                    f"Invalid {name} summon pool row {index} at offset 0x{offset:x}: "
                    f"category {category} cannot have zero weight"
                )
            rows.append((offset, weight, category))

        if Counter(category for _, _, category in rows) != expected:
            raise ValueError(f"Unexpected {name} pool category distribution")

        for category in expected:
            entries = [(offset, weight) for offset, weight, group in rows if group == category]
            target = targets.get(category, 0)
            total = sum(weight for _, weight in entries)
            if total == 0:
                if target != 0:
                    raise ValueError(f"All weights are zero for {name} category {category}")
                continue
            # Largest-remainder apportionment preserves relative weights within rarity
            parts = [(offset, target * weight // total, target * weight % total) for offset, weight in entries]
            remaining = target - sum(value for _, value, _ in parts)
            winners = {offset for offset, _, _ in sorted(parts, key=lambda x: (-x[2], x[0]))[:remaining]}
            for offset, value, _ in parts:
                new_weight = value + (offset in winners)
                if new_weight != struct.unpack_from("<i", buf, offset)[0]:
                    changed += 1
                struct.pack_into("<i", buf, offset, new_weight)
    return changed


def apply_expeditions(buf: bytearray) -> int:
    """Multiplies expedition hero XP and reward quantities (crystals, mana, coins, genes, items) by 10x."""
    # The call-site hook is the authoritative "already applied" marker; do not
    # infer it from a table value, which can occur naturally.
    first_site = EXPEDITION_CALL_SITES[0]
    first_offset = seg_offset(first_site)
    first_replacement = encode_arm64_branch(first_site, EXPEDITION_CAVE_VADDR, link=True)
    already_patched = bytes(buf[first_offset:first_offset + 4]) == first_replacement

    changed = 0

    # 1. Multiply hero XP by 10 in table
    for index, region in enumerate(EXPEDITION_REGIONS):
        start = EXPEDITION_TABLE + index * EXPEDITION_ROW_SIZE
        row_id, actual_region, duration, gold, hero_xp, lord_xp = struct.unpack_from("<6i", buf, start)
        if row_id != index + 1 or actual_region != region or duration <= 0 or not 0 <= hero_xp <= 0x7FFFFFFF // 10:
            raise ValueError(f"Unexpected expedition reward row {index} at offset 0x{start:x}")
        if not already_patched:
            struct.pack_into("<i", buf, start + 16, hero_xp * 10)
            changed += 1

    # 2. Install expedition 10x cave trampoline after verifying the original slot.
    cave_blob = _build_expedition_cave(EXPEDITION_CAVE_VADDR)
    _write_checked_cave(
        buf,
        EXPEDITION_CAVE_VADDR,
        cave_blob,
        EXPEDITION_CAVE_ORIGINAL_SHA256,
        label="expedition cave",
    )

    # 3. Patch 5 call sites to branch with link to expedition cave
    for address in EXPEDITION_CALL_SITES:
        offset = seg_offset(address)
        original_bl = encode_arm64_branch(address, 0xA75904, link=True)
        replacement_bl = encode_arm64_branch(address, EXPEDITION_CAVE_VADDR, link=True)
        current = bytes(buf[offset:offset + 4])
        if current not in (original_bl, replacement_bl):
            raise ValueError(f"Unexpected instruction at expedition call 0x{address:x}: {current.hex()}")
        if current != replacement_bl:
            _write_bytes(buf, offset, replacement_bl, "expedition hook")
            changed += 1

    # 4. Normalize any legacy 2x shifted instructions without inflating changed
    # above EXPECTED_PATCH_COUNTS["expedition_bonus"].
    for address, (legacy_lsl, original_mov) in EXPEDITION_LEGACY_RESTORATIONS.items():
        offset = seg_offset(address)
        current = bytes(buf[offset:offset + 4])
        if current not in (legacy_lsl, original_mov):
            raise ValueError(
                f"Unexpected instruction at expedition legacy site 0x{address:x}: "
                f"{current.hex()} (expected {original_mov.hex()} or {legacy_lsl.hex()})"
            )
        if current == legacy_lsl:
            _write_bytes(buf, offset, original_mov, "expedition legacy restore")

    return changed


def apply_gene_priority(buf: bytearray) -> int:
    """Prioritizes hero gene drops over all other drop types in map & island stages."""
    changed = 0
    for index in range(STAGE_ROW_COUNT):
        at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
        row = struct.unpack_from("<35i", buf, at)
        stage = _stage_prefix(row[0])
        gene_weight, gene_id = row[22], row[23]
        if stage not in GENE_PREFIXES or gene_weight <= 0 or gene_id <= 0:
            continue
        highest = max(0, *(row[pos] for pos in GENE_OTHER_WEIGHT_COLS))
        priority = max(gene_weight, highest + 1)
        if priority > 0x7FFFFFFF:
            raise ValueError(f"Gene weight exceeds native int32 at stage {stage}")
        if priority == gene_weight:
            continue
        struct.pack_into("<i", buf, at + 22 * 4, priority)
        changed += 1
    return changed


def apply_no_equip_drops(buf: bytearray) -> int:
    """Removes equipment from stage drop pools and redistributes its weight.

    The server picks one reward category per rank-drop slot from a weighted
    pool.  Setting the equipment chance to zero would remove those rolls
    entirely; instead its weight is apportioned across the other eligible
    categories (gold, items, monsters, manastone, genes and energy) in
    proportion to their current weights.
    """
    changed = 0
    for index in range(STAGE_ROW_COUNT):
        at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
        row = list(struct.unpack_from("<35i", buf, at))
        equip_weight = row[STAGE_EQUIP_WEIGHT]
        if equip_weight <= 0:
            continue

        eligible: list[tuple[int, int]] = []
        if row[STAGE_GOLD_WEIGHT] > 0:
            eligible.append((STAGE_GOLD_WEIGHT, row[STAGE_GOLD_WEIGHT]))
        if row[STAGE_ITEM_WEIGHT] > 0 and row[STAGE_ITEM_TABLE] > 0:
            eligible.append((STAGE_ITEM_WEIGHT, row[STAGE_ITEM_WEIGHT]))
        if row[STAGE_MONSTER_WEIGHT] > 0 and row[STAGE_MONSTER_TABLE] > 0:
            eligible.append((STAGE_MONSTER_WEIGHT, row[STAGE_MONSTER_WEIGHT]))
        if row[STAGE_MANASTONE_WEIGHT] > 0:
            eligible.append((STAGE_MANASTONE_WEIGHT, row[STAGE_MANASTONE_WEIGHT]))
        if row[STAGE_GENE_WEIGHT] > 0 and row[STAGE_GENE_ID] >= 0:
            eligible.append((STAGE_GENE_WEIGHT, row[STAGE_GENE_WEIGHT]))
        if row[STAGE_ENERGY_WEIGHT] > 0 and row[STAGE_ENERGY_VALUE] >= 0:
            eligible.append((STAGE_ENERGY_WEIGHT, row[STAGE_ENERGY_WEIGHT]))

        if eligible:
            total = sum(weight for _, weight in eligible)
            allocation: list[list[int]] = []
            allocated = 0
            for field, weight in eligible:
                quotient, remainder = divmod(equip_weight * weight, total)
                allocation.append([field, quotient, remainder])
                allocated += quotient
            for entry in sorted(allocation, key=lambda item: (-item[2], item[0]))[
                : equip_weight - allocated
            ]:
                entry[1] += 1
            for field, value, _remainder in allocation:
                row[field] += value

        row[STAGE_EQUIP_WEIGHT] = 0
        struct.pack_into("<35i", buf, at, *row)
        changed += 1
    return changed


def apply_campaign_xp(buf: bytearray) -> int:
    """Multiplies campaign hero XP and Lord XP by 10x for regular campaign stages."""
    already_patched = _has_flag(buf, CAMPAIGN_XP_FLAG)

    count = 0
    limit = 0x7FFFFFFF // 10
    for index in range(STAGE_ROW_COUNT):
        at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
        stage, hero_xp, gold, lord_xp = struct.unpack_from("<4i", buf, at)
        if _stage_prefix(stage) not in CAMPAIGN_PREFIXES:
            continue
        if min(hero_xp, lord_xp) < 0 or max(hero_xp, lord_xp) > limit:
            raise ValueError(f"Unexpected XP value in stage {stage:x}")
        if not already_patched:
            struct.pack_into("<i", buf, at + 4, hero_xp * 10)
            struct.pack_into("<i", buf, at + 12, lord_xp * 10)
            count += 1
    if count == 0 and not already_patched:
        raise ValueError("Campaign XP patch found no matching campaign stage rows")
    if count > 0:
        _set_flag(buf, CAMPAIGN_XP_FLAG)
    return count


def apply_campaign_gold_and_drops(buf: bytearray) -> int:
    """Multiplies campaign base gold, stamina, and in-game item/mana/gene drop quantities by 10x."""
    already_patched = all(
        bytes(buf[seg_offset(address):seg_offset(address) + len(code)]) == code
        for address, code in CAMPAIGN_HOOKS.items()
    )

    count = 0
    limit = 0x7FFFFFFF // 10
    for index in range(STAGE_ROW_COUNT):
        at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
        stage, _hero_xp, gold = struct.unpack_from("<3i", buf, at)
        if _stage_prefix(stage) not in CAMPAIGN_PREFIXES:
            continue
        if not 0 <= gold <= limit:
            raise ValueError(f"Unexpected gold value in stage {stage:x}")
        if not already_patched:
            struct.pack_into("<i", buf, at + 8, gold * 10)

        # Stamina multiplier
        stamina = struct.unpack_from("<i", buf, at + 128)[0]
        if stamina > 0:
            if stamina > limit:
                raise ValueError(f"Unexpected stamina value in stage {stage:x}")
            if not already_patched:
                struct.pack_into("<i", buf, at + 128, stamina * 10)
        if not already_patched:
            count += 1

    # Install code trampolines in checked cave slots and patch verified hook sites.
    for address, code in CAMPAIGN_HOOKS.items():
        cave_sha = CAMPAIGN_CAVE_ORIGINAL_SHA256.get(address)
        if cave_sha is not None:
            _write_checked_cave(buf, address, code, cave_sha, label="campaign cave")
            continue
        original = CAMPAIGN_HOOK_ORIGINALS.get(address)
        if original is None:
            raise RuntimeError(
                f"Missing baseline expectation for campaign address 0x{address:x}"
            )
        offset = seg_offset(address)
        current = bytes(buf[offset:offset + len(original)])
        if current not in (original, code):
            raise ValueError(
                f"Unexpected instruction at campaign hook 0x{address:x}: {current.hex()} "
                f"(expected {original.hex()} or {code.hex()})"
            )
        if current != code:
            _write_bytes(buf, offset, code, "campaign hook")

    if count == 0 and not already_patched:
        raise ValueError("Campaign gold patch found no matching campaign stage rows")

    return count


def apply_english_localization_so(buf: bytearray) -> int:
    """Bypasses forced-Korean C# string table, message-box localization gates, and patches Korean UI text in native SO."""
    changed = 0
    for src, dst in ENGLISH_SO_GATES:
        offset = seg_offset(src)
        replacement = encode_arm64_branch(src, dst, link=False)
        current = bytes(buf[offset:offset + 4])
        original = ENGLISH_SO_GATE_ORIGINALS[src]
        if current not in (original, replacement):
            raise ValueError(
                f"Unexpected instruction at English gate 0x{src:x}: {current.hex()} "
                f"(expected {original.hex()} or {replacement.hex()})"
            )
        if current != replacement:
            _write_bytes(buf, offset, replacement, "English gate")
            changed += 1

    # Replace Korean "수량" with "Qty" in .rodata
    qty_current = bytes(buf[ENGLISH_SO_QTY_OFFSET:ENGLISH_SO_QTY_OFFSET + len(ENGLISH_SO_QTY_REPLACEMENT)])
    if qty_current not in (ENGLISH_SO_QTY_ORIGINAL, ENGLISH_SO_QTY_REPLACEMENT):
        raise ValueError(
            f"Unexpected bytes at English Qty offset 0x{ENGLISH_SO_QTY_OFFSET:x}: {qty_current.hex()}"
        )
    if qty_current != ENGLISH_SO_QTY_REPLACEMENT:
        _write_bytes(
            buf,
            ENGLISH_SO_QTY_OFFSET,
            ENGLISH_SO_QTY_REPLACEMENT,
            "English Qty rodata",
        )
        changed += 1
    return changed


def recalculate_dex_hashes(dex_buf: bytearray) -> None:
    """Recomputes SHA-1 and Adler32 checksums for Android DEX file."""
    if len(dex_buf) < 0x70 or dex_buf[:4] != b"dex\n":
        raise ValueError("Invalid DEX header")
    dex_buf[12:32] = hashlib.sha1(memoryview(dex_buf)[32:]).digest()
    checksum = zlib.adler32(memoryview(dex_buf)[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", dex_buf, 8, checksum)


def apply_bootstrap_dex(
    dex_buf: bytearray,
    *,
    translate: bool,
    contract: ResourceContract | None,
    apktool_jar: str | Path | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> int:
    """Rewrites bootstrap strings and/or resource-contract values through smali.

    Returns the number of translation edits (resource-contract edits are
    reported through the log only because they are not a user-facing feature).
    """
    jar = Path(apktool_jar) if apktool_jar is not None else ensure_apktool_jar(log_fn)
    patched, changes = rebuild_dex(
        bytes(dex_buf),
        translate=translate,
        contract=contract,
        apktool_jar=jar,
        log_fn=log_fn,
    )
    dex_buf[:] = patched
    if contract is not None and changes.contract == 0:
        raise ValueError("Resource contract update made no changes")
    return changes.translation


def apply_english_localization_dex(
    dex_buf: bytearray,
    *,
    apktool_jar: str | Path | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> int:
    """Translates the bootstrap UI and forces the English save-copy prompt."""
    return apply_bootstrap_dex(
        dex_buf,
        translate=True,
        contract=None,
        apktool_jar=apktool_jar,
        log_fn=log_fn,
    )


def apply_lan_redirect(
    buf: bytearray,
    dex_buf: bytearray,
    server_ip: str,
    server_port: int,
    *,
    force_english: bool = True,
) -> int:
    """Injects Zero-DNS LAN redirect shim and disables phone-side server spawns."""
    try:
        packed_ip = ipaddress.IPv4Address(server_ip).packed
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid LAN IPv4 address: {server_ip!r}") from exc
    try:
        port = int(server_port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid LAN port: {server_port!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"LAN port out of range (1..65535): {port}")

    raw_shim = base64.b64decode(EMBEDDED_SHIM_B64)
    if len(raw_shim) < 24 or len(raw_shim) > SHIM_MAX_BYTES:
        raise ValueError(
            f"Embedded LAN shim has invalid size {len(raw_shim)} bytes "
            f"(expected 24..{SHIM_MAX_BYTES})"
        )
    shim_buf = bytearray(raw_shim)
    if struct.unpack_from("<I", shim_buf, 8)[0] != SHIM_MAGIC:
        raise ValueError("Embedded LAN shim magic does not match SHIM_MAGIC")
    shim_off = seg_offset(SHIM_VADDR)
    shim_already = (
        len(buf) >= shim_off + 12
        and struct.unpack_from("<I", buf, shim_off + 8)[0] == SHIM_MAGIC
    )
    shim_buf[12:16] = packed_ip
    struct.pack_into(">H", shim_buf, 16, port)
    struct.pack_into("<H", shim_buf, 18, 1 if force_english else 0)
    struct.pack_into("<I", shim_buf, 20, 0)

    replacements = {
        0xAAD9F8: encode_arm64_branch(0xAAD9F8, SHIM_VADDR + 4, link=False),
        0xAA6D70: LOOPBACK_CONNECT_STUB[:4],
        0xAB5D48: encode_arm64_branch(0xAB5D48, 0xAA6D2C, link=True),
        0xAAE450: ARM64_RET,
        0xAADE84: ARM64_MOV_W0_1,
        0xAADFA0: ARM64_MOV_W0_1,
    }
    for address, replacement in replacements.items():
        offset = seg_offset(address)
        current = bytes(buf[offset:offset + 4])
        original = LAN_SITE_ORIGINALS[address]
        if current not in (original, replacement):
            raise ValueError(
                f"Unexpected instruction at LAN site 0x{address:x}: {current.hex()} "
                f"(expected {original.hex()} or {replacement.hex()})"
            )

    # 1. Inject shim into unused HTTP server body
    _write_bytes(buf, seg_offset(SHIM_VADDR), bytes(shim_buf), "LAN shim")

    # 2. Early network boundary hook to run Locale.setDefault(Locale.US)
    _write_bytes(buf, seg_offset(0xAAD9F8), replacements[0xAAD9F8], "LAN boundary hook")

    # 3. Route loopback connect into fwt_lan_connect_impl
    _write_bytes(
        buf,
        seg_offset(0xAA6D70),
        LOOPBACK_CONNECT_STUB,
        "LAN loopback stub",
    )

    # 4. Route startup server ready check
    _write_bytes(buf, seg_offset(0xAB5D48), replacements[0xAB5D48], "LAN ready hook")

    # 5. Disable post-Unity external socket reaper
    _write_bytes(buf, seg_offset(0xAAE450), ARM64_RET, "LAN reaper")

    # 6. Disable attendance & shop materializers
    _write_bytes(buf, seg_offset(0xAADE84), ARM64_MOV_W0_1, "LAN attendance")
    _write_bytes(buf, seg_offset(0xAADFA0), ARM64_MOV_W0_1, "LAN shop materializer")

    # 7. Disable server spawn calls
    for bl_vaddr in SERVER_SPAWN_BL_VADDRS:
        off = seg_offset(bl_vaddr)
        current = bytes(buf[off:off + 4])
        original = SERVER_SPAWN_ORIGINALS[bl_vaddr]
        if current not in (original, ARM64_NOP):
            raise ValueError(
                f"Unexpected instruction at server spawn 0x{bl_vaddr:x}: {current.hex()} "
                f"(expected {original.hex()} or NOP)"
            )
        buf[off:off + 4] = ARM64_NOP

    # 8. Patch DEX to skip local save backup dialogs
    for offset, length in LAN_DEX_BACKUP_PATCHES:
        current = bytes(dex_buf[offset:offset + length])
        patched = bytes(length)
        if current != patched:
            # Only accept the known original bytes; reject unknown DEX layouts.
            expected = {
                0x006148: bytes.fromhex("38001900"),
                0x005D7C: bytes.fromhex("7807ae010300"),
            }[offset]
            if current != expected:
                raise ValueError(
                    f"Unexpected DEX bytes at 0x{offset:x}: {current.hex()} "
                    f"(expected {expected.hex()} or {patched.hex()})"
                )
            dex_buf[offset:offset + length] = patched
    recalculate_dex_hashes(dex_buf)
    sites_already = all(
        bytes(buf[seg_offset(address):seg_offset(address) + len(replacement)])
        == replacement
        for address, replacement in replacements.items()
    ) and all(
        bytes(buf[seg_offset(address):seg_offset(address) + 4]) == ARM64_NOP
        for address in SERVER_SPAWN_BL_VADDRS
    )
    dex_already = all(
        bytes(dex_buf[offset:offset + length]) == bytes(length)
        for offset, length in LAN_DEX_BACKUP_PATCHES
    )
    return 0 if shim_already and sites_already and dex_already else 1


def apply_event_discount(buf: bytearray) -> int:
    """Applies a 90% discount to all event shop items (shop_content: 2)."""
    pat = re.compile(
        rb'\{(?=[^{}]*?"shop_content":\s*2)'
        rb'(?=[^{}]*?"price_count":(\s*\d+))[^{}]*\}'
    )
    flags = _flags_supported(buf)
    if flags and _has_flag(buf, EVENT_DISCOUNT_FLAG):
        return 0
    matches = list(pat.finditer(buf))
    if not flags and any(m.group(1).startswith(b" ") for m in matches):
        return 0
    count = 0
    for m in matches:
        sub = m.group(0)
        p_match = re.search(rb'"price_count":(\s*\d+)', sub)
        if p_match:
            old_val_str = p_match.group(1)
            old_val = int(old_val_str)
            new_val = (old_val + 9) // 10
            new_val_str = f"{new_val:>{len(old_val_str)}}".encode("ascii")
            if len(new_val_str) != len(old_val_str):
                raise ValueError(
                    f"Price string length mismatch: {old_val_str!r} vs {new_val_str!r}"
                )
            abs_pos = m.start() + p_match.start(1)
            if old_val != new_val:
                _write_bytes(buf, abs_pos, new_val_str, "event discount price")
            count += 1
    if count == 0:
        raise ValueError("Event discount patch matched no shop rows")
    _set_flag(buf, EVENT_DISCOUNT_FLAG)
    return count


def _write_recycle_cave(
    buf: bytearray,
    vaddr: int,
    blob: bytes,
    original_sha256: str,
) -> int:
    """Installs a recycle/reward trampoline, rejecting an unknown cave slot."""
    return _write_checked_cave(
        buf,
        vaddr,
        blob,
        original_sha256,
        label="recycle cave",
    )


def apply_recycle_ticket_rewards(buf: bytearray) -> int:
    """Replaces equipment recycling rewards with transcendence-ticket items.

    The bar-completion equipment grant at ``0x89D150`` is replaced by a
    trampoline that grants the class ticket matching the captured alchemy grade
    (1..5 -> 130001..130005) on normal completions, or the Ultimate ticket
    (130006) on the final bar step.  A flag cave at ``0x89CEF8`` saves the
    native table selector so the trampoline can distinguish the two cases, and
    a grade cave at ``0x89CCD0`` saves the real 1..5 grade before the handler
    overwrites ``x28``.  A wrapper on the shared reward-pick failure path lets
    the native pick return a valid dummy row for the disassemble caller.

    Returns the number of changed sites (5 caves + 4 hooks on a pristine
    build, 0 when the feature is already installed).
    """
    if len(RECYCLE_COMPLETION_CAVE_BYTES) > RECYCLE_COMPLETION_CAVE_SIZE:
        raise RuntimeError("Internal recycle completion cave layout error")
    if len(RECYCLE_COMPLETION_CAVE_TAIL_BYTES) > RECYCLE_COMPLETION_CAVE_TAIL_SIZE:
        raise RuntimeError("Internal recycle completion tail layout error")
    if len(RECYCLE_REWARD_FLAG_CAVE_BYTES) > RECYCLE_REWARD_FLAG_CAVE_SIZE:
        raise RuntimeError("Internal recycle reward flag cave layout error")
    if len(RECYCLE_GRADE_CAVE_BYTES) > RECYCLE_GRADE_CAVE_SIZE:
        raise RuntimeError("Internal recycle grade cave layout error")
    if len(RECYCLE_PICK_CAVE_BYTES) > RECYCLE_PICK_CAVE_SIZE:
        raise RuntimeError("Internal recycle pick cave layout error")

    changed = 0
    changed += _write_recycle_cave(
        buf,
        RECYCLE_COMPLETION_CAVE_VADDR,
        RECYCLE_COMPLETION_CAVE_BYTES,
        RECYCLE_COMPLETION_CAVE_ORIGINAL_SHA256,
    )
    changed += _write_recycle_cave(
        buf,
        RECYCLE_COMPLETION_CAVE_TAIL_VADDR,
        RECYCLE_COMPLETION_CAVE_TAIL_BYTES,
        RECYCLE_COMPLETION_CAVE_TAIL_ORIGINAL_SHA256,
    )
    changed += _write_recycle_cave(
        buf,
        RECYCLE_REWARD_FLAG_CAVE_VADDR,
        RECYCLE_REWARD_FLAG_CAVE_BYTES,
        RECYCLE_REWARD_FLAG_CAVE_ORIGINAL_SHA256,
    )
    changed += _write_recycle_cave(
        buf,
        RECYCLE_GRADE_CAVE_VADDR,
        RECYCLE_GRADE_CAVE_BYTES,
        RECYCLE_GRADE_CAVE_ORIGINAL_SHA256,
    )
    changed += _write_recycle_cave(
        buf,
        RECYCLE_PICK_CAVE_VADDR,
        RECYCLE_PICK_CAVE_BYTES,
        RECYCLE_PICK_CAVE_ORIGINAL_SHA256,
    )

    hooks = (
        (
            RECYCLE_REWARD_FLAG_HOOK,
            RECYCLE_REWARD_FLAG_ORIGINAL,
            encode_arm64_branch(
                RECYCLE_REWARD_FLAG_HOOK,
                RECYCLE_REWARD_FLAG_CAVE_VADDR,
                link=True,
            ),
        ),
        (
            RECYCLE_COMPLETION_HOOK,
            RECYCLE_COMPLETION_ORIGINAL,
            encode_arm64_branch(
                RECYCLE_COMPLETION_HOOK,
                RECYCLE_COMPLETION_CAVE_VADDR,
                link=True,
            ),
        ),
        (
            RECYCLE_GRADE_HOOK,
            RECYCLE_GRADE_ORIGINAL,
            encode_arm64_branch(
                RECYCLE_GRADE_HOOK,
                RECYCLE_GRADE_CAVE_VADDR,
            ),
        ),
        (
            RECYCLE_PICK_HOOK,
            RECYCLE_PICK_ORIGINAL,
            encode_arm64_branch(
                RECYCLE_PICK_HOOK,
                RECYCLE_PICK_CAVE_VADDR,
            ),
        ),
    )
    for site, original, replacement in hooks:
        offset = seg_offset(site)
        current = bytes(buf[offset:offset + 4])
        if current == replacement:
            continue
        if current != original:
            raise ValueError(
                f"Unexpected recycle hook at 0x{site:x}: {current.hex()} "
                f"(expected {original.hex()} or {replacement.hex()})"
            )
        buf[offset:offset + 4] = replacement
        changed += 1
    return changed


# Backwards-compatible name for scripts written for the 2.5.1 feature key.
apply_recycle_hammer_rewards = apply_recycle_ticket_rewards


def apply_recycle_six_star(buf: bytearray) -> int:
    """Rewrites the 873 native alchemy reward rows to equal-chance 6★ sets.

    The native completion pick (0x9A2FB8) reads ``kFwtEquipRewardRows`` by
    ``w21 + grade`` (groups 102..111).  Both ``_weightValue`` (+4) and
    ``_equipCode`` (+8) are rewritten: the vanilla weights made four sets up to
    ~31x more likely than the rest, so the set totals are now evenly split
    while preserving each group's original total weight.  The native grant,
    response append and point accounting stay untouched.
    """
    groups: dict[int, list[tuple[int, int, int]]] = {
        group: [] for group in RECYCLE_SIX_STAR_GROUPS
    }
    for index in range(RECYCLE_SIX_STAR_ROW_COUNT):
        offset = RECYCLE_SIX_STAR_TABLE + index * RECYCLE_SIX_STAR_ENTRY_SIZE
        group, weight, code = struct.unpack_from("<iii", buf, offset)
        if group in groups:
            groups[group].append((offset, weight, code))

    matched = sum(len(entries) for entries in groups.values())
    if matched != RECYCLE_SIX_STAR_EXPECTED_ROWS:
        raise ValueError(
            "Unexpected alchemy reward rows: "
            f"{matched} (expected {RECYCLE_SIX_STAR_EXPECTED_ROWS})"
        )

    changed = 0
    for group, entries in groups.items():
        targets = recycle_six_star_assignment(
            [(weight, code) for _offset, weight, code in entries],
            RECYCLE_SIX_STAR_GROUP_SLOT[group],
        )
        if all(
            (weight, code) == target
            for (_offset, weight, code), target in zip(
                entries, targets, strict=True
            )
        ):
            continue
        for (offset, _weight, _code), (weight, code) in zip(
            entries, targets, strict=True
        ):
            struct.pack_into("<i", buf, offset + 4, weight)
            struct.pack_into("<i", buf, offset + RECYCLE_SIX_STAR_CODE_OFFSET, code)
        changed += len(entries)
    return changed


def apply_gold_cylinder_x10(buf: bytearray) -> int:
    """Makes the Gold Cylinder yield 10x gold per collection.

    The reward base at ``0xA65178`` is ``mov w8, #0x2710`` (10,000).  A single
    ``mov`` cannot encode 100,000, so a 12-byte cave materializes it with
    ``movz``/``movk`` and returns to the next native instruction.
    """
    cave = (
        struct.pack("<I", 0x5290D408) +  # movz w8, #0x86a0
        struct.pack("<I", 0x72A00028) +  # movk w8, #0x1, lsl #16 (100000)
        encode_arm64_branch(
            GOLD_CYLINDER_X10_CAVE_VADDR + 8, GOLD_CYLINDER_X10_RETURN_VADDR
        )
    )
    if len(cave) != GOLD_CYLINDER_X10_CAVE_SIZE:
        raise RuntimeError("Internal Gold Cylinder cave layout error")
    changed = _write_checked_cave(
        buf,
        GOLD_CYLINDER_X10_CAVE_VADDR,
        cave,
        GOLD_CYLINDER_X10_CAVE_ORIGINAL_SHA256,
        label="gold cylinder x10 cave",
    )
    offset = seg_offset(GOLD_CYLINDER_X10_SITE)
    current = bytes(buf[offset:offset + 4])
    replacement = encode_arm64_branch(
        GOLD_CYLINDER_X10_SITE, GOLD_CYLINDER_X10_CAVE_VADDR
    )
    if current == replacement:
        return changed
    if current != GOLD_CYLINDER_X10_ORIGINAL:
        raise ValueError(
            f"Unexpected Gold Cylinder base at 0x{GOLD_CYLINDER_X10_SITE:x}: "
            f"{current.hex()} (expected {GOLD_CYLINDER_X10_ORIGINAL.hex()} or "
            f"{replacement.hex()})"
        )
    _write_bytes(buf, offset, replacement, "gold cylinder x10 hook")
    return changed + 1


def apply_mana_cylinder_x10(buf: bytearray) -> int:
    """Makes the Mana Stone Compactor yield 10x mana per charge.

    The native reward base is ``level * 20 + 60`` at ``0xA65868``/``0xA6586C``;
    both immediates fit in a single ``mov`` after scaling.
    """
    changed = 0
    for address, original, replacement in MANA_CYLINDER_X10_SITES:
        offset = seg_offset(address)
        current = struct.unpack_from("<I", buf, offset)[0]
        if current == replacement:
            continue
        if current != original:
            raise ValueError(
                f"Unexpected Mana Cylinder base at 0x{address:x}: 0x{current:08x} "
                f"(expected 0x{original:08x} or 0x{replacement:08x})"
            )
        struct.pack_into("<I", buf, offset, replacement)
        changed += 1
    return changed


def apply_event_gene_unlimited(buf: bytearray) -> int:
    """Removes the Event Shop gene purchase limit using the 255 sentinel.

    Only flat shop rows whose ``item_category`` is 18 are touched.  The
    replacement keeps the JSON byte length identical, so every rodata reference
    remains valid.  Type 255 is the catalog's "no limit" value; the client
    already uses 255/255 for other unlimited products.
    """
    changed = 0
    seen_rows: set[int] = set()
    cursor = 0
    while True:
        marker = buf.find(EVENT_GENE_ITEM_CATEGORY, cursor)
        if marker < 0:
            break
        row_start = buf.rfind(b"{", 0, marker)
        row_end = buf.find(b"}", marker)
        if row_start < 0 or row_end < 0:
            raise ValueError("Malformed Event Shop row while patching gene limits")
        if row_start not in seen_rows:
            seen_rows.add(row_start)
            match = EVENT_GENE_LIMIT_PATTERN.search(buf, row_start, row_end + 1)
            if match is not None:
                if len(match.group(0)) != len(EVENT_GENE_LIMIT_REPLACEMENT):
                    raise ValueError(
                        "Event Shop gene limit row has a non-canonical length "
                        f"({len(match.group(0))} bytes, expected "
                        f"{len(EVENT_GENE_LIMIT_REPLACEMENT)}); refusing to resize the "
                        "embedded catalog"
                    )
                _write_bytes(
                    buf,
                    match.start(),
                    EVENT_GENE_LIMIT_REPLACEMENT,
                    "event gene limit",
                )
                changed += 1
        cursor = marker + len(EVENT_GENE_ITEM_CATEGORY)
    return changed


def _event_shop_count_cave_bytes() -> bytes:
    """Hook body for ``shop_buy_count_for_code`` (event-shop counters)."""
    blob = bytes.fromhex(
        "280440391fd9007101010054280840391fe5007101020054280c40391fe50071"
        "a10100540a000014280440391fdd007121010054280840391fc10071c1000054"
        "280c40391fcd007161000054000080d23a2ff517f30301aaf40300aaf92ef517"
    )
    if len(blob) != EVENT_LIMIT_COUNT_CAVE_SIZE:
        raise RuntimeError("Internal event shop count cave layout error")
    return blob


def apply_event_limits_daily(buf: bytearray) -> int:
    """Converts event-limited shop rows (limit_type 3 and 4) to daily limits.

    ``limit_type=3`` is the client's "Lifely" period and never resets;
    ``limit_type=4`` is the event/Honor period, which only advances with the
    event cycle.  Setting both to ``1`` keeps ``limit_max`` unchanged and makes
    the same quantity purchasable again after the daily reset.  The replacement
    is byte-length preserving, so the embedded catalog offsets stay valid.
    """
    changed = 0
    for match in EVENT_LIMIT_TYPE_PATTERN.finditer(buf):
        if len(match.group(0)) != len(EVENT_LIMIT_TYPE_REPLACEMENT):
            raise ValueError(
                "Event Shop limit_type row has an unexpected length; refusing to "
                "resize the embedded catalog"
            )
        _write_bytes(
            buf,
            match.start(),
            EVENT_LIMIT_TYPE_REPLACEMENT,
            "event daily limit",
        )
        changed += 1
    for match in EVENT_SHOP_TYPE_4_PATTERN.finditer(buf):
        # The match ends on the period digit; keep the JSON byte length intact.
        _write_bytes(buf, match.end() - 1, b"1", "event daily limit (type 4)")
        changed += 1
    changed += _apply_single_site(
        buf,
        EVENT_LIMIT_PERIOD_SITE,
        EVENT_LIMIT_PERIOD_ORIGINAL,
        encode_arm64_branch(EVENT_LIMIT_PERIOD_SITE, EVENT_LIMIT_PERIOD_TARGET),
        "event daily period key",
    )
    # The lifetime ``shop_buy_counts`` counter is bypassed for event-shop
    # codes (699xx/703xx), so an item that was bought before the reset is not
    # stuck at "limit reached".  Other shops keep their original counters.
    hook = encode_arm64_branch(
        EVENT_LIMIT_COUNT_HOOK_SITE, EVENT_LIMIT_COUNT_CAVE_VADDR
    ) + struct.pack("<I", 0xD503201F)  # nop
    hook_offset = seg_offset(EVENT_LIMIT_COUNT_HOOK_SITE)
    current_hook = bytes(buf[hook_offset:hook_offset + len(hook)])
    if current_hook == EVENT_LIMIT_COUNT_HOOK_ORIGINAL:
        _write_bytes(
            buf,
            hook_offset,
            hook,
            "event shop count hook",
        )
        changed += 1
    elif current_hook != hook:
        raise ValueError(
            "Unexpected event shop count hook contents at "
            f"0x{EVENT_LIMIT_COUNT_HOOK_SITE:x}: {current_hook.hex()}"
        )
    changed += _write_checked_cave(
        buf,
        EVENT_LIMIT_COUNT_CAVE_VADDR,
        _event_shop_count_cave_bytes(),
        EVENT_LIMIT_COUNT_CAVE_ORIGINAL_SHA256,
        label="event shop count cave",
    )
    return changed


def apply_event_coin_x10(buf: bytearray) -> int:
    """Multiplies stage clear event coin drops by 10x using code cave trampoline.

    The common return is 0x8D05C0 (`mov x0, x19`). The old hook at 0x8D05B8
    was only on the string-cleanup path, so it is restored to its original
    branch and the multiplication now happens at the common return path.
    """
    # 1. Restore the old string-cleanup branch if a legacy build modified it.
    old_off = seg_offset(EVENT_COIN_OLD_HOOK_VADDR)
    old_current = bytes(buf[old_off:old_off + 4])
    legacy_old = encode_arm64_branch(EVENT_COIN_OLD_HOOK_VADDR, EVENT_COIN_OLD_CAVE_VADDR)
    if old_current not in (EVENT_COIN_OLD_HOOK_ORIGINAL, legacy_old):
        raise ValueError(
            f"Unexpected instruction at old event coin hook 0x{EVENT_COIN_OLD_HOOK_VADDR:x}: "
            f"{old_current.hex()} (expected {EVENT_COIN_OLD_HOOK_ORIGINAL.hex()})"
        )
    changed = 0
    if old_current != EVENT_COIN_OLD_HOOK_ORIGINAL:
        _write_bytes(buf, old_off, EVENT_COIN_OLD_HOOK_ORIGINAL, "event coin legacy hook")

    # 2. Write trampoline into the free cave at 0xB333DC.
    cave_bytes = (
        struct.pack("<I", 0x52800148) +  # mov w8, #10
        struct.pack("<I", 0x9B087E73) +  # mul x19, x19, x8
        bytes.fromhex("e00313aa") +      # mov x0, x19
        encode_arm64_branch(EVENT_COIN_CAVE_VADDR + 12, EVENT_COIN_RETURN_VADDR)
    )
    if len(cave_bytes) != EVENT_COIN_CAVE_SIZE:
        raise RuntimeError("Internal event coin cave layout error")
    _write_checked_cave(
        buf,
        EVENT_COIN_CAVE_VADDR,
        cave_bytes,
        EVENT_COIN_CAVE_ORIGINAL_SHA256,
        label="event coin cave",
    )

    # 3. Hook the common return path at 0x8D05C0.
    hook_off = seg_offset(EVENT_COIN_HOOK_VADDR)
    replacement = encode_arm64_branch(EVENT_COIN_HOOK_VADDR, EVENT_COIN_CAVE_VADDR)
    current = bytes(buf[hook_off:hook_off + 4])
    original = bytes.fromhex("e00313aa")  # mov x0, x19
    if current not in (original, replacement):
        raise ValueError(
            f"Unexpected instruction at event coin hook 0x{EVENT_COIN_HOOK_VADDR:x}: "
            f"{current.hex()} (expected {original.hex()} or {replacement.hex()})"
        )
    if current != replacement:
        _write_bytes(buf, hook_off, replacement, "event coin hook")
        changed += 1
    return changed


def _apply_single_site(
    buf: bytearray,
    site: int,
    original: bytes,
    replacement: bytes,
    label: str,
) -> int:
    """Applies an idempotent four-byte server-site replacement."""
    offset = seg_offset(site)
    current = bytes(buf[offset:offset + len(replacement)])
    if current not in (original, replacement):
        raise ValueError(
            f"Unexpected instruction at {label} site 0x{site:x}: "
            f"{current.hex()} (expected {original.hex()} or {replacement.hex()})"
        )
    if current == replacement:
        return 0
    _write_bytes(buf, offset, replacement, f"{label} site")
    return 1


def apply_single_black_hammer(buf: bytearray) -> int:
    """Makes +16..+26 transcendence use one black hammer per attempt.

    The native server uses item 130006 for levels 15..19 and computes the
    count as ``level - 14``; levels 20..25 already use one item 130027.
    The patched instruction forces the first range to one as well.
    """
    return _apply_single_site(
        buf,
        SINGLE_BLACK_HAMMER_SITE,
        SINGLE_BLACK_HAMMER_ORIGINAL,
        SINGLE_BLACK_HAMMER_REPLACEMENT,
        "single black hammer",
    )


def apply_high_upgrade_no_fail(buf: bytearray) -> int:
    """Makes equipment transcendence attempts above +20 always succeed.

    The native table at ``0x6BAE64`` drives the success percentage for the
    infinite-transcend path: +21 uses 100%, then 90/80/70/60/50 for the
    following levels.  Every entry becomes 100 so the failure branch and the
    insurance-card regression path are never taken.
    """
    offset = INFINITE_TRANSCEND_SUCCESS_TABLE
    values = struct.unpack_from(
        "<6i", buf, offset
    )
    if any(
        current not in (original, patched)
        for current, original, patched in zip(
            values,
            INFINITE_TRANSCEND_SUCCESS_ORIGINAL,
            INFINITE_TRANSCEND_SUCCESS_PATCHED,
            strict=True,
        )
    ):
        raise ValueError(
            f"Unexpected high-level transcend success table at 0x{offset:x}: {values}"
        )
    changed = 0
    for index, target in enumerate(INFINITE_TRANSCEND_SUCCESS_PATCHED):
        if values[index] != target:
            struct.pack_into("<i", buf, offset + index * 4, target)
            changed += 1
    return changed


def apply_devil_boost_x10(buf: bytearray) -> int:
    """Multiplies the Devil's Soul EXP-synthesis boost by ten.

    The native compose path multiplies the summed ingredient EXP by a float
    stored at ``0x6C49D8`` (2.0). The patched value is 20.0, so using a
    Devil's Soul gives ten times the original bonus.
    """
    offset = DEVIL_BOOST_MULTIPLIER_SITE
    current = struct.unpack_from("<f", buf, offset)[0]
    if current == DEVIL_BOOST_MULTIPLIER_PATCHED:
        return 0
    if current != DEVIL_BOOST_MULTIPLIER_ORIGINAL:
        raise ValueError(
            f"Unexpected Devil Boost multiplier at 0x{offset:x}: {current!r}"
        )
    struct.pack_into("<f", buf, offset, DEVIL_BOOST_MULTIPLIER_PATCHED)
    return 1


def apply_gem_mining_x10(buf: bytearray) -> int:
    """Grants 10 gems for paid gem-mining rolls (free rolls stay at 1)."""
    if len(GEM_MINING_CAVE_BYTES) > GEM_MINING_CAVE_SIZE:
        raise RuntimeError("Internal gem mining cave layout error")
    _write_recycle_cave(
        buf,
        GEM_MINING_CAVE_VADDR,
        GEM_MINING_CAVE_BYTES,
        GEM_MINING_CAVE_ORIGINAL_SHA256,
    )
    offset = seg_offset(GEM_MINING_COUNT_SITE)
    replacement = encode_arm64_branch(
        GEM_MINING_COUNT_SITE, GEM_MINING_CAVE_VADDR, link=True
    )
    current = bytes(buf[offset:offset + 4])
    if current == replacement:
        return 0
    if current != GEM_MINING_COUNT_ORIGINAL:
        raise ValueError(
            f"Unexpected gem mining count site at 0x{GEM_MINING_COUNT_SITE:x}: "
            f"{current.hex()} (expected {GEM_MINING_COUNT_ORIGINAL.hex()} or "
            f"{replacement.hex()})"
        )
    buf[offset:offset + 4] = replacement
    return 1


def apply_gem_mining_types(buf: bytearray) -> int:
    """Restricts gem-mining rolls to the non-premium gem types.

    The level-1 gem table has nine attributes (1..9).  HP/ATK/DEF/CRIT
    (1/3/4/5) are sold directly in the Special Beginner Package, so the roll is
    remapped to attributes 2/6/7/8/9 (MP, Counter Rate, Counter Damage, Dodge
    and Hit Rate).
    """
    if len(GEM_MINING_TYPES_CAVE_BYTES) > GEM_MINING_TYPES_CAVE_SIZE:
        raise RuntimeError("Internal gem mining type cave layout error")
    changed = _write_recycle_cave(
        buf,
        GEM_MINING_TYPES_CAVE_VADDR,
        GEM_MINING_TYPES_CAVE_BYTES,
        GEM_MINING_TYPES_CAVE_ORIGINAL_SHA256,
    )
    offset = seg_offset(GEM_MINING_TYPES_HOOK)
    replacement = encode_arm64_branch(
        GEM_MINING_TYPES_HOOK, GEM_MINING_TYPES_CAVE_VADDR
    )
    current = bytes(buf[offset:offset + 4])
    if current == replacement:
        return changed
    if current != GEM_MINING_TYPES_ORIGINAL:
        raise ValueError(
            f"Unexpected gem mining type site at 0x{GEM_MINING_TYPES_HOOK:x}: "
            f"{current.hex()} (expected {GEM_MINING_TYPES_ORIGINAL.hex()} or "
            f"{replacement.hex()})"
        )
    buf[offset:offset + 4] = replacement
    return changed + 1


def apply_gem_level6(buf: bytearray) -> int:
    """Makes the lobby gem table hand out level-6 gem codes.

    The nine level-1 gem codes ("16781" .. "96781") are patched in place to
    their level-6 counterparts ("16786" .. "96786"); the gem level is the last
    digit of the code, so the attribute (first digit) is preserved.
    """
    changed = 0
    for addr in GEM_LEVEL6_STRINGS:
        offset = addr  # .rodata: vaddr == file offset
        current = bytes(buf[offset:offset + 5])
        if (
            len(current) != 5
            or current[1:4] != b"678"
            or not 0x31 <= current[0] <= 0x39
            or current[4:5] not in (GEM_LEVEL6_ORIGINAL_CHAR, GEM_LEVEL6_REPLACEMENT_CHAR)
        ):
            raise ValueError(
                f"Unexpected gem level table string at 0x{addr:x}: {current!r}"
            )
        if current[4:5] == GEM_LEVEL6_ORIGINAL_CHAR:
            _write_bytes(buf, offset + 4, GEM_LEVEL6_REPLACEMENT_CHAR, "gem level")
            changed += 1
    return changed


def apply_gem_upgrade_gold_half(buf: bytearray) -> int:
    """Halves the gold fee charged by REQ_GEM_GRAFTING."""
    return _apply_single_site(
        buf,
        GEM_UPGRADE_GOLD_SITE,
        GEM_UPGRADE_GOLD_ORIGINAL,
        GEM_UPGRADE_GOLD_REPLACEMENT,
        "gem upgrade gold",
    )


def _single_gem_fang_cave_bytes() -> bytes:
    """Builds the startup hook that relaxes the client-side Dragon Fang gate."""
    cave = SINGLE_GEM_FANG_CAVE_VADDR
    data_expected = cave + 0x44
    data_replacement = cave + 0x48
    code = bytearray()
    code += encode_sub_sp(0x30)
    code += encode_stp_sp(29, 30, 0x20)
    code += encode_stp_sp(19, 20, 0x10)
    code += encode_adrp(cave + len(code), 0xBE3000, 8)
    code += encode_ldr_x(0, 8, 0x798)
    code += encode_movz_w(1, SINGLE_GEM_FANG_CLIENT_SITE & 0xFFFF)
    code += encode_movk_w(1, (SINGLE_GEM_FANG_CLIENT_SITE >> 16) & 0xFFFF, 16)
    code += encode_adr(cave + len(code), data_expected, 2)
    code += encode_adr(cave + len(code), data_replacement, 3)
    code += encode_movz_w(4, 1)  # patch_words counts words, not bytes
    code += encode_add_imm(5, 31, 0x28)
    code += encode_arm64_branch(cave + len(code), 0xAB575C, link=True)
    code += encode_ldp_sp(19, 20, 0x10)
    code += encode_ldp_sp(29, 30, 0x20)
    code += encode_add_sp(0x30)
    code += encode_ldp_sp(22, 21, 0x40)  # original instruction at the hook site
    code += encode_arm64_branch(cave + len(code), SINGLE_GEM_FANG_INSTALL_RETURN)
    assert len(code) == 0x44, len(code)
    code += SINGLE_GEM_FANG_CLIENT_ORIGINAL
    code += encode_arm64_branch(SINGLE_GEM_FANG_CLIENT_SITE, 0x1DCAD7C)
    return bytes(code)


SINGLE_GEM_FANG_CAVE_BYTES = _single_gem_fang_cave_bytes()


def _single_gem_fang_all_holes_cave_bytes() -> bytes:
    """Builds the server cave unlocking holes 1..3 cleanly for 1 Dragon Fang."""
    cave = SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR
    code = bytearray()
    code += bytes.fromhex("fd7bbda9")  # stp x29, x30, [sp, #-0x30]!
    code += bytes.fromhex("fd030091")  # mov x29, sp
    code += bytes.fromhex("f35301a9")  # stp x19, x20, [sp, #0x10]
    code += bytes.fromhex("f51300f9")  # str x21, [sp, #0x20]
    code += bytes.fromhex("f40303aa")  # mov x20, x3 (std::function functor&)
    code += bytes.fromhex("33008052")  # mov w19, #1 (hole_pos = 1..3)
    code += bytes.fromhex("35008052")  # mov w21, #1 (ok accumulator)
    loop_va = cave + len(code)
    code += bytes.fromhex("e00316aa")  # mov x0, x22 (state_text&)
    code += bytes.fromhex("e10318aa")  # mov x1, x24 (equipment_seq)
    code += bytes.fromhex("e203132a")  # mov w2, w19 (hole_pos)
    code += bytes.fromhex("e30314aa")  # mov x3, x20 (functor&)
    code += bytes.fromhex("24008052")  # mov w4, #1  (create_if_missing = true)
    code += encode_arm64_branch(
        cave + len(code), SINGLE_GEM_FANG_ALL_HOLES_TARGET, link=True
    )
    code += bytes.fromhex("b502000a")  # and w21, w21, w0
    code += bytes.fromhex("73060011")  # add w19, w19, #1
    code += bytes.fromhex("7f120071")  # cmp w19, #4
    imm19 = ((loop_va - (cave + len(code))) >> 2) & 0x7FFFF
    code += struct.pack("<I", 0x54000003 | (imm19 << 5))  # b.lo loop_va
    code += bytes.fromhex("e003152a")  # mov w0, w21
    code += bytes.fromhex("f51340f9")  # ldr x21, [sp, #0x20]
    code += bytes.fromhex("f35341a9")  # ldp x19, x20, [sp, #0x10]
    code += bytes.fromhex("fd7bc3a8")  # ldp x29, x30, [sp], #0x30
    code += bytes.fromhex("c0035fd6")  # ret
    assert len(code) == SINGLE_GEM_FANG_ALL_HOLES_CAVE_SIZE, len(code)
    return bytes(code)


SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES = _single_gem_fang_all_holes_cave_bytes()


def _single_mod_stone_cave_bytes() -> bytes:
    """Builds the startup hook that forces the option-change cost to one stone."""
    cave = SINGLE_MOD_STONE_CAVE_VADDR
    data_expected = cave + 0x44
    data_replacement = cave + 0x48
    code = bytearray()
    code += encode_sub_sp(0x30)
    code += encode_stp_sp(29, 30, 0x20)
    code += encode_stp_sp(19, 20, 0x10)
    code += encode_adrp(cave + len(code), 0xBE3000, 8)
    code += encode_ldr_x(0, 8, 0x798)
    code += encode_movz_w(1, SINGLE_MOD_STONE_CLIENT_SITE & 0xFFFF)
    code += encode_movk_w(1, (SINGLE_MOD_STONE_CLIENT_SITE >> 16) & 0xFFFF, 16)
    code += encode_adr(cave + len(code), data_expected, 2)
    code += encode_adr(cave + len(code), data_replacement, 3)
    code += encode_movz_w(4, 1)  # patch_words counts words, not bytes
    code += encode_add_imm(5, 31, 0x28)
    code += encode_arm64_branch(cave + len(code), 0xAB575C, link=True)
    code += encode_ldp_sp(19, 20, 0x10)
    code += encode_ldp_sp(29, 30, 0x20)
    code += encode_add_sp(0x30)
    code += encode_ldp_sp(24, 23, 0x30)  # original instruction at the hook site
    code += encode_arm64_branch(cave + len(code), SINGLE_MOD_STONE_INSTALL_RETURN)
    assert len(code) == 0x44, len(code)
    code += SINGLE_MOD_STONE_CLIENT_ORIGINAL
    code += SINGLE_MOD_STONE_CLIENT_REPLACEMENT
    return bytes(code)


SINGLE_MOD_STONE_CAVE_BYTES = _single_mod_stone_cave_bytes()


def apply_equipment_upgrade_10_guarantee(buf: bytearray) -> int:
    """Makes the +9 -> +10 gradeup roll always succeed.

    ``EquipmentGradeupStateAccess::gradeup`` passes the fail-probability entry
    for the current enchant level to ``deterministic_success_roll_...``.  With
    fail = 0 the roll returns 1 before hashing, so only the +9 -> +10 step is
    forced; the other levels keep their stock probabilities.
    """
    offset = seg_offset(EQUIPMENT_UPGRADE_10_FAIL_SITE)
    current = bytes(buf[offset:offset + 8])
    if current == EQUIPMENT_UPGRADE_10_FAIL_REPLACEMENT:
        return 0
    if current != EQUIPMENT_UPGRADE_10_FAIL_ORIGINAL:
        raise ValueError(
            f"Unexpected +10 fail probability at "
            f"0x{EQUIPMENT_UPGRADE_10_FAIL_SITE:x}: {current.hex()}"
        )
    buf[offset:offset + 8] = EQUIPMENT_UPGRADE_10_FAIL_REPLACEMENT
    return 1


def apply_equipment_percent_options(buf: bytearray) -> int:
    """Zeros every flat equipment-option weight and closes the picker fallback.

    ``fwt_randoption_rows`` is the table the offline server uses for option
    rolls. Zeroing the six grade weights of direct and scaled flat rows
    (client value types 1 and 4) leaves only percentage rows (type 2).
    A pool whose
    rows are all flat would still be served by the picker's zero-weight
    fallback, so that branch is rewritten as well.
    """
    table_offset = seg_offset(RANDOPTION_SERVER_SITE)
    changed = 0
    for index in range(RANDOPTION_SERVER_ROW_COUNT):
        row_offset = table_offset + index * RANDOPTION_SERVER_ROW_SIZE
        if len(buf) < row_offset + RANDOPTION_SERVER_ROW_SIZE:
            raise ValueError("randoption table is truncated")
        (option_id,) = struct.unpack_from("<I", buf, row_offset)
        if option_id // 1000 not in RANDOPTION_SERVER_FLAT_GROUPS:
            continue
        for grade in range(RANDOPTION_SERVER_GRADE_COUNT):
            weight_offset = (
                row_offset + RANDOPTION_SERVER_WEIGHT_OFFSET + grade * 4
            )
            (weight,) = struct.unpack_from("<I", buf, weight_offset)
            if weight:
                struct.pack_into("<I", buf, weight_offset, 0)
                changed += 1
    changed += _apply_single_site(
        buf,
        RANDOPTION_FALLBACK_SITE,
        RANDOPTION_FALLBACK_ORIGINAL,
        RANDOPTION_FALLBACK_REPLACEMENT,
        "randoption zero-weight fallback",
    )
    return changed


def apply_equipment_single_mod_stone(buf: bytearray) -> int:
    """Charges one Modification Stone per option change, regardless of locks.

    The server helper at 0x8A4DC8 used to return 1/2/4 stones for 0-1/2/3
    locked lines.  The client GUI repeats that formula for its cost label and
    inventory check; a post-covault hook rewrites the lock-count argument so
    both sides agree on one stone.
    """
    changed = _apply_single_site(
        buf,
        SINGLE_MOD_STONE_SERVER_SITE,
        SINGLE_MOD_STONE_SERVER_ORIGINAL,
        SINGLE_MOD_STONE_SERVER_REPLACEMENT,
        "single modification stone",
    )
    cave_offset = seg_offset(SINGLE_MOD_STONE_CAVE_VADDR)
    if len(buf) >= cave_offset + SINGLE_MOD_STONE_CAVE_SIZE:
        current = bytes(buf[cave_offset:cave_offset + SINGLE_MOD_STONE_CAVE_SIZE])
        if current != SINGLE_MOD_STONE_CAVE_BYTES:
            digest = hashlib.sha256(current).hexdigest()
            if digest != SINGLE_MOD_STONE_CAVE_ORIGINAL_SHA256:
                raise ValueError(
                    f"Unexpected single mod stone cave at "
                    f"0x{SINGLE_MOD_STONE_CAVE_VADDR:x}: sha256={digest}"
                )
            _write_bytes(
                buf,
                cave_offset,
                SINGLE_MOD_STONE_CAVE_BYTES,
                "single mod stone cave",
            )
            changed += 1
        site_offset = seg_offset(SINGLE_MOD_STONE_INSTALL_SITE)
        replacement = encode_arm64_branch(
            SINGLE_MOD_STONE_INSTALL_SITE, SINGLE_MOD_STONE_CAVE_VADDR
        )
        current_site = bytes(buf[site_offset:site_offset + 4])
        if current_site not in (SINGLE_MOD_STONE_INSTALL_ORIGINAL, replacement):
            raise ValueError(
                f"Unexpected single mod stone install site "
                f"0x{SINGLE_MOD_STONE_INSTALL_SITE:x}: {current_site.hex()}"
            )
        if current_site != replacement:
            buf[site_offset:site_offset + 4] = replacement
            changed += 1
    return changed


def apply_single_gem_fang(buf: bytearray) -> int:
    """Sets Dragon Fang cost to 1 and unlocks all 3 gem slots at once.

    Patches the server charge site, hooks ``GemStateAccess::mutate_equipment_hole``
    to open slots 1..3 in one request while preserving existing sockets, and installs
    a startup hook relaxing the client-side ``OnDragonFangButtonPressed`` bag check.
    """
    changed = _apply_single_site(
        buf,
        SINGLE_GEM_FANG_SITE,
        SINGLE_GEM_FANG_ORIGINAL,
        SINGLE_GEM_FANG_REPLACEMENT,
        "single gem fang",
    )
    holes_cave_offset = seg_offset(SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR)
    if len(buf) >= holes_cave_offset + SINGLE_GEM_FANG_ALL_HOLES_CAVE_SIZE:
        current_holes_cave = bytes(
            buf[holes_cave_offset:holes_cave_offset + SINGLE_GEM_FANG_ALL_HOLES_CAVE_SIZE]
        )
        if current_holes_cave != SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES:
            digest = hashlib.sha256(current_holes_cave).hexdigest()
            if digest != SINGLE_GEM_FANG_ALL_HOLES_CAVE_ORIGINAL_SHA256:
                raise ValueError(
                    f"Unexpected single gem fang all-holes cave at "
                    f"0x{SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR:x}: sha256={digest}"
                )
            _write_bytes(
                buf,
                holes_cave_offset,
                SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES,
                "single gem fang all-holes cave",
            )
            changed += 1
        holes_hook = encode_arm64_branch(
            SINGLE_GEM_FANG_ALL_HOLES_SITE,
            SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR,
            link=True,
        )
        changed += _apply_single_site(
            buf,
            SINGLE_GEM_FANG_ALL_HOLES_SITE,
            SINGLE_GEM_FANG_ALL_HOLES_ORIGINAL,
            holes_hook,
            "single gem fang all-holes call",
        )
    cave_offset = seg_offset(SINGLE_GEM_FANG_CAVE_VADDR)
    if len(buf) >= cave_offset + SINGLE_GEM_FANG_CAVE_SIZE:
        current = bytes(buf[cave_offset:cave_offset + SINGLE_GEM_FANG_CAVE_SIZE])
        if current != SINGLE_GEM_FANG_CAVE_BYTES:
            digest = hashlib.sha256(current).hexdigest()
            if digest != SINGLE_GEM_FANG_CAVE_ORIGINAL_SHA256:
                raise ValueError(
                    f"Unexpected single gem fang cave at "
                    f"0x{SINGLE_GEM_FANG_CAVE_VADDR:x}: sha256={digest}"
                )
            _write_bytes(
                buf,
                cave_offset,
                SINGLE_GEM_FANG_CAVE_BYTES,
                "single gem fang cave",
            )
            changed += 1
        site_offset = seg_offset(SINGLE_GEM_FANG_INSTALL_SITE)
        replacement = encode_arm64_branch(
            SINGLE_GEM_FANG_INSTALL_SITE, SINGLE_GEM_FANG_CAVE_VADDR
        )
        current_site = bytes(buf[site_offset:site_offset + 4])
        if current_site not in (SINGLE_GEM_FANG_INSTALL_ORIGINAL, replacement):
            raise ValueError(
                f"Unexpected single gem fang install site "
                f"0x{SINGLE_GEM_FANG_INSTALL_SITE:x}: {current_site.hex()}"
            )
        if current_site != replacement:
            buf[site_offset:site_offset + 4] = replacement
            changed += 1
    return changed


def apply_select_all_4_5(buf: bytearray) -> int:
    """Installs the runtime client hooks that include 4★/5★ in Select All.

    The client library is decrypted by AppSealing at startup.  The existing
    ``patch_words`` flow in ``libfwt_local_server.so`` installs a 16-byte
    trampoline at client RVA ``0x1CE93F8``.  The hook accepts grades 4 and 5
    when the popup's Select All flag is set and resumes ``BlockSelect``.  A
    second patch at ``0x1CE9420`` routes quality-4/5 items into the Epic
    quality bucket so the quality filter does not discard them.
    """
    cave_offset = seg_offset(SELECT_ALL_CLIENT_CAVE)
    current_cave = bytes(
        buf[cave_offset:cave_offset + SELECT_ALL_CAVE_RESERVED_SIZE]
    )
    patched_cave = SELECT_ALL_CLIENT_CAVE_BYTES + b"\x00" * (
        SELECT_ALL_CAVE_RESERVED_SIZE - len(SELECT_ALL_CLIENT_CAVE_BYTES)
    )
    stub_offset = seg_offset(SELECT_ALL_STUB_VADDR)
    current_stub = bytes(
        buf[stub_offset:stub_offset + len(SELECT_ALL_GRADE_STUB_BYTES)]
    )
    site_offset = seg_offset(SELECT_ALL_INSTALL_SITE)
    replacement = encode_arm64_branch(SELECT_ALL_INSTALL_SITE, SELECT_ALL_CLIENT_CAVE)
    current_site = bytes(buf[site_offset:site_offset + 4])

    if current_cave != patched_cave:
        cave_digest = hashlib.sha256(current_cave).hexdigest()
        if cave_digest != SELECT_ALL_CAVE_ORIGINAL_SHA256:
            raise ValueError(
                f"Unexpected Select All cave contents at 0x{SELECT_ALL_CLIENT_CAVE:x}: "
                f"sha256={cave_digest}"
            )
    if current_stub != SELECT_ALL_GRADE_STUB_BYTES:
        stub_digest = hashlib.sha256(current_stub).hexdigest()
        if stub_digest != SELECT_ALL_STUB_ORIGINAL_SHA256:
            raise ValueError(
                f"Unexpected Select All grade stub at 0x{SELECT_ALL_STUB_VADDR:x}: "
                f"sha256={stub_digest}"
            )
    if current_site not in (SELECT_ALL_INSTALL_ORIGINAL, replacement):
        raise ValueError(
            f"Unexpected Select All installer site 0x{SELECT_ALL_INSTALL_SITE:x}: "
            f"{current_site.hex()} (expected {SELECT_ALL_INSTALL_ORIGINAL.hex()} "
            f"or {replacement.hex()})"
        )

    changed = 0
    if current_cave != patched_cave:
        _write_bytes(buf, cave_offset, patched_cave, "Select All client cave")
        changed += 1
    if current_stub != SELECT_ALL_GRADE_STUB_BYTES:
        _write_bytes(
            buf,
            stub_offset,
            SELECT_ALL_GRADE_STUB_BYTES,
            "Select All grade stub",
        )
        changed += 1
    if current_site != replacement:
        _write_bytes(buf, site_offset, replacement, "Select All installer")
        changed += 1
    return changed


def apply_battle_arena_save_fix(buf: bytearray) -> int:
    """Installs the client hook that makes the Battle Arena team Save work.

    The cave runs from the epilogue of the covault permission-finalization
    function (0xAB337C), i.e. *after* AppSealing has sealed the client code
    pages, reads the cached libil2cpp base from 0xBE3798 and patches client RVA
    0x1AA6FCC (``csel x8, x20, xzr, eq`` -> ``mov x8, x20``) so
    ``ArenaAttackTeamListGUIInInventory.Init`` always stores its team manager.
    """
    cave_offset = seg_offset(BATTLE_ARENA_SAVE_CAVE_VADDR)
    current_cave = bytes(
        buf[cave_offset:cave_offset + len(BATTLE_ARENA_SAVE_CAVE_BYTES)]
    )
    changed = 0
    if current_cave != BATTLE_ARENA_SAVE_CAVE_BYTES:
        if (
            hashlib.sha256(current_cave).hexdigest()
            != BATTLE_ARENA_SAVE_CAVE_ORIGINAL_SHA256
        ):
            raise ValueError(
                f"Unexpected Battle Arena cave contents at "
                f"0x{BATTLE_ARENA_SAVE_CAVE_VADDR:x}: "
                f"sha256={hashlib.sha256(current_cave).hexdigest()}"
            )
        _write_bytes(
            buf,
            cave_offset,
            BATTLE_ARENA_SAVE_CAVE_BYTES,
            "Battle Arena save cave",
        )
        changed += 1

    site_offset = seg_offset(BATTLE_ARENA_SAVE_LATE_SITE)
    replacement = encode_arm64_branch(
        BATTLE_ARENA_SAVE_LATE_SITE, BATTLE_ARENA_SAVE_CAVE_VADDR
    )
    current_site = bytes(buf[site_offset:site_offset + 4])
    if current_site not in (BATTLE_ARENA_SAVE_LATE_ORIGINAL, replacement):
        raise ValueError(
            f"Unexpected Battle Arena late site "
            f"0x{BATTLE_ARENA_SAVE_LATE_SITE:x}: {current_site.hex()} "
            f"(expected {BATTLE_ARENA_SAVE_LATE_ORIGINAL.hex()} or "
            f"{replacement.hex()})"
        )
    if current_site != replacement:
        buf[site_offset:site_offset + 4] = replacement
        changed += 1
    return 1 if changed else 0


def apply_limit_break_cost_tenth(buf: bytearray) -> int:
    """Cuts both the gold and the material cost of all 45 limit-break rows to a tenth.

    Every cell in the reference table is a multiple of ten, so the discount is exact.
    Both the affordability check and the charge in ``CREATURE_TRANSCEND`` read these
    same cells. During APK repacking, ``core.apk_tooling`` divides the client's bundled
    ``limitbreakcost.unity3d`` table by ten to match so the Awake UI and button gate
    agree with the server cost.
    """
    table_offset = LIMIT_BREAK_GOLD_TABLE
    table_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
    current = bytes(buf[table_offset:table_offset + table_size])
    digest, step_mode = inspect_limit_break_table(current)
    if step_mode == "unknown":
        raise ValueError(
            f"Unexpected limit break cost table at 0x{LIMIT_BREAK_GOLD_TABLE:x}: "
            f"sha256={digest} (the tenth patch only applies to the stock table)"
        )
    if digest == LIMIT_BREAK_COST_TENTH_SHA256:
        return 0
    if digest == LIMIT_BREAK_COST_FIXED_SHA256:
        return 0
    if digest != LIMIT_BREAK_GOLD_TABLE_ORIGINAL_SHA256:
        raise ValueError(
            f"Unexpected limit break cost table at 0x{LIMIT_BREAK_GOLD_TABLE:x}: "
            f"sha256={digest} (the tenth patch only applies to the stock table)"
        )

    changed = 0
    for index in range(LIMIT_BREAK_GOLD_ROWS):
        row_offset = table_offset + index * LIMIT_BREAK_GOLD_ROW_SIZE
        for field_offset in (
            LIMIT_BREAK_MATERIAL_FIELD_OFFSET,
            LIMIT_BREAK_GOLD_FIELD_OFFSET,
        ):
            offset = row_offset + field_offset
            value = struct.unpack_from("<i", buf, offset)[0]
            if value <= 0 or value % 10:
                raise ValueError(
                    f"Row {index} field {field_offset} is {value}; a tenth off needs a "
                    f"positive multiple of ten"
                )
            struct.pack_into("<i", buf, offset, value // 10)
        changed += 1
    return changed


def apply_limit_break_cost_fixed(buf: bytearray) -> int:
    """Charges a flat 1,000,000 gold and 100 materials for every hero limit break.

    ``kFwtCreatureLimitBreakCosts`` prices each level step separately, so the last
    steps cost 190,000,000 gold and 17,380 materials even after a percentage
    discount.  Writing the same price into all 45 rows stops the cost from growing
    with the level.  Both the affordability check and the charge in
    ``CREATURE_TRANSCEND`` read these cells, and ``core.apk_tooling`` writes the
    same pair into the client's bundled ``limitbreakcost.unity3d`` so the Awake
    screen and its button gate agree.

    Discount profiles that ran first (gold half, cost half, 90% off) are
    overwritten: the flat price always wins, and a second pass is a no-op.
    """
    table_offset = LIMIT_BREAK_GOLD_TABLE
    table_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
    current = bytes(buf[table_offset:table_offset + table_size])
    digest, step_mode = inspect_limit_break_table(current)
    if step_mode == "unknown":
        raise ValueError(
            f"Unexpected limit break cost table at 0x{LIMIT_BREAK_GOLD_TABLE:x}: "
            f"sha256={digest}"
        )
    if digest == LIMIT_BREAK_COST_FIXED_SHA256:
        return 0
    if digest not in (
        LIMIT_BREAK_GOLD_TABLE_ORIGINAL_SHA256,
        LIMIT_BREAK_GOLD_TABLE_PATCHED_SHA256,
        LIMIT_BREAK_COST_TABLE_PATCHED_SHA256,
        LIMIT_BREAK_COST_TENTH_SHA256,
    ):
        raise ValueError(
            f"Unexpected limit break cost table at 0x{LIMIT_BREAK_GOLD_TABLE:x}: "
            f"sha256={digest}"
        )

    changed = 0
    for index in range(LIMIT_BREAK_GOLD_ROWS):
        row_offset = table_offset + index * LIMIT_BREAK_GOLD_ROW_SIZE
        category = struct.unpack_from("<i", buf, row_offset + 8)[0]
        if category != LIMIT_BREAK_ITEM_CATEGORY:
            raise ValueError(
                f"Unexpected limit break material category at row {index}: {category}"
            )
        struct.pack_into(
            "<i", buf, row_offset + LIMIT_BREAK_MATERIAL_FIELD_OFFSET, LIMIT_BREAK_FIXED_MATERIAL
        )
        struct.pack_into(
            "<i", buf, row_offset + LIMIT_BREAK_GOLD_FIELD_OFFSET, LIMIT_BREAK_FIXED_GOLD
        )
        changed += 1
    post_digest, _ = inspect_limit_break_table(
        bytes(buf[table_offset:table_offset + table_size])
    )
    if post_digest != LIMIT_BREAK_COST_FIXED_SHA256:
        raise ValueError("Limit break table differs from the verified flat profile")
    return changed


def apply_limit_break_step_10(buf: bytearray) -> int:
    """Opens +10 levels per hero limit break up to Lv 120 (70->80->90->100->110->120).

    Updates the ``level_after`` column (+4) in all 45 rows of
    ``kFwtCreatureLimitBreakCosts`` so any hero at level ``level_before`` advances to
    ``min(120, ((level_before // 10) + 1) * 10)``.  Orthogonal to any gold/material
    cost profile and idempotent across repeated invocations.
    """
    table_offset = LIMIT_BREAK_GOLD_TABLE
    table_size = LIMIT_BREAK_GOLD_ROW_SIZE * LIMIT_BREAK_GOLD_ROWS
    current = bytes(buf[table_offset:table_offset + table_size])
    digest, step_mode = inspect_limit_break_table(current)
    if step_mode == "unknown" or digest not in _LIMIT_BREAK_KNOWN_COST_DIGESTS:
        raise ValueError(
            f"Unexpected limit break cost table at 0x{LIMIT_BREAK_GOLD_TABLE:x}: "
            f"sha256={digest}, step_mode={step_mode}"
        )
    if step_mode == "step_10":
        return 0

    changed = 0
    for index in range(LIMIT_BREAK_GOLD_ROWS):
        row_offset = table_offset + index * LIMIT_BREAK_GOLD_ROW_SIZE
        level_before = struct.unpack_from("<i", buf, row_offset)[0]
        target_after = limit_break_step10_target(level_before)
        struct.pack_into(
            "<i", buf, row_offset + LIMIT_BREAK_AFTER_FIELD_OFFSET, target_after
        )
        changed += 1
    return changed


def apply_coocoo_exp_x2(buf: bytearray) -> int:
    """Keeps the x2 EXP bonus active for every SUMEXP_CREATURE request."""
    return _apply_single_site(
        buf,
        COOCOO_EXP_X2_SITE,
        COOCOO_EXP_X2_ORIGINAL,
        COOCOO_EXP_X2_REPLACEMENT,
        "coocoo EXP x2",
    )


def apply_coocoo_level_x2(buf: bytearray) -> int:
    """Doubles the dropped coocoo level in all 30 coocoo reward stages."""
    changed = 0
    for index, original in enumerate(COOCOO_STAGE_LEVELS):
        row_offset = COOCOO_STAGE_TABLE_OFFSET + index * COOCOO_STAGE_ROW_SIZE
        level_offset = row_offset + COOCOO_STAGE_LEVEL_OFFSET
        level_min, level_max = struct.unpack_from("<2i", buf, level_offset)
        if level_min == original and level_max == original:
            struct.pack_into("<2i", buf, level_offset, original * 2, original * 2)
            changed += 1
        elif level_min == original * 2 and level_max == original * 2:
            continue
        else:
            raise ValueError(
                "Unexpected Coocoo Garden level at row "
                f"{index}: {level_min}/{level_max} (expected {original})"
            )
    return changed


def apply_worldboss_full_ship_repair(buf: bytearray) -> int:
    """Restore maximum ship HP through the stock repair paths."""
    pending = []
    for site, original, replacement in WORLDBOSS_FULL_SHIP_REPAIR_SITES:
        offset = seg_offset(site)
        current = bytes(buf[offset:offset + len(original)])
        if current == replacement:
            continue
        if current != original:
            raise ValueError(f"Unexpected ship repair instruction at 0x{site:x}")
        pending.append((offset, replacement))
    for offset, replacement in pending:
        _write_bytes(buf, offset, replacement, "full ship repair")
    return len(pending)


def apply_ship_parts_90_off(buf: bytearray) -> int:
    """Applies a 90% discount to the Unknown Paradise battleship part gold upgrade costs."""
    changed = 0
    for table_offset, values in SHIP_PART_COST_TABLES:
        for index, original in enumerate(values):
            field_offset = table_offset + index * SHIP_PART_COST_FIELD_SIZE
            current = struct.unpack_from("<q", buf, field_offset)[0]
            if original == 0:
                if current != 0:
                    raise ValueError(
                        "Unexpected battleship part cost padding at "
                        f"0x{field_offset:x}: {current} (expected 0)"
                    )
                continue
            discounted = max(1, (original + 9) // 10)
            if current == original:
                struct.pack_into("<q", buf, field_offset, discounted)
                changed += 1
            elif current == discounted:
                continue
            else:
                raise ValueError(
                    "Unexpected battleship part cost at "
                    f"0x{field_offset:x}: {current} (expected {original})"
                )
    return changed


# Backwards-compatible alias from when the patch halved costs (raised to 90% in 2.5.5).
apply_ship_parts_half = apply_ship_parts_90_off


def apply_crystal_skill_90_off(buf: bytearray) -> int:
    """Charges 5 Kraken Scales instead of 50 per crystal skill upgrade."""
    return _apply_single_site(
        buf,
        CRYSTAL_SKILL_COST_SITE,
        CRYSTAL_SKILL_COST_ORIGINAL,
        CRYSTAL_SKILL_COST_REPLACEMENT,
        "crystal skill cost",
    )


def apply_stamina_cost_half(buf: bytearray) -> int:
    """Halves the stamina deducted by BattleSecondStartStateAccess::charge."""
    return _apply_single_site(
        buf,
        STAMINA_HALF_SITE,
        STAMINA_HALF_ORIGINAL,
        STAMINA_HALF_REPLACEMENT,
        "dungeon stamina half",
    )


def apply_stamina_potion_1000(buf: bytearray) -> int:
    """Makes normal Stamina Potions restore 1000 points instead of max stamina."""
    return _apply_single_site(
        buf,
        STAMINA_POTION_1000_SITE,
        STAMINA_POTION_1000_ORIGINAL,
        STAMINA_POTION_1000_REPLACEMENT,
        "stamina potion 1000",
    )


def apply_energy_flask_x10(buf: bytearray) -> int:
    """Raises the daily Energy Flask free stamina from 100 to 1000 points.

    The native window guard in ``laboratory_use_fields`` keeps the original
    12-15h and 18-21h windows; only the granted amount changes.
    """
    return _apply_single_site(
        buf,
        ENERGY_FLASK_STAMINA_SITE,
        ENERGY_FLASK_STAMINA_ORIGINAL,
        ENERGY_FLASK_STAMINA_REPLACEMENT,
        "energy flask x10",
    )


def _randoption_rows(
    buf: bytes | bytearray,
) -> list[tuple[int, int, int, tuple[int, ...], int]]:
    """Reads the server option table together with its parallel quality table.

    Each entry is ``(index, option_id, pool_key, six_weights, quality)``.  Rows
    that share ``pool_key`` compete for the same attribute and equipment slot, and
    the quality grade (1..5) ranks the value each row would grant.  The picker
    prefers the best grade of the pool on the ``:mastery-good-pick`` path; the
    table below is what makes every ordinary roll do the same.
    """
    table_offset = seg_offset(RANDOPTION_SERVER_SITE)
    quality_offset = seg_offset(RANDOPTION_QUALITY_SITE)
    table_end = table_offset + RANDOPTION_SERVER_ROW_COUNT * RANDOPTION_SERVER_ROW_SIZE
    quality_end = quality_offset + RANDOPTION_SERVER_ROW_COUNT * RANDOPTION_QUALITY_ROW_SIZE
    if len(buf) < table_end or len(buf) < quality_end:
        raise ValueError("randoption table is truncated")
    rows: list[tuple[int, int, int, tuple[int, ...], int]] = []
    for index in range(RANDOPTION_SERVER_ROW_COUNT):
        base = table_offset + index * RANDOPTION_SERVER_ROW_SIZE
        option_id, pool_key = struct.unpack_from("<2i", buf, base)
        weights = struct.unpack_from("<6i", buf, base + RANDOPTION_SERVER_WEIGHT_OFFSET)
        quality_id, quality = struct.unpack_from(
            "<2i", buf, quality_offset + index * RANDOPTION_QUALITY_ROW_SIZE
        )
        if quality_id != option_id:
            raise ValueError(
                f"randoption quality row {index} names option {quality_id}, "
                f"expected {option_id}"
            )
        if not 1 <= quality <= RANDOPTION_TOP_QUALITY:
            raise ValueError(
                f"randoption quality {quality} for option {option_id} is out of range"
            )
        if any(weight < 0 for weight in weights):
            raise ValueError(f"randoption weights for option {option_id} are negative")
        rows.append((index, option_id, pool_key, weights, quality))
    return rows


def _top_quality_weight_plan(
    rows: list[tuple[int, int, int, tuple[int, ...], int]],
) -> tuple[dict[int, tuple[int, ...]], int]:
    """Computes weight rewrites concentrating each ``(pool_key, column)`` pool on its top quality."""
    pools: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
    for index, _row_id, pool_key, weights, quality in rows:
        for column, weight in enumerate(weights):
            if weight > 0:
                pools.setdefault((pool_key, column), []).append(
                    (index, weight, quality)
                )
    weights_by_index = {index: list(weights) for index, _i, _k, weights, _q in rows}
    for (_pool_key, column), members in sorted(pools.items()):
        total = sum(weight for _index, weight, _quality in members)
        best = max(quality for _index, _weight, quality in members)
        winners = [
            (index, weight) for index, weight, quality in members if quality == best
        ]
        for index, _weight, _quality in members:
            weights_by_index[index][column] = 0
        if len(winners) == 1:
            weights_by_index[winners[0][0]][column] = total
            continue
        winner_total = sum(weight for _index, weight in winners)
        assigned = 0
        for position, (index, weight) in enumerate(winners):
            share = (
                total - assigned
                if position == len(winners) - 1
                else total * weight // winner_total
            )
            assigned += share
            weights_by_index[index][column] = share
    plan = {
        index: tuple(weights_by_index[index])
        for index, _row_id, _pool_key, weights, _quality in rows
        if tuple(weights_by_index[index]) != weights
    }
    return plan, len(pools)


def randoption_top_quality_state(
    buf: bytes | bytearray,
) -> tuple[dict[int, tuple[int, ...]], int]:
    """Returns the pending weight changes and the number of weighted option pools.

    A pool is one attribute at one equipment grade.  The returned mapping is keyed
    by row index and holds every row whose weights must change so that only the
    pool's best-quality rows stay drawable; an empty mapping means the bias is
    already in place.  The winning rows receive the pool's whole weight, so each
    attribute keeps the odds it had before and only the value inside the attribute
    changes.
    """
    return _top_quality_weight_plan(_randoption_rows(buf))


def apply_option_max_attributes(buf: bytearray) -> int:
    """Makes every equipment option roll use its pool's top-quality row.

    The picker draws inside a pool of rows that share an attribute and an
    equipment grade, then applies its own quality preference on top.  Leaving only
    the best-grade rows weighted — and handing them the pool's whole weight, so the
    attribute keeps its original odds — makes every roll (potion, granted gear and
    re-roll) land on the highest value available for that attribute and grade.  The
    candidate list is untouched, so locked attributes stay excluded and locked
    values stay restored exactly as the stock game restores them.
    """
    plan, _pools = randoption_top_quality_state(buf)
    if not plan:
        return 0
    table_offset = seg_offset(RANDOPTION_SERVER_SITE)
    for index, weights in plan.items():
        offset = (
            table_offset
            + index * RANDOPTION_SERVER_ROW_SIZE
            + RANDOPTION_SERVER_WEIGHT_OFFSET
        )
        _write_bytes(
            buf,
            offset,
            struct.pack("<6i", *weights),
            "randoption top quality weights",
        )
    return len(plan)


def _potential_rows(
    buf: bytes | bytearray,
) -> list[tuple[int, int, int, tuple[int, ...], int]]:
    """Reads and validates the hero potential (Trait) data and grade tables."""
    table_offset = seg_offset(POTENTIAL_DATA_TABLE_VADDR)
    grade_offset = seg_offset(POTENTIAL_GRADE_TABLE_VADDR)
    rows: list[tuple[int, int, int, tuple[int, ...], int]] = []
    for index in range(POTENTIAL_DATA_ROW_COUNT):
        base = table_offset + index * POTENTIAL_DATA_ROW_SIZE
        potential_id, potential_type = struct.unpack_from("<2i", buf, base)
        weights = struct.unpack_from(
            f"<{POTENTIAL_DATA_WEIGHT_COUNT}i",
            buf,
            base + POTENTIAL_DATA_WEIGHT_OFFSET,
        )
        grade_id, grade, _combat_power = struct.unpack_from(
            "<3i", buf, grade_offset + index * POTENTIAL_GRADE_ROW_SIZE
        )
        if grade_id != potential_id:
            raise ValueError(
                f"potential grade row {index} names id {grade_id}, "
                f"expected {potential_id}"
            )
        if not 1 <= grade <= POTENTIAL_TOP_QUALITY:
            raise ValueError(
                f"potential grade {grade} for id {potential_id} is out of range"
            )
        if any(weight < 0 for weight in weights):
            raise ValueError(
                f"potential weights for id {potential_id} are negative"
            )
        rows.append((index, potential_id, potential_type, weights, grade))
    return rows


def potential_top_quality_state(
    buf: bytes | bytearray,
) -> tuple[dict[int, tuple[int, ...]], int]:
    """Returns pending weight changes and the count of weighted potential pools.

    Each pool is one ``(potential_type, slot_phase_column)`` pair with positive
    total weight.  The winning highest-grade row(s) receive the pool's entire
    weight while lower-grade rows are zeroed, preserving every attribute's
    original roll probability.
    """
    return _top_quality_weight_plan(_potential_rows(buf))


def apply_trait_max_quality(buf: bytearray) -> int:
    """Makes every hero Trait roll use its pool's top-quality (grade 5) row."""
    plan, _pools = potential_top_quality_state(buf)
    if not plan:
        return 0
    table_offset = seg_offset(POTENTIAL_DATA_TABLE_VADDR)
    for index, weights in plan.items():
        offset = (
            table_offset
            + index * POTENTIAL_DATA_ROW_SIZE
            + POTENTIAL_DATA_WEIGHT_OFFSET
        )
        _write_bytes(
            buf,
            offset,
            struct.pack(f"<{POTENTIAL_DATA_WEIGHT_COUNT}i", *weights),
            "potential top quality weights",
        )
    return len(plan)


def apply_trait_allow_duplicates(buf: bytearray) -> int:
    """Allows rolling trait types already saved in other slots of the hero."""
    if (
        encode_arm64_branch(POTENTIAL_DEDUP_SITE, POTENTIAL_DEDUP_TARGET)
        != POTENTIAL_DEDUP_REPLACEMENT
    ):
        raise ValueError("Invalid potential dedup branch encoding")
    return _apply_single_site(
        buf,
        POTENTIAL_DEDUP_SITE,
        POTENTIAL_DEDUP_ORIGINAL,
        POTENTIAL_DEDUP_REPLACEMENT,
        "trait allow duplicates",
    )


def potential_multi_unique_sites() -> tuple[tuple[str, int, bytes, bytes], ...]:
    """Returns ``(label, vaddr, original_bytes, replacement_bytes)`` for ``trait_multi_unique``."""
    return (
        (
            "trait batch init",
            POTENTIAL_BATCH_INIT_SITE,
            POTENTIAL_BATCH_INIT_ORIGINAL,
            encode_arm64_branch(
                POTENTIAL_BATCH_INIT_SITE,
                POTENTIAL_MULTI_UNIQUE_BATCH_INIT_VADDR,
                link=True,
            ),
        ),
        (
            "trait batch call",
            POTENTIAL_BATCH_CALL_SITE,
            POTENTIAL_BATCH_CALL_ORIGINAL,
            encode_arm64_branch(
                POTENTIAL_BATCH_CALL_SITE,
                POTENTIAL_MULTI_UNIQUE_BATCH_CALL_VADDR,
                link=True,
            ),
        ),
        (
            "trait flags store",
            POTENTIAL_FLAGS_STORE_SITE,
            POTENTIAL_FLAGS_STORE_ORIGINAL,
            POTENTIAL_FLAGS_STORE_REPLACEMENT,
        ),
        (
            "trait pass1 filter",
            POTENTIAL_PASS1_FILTER_SITE,
            POTENTIAL_PASS1_FILTER_ORIGINAL,
            encode_arm64_branch(
                POTENTIAL_PASS1_FILTER_SITE,
                POTENTIAL_MULTI_UNIQUE_PASS1_FILTER_VADDR,
            ),
        ),
        (
            "trait pass2 filter",
            POTENTIAL_PASS2_FILTER_SITE,
            POTENTIAL_PASS2_FILTER_ORIGINAL,
            encode_arm64_branch(
                POTENTIAL_PASS2_FILTER_SITE,
                POTENTIAL_MULTI_UNIQUE_PASS2_FILTER_VADDR,
            ),
        ),
        (
            "trait pass2 empty",
            POTENTIAL_PASS2_EMPTY_SITE,
            POTENTIAL_PASS2_EMPTY_ORIGINAL,
            encode_arm64_branch(
                POTENTIAL_PASS2_EMPTY_SITE,
                POTENTIAL_MULTI_UNIQUE_PASS2_EMPTY_VADDR,
            ),
        ),
    )


def apply_trait_multi_unique(buf: bytearray) -> int:
    """Prevents multi-roll Trait batches from repeating attribute types within a batch."""
    sites = potential_multi_unique_sites()
    # Validate all six hook instructions and the cave slice before mutating so broken inputs never partially patch.
    for label, site, original, replacement in sites:
        off = seg_offset(site)
        current = bytes(buf[off : off + len(replacement)])
        if current not in (original, replacement):
            raise ValueError(
                f"Unexpected instruction at {label} site 0x{site:x}: "
                f"{current.hex()} (expected {original.hex()} or {replacement.hex()})"
            )

    cave_off = seg_offset(POTENTIAL_MULTI_UNIQUE_CAVE_VADDR)
    current_cave = bytes(buf[cave_off : cave_off + POTENTIAL_MULTI_UNIQUE_CAVE_SIZE])
    cave_digest = hashlib.sha256(current_cave).hexdigest()
    if (
        current_cave != POTENTIAL_MULTI_UNIQUE_CAVE_BYTES
        and cave_digest != POTENTIAL_MULTI_UNIQUE_CAVE_ORIGINAL_SHA256
    ):
        raise ValueError(
            f"Unexpected trait multi unique cave at 0x{POTENTIAL_MULTI_UNIQUE_CAVE_VADDR:x}: "
            f"sha256={cave_digest}"
        )

    changed = 0
    if current_cave != POTENTIAL_MULTI_UNIQUE_CAVE_BYTES:
        _write_bytes(buf, cave_off, POTENTIAL_MULTI_UNIQUE_CAVE_BYTES, "trait multi unique cave")
        changed += 1

    for label, site, original, replacement in sites:
        changed += _apply_single_site(buf, site, original, replacement, label)
    return changed


def potential_immunity_weight_state(so_bytes: bytes) -> tuple[int, int, int]:
    """Counts ``(patched, original, total)`` Slot 3..5 immunity rows."""
    data_off = seg_offset(POTENTIAL_DATA_TABLE_VADDR)
    patched = 0
    original = 0
    for row_idx, expected_pid, expected_ptype, col, orig_weight in POTENTIAL_IMMUNITY_ROWS:
        row_off = data_off + row_idx * POTENTIAL_DATA_ROW_SIZE
        pid, ptype = struct.unpack_from("<2i", so_bytes, row_off)
        if (pid, ptype) != (expected_pid, expected_ptype):
            raise ValueError(
                f"Unexpected potential immunity row {row_idx}: "
                f"id={pid} type={ptype} (expected {expected_pid}, {expected_ptype})"
            )
        weight_off = row_off + POTENTIAL_DATA_WEIGHT_OFFSET + col * 4
        weight = struct.unpack_from("<i", so_bytes, weight_off)[0]
        if weight == POTENTIAL_IMMUNITY_WEIGHT:
            patched += 1
        elif weight == orig_weight:
            original += 1
        else:
            raise ValueError(
                f"Unexpected immunity weight at row {row_idx} col {col}: "
                f"{weight} (expected {orig_weight} or {POTENTIAL_IMMUNITY_WEIGHT})"
            )
    return patched, original, len(POTENTIAL_IMMUNITY_ROWS)


def apply_trait_immunity_weight_x2(buf: bytearray) -> int:
    """Doubles Slot 3..5 immunity trait weights relative to normal stats (335 -> 20,000)."""
    potential_immunity_weight_state(bytes(buf))
    data_off = seg_offset(POTENTIAL_DATA_TABLE_VADDR)
    changed = 0
    for row_idx, _pid, _ptype, col, _orig in POTENTIAL_IMMUNITY_ROWS:
        weight_off = (
            data_off
            + row_idx * POTENTIAL_DATA_ROW_SIZE
            + POTENTIAL_DATA_WEIGHT_OFFSET
            + col * 4
        )
        current = struct.unpack_from("<i", buf, weight_off)[0]
        if current != POTENTIAL_IMMUNITY_WEIGHT:
            _write_bytes(
                buf,
                weight_off,
                struct.pack("<i", POTENTIAL_IMMUNITY_WEIGHT),
                "potential immunity weight",
            )
            changed += 1
    return changed


def apply_rune_option_max_quality(buf: bytearray) -> int:
    """Gives every rune option pool's top-quality rows the pool's whole weight.

    The stock picker only *biases* its draw towards the best quality: the mastery
    bonus (``mastery * 30``, 450 at most) is a probability out of 10000, so the top
    rows stay rare no matter how large the bonus grows.  Handing the top-quality
    rows of each pool the weight of the whole pool — and zeroing the rest — makes
    every draw land on the highest value available, the same trick
    ``apply_option_max_attributes`` uses for equipment.  Pools whose rows are all
    fixed-value keep their zero weight, so they never come back.
    """
    start = seg_offset(RUNE_OPTION_TABLE_VADDR)
    end = start + RUNE_OPTION_ROW_COUNT * RUNE_OPTION_ROW_SIZE
    digest = hashlib.sha256(buf[start:end]).hexdigest()
    if digest in (RUNE_OPTION_TABLE_PINK_SHA256, RUNE_OPTION_TABLE_PERCENT_PINK_SHA256):
        return 0
    if digest not in (RUNE_OPTION_TABLE_STOCK_SHA256, RUNE_OPTION_TABLE_PERCENT_SHA256):
        raise ValueError(f"Unexpected rune option table: sha256={digest}")
    pools: dict[tuple[int, int, int, int, int], list[tuple[int, int, int]]] = defaultdict(list)
    for index in range(RUNE_OPTION_ROW_COUNT):
        row = start + index * RUNE_OPTION_ROW_SIZE
        _option_id, kind, _condition, value_type, grade = struct.unpack_from("<5i", buf, row)
        slot, fourth = struct.unpack_from("<2i", buf, row + 0x18)
        weight = struct.unpack_from("<i", buf, row + 0x20)[0]
        quality = struct.unpack_from("<i", buf, row + 0x24)[0]
        pools[(kind, grade, slot, fourth, value_type)].append((index, quality, weight))
    for rows in pools.values():
        total = sum(weight for _index, _quality, weight in rows)
        best = max(quality for _index, quality, _weight in rows)
        top = [entry for entry in rows if entry[1] == best]
        share, remainder = divmod(total, len(top))
        for position, (index, _quality, _weight) in enumerate(top):
            offset = start + index * RUNE_OPTION_ROW_SIZE + 0x20
            struct.pack_into("<i", buf, offset, share + (remainder if position == 0 else 0))
        for index, quality, _weight in rows:
            if quality != best:
                struct.pack_into("<i", buf, start + index * RUNE_OPTION_ROW_SIZE + 0x20, 0)
    final = hashlib.sha256(buf[start:end]).hexdigest()
    if final not in (RUNE_OPTION_TABLE_PINK_SHA256, RUNE_OPTION_TABLE_PERCENT_PINK_SHA256):
        raise ValueError(f"Rune option table does not match the verified pink profile: sha256={final}")
    return 1


def apply_rune_option_quality(buf: bytearray) -> int:
    """Forces every rune option roll onto its pool's top-quality row."""
    instruction = _apply_single_site(
        buf,
        RUNE_OPTION_MASTERY_SITE,
        RUNE_OPTION_MASTERY_ORIGINAL,
        RUNE_OPTION_MASTERY_REPLACEMENT,
        "rune option quality",
    )
    table = apply_rune_option_max_quality(buf)
    return int(bool(instruction or table))



def equipment_option_bonus(factor: int) -> int:
    """Returns the constant bonus a factor maps to, clamped to the game's ceiling."""
    if factor < 0:
        raise ValueError(f"equipment option factor must be >= 0, got {factor}")
    if factor == 0:
        return 0
    return min(EQUIPMENT_OPTION_BONUS_BASE * factor, EQUIPMENT_OPTION_BONUS_CAP)


def apply_equipment_option_factor(buf: bytearray, factor: int) -> int:
    """Scales the Lord-mastery quality bias of every equipment option roll.

    ``factor`` multiplies the ``15 * 30 = 450`` maximum mastery bonus that callers
    already pass; the picker itself is untouched, so the odds stay linear in the
    bonus until they saturate at the game's own 10000 (100%) clamp.  Both reads
    of the argument are rewritten, which covers the option potion, granted gear
    and re-rolls alike.
    """
    bonus = equipment_option_bonus(factor)
    if bonus == 0:
        return 0
    changed = 0
    for site, original, register in zip(
        EQUIPMENT_OPTION_BONUS_SITES,
        EQUIPMENT_OPTION_BONUS_ORIGINALS,
        EQUIPMENT_OPTION_BONUS_REGISTERS,
        strict=True,
    ):
        changed += _apply_single_site(
            buf,
            site,
            original,
            encode_movz_w(register, bonus),
            f"equipment option bonus (w{register} = {bonus})",
        )
    return changed


def apply_soulgear_enchant_always(buf: bytearray) -> int:
    """Forces the gold-paid soulgear enchant to succeed every time."""
    return _apply_single_site(
        buf,
        SOULGEAR_ENCHANT_SITE,
        SOULGEAR_ENCHANT_ORIGINAL,
        encode_movz_w(SOULGEAR_ENCHANT_REGISTER, 1),
        "soulgear enchant verdict",
    )


def apply_no_win_box(buf: bytearray) -> int:
    """Hide phantom battle boxes and disable bonus boxes in hero-gene sweeps."""
    pending = []
    for site, original, replacement in (
        (NO_WIN_BOX_SITE, NO_WIN_BOX_ORIGINAL, NO_WIN_BOX_PATCHED),
        (SWEEP_GENE_BOX_SITE, SWEEP_GENE_BOX_ORIGINAL, SWEEP_GENE_BOX_PATCHED),
    ):
        offset = seg_offset(site)
        current = bytes(buf[offset:offset + len(original)])
        if current == replacement:
            continue
        if current != original:
            raise ValueError(f"Unexpected win box guard at 0x{site:x}: {current.hex()}")
        pending.append((offset, replacement))
    for offset, replacement in pending:
        _write_bytes(buf, offset, replacement, "win box guard")
    return len(pending)


def _hero_exp_cap_cave_bytes() -> bytes:
    """Builds the hero EXP clamping helper and 3 call-site trampolines."""
    cave = HERO_EXP_CAP_CAVE_VADDR
    code = bytearray()
    # Helper _clamp_exp(x0=creature_str*, x1=proposed_exp) -> x0=clamped_exp
    code += bytes.fromhex("fd7bbda9")  # stp x29, x30, [sp, #-0x30]!
    code += bytes.fromhex("f35301a9")  # stp x19, x20, [sp, #0x10]
    code += bytes.fromhex("fd030091")  # mov x29, sp
    code += bytes.fromhex("f30300aa")  # mov x19, x0
    code += bytes.fromhex("f40301aa")  # mov x20, x1
    code += encode_arm64_branch(cave + len(code), HERO_LEVEL_MAX_FUNC, link=True)
    code += bytes.fromhex("e10300aa")  # mov x1, x0
    code += bytes.fromhex("e00313aa")  # mov x0, x19
    code += encode_arm64_branch(cave + len(code), HERO_MAX_EXP_FUNC, link=True)
    code += bytes.fromhex("9f0200eb")  # cmp x20, x0
    code += bytes.fromhex("81d2809a")  # csel x1, x20, x0, le
    code += bytes.fromhex("1f0000f1")  # cmp x0, #0
    code += bytes.fromhex("20c0949a")  # csel x0, x1, x20, gt
    code += bytes.fromhex("f35341a9")  # ldp x19, x20, [sp, #0x10]
    code += bytes.fromhex("fd7bc3a8")  # ldp x29, x30, [sp], #0x30
    code += bytes.fromhex("c0035fd6")  # ret
    assert len(code) == HERO_EXP_CAP_HELPER_SIZE, len(code)

    # Trampoline 1 (0x80963C stage clear/sweep): x26 = clamp(x19, x20 + x26)
    t1_start = len(code)
    code += bytes.fromhex("fd7bbfa9fd030091")  # stp x29, x30, [sp, #-0x10]! ; mov x29, sp
    code += bytes.fromhex("81021a8be00313aa")  # add x1, x20, x26 ; mov x0, x19
    code += encode_arm64_branch(cave + len(code), cave, link=True)
    code += bytes.fromhex("fa0300aafd7bc1a8c0035fd6")  # mov x26, x0 ; ldp ; ret
    assert len(code) - t1_start == HERO_EXP_CAP_TRAMPOLINE_STD_SIZE

    # Trampoline 2 (0x81831C Tower of Dawn): x28 = clamp(x19, x23 + x24)
    t2_start = len(code)
    code += bytes.fromhex("fd7bbfa9fd030091")
    code += bytes.fromhex("e102188be00313aa")  # add x1, x23, x24 ; mov x0, x19
    code += encode_arm64_branch(cave + len(code), cave, link=True)
    code += bytes.fromhex("fc0300aafd7bc1a8c0035fd6")  # mov x28, x0 ; ldp ; ret
    assert len(code) - t2_start == HERO_EXP_CAP_TRAMPOLINE_STD_SIZE

    # Trampoline 3 (0x945E30 Expedition): x25 = clamp(x24, x0 + x9), preserving x8
    t3_start = len(code)
    code += bytes.fromhex("fd7bbea9e80b00f9fd030091")  # stp ; str x8, [sp,#0x10] ; mov x29, sp
    code += bytes.fromhex("0100098be00318aa")  # add x1, x0, x9 ; mov x0, x24
    code += encode_arm64_branch(cave + len(code), cave, link=True)
    code += bytes.fromhex("f90300aae80b40f9fd7bc2a8c0035fd6")  # mov x25, x0 ; ldr x8 ; ldp ; ret
    assert len(code) - t3_start == HERO_EXP_CAP_EXPEDITION_SIZE
    assert len(code) == HERO_EXP_CAP_CAVE_SIZE, len(code)
    return bytes(code)


HERO_EXP_CAP_CAVE_BYTES = _hero_exp_cap_cave_bytes()


def apply_hero_exp_cap(buf: bytearray) -> int:
    """Clamps battle/expedition EXP to level_max and restores Lv70 Limit Break lookup."""
    changed = _apply_single_site(
        buf,
        HERO_LEVEL_MAX_FLOOR_SITE,
        HERO_LEVEL_MAX_FLOOR_ORIGINAL,
        HERO_LEVEL_MAX_FLOOR_PATCHED,
        "hero level_max floor",
    )
    _write_checked_cave(
        buf,
        HERO_EXP_CAP_CAVE_VADDR,
        HERO_EXP_CAP_CAVE_BYTES,
        HERO_EXP_CAP_CAVE_ORIGINAL_SHA256,
        label="hero exp cap cave",
    )
    for site, orig, target, label in (
        (
            HERO_EXP_CAP_STAGE_SITE,
            HERO_EXP_CAP_STAGE_ORIGINAL,
            HERO_EXP_CAP_STAGE_TRAMPOLINE,
            "stage hero exp cap",
        ),
        (
            HERO_EXP_CAP_INFINITY_SITE,
            HERO_EXP_CAP_INFINITY_ORIGINAL,
            HERO_EXP_CAP_INFINITY_TRAMPOLINE,
            "tower hero exp cap",
        ),
        (
            HERO_EXP_CAP_EXPEDITION_SITE,
            HERO_EXP_CAP_EXPEDITION_ORIGINAL,
            HERO_EXP_CAP_EXPEDITION_TRAMPOLINE,
            "expedition hero exp cap",
        ),
    ):
        changed += _apply_single_site(
            buf,
            site,
            orig,
            encode_arm64_branch(site, target, link=True),
            label,
        )
    return changed


def apply_equipment_lock_fix(buf: bytearray) -> int:
    """Stops ``change_option`` from re-rolling the options before it reads the locks.

    The refresh call re-rolls with an empty lock set and overwrites the record the locked
    lines are restored from, so a lock only held from the second roll onwards.  With the
    call NOPed the handler performs a single roll that already carries the lock set.
    """
    return _apply_single_site(
        buf,
        EQUIPMENT_LOCK_FIX_SITE,
        EQUIPMENT_LOCK_FIX_ORIGINAL,
        EQUIPMENT_LOCK_FIX_NOP,
        "equipment lock fix",
    )


def apply_rune_box_random_type(buf: bytearray) -> int:
    """Makes the 4-star random rune box roll the three basic rune types.

    Rewrites rows 11..13 of the reward-type table into a three-row group 9, so the
    box's ``gacha_weight_no = 9`` maps to a fair choice between rune types 0, 1 and
    2 instead of a single ``runeType 8`` row the picker rejects.
    """
    changed = 0
    for row, expected, replacement in RUNE_BOX_TYPE_REWRITES:
        site = RUNE_REWARD_TYPE_TABLE + row * RUNE_REWARD_TYPE_STRIDE
        original = struct.pack("<4i", *expected)
        wanted = struct.pack("<4i", *replacement)
        offset = seg_offset(site)
        current = bytes(buf[offset : offset + len(wanted)])
        if current not in (original, wanted):
            raise ValueError(
                f"Unexpected rune reward type row {row} at 0x{site:x}: "
                f"found {current.hex()}, expected {original.hex()}"
            )
        if current == wanted:
            continue
        buf[offset : offset + len(wanted)] = wanted
        changed += 1
    return changed


def rune_quality_bonus(factor: int) -> int:
    """Returns the constant rune-quality bonus a factor maps to, clamped to the cap."""
    if factor < 0:
        raise ValueError(f"rune quality factor must be >= 0, got {factor}")
    if factor == 0:
        return 0
    return min(RUNE_QUALITY_BONUS_BASE * factor, RUNE_QUALITY_BONUS_CAP)


def apply_rune_quality_factor(buf: bytearray, factor: int) -> int:
    """Scales rune quality bias and excludes fixed-value attributes.

    The rune picker turns ``mastery * 30`` (ceiling 450) into the same 1/10000
    probability the equipment picker uses, so ``factor`` multiplies exactly that
    number. Flat rows are excluded by setting their selection weight to zero.
    """
    bonus = rune_quality_bonus(factor)
    if bonus == 0:
        return 0
    start = seg_offset(RUNE_OPTION_TABLE_VADDR)
    end = start + RUNE_OPTION_ROW_COUNT * RUNE_OPTION_ROW_SIZE
    digest = hashlib.sha256(buf[start:end]).hexdigest()
    if digest not in (
        RUNE_OPTION_TABLE_STOCK_SHA256,
        RUNE_OPTION_TABLE_PERCENT_SHA256,
        RUNE_OPTION_TABLE_PINK_SHA256,
        RUNE_OPTION_TABLE_PERCENT_PINK_SHA256,
    ):
        raise ValueError(f"Unexpected rune option table: sha256={digest}")
    instruction_changed = _apply_single_site(
        buf,
        RUNE_QUALITY_BONUS_SITE,
        RUNE_QUALITY_BONUS_ORIGINAL,
        encode_movz_x(RUNE_QUALITY_BONUS_REGISTER, bonus),
        f"rune quality bonus (x{RUNE_QUALITY_BONUS_REGISTER} = {bonus})",
    )
    table_changed = digest in (RUNE_OPTION_TABLE_STOCK_SHA256, RUNE_OPTION_TABLE_PINK_SHA256)
    if table_changed:
        count = 0
        for index in range(RUNE_OPTION_ROW_COUNT):
            row = start + index * RUNE_OPTION_ROW_SIZE
            if struct.unpack_from("<i", buf, row + 0x0C)[0] == 1:
                struct.pack_into("<i", buf, row + 0x20, 0)
                count += 1
        if count != RUNE_OPTION_FLAT_COUNT or hashlib.sha256(buf[start:end]).hexdigest() not in (
            RUNE_OPTION_TABLE_PERCENT_SHA256,
            RUNE_OPTION_TABLE_PERCENT_PINK_SHA256,
        ):
            raise ValueError("Rune option table does not match the verified percentage-only profile")
    return int(bool(instruction_changed or table_changed))


def apply_rune_upgrade_server_only(buf: bytearray) -> int:
    """Prepare the server half of the rune upgrade feature; not yet exposed.

    The caller must also fix the client price display before enabling this in an
    APK. The guaranteed-upgrade result is divided by ten after its existing
    rounding, and only levels 12–14 have their failure weights and costs changed.
    """
    start = seg_offset(RUNE_UPGRADE_TABLE_VADDR)
    end = start + RUNE_UPGRADE_ROW_SIZE * RUNE_UPGRADE_ROW_COUNT
    current = bytes(buf[start:end])
    digest = hashlib.sha256(current).hexdigest()
    if digest not in (RUNE_UPGRADE_TABLE_STOCK_SHA256, RUNE_UPGRADE_TABLE_PATCHED_SHA256):
        raise ValueError(f"Unexpected rune upgrade table: sha256={digest}")
    site = seg_offset(RUNE_DECIDED_COST_SITE)
    word = bytes(buf[site:site + len(RUNE_DECIDED_COST_ORIGINAL)])
    if word not in (RUNE_DECIDED_COST_ORIGINAL, RUNE_DECIDED_COST_PATCHED):
        raise ValueError(f"Unexpected rune decided cost instructions: {word.hex()}")
    changed = 0
    if digest == RUNE_UPGRADE_TABLE_STOCK_SHA256:
        table = bytearray(current)
        for level in range(12, 15):
            row = level * RUNE_UPGRADE_ROW_SIZE
            if struct.unpack_from("<i", table, row)[0] != level:
                raise ValueError(f"Unexpected rune upgrade level {level}")
            for grade in range(6):
                failure = row + 28 + grade * 4
                cost = row + 52 + grade * 4
                fail_value = struct.unpack_from("<i", table, failure)[0]
                gold_value = struct.unpack_from("<i", table, cost)[0]
                if fail_value <= 0 or gold_value <= 0 or gold_value % 10:
                    raise ValueError(f"Unexpected rune upgrade row {level}, grade {grade + 1}")
                struct.pack_into("<i", table, failure, 0)
                struct.pack_into("<i", table, cost, gold_value // 10)
        if hashlib.sha256(table).hexdigest() != RUNE_UPGRADE_TABLE_PATCHED_SHA256:
            raise ValueError("Rune upgrade table differs from the verified profile")
        _write_bytes(buf, start, bytes(table), "rune upgrade table")
        changed += 1
    if word == RUNE_DECIDED_COST_ORIGINAL:
        _write_bytes(buf, site, RUNE_DECIDED_COST_PATCHED, "rune decided cost")
        changed += 1
    return changed


def _rune_upgrade_cave_bytes() -> bytes:
    """Builds the startup hook that fixes the client's decided-upgrade price display."""
    cave = RUNE_UPGRADE_CAVE_VADDR
    data_expected = cave + 0x44
    data_replacement = cave + 0x48
    code = bytearray()
    code += encode_sub_sp(0x30)
    code += encode_stp_sp(29, 30, 0x20)
    code += encode_stp_sp(19, 20, 0x10)
    code += encode_adrp(cave + len(code), 0xBE3000, 8)
    code += encode_ldr_x(0, 8, 0x798)
    code += encode_movz_w(1, RUNE_UPGRADE_CLIENT_SITE & 0xFFFF)
    code += encode_movk_w(1, (RUNE_UPGRADE_CLIENT_SITE >> 16) & 0xFFFF, 16)
    code += encode_adr(cave + len(code), data_expected, 2)
    code += encode_adr(cave + len(code), data_replacement, 3)
    code += encode_movz_w(4, 1)  # patch_words counts words, not bytes
    code += encode_add_imm(5, 31, 0x28)
    code += encode_arm64_branch(cave + len(code), 0xAB575C, link=True)
    code += encode_ldp_sp(19, 20, 0x10)
    code += encode_ldp_sp(29, 30, 0x20)
    code += encode_add_sp(0x30)
    code += encode_ldp_sp(26, 25, 0x20)  # original instruction at the hook site
    code += encode_arm64_branch(cave + len(code), RUNE_UPGRADE_INSTALL_RETURN)
    assert len(code) == 0x44, len(code)
    code += RUNE_UPGRADE_CLIENT_ORIGINAL
    code += RUNE_UPGRADE_CLIENT_REPLACEMENT
    return bytes(code)


RUNE_UPGRADE_CAVE_BYTES = _rune_upgrade_cave_bytes()
RUNE_UPGRADE_CAVE_ORIGINAL_SHA256 = (
    "f13e0d041a5cbd90a815e390ff5e246ab22cc3f9858dfec508dc5342fe02b322"
)


def apply_rune_upgrade_discount(buf: bytearray) -> int:
    """Guarantees the +12→+15 upgrades and charges a tenth of the gold for them.

    Server half: rows 12-14 of ``kFwtRuneEnchantRows`` lose their failure weights
    and have their gold divided by ten, and ``rune_decided_enchant_cost_json``
    divides the final rounded total by ten.  Client half: the startup cave
    rewrites ``RuneGradeUpPopup.GetEnchantCoast`` so the Awake screen shows the
    same tenth instead of the full price.
    """
    # Validate every target before writing so a foreign library is left untouched.
    cave_offset = seg_offset(RUNE_UPGRADE_CAVE_VADDR)
    if len(buf) < cave_offset + RUNE_UPGRADE_CAVE_SIZE:
        raise ValueError("rune upgrade cave does not fit in the library")
    current = bytes(buf[cave_offset:cave_offset + RUNE_UPGRADE_CAVE_SIZE])
    cave_digest = hashlib.sha256(current).hexdigest()
    if current != RUNE_UPGRADE_CAVE_BYTES and cave_digest != RUNE_UPGRADE_CAVE_ORIGINAL_SHA256:
        raise ValueError(
            f"Unexpected rune upgrade cave at 0x{RUNE_UPGRADE_CAVE_VADDR:x}: "
            f"sha256={cave_digest}"
        )
    site_offset = seg_offset(RUNE_UPGRADE_INSTALL_SITE)
    replacement = encode_arm64_branch(RUNE_UPGRADE_INSTALL_SITE, RUNE_UPGRADE_CAVE_VADDR)
    current_site = bytes(buf[site_offset:site_offset + 4])
    if current_site not in (RUNE_UPGRADE_INSTALL_ORIGINAL, replacement):
        raise ValueError(
            f"Unexpected rune upgrade install site 0x{RUNE_UPGRADE_INSTALL_SITE:x}: "
            f"{current_site.hex()}"
        )

    changed = apply_rune_upgrade_server_only(buf)
    if current != RUNE_UPGRADE_CAVE_BYTES:
        _write_bytes(buf, cave_offset, RUNE_UPGRADE_CAVE_BYTES, "rune upgrade cave")
        changed += 1
    if current_site != replacement:
        buf[site_offset:site_offset + 4] = replacement
        changed += 1
    return changed


def rune_roll_cave_blob() -> bytes:
    """Builds the cave that turns one deterministic reward roll into a random one.

    It calls ``stable_reward_roll_text`` with the caller's arguments untouched and
    then mixes a monotonically increasing counter into the returned value, so two
    identical boxes no longer roll the same number.  The counter lives in the
    zero-filled padding between ``.data`` and ``.bss`` (inside the RW segment, no
    section owns it).
    """
    cave_va = RUNE_ROLL_CAVE_VA
    blob = b"".join(
        (
            encode_stp_pre_index(29, 30, -16),
            encode_arm64_branch(cave_va + 4, RUNE_ROLL_TEXT_VA, link=True),
            encode_adrp(
                cave_va + 8,
                RUNE_ROLL_COUNTER_PAGE + RUNE_ROLL_COUNTER_OFFSET,
                RUNE_ROLL_ADRP_REG,
            ),
            encode_ldr_w(
                RUNE_ROLL_COUNTER_REG, RUNE_ROLL_ADRP_REG, RUNE_ROLL_COUNTER_OFFSET
            ),
            encode_add_w_imm(
                RUNE_ROLL_COUNTER_REG, RUNE_ROLL_COUNTER_REG, 1
            ),
            encode_str_w(
                RUNE_ROLL_COUNTER_REG, RUNE_ROLL_ADRP_REG, RUNE_ROLL_COUNTER_OFFSET
            ),
            encode_eor_x(0, 0, RUNE_ROLL_COUNTER_REG),
            encode_ldp_post_index(29, 30, 16),
            encode_ret(),
        )
    )
    blob += rune_type_seed_cave_blob()
    if len(blob) != RUNE_ROLL_CAVE_LEN:
        raise AssertionError(
            f"rune roll cave is {len(blob)} bytes, expected {RUNE_ROLL_CAVE_LEN}"
        )
    return blob


def rune_type_seed_cave_blob() -> bytes:
    """Builds the block that seeds the type-table loop with a real pseudo-random value.

    The library does not import ``rand``, so the block carries its own xorshift32 over a
    word kept in the padding between ``.data`` and ``.bss``: seven instructions, no call.
    A plain incremented counter was not enough -- values 1, 2, 3 all fall inside the
    first weight bucket, so the box handed out attack runes on every purchase.
    ``x6`` is unused by ``pick_battle_rune_code``; the mixed value is left in ``w0``,
    which is the register the loop's weighted pick reads.
    """
    base = RUNE_ROLL_CAVE_VA + RUNE_TYPE_CAVE_OFFSET
    return b"".join(
        (
            encode_adrp(
                base, RUNE_ROLL_COUNTER_PAGE + RUNE_TYPE_SEED_OFFSET, RUNE_TYPE_SEED_REG
            ),
            encode_ldr_w(0, RUNE_TYPE_SEED_REG, RUNE_TYPE_SEED_OFFSET),
            encode_add_w_imm(0, 0, RUNE_TYPE_SEED_ADVANCE),
            encode_eor_w(0, 0, 0, shift=0, amount=13),   # x ^= x << 13
            encode_eor_w(0, 0, 0, shift=1, amount=17),   # x ^= x >> 17
            encode_eor_w(0, 0, 0, shift=0, amount=5),    # x ^= x << 5
            encode_str_w(0, RUNE_TYPE_SEED_REG, RUNE_TYPE_SEED_OFFSET),
            encode_arm64_branch(base + 28, RUNE_TYPE_LOOP_BODY),
        )
    )


def apply_rune_box_random_roll(buf: bytearray) -> int:
    """Restores the RNG on the rune box's slot and type rolls.

    ``pick_battle_rune_code`` keys every reward roll on a fixed string, and the
    Korean dev's ``stable_reward_roll_text`` hashes those strings deterministically
    to pin the rune quality and the fourth attribute.  Only the ``-slot`` and
    ``-type`` rolls are rerouted here, so a shop rune box hands out all nine
    slot/type combinations while ``-grade`` and ``-quality`` keep the dev's design.
    """
    changed = int(
        _write_guild_raid_cave(
            buf, RUNE_ROLL_CAVE_VA, rune_roll_cave_blob(), RUNE_ROLL_CAVE_SHA256
        )
    )
    for site in RUNE_ROLL_SITES:
        changed += _apply_single_site(
            buf,
            site,
            encode_arm64_branch(site, RUNE_ROLL_TEXT_VA, link=True),
            encode_arm64_branch(site, RUNE_ROLL_CAVE_VA, link=True),
            f"rune box roll 0x{site:x}",
        )
    changed += _apply_single_site(
        buf,
        RUNE_TYPE_LOOP_ENTER,
        encode_arm64_branch(RUNE_TYPE_LOOP_ENTER, RUNE_TYPE_LOOP_BODY),
        encode_arm64_branch(
            RUNE_TYPE_LOOP_ENTER, RUNE_ROLL_CAVE_VA + RUNE_TYPE_CAVE_OFFSET
        ),
        "rune box type seed",
    )
    return changed


def _write_guild_raid_cave(
    buf: bytearray,
    vaddr: int,
    blob: bytes,
    original_sha256: str,
) -> bool:
    """Writes a guild-raid cave slot, accepting only reference or patched bytes."""
    offset = seg_offset(vaddr)
    current = bytes(buf[offset:offset + len(blob)])
    if current == blob:
        return False
    if hashlib.sha256(current).hexdigest() != original_sha256:
        raise ValueError(
            f"Unexpected guild raid cave contents at 0x{vaddr:x}: "
            f"sha256={hashlib.sha256(current).hexdigest()}"
        )
    buf[offset:offset + len(blob)] = blob
    return True


def apply_guild_raid_score_fix(buf: bytearray) -> int:
    """Enables 64-bit Guild Raid records above the signed 32-bit limit.

    The native server normally serializes the stored ``guild_raid_score`` into
    the signed 32-bit ``bonus_limit`` field.  The cave sends ``-1`` for values
    above INT32_MAX, and the client hook restores the real 64-bit value from
    ``rank_list[0].rank_score`` before calling ``set_scoreLimit``.  Both hook
    sites and the runtime client-patch trampolines are verified before any
    write; a different client build makes the installer fail closed at runtime
    while the server falls back to zero.
    """
    start_off = seg_offset(GUILD_RAID_START_SITE)
    install_off = seg_offset(GUILD_RAID_INSTALL_SITE)
    start_patched = (
        encode_arm64_branch(GUILD_RAID_START_SITE, GUILD_RAID_SENTINEL_CAVE)
        + bytes.fromhex("1f2003d5")  # nop; the cave returns to 0x831CEC
    )
    install_patched = encode_arm64_branch(
        GUILD_RAID_INSTALL_SITE, GUILD_RAID_CLIENT_CAVE
    )

    current_start = bytes(buf[start_off:start_off + len(start_patched)])
    if current_start not in (GUILD_RAID_START_ORIGINAL, start_patched):
        raise ValueError(
            f"Unexpected instruction at guild raid start site "
            f"0x{GUILD_RAID_START_SITE:x}: {current_start.hex()} "
            f"(expected {GUILD_RAID_START_ORIGINAL.hex()} or {start_patched.hex()})"
        )
    current_install = bytes(buf[install_off:install_off + len(install_patched)])
    if current_install not in (GUILD_RAID_INSTALL_ORIGINAL, install_patched):
        raise ValueError(
            f"Unexpected instruction at guild raid installer site "
            f"0x{GUILD_RAID_INSTALL_SITE:x}: {current_install.hex()} "
            f"(expected {GUILD_RAID_INSTALL_ORIGINAL.hex()} or {install_patched.hex()})"
        )

    _write_guild_raid_cave(
        buf,
        GUILD_RAID_SENTINEL_CAVE,
        GUILD_RAID_SENTINEL_CAVE_BYTES,
        GUILD_RAID_SENTINEL_SLOT_SHA256,
    )
    _write_guild_raid_cave(
        buf,
        GUILD_RAID_CLIENT_CAVE,
        GUILD_RAID_CLIENT_CAVE_BYTES,
        GUILD_RAID_CLIENT_SLOT_SHA256,
    )

    changed = 0
    if current_start != start_patched:
        _write_bytes(buf, start_off, start_patched, "guild raid start site")
        changed += 1
    if current_install != install_patched:
        _write_bytes(buf, install_off, install_patched, "guild raid installer site")
        changed += 1
    return changed


def _campaign_discount_90(value: int) -> int:
    """Returns ceil(value * 10%) with a minimum price of one unit."""
    return max(1, (value + 9) // 10)


def apply_campaign_shop_discount(buf: bytearray) -> int:
    """Applies 90% discount across campaign shops (Honor, Guild Raid, Ancient Coins, Unknown Paradise, and Friend Shop)."""
    pat_c = re.compile(rb'\{[^{}]*?"shop_content":\s*([1356])[^{}]*?"price_count":(\s*\d+)[^{}]*?\}')
    pat_f = re.compile(rb'\{[^{}]*?"price_friendship_point":(\s*[1-9]\d*)[^{}]*?\}')
    pat_coin = re.compile(
        rb'\{[^{}\x00]*?"shop_kind":\s*6\s*,[^{}\x00]*?'
        rb'"price_coin":(\s*[1-9]\d*)(?=\s*,)[^{}\x00]*?\}'
    )
    # This catalog row is assembled from multiple literals. Its first fragment
    # ends after "20" and the following fragment supplies the trailing zeroes.
    # Replacing "20" with " 2" therefore changes 20000 to 2000 while preserving
    # the fragment's width and its NUL terminator.
    pat_fragment = re.compile(
        rb'"shop_code":"6A102"[^{}\x00]*?"price_coin":(20| 2)\x00'
    )
    flags = _flags_supported(buf)
    if flags and _has_flag(buf, CAMPAIGN_SHOP_FLAG):
        return 0
    matches_c = list(pat_c.finditer(buf))
    matches_f = list(pat_f.finditer(buf))
    matches_coin = list(pat_coin.finditer(buf))
    matches_fragment = list(pat_fragment.finditer(buf))
    if not flags and (
        any(m.group(2).startswith(b" ") for m in matches_c)
        or any(m.group(1).startswith(b" ") for m in matches_f)
        or any(m.group(1).startswith(b" ") for m in matches_coin)
    ):
        return 0
    if not matches_c and not matches_f and not matches_coin:
        raise ValueError("Campaign shop discount patch matched no shop rows")

    count = 0
    for m in matches_c:
        sub = m.group(0)
        p_match = re.search(rb'"price_count":(\s*\d+)', sub)
        if p_match:
            old_val_str = p_match.group(1)
            old_val = int(old_val_str)
            new_val = _campaign_discount_90(old_val)
            new_val_str = f"{new_val:>{len(old_val_str)}}".encode("ascii")
            if len(new_val_str) != len(old_val_str):
                raise ValueError(
                    f"Price string length mismatch: {old_val_str!r} vs {new_val_str!r}"
                )
            abs_pos = m.start() + p_match.start(1)
            if old_val != new_val:
                _write_bytes(buf, abs_pos, new_val_str, "campaign shop price")
            count += 1

    for m in matches_f:
        sub = m.group(0)
        p_match = re.search(rb'"price_friendship_point":(\s*[1-9]\d*)', sub)
        if p_match:
            old_val_str = p_match.group(1)
            old_val = int(old_val_str)
            new_val = _campaign_discount_90(old_val)
            new_val_str = f"{new_val:>{len(old_val_str)}}".encode("ascii")
            if len(new_val_str) != len(old_val_str):
                raise ValueError(
                    f"Friendship point string length mismatch: {old_val_str!r} vs {new_val_str!r}"
                )
            abs_pos = m.start() + p_match.start(1)
            if old_val != new_val:
                _write_bytes(buf, abs_pos, new_val_str, "campaign shop friendship price")
            count += 1

    for m in matches_coin:
        old = m.group(1)
        value = int(old)
        replacement = f"{_campaign_discount_90(value):>{len(old)}}".encode("ascii")
        if len(replacement) != len(old):
            raise ValueError("Coin price string length mismatch")
        if value != int(replacement):
            _write_bytes(buf, m.start(1), replacement, "campaign shop coin price")
        count += 1

    if len(matches_fragment) > 1:
        raise ValueError("Duplicate Ancient Coin shop price fragment")
    if matches_fragment:
        fragment = matches_fragment[0]
        if fragment.group(1) == b"20":
            _write_bytes(buf, fragment.start(1), b" 2", "ancient coin price fragment")
        count += 1

    _set_flag(buf, CAMPAIGN_SHOP_FLAG)
    return count


def apply_mode_drops_x10(buf: bytearray) -> int:
    """Multiplies drops by 10x across 6 game modes:

    1. Unknown Paradise World Boss: 10x final cycle-end rank/grade rewards
       (`kWorldBossCycleRewardRows` at 0x75EB90, reward types 1..3) and fixed
       1000 Kraken Scales/day (500 + 500 via cave 0x8E69F4 -> 0xB2AB00), while
       preserving the event 10002 Mobile Repair Shop row (`0x75F6C0`)
    2. Dimension Breakthrough match win drop hook (0x94B528 -> cave)
    3. Pit of Nephthys base gold (126 stages, prefixes 0x70, 0x71)
    4. Lost Island base gold (82 stages, prefixes 0x80, 0x81)
    5. Sky Library riddle table rewards (156 rows, col 5)
    6. Battle of Honor coin grant (6 -> 60) and win rank points (fixed 100)

    It also makes Dimension Breakthrough gene drops guaranteed and 10x larger.
    """
    changed = 0
    dim_hook_off = seg_offset(DIMENSION_DROP_SITE)
    dim_replacement = encode_arm64_branch(DIMENSION_DROP_SITE, DIMENSION_CAVE_VADDR)
    already_patched = bytes(buf[dim_hook_off:dim_hook_off + 4]) == dim_replacement

    # Battle of Honor: the server-side result handler granted and displayed a
    # hardcoded 6 Honor Coins. The client asset patch alone only changed the
    # preview table, so the actual grant stayed at 6.
    honor_off = seg_offset(HONOR_COIN_COUNT_SITE)
    current = bytes(buf[honor_off:honor_off + 4])
    if current not in (HONOR_COIN_COUNT_ORIGINAL, HONOR_COIN_COUNT_REPLACEMENT):
        raise ValueError(
            f"Unexpected Honor Coin count at 0x{HONOR_COIN_COUNT_SITE:x}: {current.hex()}"
        )
    if current != HONOR_COIN_COUNT_REPLACEMENT:
        _write_bytes(buf, honor_off, HONOR_COIN_COUNT_REPLACEMENT, "honor coin count")
        changed += 1

    # Battle of Honor rank points: fix the score delta to 100 on a victory.
    _write_recycle_cave(
        buf,
        HONOR_POINTS_CAVE_VADDR,
        HONOR_POINTS_CAVE_BYTES,
        HONOR_POINTS_CAVE_ORIGINAL_SHA256,
    )
    honor_points_off = seg_offset(HONOR_POINTS_DELTA_SITE)
    honor_points_replace = encode_arm64_branch(
        HONOR_POINTS_DELTA_SITE, HONOR_POINTS_CAVE_VADDR, link=True
    )
    current = bytes(buf[honor_points_off:honor_points_off + 4])
    if current not in (HONOR_POINTS_DELTA_ORIGINAL, honor_points_replace):
        raise ValueError(
            f"Unexpected honor score delta site at 0x{HONOR_POINTS_DELTA_SITE:x}: "
            f"{current.hex()}"
        )
    if current != honor_points_replace:
        _write_bytes(buf, honor_points_off, honor_points_replace, "honor score delta")
        changed += 1

    # Dimension Breakthrough gene drops: skip the native chance gate and
    # multiply the rolled gene count by ten.
    gene_gate_off = seg_offset(DIMENSION_GENE_GUARANTEE_SITE)
    current = bytes(buf[gene_gate_off:gene_gate_off + 4])
    if current not in (
        DIMENSION_GENE_GUARANTEE_ORIGINAL,
        DIMENSION_GENE_GUARANTEE_REPLACEMENT,
    ):
        raise ValueError(
            "Unexpected Dimension gene gate at "
            f"0x{DIMENSION_GENE_GUARANTEE_SITE:x}: {current.hex()}"
        )
    if current != DIMENSION_GENE_GUARANTEE_REPLACEMENT:
        _write_bytes(buf, gene_gate_off, DIMENSION_GENE_GUARANTEE_REPLACEMENT, "dimension gene gate")
        changed += 1

    gene_cave = _build_dimension_gene_cave(DIMENSION_GENE_CAVE_VADDR)
    _write_checked_cave(
        buf,
        DIMENSION_GENE_CAVE_VADDR,
        gene_cave,
        DIMENSION_GENE_CAVE_ORIGINAL_SHA256,
        label="dimension gene cave",
    )

    gene_count_off = seg_offset(DIMENSION_GENE_COUNT_SITE)
    gene_count_replacement = encode_arm64_branch(
        DIMENSION_GENE_COUNT_SITE, DIMENSION_GENE_CAVE_VADDR
    )
    current = bytes(buf[gene_count_off:gene_count_off + 4])
    if current not in (DIMENSION_GENE_COUNT_ORIGINAL, gene_count_replacement):
        raise ValueError(
            "Unexpected Dimension gene count site at "
            f"0x{DIMENSION_GENE_COUNT_SITE:x}: {current.hex()}"
        )
    if current != gene_count_replacement:
        _write_bytes(buf, gene_count_off, gene_count_replacement, "dimension gene count")
        changed += 1

    # 1. World Boss final cycle-end rank/grade rewards (types 1..3 -> 10x).
    # Keep daily settlement mana stones (28,800) and score-renewal boxes at 1x.
    wb_cycle_base = seg_offset(WORLDBOSS_CYCLE_REWARD_VADDR)
    matched_cycle_rows = 0
    for index in range(WORLDBOSS_CYCLE_REWARD_ROW_COUNT):
        at = wb_cycle_base + index * WORLDBOSS_CYCLE_REWARD_ROW_SIZE
        _row_id, reward_type, _min_v, _max_v, resource_type, _pad, val1, val2 = (
            struct.unpack_from("<iiqqiiqq", buf, at)
        )
        if reward_type not in WORLDBOSS_CYCLE_REWARD_TARGET_TYPES:
            continue
        matched_cycle_rows += 1
        if already_patched:
            continue
        if resource_type == WORLDBOSS_CYCLE_REWARD_GOLD_RES:
            if not (0 < val1 <= WORLDBOSS_CYCLE_REWARD_GOLD_STOCK_MAX):
                raise ValueError(
                    f"Unexpected World Boss cycle gold reward at row {index}: {val1}"
                )
            struct.pack_into("<q", buf, at + 0x20, val1 * 10)
            changed += 1
        elif resource_type == WORLDBOSS_CYCLE_REWARD_ITEM_RES:
            if (
                val1 != WORLDBOSS_KRAKEN_SCALE_CODE
                or not (0 < val2 <= WORLDBOSS_CYCLE_REWARD_ITEM_STOCK_MAX)
            ):
                raise ValueError(
                    f"Unexpected World Boss cycle item reward at row {index}: "
                    f"code={val1}, count={val2}"
                )
            struct.pack_into("<q", buf, at + 0x28, val2 * 10)
            changed += 1
        else:
            raise ValueError(
                f"Unexpected World Boss cycle resource_type at row {index}: {resource_type}"
            )
    if matched_cycle_rows != WORLDBOSS_CYCLE_REWARD_TARGET_COUNT:
        raise ValueError(
            "Unexpected World Boss cycle reward row count: "
            f"expected {WORLDBOSS_CYCLE_REWARD_TARGET_COUNT}, got {matched_cycle_rows}"
        )

    # 1b. Event 10002 (Mobile Repair Shop, row_type == 2) in .rodata. Keep
    # stock so WORLDBOSS_RESULT_EVENT opens `worldboss_travel_repair_offer`
    # instead of completing immediately and locking Instant Repair; repair
    # older builds if they rewrote this row.
    reward_off = seg_offset(WORLDBOSS_EVENT_REWARD_SITE)
    current = bytes(buf[reward_off:reward_off + len(WORLDBOSS_EVENT_REWARD_ORIGINAL)])
    if current not in (
        WORLDBOSS_EVENT_REWARD_ORIGINAL,
        WORLDBOSS_EVENT_REWARD_REPLACEMENT,
    ):
        raise ValueError(
            "Unexpected World Boss event reward row at "
            f"0x{WORLDBOSS_EVENT_REWARD_SITE:x}: {current.hex()}"
        )
    if current != WORLDBOSS_EVENT_REWARD_ORIGINAL:
        _write_bytes(
            buf,
            reward_off,
            WORLDBOSS_EVENT_REWARD_ORIGINAL,
            "world boss event repair row restore",
        )
        changed += 1

    # 2. World Boss daily Kraken Scale cave (500 per attack = 1000/day)
    _write_checked_cave(
        buf,
        WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
        WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES,
        WORLDBOSS_DAILY_KRAKEN_CAVE_ORIGINAL_SHA256,
        label="world boss daily kraken cave",
    )

    wb_hook_off = seg_offset(WORLDBOSS_DAILY_KRAKEN_SITE)
    wb_replacement = encode_arm64_branch(
        WORLDBOSS_DAILY_KRAKEN_SITE, WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR
    )
    current = bytes(buf[wb_hook_off:wb_hook_off + 4])
    if current not in (WORLDBOSS_DAILY_KRAKEN_ORIGINAL, wb_replacement):
        raise ValueError(
            "Unexpected instruction at World Boss daily kraken hook "
            f"0x{WORLDBOSS_DAILY_KRAKEN_SITE:x}: {current.hex()}"
        )
    if current != wb_replacement:
        _write_bytes(buf, wb_hook_off, wb_replacement, "world boss daily kraken hook")
        changed += 1

    # 3. Dimension Breakthrough hook & cave
    dim_cave_bytes = _build_dimension_cave(DIMENSION_CAVE_VADDR)
    _write_checked_cave(
        buf,
        DIMENSION_CAVE_VADDR,
        dim_cave_bytes,
        DIMENSION_CAVE_ORIGINAL_SHA256,
        label="dimension cave",
    )

    dim_hook_off = seg_offset(DIMENSION_DROP_SITE)
    dim_replacement = encode_arm64_branch(DIMENSION_DROP_SITE, DIMENSION_CAVE_VADDR)
    current = bytes(buf[dim_hook_off:dim_hook_off + 4])
    if current not in (DIMENSION_DROP_ORIGINAL, dim_replacement):
        raise ValueError(
            f"Unexpected instruction at Dimension Breakthrough hook 0x{DIMENSION_DROP_SITE:x}: {current.hex()}"
        )
    if current != dim_replacement:
        _write_bytes(buf, dim_hook_off, dim_replacement, "dimension hook")
        changed += 1

    # 4 & 5. Pit of Nephthys (126 stages) & Lost Island (82 stages).  The
    # dimension hook is the authoritative "already applied" marker; the old
    # gold-value heuristic could silently skip the patch or double-multiply.
    for index in range(STAGE_ROW_COUNT):
        at = STAGE_TABLE_OFFSET + index * STAGE_ROW_SIZE
        stage = struct.unpack_from("<i", buf, at)[0]
        prefix = _stage_prefix(stage)
        if (
            prefix in NEPHTHYS_STAGE_PREFIXES or prefix in LOST_ISLAND_STAGE_PREFIXES
        ) and not already_patched:
            gold = struct.unpack_from("<i", buf, at + 8)[0]
            if gold > 0x7FFFFFFF // 10:
                raise ValueError(f"Unexpected Nephthys/Lost Island gold in stage {stage:x}")
            struct.pack_into("<i", buf, at + 8, gold * 10)
            changed += 1

    # 6. Sky Library riddle table (156 rows)
    for index in range(RIDDLE_ROW_COUNT):
        at = RIDDLE_TABLE_OFFSET + index * RIDDLE_ROW_SIZE
        if not already_patched:
            val = struct.unpack_from("<i", buf, at + 20)[0]
            if val > 0x7FFFFFFF // 10:
                raise ValueError(f"Unexpected Sky Library reward at row {index}")
            struct.pack_into("<i", buf, at + 20, val * 10)
            changed += 1

    return changed


def apply_battle_arena_fix(buf: bytearray) -> int:
    """Fixes Battle Arena team configuration save bug and empty slot handling."""
    changed = 0
    for site, original, replacement in ARENA_WEEK_STATE_SITES:
        offset = seg_offset(site)
        current = bytes(buf[offset:offset + len(replacement)])
        if current == replacement:
            continue
        if current != original:
            raise ValueError(
                f"Unexpected instruction at arena site 0x{site:x}: {current.hex()} "
                f"(expected {original.hex()} or {replacement.hex()})"
            )
        buf[offset:offset + len(replacement)] = replacement
        changed += 1

    slot_off = seg_offset(ARENA_EMPTY_SLOT_SITE)
    current = bytes(buf[slot_off:slot_off + len(ARENA_EMPTY_SLOT_REPLACEMENT)])
    if current not in (ARENA_EMPTY_SLOT_ORIGINAL, ARENA_EMPTY_SLOT_REPLACEMENT):
        raise ValueError(
            f"Unexpected instruction at arena empty slot site 0x{ARENA_EMPTY_SLOT_SITE:x}: {current.hex()}"
        )
    if current != ARENA_EMPTY_SLOT_REPLACEMENT:
        buf[slot_off:slot_off + len(ARENA_EMPTY_SLOT_REPLACEMENT)] = ARENA_EMPTY_SLOT_REPLACEMENT
        changed += 1

    # ARENA_SET_ATTACK_TEAM: accept the client's four defence leaders instead of
    # requiring eight values (see ARENA_DEFENCE_* above).
    for site, original, replacement in (
        (
            ARENA_DEFENCE_SIZE_SITE,
            ARENA_DEFENCE_SIZE_ORIGINAL,
            ARENA_DEFENCE_SIZE_REPLACEMENT,
        ),
        (
            ARENA_DEFENCE_COUNT_SITE,
            ARENA_DEFENCE_COUNT_ORIGINAL,
            ARENA_DEFENCE_COUNT_REPLACEMENT,
        ),
        (
            ARENA_SCHEMA_GATE_SITE,
            ARENA_SCHEMA_GATE_ORIGINAL,
            ARENA_SCHEMA_GATE_REPLACEMENT,
        ),
    ):
        offset = seg_offset(site)
        current = bytes(buf[offset:offset + len(replacement)])
        if current == replacement:
            continue
        if current != original:
            raise ValueError(
                f"Unexpected instruction at arena defence site 0x{site:x}: "
                f"{current.hex()} (expected {original.hex()} or "
                f"{replacement.hex()})"
            )
        buf[offset:offset + len(replacement)] = replacement
        changed += 1

    # The client sends four teams as eight members; compact to the four leaders
    # before the native server validates and stores the PvP teams.
    changed += _write_recycle_cave(
        buf,
        PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR,
        PVP_TEAM_COMPACT_ATTACK_CAVE_BYTES,
        PVP_TEAM_COMPACT_ATTACK_CAVE_ORIGINAL_SHA256,
    )
    changed += _write_recycle_cave(
        buf,
        PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR,
        PVP_TEAM_COMPACT_DEFENSE_CAVE_BYTES,
        PVP_TEAM_COMPACT_DEFENSE_CAVE_ORIGINAL_SHA256,
    )
    for hook, original, cave in (
        (
            PVP_TEAM_COMPACT_ATTACK_HOOK,
            PVP_TEAM_COMPACT_ATTACK_ORIGINAL,
            PVP_TEAM_COMPACT_ATTACK_CAVE_VADDR,
        ),
        (
            PVP_TEAM_COMPACT_DEFENSE_HOOK,
            PVP_TEAM_COMPACT_DEFENSE_ORIGINAL,
            PVP_TEAM_COMPACT_DEFENSE_CAVE_VADDR,
        ),
    ):
        offset = seg_offset(hook)
        replacement = encode_arm64_branch(hook, cave)
        current = bytes(buf[offset:offset + 4])
        if current == replacement:
            continue
        if current != original:
            raise ValueError(
                f"Unexpected PvP team hook at 0x{hook:x}: {current.hex()} "
                f"(expected {original.hex()} or {replacement.hex()})"
            )
        buf[offset:offset + 4] = replacement
        changed += 1
    return changed


def apply_guild_raid_self_mercenary(buf: bytearray) -> int:
    """Allows selecting your own mercenary with equipment and stats in Guild Raid.

    Installs the weekday-aware self projection cave at ``0x930100`` -> ``0xB34860``
    (filling the projection from ownership lists, or resuming the selected stock
    hire when no valid weekday hero exists) and removes the client-side self
    filter (RVA ``0x1EE5220``) through a post-covault cave (``0xAB3380`` ->
    ``0xB336D8``).
    """
    changed = 0

    cave_offset = seg_offset(GUILD_RAID_MERCENARY_CAVE_VADDR)
    current_cave = bytes(
        buf[cave_offset:cave_offset + len(GUILD_RAID_MERCENARY_CAVE_BYTES)]
    )
    if current_cave != GUILD_RAID_MERCENARY_CAVE_BYTES:
        if (
            hashlib.sha256(current_cave).hexdigest()
            != GUILD_RAID_MERCENARY_CAVE_ORIGINAL_SHA256
        ):
            raise ValueError(
                f"Unexpected guild raid mercenary cave at "
                f"0x{GUILD_RAID_MERCENARY_CAVE_VADDR:x}: "
                f"sha256={hashlib.sha256(current_cave).hexdigest()}"
            )
        _write_bytes(
            buf,
            cave_offset,
            GUILD_RAID_MERCENARY_CAVE_BYTES,
            "guild raid mercenary cave",
        )
        changed += 1

    offset = seg_offset(GUILD_RAID_MERCENARY_SITE)
    replacement = encode_arm64_branch(
        GUILD_RAID_MERCENARY_SITE, GUILD_RAID_MERCENARY_CAVE_VADDR
    )
    current = bytes(buf[offset:offset + 4])
    if current not in (GUILD_RAID_MERCENARY_ORIGINAL, replacement):
        raise ValueError(
            f"Unexpected instruction at guild raid mercenary site "
            f"0x{GUILD_RAID_MERCENARY_SITE:x}: {current.hex()}"
        )
    if current != replacement:
        buf[offset:offset + 4] = replacement
        changed += 1

    # Client filter: let the player appear in the guild raid mercenary list.
    changed += _write_recycle_cave(
        buf,
        GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR,
        GUILD_RAID_MERCENARY_CLIENT_CAVE_BYTES,
        GUILD_RAID_MERCENARY_CLIENT_CAVE_ORIGINAL_SHA256,
    )
    hook_offset = seg_offset(GUILD_RAID_MERCENARY_CLIENT_HOOK)
    hook_replacement = encode_arm64_branch(
        GUILD_RAID_MERCENARY_CLIENT_HOOK, GUILD_RAID_MERCENARY_CLIENT_CAVE_VADDR
    )
    hook_current = bytes(buf[hook_offset:hook_offset + 4])
    if hook_current not in (
        GUILD_RAID_MERCENARY_CLIENT_HOOK_ORIGINAL,
        hook_replacement,
    ):
        raise ValueError(
            f"Unexpected client filter hook at 0x{GUILD_RAID_MERCENARY_CLIENT_HOOK:x}: "
            f"{hook_current.hex()}"
        )
    if hook_current != hook_replacement:
        buf[hook_offset:hook_offset + 4] = hook_replacement
        changed += 1
    return changed


def apply_guild_raid_reward_x10(buf: bytearray) -> int:
    """Multiplies the Guild Raid daily/weekly rank reward mails by 10.

    The two 8-entry tables in .rodata hold the reward id plus the item, gold and
    secondary item amounts delivered at settlement.  Only non-zero amounts are
    scaled; the reward ids and padding stay untouched.
    """
    changed = 0
    for table, rows in (
        (GUILD_RAID_DAILY_REWARD_TABLE, GUILD_RAID_DAILY_REWARDS),
        (GUILD_RAID_WEEKLY_REWARD_TABLE, GUILD_RAID_WEEKLY_REWARDS),
    ):
        for index, amounts in enumerate(rows):
            for field_index, original in enumerate(amounts):
                offset = (
                    table
                    + index * GUILD_RAID_REWARD_ENTRY_SIZE
                    + GUILD_RAID_REWARD_AMOUNT_OFFSETS[field_index]
                )
                current = struct.unpack_from("<i", buf, offset)[0]
                if original == 0:
                    if current != 0:
                        raise ValueError(
                            "Unexpected guild raid reward padding at "
                            f"0x{offset:x}: {current} (expected 0)"
                        )
                    continue
                scaled = original * 10
                if current == original:
                    struct.pack_into("<i", buf, offset, scaled)
                    changed += 1
                elif current == scaled:
                    continue
                else:
                    raise ValueError(
                        "Unexpected guild raid reward amount at "
                        f"0x{offset:x}: {current} "
                        f"(expected {original} or {scaled})"
                    )
    return changed


def validate_patch_options(options: PatchOptions) -> None:
    """Validate mutually exclusive feature combinations in ``PatchOptions``."""
    options.dev.validate()

    if options.alex_awakening and options.allow_unknown:
        raise ValueError("Alex Awakening requires the exact reference build; --force is unsupported.")

    if options.summon_rates and options.summon_rates_50_30_20:
        raise ValueError(
            "summon_rates (70/20/10) and summon_rates_50_30_20 (50/30/20) are "
            "mutually exclusive; enable only one summon profile."
        )

    if options.limit_break_cost_tenth and options.limit_break_cost_fixed:
        raise ValueError(
            "limit_break_cost_tenth (90% off) and limit_break_cost_fixed (flat "
            "1,000,000 gold + 100 materials) write the same table and are "
            "mutually exclusive; enable only one limit-break price."
        )



def apply_dev_instrumentation(
    so_buf: bytearray,
    dev: DevOptions,
    *,
    patch_count: int = 0,
) -> dict[str, int]:
    """Install requested dev instrumentation caves into a canonicalized SO buffer."""
    dev_marker = ""
    if dev.build_marker:
        dev_marker = dev_build_marker(APP_VERSION, dev.instrumentation(), patch_count)
    # Response logging lives in the exit cave, so it needs the timing hook installed.
    dev_timing = dev.handler_timing or dev.log_responses or dev.dev_endpoint
    results: dict[str, int] = {}
    if (
        dev.log_dispatch
        or dev.hit_counters
        or dev_marker
        or dev_timing
        or dev.log_responses
        or dev.dev_endpoint
    ):
        dispatch_key = (
            "dev_log_dispatch"
            if dev.log_dispatch
            else ("dev_build_marker" if dev_marker else "dev_dispatch_hook")
        )
        results[dispatch_key] = apply_dev_dispatch_log(
            so_buf,
            limit=dev.log_body_limit,
            version=APP_VERSION,
            counters=dev.hit_counters,
            log=dev.log_dispatch,
            marker=dev_marker,
            timing=dev_timing,
            capture_sret=dev.log_responses or dev.dev_endpoint,
            dev_dump=dev.dev_endpoint,
        )
    if dev_timing:
        response_tag = f"{DEV_RESPONSE_TAG}-v{APP_VERSION}" if dev.log_responses else ""
        results["dev_handler_timing"] = apply_dev_handler_timing(
            so_buf,
            version=APP_VERSION,
            response_tag=response_tag,
            limit=dev.log_body_limit,
            dev_dump=dev.dev_endpoint,
        )
    return results


def apply_all_patches(
    so_bytes: bytes,
    dex_bytes: bytes,
    options: PatchOptions,
    *,
    resource_contract: ResourceContract | None = None,
    apktool_jar: str | Path | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> PatchResult:
    """Applies selected patches after validating the input build and counts.

    By default only the supported 0.682 v1574 reference SO/DEX is accepted.
    ``PatchOptions.allow_unknown`` (CLI ``--force``) downgrades the hash
    mismatch to a warning, but every patch site still validates its original
    bytes and expected change count.

    ``resource_contract`` must describe the final internal
    ``fwt_resources_v1.zip`` when it was modified; the bootstrap DEX values are
    rewritten in the same smali pass as the English translation.
    """
    validate_cave_layout()
    validate_patch_options(options)

    needs_dex = (
        options.english_localization
        or options.lan_redirect
        or resource_contract is not None
    )
    so_sha, dex_sha, warnings = _validate_reference_hashes(
        so_bytes,
        dex_bytes,
        allow_unknown=options.allow_unknown,
        needs_dex=needs_dex,
    )

    if options.dev.instrumentation():
        pending = sorted(
            set(options.dev.instrumentation()) - IMPLEMENTED_DEV_INSTRUMENTATION
        )
        if pending:
            warnings.append(
                "Dev instrumentation requested but not implemented yet: "
                + ", ".join(pending)
                + " — this dev build is byte-identical to the release build."
            )
    if options.dev.log_commands.strip():
        warnings.append(
            "--dev-log-commands filtering is not implemented in-cave yet "
            "(ignored during patching; filter --dev-log captures offline with "
            "tools/dev_log_parse.py --cmd)."
        )

    so_buf, segment_mappings = canonicalize_segments(so_bytes, ELF_SEGMENTS)
    canonical_before = bytes(so_buf)
    dex_buf = bytearray(dex_bytes)
    counts: dict[str, int] = {}
    applied: list[str] = []

    def record(name: str, count: int, *, check_expected: bool = True) -> None:
        expected = EXPECTED_PATCH_COUNTS.get(name)
        if count < 0:
            raise ValueError(f"Patch {name} returned a negative change count")
        # Idempotent patches legitimately change zero rows on a second pass
        # when allow_unknown/--force is used on an already-patched binary.
        allow_zero = name in IDEMPOTENT_PATCHES
        if (
            so_sha == REFERENCE_SO_SHA256
            and check_expected
            and expected is not None
            and count != expected
            and not (allow_zero and count == 0)
        ):
            raise ValueError(
                f"Patch {name} changed {count} site(s), expected {expected} for the "
                "reference build. Aborting to avoid a partially-applied APK."
            )
        if count == 0 and not allow_zero:
            raise ValueError(
                f"Patch {name} did not change any site; the input layout is not supported."
            )
        counts[name] = count
        applied.append(name)

    if options.summon_rates:
        record("summon_rates", apply_summon_rates(so_buf, SUMMON_TARGETS))

    if options.summon_rates_50_30_20:
        record(
            "summon_rates_50_30_20",
            apply_summon_rates(so_buf, SUMMON_TARGETS_50_30_20),
        )

    if options.expedition_bonus:
        record("expedition_bonus", apply_expeditions(so_buf))

    if options.no_equip_drops:
        record("no_equip_drops", apply_no_equip_drops(so_buf))

    if options.gene_priority:
        record("gene_priority", apply_gene_priority(so_buf))

    if options.campaign_xp:
        record("campaign_xp", apply_campaign_xp(so_buf))

    if options.campaign_gold:
        record("campaign_gold", apply_campaign_gold_and_drops(so_buf))

    if options.campaign_shop_discount:
        record("campaign_shop_discount", apply_campaign_shop_discount(so_buf))

    if options.mode_drops_x10:
        record("mode_drops_x10", apply_mode_drops_x10(so_buf))

    if options.devil_boost_x10:
        record("devil_boost_x10", apply_devil_boost_x10(so_buf))

    if options.battle_arena_fix:
        record("battle_arena_fix", apply_battle_arena_fix(so_buf))

    if options.guild_raid_mercenary:
        record("guild_raid_mercenary", apply_guild_raid_self_mercenary(so_buf))

    if options.guild_raid_reward_x10:
        record("guild_raid_reward_x10", apply_guild_raid_reward_x10(so_buf))

    if options.event_discount:
        record("event_discount", apply_event_discount(so_buf))

    if options.event_gene_unlimited:
        record("event_gene_unlimited", apply_event_gene_unlimited(so_buf))

    if options.event_limits_daily:
        record("event_limits_daily", apply_event_limits_daily(so_buf))

    if options.mythical_stone_shop:
        record("mythical_stone_shop", apply_mythical_shop(so_buf))

    if options.hero_shop_offers:
        record("hero_shop_offers", apply_hero_shop_offers(so_buf))
    if options.surprise_transcendence_package:
        record("surprise_transcendence_package", apply_surprise_transcendence_package(so_buf, seg_offset))

    if options.costume_packages_all:
        record("costume_packages_all", apply_costume_packages(so_buf, seg_offset))

    if options.recycle_six_star:
        record("recycle_six_star", apply_recycle_six_star(so_buf))

    if options.coocoo_exp_x2:
        record("coocoo_exp_x2", apply_coocoo_exp_x2(so_buf))

    if options.coocoo_level_x2:
        record("coocoo_level_x2", apply_coocoo_level_x2(so_buf))

    if options.ship_parts_90_off:
        record("ship_parts_90_off", apply_ship_parts_90_off(so_buf))
    if options.worldboss_full_ship_repair:
        record("worldboss_full_ship_repair", apply_worldboss_full_ship_repair(so_buf))

    if options.crystal_skill_90_off:
        record("crystal_skill_90_off", apply_crystal_skill_90_off(so_buf))

    if options.gem_mining_x10:
        record("gem_mining_x10", apply_gem_mining_x10(so_buf))

    if options.gem_mining_types:
        record("gem_mining_types", apply_gem_mining_types(so_buf))

    if options.gem_level6:
        record("gem_level6", apply_gem_level6(so_buf))

    if options.gem_upgrade_gold_half:
        record("gem_upgrade_gold_half", apply_gem_upgrade_gold_half(so_buf))

    if options.stamina_cost_half:
        record("stamina_cost_half", apply_stamina_cost_half(so_buf))

    if options.stamina_potion_1000:
        record("stamina_potion_1000", apply_stamina_potion_1000(so_buf))

    if options.energy_flask_x10:
        record("energy_flask_x10", apply_energy_flask_x10(so_buf))
    if options.option_max_attributes:
        record("option_max_attributes", apply_option_max_attributes(so_buf))
    if options.rune_box_random_type:
        record("rune_box_random_type", apply_rune_box_random_type(so_buf))
    if options.rune_quality_factor:
        record(
            "rune_quality_factor",
            apply_rune_quality_factor(so_buf, options.rune_quality_factor),
        )
    if options.rune_box_random_roll:
        record("rune_box_random_roll", apply_rune_box_random_roll(so_buf))
    if options.equipment_lock_fix:
        record("equipment_lock_fix", apply_equipment_lock_fix(so_buf))

    if options.equipment_single_mod_stone:
        record(
            "equipment_single_mod_stone",
            apply_equipment_single_mod_stone(so_buf),
        )

    if options.equipment_percent_options:
        # The max-quality bias already rewrote every row of the same table, so
        # the number of flat weights still standing depends on that table state;
        # the inspector verifies the combined result structurally.
        record(
            "equipment_percent_options",
            apply_equipment_percent_options(so_buf),
            check_expected=not options.option_max_attributes,
        )

    if options.equipment_upgrade_10_guarantee:
        record(
            "equipment_upgrade_10_guarantee",
            apply_equipment_upgrade_10_guarantee(so_buf),
        )
    if options.limit_break_cost_tenth:
        record("limit_break_cost_tenth", apply_limit_break_cost_tenth(so_buf))
    if options.limit_break_cost_fixed:
        record("limit_break_cost_fixed", apply_limit_break_cost_fixed(so_buf))
    if options.limit_break_step_10:
        record("limit_break_step_10", apply_limit_break_step_10(so_buf))
    if options.soulgear_enchant_always:
        record("soulgear_enchant_always", apply_soulgear_enchant_always(so_buf))
    if options.rune_option_quality:
        record("rune_option_quality", apply_rune_option_quality(so_buf))
    if options.rune_upgrade_discount:
        record("rune_upgrade_discount", apply_rune_upgrade_discount(so_buf))

    # Bug fix, not an option: the embedded server never grants a cocoo box, so
    # the result payload must not advertise one.  Applied to every build.
    record("no_win_box", apply_no_win_box(so_buf))
    # Bug fix, not an option: prevent battle/expedition EXP overflow past
    # level_max and ensure un-transcended 6★ heroes return level_max == 70 for
    # LimitBreakCost lookup.
    record("hero_exp_cap", apply_hero_exp_cap(so_buf))
    # Bug fix, not an option: return -1 on non-hex item_code strings in
    # UtilFunc$$ConvertHexU32 instead of throwing FormatException and aborting
    # OnGetMyItemInfo before later items (e.g. Mythical Stones) are loaded.
    record("convert_hex_guard", apply_convert_hex_guard(so_buf, seg_offset))
    # Bug fix, not an option: the embedded server never implements
    # DUNGEON_RECOM_INFO, so the pre-battle mercenary auto-select has no
    # candidate list; answer it with the friend array the manual list uses.
    record("dungeon_recom_info", apply_dungeon_recom_info(so_buf, seg_offset))

    if options.gold_cylinder_x10:
        record("gold_cylinder_x10", apply_gold_cylinder_x10(so_buf))

    if options.mana_cylinder_x10:
        record("mana_cylinder_x10", apply_mana_cylinder_x10(so_buf))

    if options.event_coin_x10:
        record("event_coin_x10", apply_event_coin_x10(so_buf))

    if options.guild_raid_score_fix:
        record("guild_raid_score_fix", apply_guild_raid_score_fix(so_buf))

    if options.guild_raid_fire_support:
        record(
            "guild_raid_fire_support",
            apply_guild_raid_fire_support(so_buf, seg_offset),
        )

    if options.guild_raid_protection_persist:
        record(
            "guild_raid_protection_persist",
            apply_guild_raid_protection_persist(so_buf, seg_offset),
        )

    if options.alex_heros_mark:
        record(
            "alex_heros_mark",
            apply_alex_heros_mark_so(so_buf, seg_offset),
        )

    if options.merlin_auto_support:
        record(
            "merlin_auto_support",
            apply_merlin_auto_support(so_buf, seg_offset),
        )

    if options.trait_max_quality:
        record("trait_max_quality", apply_trait_max_quality(so_buf))

    if options.trait_allow_duplicates:
        record("trait_allow_duplicates", apply_trait_allow_duplicates(so_buf))

    if options.trait_multi_unique:
        record("trait_multi_unique", apply_trait_multi_unique(so_buf))

    if options.trait_immunity_weight_x2:
        record("trait_immunity_weight_x2", apply_trait_immunity_weight_x2(so_buf))

    if options.single_black_hammer:
        record("single_black_hammer", apply_single_black_hammer(so_buf))
    elif options.equipment_tier_upgrades:
        apply_single_black_hammer(so_buf)

    if options.single_gem_fang:
        record("single_gem_fang", apply_single_gem_fang(so_buf))

    if options.upgrade_no_fail_above_20:
        record("upgrade_no_fail_above_20", apply_high_upgrade_no_fail(so_buf))
    elif options.equipment_tier_upgrades:
        apply_high_upgrade_no_fail(so_buf)

    if options.equipment_tier_upgrades:
        record("equipment_tier_upgrades", apply_equipment_tiers(so_buf, seg_offset))

    if options.battle_arena_save_fix:
        record("battle_arena_save_fix", apply_battle_arena_save_fix(so_buf))

    # LAN redirect patches use the original DEX layout. Apply them before the
    # smali rebuild, which is free to move code and rebuild the string table.
    if options.lan_redirect:
        record(
            "lan_redirect",
            apply_lan_redirect(
                so_buf,
                dex_buf,
                server_ip=options.server_ip,
                server_port=options.server_port,
                force_english=options.english_localization,
            ),
        )

    if options.english_localization or resource_contract is not None:
        translation_count = apply_bootstrap_dex(
            dex_buf,
            translate=options.english_localization,
            contract=resource_contract,
            apktool_jar=apktool_jar,
            log_fn=log_fn,
        )
        if options.english_localization:
            english_count = apply_english_localization_so(so_buf)
            english_count += translation_count
            record("english_localization", english_count)
        if resource_contract is not None and log_fn is not None:
            log_fn(
                "Bundled resource contract updated: "
                f"SHA-256 {resource_contract.sha256_hex}, "
                f"{resource_contract.file_count} files, "
                f"{resource_contract.uncompressed_bytes} bytes"
            )

    for dev_key, dev_value in apply_dev_instrumentation(
        so_buf,
        options.dev,
        patch_count=len(applied) + (1 if options.alex_awakening else 0),
    ).items():
        record(dev_key, dev_value)

    # Raw byte patches must never resize the ELF.  The smali/bootstrap rebuild
    # legitimately changes the DEX size, so only enforce the DEX invariant when
    # no rebuild was requested.
    dex_rebuilt = options.english_localization or resource_contract is not None
    if len(so_buf) != len(so_bytes):
        raise RuntimeError(
            "Patch engine resized the native library; refusing to emit a corrupt ELF "
            f"(SO {len(so_bytes)} -> {len(so_buf)})"
        )
    if len(dex_buf) != len(dex_bytes) and not dex_rebuilt:
        raise RuntimeError(
            "Patch engine resized the DEX without a rebuild request; refusing to "
            f"emit a corrupt file (DEX {len(dex_bytes)} -> {len(dex_buf)})"
        )

    patched_so = project_segments(so_bytes, canonical_before, so_buf, segment_mappings)
    if options.alex_awakening:
        from core.alex_awakening import apply_alex_awakening

        patched_so = apply_alex_awakening(so_bytes, patched_so)
        record("alex_awakening", 1)
    return PatchResult(
        so_bytes=patched_so,
        dex_bytes=bytes(dex_buf),
        so_sha256=hashlib.sha256(patched_so).hexdigest(),
        dex_sha256=hashlib.sha256(dex_buf).hexdigest(),
        input_so_sha256=so_sha,
        input_dex_sha256=dex_sha,
        counts=counts,
        applied=applied,
        warnings=warnings,
    )

