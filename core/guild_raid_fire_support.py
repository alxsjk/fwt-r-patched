"""Strict reference-build patch for Guild Raid Fire Support QoL (07.06).

Combines:
1. Client datatable ``guildskilldata.unity3d`` row ``1048578`` (``0x100002``): sets
   ``_value01=1.0, _value01Factor=0.0, _value02=0.0, _value02Factor=0.0`` so Fire Support
   deals exact 100% maxHP damage to targeted minions regardless of DR or turn count.
2. Native post-Covault client hook at ``0xAB335C`` -> cave ``0xB2ABC0`` patching
   ``Player$$ExecuteReservedLordSkill+0x2b4`` (RVA ``0x018E7060``) at runtime: when Fire
   Support (``0x20000002``) is active/reserved with full gauge (``lordGauge >= 15``) on an
   even UI turn (0-based ``(GameStage$$get_currentTurnNo() & 1) == 1``, since HUD shows
   ``currentTurnNo + 1``), hold the reservation without casting so it auto-fires at the
   start of the next odd UI turn. All other Guild Raid skills retain normal immediate auto-fire.
"""
from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Callable
from functools import partial
from typing import Any

from core.elf_mapping import read_load_segments, translate_vaddr

GUILD_SKILL_DATA_CLIENT_ASSET_PATH = "files/Resources/datatable/guildskilldata.unity3d"
FIRE_SUPPORT_DAMAGE_EFFECT_ID = 1048578
FIRE_SUPPORT_STOCK_VALUES = (0.1, 0.01, 15000.0, 5000.0)
FIRE_SUPPORT_PATCHED_VALUES = (1.0, 0.0, 0.0, 0.0)
FIRE_SUPPORT_FIELDS = ("_value01", "_value01Factor", "_value02", "_value02Factor")

CAVE_VADDR = 0xB2ABC0
CAVE_BYTES = bytes.fromhex(
    "ff0301d1fd7b03a9f35302a9c80500b013cd43f9330200b4090a80520900ab72"
    "e90300b909408052e9c3ba72e90700b9e9010010e90700f9e00313aa010c8e52"
    "c131a07202070010e30300918400805225070010d22afe97f35342a9fd7b43a9"
    "ff03019180008052c0035fd6500080521000a4729f02106ba1020054ff4300d1"
    "e00300f9e0031faad00500b010ce43f9114980d2912ca0f21002118b00023fd6"
    "200100b4e1031faad00500b010ce43f911e783d2912ca0f21002118b00023fd6"
    "40020037e00340f9ff430091e103142ae2031faad00500b010ce43f911a18ed2"
    "f130a0f21002118b00023fd600010036d00500b010ce43f911648ed2d131a0f2"
    "1002118b00021fd6ff430091d00500b010ce43f991668ed2d131a0f21002118b"
    "00021fd6e103142ae2031faa2841fe97a0150037666972655f737570706f7274"
    "5f6f646400000000"
)
CAVE_SIZE = len(CAVE_BYTES)
CAVE_ORIGINAL_SHA256 = "28088fb932446b8d2bc49b41142ec541f8bd93a292947f4af9c62a4baded91ee"

LATE_HOOK_SITE = 0xAB335C
LATE_HOOK_ORIGINAL = bytes.fromhex("80008052")  # mov w0, #4

CAVES: tuple[tuple[int, bytes, str], ...] = (
    (CAVE_VADDR, CAVE_BYTES, CAVE_ORIGINAL_SHA256),
)
HOOKS: tuple[tuple[int, bytes, int], ...] = (
    (LATE_HOOK_SITE, LATE_HOOK_ORIGINAL, CAVE_VADDR),
)


def _branch_link(source: int, target: int) -> bytes:
    diff = target - source
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise ValueError("Unsupported ARM64 branch-link distance")
    return struct.pack("<I", 0x94000000 | ((diff >> 2) & 0x03FFFFFF))


def _code_state(data: bytes | bytearray, offset: Callable[[int], int]) -> str:
    states = []
    for addr, original, target in HOOKS:
        off = offset(addr)
        current = bytes(data[off:off + 4])
        states.append(
            "stock"
            if current == original
            else "patched"
            if current == _branch_link(addr, target)
            else "invalid"
        )
    for addr, payload, digest in CAVES:
        off = offset(addr)
        current = bytes(data[off:off + len(payload)])
        states.append(
            "stock"
            if hashlib.sha256(current).hexdigest() == digest
            else "patched"
            if current == payload
            else "invalid"
        )
    if len(set(states)) != 1 or states[0] == "invalid":
        raise ValueError("Unexpected or partially patched Guild Raid Fire Support code")
    return states[0]


def apply_guild_raid_fire_support(
    buf: bytearray, offset: Callable[[int], int] | None = None
) -> int:
    """Install the post-Covault odd-turn Fire Support client hook if stock."""
    if offset is None:
        segments = read_load_segments(buf)
        offset = partial(translate_vaddr, segments)
    state = _code_state(buf, offset)
    if state == "patched":
        return 0
    for addr, payload, _digest in CAVES:
        off = offset(addr)
        buf[off:off + len(payload)] = payload
    for addr, _original, target in HOOKS:
        off = offset(addr)
        buf[off:off + 4] = _branch_link(addr, target)
    return len(HOOKS) + len(CAVES)


def inspect_guild_raid_fire_support(
    data: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> bool:
    """Verify the native hook and cave for Guild Raid Fire Support."""
    try:
        if offset is None:
            segments = read_load_segments(data)
            offset = partial(translate_vaddr, segments)
        return _code_state(data, offset) == "patched"
    except (ValueError, IndexError, struct.error):
        return False


def patch_guildskilldata_rows(rows: list[dict[str, Any]]) -> int:
    """Patch effect 1048578 (Fire Support AddDamage) to exact 100% maxHp damage."""
    target = next(
        (
            row
            for row in rows
            if int(row.get("_guildSkillEffectId", -1)) == FIRE_SUPPORT_DAMAGE_EFFECT_ID
        ),
        None,
    )
    if target is None:
        raise ValueError(f"guildskilldata has no effect row {FIRE_SUPPORT_DAMAGE_EFFECT_ID}")

    current = tuple(float(target.get(field, float("nan"))) for field in FIRE_SUPPORT_FIELDS)
    if all(
        math.isclose(cur, patched, rel_tol=0.0, abs_tol=1e-6)
        for cur, patched in zip(current, FIRE_SUPPORT_PATCHED_VALUES, strict=True)
    ):
        return 0

    if not all(
        math.isclose(cur, stock, rel_tol=0.0, abs_tol=1e-4)
        for cur, stock in zip(current, FIRE_SUPPORT_STOCK_VALUES, strict=True)
    ):
        raise ValueError(
            f"Unexpected guildskilldata effect {FIRE_SUPPORT_DAMAGE_EFFECT_ID} values: {current}"
        )

    for field, patched in zip(FIRE_SUPPORT_FIELDS, FIRE_SUPPORT_PATCHED_VALUES, strict=True):
        target[field] = patched
    return len(FIRE_SUPPORT_FIELDS)


def inspect_guildskilldata_rows(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Check whether effect 1048578 carries the 100% maxHp values."""
    target = next(
        (
            row
            for row in rows
            if int(row.get("_guildSkillEffectId", -1)) == FIRE_SUPPORT_DAMAGE_EFFECT_ID
        ),
        None,
    )
    if target is None:
        return False, f"guildskilldata has no effect row {FIRE_SUPPORT_DAMAGE_EFFECT_ID}"

    values = tuple(float(target.get(field, float("nan"))) for field in FIRE_SUPPORT_FIELDS)
    active = all(
        math.isclose(cur, patched, rel_tol=0.0, abs_tol=1e-6)
        for cur, patched in zip(values, FIRE_SUPPORT_PATCHED_VALUES, strict=True)
    )
    details = (
        f"effect {FIRE_SUPPORT_DAMAGE_EFFECT_ID}: "
        + ", ".join(
            f"{field}={val:g}" for field, val in zip(FIRE_SUPPORT_FIELDS, values, strict=True)
        )
    )
    return active, details
