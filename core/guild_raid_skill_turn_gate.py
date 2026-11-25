"""Strict reference-build patch for the Guild Raid lord-skill turn gate (07.10).

Combines a single native post-Covault client hook with a 16-byte RW state slot:

1. Late epilogue site ``0xAB3374`` (``mov w4, w19`` -> ``bl`` cave) installs,
   via ``PATCH_IL2CPP_HELPER`` (``0xAB575C``), the 4-word absolute stub over
   ``Player$$ExecuteReservedLordSkill`` RVA ``0x018E6FF0`` (stock words
   ``0x2A1403E0, 0xAA1F03E1, 0x97FC1B68, 0x370019C0`` — the last stock hold
   gate ``mov w0,w20 / mov x1,xzr / bl 0x17edd98 / tbnz w0,#0 -> hold``).
2. The runtime body replays that block, then gates the three non-Fire-Support
   guild skills (``0x20000001`` Guild Shelling, ``0x20000003`` Absolute
   Protection, ``0x20000004`` Combat Support) against the state slot at
   ``0xBE62C8`` (``{GameStage instance, currentTurnNo, cast bitmask}``,
   page-mapped RW tail after ``alex_awakening_scratch``): instance or turn
   change resets the mask; a set bit holds the cast at ``0x018E7334``
   (reservation kept, gauge undrained) until the turn advances; an unset bit
   is marked and the flow resumes at ``0x018E7000`` into the stock manager
   reload and the 07.06 Fire Support stub, which stays byte-identical.
   Fire Support (``d == 1``) and unexpected ids pass through unmarked; a null
   ``GameStage::get_instance`` fails open to stock behavior.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from functools import partial

from core.elf_mapping import read_load_segments, translate_vaddr

CAVE_VADDR = 0xB30990
CAVE_BYTES = bytes.fromhex(
    "ff0301d1fd7b03a9f35302a9880500f013cd43f9330200b4090a80520900ab72e90300b90940"
    "8052e9c3ba72e90700b9e9010010e90700f9e00313aa01fe8d52c131a072c2080010e3030091"
    "84008052e50800105e13fe97f35342a9fd7b43a9ff030191e403132ac0035fd6e003142ae103"
    "1faa11b39bd2d12fa0f23400009400060037290080520900a4728802094b1f0d007108050054"
    "1f050071c0040054e0031faa114980d2912ca0f228000094200400b4a90500d029210b912a01"
    "40f95f0100eb00010054200100f93f0d00b911e783d2912ca0f21d000094200900b909000014"
    "11e783d2912ca0f2180000942a0940b95f01006b60000054200900b93f0d00b91f010071a000"
    "0054080500512a0080524a21c81a020000142a0080522b0d40b97f010a6ac10000546b010a2a"
    "2b0d00b911008ed2d131a0f20400001491668ed2d131a0f201000014900500f010ce43f91002"
    "118b00021fd6e003142ae1031faa681bfc97c01900376775696c645f736b696c6c5f7475726e"
    "5f67617465000000"
)
CAVE_SIZE = len(CAVE_BYTES)
CAVE_ORIGINAL_SHA256 = "f051ae887bc845df610cee13e3e5f8668d9db727b6386fcd9bba347a29ed0bbd"

LATE_HOOK_SITE = 0xAB3374
LATE_HOOK_ORIGINAL = bytes.fromhex("e403132a")  # mov w4, w19

STATE_SLOT_VADDR = 0xBE62C8
STATE_SLOT_SIZE = 16  # instance (8B), currentTurnNo (4B), cast bitmask (4B)

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
        raise ValueError("Unexpected or partially patched Guild Raid skill turn gate code")
    return states[0]


def apply_guild_raid_skill_turn_gate(
    buf: bytearray, offset: Callable[[int], int] | None = None
) -> int:
    """Install the post-Covault lord-skill per-turn gate client hook if stock."""
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


def inspect_guild_raid_skill_turn_gate(
    data: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> bool:
    """Verify the native hook and cave for the Guild Raid skill turn gate."""
    try:
        if offset is None:
            segments = read_load_segments(data)
            offset = partial(translate_vaddr, segments)
        return _code_state(data, offset) == "patched"
    except (ValueError, IndexError, struct.error):
        return False
