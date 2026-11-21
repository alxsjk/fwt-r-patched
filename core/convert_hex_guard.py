"""Always-on non-hex guard for UtilFunc$$ConvertHexU32 (fixes KB-001).

When ``GET_MY_ITEM_INFO`` returns corrupted non-hex template rows (such as
``13000K`` or ``13000Y``) before later valid rows (such as ``2040031`` Mythical
Stones or ``200002`` Green Gems), stock ``UtilFunc$$ConvertHexU32`` throws a
``FormatException`` inside ``OnGetMyItemInfo``'s unguarded ``foreach`` loop and
aborts processing all remaining inventory items on restart.

This post-Covault client hook at ``0xAB3370`` -> cave ``0xB2B098`` patches
``UtilFunc$$ConvertHexU32+0x94`` (RVA ``0x0181178C``) so non-hex or >8-char
strings return ``-1`` cleanly without throwing, allowing ``InventoryItemData``
to skip invalid rows and load all subsequent items normally.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from functools import partial

from core.elf_mapping import read_load_segments, translate_vaddr

CAVE_VADDR = 0xB2B098
CAVE_BYTES = bytes.fromhex(
    "ff4301d1fd7b04a9f35303a9e10b02a9c805009013cd43f9330200b4090a8052"
    "0900ab72e90300b909408052e9c3ba72e90700b909020010e90700f9e00313aa"
    "81f182522130a07282050010e303009184008052a50500109b29fe97e10b42a9"
    "f35343a9fd7b44a9ff430191e303142ac0035fd6681240b9080300341f210071"
    "c802005469520091ea03082a2b2540786cc100519f250071a90000546b011b32"
    "6c8501519f150071880100544a050071e1feff5401028052e00313aae2031faa"
    "910c93d25123a0f20800009491f382d23130a0f2050000141400801211f482d2"
    "3130a0f201000014d005009010ce43f91002118b00021fd6e1031c32e00313aa"
    "e2031faa3360e697636f6e766572745f6865785f6775617264000000"
)
CAVE_SIZE = len(CAVE_BYTES)
CAVE_ORIGINAL_SHA256 = "0060c1a7dc2df91aa6a9ddfae25457d54e80090f19580b67a3fcffaaae9a5c60"

LATE_HOOK_SITE = 0xAB3370
LATE_HOOK_ORIGINAL = bytes.fromhex("e303142a")  # mov w3, w20

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
        raise ValueError("Unexpected or partially patched ConvertHexU32 guard code")
    return states[0]


def apply_convert_hex_guard(
    buf: bytearray, offset: Callable[[int], int] | None = None
) -> int:
    """Install the post-Covault ConvertHexU32 non-hex guard if stock."""
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


def inspect_convert_hex_guard(
    data: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> bool:
    """Verify the native hook and cave for the ConvertHexU32 non-hex guard."""
    try:
        if offset is None:
            segments = read_load_segments(data)
            offset = partial(translate_vaddr, segments)
        return _code_state(data, offset) == "patched"
    except (ValueError, IndexError, struct.error):
        return False
