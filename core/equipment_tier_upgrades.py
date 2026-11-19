"""Verified native and client hooks for equipment tier completion."""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from functools import partial

from core.elf_mapping import read_load_segments, translate_vaddr

CAVES = (
    (0xB2A700, bytes.fromhex("ff4300d1f00300f90a050091b00340f9101640f91f0600f1c10100541f2900f18b0100541f3d00f1eb0000541f5100f1eb0000541f6900f1ca0000544a0380d204000014ea0180d2020000148a0280d2f00340f9ff4300915ab8fb17"), "5061c1a01982c86cbe0520584f74c0bf10a6e815514ad346bcf7cf848c8db372"),
    (0xB2A800, bytes.fromhex("ffc301d1fd7b05a9f35304a9c80500b013cd43f9090a80520900ab72e90300b909408052e9c3ba72e90700b981dc95526137a072e213001049070010e90700f9e00313aae303009184008052e5830091c32bfe9781f899526137a07222130010e9080010e90700f9e00313aae303009184008052e5830091b92bfe97815d9b526137a07262120010c90b0010e90700f9e00313aae303009184008052e5830091af2bfe9781759b526137a072a2110010490d0010e90700f9e00313aae303009184008052e5830091a52bfe9781a39a526137a072e2100010e3100010e00313aa24008052e58300919d2bfe9701da9a526137a0722210001023100010e00313aa24008052e5830091952bfe97f35344a9fd7b45a9ffc30191fd7bc6a8c0035fd6890e41b9015d4039e3031faa220500113f2900718b0100543f3d0071eb0000543f510071eb0000543f690071ca0000544203805204000014e20180520200001482028052d00500b010ce43f991de95d27137a0f21002118b00021fd6750300b440030037607e40f921008052698640f9090200b4090c41b93f290071ab0100543f3d0071eb0000543f510071eb0000543f690071ea0000544103805204000014e101805202000014810280522100094bd00500b010ce43f991fa99d27137a0f21002118b00021fd6d00500b010ce43f991149ad27137a0f21002118b00021fd6e00313aad00500b010ce43f911229ad27137a0f21002118b00023fd6e00313aad00500b010ce43f991d699d27137a0f21002118b00023fd6e00313aafd7b42a9d00500b010ce43f9915f9bd27137a0f21002118b00021fd6e00313aad00500b010ce43f911229ad27137a0f21002118b00023fd6e00313aad00500b010ce43f991d699d27137a0f21002118b00023fd6e00313aafd7b42a9d00500b010ce43f991779bd27137a0f21002118b00021fd6890e41b9015d4039e3031faa22050011150700b4e0060037607e40f9e1030032e00313aa88fdff97e00313aafd7b42a9e00313aa58fdff97e00313aafd7b42a9882240b928008052892240b929008052"), "d4a690b200f91ac459c1fc00311dcc4ff5b13e75fd4b5de8a5f3ab97f4efc6dd"),
)
HOOKS = (
    (0xA188BC, bytes.fromhex("0a050091"), 0xB2A700),
    (0xAB3394, bytes.fromhex("fd7bc6a8"), 0xB2A800),
)


def _branch(source: int, target: int) -> bytes:
    diff = target - source
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise ValueError("Unsupported ARM64 branch distance")
    return struct.pack("<I", 0x14000000 | ((diff >> 2) & 0x03FFFFFF))


def _state(data: bytes | bytearray, offset: Callable[[int], int]) -> str:
    states = []
    for addr, original, target in HOOKS:
        off = offset(addr)
        current = bytes(data[off:off + 4])
        states.append("stock" if current == original else "patched" if current == _branch(addr, target) else "invalid")
    for addr, payload, digest in CAVES:
        off = offset(addr)
        current = bytes(data[off:off + len(payload)])
        states.append("stock" if hashlib.sha256(current).hexdigest() == digest else "patched" if current == payload else "invalid")
    if len(set(states)) != 1 or states[0] == "invalid":
        raise ValueError("Unexpected or partially patched equipment tier code")
    return states[0]


def apply_equipment_tiers(buf: bytearray, offset: Callable[[int], int]) -> int:
    if _state(buf, offset) == "patched":
        return 0
    for addr, payload, _digest in CAVES:
        off = offset(addr)
        buf[off:off + len(payload)] = payload
    for addr, _original, target in HOOKS:
        off = offset(addr)
        buf[off:off + 4] = _branch(addr, target)
    return len(CAVES) + len(HOOKS)


def inspect_equipment_tiers(data: bytes | bytearray, offset: Callable[[int], int] | None = None) -> bool:
    try:
        if offset is None:
            offset = partial(translate_vaddr, read_load_segments(data))
        return _state(data, offset) == "patched"
    except (ValueError, IndexError, struct.error):
        return False
