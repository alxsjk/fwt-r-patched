"""Strict reference-build patch for eligible owned-costume package rewards.

Generated ARM64 payloads are maintained by tools/gen_owned_costume_caves.py
and tools/gen_costume_claim_hook_v3.py; production has no Keystone dependency.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from functools import partial

from core.costume_package_limits import apply_costume_package_limits, inspect_costume_package_limits
from core.elf_mapping import read_load_segments, translate_vaddr

CAVES: tuple[tuple[int, bytes, str], ...] = (
    (0xB2A3AC, bytes.fromhex("ffc300d1ed3b00a9ef4301a9f11300f911423bd5ef031daaed0540f92effff1090e592d23003a0f2ce0110cbbf010eebe1030054ef0140f9ef2102d1ed014039bf29007141030054ed1140b8eea686522ea6a672bf010e6b20010054eea686522e06a772bf010e6b21020054ed154039bfd90071c101005405000014ed154039bfc10071400000540900001411421bd5ed3b40a9ef4341a9f11340f9ffc30091eb2300f9f40316aa9668f91711421bd5ed3b40a9ef4341a9f11340f9ffc3009194a50b9b8f68f917"), "60771df02628a9fe5ea968dd2bac1de15550ae110e0fa907d1adc13aaab53ee9"),
    (0xB2A4AC, bytes.fromhex("ffc300d1ed3b00a9ef4301a9f11300f911423bd5ef031daaed0540f92effff10900593d23003a0f2ce0110cbbf010eeb41030054ef0140f9ef2102d1ed014039bf290071a1020054ed1140b8eea686522ea6a672bf010e6b20010054eea686522e06a772bf010e6b81010054ed154039bfd900712101005405000014ed154039bfc100714000005404000014f03b40f99f0210eb0201005411421bd5ed3b40a9ef4341a9f11340f9ffc30091080380525868f91711421bd5ed3b40a9ef4341a9f11340f9ffc300915868f917"), "31368080e019814eaa6cbb8b14250e8e3de66c52a403ffc30066492e1b1de692"),
    (0xB2A5AC, bytes.fromhex("ff8301d1fd7b04a9c80500b000cd43f981088b52412ca07242ffff1042c00191090a80520900ab72e90300b909408052e9c3ba72e90700b949feff1029010291e90700f9e303009184008052e5830091582cfe97fd7b44a9ff830191fc0b40f96223fe1700000000000000000000000086831794e8030032f503192af803132aff8300d1d00500b010ce43f991cb8cd21138a0f21002118b00023fd6ed3b00a90d423bd5ed0b00f94d3340b9ceb184522e00a072bf010e6ba00000544eb684522e00a072bf010e6b41000054e0031faaed0b40f90d421bd5ed3b40a9ff83009128008052f503192af803132ad00500b010ce43f911098bd2512ca0f21e02118b313200911002118b00021fd6"), "80987c9030f6a093c85a831133bc786456f280e7a3ce2ef28bc11a955c0b1578"),
)
HOOKS = (
    (0x9846A8, bytes.fromhex("94a50b9b"), 0xB2A3AC),
    (0x9846B8, bytes.fromhex("08038052"), 0xB2A4AC),
    (0xAB3390, bytes.fromhex("fc0b40f9"), 0xB2A5AC),
)


def _branch(source: int, target: int) -> bytes:
    diff = target - source
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise ValueError("Unsupported ARM64 branch distance")
    return struct.pack("<I", 0x14000000 | ((diff >> 2) & 0x03FFFFFF))


def _code_state(data: bytes | bytearray, offset: Callable[[int], int]) -> str:
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
        raise ValueError("Unexpected or partially patched costume package code")
    return states[0]


def apply_costume_packages(buf: bytearray, offset: Callable[[int], int]) -> int:
    """Apply the complete patch only if every original site is recognized."""
    state = _code_state(buf, offset)
    trial = bytearray(buf)
    limit_changes = apply_costume_package_limits(trial)
    if (state == "stock" and limit_changes != 4) or (state == "patched" and limit_changes != 0):
        raise ValueError("Mixed costume package code and catalog state")
    if state == "patched":
        return 0
    for addr, payload, _digest in CAVES:
        off = offset(addr)
        trial[off:off + len(payload)] = payload
    for addr, _original, target in HOOKS:
        off = offset(addr)
        trial[off:off + 4] = _branch(addr, target)
    buf[:] = trial
    return 10


def inspect_costume_packages(
    data: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> bool:
    """Independently inspect all native code and catalog sites on the input ELF."""
    try:
        if offset is None:
            segments = read_load_segments(data)
            offset = partial(translate_vaddr, segments)
        return (_code_state(data, offset) == "patched"
                and inspect_costume_package_limits(data))
    except (ValueError, IndexError, struct.error):
        return False
