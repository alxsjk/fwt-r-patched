"""Strict reference-build patch for Absolute Protection persistence (07.09).

Makes the Guild Raid lord skill *Absolute Protection* (effect ``1048579``)
reduce every incoming hit on a protected ally until its native turn expiry,
instead of only the first hit per ally.

Mechanism (verified against the live decrypted 0.682 client pages — see
``output/guild-skill-research-2026-11-20.md``): every incoming hit runs
``GameRule::GetTargetReduceDamageRate`` →
``GuildSkillManager::UseDamageReduceEffect`` (client RVA ``0x1877BA8``),
whose per-hit consumption calls ``GuildSkillEffect::RemoveMultiTarget``
(``0x1BAAEBC``, call site RVA ``0x1877C60``) — permanently removing the
ally from the protected list before returning the stored rate for that
single hit. This patch swaps that one call site to the ABI-identical
non-destructive ``GuildSkillEffect::GetMultiTarget`` (``0x1BAADB8``), so
the shield ends only via the native turn expiry
(``GuildSkillManager::OnEndTurnCamp`` → ``RemoveGuildSkillEffect``).
Note: the decrypted dump at ``C:/tmp/fwt/handoff/libil2cpp.unido.so`` is
a **0.683.1** image; the 0.682 GuildSkillEffect cluster lives at
``0x1BA9xxx`` (as recorded in specs/009), not at the 0.683.1 layout.

Delivery follows the established post-Covault runtime patch pattern, hooked
mid-function at ``0xAB32F4`` (``mov w8, #1`` on the flow's common exit
path: the block at ``0xAB32EC`` closes the dump file and sets the
completion flag before the ``cbz w19`` at ``0xAB3304`` branches to the
fire-support site — every normal boot passes through this block), after
the il2cpp base cache is written at ``0xAB0064`` and in the same pass
where the neighboring client patches apply: the site is replaced by a
linked ``bl`` into a self-healing installer cave at
``0xB2AE18..0xB2AFDC`` (free tail of
``AbstractManglingParser::parseType``). The cave:

1. logs what it sees (``ap_diag pre base=%p word=%08x`` via the author's
   ``FwtLocalServer`` tag and ``__android_log_print`` PLT ``0xB464B0``),
2. asks ``PATCH_IL2CPP_HELPER`` (``0xAB575C``) to swap the single client
   word (validating the stock word first, exactly like every other
   runtime client patch),
3. re-reads the target: if the helper refused while the word still equals
   the stock value, the cave applies the patch itself — page-aligned via
   ``sysconf(_SC_PAGESIZE)`` (PLT ``0xB476C0``), ``mprotect`` RWX
   (``0xB476D0``), the word write, the icache flush helper (``0xB41794``),
   and ``mprotect`` RX back,
4. logs the outcome (``ap_diag post res=%d word=%08x``), restores
   ``x0``–``x5``/``x19``/``x20``/``x30``, replays the displaced
   ``mov w8, #1`` and returns to ``0xAB32F8``.

The self-healing step exists because two full-featured builds showed the
helper silently skipping this specific client word (no success or failure
log) while neighboring patches succeeded — the diagnostic log now pins
down what the helper actually saw at install time, and the direct-write
fallback guarantees the patch lands whenever the page carries the stock
word in plaintext.

**Site history (verified on device across three failed hooks)**:
1. the flow's final ``ret`` (``0xAB3398``) is DEAD CODE since feature 03.11
   hooked ``0xAB3394`` — that cave replays ``ldp x29, x30, [sp], #0x60``
   (restoring the caller's return address in ``x30``) and returns directly,
   never reaching the old ``ret``;
2. ``0xAB3348`` (``mov w8, #1`` in the ``0xAB3340`` block) is on a RARE
   exit path — the common path branches at ``0xAB3304``
   (``cbz w19, #0xab335c``) straight to the fire-support site, skipping the
   whole ``0xAB3308..0xAB3358`` range;
3. ``0xAB32F4`` is inside the common exit block (``0xAB32EC..0xAB3304``)
   that executes on every normal boot — the shipped site.

The immunity VFX/status removal after the first absorbed hit still runs
(cosmetic only; spec-approved edge case).
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from functools import partial

from core.elf_mapping import read_load_segments, translate_vaddr

CAVE_VADDR = 0xB2AE18
CAVE_BYTES = bytes.fromhex(
    "fd7bb8a9e00707a9e20f06a9e41705a9f35304a9f55b03a9f76302a9f96b01a9"
    "c80500b013cd43f9b30600b4540800107a008052985ac128974640b87542388b"
    "f60300b9f70700b9a40240b9c000805241080010a2080010e30315aa8f6d0094"
    "e00313aae103182ae2030091e31300912400805205090010332afe97f803002a"
    "a80240b91f01176b800200541f01166b41020054e004805204720094f60300aa"
    "e80316cbb902088ae00319aae10316aae200805201720094b70200b9e00315aa"
    "a11200912e5a0094e00319aae10316aaa2008052f9710094a40240b9c0008052"
    "c1030010a2040010e303182a6b6d00945a07007101faff5405000014c0008052"
    "c102001022040010646d0094f96b41a9f76342a9f55b43a9f35344a9e41745a9"
    "e20f46a9e00747a9fd7bc8a828008052c0035fd6607c870197cc0c9456cc0c94"
    "fca2ba01c30100541f2003d518a3ba01e10000541f2003d54677744c6f63616c"
    "53657276657200006170207072652025703d253038780000617020706f737420"
    "25643d2530387800617020626173653d3000000061705f736869656c645f7065"
    "7273697374000000"
)
CAVE_SIZE = len(CAVE_BYTES)
CAVE_ORIGINAL_SHA256 = "3f2a39e0373ae9fd2c42b2f41daffd4a7fc7f817bd00cd774615625851a4aa61"

LATE_HOOK_SITE = 0xAB32F4
LATE_HOOK_ORIGINAL = bytes.fromhex("28008052")  # mov w8, #1

CLIENT_RVA = 0x1877C60
REMOVE_MULTI_TARGET_VADDR = 0x1BAAEBC
GET_MULTI_TARGET_VADDR = 0x1BAADB8
CLIENT_EXPECTED_WORD = 0x940CCC97  # bl GuildSkillEffect::RemoveMultiTarget
CLIENT_REPLACEMENT_WORD = 0x940CCC56  # bl GuildSkillEffect::GetMultiTarget
EXPIRY_SKIP_RVA = 0x1BAA2FC
EXPIRY_SKIP_EXPECTED = 0x540001C3  # b.lo #0x1baa334 (skips 1048577..1048582)
EXPIRY_ID_RVA = 0x1BAA318
EXPIRY_ID_EXPECTED = 0x540000E1  # b.ne #0x1baa334 (restricts expiry to 1048583)
ARM64_NOP = 0xD503201F

CAVES: tuple[tuple[int, bytes, str], ...] = (
    (CAVE_VADDR, CAVE_BYTES, CAVE_ORIGINAL_SHA256),
)
HOOKS: tuple[tuple[int, bytes, int], ...] = (
    (LATE_HOOK_SITE, LATE_HOOK_ORIGINAL, CAVE_VADDR),
)


def _branch(source: int, target: int, *, link: bool) -> bytes:
    diff = target - source
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise ValueError("Unsupported ARM64 branch distance")
    opcode = 0x94000000 if link else 0x14000000
    return struct.pack("<I", opcode | ((diff >> 2) & 0x03FFFFFF))


def _code_state(data: bytes | bytearray, offset: Callable[[int], int]) -> str:
    states = []
    for addr, original, target in HOOKS:
        off = offset(addr)
        current = bytes(data[off:off + 4])
        states.append(
            "stock"
            if current == original
            else "patched"
            if current == _branch(addr, target, link=True)
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
        raise ValueError("Unexpected or partially patched Absolute Protection persistence code")
    return states[0]


def apply_guild_raid_protection_persist(
    buf: bytearray, offset: Callable[[int], int] | None = None
) -> int:
    """Install the post-Covault Absolute Protection persistence client patch if stock."""
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
        buf[off:off + 4] = _branch(addr, target, link=True)
    return len(HOOKS) + len(CAVES)


def inspect_guild_raid_protection_persist(
    data: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> bool:
    """Verify the native hook and cave for Absolute Protection persistence."""
    try:
        if offset is None:
            segments = read_load_segments(data)
            offset = partial(translate_vaddr, segments)
        return _code_state(data, offset) == "patched"
    except (ValueError, IndexError, struct.error):
        return False
