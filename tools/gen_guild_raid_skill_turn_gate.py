"""Keystone generator for the Guild Raid lord-skill per-turn auto-cast gate cave.

Feature 07.10 (`guild_raid_skill_turn_gate`). Emits the payload for cave
``0xB30990`` (free tail of ``AbstractManglingParser::parseEncoding``):

1. ``installer_entry`` runs once at boot from the late epilogue word
   ``0xAB3374`` (``mov w4, w19`` -> ``bl`` into the cave, replaying the word
   on exit). It validates the four stock client words at
   ``Player$$ExecuteReservedLordSkill`` RVA ``0x018E6FF0`` and swaps them for
   the stack-composed 4-word absolute stub into ``handler`` via
   ``PATCH_IL2CPP_HELPER``.
2. ``handler`` replays the displaced block
   (``mov w0,w20 / mov x1,xzr / bl 0x17edd98 / tbnz w0,#0 -> hold``), then
   gates the three non-Fire-Support guild skills against the 16-byte state
   slot at ``0xBE62C8`` (``{GameStage instance, currentTurnNo, cast bitmask}``):
   instance or turn change resets the mask, a set bit holds the cast at
   ``0x018E7334`` (reservation kept, gauge undrained), an unset bit is marked
   and the flow resumes at ``0x018E7000`` — straight into the stock manager
   reload and the 07.06 Fire Support stub, which stays byte-identical.
   ``d == 1`` (Fire Support) and ``d > 3`` (unexpected id) pass through
   unmarked; a null ``GameStage::get_instance`` fails open to stock.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

CAVE = 0xB30990
LATE_HOOK = 0xAB3374
LATE_HOOK_ORIGINAL = bytes.fromhex("e403132a")  # mov w4, w19

PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798

RVA_GATE_SITE = 0x018E6FF0
EXPECTED_WORDS = (0x2A1403E0, 0xAA1F03E1, 0x97FC1B68, 0x370019C0)
RVA_STOCK_GATE_CALL = 0x17EDD98
RVA_HOLD = 0x018E7334
RVA_RESUME = 0x018E7000
RVA_GAME_STAGE_GET_INSTANCE = 0x01640248
RVA_GAME_STAGE_GET_TURN = 0x01641F38

STATE_PAGE = 0xBE6000
STATE_OFF = 0x2C8  # 0xBE62C8: instance (8B), turn (4B), mask (4B)
SKILL_ID_BASE = 0x20000001  # d=0 Shelling, 1 Fire Support, 2 Absolute Protection, 3 Combat Support


def _imm32(reg: str, value: int) -> str:
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    lines = [f"movz {reg}, #{lo:#x}"]
    if hi:
        lines.append(f"movk {reg}, #{hi:#x}, lsl #16")
    return "\n        ".join(lines)


def _call_rva(rva: int, *, link: bool) -> str:
    op = "bl" if link else "b"
    return f"{_imm32('x17', rva)}\n        {op} call_rva"


def generate() -> bytes:
    """Assemble the 0xB30990 installer + runtime per-turn gate cave."""
    page = IL2CPP_BASE_CACHE & ~0xFFF
    off = IL2CPP_BASE_CACHE & 0xFFF
    src = f"""
    installer_entry:
        sub sp, sp, #0x40
        stp x29, x30, [sp, #0x30]
        stp x19, x20, [sp, #0x20]
        adrp x8, {page:#x}
        ldr x19, [x8, #{off:#x}]
        cbz x19, installer_done
        movz w9, #0x0050
        movk w9, #0x5800, lsl #16
        str w9, [sp]
        movz w9, #0x0200
        movk w9, #0xd61f, lsl #16
        str w9, [sp, #4]
        adr x9, handler
        str x9, [sp, #8]
        mov x0, x19
        {_imm32('w1', RVA_GATE_SITE)}
        adr x2, expected_words
        mov x3, sp
        mov w4, #4
        adr x5, hook_name
        bl {PATCH_IL2CPP_HELPER:#x}
    installer_done:
        ldp x19, x20, [sp, #0x20]
        ldp x29, x30, [sp, #0x30]
        add sp, sp, #0x40
        mov w4, w19
        ret

    handler:
        mov w0, w20
        mov x1, xzr
        {_call_rva(RVA_STOCK_GATE_CALL, link=True)}
        tbnz w0, #0, local_hold

        {_imm32('w9', SKILL_ID_BASE)}
        sub w8, w20, w9
        cmp w8, #3
        b.hi resume_stock
        cmp w8, #1
        b.eq resume_stock

        mov x0, xzr
        {_call_rva(RVA_GAME_STAGE_GET_INSTANCE, link=True)}
        cbz x0, resume_stock

        adrp x9, {STATE_PAGE:#x}
        add x9, x9, #{STATE_OFF:#x}
        ldr x10, [x9]
        cmp x10, x0
        b.eq same_instance
        str x0, [x9]
        str wzr, [x9, #12]
        {_call_rva(RVA_GAME_STAGE_GET_TURN, link=True)}
        str w0, [x9, #8]
        b mask_check
    same_instance:
        {_call_rva(RVA_GAME_STAGE_GET_TURN, link=True)}
        ldr w10, [x9, #8]
        cmp w10, w0
        b.eq mask_check
        str w0, [x9, #8]
        str wzr, [x9, #12]
    mask_check:
        cmp w8, #0
        b.eq bit_zero
        sub w8, w8, #1
        mov w10, #1
        lsl w10, w10, w8
        b have_bit
    bit_zero:
        mov w10, #1
    have_bit:
        ldr w11, [x9, #12]
        tst w11, w10
        b.ne local_hold
        orr w11, w11, w10
        str w11, [x9, #12]
    resume_stock:
        {_call_rva(RVA_RESUME, link=False)}
    local_hold:
        {_call_rva(RVA_HOLD, link=False)}

    call_rva:
        adrp x16, {page:#x}
        ldr x16, [x16, #{off:#x}]
        add x16, x16, x17
        br x16

    expected_words:
        .word {EXPECTED_WORDS[0]:#x}, {EXPECTED_WORDS[1]:#x}, {EXPECTED_WORDS[2]:#x}, {EXPECTED_WORDS[3]:#x}
    hook_name:
        .asciz "guild_skill_turn_gate"
        .balign 4
    """
    raw, count = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(src, addr=CAVE)
    if not count or raw is None:
        raise RuntimeError("Keystone assembly failed")
    return bytes(raw)


def main() -> None:
    payload = generate()
    print(f"CAVE=0x{CAVE:x} size={len(payload)} end=0x{CAVE + len(payload):x}")
    print(f"HEX={payload.hex()}")
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    data_start = len(payload) - (16 + 24)
    for ins in md.disasm(payload[:data_start], CAVE):
        print(f"  0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}")

    import os
    import zipfile

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.elf_mapping import read_load_segments, translate_vaddr

    so_path = os.environ.get("FWT_LOCAL_SO")
    if so_path:
        so = Path(so_path).read_bytes()
    else:
        apk_path = Path(__file__).resolve().parent.parent / "source/fwt_0.682_offline_v1574.apk"
        with zipfile.ZipFile(apk_path, "r") as zf:
            so = zf.read("lib/arm64-v8a/libfwt_local_server.so")
    segments = read_load_segments(so)
    cave_off = translate_vaddr(segments, CAVE)
    orig = so[cave_off : cave_off + len(payload)]
    print(f"ORIG_SHA256={hashlib.sha256(orig).hexdigest()}")
    print(f"ORIG_SHA256_FULL_RANGE=0x{CAVE:x}..0x{CAVE + len(payload):x}")


if __name__ == "__main__":
    main()
