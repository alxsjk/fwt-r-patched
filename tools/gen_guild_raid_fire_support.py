"""Keystone generator for the Guild Raid Fire Support odd-turn auto-cast cave."""
from __future__ import annotations

import hashlib
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

CAVE = 0xB2ABC0
LATE_HOOK = 0xAB335C
LATE_HOOK_ORIGINAL = bytes.fromhex("80008052")  # mov w0, #4

PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798

RVA_EXEC_RESERVED_HOOK = 0x018E7060
EXPECTED_WORDS = (0x2A1403E1, 0xAA1F03E2, 0x97FE4128, 0x370015A0)
RVA_GAME_STAGE_GET_INSTANCE = 0x01640248
RVA_GAME_STAGE_GET_TURN_NO = 0x01641F38
RVA_GUILD_SKILL_MGR_ACTION = 0x01877508
RVA_EXEC_RESERVED_TRUE = 0x018E7320
RVA_EXEC_RESERVED_FALSE = 0x018E7334

FIRE_SUPPORT_SKILL_ID = 0x20000002


def _imm32(reg: str, value: int) -> str:
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    lines = [f"movz {reg}, #{lo:#x}"]
    if hi:
        lines.append(f"movk {reg}, #{hi:#x}, lsl #16")
    return "\n        ".join(lines)


def _jump_rva(rva: int, *, link: bool) -> str:
    page = IL2CPP_BASE_CACHE & ~0xFFF
    off = IL2CPP_BASE_CACHE & 0xFFF
    op = "blr" if link else "br"
    return (
        f"adrp x16, {page:#x}\n        "
        f"ldr x16, [x16, #{off:#x}]\n        "
        f"{_imm32('x17', rva)}\n        "
        f"add x16, x16, x17\n        "
        f"{op} x16"
    )


def generate() -> bytes:
    """Assemble the 0xB2ABC0 installer + runtime odd-turn gate cave."""
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
        {_imm32('w1', RVA_EXEC_RESERVED_HOOK)}
        adr x2, expected_words
        mov x3, sp
        mov w4, #4
        adr x5, hook_name
        bl {PATCH_IL2CPP_HELPER:#x}
    installer_done:
        ldp x19, x20, [sp, #0x20]
        ldp x29, x30, [sp, #0x30]
        add sp, sp, #0x40
        mov w0, #4
        ret

    handler:
        {_imm32('w16', FIRE_SUPPORT_SKILL_ID)}
        cmp w20, w16
        b.ne do_action

        sub sp, sp, #0x10
        str x0, [sp]

        mov x0, xzr
        {_jump_rva(RVA_GAME_STAGE_GET_INSTANCE, link=True)}
        cbz x0, fail_open_stage

        mov x1, xzr
        {_jump_rva(RVA_GAME_STAGE_GET_TURN_NO, link=True)}
        // get_currentTurnNo() is 0-based (HUD displays turnNo + 1):
        // bit 0 == 1 means even UI turns (2, 4, 6...) -> hold.
        tbnz w0, #0, hold_even_turn

    fail_open_stage:
        ldr x0, [sp]
        add sp, sp, #0x10

    do_action:
        mov w1, w20
        mov x2, xzr
        {_jump_rva(RVA_GUILD_SKILL_MGR_ACTION, link=True)}
        tbz w0, #0, ret_false
        {_jump_rva(RVA_EXEC_RESERVED_TRUE, link=False)}

    hold_even_turn:
        add sp, sp, #0x10
    ret_false:
        {_jump_rva(RVA_EXEC_RESERVED_FALSE, link=False)}

    expected_words:
        .word {EXPECTED_WORDS[0]:#x}, {EXPECTED_WORDS[1]:#x}, {EXPECTED_WORDS[2]:#x}, {EXPECTED_WORDS[3]:#x}
    hook_name:
        .asciz "fire_support_odd"
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
    data_start = len(payload) - (16 + 20)
    for ins in md.disasm(payload[:data_start], CAVE):
        print(f"  0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}")

    apk_path = Path("source/fwt_0.682_offline_v1574.apk")
    if apk_path.exists():
        import zipfile

        from core.elf_mapping import read_load_segments, translate_vaddr

        with zipfile.ZipFile(apk_path, "r") as zf:
            so = zf.read("lib/arm64-v8a/libfwt_local_server.so")
        off = translate_vaddr(read_load_segments(so), CAVE)
        orig = so[off : off + len(payload)]
        print(f"ORIG_SHA256={hashlib.sha256(orig).hexdigest()}")


if __name__ == "__main__":
    main()
