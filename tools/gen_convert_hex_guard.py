"""Keystone generator for the ConvertHexU32 non-hex guard cave (KB-001)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

CAVE = 0xB2B098
LATE_HOOK = 0xAB3370
LATE_HOOK_ORIGINAL = bytes.fromhex("e303142a")  # mov w3, w20

PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798

RVA_CONVERT_HEX_HOOK = 0x0181178C
EXPECTED_WORDS = (0x321C03E1, 0xAA1303E0, 0xAA1F03E2, 0x97E66033)
RVA_CONVERT_TO_INT32 = 0x011A9864
RVA_CONVERT_HEX_RET_OK = 0x0181179C
RVA_CONVERT_HEX_RET_NEG1 = 0x018117A0


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
    """Assemble the 0xB2B098 installer + runtime ConvertHexU32 non-hex guard cave."""
    page = IL2CPP_BASE_CACHE & ~0xFFF
    off = IL2CPP_BASE_CACHE & 0xFFF
    src = f"""
    installer_entry:
        sub sp, sp, #0x50
        stp x29, x30, [sp, #0x40]
        stp x19, x20, [sp, #0x30]
        stp x1, x2, [sp, #0x20]
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
        {_imm32('w1', RVA_CONVERT_HEX_HOOK)}
        adr x2, expected_words
        mov x3, sp
        mov w4, #4
        adr x5, hook_name
        bl {PATCH_IL2CPP_HELPER:#x}
    installer_done:
        ldp x1, x2, [sp, #0x20]
        ldp x19, x20, [sp, #0x30]
        ldp x29, x30, [sp, #0x40]
        add sp, sp, #0x50
        mov w3, w20
        ret

    handler:
        ldr w8, [x19, #0x10]
        cbz w8, invalid_hex
        cmp w8, #8
        b.hi invalid_hex
        add x9, x19, #0x14
        mov w10, w8
    loop_char:
        ldrh w11, [x9], #2
        sub w12, w11, #0x30
        cmp w12, #9
        b.ls next_char
        orr w11, w11, #0x20
        sub w12, w11, #0x61
        cmp w12, #5
        b.hi invalid_hex
    next_char:
        subs w10, w10, #1
        b.ne loop_char

        mov w1, #0x10
        mov x0, x19
        mov x2, xzr
        {_call_rva(RVA_CONVERT_TO_INT32, link=True)}
        {_call_rva(RVA_CONVERT_HEX_RET_OK, link=False)}

    invalid_hex:
        mov w20, #-1
        {_call_rva(RVA_CONVERT_HEX_RET_NEG1, link=False)}

    call_rva:
        adrp x16, {page:#x}
        ldr x16, [x16, #{off:#x}]
        add x16, x16, x17
        br x16

    expected_words:
        .word {EXPECTED_WORDS[0]:#x}, {EXPECTED_WORDS[1]:#x}, {EXPECTED_WORDS[2]:#x}, {EXPECTED_WORDS[3]:#x}
    hook_name:
        .asciz "convert_hex_guard"
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
