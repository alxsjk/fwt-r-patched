"""Keystone generator for the Absolute Protection persistence installer cave (07.09).

Derives the frozen payload for ``core/guild_raid_protection_persist.py``:
a post-Covault installer hooked mid-function at ``0xAB32F4`` on the flow's common exit path
(``mov w8, #1``, inside the epilogue setup of
``patch_offline_convenience_flow``, after the il2cpp base cache is written
at ``0xAB0064``) that calls ``PATCH_IL2CPP_HELPER`` to swap the per-hit
consumption call inside ``GuildSkillManager::UseDamageReduceEffect``:

    client RVA 0x1877C60: bl GuildSkillEffect::RemoveMultiTarget (0x1BAAEBC)
                       -> bl GuildSkillEffect::GetMultiTarget     (0x1BAADB8)

so the damage-reduction shield stops being consumed by the first hit and
lasts until its native turn expiry.

Site history (why 0xAB3348): the final ``ret`` of the flow (``0xAB3398``)
is DEAD CODE since feature 03.11 hooked ``0xAB3394`` — that cave replays
``ldp x29, x30, [sp], #0x60`` (restoring the caller's return address in
``x30``) and returns directly, never reaching the old ``ret``. A hook there
never executes in full builds. Dev/test only: production ``core/`` carries
the frozen bytes; this tool re-derives them for verification.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

CAVE = 0xB2AE18  # free tail of AbstractManglingParser::parseType (0xB2AE18..0xB2B098)
LATE_HOOK = 0xAB32F4  # `mov w8, #1` on the flow's common exit path (before the cbz at 0xAB3304)
LATE_HOOK_ORIGINAL = bytes.fromhex("28008052")  # mov w8, #1

PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798  # written earlier in the flow at 0xAB0064
LOG_PRINT = 0xB464B0
SYSCONF = 0xB476C0
MPROTECT = 0xB476D0
CACHE_FLUSH = 0xB41794

# Reference 0.682 v1574 client RVAs (verified live: the decrypted pages of the
# running process at base 0x400022200000; C:/tmp/fwt/handoff/libil2cpp.unido.so
# is a 0.683.1 dump and must NOT be used for 0.682 addresses).
CLIENT_RVA = 0x1877C60  # bl RemoveMultiTarget inside UseDamageReduceEffect
REMOVE_MULTI_TARGET = 0x1BAAEBC
GET_MULTI_TARGET = 0x1BAADB8


def _branch_word(source: int, target: int, *, link: bool) -> int:
    diff = target - source
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise ValueError("Unsupported ARM64 branch distance")
    opcode = 0x94000000 if link else 0x14000000
    return opcode | ((diff >> 2) & 0x03FFFFFF)


def expected_client_word() -> int:
    """Stock word at the client site: bl RemoveMultiTarget."""
    return _branch_word(CLIENT_RVA, REMOVE_MULTI_TARGET, link=True)


def replacement_client_word() -> int:
    """Patched word at the client site: bl GetMultiTarget."""
    return _branch_word(CLIENT_RVA, GET_MULTI_TARGET, link=True)


def _imm32(reg: str, value: int) -> str:
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    lines = [f"movz {reg}, #{lo:#x}"]
    if hi:
        lines.append(f"movk {reg}, #{hi:#x}, lsl #16")
    return "\n        ".join(lines)


def generate() -> bytes:
    """Assemble the self-healing installer cave (mid-function bl hook).

    Beyond the PATCH_IL2CPP_HELPER call, the cave logs what it sees
    (pre/post words plus the helper result) and, if the helper refuses while
    the client word still matches the expected stock value, applies the
    patch itself (sysconf page align + mprotect RWX + write + icache flush +
    mprotect RX). Diagnostic output uses the author's FwtLocalServer tag so
    a failed attempt always leaves evidence in logcat.
    """
    page = IL2CPP_BASE_CACHE & ~0xFFF
    off = IL2CPP_BASE_CACHE & 0xFFF
    src = f"""
    installer_entry:
        stp x29, x30, [sp, #-0x60]!
        stp x0, x1, [sp, #0x50]
        stp x2, x3, [sp, #0x40]
        stp x4, x5, [sp, #0x30]
        stp x19, x20, [sp, #0x20]
        adrp x8, {page:#x}
        ldr x19, [x8, #{off:#x}]
        cbz x19, log_zero
        {_imm32('x9', CLIENT_RVA)}
        add x9, x19, x9
        ldr w10, [x9]
        mov w0, #6
        adr x1, log_tag
        adr x2, fmt_pre
        mov x3, x19
        mov w4, w10
        bl {LOG_PRINT:#x}
        mov x0, x19
        {_imm32('w1', CLIENT_RVA)}
        adr x2, expected_word
        adr x3, replacement_word
        mov w4, #1
        adr x5, hook_name
        bl {PATCH_IL2CPP_HELPER:#x}
        mov x20, x0
        ldr w10, [x9]
        adr x11, replacement_word
        ldr w11, [x11]
        cmp w10, w11
        b.eq log_post
        adr x12, expected_word
        ldr w12, [x12]
        cmp w10, w12
        b.ne log_post
        mov w0, #0x27
        bl {SYSCONF:#x}
        mov x15, x0
        neg x13, x15
        and x14, x9, x13
        mov x0, x14
        mov x1, x15
        mov w2, #7
        bl {MPROTECT:#x}
        adr x11, replacement_word
        ldr w11, [x11]
        str w11, [x9]
        mov x0, x9
        add x1, x9, #4
        bl {CACHE_FLUSH:#x}
        mov x0, x14
        mov x1, x15
        mov w2, #5
        bl {MPROTECT:#x}
    log_post:
        ldr w10, [x9]
        mov w0, #6
        adr x1, log_tag
        adr x2, fmt_post
        mov w3, w20
        mov w4, w10
        bl {LOG_PRINT:#x}
        ldp x19, x20, [sp, #0x20]
        ldp x4, x5, [sp, #0x30]
        ldp x2, x3, [sp, #0x40]
        ldp x0, x1, [sp, #0x50]
        ldp x29, x30, [sp], #0x60
        mov w8, #1
        ret
    log_zero:
        mov w0, #6
        adr x1, log_tag
        adr x2, fmt_zero
        bl {LOG_PRINT:#x}
        ldp x19, x20, [sp, #0x20]
        ldp x4, x5, [sp, #0x30]
        ldp x2, x3, [sp, #0x40]
        ldp x0, x1, [sp, #0x50]
        ldp x29, x30, [sp], #0x60
        mov w8, #1
        ret

    log_tag:
        .asciz "FwtLocalServer"
        .balign 4
    fmt_pre:
        .asciz "ap_diag pre base=%p word=%08x"
        .balign 4
    fmt_post:
        .asciz "ap_diag post res=%d word=%08x"
        .balign 4
    fmt_zero:
        .asciz "ap_diag base=0 skipped"
        .balign 4
    expected_word:
        .word {expected_client_word():#x}
    replacement_word:
        .word {replacement_client_word():#x}
    hook_name:
        .asciz "ap_shield_persist"
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
    print(f"EXPECTED_WORD={expected_client_word():#010x}")
    print(f"REPLACEMENT_WORD={replacement_client_word():#010x}")
    print(f"HOOK_BRANCH={_branch_word(LATE_HOOK, CAVE, link=True):#010x}")
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    data_start = len(payload) - 24  # 4-byte expected word + padded name literal
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
        hook_off = translate_vaddr(read_load_segments(so), LATE_HOOK)
        hook_word = struct.unpack_from("<I", so, hook_off)[0]
        print(f"HOOK_ORIGINAL_WORD={hook_word:#010x} (expect 0x52800028 mov w8, #1)")
        # Cross-check the client site against the live 0.682 memory dump
        # (dump-relative offset == RVA; base 0x400022200000 verified on device).
        live = Path("output/il2cpp_live_0682.bin")
        if live.exists():
            data = live.read_bytes()
            client = struct.unpack_from("<I", data, CLIENT_RVA)[0]
            print(f"CLIENT_WORD_LIVE_0682={client:#010x} (expect {expected_client_word():#010x})")


if __name__ == "__main__":
    main()
