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
EXPIRY_SKIP_RVA = 0x1BAA2FC  # b.lo #0x1baa334 inside GuildSkillEffect::OnEndTurnCamp
EXPIRY_SKIP_EXPECTED = 0x540001C3
EXPIRY_ID_RVA = 0x1BAA318  # b.ne #0x1baa334 inside GuildSkillEffect::OnEndTurnCamp
EXPIRY_ID_EXPECTED = 0x540000E1
ARM64_NOP = 0xD503201F


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


def generate() -> bytes:
    """Assemble the self-healing installer cave (mid-function bl hook).

    Uses a 3-entry table and callee-saved registers (x19..x26) across every
    PLT/helper call to patch:
      1. 0x1877C60: bl RemoveMultiTarget -> bl GetMultiTarget (multi-hit DR)
      2. 0x1BAA2FC: b.lo -> nop (include 1048579 in GuildSkillEffect::OnEndTurnCamp)
      3. 0x1BAA318: b.ne -> nop (allow 1048579 turn-end expiry at System0 end)
    """
    page = IL2CPP_BASE_CACHE & ~0xFFF
    off = IL2CPP_BASE_CACHE & 0xFFF
    src = f"""
    installer_entry:
        stp x29, x30, [sp, #-0x80]!
        stp x0, x1, [sp, #0x70]
        stp x2, x3, [sp, #0x60]
        stp x4, x5, [sp, #0x50]
        stp x19, x20, [sp, #0x40]
        stp x21, x22, [sp, #0x30]
        stp x23, x24, [sp, #0x20]
        stp x25, x26, [sp, #0x10]
        adrp x8, {page:#x}
        ldr x19, [x8, #{off:#x}]
        cbz x19, log_zero

        adr x20, patch_table
        mov w26, #3
    loop_table:
        ldp w24, w22, [x20], #8
        ldr w23, [x20], #4
        add x21, x19, w24, uxtw
        str w22, [sp]
        str w23, [sp, #4]

        ldr w4, [x21]
        mov w0, #6
        adr x1, log_tag
        adr x2, fmt_pre
        mov x3, x21
        bl {LOG_PRINT:#x}

        mov x0, x19
        mov w1, w24
        mov x2, sp
        add x3, sp, #4
        mov w4, #1
        adr x5, hook_name
        bl {PATCH_IL2CPP_HELPER:#x}
        mov w24, w0

        ldr w8, [x21]
        cmp w8, w23
        b.eq patch_log_post
        cmp w8, w22
        b.ne patch_log_post

        mov w0, #0x27
        bl {SYSCONF:#x}
        mov x22, x0
        neg x8, x22
        and x25, x21, x8
        mov x0, x25
        mov x1, x22
        mov w2, #7
        bl {MPROTECT:#x}
        str w23, [x21]
        mov x0, x21
        add x1, x21, #4
        bl {CACHE_FLUSH:#x}
        mov x0, x25
        mov x1, x22
        mov w2, #5
        bl {MPROTECT:#x}

    patch_log_post:
        ldr w4, [x21]
        mov w0, #6
        adr x1, log_tag
        adr x2, fmt_post
        mov w3, w24
        bl {LOG_PRINT:#x}

        subs w26, w26, #1
        b.ne loop_table
        b exit_ok

    log_zero:
        mov w0, #6
        adr x1, log_tag
        adr x2, fmt_zero
        bl {LOG_PRINT:#x}

    exit_ok:
        ldp x25, x26, [sp, #0x10]
        ldp x23, x24, [sp, #0x20]
        ldp x21, x22, [sp, #0x30]
        ldp x19, x20, [sp, #0x40]
        ldp x4, x5, [sp, #0x50]
        ldp x2, x3, [sp, #0x60]
        ldp x0, x1, [sp, #0x70]
        ldp x29, x30, [sp], #0x80
        mov w8, #1
        ret

    patch_table:
        .word {CLIENT_RVA:#x}, {expected_client_word():#x}, {replacement_client_word():#x}
        .word {EXPIRY_SKIP_RVA:#x}, {EXPIRY_SKIP_EXPECTED:#x}, {ARM64_NOP:#x}
        .word {EXPIRY_ID_RVA:#x}, {EXPIRY_ID_EXPECTED:#x}, {ARM64_NOP:#x}
    log_tag:
        .asciz "FwtLocalServer"
        .balign 4
    fmt_pre:
        .asciz "ap pre %p=%08x"
        .balign 4
    fmt_post:
        .asciz "ap post %d=%08x"
        .balign 4
    fmt_zero:
        .asciz "ap base=0"
        .balign 4
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
