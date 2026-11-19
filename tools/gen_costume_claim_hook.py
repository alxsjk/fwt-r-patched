"""Experimental package-scoped Claim All installer and handler.

Device-only laboratory prototype: not integrated in a release patch.
"""
from __future__ import annotations

from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

BASE = 0xB2A5AC
HANDLER = BASE + 0x80
CLIENT_SITE = 0x1625858
CLIENT_EXPECTED = bytes.fromhex('20f8ffb4')


def _asm(text: str, addr: int) -> bytes:
    result, _ = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(text, addr)
    return bytes(result)


def generate() -> tuple[bytes, bytes]:
    """Return installer and handler for an explicitly allocated cave."""
    installer = _asm('''
    cave_start:
        sub sp, sp, #0x60
        stp x29, x30, [sp, #0x40]
        adrp x8, 0xbe3000
        ldr x0, [x8, #0x798]
        movz w1, #0x5858
        movk w1, #0x162, lsl #16
        adr x9, cave_start
        add x9, x9, #0x80
        add x10, x0, x1
        sub x9, x9, x10
        asr x10, x9, #27
        cmp x10, #0
        b.eq encode
        cmn x10, #1
        b.ne done
    encode:
        asr x9, x9, #2
        and w9, w9, #0x3ffffff
        movz w11, #0x1400, lsl #16
        orr w9, w9, w11
        str w9, [sp]
        adr x2, cave_start
        add x2, x2, #0x7c
        mov x3, sp
        mov w4, #1
        add x5, sp, #0x20
        bl 0xab575c
    done:
        ldp x29, x30, [sp, #0x40]
        add sp, sp, #0x60
        ldr x28, [sp, #0x10]
        b 0xab3394
    ''', BASE)
    if len(installer) > 0x7c:
        raise ValueError('installer exceeds its reserved space')
    installer += bytes(0x7c - len(installer)) + CLIENT_EXPECTED
    handler = _asm('''
        sub sp, sp, #0x20
        stp x13, x14, [sp]
        mrs x13, nzcv
        str x13, [sp, #0x10]
        ldr w13, [x26, #0x30]
        movz w14, #0x258e
        movk w14, #1, lsl #16
        cmp w13, w14
        b.eq accept
        movz w14, #0x25b2
        movk w14, #1, lsl #16
        cmp w13, w14
        b.eq accept
        cbz x0, accept
        ldr x13, [sp, #0x10]
        msr nzcv, x13
        ldp x13, x14, [sp]
        add sp, sp, #0x20
        adrp x16, 0xbe3000
        ldr x16, [x16, #0x798]
        movz x17, #0x585c
        movk x17, #0x162, lsl #16
        add x16, x16, x17
        br x16
    accept:
        ldr x13, [sp, #0x10]
        msr nzcv, x13
        ldp x13, x14, [sp]
        add sp, sp, #0x20
        adrp x16, 0xbe3000
        ldr x16, [x16, #0x798]
        movz x17, #0x575c
        movk x17, #0x162, lsl #16
        add x16, x16, x17
        br x16
    ''', HANDLER)
    if len(installer) + len(handler) > 0x180:
        raise ValueError('installer and handler exceed 0x180-byte cave')
    return installer, handler

