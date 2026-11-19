"""Experimental absolute trampoline for scoped costume-package Claim All."""
from __future__ import annotations

from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

BASE = 0xB2A5AC
HANDLER = BASE + 0x80
CLIENT_SITE = 0x1625844
CLIENT_EXPECTED = bytes.fromhex("86831794e8030032f503192af803132a")


def _asm(source: str, address: int) -> bytes:
    encoded, _ = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(source, address)
    return bytes(encoded)


def generate() -> tuple[bytes, bytes]:
    installer = _asm('''
    cave_start:
        sub sp, sp, #0x60
        stp x29, x30, [sp, #0x40]
        adrp x8, 0xbe3000
        ldr x0, [x8, #0x798]
        movz w1, #0x5844
        movk w1, #0x162, lsl #16
        adr x2, cave_start
        add x2, x2, #0x70
        movz w9, #0x50
        movk w9, #0x5800, lsl #16
        str w9, [sp]
        movz w9, #0x200
        movk w9, #0xd61f, lsl #16
        str w9, [sp, #4]
        adr x9, cave_start
        add x9, x9, #0x80
        str x9, [sp, #8]
        mov x3, sp
        mov w4, #4
        add x5, sp, #0x20
        bl 0xab575c
        ldp x29, x30, [sp, #0x40]
        add sp, sp, #0x60
        ldr x28, [sp, #0x10]
        b 0xab3394
    ''', BASE)
    if len(installer) > 0x70:
        raise ValueError('installer exceeds reserved space')
    installer += bytes(0x70 - len(installer)) + CLIENT_EXPECTED
    handler = _asm('''
        sub sp, sp, #0x20
        adrp x16, 0xbe3000
        ldr x16, [x16, #0x798]
        movz x17, #0x665c
        movk x17, #0x1c0, lsl #16
        add x16, x16, x17
        blr x16
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
        b.ne resume
    accept:
        mov x0, xzr
    resume:
        ldr x13, [sp, #0x10]
        msr nzcv, x13
        ldp x13, x14, [sp]
        add sp, sp, #0x20
        mov w8, #1
        mov w21, w25
        mov w24, w19
        adrp x16, 0xbe3000
        ldr x16, [x16, #0x798]
        movz x17, #0x5848
        movk x17, #0x162, lsl #16
        add x30, x16, x17
        add x17, x17, #0xc
        add x16, x16, x17
        br x16
    ''', HANDLER)
    if len(installer) + len(handler) > 276:
        raise ValueError('exceeds the device-tested cave')
    return installer, handler
