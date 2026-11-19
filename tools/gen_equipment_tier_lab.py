"""Laboratory-only native hook for testing equipment tier completion."""
from __future__ import annotations

from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

HOOK = 0xA188BC
CAVE = 0xB2A700
ORIGINAL = bytes.fromhex('0a050091')


def generate() -> bytes:
    source = '''
        sub sp, sp, #16
        str x16, [sp]
        add x10, x8, #1
        ldr x16, [x29]
        ldr x16, [x16, #0x28]
        cmp x16, #1
        b.ne done
        cmp x8, #10
        b.lt done
        cmp x8, #15
        b.lt low
        cmp x8, #20
        b.lt middle
        cmp x8, #26
        b.ge done
        mov x10, #26
        b done
    low:
        mov x10, #15
        b done
    middle:
        mov x10, #20
    done:
        ldr x16, [sp]
        add sp, sp, #16
        b 0xa188c0
    '''
    encoded, _ = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(source, CAVE)
    return bytes(encoded)
