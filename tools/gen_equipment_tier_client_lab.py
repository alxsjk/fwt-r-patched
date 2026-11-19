"""Experimental client preview and cost hooks for equipment tier upgrades."""
from __future__ import annotations

from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

CAVE = 0xB2A800
HOOK = 0xAB3394
HOOK_ORIGINAL = bytes.fromhex('fd7bc6a8')

SITES = (
    (0x1BBAEE4, bytes.fromhex('890e41b9015d4039e3031faa22050011'), 'confirm'),
    (0x1BBCFC4, bytes.fromhex('150700b4e0060037607e40f9e1030032'), 'stats'),
    (0x1BBDAEC, bytes.fromhex('e00313aa88fdff97e00313aafd7b42a9'), 'refresh_equip'),
    (0x1BBDBAC, bytes.fromhex('e00313aa58fdff97e00313aafd7b42a9'), 'refresh_item'),
)
WORDS = (
    (0x1BBD51C, bytes.fromhex('882240b9'), bytes.fromhex('28008052')),
    (0x1BBD6D0, bytes.fromhex('892240b9'), bytes.fromhex('29008052')),
)


def _imm(reg: str, number: int) -> str:
    return f'movz {reg}, #{number & 0xffff}\n movk {reg}, #{number >> 16}, lsl #16\n'


def _target(rva: int, *, link: bool = False) -> str:
    return (f'''adrp x16, 0xbe3000
        ldr x16, [x16, #0x798]
        movz x17, #{rva & 0xffff}
        movk x17, #{rva >> 16}, lsl #16
        add x16, x16, x17
        {'blr' if link else 'br'} x16
    ''')


def generate() -> bytes:
    src = '''
        sub sp, sp, #0x70
        stp x29, x30, [sp, #0x50]
        stp x19, x20, [sp, #0x40]
        adrp x8, 0xbe3000
        ldr x19, [x8, #0x798]
        movz w9, #0x50
        movk w9, #0x5800, lsl #16
        str w9, [sp]
        movz w9, #0x200
        movk w9, #0xd61f, lsl #16
        str w9, [sp, #4]
    '''
    for index, (rva, _expected, handler) in enumerate(SITES):
        src += _imm('w1', rva) + f'''
        adr x2, exp{index}
        adr x9, {handler}
        str x9, [sp, #8]
        mov x0, x19
        mov x3, sp
        mov w4, #4
        add x5, sp, #0x20
        bl 0xab575c
        '''
    for index, (rva, _expected, _patched) in enumerate(WORDS):
        src += _imm('w1', rva) + f'''
        adr x2, word_orig{index}
        adr x3, word_new{index}
        mov x0, x19
        mov w4, #1
        add x5, sp, #0x20
        bl 0xab575c
        '''
    src += '''
        ldp x19, x20, [sp, #0x40]
        ldp x29, x30, [sp, #0x50]
        add sp, sp, #0x70
        ldp x29, x30, [sp], #0x60
        ret
    confirm:
        ldr w9, [x20, #0x10c]
        ldrb w1, [x8, #0x17]
        mov x3, xzr
        add w2, w9, #1
        cmp w9, #10
        b.lt confirm_done
        cmp w9, #15
        b.lt confirm_low
        cmp w9, #20
        b.lt confirm_mid
        cmp w9, #26
        b.ge confirm_done
        mov w2, #26
        b confirm_done
    confirm_low:
        mov w2, #15
        b confirm_done
    confirm_mid:
        mov w2, #20
    confirm_done:
    ''' + _target(0x1BBAEF4)
    src += '''
    stats:
        cbz x21, stats_skip
        tbnz w0, #0, stats_skip
        ldr x0, [x19, #0xf8]
        mov w1, #1
        ldr x9, [x19, #0x108]
        cbz x9, stats_done
        ldr w9, [x0, #0x10c]
        cmp w9, #10
        b.lt stats_done
        cmp w9, #15
        b.lt stats_low
        cmp w9, #20
        b.lt stats_mid
        cmp w9, #26
        b.ge stats_done
        mov w1, #26
        b stats_sub
    stats_low:
        mov w1, #15
        b stats_sub
    stats_mid:
        mov w1, #20
    stats_sub:
        sub w1, w1, w9
    stats_done:
    ''' + _target(0x1BBCFD4)
    src += 'stats_skip:\n' + _target(0x1BBD0A4)
    for handler,ret in (('refresh_equip',0x1BBDAFC),('refresh_item',0x1BBDBBC)):
        src += handler+':\n mov x0, x19\n' + _target(0x1BBD110,link=True)
        src += 'mov x0, x19\n' + _target(0x1BBCEB4,link=True)
        src += 'mov x0, x19\n ldp x29, x30, [sp, #0x20]\n' + _target(ret)
    for index, (_rva, expected, _handler) in enumerate(SITES):
        src += f'exp{index}:\n.byte '+','.join(hex(b) for b in expected)+'\n'
    for index, (_rva, expected, patched) in enumerate(WORDS):
        for name, data in ((f'word_orig{index}',expected),(f'word_new{index}',patched)):
            src += name+':\n.byte '+','.join(hex(b) for b in data)+'\n'
    encoded, _ = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(src,CAVE)
    result=bytes(encoded)
    if len(result)>0x300:
        raise ValueError(f'client installer exceeds trap-tested range: {len(result)}')
    return result
