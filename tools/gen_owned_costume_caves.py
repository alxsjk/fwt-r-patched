"""Experimental ARM64 branches for inspecting owned-costume package behavior.

Not integrated into the patcher. Candidate cave addresses are unverified: do not
install without dead-code, hash, CFI, and device validation.
"""
from __future__ import annotations

from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

CAVES = (0xB2A3AC, 0xB2A4AC)
HOOKS = (0x9846A8, 0x9846B8)


def _context(eligible: bool, address: int) -> str:
    # Scratch x13-x17 only; neither x8 (string flags) nor x9/x11/x12 is touched.
    # Require both return sites and a five-byte libc++ short shop-code string.
    save = """
    cave_entry:
        sub sp, sp, #0x30
        stp x13, x14, [sp]
        stp x15, x16, [sp, #0x10]
        str x17, [sp, #0x20]
        mrs x17, nzcv
    """
    prefix = f"""
        ldr x13, [x29, #8]
        adr x14, cave_entry
        movz x16, #{(address - 0x98461C) & 0xffff}
        movk x16, #{(address - 0x98461C) >> 16}, lsl #16
        sub x14, x14, x16
        cmp x13, x14
        b.ne stock
        ldr x15, [x29]
    """ if eligible else "mov x15, x29\n"
    context = f"""
        ldr x13, [x15, #8]
        adr x14, cave_entry
        movz x16, #{(address - 0x990C80) & 0xffff}
        movk x16, #{(address - 0x990C80) >> 16}, lsl #16
        sub x14, x14, x16
        cmp x13, x14
        b.ne stock
        ldr x15, [x15]
        sub x15, x15, #0x88
        ldrb w13, [x15]
        cmp w13, #10
        b.ne stock
        ldur w13, [x15, #1]
        movz w14, #0x3537
        movk w14, #0x3531, lsl #16
        cmp w13, w14
        b.ne stock
        ldrb w13, [x15, #5]
        cmp w13, #0x30
        b.eq selected
        cmp w13, #0x36
        b.ne stock
        ldrb w13, [x15, #4]
        cmp w13, #0x38
        b.ne stock
        b selected
    """
    return save + prefix + context.replace("cmp w13, w14\n        b.ne stock", """cmp w13, w14
        b.eq prefix_7515
        movz w14, #0x3537
        movk w14, #0x3831, lsl #16
        cmp w13, w14
        b.ne stock
        ldrb w13, [x15, #5]
        cmp w13, #0x36
        b.ne stock
        b selected
    prefix_7515:""").replace("        cmp w13, #0x36\n        b.ne stock\n        ldrb w13, [x15, #4]\n        cmp w13, #0x38\n        b.ne stock\n        b selected\n", "        b stock\n")


def _assemble(source: str, address: int) -> bytes:
    encoded, _ = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(source, address)
    return bytes(encoded)


def _restore() -> str:
    return """
        msr nzcv, x17
        ldp x13, x14, [sp]
        ldp x15, x16, [sp, #0x10]
        ldr x17, [sp, #0x20]
        add sp, sp, #0x30
    """


def generate() -> tuple[bytes, bytes]:
    """Prototype sequential selection of the existing eligible costume vector."""
    select = _context(False, CAVES[0]) + """
    selected:
    """ + _restore() + """
        str x11, [sp, #0x40]
        mov x20, x22
        b 0x9846ac
    stock:
    """ + _restore() + """
        msub x20, x12, x11, x9
        b 0x9846ac
    """
    bounds = _context(False, CAVES[1]) + """
    selected:
        ldr x16, [sp, #0x70]
        cmp x20, x16
        b.hs out_of_bounds
    stock:
    """ + _restore() + """
        mov w8, #0x18
        b 0x9846bc
    out_of_bounds:
    """ + _restore() + """
        b 0x9846d4
    """
    blobs = tuple(_assemble(code, addr) for code, addr in zip((select, bounds), CAVES, strict=True))
    if any(len(blob) > 0x100 for blob in blobs):
        raise ValueError("experimental cave exceeds its 0x100-byte budget")
    return blobs[0], blobs[1]
