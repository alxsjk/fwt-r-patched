"""Tests for always-on hero EXP cap and Limit Break level_max floor (08.06)."""

from __future__ import annotations

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks
from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X25,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X28,
)

from core.core_patches import (
    HERO_EXP_CAP_CAVE_BYTES,
    HERO_EXP_CAP_CAVE_VADDR,
    HERO_EXP_CAP_EXPEDITION_ORIGINAL,
    HERO_EXP_CAP_EXPEDITION_SITE,
    HERO_EXP_CAP_EXPEDITION_TRAMPOLINE,
    HERO_EXP_CAP_INFINITY_ORIGINAL,
    HERO_EXP_CAP_INFINITY_SITE,
    HERO_EXP_CAP_INFINITY_TRAMPOLINE,
    HERO_EXP_CAP_STAGE_ORIGINAL,
    HERO_EXP_CAP_STAGE_SITE,
    HERO_EXP_CAP_STAGE_TRAMPOLINE,
    HERO_LEVEL_MAX_FLOOR_ORIGINAL,
    HERO_LEVEL_MAX_FLOOR_PATCHED,
    HERO_LEVEL_MAX_FLOOR_SITE,
    HERO_LEVEL_MAX_FUNC,
    HERO_MAX_EXP_FUNC,
    apply_hero_exp_cap,
    encode_arm64_branch,
    seg_offset,
)


def _asm(text: str, addr: int) -> bytes:
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(text, addr)
    return bytes(enc)


def test_cave_bytes_match_keystone_assembly() -> None:
    cave = HERO_EXP_CAP_CAVE_VADDR
    helper_bytes = _asm(
        f"""
        stp x29, x30, [sp, #-0x30]!
        stp x19, x20, [sp, #0x10]
        mov x29, sp
        mov x19, x0
        mov x20, x1
        bl 0x{HERO_LEVEL_MAX_FUNC:x}
        mov x1, x0
        mov x0, x19
        bl 0x{HERO_MAX_EXP_FUNC:x}
        cmp x20, x0
        csel x1, x20, x0, le
        cmp x0, #0
        csel x0, x1, x20, gt
        ldp x19, x20, [sp, #0x10]
        ldp x29, x30, [sp], #0x30
        ret
        """,
        cave,
    )
    t1_bytes = _asm(
        f"""
        stp x29, x30, [sp, #-0x10]!
        mov x29, sp
        add x1, x20, x26
        mov x0, x19
        bl 0x{cave:x}
        mov x26, x0
        ldp x29, x30, [sp], #0x10
        ret
        """,
        HERO_EXP_CAP_STAGE_TRAMPOLINE,
    )
    t2_bytes = _asm(
        f"""
        stp x29, x30, [sp, #-0x10]!
        mov x29, sp
        add x1, x23, x24
        mov x0, x19
        bl 0x{cave:x}
        mov x28, x0
        ldp x29, x30, [sp], #0x10
        ret
        """,
        HERO_EXP_CAP_INFINITY_TRAMPOLINE,
    )
    t3_bytes = _asm(
        f"""
        stp x29, x30, [sp, #-0x20]!
        str x8, [sp, #0x10]
        mov x29, sp
        add x1, x0, x9
        mov x0, x24
        bl 0x{cave:x}
        mov x25, x0
        ldr x8, [sp, #0x10]
        ldp x29, x30, [sp], #0x20
        ret
        """,
        HERO_EXP_CAP_EXPEDITION_TRAMPOLINE,
    )
    assert helper_bytes + t1_bytes + t2_bytes + t3_bytes == HERO_EXP_CAP_CAVE_BYTES


def test_unicorn_clamping_and_register_preservation() -> None:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x900000, 0x300000)
    uc.mem_map(0x7000000, 0x10000)
    uc.mem_write(HERO_EXP_CAP_CAVE_VADDR, HERO_EXP_CAP_CAVE_BYTES)
    uc.mem_write(HERO_LEVEL_MAX_FUNC, _asm("mov x0, #70; ret", HERO_LEVEL_MAX_FUNC))
    uc.mem_write(
        HERO_MAX_EXP_FUNC,
        _asm("mov w8, #0xdead; movz x0, #0x2370; movk x0, #0x182, lsl #16; ret", HERO_MAX_EXP_FUNC),
    )
    sentinel = 0x902000

    # Stage trampoline: clamps x20 + x26 to 25,305,968 and allows below-cap sums
    for cur_exp, add_exp, expected in [(25_300_000, 10_000, 25_305_968), (1_000, 500, 1_500)]:
        uc.reg_write(UC_ARM64_REG_SP, 0x7008000)
        uc.reg_write(UC_ARM64_REG_X19, 0x7001000)
        uc.reg_write(UC_ARM64_REG_X20, add_exp)
        uc.reg_write(UC_ARM64_REG_X26, cur_exp)
        uc.reg_write(UC_ARM64_REG_LR, sentinel)
        uc.emu_start(HERO_EXP_CAP_STAGE_TRAMPOLINE, sentinel)
        assert uc.reg_read(UC_ARM64_REG_X26) == expected

    # Tower of Dawn trampoline: clamps x23 + x24 into x28
    uc.reg_write(UC_ARM64_REG_SP, 0x7008000)
    uc.reg_write(UC_ARM64_REG_X19, 0x7001000)
    uc.reg_write(UC_ARM64_REG_X23, 25_000)
    uc.reg_write(UC_ARM64_REG_X24, 25_300_000)
    uc.reg_write(UC_ARM64_REG_LR, sentinel)
    uc.emu_start(HERO_EXP_CAP_INFINITY_TRAMPOLINE, sentinel)
    assert uc.reg_read(UC_ARM64_REG_X28) == 25_305_968

    # Expedition trampoline: clamps x0 + x9 into x25 and preserves w8 across call
    uc.reg_write(UC_ARM64_REG_SP, 0x7008000)
    uc.reg_write(UC_ARM64_REG_X24, 0x7001000)
    uc.reg_write(UC_ARM64_REG_X0, 25_300_000)
    uc.reg_write(UC_ARM64_REG_X9, 50_000)
    uc.reg_write(UC_ARM64_REG_X8, 1)
    uc.reg_write(UC_ARM64_REG_LR, sentinel)
    uc.emu_start(HERO_EXP_CAP_EXPEDITION_TRAMPOLINE, sentinel)
    assert uc.reg_read(UC_ARM64_REG_X25) == 25_305_968
    assert uc.reg_read(UC_ARM64_REG_X8) == 1

    # Fallback guard: if max_exp == 0, return unclamped sum
    uc.mem_write(HERO_MAX_EXP_FUNC, _asm("mov x0, xzr; ret", HERO_MAX_EXP_FUNC))
    uc.reg_write(UC_ARM64_REG_SP, 0x7008000)
    uc.reg_write(UC_ARM64_REG_X0, 1234)
    uc.reg_write(UC_ARM64_REG_X1, 5678)
    uc.reg_write(UC_ARM64_REG_LR, sentinel)
    uc.emu_start(HERO_EXP_CAP_CAVE_VADDR, sentinel)
    assert uc.reg_read(UC_ARM64_REG_X0) == 5678


def test_apply_hero_exp_cap_and_idempotency(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)

    floor_off = seg_offset(HERO_LEVEL_MAX_FLOOR_SITE)
    assert bytes(buf[floor_off : floor_off + 8]) == HERO_LEVEL_MAX_FLOOR_ORIGINAL
    assert (
        bytes(buf[seg_offset(HERO_EXP_CAP_STAGE_SITE) : seg_offset(HERO_EXP_CAP_STAGE_SITE) + 4])
        == HERO_EXP_CAP_STAGE_ORIGINAL
    )
    assert (
        bytes(
            buf[
                seg_offset(HERO_EXP_CAP_INFINITY_SITE) : seg_offset(HERO_EXP_CAP_INFINITY_SITE) + 4
            ]
        )
        == HERO_EXP_CAP_INFINITY_ORIGINAL
    )
    assert (
        bytes(
            buf[
                seg_offset(HERO_EXP_CAP_EXPEDITION_SITE) : seg_offset(HERO_EXP_CAP_EXPEDITION_SITE)
                + 4
            ]
        )
        == HERO_EXP_CAP_EXPEDITION_ORIGINAL
    )

    assert apply_hero_exp_cap(buf) == 4
    once = bytes(buf)
    assert apply_hero_exp_cap(buf) == 0
    assert bytes(buf) == once

    assert bytes(buf[floor_off : floor_off + 8]) == HERO_LEVEL_MAX_FLOOR_PATCHED
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    first, second = list(md.disasm(HERO_LEVEL_MAX_FLOOR_PATCHED, HERO_LEVEL_MAX_FLOOR_SITE))
    assert (first.mnemonic, first.op_str) == ("mov", "w20, #0x46")
    assert (second.mnemonic, second.op_str) == ("b", "#0x9020b8")

    for site, target in (
        (HERO_EXP_CAP_STAGE_SITE, HERO_EXP_CAP_STAGE_TRAMPOLINE),
        (HERO_EXP_CAP_INFINITY_SITE, HERO_EXP_CAP_INFINITY_TRAMPOLINE),
        (HERO_EXP_CAP_EXPEDITION_SITE, HERO_EXP_CAP_EXPEDITION_TRAMPOLINE),
    ):
        assert bytes(buf[seg_offset(site) : seg_offset(site) + 4]) == encode_arm64_branch(
            site, target, link=True
        )


def test_apply_hero_exp_cap_rejects_foreign_site(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    off = seg_offset(HERO_LEVEL_MAX_FLOOR_SITE)
    buf[off : off + 4] = b"\x1f\x20\x03\xd5"
    with pytest.raises(ValueError, match="hero level_max floor"):
        apply_hero_exp_cap(buf)
