"""Tests for the battle advertisement and hero-gene Subjugation box guards."""

from __future__ import annotations

import struct

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import UC_ARM64_REG_W21, UC_ARM64_REG_X22

from core.core_patches import (
    NO_WIN_BOX_ORIGINAL,
    NO_WIN_BOX_PATCHED,
    NO_WIN_BOX_SITE,
    SWEEP_GENE_BOX_ORIGINAL,
    SWEEP_GENE_BOX_PATCHED,
    SWEEP_GENE_BOX_SITE,
    apply_no_win_box,
    seg_offset,
)


def _window(buf: bytes | bytearray) -> bytes:
    start = seg_offset(NO_WIN_BOX_SITE)
    return bytes(buf[start:start + len(NO_WIN_BOX_ORIGINAL)])


def test_reference_build_has_the_stock_guard(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    assert _window(so_bytes) == NO_WIN_BOX_ORIGINAL

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    first, second = list(md.disasm(NO_WIN_BOX_ORIGINAL, NO_WIN_BOX_SITE))
    assert (first.mnemonic, first.op_str) == ("mov", "x8, x0")
    assert (second.mnemonic, second.op_str) == ("ldrb", "w9, [x0, #0xac]")


def test_patch_forces_a_false_verdict(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)

    assert apply_no_win_box(buf) == 2
    assert _window(buf) == NO_WIN_BOX_PATCHED

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    first, second = list(md.disasm(NO_WIN_BOX_PATCHED, NO_WIN_BOX_SITE))
    assert (first.mnemonic, first.op_str) == ("mov", "w0, wzr")
    assert second.mnemonic == "ret"


def test_patch_touches_only_the_box_guards(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_no_win_box(buf)

    start = seg_offset(NO_WIN_BOX_SITE)
    sweep = seg_offset(SWEEP_GENE_BOX_SITE)
    assert so_bytes[sweep:sweep + len(SWEEP_GENE_BOX_ORIGINAL)] == SWEEP_GENE_BOX_ORIGINAL
    assert buf[sweep:sweep + len(SWEEP_GENE_BOX_PATCHED)] == SWEEP_GENE_BOX_PATCHED
    buf[start:start + len(NO_WIN_BOX_ORIGINAL)] = NO_WIN_BOX_ORIGINAL
    buf[sweep:sweep + len(SWEEP_GENE_BOX_ORIGINAL)] = SWEEP_GENE_BOX_ORIGINAL
    assert bytes(buf) == so_bytes


def test_patch_is_idempotent(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_no_win_box(buf) == 2
    once = bytes(buf)
    assert apply_no_win_box(buf) == 0
    assert bytes(buf) == once


def test_patch_refuses_a_foreign_guard(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    start = seg_offset(NO_WIN_BOX_SITE)
    buf[start:start + 4] = b"\x1f\x20\x03\xd5"  # nop: not the stock prologue
    with pytest.raises(ValueError, match="Unexpected win box guard"):
        apply_no_win_box(buf)


@pytest.mark.parametrize(
    ("gene_id", "mapping", "group", "should_roll"),
    [(1181809, 1137, 140, False), (-1, 1137, 140, True), (-1, 0, 140, False), (-1, 1137, 0, False)],
)
def test_sweep_box_gate_preserves_stock_checks(gene_id, mapping, group, should_roll) -> None:
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.mem_map(0x8CF000, 0x2000)
    cpu.mem_map(0x100000, 0x1000)
    cpu.mem_write(SWEEP_GENE_BOX_SITE, SWEEP_GENE_BOX_PATCHED)
    cpu.mem_write(0x10007C, struct.pack("<i", gene_id))
    cpu.mem_write(0x1000A4, struct.pack("<ii", mapping, group))
    cpu.reg_write(UC_ARM64_REG_X22, 0x100000)
    fallthrough = SWEEP_GENE_BOX_SITE + len(SWEEP_GENE_BOX_PATCHED)
    no_box = 0x8D01AC
    reached = []

    def stop_at_exit(uc, address, _size, _context):
        if address in (fallthrough, no_box):
            reached.append(address)
            uc.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, stop_at_exit)
    cpu.emu_start(SWEEP_GENE_BOX_SITE, no_box + 4, count=7)
    assert reached == [fallthrough if should_roll else no_box]
    if should_roll:
        assert cpu.reg_read(UC_ARM64_REG_W21) == group
