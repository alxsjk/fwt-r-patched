"""Tests for the win-box advertisement patch.

The battle result payload carries ``"is_win_box":`` followed by ``true``/``false``, chosen by
the single caller of ``battle_has_mapped_coocoo_box`` (``0x8da77c``).  The embedded server
never fills ``coocoobox_reward``/``coocoobox_reward_list`` and never inserts a box item, so a
``true`` only produces box rows in the end-of-battle list that never reach the inventory.
The patch makes the function return 0 without touching anything else.
"""

from __future__ import annotations

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from core.core_patches import (
    NO_WIN_BOX_ORIGINAL,
    NO_WIN_BOX_PATCHED,
    NO_WIN_BOX_SITE,
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

    assert apply_no_win_box(buf) == 1
    assert _window(buf) == NO_WIN_BOX_PATCHED

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    first, second = list(md.disasm(NO_WIN_BOX_PATCHED, NO_WIN_BOX_SITE))
    assert (first.mnemonic, first.op_str) == ("mov", "w0, wzr")
    assert second.mnemonic == "ret"


def test_patch_touches_only_that_window(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    apply_no_win_box(buf)

    start = seg_offset(NO_WIN_BOX_SITE)
    changed_offsets = [
        i for i in range(len(so_bytes)) if so_bytes[i] != buf[i]
    ]
    assert changed_offsets, "the patch changed nothing"
    assert min(changed_offsets) >= start
    assert max(changed_offsets) < start + len(NO_WIN_BOX_ORIGINAL)
    assert len(changed_offsets) == 7  # movz keeps one byte of the original mov


def test_patch_is_idempotent(reference_buffers) -> None:
    so_bytes, _ = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_no_win_box(buf) == 1
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
