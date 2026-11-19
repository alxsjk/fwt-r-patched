"""Tests for the assembly-driven cave builder."""

from __future__ import annotations

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from tools.asm_cave import assemble_cave

pytest.importorskip("keystone")

BASE = 0xB34860


def _disasm(code: bytes, base: int = BASE):
    return list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, base))


def test_symbolic_branches_resolve_to_addresses() -> None:
    code = assemble_cave(
        """
            mov  x0, #1        ; a comment, dropped
            bl   BUILDER
            b    EPILOGUE
        """,
        base=BASE,
        symbols={"BUILDER": 0xA6B304, "EPILOGUE": 0x9302C4},
    )
    insns = _disasm(code)
    assert [i.mnemonic for i in insns] == ["mov", "bl", "b"]
    assert int(insns[1].op_str.lstrip("#"), 16) == 0xA6B304
    assert int(insns[2].op_str.lstrip("#"), 16) == 0x9302C4


def test_labels_inside_the_cave_are_supported() -> None:
    """Locals keep a conditional branch in range; keystone resolves the labels itself."""
    code = assemble_cave(
        """
        again:
            cmp  x8, x23
            b.eq again
            ret
        """,
        base=BASE,
    )
    insns = _disasm(code)
    assert insns[1].mnemonic == "b.eq"
    assert insns[1].op_str == "#0xb34860"


def test_unknown_symbol_is_refused() -> None:
    """A name that is neither in symbols nor a local label must not assemble silently."""
    with pytest.raises(ValueError, match="keystone failed"):
        assemble_cave("bl NOPE", base=BASE, symbols={})


def test_broken_assembly_is_reported_with_the_address() -> None:
    with pytest.raises(ValueError, match="keystone failed"):
        assemble_cave("mov x0, not_a_register", base=BASE)
