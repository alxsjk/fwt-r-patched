"""Unicorn emulation regression tests for recycle and rune scratch RAM isolation."""

from __future__ import annotations

import struct

import pytest

unicorn = pytest.importorskip("unicorn")

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W0,
    UC_ARM64_REG_W21,
    UC_ARM64_REG_W22,
    UC_ARM64_REG_W28,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X27,
    UC_ARM64_REG_X29,
)

from core.core_patches import (  # noqa: E402
    RECYCLE_COMPLETION_CAVE_BYTES,
    RECYCLE_COMPLETION_CAVE_TAIL_BYTES,
    RECYCLE_COMPLETION_CAVE_TAIL_VADDR,
    RECYCLE_COMPLETION_CAVE_VADDR,
    RECYCLE_GRADE_CAVE_BYTES,
    RECYCLE_GRADE_CAVE_VADDR,
    RECYCLE_GRADE_OFFSET,
    RECYCLE_GRADE_RETURN,
    RECYCLE_REWARD_FLAG_CAVE_BYTES,
    RECYCLE_REWARD_FLAG_CAVE_VADDR,
    RECYCLE_REWARD_FLAG_OFFSET,
    RECYCLE_REWARD_FLAG_RETURN,
    RECYCLE_SCRATCH_PAGE,
    RUNE_ROLL_CAVE_VA,
    RUNE_ROLL_TEXT_VA,
    RUNE_TYPE_CAVE_OFFSET,
    RUNE_TYPE_LOOP_BODY,
    rune_roll_cave_blob,
)

_RET = bytes.fromhex("c0035fd6")  # ret
_GRANT_ITEM_JSON_VA = 0x955C74
_LR_SENTINEL = 0xB39000
_STACK_BASE = 0x7FFF0000
_STACK_TOP = 0x7FFF8000
_FP_ADDR = 0x7FFF8400
_EQUIP_OBJ_ADDR = 0x7FFF9000
_DWARF_BUFFER_END_VA = 0xBE2F60
_DWARF_SENTINEL = 0xDEADBEEFCAFEBABE


def _decode_sso_string(uc: Uc, addr: int) -> str:
    raw = uc.mem_read(addr, 24)
    if (raw[0] & 1) == 0:
        length = raw[0] >> 1
        return bytes(raw[1:1 + length]).decode("ascii")
    length = struct.unpack_from("<Q", raw, 8)[0]
    ptr = struct.unpack_from("<Q", raw, 16)[0]
    return bytes(uc.mem_read(ptr, length)).decode("ascii")


_COMPLETION_RESUME_VA = 0x89D154


def _new_vm() -> Uc:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for page in (
        0x89C000,
        0x89D000,
        0x955000,
        0x983000,
        0x987000,
        0xAC8000,
        0xB33000,
        0xB39000,
        RECYCLE_SCRATCH_PAGE,
    ):
        uc.mem_map(page, 0x1000)
    uc.mem_map(_STACK_BASE, 0x10000)

    uc.mem_write(RECYCLE_GRADE_CAVE_VADDR, RECYCLE_GRADE_CAVE_BYTES)
    uc.mem_write(RECYCLE_REWARD_FLAG_CAVE_VADDR, RECYCLE_REWARD_FLAG_CAVE_BYTES)
    uc.mem_write(RECYCLE_COMPLETION_CAVE_VADDR, RECYCLE_COMPLETION_CAVE_BYTES)
    uc.mem_write(
        RECYCLE_COMPLETION_CAVE_TAIL_VADDR, RECYCLE_COMPLETION_CAVE_TAIL_BYTES
    )
    uc.mem_write(RUNE_ROLL_CAVE_VA, rune_roll_cave_blob())
    uc.mem_write(_DWARF_BUFFER_END_VA, struct.pack("<Q", _DWARF_SENTINEL))
    return uc


def _run_recycle_cycle(
    uc: Uc, *, grade: int, selector: int, reward_str_len: int = 28
) -> tuple[str, int]:
    granted: list[str] = []

    def on_code(emu: Uc, address: int, _size: int, _data: object) -> None:
        if address == _GRANT_ITEM_JSON_VA:
            granted.append(_decode_sso_string(emu, emu.reg_read(UC_ARM64_REG_X1)))
            emu.reg_write(UC_ARM64_REG_X0, 0)
        elif address in (
            RECYCLE_GRADE_RETURN,
            RECYCLE_REWARD_FLAG_RETURN,
            _COMPLETION_RESUME_VA,
        ):
            emu.emu_stop()

    uc.mem_write(_GRANT_ITEM_JSON_VA, _RET)
    hook = uc.hook_add(UC_HOOK_CODE, on_code)
    try:
        # Step 1: capture equipment grade from [x0 + 0x38]
        uc.mem_write(_EQUIP_OBJ_ADDR + 0x38, struct.pack("<I", grade))
        uc.reg_write(UC_ARM64_REG_SP, _STACK_TOP)
        uc.reg_write(UC_ARM64_REG_X29, _FP_ADDR)
        uc.reg_write(UC_ARM64_REG_X0, _EQUIP_OBJ_ADDR)
        uc.emu_start(RECYCLE_GRADE_CAVE_VADDR, RECYCLE_GRADE_RETURN)

        # Step 2: capture native reward selector w21 before add w22, w21, w28
        uc.reg_write(UC_ARM64_REG_W21, selector)
        uc.reg_write(UC_ARM64_REG_W28, reward_str_len)
        uc.emu_start(RECYCLE_REWARD_FLAG_CAVE_VADDR, RECYCLE_REWARD_FLAG_RETURN)
        w22_after = uc.reg_read(UC_ARM64_REG_W22)

        # Step 3: build ticket code 13000X and pass ItemInfo slot to grant_item_json
        uc.reg_write(UC_ARM64_REG_X0, 0x1111)
        uc.emu_start(RECYCLE_COMPLETION_CAVE_VADDR, _COMPLETION_RESUME_VA)
    finally:
        uc.hook_del(hook)

    assert len(granted) == 1
    assert uc.reg_read(UC_ARM64_REG_X8) == _STACK_TOP + 0x1E0
    assert uc.reg_read(UC_ARM64_REG_X2) == 1
    assert uc.reg_read(UC_ARM64_REG_X27) == _STACK_TOP + 0x1A0
    return granted[0], w22_after


def test_recycle_caves_and_rune_roll_scratch_ram_stay_isolated() -> None:
    uc = _new_vm()

    # Normal bar completion (selector=0x65) builds 130001..130005 from captured grade.
    ticket, w22 = _run_recycle_cycle(uc, grade=3, selector=0x65)
    assert ticket == "130003"
    assert w22 == 0x65 + 28

    # Simulate rune box purchases using RUNE_ROLL_CAVE_VA and type loop seed block.
    def on_rune_code(emu: Uc, address: int, _size: int, _data: object) -> None:
        if address == RUNE_ROLL_TEXT_VA:
            emu.reg_write(UC_ARM64_REG_X0, 0x12345678)
        elif address in (_LR_SENTINEL, RUNE_TYPE_LOOP_BODY):
            emu.emu_stop()

    uc.mem_write(RUNE_ROLL_TEXT_VA, _RET)
    hook = uc.hook_add(UC_HOOK_CODE, on_rune_code)
    try:
        for _ in range(5):
            uc.reg_write(UC_ARM64_REG_SP, _STACK_TOP)
            uc.reg_write(UC_ARM64_REG_LR, _LR_SENTINEL)
            uc.emu_start(RUNE_ROLL_CAVE_VA, _LR_SENTINEL)

            uc.reg_write(UC_ARM64_REG_W0, 0)
            uc.emu_start(
                RUNE_ROLL_CAVE_VA + RUNE_TYPE_CAVE_OFFSET, RUNE_TYPE_LOOP_BODY
            )
    finally:
        uc.hook_del(hook)

    # Recycle scratch RAM must remain completely intact after rune rolls, and
    # libunwind's _bufferEnd pointer at 0xBE2F60 must never be corrupted.
    assert (
        struct.unpack("<Q", uc.mem_read(_DWARF_BUFFER_END_VA, 8))[0]
        == _DWARF_SENTINEL
    )
    assert (
        struct.unpack(
            "<I", uc.mem_read(RECYCLE_SCRATCH_PAGE + RECYCLE_REWARD_FLAG_OFFSET, 4)
        )[0]
        == 0x65
    )
    assert (
        struct.unpack(
            "<I", uc.mem_read(RECYCLE_SCRATCH_PAGE + RECYCLE_GRADE_OFFSET, 4)
        )[0]
        == 3
    )

    # Final full-bar step (selector=0x6A) always grants 130006 (Ultimate ticket).
    final_ticket, _ = _run_recycle_cycle(uc, grade=4, selector=0x6A)
    assert final_ticket == "130006"
    assert (
        struct.unpack("<Q", uc.mem_read(_DWARF_BUFFER_END_VA, 8))[0]
        == _DWARF_SENTINEL
    )
