"""Emulate candidate server skill-ID and level-cost fallbacks in isolation.

Addresses are speculative and used only in Unicorn. No ELF or APK is written.
Full register liveness, cave reachability, native loading and gameplay are
unverified. The donor costs are temporary laboratory values.
"""

from __future__ import annotations

import struct

from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_NZCV,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X19,
)

_SKILL = 0x100185
_ID_CAVE = 0xB34E08
_COST_CAVE = 0xB34E40
_CANDIDATE_COST = 0xB34F24
CANDIDATE_COST_ROW: tuple[int, ...] = (_SKILL, 10, 20, 30, 40, 50, 60, 70, 80, 90, -1)
_ID_FOUND = 0x8C3A14
_ID_NEXT = 0x8C39D4
_COST_FOUND = 0x800E04
_COST_MISSING = 0x800E10
_DONOR_COST = 0x6D5E64


def make_candidate_cost_row() -> bytes:
    """Serialize the 44-byte synthetic SkillLevelTable row for 0x100185."""
    return struct.pack("<11i", *CANDIDATE_COST_ROW)


def _assemble(source: str, address: int) -> bytes:
    code, count = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(source, addr=address)
    if not count or code is None:
        raise ValueError("Could not assemble prototype")
    return bytes(code)


def prototype() -> tuple[bytes, bytes]:
    # Reproduce the original equal branch before applying the new exception.
    # x13 is the last compared table value and is retained on the found path.
    recognition = _assemble(f"""
        b.ne check_candidate
        b {_ID_FOUND:#x}
    check_candidate:
        movz w14, #0x0185
        movk w14, #0x10, lsl #16
        cmp x19, x14
        b.ne not_candidate
        b {_ID_FOUND:#x}
    not_candidate:
        b {_ID_NEXT:#x}
    """, _ID_CAVE)
    cost = _assemble(f"""
        movz w9, #0x0185
        movk w9, #0x10, lsl #16
        cmp x11, x9
        b.eq candidate_cost
        b {_COST_MISSING:#x}
    candidate_cost:
        adrp x9, {_CANDIDATE_COST & ~0xfff:#x}
        add x9, x9, #{_CANDIDATE_COST & 0xfff}
        mov x8, x11
        b {_COST_FOUND:#x}
    """, _COST_CAVE)
    if _ID_CAVE + len(recognition) > _COST_CAVE or _COST_CAVE + len(cost) > 0xB34E64:
        raise ValueError("Prototype ranges overlap or exceed the modeled function")
    return recognition, cost


def exercise() -> None:
    recognition, cost = prototype()
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address in (0x800000, 0x8C0000, 0xB30000):
        vm.mem_map(address, 0x10000)
    vm.mem_write(_ID_CAVE, recognition)
    vm.mem_write(_COST_CAVE, cost)
    vm.mem_write(_CANDIDATE_COST, make_candidate_cost_row())

    def stop(uc: Uc, address: int, _size: int, _user: object) -> None:
        if address in (_ID_FOUND, _ID_NEXT, _COST_FOUND, _COST_MISSING):
            uc.emu_stop()

    vm.hook_add(UC_HOOK_CODE, stop)

    def id_path(skill: int, *, found: bool) -> int:
        vm.reg_write(UC_ARM64_REG_X19, skill)
        vm.reg_write(UC_ARM64_REG_X13, skill if found else 0x1234)
        vm.reg_write(UC_ARM64_REG_NZCV, 0x40000000 if found else 0)
        vm.emu_start(_ID_CAVE, 0, count=20)
        return int(vm.reg_read(UC_ARM64_REG_PC))

    assert id_path(_SKILL, found=False) == _ID_FOUND
    assert id_path(1234, found=False) == _ID_NEXT
    assert id_path(1234, found=True) == _ID_FOUND

    def cost_path(skill: int) -> int:
        vm.reg_write(UC_ARM64_REG_X11, skill)
        vm.reg_write(UC_ARM64_REG_X4, 3)
        vm.reg_write(UC_ARM64_REG_X8, 0x5555)
        vm.emu_start(_COST_CAVE, 0, count=20)
        assert vm.reg_read(UC_ARM64_REG_X4) == 3
        return int(vm.reg_read(UC_ARM64_REG_PC))

    assert cost_path(_SKILL) == _COST_FOUND
    assert vm.reg_read(UC_ARM64_REG_X9) == _CANDIDATE_COST
    assert vm.reg_read(UC_ARM64_REG_X8) == _SKILL
    assert cost_path(1234) == _COST_MISSING
    assert vm.reg_read(UC_ARM64_REG_X8) == 0x5555
    print("Skill recognition and cost fallback prototypes passed in emulation; no files changed.")


if __name__ == "__main__":
    exercise()
