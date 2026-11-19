"""Regression test: emulate the Battle Arena late cave.

The cave runs from the covault permission-finalization epilogue (0xAB337C):
it reads the cached libil2cpp base from 0xBE3798, calls patch_words with
(base, 0x1AA6FCC, expected, replacement, 1 word, status), restores its own frame
and executes the original `add sp, sp, #0xc50` before branching to 0xAB3380.
"""

import struct

import pytest

unicorn = pytest.importorskip("unicorn")

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X29,
)

from core.core_patches import (
    BATTLE_ARENA_SAVE_CAVE_BYTES,
    BATTLE_ARENA_SAVE_CAVE_VADDR,
    BATTLE_ARENA_SAVE_CLIENT_BASE_GLOBAL,
    BATTLE_ARENA_SAVE_ORIGINAL,
    BATTLE_ARENA_SAVE_REPLACEMENT,
    BATTLE_ARENA_SAVE_RVA,
)

CAVE = BATTLE_ARENA_SAVE_CAVE_VADDR
PATCH_WORDS = 0xAB575C
CONTINUE = 0xAB3380
SCRATCH = 0x2000_0000
ENTRY_SP = SCRATCH + 0x40000


def _run() -> tuple[dict, list[str], int]:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(SCRATCH, 0x100000)
    uc.mem_map(0xAB0000, 0x100000)
    uc.mem_map(0xBE0000, 0x100000)
    uc.mem_write(CAVE, BATTLE_ARENA_SAVE_CAVE_BYTES)
    uc.mem_write(PATCH_WORDS, struct.pack("<I", 0xD65F03C0))  # RET stub

    client_base = 0x400022200000
    uc.mem_write(BATTLE_ARENA_SAVE_CLIENT_BASE_GLOBAL, struct.pack("<Q", client_base))

    captured: dict[str, int | bytes] = {}
    stops: list[str] = []

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        if address == PATCH_WORDS:
            captured["base"] = uc_.reg_read(UC_ARM64_REG_X0)
            captured["rva"] = uc_.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
            captured["expected"] = bytes(
                uc_.mem_read(uc_.reg_read(UC_ARM64_REG_X2), 4)
            )
            captured["replacement"] = bytes(
                uc_.mem_read(uc_.reg_read(UC_ARM64_REG_X3), 4)
            )
            captured["words"] = uc_.reg_read(UC_ARM64_REG_X4)
            captured["status"] = uc_.reg_read(UC_ARM64_REG_X5)
            uc_.reg_write(UC_ARM64_REG_X0, 1)  # pretend the patch succeeded
            uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))
        elif address == CONTINUE:
            stops.append(hex(address))
            uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_SP, ENTRY_SP)
    uc.reg_write(UC_ARM64_REG_X29, ENTRY_SP)
    uc.reg_write(UC_ARM64_REG_LR, 0xDEADBEEF)
    uc.emu_start(CAVE, 0, 0, 1000)
    return captured, stops, uc.reg_read(UC_ARM64_REG_SP)


def test_battle_arena_cave_arguments():
    captured, stops, sp = _run()
    assert captured["base"] == 0x400022200000
    assert captured["rva"] == BATTLE_ARENA_SAVE_RVA
    assert captured["expected"] == BATTLE_ARENA_SAVE_ORIGINAL
    assert captured["replacement"] == BATTLE_ARENA_SAVE_REPLACEMENT
    assert captured["words"] == 1
    assert stops == [hex(CONTINUE)]
    # the cave balances its own frame and then applies the original
    # `add sp, sp, #0xc50` before jumping back
    assert sp == ENTRY_SP + 0xC50
