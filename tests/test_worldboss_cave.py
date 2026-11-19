"""Unicorn emulation tests for the Unknown Paradise daily Kraken Scale cave."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W2,
    UC_ARM64_REG_W25,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X22,
)

from core.core_patches import (
    WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES,
    WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR,
)

_CODE_BASE = 0x880000
_CODE_SIZE = 0x2E0000
_STACK_BASE = 0x2000000
_STACK_SIZE = 0x10000
_STATE_JSON_ADDR = 0x2100000
_MUTATION_RESULT_ADDR = 0x2200000
_OLD_HEAP_PTR = 0x2300000

_GRANT_ITEM_JSON_VADDR = 0x955C74
_REPLACE_RAW_VALUE_VADDR = 0x880C20
_OPERATOR_DELETE_VADDR = 0xB45EE0
_RESUME_VADDR = 0x8E69F8


def _read_libcxx_sso(uc: Uc, addr: int) -> str:
    """Decodes an SSO libc++ std::string at `addr`."""
    raw = bytes(uc.mem_read(addr, 24))
    tag = raw[0]
    assert (tag & 1) == 0, f"expected SSO string at 0x{addr:x}, got tag 0x{tag:02x}"
    length = tag >> 1
    return raw[1 : 1 + length].decode("ascii")


@dataclass(frozen=True)
class _CaveRunResult:
    grants: list[tuple[int, str, int, int]]
    replacements: list[tuple[int, str, str]]
    deleted: list[int]
    sp_end: int
    sp_init: int
    x0_end: int
    reward_item: bytes
    has_reward: int
    sentinel: bytes


def _run_daily_kraken_cave(
    *,
    is_win: int,
    initial_heap_ptr: int = 0,
) -> _CaveRunResult:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(_CODE_BASE, _CODE_SIZE)
    uc.mem_map(_STACK_BASE, _STACK_SIZE)
    uc.mem_map(_STATE_JSON_ADDR, 0x1000)
    uc.mem_map(_MUTATION_RESULT_ADDR, 0x1000)

    uc.mem_write(WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR, WORLDBOSS_DAILY_KRAKEN_CAVE_BYTES)
    if initial_heap_ptr:
        # Mark libc++ std::string long mode (lsb=1) with heap pointer at +0x10.
        uc.mem_write(
            _MUTATION_RESULT_ADDR + 0xC0,
            struct.pack("<QQQ", 0x21, 12, initial_heap_ptr),
        )

    sp_init = _STACK_BASE + 0xF000
    uc.reg_write(UC_ARM64_REG_SP, sp_init)
    uc.reg_write(UC_ARM64_REG_X19, _STATE_JSON_ADDR)
    uc.reg_write(UC_ARM64_REG_X22, _MUTATION_RESULT_ADDR)
    uc.reg_write(UC_ARM64_REG_W25, is_win)
    uc.reg_write(UC_ARM64_REG_X0, 0)

    grants: list[tuple[int, str, int, int]] = []
    replacements: list[tuple[int, str, str]] = []
    deleted: list[int] = []
    sentinel = bytes(
        [len(b"patched!") << 1] + list(b"patched!") + [0] * (23 - len(b"patched!"))
    )

    def _on_code(emu: Uc, address: int, _size: int, _user_data: object) -> None:
        if address == _GRANT_ITEM_JSON_VADDR:
            sret = emu.reg_read(UC_ARM64_REG_X8)
            grants.append(
                (
                    emu.reg_read(UC_ARM64_REG_X0),
                    _read_libcxx_sso(emu, emu.reg_read(UC_ARM64_REG_X1)),
                    emu.reg_read(UC_ARM64_REG_W2),
                    sret,
                )
            )
            emu.mem_write(sret, struct.pack("<QQQ", 2, 0, 0))
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
        elif address == _REPLACE_RAW_VALUE_VADDR:
            target = emu.reg_read(UC_ARM64_REG_X0)
            replacements.append(
                (
                    target,
                    _read_libcxx_sso(emu, emu.reg_read(UC_ARM64_REG_X1)),
                    _read_libcxx_sso(emu, emu.reg_read(UC_ARM64_REG_X2)),
                )
            )
            emu.mem_write(target, sentinel)
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
        elif address == _OPERATOR_DELETE_VADDR:
            deleted.append(emu.reg_read(UC_ARM64_REG_X0))
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_LR))
        elif address == _RESUME_VADDR:
            emu.emu_stop()

    uc.hook_add(UC_HOOK_CODE, _on_code)
    uc.emu_start(WORLDBOSS_DAILY_KRAKEN_CAVE_VADDR, _RESUME_VADDR, timeout=1_000_000)

    return _CaveRunResult(
        grants=grants,
        replacements=replacements,
        deleted=deleted,
        sp_end=uc.reg_read(UC_ARM64_REG_SP),
        sp_init=sp_init,
        x0_end=uc.reg_read(UC_ARM64_REG_X0),
        reward_item=bytes(uc.mem_read(_MUTATION_RESULT_ADDR + 0xC0, 24)),
        has_reward=uc.mem_read(_MUTATION_RESULT_ADDR + 0x1C8, 1)[0],
        sentinel=sentinel,
    )


def test_worldboss_daily_kraken_cave_grants_500_on_win() -> None:
    res = _run_daily_kraken_cave(is_win=1)
    assert len(res.grants) == 1
    assert res.grants[0][:3] == (_STATE_JSON_ADDR, "280001", 500)
    assert res.replacements == [(res.grants[0][3], "item_count", "500")]
    assert res.deleted == []
    assert res.reward_item == res.sentinel
    assert res.has_reward == 1
    assert res.sp_end == res.sp_init
    assert res.x0_end == _STATE_JSON_ADDR


def test_worldboss_daily_kraken_cave_frees_existing_heap_reward_item() -> None:
    res = _run_daily_kraken_cave(is_win=1, initial_heap_ptr=_OLD_HEAP_PTR)
    assert res.deleted == [_OLD_HEAP_PTR]
    assert res.reward_item == res.sentinel
    assert res.has_reward == 1
    assert res.sp_end == res.sp_init


def test_worldboss_daily_kraken_cave_skips_grant_when_not_win() -> None:
    res = _run_daily_kraken_cave(is_win=0)
    assert res.grants == []
    assert res.replacements == []
    assert res.deleted == []
    assert res.has_reward == 0
    assert res.sp_end == res.sp_init
    assert res.x0_end == _STATE_JSON_ADDR
