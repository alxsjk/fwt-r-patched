"""Tests for Feature 07.06: Guild Raid Fire Support 100% HP + odd-turn auto-cast."""
from __future__ import annotations

import struct

import pytest

from core.core_patches import PatchOptions, apply_all_patches, validate_cave_layout
from core.elf_mapping import read_load_segments, translate_vaddr
from core.guild_raid_fire_support import (
    CAVE_BYTES,
    CAVE_VADDR,
    FIRE_SUPPORT_DAMAGE_EFFECT_ID,
    FIRE_SUPPORT_PATCHED_VALUES,
    FIRE_SUPPORT_STOCK_VALUES,
    LATE_HOOK_SITE,
    apply_guild_raid_fire_support,
    inspect_guildskilldata_rows,
    patch_guildskilldata_rows,
)
from core.patch_inspector import inspect_native_so


def test_generated_payload_matches_frozen_bytes() -> None:
    pytest.importorskip("keystone")
    from tools.gen_guild_raid_fire_support import generate

    assert generate() == CAVE_BYTES


def test_patch_and_inspect_native_so_and_idempotence(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    validate_cave_layout()
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_fire_support=True),
    )
    assert result.counts["guild_raid_fire_support"] == 2
    reports = inspect_native_so(result.so_bytes)
    assert reports["guild_raid_fire_support"].active

    again = apply_all_patches(
        result.so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_fire_support=True, allow_unknown=True),
    )
    assert again.counts["guild_raid_fire_support"] == 0
    assert again.so_bytes == result.so_bytes


@pytest.mark.parametrize("address", [CAVE_VADDR, LATE_HOOK_SITE])
def test_invalid_bytes_rejected_before_mutation(
    reference_buffers: tuple[bytes, bytes],
    address: int,
) -> None:
    buf = bytearray(reference_buffers[0])
    segments = read_load_segments(buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    buf[offset(address)] ^= 1
    before = bytes(buf)
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_guild_raid_fire_support(buf, offset)
    assert bytes(buf) == before


def test_guildskilldata_row_patch_and_idempotence() -> None:
    rows = [
        {
            "_guildSkillEffectId": FIRE_SUPPORT_DAMAGE_EFFECT_ID,
            "_value01": 0.10000000149011612,
            "_value01Factor": 0.009999999776482582,
            "_value02": 15000.0,
            "_value02Factor": 5000.0,
        },
        {
            "_guildSkillEffectId": 1048577,
            "_value01": 0.5,
            "_value01Factor": 0.1,
            "_value02": 0.0,
            "_value02Factor": 0.0,
        },
    ]
    assert patch_guildskilldata_rows(rows) == 4
    assert patch_guildskilldata_rows(rows) == 0
    active, details = inspect_guildskilldata_rows(rows)
    assert active
    assert "1048578" in details
    assert rows[0]["_value01"] == FIRE_SUPPORT_PATCHED_VALUES[0]
    assert rows[0]["_value01Factor"] == FIRE_SUPPORT_PATCHED_VALUES[1]
    assert rows[0]["_value02"] == FIRE_SUPPORT_PATCHED_VALUES[2]
    assert rows[0]["_value02Factor"] == FIRE_SUPPORT_PATCHED_VALUES[3]
    assert rows[1]["_value01"] == 0.5

    bad = [dict(zip(
        ("_guildSkillEffectId", "_value01", "_value01Factor", "_value02", "_value02Factor"),
        (FIRE_SUPPORT_DAMAGE_EFFECT_ID, 2.0, *FIRE_SUPPORT_STOCK_VALUES[1:]),
        strict=True,
    ))]
    with pytest.raises(ValueError, match="Unexpected guildskilldata effect"):
        patch_guildskilldata_rows(bad)


def test_unicorn_emulation_installer_and_turn_gating(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W0,
        UC_ARM64_REG_W1,
        UC_ARM64_REG_W4,
        UC_ARM64_REG_W20,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X5,
    )

    so_buf = bytearray(reference_buffers[0])
    segments = read_load_segments(so_buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    apply_guild_raid_fire_support(so_buf, offset)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    # Map server code page around 0xAB3000 (16 KB) & cave page 0xB2A000..0xB2C000
    # and cache page 0xBE3000, stack at 0x08000000, and fake il2cpp at 0x40000000.
    IL2CPP_BASE = 0x40000000
    STACK_TOP = 0x08008000
    STOP_ADDR = 0x09000000

    for addr, size in (
        (0x00AB3000, 0x10000),
        (0x00B2A000, 0x4000),
        (0x00BE3000, 0x2000),
        (0x08000000, 0x10000),
        (STOP_ADDR, 0x1000),
        (IL2CPP_BASE + 0x01640000, 0x4000),
        (IL2CPP_BASE + 0x01877000, 0x4000),
        (IL2CPP_BASE + 0x018E7000, 0x4000),
    ):
        uc.mem_map(addr, size)

    # Copy patched hook word + cave bytes into SO pages, and store il2cpp base cache.
    uc.mem_write(LATE_HOOK_SITE, bytes(so_buf[offset(LATE_HOOK_SITE):offset(LATE_HOOK_SITE) + 4]))
    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    uc.mem_write(0x00BE3798, struct.pack("<Q", IL2CPP_BASE))
    # Write expected 4 words into fake il2cpp at 0x018E7060 and RET stubs elsewhere.
    expected_words = (0x2A1403E1, 0xAA1F03E2, 0x97FE4128, 0x370015A0)
    uc.mem_write(IL2CPP_BASE + 0x018E7060, b"".join(struct.pack("<I", w) for w in expected_words))
    ret_insn = struct.pack("<I", 0xD65F03C0)
    for rva in (0x01640248, 0x01641F38, 0x01877508, 0x018E7320, 0x018E7334):
        uc.mem_write(IL2CPP_BASE + rva, ret_insn)
    uc.mem_write(0x00AB575C, ret_insn)
    uc.mem_write(0x00AB3360, struct.pack("<I", 0xD503201F))  # nop at return site

    events: list[tuple[str, int]] = []
    state = {"stage_ptr": 0x12340000, "turn_no": 2, "action_ret": 1, "action_calls": 0}

    def hook_code(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address == 0x00AB575C:
            base = engine.reg_read(UC_ARM64_REG_X0)
            rva = engine.reg_read(UC_ARM64_REG_W1)
            exp_ptr = engine.reg_read(UC_ARM64_REG_X2)
            patch_ptr = engine.reg_read(UC_ARM64_REG_X3)
            count = engine.reg_read(UC_ARM64_REG_W4)
            name_ptr = engine.reg_read(UC_ARM64_REG_X5)
            assert base == IL2CPP_BASE
            assert rva == 0x018E7060
            assert count == 4
            assert engine.mem_read(exp_ptr, 16) == engine.mem_read(base + rva, 16)
            assert bytes(engine.mem_read(name_ptr, 16)) == b"fire_support_odd"
            engine.mem_write(base + rva, bytes(engine.mem_read(patch_ptr, 16)))
            engine.reg_write(UC_ARM64_REG_W0, 1)
            events.append(("helper_installed", rva))
        elif address == IL2CPP_BASE + 0x01640248:
            events.append(("get_instance", 0))
            engine.reg_write(UC_ARM64_REG_X0, state["stage_ptr"])
        elif address == IL2CPP_BASE + 0x01641F38:
            events.append(("get_turn", engine.reg_read(UC_ARM64_REG_X0)))
            engine.reg_write(UC_ARM64_REG_W0, state["turn_no"])
        elif address == IL2CPP_BASE + 0x01877508:
            state["action_calls"] += 1
            events.append(("action", engine.reg_read(UC_ARM64_REG_W1)))
            assert engine.reg_read(UC_ARM64_REG_X0) == 0x55550000
            assert engine.reg_read(UC_ARM64_REG_X2) == 0
            engine.reg_write(UC_ARM64_REG_W0, state["action_ret"])
        elif address in (IL2CPP_BASE + 0x018E7320, IL2CPP_BASE + 0x018E7334):
            tag = "exit_true" if address == IL2CPP_BASE + 0x018E7320 else "exit_false"
            events.append((tag, 0))
            engine.emu_stop()
        elif address == 0x00AB3360:
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    # 1. Run post-Covault installer at 0xAB335C -> returns at 0xAB3360 with w0=4.
    uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM64_REG_W0, 99)
    uc.emu_start(LATE_HOOK_SITE, 0x00AB3360 + 4)
    assert events == [("helper_installed", 0x018E7060)]
    assert uc.reg_read(UC_ARM64_REG_W0) == 4
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP

    def run_hook(skill_id: int, turn_no: int, *, stage_ptr: int = 0x12340000, action_ret: int = 1) -> list[tuple[str, int]]:
        events.clear()
        state.update({"stage_ptr": stage_ptr, "turn_no": turn_no, "action_ret": action_ret})
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM64_REG_X0, 0x55550000)
        uc.reg_write(UC_ARM64_REG_W20, skill_id)
        uc.reg_write(UC_ARM64_REG_LR, STOP_ADDR)
        uc.emu_start(IL2CPP_BASE + 0x018E7060, STOP_ADDR)
        assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
        return list(events)

    # 0-based turn_no: 1 == HUD Turn 2 (even), 2 == HUD Turn 3 (odd), 0 == HUD Turn 1 (odd).
    # Even UI turn (HUD Turn 2 -> turn_no=1) + Fire Support (0x20000002): holds without Action.
    assert run_hook(0x20000002, 1) == [("get_instance", 0), ("get_turn", 0x12340000), ("exit_false", 0)]
    assert state["action_calls"] == 0

    # Even UI turn (HUD Turn 4 -> turn_no=3) + Fire Support (0x20000002): also holds.
    assert run_hook(0x20000002, 3) == [("get_instance", 0), ("get_turn", 0x12340000), ("exit_false", 0)]
    assert state["action_calls"] == 0

    # Odd UI turn (HUD Turn 3 -> turn_no=2) + Fire Support (0x20000002): calls Action and exits true.
    assert run_hook(0x20000002, 2, action_ret=1) == [
        ("get_instance", 0),
        ("get_turn", 0x12340000),
        ("action", 0x20000002),
        ("exit_true", 0),
    ]
    assert state["action_calls"] == 1

    # Odd UI turn (HUD Turn 1 -> turn_no=0) + Fire Support when Action returns 0: exits false.
    assert run_hook(0x20000002, 0, action_ret=0)[-1] == ("exit_false", 0)

    # Combat Support (0x20000004) on even UI turn (turn_no=1 -> HUD Turn 2): fires immediately.
    assert run_hook(0x20000004, 1, action_ret=1) == [("action", 0x20000004), ("exit_true", 0)]

    # Fail-open when GameStage.instance is null.
    assert run_hook(0x20000002, 1, stage_ptr=0, action_ret=1) == [
        ("get_instance", 0),
        ("action", 0x20000002),
        ("exit_true", 0),
    ]
