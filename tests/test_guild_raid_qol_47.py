"""Tests for 2.5.47 Guild Raid QoL asset tables and 1-fang-all-3-gem-slots cave."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W0,
    UC_ARM64_REG_W2,
    UC_ARM64_REG_W4,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X30,
)

from core.core_patches import (
    SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES,
    SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR,
    SINGLE_GEM_FANG_ALL_HOLES_TARGET,
    validate_cave_layout,
)
from core.guild_raid_fire_support import (
    inspect_guildskilldata_rows,
    patch_guildskilldata_rows,
)
from core.guild_raid_qol_assets import (
    ABSOLUTE_PROTECTION_SKILL_ID,
    GUILD_RAID_BOSS_MONSTER_IDS,
    GUILD_SKILL_ALLY_TARGET,
    GUILD_SKILL_MAX_SPECS,
    GUILD_SKILL_MP_EFFECT_ID,
    GUILD_SKILL_VALUE_FIELDS,
    inspect_guildskilldata_max_rows,
    inspect_guildskillinfo_max_rows,
    inspect_monsterdata_boss_car_rows,
    patch_guildskilldata_max_rows,
    patch_guildskillinfo_max_rows,
    patch_monsterdata_boss_car_rows,
)


def _sample_guildskill_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = [
        {
            "_guildSkillEffectId": 1048578,
            "_value01": 0.1,
            "_value01Factor": 0.01,
            "_value02": 15000.0,
            "_value02Factor": 5000.0,
        }
    ]
    for eid, (stock, _patched) in GUILD_SKILL_MAX_SPECS.items():
        row: dict[str, object] = {"_guildSkillEffectId": eid}
        for field, val in zip(GUILD_SKILL_VALUE_FIELDS, stock, strict=True):
            row[field] = val
        rows.append(row)
    return rows


def _sample_monster_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = [
        {"_monsterId": mid, "_boss": 100, "_car": -1.0}
        for mid in sorted(GUILD_RAID_BOSS_MONSTER_IDS)
    ]
    rows.append({"_monsterId": 1694502931, "_boss": 100, "_car": -1.0})
    return rows


def test_guildskilldata_max_rows_compose_with_fire_support() -> None:
    rows = _sample_guildskill_rows()

    ok, detail = inspect_guildskilldata_max_rows(rows)
    assert not ok
    assert "Original" in detail

    assert patch_guildskilldata_rows(rows) == 4
    assert patch_guildskilldata_max_rows(rows) == len(GUILD_SKILL_MAX_SPECS)

    # Idempotent on repeat run
    assert patch_guildskilldata_max_rows(rows) == 0

    ok_fs, _ = inspect_guildskilldata_rows(rows)
    ok_max, _ = inspect_guildskilldata_max_rows(rows)
    assert ok_fs
    assert ok_max

    # Reverse order still composes identically
    rows_rev = _sample_guildskill_rows()
    assert patch_guildskilldata_max_rows(rows_rev) == len(GUILD_SKILL_MAX_SPECS)
    assert patch_guildskilldata_rows(rows_rev) == 4
    assert rows_rev == rows


def test_guildskilldata_max_rows_reject_unexpected_values() -> None:
    rows = _sample_guildskill_rows()
    rows[1]["_value01"] = 1234.0
    with pytest.raises(ValueError, match="Unexpected guildskilldata row"):
        patch_guildskilldata_max_rows(rows)

    bad_inspect = _sample_guildskill_rows()
    bad_inspect.pop()
    ok, msg = inspect_guildskilldata_max_rows(bad_inspect)
    assert not ok
    assert "missing effects" in msg


def test_monsterdata_boss_car_rows_patch_and_inspect() -> None:
    rows = _sample_monster_rows()
    untouched = copy.deepcopy(rows[-1])

    ok, detail = inspect_monsterdata_boss_car_rows(rows)
    assert not ok
    assert "Original" in detail

    assert patch_monsterdata_boss_car_rows(rows) == 70
    assert patch_monsterdata_boss_car_rows(rows) == 0
    assert rows[-1] == untouched

    ok, detail = inspect_monsterdata_boss_car_rows(rows)
    assert ok
    assert "70 Guild Raid boss rows" in detail

    bad_rows = _sample_monster_rows()
    bad_rows[0]["_car"] = 0.05
    with pytest.raises(ValueError, match="Unexpected monsterdata _car"):
        patch_monsterdata_boss_car_rows(bad_rows)


def test_guildskillinfo_absolute_protection_mp_patch_and_inspect() -> None:
    rows: list[dict[str, object]] = [
        {"_guildSkillId": 536870913, "_effect03Id": -1, "_effect03Target": 255},
        {
            "_guildSkillId": ABSOLUTE_PROTECTION_SKILL_ID,
            "_effect03Id": -1,
            "_effect03Target": 255,
        },
    ]
    ok, detail = inspect_guildskillinfo_max_rows(rows)
    assert not ok
    assert "Original" in detail

    assert patch_guildskillinfo_max_rows(rows) == 1
    assert patch_guildskillinfo_max_rows(rows) == 0
    assert rows[1]["_effect03Id"] == GUILD_SKILL_MP_EFFECT_ID
    assert rows[1]["_effect03Target"] == GUILD_SKILL_ALLY_TARGET

    ok, detail = inspect_guildskillinfo_max_rows(rows)
    assert ok
    assert "1048581" in detail

    bad_rows: list[dict[str, object]] = [
        {"_guildSkillId": ABSOLUTE_PROTECTION_SKILL_ID, "_effect03Id": 999, "_effect03Target": 1}
    ]
    with pytest.raises(ValueError, match="Unexpected guildskillinfo"):
        patch_guildskillinfo_max_rows(bad_rows)
    with pytest.raises(ValueError, match="missing skill row"):
        patch_guildskillinfo_max_rows([{"_guildSkillId": 536870913}])


def test_single_gem_fang_all_holes_cave_disasm_and_unicorn() -> None:
    validate_cave_layout()

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(
        md.disasm(SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES, SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR)
    )
    assert [ins.mnemonic for ins in insns] == [
        "stp", "mov", "stp", "str", "mov", "mov", "mov",
        "mov", "mov", "mov", "mov", "mov", "bl", "and", "add", "cmp", "b.lo",
        "mov", "ldr", "ldp", "ldp", "ret",
    ]

    def run_emu(*, fail_slot: int | None = None) -> tuple[list[tuple[int, int, int, int, int]], int]:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(0xA00000, 0x200000)
        uc.mem_map(0x2000000, 0x10000)
        uc.mem_write(SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR, SINGLE_GEM_FANG_ALL_HOLES_CAVE_BYTES)
        sentinel = 0xB00000
        uc.mem_write(sentinel, bytes.fromhex("00000014"))

        calls: list[tuple[int, int, int, int, int]] = []

        def on_code(u: Uc, addr: int, _size: int, _data: object) -> None:
            if addr == SINGLE_GEM_FANG_ALL_HOLES_TARGET:
                hole_pos = u.reg_read(UC_ARM64_REG_W2)
                calls.append((
                    u.reg_read(UC_ARM64_REG_X0),
                    u.reg_read(UC_ARM64_REG_X1),
                    hole_pos,
                    u.reg_read(UC_ARM64_REG_X3),
                    u.reg_read(UC_ARM64_REG_W4),
                ))
                u.reg_write(UC_ARM64_REG_W0, 0 if hole_pos == fail_slot else 1)
                u.reg_write(UC_ARM64_REG_X30, u.reg_read(UC_ARM64_REG_X30))
                ret_addr = u.reg_read(UC_ARM64_REG_X30)
                # Simulate `ret` from update_equipment_hole_json cleanly
                u.mem_write(SINGLE_GEM_FANG_ALL_HOLES_TARGET, bytes.fromhex("c0035fd6"))
                _ = ret_addr
            elif addr == sentinel:
                u.emu_stop()

        uc.mem_write(SINGLE_GEM_FANG_ALL_HOLES_TARGET, bytes.fromhex("c0035fd6"))
        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.reg_write(UC_ARM64_REG_SP, 0x2008000)
        uc.reg_write(UC_ARM64_REG_X22, 0x11112222)
        uc.reg_write(UC_ARM64_REG_X24, 930)
        uc.reg_write(UC_ARM64_REG_X3, 0x2008020)
        uc.reg_write(UC_ARM64_REG_X19, 0xCAFEBABE)
        uc.reg_write(UC_ARM64_REG_X20, 0xDEADBEEF)
        uc.reg_write(UC_ARM64_REG_X21, 0x12345678)
        uc.reg_write(UC_ARM64_REG_X30, sentinel)
        uc.emu_start(SINGLE_GEM_FANG_ALL_HOLES_CAVE_VADDR, sentinel)
        assert uc.reg_read(UC_ARM64_REG_SP) == 0x2008000
        assert uc.reg_read(UC_ARM64_REG_X19) == 0xCAFEBABE
        assert uc.reg_read(UC_ARM64_REG_X20) == 0xDEADBEEF
        assert uc.reg_read(UC_ARM64_REG_X21) == 0x12345678
        return calls, uc.reg_read(UC_ARM64_REG_W0)

    calls, rc = run_emu()
    assert calls == [
        (0x11112222, 930, 1, 0x2008020, 1),
        (0x11112222, 930, 2, 0x2008020, 1),
        (0x11112222, 930, 3, 0x2008020, 1),
    ]
    assert rc == 1

    calls_fail, rc_fail = run_emu(fail_slot=2)
    assert len(calls_fail) == 3
    assert rc_fail == 0


@pytest.mark.integration
def test_reference_apk_assets_match_47_tables() -> None:
    apk_path = Path(__file__).resolve().parents[1] / "source" / "fwt_0.682_offline_v1574.apk"
    if not apk_path.exists():
        pytest.skip("Reference APK not present")
    import io
    import zipfile

    import UnityPy

    from core.apk_tooling import _decrypt_datatable
    from core.guild_raid_qol_assets import (
        GUILD_SKILL_DATA_CLIENT_ASSET_PATH,
        GUILD_SKILL_INFO_CLIENT_ASSETS,
        MONSTER_DATA_CLIENT_ASSET_PATH,
    )

    with zipfile.ZipFile(apk_path, "r") as zf:
        res_zip = zipfile.ZipFile(io.BytesIO(zf.read("assets/fwt_resources_v1.zip")), "r")
        gs_clear, _, _ = _decrypt_datatable(res_zip.read(GUILD_SKILL_DATA_CLIENT_ASSET_PATH))
        gs_rows = next(
            o.read_typetree()["_data"]
            for o in UnityPy.load(gs_clear).objects
            if o.type.name == "MonoBehaviour"
        )
        assert patch_guildskilldata_max_rows(gs_rows) == len(GUILD_SKILL_MAX_SPECS)
        assert inspect_guildskilldata_max_rows(gs_rows)[0] is True

        for info_asset in GUILD_SKILL_INFO_CLIENT_ASSETS:
            gi_clear, _, _ = _decrypt_datatable(res_zip.read(info_asset))
            gi_rows = next(
                o.read_typetree()["_data"]
                for o in UnityPy.load(gi_clear).objects
                if o.type.name == "MonoBehaviour"
            )
            assert patch_guildskillinfo_max_rows(gi_rows) == 1
            assert inspect_guildskillinfo_max_rows(gi_rows)[0] is True

        m_clear, _, _ = _decrypt_datatable(res_zip.read(MONSTER_DATA_CLIENT_ASSET_PATH))
        m_rows = next(
            o.read_typetree()["_data"]
            for o in UnityPy.load(m_clear).objects
            if o.type.name == "MonoBehaviour"
        )
        assert patch_monsterdata_boss_car_rows(m_rows) == len(GUILD_RAID_BOSS_MONSTER_IDS)
        assert inspect_monsterdata_boss_car_rows(m_rows)[0] is True
