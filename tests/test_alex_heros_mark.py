"""Tests for Feature 12.03: Alex's Hero's Mark — The Unbroken Lance (native side).

The client hook bootstraps from the Covault permission-finalization flow, whose
epilogue is shared with several other features. These tests pin the chosen site
(so a future feature cannot collide with it again) and emulate the installer to
prove it preserves the flow's state and both of its branch outcomes.
"""
from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from core.alex_heros_mark import (
    ALEX_MARK_CLIENT_CAVE_MAX_SIZE,
    ALEX_MARK_CLIENT_CAVE_VADDR,
    ALEX_MARK_CLIENT_INSTALL_SITE,
    ALEX_MARK_CLIENT_INSTALL_STOCK,
    ALEX_MARK_CLIENT_INSTALL_W19_ZERO,
    ALEX_MARK_NAME,
    ALEX_MARK_SERVER_CAVE_SIZE,
    ALEX_MARK_SERVER_CAVE_VADDR,
    ALEX_MARK_SET_GROUP_ID,
    ALEX_MARK_SKILL_GROUP_ID,
    ALEX_SET_EFFECT01_ID,
    ALEX_SET_SKILL_ID,
    CLIENT_GET_COOLTIME_EXPECTED_WORDS,
    CLIENT_GET_COOLTIME_RVA,
    DONOR_AP_UP_RATE,
    DONOR_FINAL_POWER_BUFF,
    IL2CPP_BASE_CACHE,
    KIDS_HOOK_SITES,
    OVERLAP_LEVELS,
    PATCH_IL2CPP_HELPER,
    _has_valid_mark_effects,
    apply_alex_heros_mark_so,
    build_alex_heros_mark_client_cave,
    build_set_effect_rows,
    build_set_row,
    build_set_skill_row,
    overlap_description,
    patch_overlap_rows,
    patch_set_effect_rows,
    patch_set_skilldata_rows,
    patch_setitemtable_rows,
)
from core.core_patches import (
    BATTLE_ARENA_SAVE_LATE_SITE,
    GUILD_RAID_MERCENARY_CLIENT_HOOK,
    RUNE_UPGRADE_INSTALL_SITE,
    SINGLE_GEM_FANG_INSTALL_SITE,
    SINGLE_MOD_STONE_INSTALL_SITE,
    PatchOptions,
    apply_all_patches,
    validate_cave_layout,
)
from core.elf_mapping import read_load_segments, translate_vaddr
from core.patch_inspector import inspect_native_so

# Every other instruction of the same Covault flow that a feature already owns.
OTHER_COVAULT_HOOK_SITES = {
    "alex_awakening": 0xAB3378,
    "battle_arena_save_fix": BATTLE_ARENA_SAVE_LATE_SITE,
    "guild_raid_mercenary": GUILD_RAID_MERCENARY_CLIENT_HOOK,
    "single_gem_fang": SINGLE_GEM_FANG_INSTALL_SITE,
    "single_mod_stone": SINGLE_MOD_STONE_INSTALL_SITE,
    "rune_upgrade": RUNE_UPGRADE_INSTALL_SITE,
    "costume_packages_all": 0xAB3390,
    "equipment_tier_upgrades": 0xAB3394,
    "guild_raid_fire_support": 0xAB335C,
    "guild_raid_protection_persist": 0xAB32F4,
}


def _offset(so_bytes: bytes | bytearray):
    segments = read_load_segments(bytes(so_bytes))
    return lambda addr: translate_vaddr(segments, addr)


def test_install_site_is_not_shared_with_another_feature() -> None:
    collisions = {
        name: hex(addr)
        for name, addr in OTHER_COVAULT_HOOK_SITES.items()
        if addr == ALEX_MARK_CLIENT_INSTALL_SITE
    }
    assert not collisions, f"Hero's Mark installer site collides with {collisions}"


def test_stock_word_matches_reference_build(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    so_bytes = reference_buffers[0]
    offset = _offset(so_bytes)
    site = offset(ALEX_MARK_CLIENT_INSTALL_SITE)
    assert bytes(so_bytes[site:site + 4]) == ALEX_MARK_CLIENT_INSTALL_STOCK


def test_installer_branch_encodes_to_the_cave() -> None:
    install_bl, _cave = build_alex_heros_mark_client_cave()
    assert install_bl[3] & 0xFC == 0x94  # BL
    imm = int.from_bytes(install_bl, "little") & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    assert ALEX_MARK_CLIENT_INSTALL_SITE + (imm << 2) == ALEX_MARK_CLIENT_CAVE_VADDR


def test_cave_fits_and_keeps_its_landmarks() -> None:
    pytest.importorskip("capstone")
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

    _install_bl, cave = build_alex_heros_mark_client_cave()
    assert len(cave) <= ALEX_MARK_CLIENT_CAVE_MAX_SIZE

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    instructions = list(md.disasm(cave, ALEX_MARK_CLIENT_CAVE_VADDR))
    assert instructions, "cave did not disassemble"

    # Installer entry: no stack frame growth beyond its own push, and the
    # helper call plus both branch outcomes must be present.
    assert instructions[0].mnemonic == "stp"
    assert "[sp, #-0x20]!" in instructions[0].op_str
    helper_calls = [
        i for i in instructions
        if i.mnemonic == "bl" and int(i.op_str[1:], 16) == PATCH_IL2CPP_HELPER
    ]
    assert len(helper_calls) == 1
    fire_support = [
        i for i in instructions
        if i.mnemonic == "b" and int(i.op_str[1:], 16) == ALEX_MARK_CLIENT_INSTALL_W19_ZERO
    ]
    assert len(fire_support) == 1
    assert any(i.mnemonic == "cbnz" and "w19" in i.op_str for i in instructions)

    # The trampoline instruction pair is copied to the stack; its target is
    # resolved at runtime so the library's load address is included.
    blob_offset = cave.find(struct.pack("<II", 0x58000050, 0xD61F0200))
    assert blob_offset >= 0
    assert any(i.mnemonic == "adr" and i.op_str.startswith("x9,") for i in instructions)


def test_apply_alongside_battle_arena_save(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    """Regression: the Hero's Mark hook used to overwrite the Arena late site."""
    validate_cave_layout()
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(alex_heros_mark=True, battle_arena_save_fix=True),
    )
    assert result.counts["alex_heros_mark"] == 8
    assert result.counts["battle_arena_save_fix"] == 1

    reports = inspect_native_so(result.so_bytes)
    assert reports["alex_heros_mark"].active
    assert reports["battle_arena_save_fix"].active

    again = apply_all_patches(
        result.so_bytes,
        dex_bytes,
        PatchOptions(alex_heros_mark=True, battle_arena_save_fix=True, allow_unknown=True),
    )
    assert again.counts["alex_heros_mark"] == 0
    assert again.counts["battle_arena_save_fix"] == 0
    assert again.so_bytes == result.so_bytes


def test_surgical_diff_only_declared_sites_and_caves(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    so_bytes, dex_bytes = reference_buffers
    base = apply_all_patches(so_bytes, dex_bytes, PatchOptions())
    patched = apply_all_patches(so_bytes, dex_bytes, PatchOptions(alex_heros_mark=True))
    offset = _offset(so_bytes)
    diffs = {
        idx
        for idx, (a, b) in enumerate(
            zip(bytes(base.so_bytes), bytes(patched.so_bytes), strict=True)
        )
        if a != b
    }
    install_bl, cave = build_alex_heros_mark_client_cave()
    allowed = set()
    for site_va, *_rest in KIDS_HOOK_SITES:
        allowed |= set(range(offset(site_va), offset(site_va) + 4))
    for va, size in (
        (ALEX_MARK_SERVER_CAVE_VADDR, ALEX_MARK_SERVER_CAVE_SIZE),
        (ALEX_MARK_CLIENT_CAVE_VADDR, len(cave)),
    ):
        allowed |= set(range(offset(va), offset(va) + size))
    allowed |= set(range(offset(ALEX_MARK_CLIENT_INSTALL_SITE),
                       offset(ALEX_MARK_CLIENT_INSTALL_SITE) + 4))
    assert diffs <= allowed, "Hero's Mark changed bytes outside its declared sites"
    assert patched.so_bytes[offset(ALEX_MARK_CLIENT_INSTALL_SITE):
                            offset(ALEX_MARK_CLIENT_INSTALL_SITE) + 4] == install_bl
    # The Arena late site keeps its stock word even though both features run.
    assert patched.so_bytes[offset(BATTLE_ARENA_SAVE_LATE_SITE):
                            offset(BATTLE_ARENA_SAVE_LATE_SITE) + 4] == (
        bytes(so_bytes[offset(BATTLE_ARENA_SAVE_LATE_SITE):
                       offset(BATTLE_ARENA_SAVE_LATE_SITE) + 4])
    )


def test_rejects_unexpected_site_bytes(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    buf = bytearray(reference_buffers[0])
    offset = _offset(buf)
    buf[offset(ALEX_MARK_CLIENT_INSTALL_SITE)] ^= 1
    before = bytes(buf)
    with pytest.raises(ValueError, match="client install site"):
        apply_alex_heros_mark_so(buf, offset)
    assert bytes(buf) == before


def test_unicorn_installer_preserves_flow_and_branches() -> None:
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W0,
        UC_ARM64_REG_W1,
        UC_ARM64_REG_W4,
        UC_ARM64_REG_W19,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X20,
    )

    install_bl, cave = build_alex_heros_mark_client_cave()

    IL2CPP_BASE = 0x40000000
    STACK_TOP = 0x08008000
    FALLTHROUGH = ALEX_MARK_CLIENT_INSTALL_SITE + 4
    X19 = 0x1234_5678_9ABC_DEF0
    X20 = 0x0FED_CBA9_8765_4321

    def fresh() -> tuple[Uc, list[str], dict[str, int]]:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for addr, size in (
            (0x00AB3000, 0x10000),
            (0x00B2F000, 0x2000),
            (0x00BE3000, 0x2000),
            (0x08000000, 0x10000),
        ):
            uc.mem_map(addr, size)
        uc.mem_write(ALEX_MARK_CLIENT_INSTALL_SITE, install_bl)
        uc.mem_write(ALEX_MARK_CLIENT_CAVE_VADDR, cave)
        uc.mem_write(IL2CPP_BASE_CACHE, struct.pack("<Q", IL2CPP_BASE))
        # The IL2CPP helper returns "1 word patched"; emulate its return only,
        # the helper's own body is covered by the other runtime-patch tests.
        uc.mem_write(PATCH_IL2CPP_HELPER, struct.pack("<I", 0xD65F03C0))
        seen: dict[str, int] = {}
        events: list[str] = []

        def hook(engine: Uc, address: int, _size: int, _user: object) -> None:
            if address == PATCH_IL2CPP_HELPER:
                assert engine.reg_read(UC_ARM64_REG_X0) == IL2CPP_BASE
                assert engine.reg_read(UC_ARM64_REG_W1) == CLIENT_GET_COOLTIME_RVA
                expected_ptr = engine.reg_read(UC_ARM64_REG_X2)
                tramp_ptr = engine.reg_read(UC_ARM64_REG_X3)
                assert engine.reg_read(UC_ARM64_REG_W4) == 4
                assert bytes(engine.mem_read(expected_ptr, 16)) == b"".join(
                    struct.pack("<I", w) for w in CLIENT_GET_COOLTIME_EXPECTED_WORDS
                )
                tramp = bytes(engine.mem_read(tramp_ptr, 16))
                assert struct.unpack("<II", tramp[:8]) == (0x58000050, 0xD61F0200)
                assert struct.unpack("<Q", tramp[8:])[0] > ALEX_MARK_CLIENT_CAVE_VADDR
                assert bytes(engine.mem_read(engine.reg_read(UC_ARM64_REG_X5), 3)) == b"mk\x00"
                seen["tramp_va"] = struct.unpack("<Q", tramp[8:])[0]
                events.append("helper")
                engine.reg_write(UC_ARM64_REG_W0, 1)

        uc.hook_add(UC_HOOK_CODE, hook)
        return uc, events, seen

    # 1. w19 != 0: helper runs, then the flow resumes at the instruction
    # after the displaced `cbz` with x19/x20/sp intact.
    uc, events, seen = fresh()
    uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM64_REG_X20, X20)
    uc.reg_write(UC_ARM64_REG_W19, 1)
    uc.reg_write(UC_ARM64_REG_X19, (X19 & ~0xFFFFFFFF) | 1)
    x19_value = uc.reg_read(UC_ARM64_REG_X19)
    for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5):
        uc.reg_write(reg, 0xDEAD_0000 + reg)
    uc.emu_start(ALEX_MARK_CLIENT_INSTALL_SITE, FALLTHROUGH)
    assert events == ["helper"]
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
    assert uc.reg_read(UC_ARM64_REG_X19) == x19_value
    assert uc.reg_read(UC_ARM64_REG_X20) == X20
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    payload = next(
        i
        for i in md.disasm(cave, ALEX_MARK_CLIENT_CAVE_VADDR)
        if i.address == seen["tramp_va"]
    )
    assert payload.mnemonic == "cbz"

    # 2. w19 == 0: the stock branch target (fire-support hook site) is taken.
    uc, events, _ = fresh()
    uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM64_REG_X20, X20)
    uc.reg_write(UC_ARM64_REG_W19, 0)
    uc.reg_write(UC_ARM64_REG_X19, X19 & ~0xFFFFFFFF)
    x19_value = uc.reg_read(UC_ARM64_REG_X19)
    uc.emu_start(ALEX_MARK_CLIENT_INSTALL_SITE, ALEX_MARK_CLIENT_INSTALL_W19_ZERO)
    assert events == ["helper"]
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
    assert uc.reg_read(UC_ARM64_REG_X19) == x19_value

    # 3. No cached il2cpp base: the installer skips the helper but still
    # reproduces the stock branch and leaves the stack balanced.
    uc, events, _ = fresh()
    uc.mem_write(IL2CPP_BASE_CACHE, struct.pack("<Q", 0))
    uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM64_REG_W19, 1)
    uc.reg_write(UC_ARM64_REG_X19, (X19 & ~0xFFFFFFFF) | 1)
    x19_value = uc.reg_read(UC_ARM64_REG_X19)
    uc.emu_start(ALEX_MARK_CLIENT_INSTALL_SITE, FALLTHROUGH)
    assert events == []
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
    assert uc.reg_read(UC_ARM64_REG_X19) == x19_value


def test_installer_uses_relocated_payload_address() -> None:
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_W19, UC_ARM64_REG_X3

    relocation = 0x40000000
    stack = 0x8000000
    branch, cave = build_alex_heros_mark_client_cave()
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address, size in ((0xAB3000, 0x10000), (0xB2F000, 0x2000), (0xBE3000, 0x2000)):
        uc.mem_map(relocation + address, size)
    uc.mem_map(stack, 0x10000)
    uc.mem_write(relocation + ALEX_MARK_CLIENT_INSTALL_SITE, branch)
    uc.mem_write(relocation + ALEX_MARK_CLIENT_CAVE_VADDR, cave)
    uc.mem_write(relocation + IL2CPP_BASE_CACHE, struct.pack("<Q", 0x60000000))
    uc.mem_write(relocation + PATCH_IL2CPP_HELPER, struct.pack("<I", 0xD65F03C0))
    seen: list[int] = []

    def observe(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address == relocation + PATCH_IL2CPP_HELPER:
            data = bytes(engine.mem_read(engine.reg_read(UC_ARM64_REG_X3), 16))
            assert struct.unpack("<II", data[:8]) == (0x58000050, 0xD61F0200)
            seen.append(struct.unpack("<Q", data[8:])[0])

    uc.hook_add(UC_HOOK_CODE, observe)
    uc.reg_write(UC_ARM64_REG_SP, stack + 0x8000)
    uc.reg_write(UC_ARM64_REG_W19, 1)
    uc.emu_start(relocation + ALEX_MARK_CLIENT_INSTALL_SITE,
                 relocation + ALEX_MARK_CLIENT_INSTALL_SITE + 4)
    assert len(seen) == 1
    assert relocation + ALEX_MARK_CLIENT_CAVE_VADDR <= seen[0] < (
        relocation + ALEX_MARK_CLIENT_CAVE_VADDR + len(cave)
    )


@pytest.mark.parametrize(("level", "returns_zero"), [(9, False), (10, True)])
def test_cooldown_hook_reads_character_data(level: int, returns_zero: bool) -> None:
    """Exercise both cooldown paths with the character data at its verified offset."""
    pytest.importorskip("unicorn")
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_SP, UC_ARM64_REG_X0

    from core.alex_heros_mark import CLIENT_GET_COOLTIME_CONT_RVA, DESTINY_LANCE_SKILL_ID

    _, cave = build_alex_heros_mark_client_cave()
    insns = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(cave, ALEX_MARK_CLIENT_CAVE_VADDR))
    payload_adr = next(i for i in insns if i.mnemonic == "adr" and i.op_str.startswith("x9,"))
    payload = int(payload_adr.op_str.split("#")[-1], 16)
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for addr, size in ((0xB2F000, 0x2000), (0xBE3000, 0x2000), (0x10000000, 0x10000),
                       (0x40000000 + (CLIENT_GET_COOLTIME_CONT_RVA & ~0xFFF), 0x2000)):
        uc.mem_map(addr, size)
    uc.mem_write(ALEX_MARK_CLIENT_CAVE_VADDR, cave)
    uc.mem_write(IL2CPP_BASE_CACHE, struct.pack("<Q", 0x40000000))
    skill, skill_data, character, data, klass, mark = (
        0x10000100, 0x10000200, 0x10000300, 0x10000400, 0x10001000, 0x10003000
    )
    getter, done = 0x10005000, 0x10006000
    uc.mem_write(skill + 0x10, struct.pack("<QQ", character, skill_data))
    uc.mem_write(skill_data + 0x10, struct.pack("<I", DESTINY_LANCE_SKILL_ID))
    uc.mem_write(character + 0x20, struct.pack("<Q", data))
    uc.mem_write(data, struct.pack("<Q", klass))
    uc.mem_write(klass + 0xA40, struct.pack("<QQ", getter, 0))
    uc.mem_write(mark + 0x30, struct.pack("<I", level))
    uc.mem_write(getter, struct.pack("<I", 0xD65F03C0))
    seen: list[int] = []

    def hook(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address == getter:
            seen.append(engine.reg_read(UC_ARM64_REG_X0))
            engine.reg_write(UC_ARM64_REG_X0, mark)

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM64_REG_SP, 0x1000F000)
    uc.reg_write(UC_ARM64_REG_LR, done)
    uc.reg_write(UC_ARM64_REG_X0, skill)
    stop = done if returns_zero else 0x40000000 + CLIENT_GET_COOLTIME_CONT_RVA
    uc.emu_start(payload, stop)
    assert seen == [data]
    if returns_zero:
        assert uc.reg_read(UC_ARM64_REG_X0) == 0
    else:
        assert uc.reg_read(UC_ARM64_REG_X0) == skill


def test_set_row_is_built_with_a_free_group() -> None:
    row = build_set_row(ALEX_MARK_NAME)
    assert row["_setgroupid"] == ALEX_MARK_SET_GROUP_ID
    assert row["_setName"] == ALEX_MARK_NAME
    assert row["_setSkillid01"] == ALEX_SET_SKILL_ID
    assert row["_equipType"] == 3


def test_mark_effect_inspection_rejects_changed_semantics() -> None:
    rows = build_set_effect_rows({
        DONOR_FINAL_POWER_BUFF: {"_skillEffectType": 68},
        DONOR_AP_UP_RATE: {"_skillEffectType": 58},
    })
    assert _has_valid_mark_effects(rows)
    rows[0]["_effectValue"] = 0.0
    assert not _has_valid_mark_effects(rows)
    rows[0]["_effectValue"] = 0.20
    rows[1]["_precondition"] = 255
    assert not _has_valid_mark_effects(rows)


def test_final_skill_power_effect_and_idempotence() -> None:
    rows = [
        {"_skillEffectId": DONOR_FINAL_POWER_BUFF, "_skillEffectType": 68},
        {"_skillEffectId": DONOR_AP_UP_RATE, "_skillEffectType": 58},
    ]
    assert patch_set_effect_rows(rows) == 2
    effect = next(r for r in rows if r["_skillEffectId"] == ALEX_SET_EFFECT01_ID)
    assert effect["_precondition"] == 255
    assert effect["_preconValue"] == -1.0
    assert effect["_effectTarget"] == 2
    assert effect["_effectValue"] == pytest.approx(0.20)
    assert _has_valid_mark_effects(rows)
    assert patch_set_effect_rows(rows) == 0
    effect["_precondition"] = 71
    with pytest.raises(ValueError, match="differ"):
        patch_set_effect_rows(rows)


def test_set_row_refuses_to_hijack_a_stock_group() -> None:
    rows = [{
        "_setgroupid": ALEX_MARK_SET_GROUP_ID,
        "_setName": "Vampire",
        "_setSkillid01": 11556977,
        "_equipType": 3,
    }]
    with pytest.raises(ValueError, match="already used by 'Vampire'"):
        patch_setitemtable_rows(rows, "")


def test_overlap_descriptions_scale_and_announce_the_lv10_cooldown() -> None:
    texts = [overlap_description(level) for level in OVERLAP_LEVELS]
    assert "25%" in texts[0]
    assert "50%" in texts[1]
    assert "250%" in texts[-1]
    assert "Decreases Awakening Skill Cooldown by 1." in texts[-1]
    assert all("Cooldown" not in t for t in texts[:-1])


def test_set_skill_tooltip_matches_the_builder() -> None:
    rows: list[dict] = []
    assert patch_set_skilldata_rows(rows) == 1
    built = build_set_skill_row()
    assert rows[0]["_tooltip"] == built["_tooltip"]
    assert "[41FF3A]" in rows[0]["_tooltip"]
    assert rows[0]["_skillName"] == built["_skillName"]


def test_stock_bundles_leave_mark_ids_free_and_rows_build(
    reference_apk: Path,
) -> None:
    """The set group must be free in all locales, or the client shows another set."""
    from core.apk_tooling import _read_datatable_rows

    locales = ["", "chinese", "english", "german", "japanese", "spanish", "thai", "vietnamese"]
    with (
        zipfile.ZipFile(reference_apk) as apk,
        zipfile.ZipFile(io.BytesIO(apk.read("assets/fwt_resources_v1.zip"))) as inner,
    ):
        for suffix in locales:
            set_path = f"files/Resources/datatable/setitemtable{suffix}.unity3d"
            if set_path not in inner.namelist():
                continue
            rows, err = _read_datatable_rows(inner, set_path, label=set_path)
            assert rows is not None, err
            used = {int(r.get("_setgroupid", -1)) for r in rows}
            assert ALEX_MARK_SET_GROUP_ID not in used, (
                f"set group {ALEX_MARK_SET_GROUP_ID} is taken in {set_path}"
            )
            overlap_path = f"files/Resources/datatable/skilloverlaptable{suffix}.unity3d"
            orows, oerr = _read_datatable_rows(inner, overlap_path, label=overlap_path)
            assert orows is not None, oerr
            assert ALEX_MARK_SKILL_GROUP_ID not in {
                int(r.get("_groupId", -1)) for r in orows
            }, f"overlap group {ALEX_MARK_SKILL_GROUP_ID} is taken in {overlap_path}"

        set_rows, _ = _read_datatable_rows(
            inner, "files/Resources/datatable/setitemtableenglish.unity3d", label="set"
        )
        assert set_rows is not None
        vampire = next(r for r in set_rows if int(r.get("_setgroupid", -1)) == 30048)
        assert str(vampire["_setName"]) == "Vampire"  # the row that used to leak through
        assert patch_setitemtable_rows(set_rows, "english") == 1
        assert patch_setitemtable_rows(set_rows, "english") == 0
        ours = next(r for r in set_rows if int(r.get("_setgroupid", -1)) == ALEX_MARK_SET_GROUP_ID)
        assert str(ours["_setName"]) == ALEX_MARK_NAME
        assert str(vampire["_setName"]) == "Vampire"  # stock row untouched

        overlap_rows, _ = _read_datatable_rows(
            inner, "files/Resources/datatable/skilloverlaptableenglish.unity3d", label="overlap"
        )
        assert overlap_rows is not None
        assert patch_overlap_rows(overlap_rows) == len(OVERLAP_LEVELS)
        mine = sorted(
            (r for r in overlap_rows if int(r.get("_groupId", -1)) == ALEX_MARK_SKILL_GROUP_ID),
            key=lambda r: int(r["_equipLevel"]),
        )
        assert [int(r["_equipLevel"]) for r in mine] == list(OVERLAP_LEVELS)
        assert round(float(mine[0]["_effect01Extravalue"]), 4) == 0.25
        assert round(float(mine[-1]["_effect01Extravalue"]), 4) == 2.5
        assert mine[0]["_desEquip"] == overlap_description(1)
        assert "Decreases Awakening Skill Cooldown by 1." in str(mine[-1]["_desEquip"])

        skill_rows, _ = _read_datatable_rows(
            inner, "files/Resources/datatable/skilldataenglish.unity3d", label="skilldata"
        )
        assert skill_rows is not None
        assert patch_set_skilldata_rows(skill_rows) == 1
        skill = next(
            r for r in skill_rows if int(r.get("_skillId", -1)) == ALEX_SET_SKILL_ID
        )
        assert skill["_tooltip"] == build_set_skill_row()["_tooltip"]
        assert "[41FF3A]" in str(skill["_tooltip"])
        assert patch_set_skilldata_rows(skill_rows) == 0

        effect_rows, err = _read_datatable_rows(
            inner, "files/Resources/datatable/skilleffecttableenglish.unity3d", label="effects"
        )
        assert effect_rows is not None, err
        donor = next(r for r in effect_rows if r.get("_skillEffectId") == DONOR_FINAL_POWER_BUFF)
        assert (donor["_skillEffectType"], donor["_effectTarget"], donor["_precondition"]) == (68, 2, 255)
        team = next(r for r in skill_rows if r.get("_skillId") == 11608088)
        assert team["_skillTarget"] == 2
        assert patch_set_effect_rows(effect_rows) == 2
        assert _has_valid_mark_effects(effect_rows)
        assert patch_set_effect_rows(effect_rows) == 0
