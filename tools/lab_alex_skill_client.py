"""Assemble and emulate dev-only client hooks for Awakened Alex's 5th skill (0x100185).

Code lives in libfwt_local_server.so's clean cave (0xB2EA8C..0xB2FAA0) and is
installed into libil2cpp.so after AppSealing finalization by chaining from
0xB2A918 (end of the existing 0xB2A800 post-AppSealing initializer) via 0xAB575C.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W0,
    UC_ARM64_REG_W1,
    UC_ARM64_REG_W20,
    UC_ARM64_REG_W21,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X29,
)

SKILL_ID = 0x100185

# libfwt_local_server.so addresses (ELF VAs)
CLIENT_CAVE_START = 0xB2EA8C
CLIENT_CAVE_END = 0xB2FAA0
RELEASE_LATE_HOOK_SITE = 0xAB3378
RELEASE_LATE_HOOK_EXPECTED = bytes.fromhex("4e4c0294")  # bl 0xb464b0 (__android_log_print)
ORIG_LATE_LOG_FN = 0xB464B0
PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798

# libil2cpp.so RVAs (runtime unsealed Assembly-CSharp / Unity / IL2CPP)
RVA_GAME_STAGE_GET_INSTANCE = 0x1640248
RVA_GAME_STAGE_GET_OPPONENT_CAMP = 0x1641FA4
RVA_GAME_STAGE_CHANGE_TILE_TYPE = 0x1657D8C
RVA_CAMP_GET_COUNT = 0x1AE9BE8
RVA_CAMP_GET_ITEM = 0x1AE9B60
RVA_GAMEMAPTILE_GET_DISTANCE = 0x1C9B86C
RVA_GAMEMAPTILE_SET_ATTRIBUTE = 0x1C992A4
RVA_IL2CPP_CLASS_GET_ITF_METHOD = 0xDEBC64
RVA_MONSTER_TYPEINFO_SLOT = 0x3A006D0
RVA_ICHAR_ASSET_TYPEINFO_SLOT = 0x3A1FAF8

RVA_SKILL_IS_CASTABLE_EPILOGUE = 0x1B6F9C0
RVA_SKILL_IS_AWAKENING_SKILL = 0x1B6F560
RVA_SKILL_CONTAINER_GET_CURRENT_SKILL = 0x2022F08
RVA_SKILL_CONTAINER_GET_ITEM = 0x2022E98
RVA_SKILL_CONTAINER_GET_ANIM_HOOK = 0x2022FA0
RVA_SKILL_CONTAINER_GET_ANIM_CONT = 0x2022FB0
RVA_PLAYER_ON_GUI_CAST_BTN_HOOK = 0x18E93FC
RVA_GAME_GUI_SHOW_UI_AS_TARGET_ON = 0x1C8B51C
RVA_PLAYER_HANDLE_INPUT = 0x18E6AA8
RVA_CASTING_ACTION_HOOK = 0x1885DBC
RVA_CASTING_ACTION_ATTACK_STATE = 0x1885F58
RVA_CASTING_ACTION_AWAKE_STATE = 0x1885DCC
RVA_CASTING_ACTION_NULL_ERR = 0x18860D8
RVA_EFFECT_IS_EQUAL = 0x2022954
RVA_TAKE_SKILL_SWAP_HOOK = 0x1F07C9C
RVA_TAKE_SKILL_NOT_SWAP = 0x1F07CDC
RVA_TAKE_SKILL_SWAP_IMMUNE_CHECK = 0x1F07CAC
RVA_TAKE_SKILL_SWAP_EXEC = 0x1F07F10
RVA_TAKE_SKILL_CASTER_TILE_HOOK = 0x1F08498
RVA_TAKE_SKILL_CASTER_TILE_RESUME = 0x1F084A8
RVA_UI_EASY_BRANCH_HOOK = 0x17E5628
RVA_UI_EASY_CONTINUE = 0x17E5638
RVA_UI_NORMAL_CAST = 0x17E59F8
RVA_UI_NULL_ERROR = 0x17E5A44
RVA_AI_ATTACK_HOOK = 0x1A38BE0
RVA_AI_ATTACK = 0x1A38CC4
RVA_AI_ATTACK_CONT = 0x1A38BF0
RVA_PLAYER_AI_ATTACK_HOOK = 0x18EB104
RVA_PLAYER_AI_ATTACK_CONT = 0x18EB114
RVA_PLAYER_AI_ATTACK_RETURN = 0x18EB5CC
RVA_PLAYER_AI_ATTACK_NULL = 0x18EB5E4


@dataclass(frozen=True)
class ClientHookSpec:
    name: str
    rva: int
    expected_words: tuple[int, int, int, int]
    label: str


CLIENT_HOOKS: tuple[ClientHookSpec, ...] = (
    ClientHookSpec(
        "skill_is_castable",
        RVA_SKILL_IS_CASTABLE_EPILOGUE,
        (0xA9457BFD, 0xA9444FF4, 0xA94357F6, 0xA9425FF8),
        "hook_is_castable",
    ),
    ClientHookSpec(
        "player_on_gui_cast_button",
        RVA_PLAYER_ON_GUI_CAST_BTN_HOOK,
        (0xA9427BFD, 0xA9414FF4, 0xAA1F03E2, 0xF84307F5),
        "hook_on_cast_btn",
    ),
    ClientHookSpec(
        "skill_container_anim_type",
        RVA_SKILL_CONTAINER_GET_ANIM_HOOK,
        (0x97ED3170, 0x36000060, 0x321C03E0, 0x14000018),
        "hook_get_anim_type",
    ),
    ClientHookSpec(
        "casting_action_attack_state",
        RVA_CASTING_ACTION_HOOK,
        (0x940BA5E9, 0xF9400A76, 0xB40018B6, 0x36000C80),
        "hook_casting_action",
    ),
    ClientHookSpec(
        "take_skill_swap_bypass",
        RVA_TAKE_SKILL_SWAP_HOOK,
        (0x94046B2E, 0x360001E0, 0xD10023A8, 0xF8500108),
        "hook_take_skill_swap",
    ),
    ClientHookSpec(
        "take_skill_caster_org_tile",
        RVA_TAKE_SKILL_CASTER_TILE_HOOK,
        (0xAA1703E0, 0xAA1803E1, 0xD63F0100, 0xD10123A8),
        "hook_take_skill_caster_tile",
    ),
    ClientHookSpec(
        "alex_skip_easy_skill",
        RVA_UI_EASY_BRANCH_HOOK,
        (0x36001E95, 0xF9403A68, 0xB40020A8, 0xF9402D00),
        "hook_skip_easy_skill",
    ),
    ClientHookSpec(
        "alex_auto_attack_target",
        RVA_AI_ATTACK_HOOK,
        (0xAA1303E0, 0xAA1403E1, 0x94000037, 0xF9400E69),
        "hook_auto_attack_target",
    ),
    ClientHookSpec(
        "alex_player_auto_target",
        RVA_PLAYER_AI_ATTACK_HOOK,
        (0xF9400E68, 0xB40026E8, 0xF9402900, 0xB40026A0),
        "hook_player_auto_target",
    ),
)


def _mov32(reg: str, value: int) -> str:
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    lines = [f"movz {reg}, #{lo:#x}"]
    if hi:
        lines.append(f"movk {reg}, #{hi:#x}, lsl #16")
    return "\n        ".join(lines)


def _add_rva(dst: str, base_reg: str, rva: int) -> str:
    # AArch64 add supports 12-bit imm optionally shifted by 12; build safely via scratch x17
    # unless rva fits in 24-bit unsigned. All libil2cpp RVAs here fit in 26 bits (<0x04000000).
    lo = rva & 0xFFF
    hi = (rva >> 12) & 0xFFF
    top = (rva >> 24) & 0xFF
    if top == 0:
        parts = []
        if hi:
            parts.append(f"add {dst}, {base_reg}, #{hi:#x}, lsl #12")
            base_reg = dst
        if lo or not parts:
            parts.append(f"add {dst}, {base_reg}, #{lo:#x}")
        return "\n        ".join(parts)
    if base_reg in ("x17", "w17"):
        raise ValueError("base_reg cannot be x17")
    return "\n        ".join((_mov32("w17", rva), f"add {dst}, {base_reg}, w17, uxtw"))


def _asm(source: str, address: int) -> bytes:
    code, count = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(source, addr=address)
    if not count or code is None:
        raise ValueError(f"Keystone failed to assemble at {address:#x}")
    return bytes(code)


def _load_il2cpp_base(reg: str) -> str:
    page = IL2CPP_BASE_CACHE & ~0xFFF
    off = IL2CPP_BASE_CACHE & 0xFFF
    return f"adrp {reg}, {page:#x}\n        ldr {reg}, [{reg}, #{off:#x}]"


def _check_skill_id_eq_candidate(skill_reg: str, tmp_reg: str, fail_label: str) -> str:
    return f"""
        cbz {skill_reg}, {fail_label}
        ldr {tmp_reg}, [{skill_reg}, #0x18]
        cbz {tmp_reg}, {fail_label}
        ldr w17, [{tmp_reg}, #0x10]
        {_mov32("w16", SKILL_ID)}
        cmp w17, w16
        b.ne {fail_label}"""


def assemble_client_cave() -> tuple[bytes, bytes]:
    """Build (late_branch_4B, client_cave_bytes) for libfwt_local_server.so."""
    install_lines = [
        "installer_entry:",
        "    sub sp, sp, #0x60",
        "    stp x29, x30, [sp, #0x50]",
        "    stp x19, x20, [sp, #0x40]",
        "    add x29, sp, #0x50",
        f"    bl {ORIG_LATE_LOG_FN:#x}",
        f"    {_load_il2cpp_base('x19')}",
        "    cbz x19, installer_done",
        f"    {_mov32('w9', 0x58000050)}",
        "    str w9, [sp]",
        f"    {_mov32('w9', 0xD61F0200)}",
        "    str w9, [sp, #4]",
    ]
    for idx, hook in enumerate(CLIENT_HOOKS):
        install_lines.extend([
            f"    {_mov32('w1', hook.rva)}",
            f"    adr x2, exp_{idx}",
            f"    adr x9, {hook.label}",
            "    str x9, [sp, #8]",
            "    mov x0, x19",
            "    mov x3, sp",
            "    mov w4, #4",
            f"    adr x5, hook_name_{idx}",
            f"    bl {PATCH_IL2CPP_HELPER:#x}",
            "    mov w20, w0",
            "    mov w0, #4",
            "    adr x1, hook_log_tag",
            "    adr x2, hook_log_format",
            f"    mov w3, #{idx}",
            "    mov w4, w20",
            f"    bl {ORIG_LATE_LOG_FN:#x}",
        ])
    install_lines.extend([
        "installer_done:",
        "    ldp x19, x20, [sp, #0x40]",
        "    ldp x29, x30, [sp, #0x50]",
        "    add sp, sp, #0x60",
        "    ret",
    ])

    data_lines = [".p2align 2"]
    for idx, hook in enumerate(CLIENT_HOOKS):
        data_lines.append(f"exp_{idx}:")
        for word in hook.expected_words:
            data_lines.append(f"    .word {word:#010x}")
    for label, value in (
        ("hook_log_tag", "FWT-ALEX-LAB"),
        ("hook_log_format", "hook=%d installed=%d"),
        ("cast_log_format", "cast_skill=%d"),
        ("boss_log_format", "boss_found=%d"),
        ("boss_count_log_format", "boss_count=%d"),
        ("tile_log_format", "boss_tile_attribute=%d"),
        ("input_log_format", "input_result=%d"),
        ("auto_boss_log_format", "auto_boss_found=%d"),
        ("player_auto_skill_format", "player_auto_skill=%d"),
        *((f"hook_name_{idx}", hook.name) for idx, hook in enumerate(CLIENT_HOOKS)),
    ):
        data_lines.append(f"{label}:")
        data_lines.append("    .byte " + ", ".join(str(byte) for byte in value.encode("ascii") + b"\0"))

    source = f"""
    {chr(10).join(install_lines)}

    // CharacterAsset/ICharacterAsset::get_tile(x0=asset, x1=il2cpp_base) -> GameMapTile* x0
    get_asset_tile:
        cbz x0, get_asset_tile_null
        stp x29, x30, [sp, #-0x20]!
        stp x19, x20, [sp, #0x10]
        mov x19, x0
        {_add_rva('x10', 'x1', RVA_ICHAR_ASSET_TYPEINFO_SLOT)}
        ldr x10, [x10]
        ldr x1, [x10]
        ldr x8, [x19]
        ldrh w9, [x8, #0x126]
        cbz x9, get_asset_tile_fallback
        ldr x11, [x8, #0xb0]
        mov x10, xzr
        add x11, x11, #8
    get_asset_tile_loop:
        ldur x12, [x11, #-8]
        cmp x12, x1
        b.eq get_asset_tile_found
        add x10, x10, #1
        cmp x10, x9
        add x11, x11, #0x10
        b.lo get_asset_tile_loop
    get_asset_tile_fallback:
        mov w2, #1
        mov x0, x19
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_IL2CPP_CLASS_GET_ITF_METHOD)}
        blr x16
        b get_asset_tile_call
    get_asset_tile_found:
        ldr w9, [x11]
        add w9, w9, #1
        add x8, x8, w9, uxtw #4
        add x0, x8, #0x130
    get_asset_tile_call:
        ldp x8, x1, [x0]
        mov x0, x19
        blr x8
        ldp x19, x20, [sp, #0x10]
        ldp x29, x30, [sp], #0x20
        ret
    get_asset_tile_null:
        mov x0, xzr
        ret

    // find_nearest_boss_tile(x0=caster, w1=mark_all) -> tile x0, count w1, character x2
    find_nearest_boss_tile:
        cbz x0, fnbt_ret_null
        stp x29, x30, [sp, #-0x80]!
        stp x27, x28, [sp, #0x10]
        stp x25, x26, [sp, #0x20]
        stp x23, x24, [sp, #0x30]
        stp x21, x22, [sp, #0x40]
        stp x19, x20, [sp, #0x50]
        mov x29, sp
        str w1, [sp, #0x60]
        str xzr, [sp, #0x70]
        mov w28, wzr

        ldr x8, [x0, #0x28]
        cbz x8, fnbt_fail
        {_load_il2cpp_base('x19')}
        cbz x19, fnbt_fail
        mov x0, x8
        mov x1, x19
        bl get_asset_tile
        mov x20, x0
        cbz x20, fnbt_fail

        mov x0, xzr
        {_add_rva('x16', 'x19', RVA_GAME_STAGE_GET_INSTANCE)}
        blr x16
        cbz x0, fnbt_fail
        mov x1, xzr
        {_add_rva('x16', 'x19', RVA_GAME_STAGE_GET_OPPONENT_CAMP)}
        blr x16
        mov x21, x0
        cbz x21, fnbt_fail

        mov x1, xzr
        {_add_rva('x16', 'x19', RVA_CAMP_GET_COUNT)}
        blr x16
        mov w22, w0
        cmp w22, #0
        b.le fnbt_fail

        {_add_rva('x8', 'x19', RVA_MONSTER_TYPEINFO_SLOT)}
        ldr x8, [x8]
        ldr x23, [x8]
        cbz x23, fnbt_fail

        mov x24, xzr
        mov w25, #0x7fffffff
        mov w26, wzr

    fnbt_loop:
        cmp w26, w22
        b.ge fnbt_done
        mov x0, x21
        mov w1, w26
        {_add_rva('x16', 'x19', RVA_CAMP_GET_ITEM)}
        blr x16
        cbz x0, fnbt_next
        ldrb w8, [x0, #0x118]
        cbnz w8, fnbt_next
        ldrb w8, [x0, #0x119]
        cbnz w8, fnbt_next
        ldrb w8, [x0, #0x11a]
        cbnz w8, fnbt_next

        ldr x9, [x0]
        cbz x9, fnbt_next
        ldrb w10, [x23, #0x128]
        ldrb w11, [x9, #0x128]
        cmp w11, w10
        b.lo fnbt_next
        ldr x12, [x9, #0xc8]
        add x12, x12, w10, uxtw #3
        ldur x12, [x12, #-8]
        cmp x12, x23
        b.ne fnbt_next

        ldr x8, [x0, #0x1a8]
        cbz x8, fnbt_next
        ldrb w9, [x8, #0x19]
        cmp w9, #80
        b.eq fnbt_is_boss
        cmp w9, #90
        b.eq fnbt_is_boss
        cmp w9, #100
        b.ne fnbt_next

    fnbt_is_boss:
        str x0, [sp, #0x68]
        ldr x0, [x0, #0x28]
        mov x1, x19
        bl get_asset_tile
        mov x27, x0
        cbz x27, fnbt_next

        mov x0, x20
        mov x1, x27
        mov w2, wzr
        mov x3, xzr
        {_add_rva('x16', 'x19', RVA_GAMEMAPTILE_GET_DISTANCE)}
        blr x16
        cmp w0, #0
        b.lt fnbt_next
        add w28, w28, #1
        str w0, [sp, #0x64]
        ldr w8, [sp, #0x60]
        cbz w8, fnbt_distance_ready
        ldrb w8, [x27, #0xce]
        sub w8, w8, #3
        cmp w8, #2
        b.lo fnbt_distance_ready
        mov x0, x27
        mov w1, #4
        mov w2, wzr
        mov x3, xzr
        {_add_rva('x16', 'x19', RVA_GAMEMAPTILE_SET_ATTRIBUTE)}
        blr x16
    fnbt_distance_ready:
        ldr w0, [sp, #0x64]
        cmp w0, w25
        b.gt fnbt_next
        b.lt fnbt_take

        // Tie-break deterministically by tile (y, x, z) ascending
        cbz x24, fnbt_take
        ldr w8, [x27, #0x20]
        ldr w9, [x24, #0x20]
        cmp w8, w9
        b.lt fnbt_take
        b.gt fnbt_next
        ldr w8, [x27, #0x1c]
        ldr w9, [x24, #0x1c]
        cmp w8, w9
        b.lt fnbt_take
        b.gt fnbt_next
        ldr w8, [x27, #0x24]
        ldr w9, [x24, #0x24]
        cmp w8, w9
        b.ge fnbt_next

    fnbt_take:
        mov x24, x27
        mov w25, w0
        ldr x8, [sp, #0x68]
        str x8, [sp, #0x70]

    fnbt_next:
        add w26, w26, #1
        b fnbt_loop

    fnbt_done:
        mov x0, x24
        b fnbt_exit
    fnbt_fail:
        mov x0, xzr
        mov w28, wzr
    fnbt_exit:
        mov w1, w28
        ldr x2, [sp, #0x70]
        ldp x19, x20, [sp, #0x50]
        ldp x21, x22, [sp, #0x40]
        ldp x23, x24, [sp, #0x30]
        ldp x25, x26, [sp, #0x20]
        ldp x27, x28, [sp, #0x10]
        ldp x29, x30, [sp], #0x80
        ret
    fnbt_ret_null:
        mov x0, xzr
        mov w1, wzr
        mov x2, xzr
        ret

    // Hook 1: Skill::IsCastable epilogue @ 0x1B6F9C0 (w0=castable, x20=Skill*)
    hook_is_castable:
        tbz w0, #0, hic_orig
        {_check_skill_id_eq_candidate('x20', 'x8', 'hic_orig')}
        ldr x0, [x20, #0x10]
        mov w1, wzr
        bl find_nearest_boss_tile
        cmp x0, #0
        cset w0, ne
    hic_orig:
        ldp x29, x30, [sp, #0x50]
        ldp x20, x19, [sp, #0x40]
        ldp x22, x21, [sp, #0x30]
        ldp x24, x23, [sp, #0x20]
        ldp x26, x25, [sp, #0x10]
        ldr x27, [sp], #0x60
        ret

    // Hook 2: Player::OnGUICastButtonPressed @ 0x18E93FC (x0=skillCastingUI, x1=x19=Player*)
    hook_on_cast_btn:
        cbz x19, hoc_fallback
        ldr x8, [x19, #0x40]
        cbz x8, hoc_fallback
        sub sp, sp, #0x20
        stp x19, x0, [sp]
        mov x0, x8
        mov x1, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_SKILL_CONTAINER_GET_CURRENT_SKILL)}
        blr x16
        str x0, [sp, #0x10]
        mov w3, #-1
        cbz x0, hoc_log_skill
        ldr x8, [x0, #0x18]
        cbz x8, hoc_log_skill
        ldr w3, [x8, #0x10]
    hoc_log_skill:
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, cast_log_format
        bl {ORIG_LATE_LOG_FN:#x}
        ldr x0, [sp, #0x10]
        {_check_skill_id_eq_candidate('x0', 'x8', 'hoc_restore_fallback')}
        ldr x0, [sp]
        mov w1, wzr
        bl find_nearest_boss_tile
        str x0, [sp, #0x10]
        str w1, [sp, #0x18]
        cmp x0, #0
        cset w3, ne
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, boss_log_format
        bl {ORIG_LATE_LOG_FN:#x}
        ldr x0, [sp, #0x10]
        cbz x0, hoc_no_boss_ret
        ldp x19, x0, [sp]
        mov x1, x19
        mov x2, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_GAME_GUI_SHOW_UI_AS_TARGET_ON)}
        blr x16
        ldr w3, [sp, #0x18]
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, boss_count_log_format
        bl {ORIG_LATE_LOG_FN:#x}
        ldr w8, [sp, #0x18]
        cmp w8, #1
        b.le hoc_single_boss
        // Several bosses: mark every eligible boss and let the player choose.
        ldr x0, [sp]
        mov w1, #1
        bl find_nearest_boss_tile
        add sp, sp, #0x20
        ldp x29, x30, [sp, #0x20]
        ldp x20, x19, [sp, #0x10]
        ldr x21, [sp], #0x30
        ret
    hoc_single_boss:
        // RangeType.All is accepted by Skill.IsInRange, but the tile
        // generator does not populate that type. Register only the chosen
        // boss tile through the game's normal attribute/cache path.
        ldr x0, [sp, #0x10]
        ldrb w8, [x0, #0xce]
        sub w8, w8, #3
        cmp w8, #2
        b.lo hoc_tile_marked
        mov w1, #4
        mov w2, wzr
        mov x3, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_GAMEMAPTILE_SET_ATTRIBUTE)}
        blr x16
    hoc_tile_marked:
        ldr x8, [sp, #0x10]
        ldrb w3, [x8, #0xce]
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, tile_log_format
        bl {ORIG_LATE_LOG_FN:#x}
        ldr x0, [sp]
        ldr x1, [sp, #0x10]
        mov x2, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_PLAYER_HANDLE_INPUT)}
        blr x16
        mov w3, w0
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, input_log_format
        bl {ORIG_LATE_LOG_FN:#x}
        add sp, sp, #0x20
        ldp x29, x30, [sp, #0x20]
        ldp x20, x19, [sp, #0x10]
        ldr x21, [sp], #0x30
        ret
    hoc_no_boss_ret:
        add sp, sp, #0x20
        ldp x29, x30, [sp, #0x20]
        ldp x20, x19, [sp, #0x10]
        ldr x21, [sp], #0x30
        ret
    hoc_restore_fallback:
        ldp x19, x0, [sp]
        add sp, sp, #0x20
    hoc_fallback:
        mov x1, x19
        ldp x29, x30, [sp, #0x20]
        ldp x20, x19, [sp, #0x10]
        mov x2, xzr
        ldr x21, [sp], #0x30
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_GAME_GUI_SHOW_UI_AS_TARGET_ON)}
        br x16

    // Hook 3: SkillContainer::get_animationType @ 0x2022FA0 (x0=Skill*, x1=xzr)
    hook_get_anim_type:
        {_check_skill_id_eq_candidate('x0', 'x8', 'hgat_orig')}
        mov w0, #3
    hgat_ret_0x10_epilogue:
        ldp x29, x30, [sp, #0x20]
        ldp x20, x19, [sp, #0x10]
        ldr x21, [sp], #0x30
        ret
    hgat_orig:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_SKILL_IS_AWAKENING_SKILL)}
        blr x16
        tbz w0, #0, hgat_cont
        mov w0, #0x10
        b hgat_ret_0x10_epilogue
    hgat_cont:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_SKILL_CONTAINER_GET_ANIM_CONT)}
        br x16

    // Hook 4: HandleInputState::CastingAction @ 0x1885DBC (x0=Skill*, x1=xzr, x19=HandleInputState*)
    hook_casting_action:
        {_check_skill_id_eq_candidate('x0', 'x8', 'hca_orig')}
        ldr x22, [x19, #0x10]
        cbz x22, hca_null
        b hca_attack
    hca_orig:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_SKILL_IS_AWAKENING_SKILL)}
        blr x16
        ldr x22, [x19, #0x10]
        cbz x22, hca_null
        tbz w0, #0, hca_attack
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_CASTING_ACTION_AWAKE_STATE)}
        br x16
    hca_attack:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_CASTING_ACTION_ATTACK_STATE)}
        br x16
    hca_null:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_CASTING_ACTION_NULL_ERR)}
        br x16

    // Hook 5: Character::TakeSkill PositionSwap @ 0x1F07C9C (x0=eff, w1=0x2a, x2=xzr, x20=Skill*)
    hook_take_skill_swap:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_EFFECT_IS_EQUAL)}
        blr x16
        tbz w0, #0, hts_not_swap
        {_check_skill_id_eq_candidate('x20', 'x8', 'hts_normal')}
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_TAKE_SKILL_SWAP_EXEC)}
        br x16
    hts_normal:
        sub x8, x29, #8
        ldur x8, [x8, #-0x100]
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_TAKE_SKILL_SWAP_IMMUNE_CHECK)}
        br x16
    hts_not_swap:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_TAKE_SKILL_NOT_SWAP)}
        br x16

    // Hook 5b: Character::TakeSkill caster._orgPositionTile sync @ 0x1F08498
    hook_take_skill_caster_tile:
        mov x0, x23
        mov x1, x24
        blr x8
        {_check_skill_id_eq_candidate('x20', 'x9', 'hts_caster_done')}
        sub x8, x29, #0x48
        ldur x9, [x8, #-0x100]
        cbz x9, hts_caster_done
        ldr x9, [x9]
        cbz x9, hts_caster_done
        str x24, [x9, #0x88]
        sub x8, x29, #8
        ldur x10, [x8, #-0x100]
        cbz x10, hts_caster_done
        ldr x10, [x10]
        cbz x10, hts_caster_done
        ldr x10, [x10, #0x88]
        cbz x10, hts_caster_done
        sub x8, x29, #0x40
        stur x10, [x8, #-0x100]
        ldr x8, [x20, #0x18]
        cbz x8, hts_caster_done
        ldrb w11, [x8, #0x39]
        cbz w11, hts_caster_done
        sub sp, sp, #0x10
        stp x9, x10, [sp]
        mov w11, #1
        strb w11, [x8, #0x2d]
        strb w11, [x8, #0x2e]
        mov x0, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_GAME_STAGE_GET_INSTANCE)}
        blr x16
        ldp x1, x3, [sp], #0x10
        cbz x0, hts_restore_range
        mov x2, x20
        mov w4, #5
        mov x5, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_GAME_STAGE_CHANGE_TILE_TYPE)}
        blr x16
    hts_restore_range:
        ldr x8, [x20, #0x18]
        strb wzr, [x8, #0x2d]
        strb wzr, [x8, #0x2e]
    hts_caster_done:
        sub x8, x29, #0x48
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_TAKE_SKILL_CASTER_TILE_RESUME)}
        br x16

    // ActionButtonGUI::OnCastButtonAtIndex, before Easy Skill AI selects a target.
    // For Alex's experimental Awake only, use the normal cast-button event;
    // the Player hook then finds the nearest boss. All other skills retain
    // the original easy-skill branch and its null checks.
    hook_skip_easy_skill:
        sub sp, sp, #0x60
        stp x0, x1, [sp]
        stp x2, x3, [sp, #0x10]
        stp x4, x5, [sp, #0x20]
        stp x6, x7, [sp, #0x30]
        stp x29, x30, [sp, #0x40]
        cbz x19, hses_restore_normal
        ldr x8, [x19, #0x70]
        cbz x8, hses_restore_normal
        ldr x0, [x8, #0x40]
        cbz x0, hses_restore_normal
        mov w1, w20
        mov x2, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_SKILL_CONTAINER_GET_ITEM)}
        blr x16
        {_check_skill_id_eq_candidate('x0', 'x8', 'hses_restore_normal')}
        ldp x29, x30, [sp, #0x40]
        ldp x6, x7, [sp, #0x30]
        ldp x4, x5, [sp, #0x20]
        ldp x2, x3, [sp, #0x10]
        ldp x0, x1, [sp]
        add sp, sp, #0x60
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_UI_NORMAL_CAST)}
        br x16
    hses_restore_normal:
        ldp x29, x30, [sp, #0x40]
        ldp x6, x7, [sp, #0x30]
        ldp x4, x5, [sp, #0x20]
        ldp x2, x3, [sp, #0x10]
        ldp x0, x1, [sp]
        add sp, sp, #0x60
        tbz w21, #0, hses_normal_cast
        ldr x8, [x19, #0x70]
        cbz x8, hses_null_error
        ldr x0, [x8, #0x58]
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_UI_EASY_CONTINUE)}
        br x16
    hses_normal_cast:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_UI_NORMAL_CAST)}
        br x16
    hses_null_error:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_UI_NULL_ERROR)}
        br x16

    // CharactersAI::ExecuteAttack: redirect Alex's Awake target before Attack.
    // Other skills retain the original target and original execution path.
    hook_auto_attack_target:
        ldr x8, [x19, #0x18]
        cbz x8, ha_original
        ldr x0, [x8, #0x40]
        cbz x0, ha_original
        mov x1, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_SKILL_CONTAINER_GET_CURRENT_SKILL)}
        blr x16
        {_check_skill_id_eq_candidate('x0', 'x8', 'ha_original')}
        ldr x0, [x19, #0x18]
        mov w1, wzr
        bl find_nearest_boss_tile
        cbz x2, ha_no_boss
        mov x20, x2
        mov w3, #1
        b ha_log
    ha_no_boss:
        mov w3, wzr
    ha_log:
        sub sp, sp, #0x10
        str w3, [sp]
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, auto_boss_log_format
        bl {ORIG_LATE_LOG_FN:#x}
        ldr w8, [sp]
        add sp, sp, #0x10
        cbz w8, ha_continue
    ha_original:
        mov x0, x19
        mov x1, x20
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_AI_ATTACK)}
        blr x16
    ha_continue:
        ldr x9, [x19, #0x18]
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_AI_ATTACK_CONT)}
        br x16

    // PlayerAI overrides ExecuteAttack and bypasses the generic AI hook.
    hook_player_auto_target:
        ldr x8, [x19, #0x18]
        cbz x8, hpa_null
        ldr x0, [x8, #0x40]
        cbz x0, hpa_original
        mov x1, xzr
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_SKILL_CONTAINER_GET_CURRENT_SKILL)}
        blr x16
        sub sp, sp, #0x10
        str x0, [sp]
        mov w3, #-1
        cbz x0, hpa_log_skill
        ldr x8, [x0, #0x18]
        cbz x8, hpa_log_skill
        ldr w3, [x8, #0x10]
    hpa_log_skill:
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, player_auto_skill_format
        bl {ORIG_LATE_LOG_FN:#x}
        ldr x0, [sp]
        add sp, sp, #0x10
        {_check_skill_id_eq_candidate('x0', 'x8', 'hpa_original')}
        ldr x0, [x19, #0x18]
        mov w1, wzr
        bl find_nearest_boss_tile
        cbz x2, hpa_no_boss
        mov x20, x2
        mov w3, #1
        b hpa_log_boss
    hpa_no_boss:
        mov w3, wzr
    hpa_log_boss:
        sub sp, sp, #0x10
        str w3, [sp]
        mov w0, #4
        adr x1, hook_log_tag
        adr x2, auto_boss_log_format
        bl {ORIG_LATE_LOG_FN:#x}
        ldr w8, [sp]
        add sp, sp, #0x10
        cbz w8, hpa_return
    hpa_original:
        ldr x8, [x19, #0x18]
        cbz x8, hpa_null
        ldr x0, [x8, #0x50]
        cbz x0, hpa_null
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_PLAYER_AI_ATTACK_CONT)}
        br x16
    hpa_return:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_PLAYER_AI_ATTACK_RETURN)}
        br x16
    hpa_null:
        {_load_il2cpp_base('x16')}
        {_add_rva('x16', 'x16', RVA_PLAYER_AI_ATTACK_NULL)}
        br x16

    {chr(10).join(data_lines)}
    """
    cave_bytes = _asm(source, CLIENT_CAVE_START)
    if CLIENT_CAVE_START + len(cave_bytes) > CLIENT_CAVE_END:
        raise ValueError(
            f"Client cave size {len(cave_bytes)} exceeds limit {CLIENT_CAVE_END - CLIENT_CAVE_START}"
        )
    late_branch = _asm(f"bl {CLIENT_CAVE_START:#x}", RELEASE_LATE_HOOK_SITE)
    if len(late_branch) != 4:
        raise ValueError("Unexpected late branch size")
    return late_branch, cave_bytes


def exercise(base: int = 0x4000000000, *, failed_hook: int | None = None,
             diagnostics: bool = True) -> None:
    """Emulate the installer and client hooks at a chosen ASLR base."""
    if diagnostics:
        late_branch, cave_bytes = assemble_client_cave()
    else:
        from core.alex_awakening_client import assemble_client_cave as release_client_cave

        late_branch, cave_bytes = release_client_cave()
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    server_base = base
    il2cpp_base = base + 0x20000000
    heap = base + 0x30000000
    stack_top = base + 0x38000000
    ret_sentinel = base + 0x3F000000

    for addr, size in (
        (server_base + 0xAA0000, 0x160000),
        (il2cpp_base + 0xD00000, 0x2E00000),
        (heap, 0x200000),
        (stack_top - 0x40000, 0x50000),
        (ret_sentinel, 0x10000),
    ):
        vm.mem_map(addr, size)

    vm.mem_write(server_base + CLIENT_CAVE_START, cave_bytes)
    vm.mem_write(server_base + RELEASE_LATE_HOOK_SITE, late_branch)
    vm.mem_write(server_base + IL2CPP_BASE_CACHE, struct.pack("<Q", il2cpp_base))

    # Write original expected words at each libil2cpp hook site
    for hook in CLIENT_HOOKS:
        vm.mem_write(
            il2cpp_base + hook.rva,
            struct.pack("<4I", *hook.expected_words),
        )

    # Synthetic IL2CPP metadata for Monster_TypeInfo & ICharacterAsset_TypeInfo
    monster_klass = heap + 0x1000
    non_monster_klass = heap + 0x1400
    boss_klass = heap + 0x1800
    monster_hier = heap + 0x1C00
    boss_hier = heap + 0x1D00
    non_hier = heap + 0x1E00
    ichar_klass = heap + 0x2000
    char_asset_klass = heap + 0x2200
    char_asset_ifaces = heap + 0x2500

    # Monster class: typeHierarchyDepth (+0x128) = 2, typeHierarchy (+0xc8)
    vm.mem_write(monster_klass + 0x128, bytes([2]))
    vm.mem_write(monster_klass + 0xC8, struct.pack("<Q", monster_hier))
    vm.mem_write(monster_hier + 8, struct.pack("<Q", monster_klass))

    vm.mem_write(boss_klass + 0x128, bytes([3]))
    vm.mem_write(boss_klass + 0xC8, struct.pack("<Q", boss_hier))
    vm.mem_write(boss_hier + 8, struct.pack("<Q", monster_klass))

    vm.mem_write(non_monster_klass + 0x128, bytes([2]))
    vm.mem_write(non_monster_klass + 0xC8, struct.pack("<Q", non_hier))
    vm.mem_write(non_hier + 8, struct.pack("<Q", non_monster_klass))

    slot_monster = heap + 0x2800
    slot_ichar = heap + 0x2810
    vm.mem_write(slot_monster, struct.pack("<Q", monster_klass))
    vm.mem_write(slot_ichar, struct.pack("<Q", ichar_klass))
    vm.mem_write(il2cpp_base + RVA_MONSTER_TYPEINFO_SLOT, struct.pack("<Q", slot_monster))
    vm.mem_write(il2cpp_base + RVA_ICHAR_ASSET_TYPEINFO_SLOT, struct.pack("<Q", slot_ichar))

    # CharacterAsset interface dispatch table: interfaceOffsetsCount (+0x126) = 1,
    # interfaceOffsets (+0xb0) -> [(ichar_klass, offset=0)], slot 1 @ +0x130 + 16 = +0x140
    stub_get_tile_va = il2cpp_base + 0x1A27CFC
    vm.mem_write(char_asset_klass + 0x126, struct.pack("<H", 1))
    vm.mem_write(char_asset_klass + 0xB0, struct.pack("<Q", char_asset_ifaces))
    vm.mem_write(char_asset_ifaces, struct.pack("<QI", ichar_klass, 0))
    vm.mem_write(char_asset_klass + 0x140, struct.pack("<QQ", stub_get_tile_va, 0))

    # Helpers to allocate synthetic objects in heap
    next_ptr = [heap + 0x10000]

    def alloc(size: int) -> int:
        p = next_ptr[0]
        next_ptr[0] += (size + 15) & ~15
        vm.mem_write(p, bytes(size))
        return p

    def make_tile(x: int, y: int, z: int) -> int:
        t = alloc(0x100)
        vm.mem_write(t + 0x1C, struct.pack("<iii", x, y, z))
        return t

    def make_asset(tile: int) -> int:
        a = alloc(0x40)
        vm.mem_write(a, struct.pack("<Q", char_asset_klass))
        vm.mem_write(a + 0x18, struct.pack("<Q", tile))
        return a

    def make_char(klass: int, tile: int, *, boss: int | None = None,
                  dead: bool = False, dropout: bool = False,
                  skill: int = 0) -> int:
        c = alloc(0x200)
        vm.mem_write(c, struct.pack("<Q", klass))
        vm.mem_write(c + 0x28, struct.pack("<Q", make_asset(tile)))
        if dead:
            vm.mem_write(c + 0x119, b"\x01")
        if dropout:
            vm.mem_write(c + 0x11A, b"\x01")
        if boss is not None:
            md = alloc(0x40)
            vm.mem_write(md + 0x19, bytes([boss]))
            vm.mem_write(c + 0x1A8, struct.pack("<Q", md))
        if skill:
            sc = alloc(0x40)
            vm.mem_write(sc + 0x10, struct.pack("<Q", skill))
            vm.mem_write(c + 0x40, struct.pack("<Q", sc))
        return c

    def make_skill(owner: int, skill_id: int) -> int:
        sd = alloc(0x40)
        vm.mem_write(sd + 0x10, struct.pack("<i", skill_id))
        sk = alloc(0x40)
        vm.mem_write(sk + 0x10, struct.pack("<Q", owner))
        vm.mem_write(sk + 0x18, struct.pack("<Q", sd))
        return sk

    camp_obj = alloc(0x40)
    camp_members: list[int] = []
    stage_obj = alloc(0x40)
    caster_tile = make_tile(0, 0, 0)
    caster_obj = make_char(non_monster_klass, caster_tile)

    last_calls: list[tuple[str, tuple[int, ...]]] = []
    is_awake_return = [1]
    is_equal_return = [1]

    def hook_cb(uc: Uc, address: int, _size: int, _user: object) -> None:
        if address == ret_sentinel:
            uc.emu_stop()
            return
        if address == server_base + PATCH_IL2CPP_HELPER:
            base_arg = int(uc.reg_read(UC_ARM64_REG_X0))
            rva_arg = int(uc.reg_read(UC_ARM64_REG_X1))
            exp_ptr = int(uc.reg_read(UC_ARM64_REG_X2))
            rep_ptr = int(uc.reg_read(UC_ARM64_REG_X3))
            count = int(uc.reg_read(UC_ARM64_REG_X4))
            name_ptr = int(uc.reg_read(UC_ARM64_REG_X5))
            assert base_arg == il2cpp_base
            index = next(i for i, hook in enumerate(CLIENT_HOOKS) if hook.rva == rva_arg)
            expected_name = CLIENT_HOOKS[index].name.encode("ascii") + b"\0"
            assert bytes(uc.mem_read(name_ptr, len(expected_name))) == expected_name
            nbytes = count * 4
            assert bytes(uc.mem_read(base_arg + rva_arg, nbytes)) == bytes(uc.mem_read(exp_ptr, nbytes))
            if index != failed_hook:
                uc.mem_write(base_arg + rva_arg, bytes(uc.mem_read(rep_ptr, nbytes)))
            uc.reg_write(UC_ARM64_REG_W0, int(index != failed_hook))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == stub_get_tile_va:
            asset = int(uc.reg_read(UC_ARM64_REG_X0))
            tile_ptr = struct.unpack("<Q", bytes(uc.mem_read(asset + 0x18, 8)))[0]
            uc.reg_write(UC_ARM64_REG_X0, tile_ptr)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_GAME_STAGE_GET_INSTANCE:
            uc.reg_write(UC_ARM64_REG_X0, stage_obj)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_GAME_STAGE_CHANGE_TILE_TYPE:
            stage = int(uc.reg_read(UC_ARM64_REG_X0))
            caster = int(uc.reg_read(UC_ARM64_REG_X1))
            skill = int(uc.reg_read(UC_ARM64_REG_X2))
            center_tile = int(uc.reg_read(UC_ARM64_REG_X3))
            moving_type = int(uc.reg_read(UC_ARM64_REG_X4)) & 0xFFFFFFFF
            assert stage == stage_obj
            sd = struct.unpack("<Q", bytes(uc.mem_read(skill + 0x18, 8)))[0]
            eff_range, eff_range_type = uc.mem_read(sd + 0x2D, 2)
            last_calls.append((
                "change_tile_type",
                (caster, skill, center_tile, moving_type, eff_range, eff_range_type),
            ))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_GAME_STAGE_GET_OPPONENT_CAMP:
            uc.reg_write(UC_ARM64_REG_X0, camp_obj)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_CAMP_GET_COUNT:
            uc.reg_write(UC_ARM64_REG_W0, len(camp_members))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_CAMP_GET_ITEM:
            idx = int(uc.reg_read(UC_ARM64_REG_W1))
            uc.reg_write(UC_ARM64_REG_X0, camp_members[idx])
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_GAMEMAPTILE_GET_DISTANCE:
            ta = int(uc.reg_read(UC_ARM64_REG_X0))
            tb = int(uc.reg_read(UC_ARM64_REG_X1))
            ax, ay, az = struct.unpack("<iii", bytes(uc.mem_read(ta + 0x1C, 12)))
            bx, by, bz = struct.unpack("<iii", bytes(uc.mem_read(tb + 0x1C, 12)))
            uc.reg_write(UC_ARM64_REG_W0, abs(ax - bx) + abs(ay - by) + abs(az - bz))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_GAMEMAPTILE_SET_ATTRIBUTE:
            tile = int(uc.reg_read(UC_ARM64_REG_X0))
            attribute = int(uc.reg_read(UC_ARM64_REG_W1))
            last_calls.append(("set_attribute", (tile, attribute)))
            uc.mem_write(tile + 0xCE, bytes([attribute]))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address in (il2cpp_base + RVA_SKILL_CONTAINER_GET_CURRENT_SKILL,
                       il2cpp_base + RVA_SKILL_CONTAINER_GET_ITEM):
            sc = int(uc.reg_read(UC_ARM64_REG_X0))
            sk = struct.unpack("<Q", bytes(uc.mem_read(sc + 0x10, 8)))[0]
            uc.reg_write(UC_ARM64_REG_X0, sk)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_SKILL_IS_AWAKENING_SKILL:
            uc.reg_write(UC_ARM64_REG_W0, is_awake_return[0])
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == il2cpp_base + RVA_EFFECT_IS_EQUAL:
            uc.reg_write(UC_ARM64_REG_W0, is_equal_return[0])
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        for tag, rva in (
            ("handle_input", RVA_PLAYER_HANDLE_INPUT),
            ("show_ui_target", RVA_GAME_GUI_SHOW_UI_AS_TARGET_ON),
            ("anim_cont", RVA_SKILL_CONTAINER_GET_ANIM_CONT),
            ("attack_state", RVA_CASTING_ACTION_ATTACK_STATE),
            ("awake_state", RVA_CASTING_ACTION_AWAKE_STATE),
            ("swap_exec", RVA_TAKE_SKILL_SWAP_EXEC),
            ("swap_immune", RVA_TAKE_SKILL_SWAP_IMMUNE_CHECK),
            ("swap_not", RVA_TAKE_SKILL_NOT_SWAP),
            ("caster_tile_resume", RVA_TAKE_SKILL_CASTER_TILE_RESUME),
            ("easy_continue", RVA_UI_EASY_CONTINUE),
            ("normal_cast", RVA_UI_NORMAL_CAST),
            ("ui_null_error", RVA_UI_NULL_ERROR),
            ("ai_attack", RVA_AI_ATTACK),
            ("ai_attack_continue", RVA_AI_ATTACK_CONT),
            ("player_ai_continue", RVA_PLAYER_AI_ATTACK_CONT),
            ("player_ai_return", RVA_PLAYER_AI_ATTACK_RETURN),
            ("player_ai_null", RVA_PLAYER_AI_ATTACK_NULL),
        ):
            if address == il2cpp_base + rva:
                if tag.startswith("player_ai_"):
                    last_calls.append((tag, (int(uc.reg_read(UC_ARM64_REG_X20)),)))
                else:
                    last_calls.append((tag, (int(uc.reg_read(UC_ARM64_REG_X0)), int(uc.reg_read(UC_ARM64_REG_X1)))))
                if tag in ("handle_input", "show_ui_target", "ai_attack"):
                    if tag == "handle_input":
                        uc.reg_write(UC_ARM64_REG_W0, 1)
                    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
                else:
                    uc.emu_stop()
                return
        if address == server_base + ORIG_LATE_LOG_FN:
            tag_addr = int(uc.reg_read(UC_ARM64_REG_X1))
            if tag_addr == 0:
                last_calls.append(("orig_log", (int(uc.reg_read(UC_ARM64_REG_X0)), int(uc.reg_read(UC_ARM64_REG_X3)))))
            else:
                tag_bytes = bytes(uc.mem_read(tag_addr, len(b"FWT-ALEX-LAB\0")))
                assert tag_bytes == b"FWT-ALEX-LAB\0"
                fmt_addr = int(uc.reg_read(UC_ARM64_REG_X2))
                fmt = bytes(uc.mem_read(fmt_addr, 64)).split(b"\0", 1)[0]
                values = (int(uc.reg_read(UC_ARM64_REG_X3)), int(uc.reg_read(UC_ARM64_REG_X4)))
                kind = {b"hook=%d installed=%d": "hook_log", b"cast_skill=%d": "cast_log",
                        b"boss_found=%d": "boss_log", b"input_result=%d": "input_log",
                        b"boss_count=%d": "boss_count_log",
                        b"auto_boss_found=%d": "auto_boss_log",
                        b"player_auto_skill=%d": "player_auto_skill_log",
                        b"boss_tile_attribute=%d": "tile_log"}.get(fmt)
                assert kind is not None, f"Unexpected Alex diagnostic format: {fmt!r}"
                last_calls.append((kind, values))
            uc.reg_write(UC_ARM64_REG_W0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == heap + 0x5000:  # mock set_tile in Hook 5b
            last_calls.append(("set_tile", (int(uc.reg_read(UC_ARM64_REG_X0)), int(uc.reg_read(UC_ARM64_REG_X1)))))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    vm.hook_add(UC_HOOK_CODE, hook_cb)

    # 1. Exercise post-AppSealing installer via 0xAB3378 -> returns to 0xAB337C
    vm.mem_write(server_base + RELEASE_LATE_HOOK_SITE + 4, _asm("ret", RELEASE_LATE_HOOK_SITE + 4))
    vm.reg_write(UC_ARM64_REG_SP, stack_top)
    vm.reg_write(UC_ARM64_REG_X0, 4)
    vm.reg_write(UC_ARM64_REG_X1, 0)
    vm.reg_write(UC_ARM64_REG_X3, 7)
    vm.emu_start(server_base + RELEASE_LATE_HOOK_SITE, server_base + RELEASE_LATE_HOOK_SITE + 4, count=5000)
    assert vm.reg_read(UC_ARM64_REG_PC) == server_base + RELEASE_LATE_HOOK_SITE + 4
    assert vm.reg_read(UC_ARM64_REG_SP) == stack_top
    hook_logs = [
        ("hook_log", (idx, int(idx != failed_hook))) for idx in range(len(CLIENT_HOOKS))
    ]
    assert last_calls == [("orig_log", (4, 7))] + (hook_logs if diagnostics else [])
    last_calls.clear()

    # Verify each trampoline was written into libil2cpp.so.
    for idx, hook in enumerate(CLIENT_HOOKS):
        patched = bytes(vm.mem_read(il2cpp_base + hook.rva, 16))
        if idx == failed_hook:
            assert patched == struct.pack("<4I", *hook.expected_words)
        else:
            assert patched[:8] == bytes.fromhex("5000005800021fd6"), f"{hook.name} trampoline missing"
    if failed_hook is not None:
        return

    # 2. Exercise Hook 1: Skill::IsCastable
    alex_awake = make_skill(caster_obj, SKILL_ID)
    other_skill = make_skill(caster_obj, 1048964)

    def run_is_castable(sk: int, initial_w0: int) -> int:
        sp = stack_top - 0x60
        vm.mem_write(sp + 0x50, struct.pack("<QQ", 0x5566, ret_sentinel))
        vm.reg_write(UC_ARM64_REG_SP, sp)
        vm.reg_write(UC_ARM64_REG_W0, initial_w0)
        vm.reg_write(UC_ARM64_REG_X20, sk)
        vm.emu_start(il2cpp_base + RVA_SKILL_IS_CASTABLE_EPILOGUE, ret_sentinel, count=5000)
        assert vm.reg_read(UC_ARM64_REG_SP) == stack_top
        return int(vm.reg_read(UC_ARM64_REG_W0)) & 1

    # No boss (mob + elite _boss=50 + dead boss + dropout boss + non-monster with mdata)
    camp_members[:] = [
        make_char(monster_klass, make_tile(1, 0, 0), boss=1),
        make_char(monster_klass, make_tile(1, 0, 0), boss=50),
        make_char(boss_klass, make_tile(1, 0, 0), boss=100, dead=True),
        make_char(boss_klass, make_tile(1, 0, 0), boss=100, dropout=True),
        make_char(non_monster_klass, make_tile(1, 0, 0), boss=100),
    ]
    assert run_is_castable(alex_awake, 1) == 0
    assert run_is_castable(other_skill, 1) == 1
    assert run_is_castable(alex_awake, 0) == 0

    # Add two living bosses (far vs near, plus tie-break check)
    far_boss_tile = make_tile(5, 5, 0)
    near_boss_b = make_tile(2, 1, 0)  # dist 3, y=1
    near_boss_a = make_tile(1, 2, 0)  # dist 3, y=2
    far_boss = make_char(boss_klass, far_boss_tile, boss=90)
    near_boss_one = make_char(boss_klass, near_boss_a, boss=100)
    near_boss_two = make_char(boss_klass, near_boss_b, boss=80)
    camp_members.extend((far_boss, near_boss_one, near_boss_two))
    assert run_is_castable(alex_awake, 1) == 1

    # 3. Exercise Hook 2: Player::OnGUICastButtonPressed
    # One living boss: it is selected automatically.
    camp_members[:] = [*camp_members[:5], near_boss_two]
    player_awake = make_char(non_monster_klass, caster_tile, skill=alex_awake)
    player_other = make_char(non_monster_klass, caster_tile, skill=other_skill)
    for plr, expected_tag, expected_x1 in (
        (player_awake, "handle_input", near_boss_b),
        (player_other, "show_ui_target", player_other),
    ):
        last_calls.clear()
        sp = stack_top - 0x30
        vm.mem_write(sp + 0x20, struct.pack("<QQ", 0x77, ret_sentinel))
        vm.reg_write(UC_ARM64_REG_SP, sp)
        vm.reg_write(UC_ARM64_REG_X0, heap + 0x9990)
        vm.reg_write(UC_ARM64_REG_X19, plr)
        vm.emu_start(il2cpp_base + RVA_PLAYER_ON_GUI_CAST_BTN_HOOK, 0, count=5000)
        assert vm.reg_read(UC_ARM64_REG_SP) == stack_top
        if expected_tag == "handle_input" and diagnostics:
            assert last_calls[0][0] == "cast_log"
            assert last_calls[0][1][0] == SKILL_ID
            assert last_calls[1][0] == "boss_log"
            assert last_calls[1][1][0] == 1
            assert last_calls[2][0] == "show_ui_target"
            assert last_calls[2][1][1] == plr
            assert last_calls[3][0] == "boss_count_log"
            assert last_calls[3][1][0] == 1
            assert last_calls[4] == ("set_attribute", (expected_x1, 4))
            assert last_calls[5][0] == "tile_log"
            assert last_calls[5][1][0] == 4
            assert last_calls[6] == ("handle_input", (plr, expected_x1))
            assert last_calls[7][0] == "input_log"
            assert last_calls[7][1][0] == 1
        elif expected_tag == "handle_input":
            assert last_calls == [
                ("show_ui_target", (heap + 0x9990, plr)),
                ("set_attribute", (expected_x1, 4)),
                ("handle_input", (plr, expected_x1)),
            ]
        else:
            assert last_calls[-1][0] == expected_tag
            if diagnostics:
                assert last_calls[0][0] == "cast_log"
                assert last_calls[0][1][0] == 1048964
            assert last_calls[-1][1][1] == expected_x1

    # An already-selectable boss tile must not be registered twice.
    last_calls.clear()
    sp = stack_top - 0x30
    vm.mem_write(sp + 0x20, struct.pack("<QQ", 0x77, ret_sentinel))
    vm.reg_write(UC_ARM64_REG_SP, sp)
    vm.reg_write(UC_ARM64_REG_X0, heap + 0x9990)
    vm.reg_write(UC_ARM64_REG_X19, player_awake)
    vm.emu_start(il2cpp_base + RVA_PLAYER_ON_GUI_CAST_BTN_HOOK, 0, count=5000)
    assert all(name != "set_attribute" for name, _ in last_calls)
    assert any(name == "handle_input" and values == (player_awake, near_boss_b)
               for name, values in last_calls)

    # Several living bosses: mark only boss tiles and do not select one.
    camp_members.extend((far_boss, near_boss_one))
    vm.mem_write(near_boss_b + 0xCE, b"\xff")
    vm.mem_write(near_boss_a + 0xCE, b"\xff")
    vm.mem_write(far_boss_tile + 0xCE, b"\xff")
    last_calls.clear()
    sp = stack_top - 0x30
    vm.mem_write(sp + 0x20, struct.pack("<QQ", 0x77, ret_sentinel))
    vm.reg_write(UC_ARM64_REG_SP, sp)
    vm.reg_write(UC_ARM64_REG_X0, heap + 0x9990)
    vm.reg_write(UC_ARM64_REG_X19, player_awake)
    vm.emu_start(il2cpp_base + RVA_PLAYER_ON_GUI_CAST_BTN_HOOK, 0, count=10000)
    assert vm.reg_read(UC_ARM64_REG_SP) == stack_top
    if diagnostics:
        assert any(name == "boss_count_log" and values[0] == 3 for name, values in last_calls)
    assert {values[0] for name, values in last_calls if name == "set_attribute"} == {
        near_boss_b, near_boss_a, far_boss_tile,
    }
    assert all(name != "handle_input" for name, _ in last_calls)

    # A boss can disappear between the castability check and button press.
    # No input is forwarded and the original target picker is not opened.
    camp_members.clear()
    last_calls.clear()
    sp = stack_top - 0x30
    vm.mem_write(sp + 0x20, struct.pack("<QQ", 0x77, ret_sentinel))
    vm.reg_write(UC_ARM64_REG_SP, sp)
    vm.reg_write(UC_ARM64_REG_X0, heap + 0x9990)
    vm.reg_write(UC_ARM64_REG_X19, player_awake)
    vm.emu_start(il2cpp_base + RVA_PLAYER_ON_GUI_CAST_BTN_HOOK, ret_sentinel, count=5000)
    assert vm.reg_read(UC_ARM64_REG_SP) == stack_top
    if diagnostics:
        assert [name for name, _ in last_calls] == ["cast_log", "boss_log"]
        assert last_calls[1][1][0] == 0
    else:
        assert not last_calls

    # The Easy Skill branch is bypassed only for Alex's candidate skill.
    for skill, easy, expected in ((alex_awake, 1, "normal_cast"),
                                  (other_skill, 1, "easy_continue"),
                                  (other_skill, 0, "normal_cast")):
        player = make_char(non_monster_klass, caster_tile, skill=skill)
        gui = alloc(0x100)
        vm.mem_write(gui + 0x70, struct.pack("<Q", player))
        vm.mem_write(player + 0x58, struct.pack("<Q", heap + 0x9990))
        last_calls.clear()
        vm.reg_write(UC_ARM64_REG_SP, stack_top - 0x50)
        vm.reg_write(UC_ARM64_REG_X19, gui)
        vm.reg_write(UC_ARM64_REG_W0, 0x1234)
        vm.reg_write(UC_ARM64_REG_W1, 0x5678)
        vm.reg_write(UC_ARM64_REG_W20, 4)
        vm.reg_write(UC_ARM64_REG_W21, easy)
        vm.emu_start(il2cpp_base + RVA_UI_EASY_BRANCH_HOOK, 0, count=1000)
        assert last_calls[-1][0] == expected
        assert vm.reg_read(UC_ARM64_REG_SP) == stack_top - 0x50
        if expected == "easy_continue":
            assert last_calls[-1][1][0] == heap + 0x9990

    # Auto attack: only Alex's skill redirects a minion target to a living boss.
    ai = alloc(0x100)
    minion = make_char(monster_klass, make_tile(1, 0, 0), boss=1)
    for player, members, expected_target in (
        (player_awake, [minion, far_boss, near_boss_two], near_boss_two),
        (player_other, [minion, near_boss_two], minion),
        (player_awake, [minion], None),
    ):
        vm.mem_write(ai + 0x18, struct.pack("<Q", player))
        camp_members[:] = members
        last_calls.clear()
        vm.reg_write(UC_ARM64_REG_SP, stack_top - 0x30)
        vm.reg_write(UC_ARM64_REG_X19, ai)
        vm.reg_write(UC_ARM64_REG_X20, minion)
        vm.emu_start(il2cpp_base + RVA_AI_ATTACK_HOOK, 0, count=10000)
        attacks = [values for name, values in last_calls if name == "ai_attack"]
        if expected_target is None:
            assert not attacks
            if diagnostics:
                assert any(name == "auto_boss_log" and values[0] == 0
                           for name, values in last_calls)
        else:
            assert attacks == [(ai, expected_target)]
        assert last_calls[-1][0] == "ai_attack_continue"
        assert vm.reg_read(UC_ARM64_REG_SP) == stack_top - 0x30

    # PlayerAI overrides the generic route. Preserve other skill targets and
    # avoid starting the attack when Alex has no living boss to target.
    for player, members, expected_tag, expected_target in (
        (player_awake, [minion, far_boss, near_boss_two], "player_ai_continue", near_boss_two),
        (player_other, [minion, near_boss_two], "player_ai_continue", minion),
        (player_awake, [minion], "player_ai_return", minion),
    ):
        vm.mem_write(ai + 0x18, struct.pack("<Q", player))
        vm.mem_write(player + 0x50, struct.pack("<Q", heap + 0x9990))
        camp_members[:] = members
        last_calls.clear()
        vm.reg_write(UC_ARM64_REG_SP, stack_top - 0x50)
        vm.reg_write(UC_ARM64_REG_X19, ai)
        vm.reg_write(UC_ARM64_REG_X20, minion)
        vm.emu_start(il2cpp_base + RVA_PLAYER_AI_ATTACK_HOOK, 0, count=10000)
        assert last_calls[-1] == (expected_tag, (expected_target,))
        assert vm.reg_read(UC_ARM64_REG_SP) == stack_top - 0x50

    # 4. Exercise Hook 3: SkillContainer::get_animationType
    sp = stack_top - 0x30
    vm.mem_write(sp + 0x20, struct.pack("<QQ", 0x88, ret_sentinel))
    vm.reg_write(UC_ARM64_REG_SP, sp)
    vm.reg_write(UC_ARM64_REG_X0, alex_awake)
    vm.emu_start(il2cpp_base + RVA_SKILL_CONTAINER_GET_ANIM_HOOK, ret_sentinel, count=500)
    assert int(vm.reg_read(UC_ARM64_REG_W0)) == 3
    assert vm.reg_read(UC_ARM64_REG_SP) == stack_top

    is_awake_return[0] = 1
    vm.mem_write(sp + 0x20, struct.pack("<QQ", 0x88, ret_sentinel))
    vm.reg_write(UC_ARM64_REG_SP, sp)
    vm.reg_write(UC_ARM64_REG_X0, other_skill)
    vm.emu_start(il2cpp_base + RVA_SKILL_CONTAINER_GET_ANIM_HOOK, ret_sentinel, count=500)
    assert int(vm.reg_read(UC_ARM64_REG_W0)) == 0x10

    # 5. Exercise Hook 4: HandleInputState::CastingAction
    fake_state = alloc(0x30)
    vm.mem_write(fake_state + 0x10, struct.pack("<Q", player_awake))
    for sk, exp_tag in ((alex_awake, "attack_state"), (other_skill, "awake_state")):
        last_calls.clear()
        vm.reg_write(UC_ARM64_REG_SP, stack_top - 0x80)
        vm.reg_write(UC_ARM64_REG_X0, sk)
        vm.reg_write(UC_ARM64_REG_X1, 0)
        vm.reg_write(UC_ARM64_REG_X19, fake_state)
        vm.emu_start(il2cpp_base + RVA_CASTING_ACTION_HOOK, 0, count=500)
        assert last_calls[-1][0] == exp_tag

    # 6. Exercise Hook 5 & 5b: Character::TakeSkill PositionSwap
    vm.reg_write(UC_ARM64_REG_X29, stack_top - 0x40)
    target_slot = alloc(8)
    vm.mem_write(target_slot, struct.pack("<Q", near_boss_one))
    vm.mem_write(near_boss_one + 0x88, struct.pack("<Q", caster_tile))
    vm.mem_write(stack_top - 0x40 - 0x108, struct.pack("<Q", target_slot))
    caster_slot = alloc(8)
    vm.mem_write(caster_slot, struct.pack("<Q", caster_obj))
    vm.mem_write(stack_top - 0x40 - 0x148, struct.pack("<Q", caster_slot))
    for sk, eq_ret, exp_tag in (
        (alex_awake, 1, "swap_exec"),
        (other_skill, 1, "swap_immune"),
        (alex_awake, 0, "swap_not"),
    ):
        last_calls.clear()
        is_equal_return[0] = eq_ret
        vm.reg_write(UC_ARM64_REG_SP, stack_top - 0x200)
        vm.reg_write(UC_ARM64_REG_X20, sk)
        vm.emu_start(il2cpp_base + RVA_TAKE_SKILL_SWAP_HOOK, 0, count=500)
        assert last_calls[-1][0] == exp_tag

    # 6a. Hook 5b without rebalance (_turnEnd == 0): syncs caster & castTargetTile, no ChangeTileType
    last_calls.clear()
    vm.mem_write(stack_top - 0x40 - 0x140, struct.pack("<Q", near_boss_b))
    vm.reg_write(UC_ARM64_REG_SP, stack_top - 0x200)
    vm.reg_write(UC_ARM64_REG_X20, alex_awake)
    vm.reg_write(UC_ARM64_REG_X23, alloc(16))
    vm.reg_write(UC_ARM64_REG_X24, near_boss_b)
    vm.reg_write(UC_ARM64_REG_X8, heap + 0x5000)
    vm.emu_start(il2cpp_base + RVA_TAKE_SKILL_CASTER_TILE_HOOK, 0, count=500)
    assert [c[0] for c in last_calls] == ["set_tile", "caster_tile_resume"]
    assert struct.unpack("<Q", bytes(vm.mem_read(caster_obj + 0x88, 8)))[0] == near_boss_b
    assert struct.unpack("<Q", bytes(vm.mem_read(stack_top - 0x40 - 0x140, 8)))[0] == caster_tile

    # 6b. Hook 5b with rebalance (_turnEnd == 99): applies 1-cell Thornbush centered on boss_dest_tile
    alex_awake_sd = struct.unpack("<Q", bytes(vm.mem_read(alex_awake + 0x18, 8)))[0]
    vm.mem_write(alex_awake_sd + 0x39, bytes([99]))
    vm.mem_write(caster_obj + 0x88, struct.pack("<Q", 0))
    vm.mem_write(stack_top - 0x40 - 0x140, struct.pack("<Q", near_boss_b))
    last_calls.clear()
    vm.reg_write(UC_ARM64_REG_SP, stack_top - 0x200)
    vm.reg_write(UC_ARM64_REG_X20, alex_awake)
    vm.reg_write(UC_ARM64_REG_X23, alloc(16))
    vm.reg_write(UC_ARM64_REG_X24, near_boss_b)
    vm.reg_write(UC_ARM64_REG_X8, heap + 0x5000)
    vm.emu_start(il2cpp_base + RVA_TAKE_SKILL_CASTER_TILE_HOOK, 0, count=500)
    assert last_calls == [
        ("set_tile", (int(vm.reg_read(UC_ARM64_REG_X23)), near_boss_b)),
        ("change_tile_type", (caster_obj, alex_awake, caster_tile, 5, 1, 1)),
        ("caster_tile_resume", (int(vm.reg_read(UC_ARM64_REG_X0)), int(vm.reg_read(UC_ARM64_REG_X1)))),
    ]
    assert struct.unpack("<Q", bytes(vm.mem_read(caster_obj + 0x88, 8)))[0] == near_boss_b
    assert struct.unpack("<Q", bytes(vm.mem_read(stack_top - 0x40 - 0x140, 8)))[0] == caster_tile
    assert bytes(vm.mem_read(alex_awake_sd + 0x2D, 2)) == b"\x00\x00"

    print(
        f"Alex skill client cave ({len(cave_bytes)} B / {CLIENT_CAVE_END - CLIENT_CAVE_START} B) "
        f"and all {len(CLIENT_HOOKS)} hooks passed in Unicorn at {base:#x}."
    )


if __name__ == "__main__":
    exercise(base=0)
    exercise(base=0x4000000000)
