"""Reference-specific client hook construction for Alex Awakening.

The feature remains experimental until the release gates are complete.
"""

from __future__ import annotations

from dataclasses import dataclass

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

SKILL_ID = 0x100185

CLIENT_CAVE_START = 0xB2EA8C

CLIENT_CAVE_END = 0xB2FAA0

RELEASE_LATE_HOOK_SITE = 0xAB3378

RELEASE_LATE_HOOK_EXPECTED = bytes.fromhex("4e4c0294")

ORIG_LATE_LOG_FN = 0xB464B0

PATCH_IL2CPP_HELPER = 0xAB575C

IL2CPP_BASE_CACHE = 0xBE3798

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

def assemble_client_cave(*, diagnostics: bool = False) -> tuple[bytes, bytes]:
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
    if not diagnostics:
        # Preserve the original late-initializer log call. The remaining calls
        # are DEV-only telemetry and must not execute in a release build.
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
        log_calls = [
            instruction.address
            for instruction in decoder.disasm(cave_bytes, CLIENT_CAVE_START)
            if instruction.mnemonic == "bl" and instruction.operands
            and instruction.operands[0].type == ARM64_OP_IMM
            and instruction.operands[0].imm == ORIG_LATE_LOG_FN
        ]
        if len(log_calls) != 18:
            raise ValueError(f"Unexpected number of client log calls: {len(log_calls)}")
        quiet = bytearray(cave_bytes)
        for address in log_calls[1:]:
            offset = address - CLIENT_CAVE_START
            quiet[offset:offset + 4] = bytes.fromhex("e0031f2a")  # mov w0, wzr
        for literal in (
            b"FWT-ALEX-LAB", b"hook=%d installed=%d", b"cast_skill=%d",
            b"boss_found=%d", b"boss_count=%d", b"boss_tile_attribute=%d",
            b"input_result=%d", b"auto_boss_found=%d", b"player_auto_skill=%d",
        ):
            marker = (b"" if literal == b"FWT-ALEX-LAB" else b"\0") + literal + b"\0"
            if quiet.count(marker) != 1:
                raise ValueError(f"Unexpected diagnostic literal count: {literal!r}")
            offset = quiet.index(marker) + int(literal != b"FWT-ALEX-LAB")
            quiet[offset:offset + len(literal)] = bytes(len(literal))
        cave_bytes = bytes(quiet)
    if CLIENT_CAVE_START + len(cave_bytes) > CLIENT_CAVE_END:
        raise ValueError(
            f"Client cave size {len(cave_bytes)} exceeds limit {CLIENT_CAVE_END - CLIENT_CAVE_START}"
        )
    late_branch = _asm(f"bl {CLIENT_CAVE_START:#x}", RELEASE_LATE_HOOK_SITE)
    if len(late_branch) != 4:
        raise ValueError("Unexpected late branch size")
    return late_branch, cave_bytes
