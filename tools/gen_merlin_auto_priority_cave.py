"""Builds the Merlin Slot-1 skill-priority cave (Feature 14.02), as AArch64 assembly.

`14.01` (`core/merlin_auto_support.py`) makes *Magic infusion* (`1053188`) target
allies whose Awakening cooldown is one turn away, but Auto Mode still walks Merlin
onto a bonus / occupy / item cell first: `CharactersAI::InitActing` (`0x1A35F2C`)
calls the virtual `MoveEnableToTile` at `0x1A35F68` *before* any skill evaluation,
and that call sets `AIPhaseAction`, which makes the following
`NormalStateFindTargetWithPath` return immediately (the whole skill scan never
runs).

This cave hooks `0x1A35F68` (four words, replaced by the absolute stub written by
`PATCH_IL2CPP_HELPER` at boot) and, for the `14.01` subject only (Merlin in Team
Slot 1, player camp, auto-play, not semi-auto), promotes two rungs ahead of the
cell move:

  * every skill index above *Magic infusion* runs the **stock** pair
    (`CharactersAI::IsEnableUsingSkill` + the virtual `EnableUseSkillToTarget`,
    `useportal = 1`) — for Merlin that is the Awakening skill `1053189`, so a
    ready Awakening is cast instead of moving;
  * *Magic infusion* itself runs only the **support branch** of
    `PlayerAI::EnableUseSkillToTarget` (`AIStatePhaseFindSupport` object + ctor +
    controller `SetState`/`Execute`/`IsExecuted`), deliberately stopping before the
    stock `FindAttackPlayer` fallback so a negative result returns to the cell move
    instead of committing an attack.

Everything below *Magic infusion* (Merlin's regular attacks in slots 0/1) keeps
losing to the cell, exactly as in stock. The body resumes the client at
`site + 0x10` (`0x1A35F78`, stock) or `site + 0x14` (`0x1A35F7C`, skipping
`MoveEnableToTile`).

Usage:
    python tools/gen_merlin_auto_priority_cave.py           # size, sha256, disassembly
    python tools/gen_merlin_auto_priority_cave.py --hex     # hex constant only
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.asm_cave import assemble_cave  # noqa: E402

# --- layout ---------------------------------------------------------------
# Lands after dungeon_recom_info's 832-byte cave (0xB301F8..0xB30538) in the dead
# tail of itanium_demangle AbstractManglingParser::parseEncoding.
CAVE_VADDR = 0xB30538
CAVE_END = 0xB3101C  # documented free tail end (docs/CODE_CAVES.md)

PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798

# client entry inside libfwt_local_server.so: the 14.01 installer's final `ret`
# (`0xB2B244`, stock `b 0xB2B634`) is turned into `b <CAVE_VADDR>`.
INSTALLER_ENTRY = 0xB2B244
INSTALLER_ENTRY_STOCK = 0x140000FC  # b 0xB2B634

# --- client (libil2cpp 0.682) --------------------------------------------
CLIENT_SITE = 0x1A35F68
CLIENT_RESUME_STOCK = 0x1A35F78  # blr x9 (stock MoveEnableToTile call)
CLIENT_RESUME_TAKEN = 0x1A35F7C  # ldp x29, x30, [sp, #0x10]
# ldr x8,[x19] / mov x0,x19 / ldr x9,[x8,#0x320] / ldr x1,[x8,#0x328]
# (verified word-for-word against the decrypted client image)
CLIENT_SITE_WORDS = (0xF9400268, 0xAA1303E0, 0xF9419109, 0xF9419501)

GET_ITEM = 0x2022E98  # SkillContainer::get_Item(container, idx, method)
IS_ENABLE_USING_SKILL = 0x1A36BA8  # CharactersAI::IsEnableUsingSkill(ai, idx, 0)
INIT_METHOD = 0xE4DCB4  # il2cpp_codegen_initialize_method(usage_index)
OBJECT_NEW = 0xE4DD80  # il2cpp_codegen_object_new(class)
SUPPORT_CTOR = 0x20ECE08  # AIStatePhaseFindSupport::.ctor(this, skillIdx, useportal, 0)
CTRL_SET_STATE = 0x217E748  # AIStatePhaseController::SetState(ctrl, state, 0)
CTRL_EXECUTE = 0x217E83C  # AIStatePhaseController::Execute(ctrl, ai, 0)
CTRL_IS_EXECUTED = 0x217E90C  # AIStatePhaseController::IsExecuted(ctrl, 0)

MAGIC_INFUSION_SKILL_ID = 1053188

# --- Feature 14.03: tie-break by Awakening-skill damage ---------------------
# Each awakening skill's power is the sum of its damage-type effect multipliers
# (`SkillEffectTable._effectValue`, e.g. 4.25 = 425%), resolved at runtime from
# `SkillData._effect01..04` through SkillEffectTableManager::GetData.
SKILL_EFFECT_GET_DATA = 0x202730C  # SkillEffectTableManager::GetData(int id) -> row
SKILL_EFFECT_TYPE_OFFSET = 0x20  # byte  _skillEffectType (0 = damage)
SKILL_EFFECT_VALUE_OFFSET = 0x38  # float _effectValue   (multiplier)
SKILL_DATA_EFFECT_SLOTS = 0x3C  # int _effect01..04 at 0x3C/0x40/0x44/0x48
SKILL_DATA_USE_PARAM_KIND = 0x4D  # byte  _useParameterKind ((v | 1) == 5 -> awakening)

# The 14.01 cave compares candidates with `slot_index_in_camp` and accepts the
# lower value (`b.lt`). Pointing those two calls at `awaken_power`, which returns
# `0x7FFF - power`, keeps every existing branch and makes the stronger Awakening
# win; `0x7FFF` (the "not found" value of the old helper) still means "worst".
COMPARE_SLOT_INDEX_CALLS = ((0xB2B468, 0x2B4), (0xB2B474, 0x2C0))
SLOT_INDEX_IN_CAMP = 0xB2B2F0

# static caches the client itself uses before allocating the support state
SUPPORT_CLASS_INIT_GUARD = 0x3CD46E5  # byte, written once after INIT_METHOD
SUPPORT_CLASS_USAGE = 0x39AD548  # [usage] -> il2cpp_codegen_initialize_method arg
SUPPORT_TYPEINFO_SLOT = 0x39D78A0  # [slot] -> Il2CppClass* for AIStatePhaseFindSupport

# the shared absolute stub words written at the hook site
STUB_WORDS = (0x58000050, 0xD61F0200)  # ldr x16, #8 ; br x16

# x5 diagnostic tag handed to PATCH_IL2CPP_HELPER, same convention as 14.01
# (padded to 4 bytes so the body that follows stays instruction-aligned)
TAG = b"merlin_auto_support_priority\x00".ljust(32, b"\x00")


def _call(rva: int) -> str:
    """`blr base + rva`, leaving x0..x3 intact."""
    return (
        f"    movz x17, #0x{rva & 0xFFFF:x}\n"
        f"    movk x17, #0x{(rva >> 16) & 0xFFFF:x}, lsl #16\n"
        f"    add  x16, x20, x17\n"
        f"    blr  x16\n"
    )


def _addr(source_reg: str, target: str, addr: int) -> str:
    """`adrp/add` pair (keystone cannot assemble `adr` with an absolute literal)."""
    page = addr & ~0xFFF
    return (
        f"    adrp {source_reg}, #0x{page:x}\n"
        f"    add  {source_reg}, {source_reg}, #0x{addr & 0xFFF:x}\n"
    )


def _installer_source(expected: int, tag: int, body_delta: int) -> str:
    return f"""
installer_entry:
    sub  sp, sp, #0x30
    stp  x29, x30, [sp, #0x20]
    mov  x29, sp
    stp  x19, x20, [sp, #0x10]
    adrp x19, #0xbe3000
    ldr  x19, [x19, #0x798]
    cbz  x19, installer_done
    ; replacement = ldr x16, #8 ; br x16 ; <runtime address of the body>.
    ; The body address MUST be computed here, PC-relative: a static `.quad`
    ; would keep the link-time VA and jump into unmapped memory.
    movz w8, #0x0050
    movk w8, #0x5800, lsl #16
    str  w8, [sp, #0x00]
    movz w8, #0x0200
    movk w8, #0xd61f, lsl #16
    str  w8, [sp, #0x04]
    adr  x9, installer_entry
    add  x9, x9, #0x{body_delta:x}
    str  x9, [sp, #0x08]
    mov  x0, x19
    movz w1, #0x{CLIENT_SITE & 0xFFFF:x}
    movk w1, #0x{(CLIENT_SITE >> 16) & 0xFFFF:x}, lsl #16
{_addr("x2", "expected", expected)}    mov  x3, sp
    mov  w4, #4
{_addr("x5", "tag", tag)}    bl   #0x{PATCH_IL2CPP_HELPER:x}
installer_done:
    ldp  x19, x20, [sp, #0x10]
    ldp  x29, x30, [sp, #0x20]
    add  sp, sp, #0x30
    ret
"""


def _body_source() -> str:
    return f"""
    ; ---- frame: save every callee-saved register this body clobbers ----
    sub  sp, sp, #0x40
    stp  x20, x21, [sp, #0x00]
    stp  x22, x23, [sp, #0x10]
    stp  x24, x25, [sp, #0x20]
    stp  x26, x27, [sp, #0x30]

    ; x19 is CharactersAI* on entry and must still hold it on both exits
    adrp x20, #0xbe3000
    ldr  x20, [x20, #0x798]

    ; ---- guard: Merlin in Team Slot 1, player camp, auto-play, not semi-auto ----
    ldr  x21, [x19, #0x18]
    cbz  x21, exit_stock
    ldrb w22, [x21, #0x18]
    cbnz w22, exit_stock
    ldrb w22, [x21, #0x1c0]
    cbz  w22, exit_stock
    ldr  x22, [x21, #0x78]
    cbz  x22, exit_stock
    ldrb w23, [x22, #0x18]
    cbnz w23, exit_stock
    ldr  x22, [x22, #0x20]
    cbz  x22, exit_stock
    ldr  w23, [x22, #0x18]
    cmp  w23, #1
    b.lt exit_stock
    ldr  x22, [x22, #0x10]
    cbz  x22, exit_stock
    ldr  w23, [x22, #0x18]
    cmp  w23, #1
    b.lt exit_stock
    ldr  x23, [x22, #0x20]
    cmp  x23, x21
    b.ne exit_stock
    ldr  x22, [x19, #0x90]
    cbnz x22, exit_stock
    ldr  w22, [x19, #0x98]
    cmn  w22, #1
    b.ne exit_stock

    ; ---- locate Magic infusion in the descending skill scan ----
    ldr  w23, [x19, #0x7c]
    ldr  w24, [x19, #0x80]
    ldr  w27, [x19, #0x58]
    mov  w26, #0xffffffff
    mov  w25, w23
scan_loop:
    cmp  w25, w24
    b.lt scan_done
    cmp  w25, w27
    b.eq scan_next
    ldr  x0, [x21, #0x40]
    cbz  x0, scan_next
    mov  w1, w25
    mov  x2, xzr
{_call(GET_ITEM)}    cbz  x0, scan_next
    ldr  x9, [x0, #0x18]
    cbz  x9, scan_next
    ldr  w9, [x9, #0x10]
    movz w10, #0x{(MAGIC_INFUSION_SKILL_ID & 0xFFFF):x}
    movk w10, #0x{((MAGIC_INFUSION_SKILL_ID >> 16) & 0xFFFF):x}, lsl #16
    cmp  w9, w10
    b.ne scan_next
    mov  w26, w25
    b    scan_done
scan_next:
    sub  w25, w25, #1
    b    scan_loop
scan_done:
    cmn  w26, #1
    b.eq exit_stock

    ; ---- rungs above Magic infusion: the stock pair, so Awake is actually cast ----
    mov  w25, w23
awake_loop:
    cmp  w25, w26
    b.le awake_done
    cmp  w25, w27
    b.eq awake_next
    mov  x0, x19
    mov  w1, w25
    mov  x2, xzr
{_call(IS_ENABLE_USING_SKILL)}    cbz  w0, awake_next
    ldr  x8, [x19]
    mov  x0, x19
    mov  w1, w25
    mov  w2, #1
    ldr  x9, [x8, #0x340]
    ldr  x3, [x8, #0x348]
    blr  x9
    cbnz w0, exit_taken
awake_next:
    sub  w25, w25, #1
    b    awake_loop
awake_done:

    ; ---- Magic infusion: support branch only, no attack fallback ----
    ; Static client data is reached as base + RVA: this body lives in the server
    ; library, so a PC-relative adrp would resolve inside the wrong image.
    movz x17, #0x{SUPPORT_CLASS_INIT_GUARD & 0xFFFF:x}
    movk x17, #0x{(SUPPORT_CLASS_INIT_GUARD >> 16) & 0xFFFF:x}, lsl #16
    add  x16, x20, x17
    ldrb w9, [x16]
    tbnz w9, #0, support_init_done
    movz x17, #0x{SUPPORT_CLASS_USAGE & 0xFFFF:x}
    movk x17, #0x{(SUPPORT_CLASS_USAGE >> 16) & 0xFFFF:x}, lsl #16
    add  x16, x20, x17
    ldr  x8, [x16]
    ldr  w0, [x8]
{_call(INIT_METHOD)}    movz x17, #0x{SUPPORT_CLASS_INIT_GUARD & 0xFFFF:x}
    movk x17, #0x{(SUPPORT_CLASS_INIT_GUARD >> 16) & 0xFFFF:x}, lsl #16
    add  x16, x20, x17
    mov  w9, #1
    strb w9, [x16]
support_init_done:
    movz x17, #0x{SUPPORT_TYPEINFO_SLOT & 0xFFFF:x}
    movk x17, #0x{(SUPPORT_TYPEINFO_SLOT >> 16) & 0xFFFF:x}, lsl #16
    add  x16, x20, x17
    ldr  x8, [x16]
    ldr  x0, [x8]
{_call(OBJECT_NEW)}    cbz  x0, exit_stock
    mov  x22, x0
    mov  w1, w26
    mov  w2, #1
    mov  x3, xzr
{_call(SUPPORT_CTOR)}    ldr  x23, [x19, #0x70]
    cbz  x23, exit_stock
    mov  x0, x23
    mov  x1, x22
    mov  x2, xzr
{_call(CTRL_SET_STATE)}    mov  x0, x23
    mov  x1, x19
    mov  x2, xzr
{_call(CTRL_EXECUTE)}    mov  x0, x23
    mov  x1, xzr
{_call(CTRL_IS_EXECUTED)}    cbz  w0, exit_stock

    ; ---- skip MoveEnableToTile: the chosen action is already committed ----
exit_taken:
    movz x17, #0x{CLIENT_RESUME_TAKEN & 0xFFFF:x}
    movk x17, #0x{(CLIENT_RESUME_TAKEN >> 16) & 0xFFFF:x}, lsl #16
    add  x16, x20, x17
    ldp  x20, x21, [sp, #0x00]
    ldp  x22, x23, [sp, #0x10]
    ldp  x24, x25, [sp, #0x20]
    ldp  x26, x27, [sp, #0x30]
    add  sp, sp, #0x40
    br   x16

    ; ---- stock: replay the four displaced words and run the tile move ----
exit_stock:
    movz x17, #0x{CLIENT_RESUME_STOCK & 0xFFFF:x}
    movk x17, #0x{(CLIENT_RESUME_STOCK >> 16) & 0xFFFF:x}, lsl #16
    add  x16, x20, x17
    ldp  x20, x21, [sp, #0x00]
    ldp  x22, x23, [sp, #0x10]
    ldp  x24, x25, [sp, #0x20]
    ldp  x26, x27, [sp, #0x30]
    add  sp, sp, #0x40
    ldr  x8, [x19]
    mov  x0, x19
    ldr  x9, [x8, #0x320]
    ldr  x1, [x8, #0x328]
    br   x16
"""


def _power_source() -> str:
    """`awaken_power(Character*) -> w0` = 0x7FFF - (damage multiplier of the Awakening skill)."""
    return f"""
awaken_power:
    sub  sp, sp, #0x50
    stp  x19, x20, [sp, #0x00]
    stp  x21, x22, [sp, #0x10]
    stp  x23, x24, [sp, #0x20]
    stp  x25, x26, [sp, #0x30]
    str  x30, [sp, #0x40]
    mov  w19, #0
    cbz  x2, ap_done
    ldr  x21, [x2, #0x40]
    cbz  x21, ap_done
    ldr  x21, [x21, #0x18]
    cbz  x21, ap_done
    ldr  w22, [x21, #0x18]
    cbz  w22, ap_done
    adrp x25, #0xbe3000
    ldr  x25, [x25, #0x798]
    cbz  x25, ap_done
    mov  w20, #0
ap_skill_loop:
    cmp  w20, w22
    b.ge ap_done
    add  x8, x21, w20, uxtw #3
    ldr  x8, [x8, #0x20]
    cbz  x8, ap_skill_next
    ldr  x23, [x8, #0x18]
    cbz  x23, ap_skill_next
    ldrb w9, [x23, #0x4d]
    orr  w9, w9, #1
    cmp  w9, #5
    b.ne ap_skill_next
    mov  w24, #0
ap_eff_loop:
    cmp  w24, #4
    b.ge ap_done
    add  x8, x23, w24, uxtw #2
    ldr  w0, [x8, #0x3c]
    cmp  w0, #0
    b.le ap_eff_next
    movz x17, #0x{SKILL_EFFECT_GET_DATA & 0xFFFF:x}
    movk x17, #0x{(SKILL_EFFECT_GET_DATA >> 16) & 0xFFFF:x}, lsl #16
    add  x16, x25, x17
    blr  x16
    cbz  x0, ap_eff_next
    ldrb w9, [x0, #0x{SKILL_EFFECT_TYPE_OFFSET:x}]
    cbnz w9, ap_eff_next
    ldr  s0, [x0, #0x{SKILL_EFFECT_VALUE_OFFSET:x}]
    adr  x8, ap_hundred
    ldr  s1, [x8]
    fmul s0, s0, s1
    fcvtzs w9, s0
    cmp  w9, #0
    b.le ap_eff_next
    add  w19, w19, w9
ap_eff_next:
    add  w24, w24, #1
    b    ap_eff_loop
ap_skill_next:
    add  w20, w20, #1
    b    ap_skill_loop
ap_done:
    mov  w0, #0x7fff
    sub  w0, w0, w19
ap_ret:
    ldr  x30, [sp, #0x40]
    ldp  x19, x20, [sp, #0x00]
    ldp  x21, x22, [sp, #0x10]
    ldp  x23, x24, [sp, #0x20]
    ldp  x25, x26, [sp, #0x30]
    add  sp, sp, #0x50
    ret
ap_hundred:
    .word 0x42c80000
"""


def build_cave() -> bytes:
    """Returns the whole cave block: installer, its literals, body, power helper."""
    # pass 1: learn the installer length (the `add` immediate is fixed width)
    probe = assemble_cave(_installer_source(CAVE_VADDR, CAVE_VADDR, 0), base=CAVE_VADDR)
    expected_va = CAVE_VADDR + len(probe)
    tag_va = expected_va + 16
    body_va = tag_va + len(TAG)
    body_delta = body_va - CAVE_VADDR
    if not 0 < body_delta < 0x1000:
        raise SystemExit(f"body delta 0x{body_delta:x} does not fit an `add` immediate")

    installer = assemble_cave(
        _installer_source(expected_va, tag_va, body_delta), base=CAVE_VADDR
    )
    if len(installer) != len(probe):
        raise SystemExit("installer length changed between passes")

    expected = b"".join(word.to_bytes(4, "little") for word in CLIENT_SITE_WORDS)
    body = assemble_cave(_body_source(), base=body_va)
    power_va = body_va + len(body)
    power = assemble_cave(_power_source(), base=power_va)
    block = installer + expected + TAG + body + power
    if CAVE_VADDR + len(block) > CAVE_END:
        raise SystemExit(f"cave overflows: 0x{CAVE_VADDR + len(block):x} > 0x{CAVE_END:x}")
    return block


def power_offset() -> int:
    """Offset of the awaken_power helper from CAVE_VADDR."""
    return _body_va() - CAVE_VADDR + len(assemble_cave(_body_source(), base=_body_va()))


def body_offset() -> int:
    """Offset of the hook body from CAVE_VADDR (for tests and documentation)."""
    return _body_va() - CAVE_VADDR


def _body_va() -> int:
    probe = assemble_cave(_installer_source(CAVE_VADDR, CAVE_VADDR, 0), base=CAVE_VADDR)
    return CAVE_VADDR + len(probe) + 16 + len(TAG)


def installer_entry_word() -> int:
    """`b <CAVE_VADDR>` from the 14.01 installer's final `ret`."""
    diff = CAVE_VADDR - INSTALLER_ENTRY
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise SystemExit("installer entry is out of branch range")
    return 0x14000000 | ((diff >> 2) & 0x03FFFFFF)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hex", action="store_true", help="print the hex constant only")
    parser.add_argument(
        "--reference",
        type=Path,
        help="reference libfwt_local_server.so (prints the stock hash of the cave range)",
    )
    args = parser.parse_args()

    block = build_cave()
    if args.hex:
        print(block.hex())
        return

    print(f"cave vaddr       0x{CAVE_VADDR:x}")
    print(f"cave size        {len(block)} B")
    print(f"cave end         0x{CAVE_VADDR + len(block):x} (limit 0x{CAVE_END:x})")
    print(f"entry word       0x{installer_entry_word():08x} (replaces `ret` at 0x{INSTALLER_ENTRY:x})")
    print(f"body vaddr       0x{CAVE_VADDR + len(block) - len(assemble_cave(_body_source(), base=CAVE_VADDR)):x}")
    print(f"fill             {len(block) * 100 // (CAVE_END - CAVE_VADDR)}% of the free tail")

    reference = args.reference
    if reference is not None and reference.exists():
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from core.elf_mapping import read_load_segments, translate_vaddr

        data = reference.read_bytes()
        offset = translate_vaddr(read_load_segments(data), CAVE_VADDR)
        stock = data[offset : offset + len(block)]
        print(f"stock sha256     {hashlib.sha256(stock).hexdigest()}")

    try:
        from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
    except ImportError:  # pragma: no cover
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for insn in md.disasm(block, CAVE_VADDR):
        print(f"0x{insn.address:08x}: {insn.mnemonic}\t{insn.op_str}")


if __name__ == "__main__":
    main()
