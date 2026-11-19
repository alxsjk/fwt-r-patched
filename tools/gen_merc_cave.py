"""Builds the self-mercenary projection from the player's own save, as AArch64 assembly.

The stock `guild_battle_hired_projection` (0x930034) can only answer for a guild member: it
indexes a synthetic roster and refuses anything else, so the cave used to hand the player a
shipped mirror row (level 120, code 00120646) instead of his own mercenary.

This cave reads the save instead. Measured facts it relies on:

  * `StateSnapshot` is `+0x00` valid, `+0x08` the state JSON `std::string`, `+0x20` self_lord;
  * every ownership list in the state carries the owner in `crs_idx` (`creatures`, `costumes`,
    `runes`, `soulgears`, `equipments`), and the configured mercenary id is the weekday entry;
  * the seven projection slots take JSON fragments and map to
    `+0x08 hired_info`, `+0x20 hired_costume`, `+0x38 hired_equips`, `+0x50 hired_runes`,
    `+0x68 all_costumes`, `+0x80 hired_soulgears`, `+0x98 all_soulgears`;
  * the helpers below all return through `x8` (hidden return pointer) and take
    `std::string const&` arguments.

`all_costumes` / `all_soulgears` contain the full corresponding ownership lists, which the
client uses to resolve costume and soulgear references while creating the hired unit.

Usage:
    python tools/gen_merc_cave.py            # print the listing and the hex of the cave
    python tools/gen_merc_cave.py --hex      # only the hex, ready to paste into core_patches
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.asm_cave import assemble_cave  # noqa: E402

CAVE_VADDR = 0xB34860
EPILOGUE = 0x9302BC  # mov w8,#1 / strb w8,[x19] then the register restores: the stock
STOCK_HIRE = 0x930104
STOCK_REJECT_SELF = 0x9302C4
# function marks the projection valid here, so a cave that jumps straight to 0x9302C4
# (the bare epilogue) leaves valid == 0 and the handler answers ERROR=-101

# --- helpers, measured in libfwt_local_server.so (reference build 03ec76a1) -----------------
STRING_CTOR = 0x7DBFB0  # basic_string(char const*) -> x0 (0xB45FB0 is NOT a constructor)
STRING_ASSIGN = 0xADABB0  # basic_string::operator=(basic_string const&)
STRING_DTOR = 0xAD913C  # ~basic_string()
INT_FIELD = 0x7E08B8  # int_field(json&, key&, default) -> x0
RAW_ARRAY_FIELD = 0x87A64C  # raw_array_field(json&, field&) -> x8
RAW_OBJECT_FIELD = 0x8BE85C  # raw_object_field(json&, field&) -> x8
FIND_OBJECT = 0x897F14  # find_object_by_int_field_json(json&, list&, key&, value) -> x8
SELECT_ROWS = 0x911F50  # select_rows_by_requested_ids_json(array&, request&, ids&, key&) -> x8
SERVER_NOW_EPOCH = 0x87ACE0  # server_now_epoch(state&) -> x0 (honours FWT_TEST_NOW_EPOCH)

# --- literals (vaddr, NUL-terminated and isolated) ------------------------------------------
LIT_HIRED_SOLDIER_IDX = 0x48BDCF
LIT_CREATURES = 0x57E53B
LIT_COSTUMES = 0x1E7EDB
LIT_RUNES = 0x196FE9
LIT_SOULGEARS = 0x196E82
LIT_EQUIPMENTS = 0x4F2AE6
LIT_CRS_IDX = 0x373D7B
LIT_CRS_IDX_LIST = 0x4B0F34
LIT_GUILD_HIRED_INFO = 0x5D1E46  # guild_hired_soldier_info
# one hero per weekday, Sunday first (the epoch arithmetic below yields 0 = Sunday)
LIT_WEEKDAYS = (
    0x1970B8,  # sun_crs_idx
    0x357C56,  # mon_crs_idx
    0x1E8088,  # tue_crs_idx
    0x5A13CA,  # wed_crs_idx
    0x417DF3,  # thu_crs_idx
    0x5A13D6,  # fri_crs_idx
    0x283803,  # sat_crs_idx
)

# --- stack layout ---------------------------------------------------------------------------
KEY_IDX = 0x00  # "hired_soldier_idx"
KEY_CRS = 0x18  # "crs_idx"
KEY_IDS = 0x30  # "crs_idx_list"
KEY_LIST = 0x48  # the list name, rebuilt per use
TEMP_OUT = 0x60  # a builder's result
TEMP_ARR = 0x78  # raw_array_field's result
TEMP_SEL = 0x90  # select_rows_by_requested_ids_json's result
REQ_STR = 0xA8  # the request std::string
SAVED_STATE = 0xC0
SAVED_OUT = 0xC8
SAVED_IDX = 0xD0
HAS_REQ = 0xD8  # 1 once REQ_STR exists (the early bail skips its construction)
USE_STOCK = 0xD9
KEY_GHSI = 0xE0  # "guild_hired_soldier_info"
KEY_DAY = 0xF8  # "<weekday>_crs_idx", rebuilt per run
TEMP_OBJ = 0x110  # raw_object_field's result
BUF_REQ = 0x128  # characters of {"crs_idx_list":[<id>]}
BUF_DIGITS = 0x158
FRAME = 0x180

SYMBOLS = {
    "STRING_CTOR": STRING_CTOR,
    "STRING_ASSIGN": STRING_ASSIGN,
    "STRING_DTOR": STRING_DTOR,
    "INT_FIELD": INT_FIELD,
    "RAW_ARRAY_FIELD": RAW_ARRAY_FIELD,
    "RAW_OBJECT_FIELD": RAW_OBJECT_FIELD,
    "FIND_OBJECT": FIND_OBJECT,
    "SELECT_ROWS": SELECT_ROWS,
    "SERVER_NOW_EPOCH": SERVER_NOW_EPOCH,
    "EPILOGUE": EPILOGUE,
    "STOCK_HIRE": STOCK_HIRE,
    "STOCK_REJECT_SELF": STOCK_REJECT_SELF,
}


def _lit(reg: str, addr: int) -> list[str]:
    return [
        f"    adrp {reg}, #{addr & ~0xFFF:#x}",
        f"    add  {reg}, {reg}, #{addr & 0xFFF:#x}",
    ]


def _make_string(dest: int, literal: int) -> list[str]:
    return [f"    add  x0, sp, #{dest:#x}", *_lit("x1", literal), "    bl   STRING_CTOR"]


def _destroy(dest: int) -> list[str]:
    return [f"    add  x0, sp, #{dest:#x}", "    bl   STRING_DTOR"]


def _assign_slot(temp: int, slot: int) -> list[str]:
    """Copies a builder result into the projection and releases the temporary."""
    return [
        f"    ldr  x0, [sp, #{SAVED_OUT:#x}]",
        f"    add  x0, x0, #{slot:#x}",
        f"    add  x1, sp, #{temp:#x}",
        "    bl   STRING_ASSIGN",
        *_destroy(temp),
    ]


def _find_owned(list_lit: int, slot: int, *, missing: str = "") -> list[str]:
    return [
        *_make_string(KEY_LIST, list_lit),
        f"    add  x8, sp, #{TEMP_OUT:#x}",
        f"    ldr  x0, [sp, #{SAVED_STATE:#x}]",
        f"    add  x1, sp, #{KEY_LIST:#x}",
        f"    add  x2, sp, #{KEY_CRS:#x}",
        f"    ldr  x3, [sp, #{SAVED_IDX:#x}]",
        "    bl   FIND_OBJECT",
        *_destroy(KEY_LIST),
        *([f"    ldrb w9, [sp, #{TEMP_OUT:#x}]", f"    cbz  w9, {missing}"] if missing else []),
        *_assign_slot(TEMP_OUT, slot),
    ]


def _filter_owned(list_lit: int, slot: int) -> list[str]:
    return [
        # array = raw_array_field(state, <list>)
        *_make_string(KEY_LIST, list_lit),
        f"    add  x8, sp, #{TEMP_ARR:#x}",
        f"    ldr  x0, [sp, #{SAVED_STATE:#x}]",
        f"    add  x1, sp, #{KEY_LIST:#x}",
        "    bl   RAW_ARRAY_FIELD",
        *_destroy(KEY_LIST),
        # selected = select_rows_by_requested_ids_json(array, request, "crs_idx_list", "crs_idx")
        f"    add  x8, sp, #{TEMP_SEL:#x}",
        f"    add  x0, sp, #{TEMP_ARR:#x}",
        f"    add  x1, sp, #{REQ_STR:#x}",
        f"    add  x2, sp, #{KEY_IDS:#x}",
        f"    add  x3, sp, #{KEY_CRS:#x}",
        "    bl   SELECT_ROWS",
        *_destroy(TEMP_ARR),
        *_assign_slot(TEMP_SEL, slot),
    ]


def _all_of(list_lit: int, slot: int) -> list[str]:
    """Slot <- the whole list, unfiltered (the `all_*` lookups the client resolves against)."""
    return [
        *_make_string(KEY_LIST, list_lit),
        f"    add  x8, sp, #{TEMP_ARR:#x}",
        f"    ldr  x0, [sp, #{SAVED_STATE:#x}]",
        f"    add  x1, sp, #{KEY_LIST:#x}",
        "    bl   RAW_ARRAY_FIELD",
        *_destroy(KEY_LIST),
        *_assign_slot(TEMP_ARR, slot),
    ]


def _resolve_merc_id() -> list[str]:
    """Which creature fights as the mercenary today.

    The game stores one hero per weekday in `guild_hired_soldier_info` (`mon_crs_idx` …
    `sun_crs_idx`), so the hero is picked from there. The weekday comes from the server clock:
    1970-01-01 was a Thursday, so `((epoch / 86400) + 4) % 7` is 0 for Sunday. A missing
    weekday entry falls back to the selected stock hire.
    """
    lines = [
        *_make_string(KEY_GHSI, LIT_GUILD_HIRED_INFO),
        # info = raw_object_field(state, "guild_hired_soldier_info")
        f"    add  x8, sp, #{TEMP_OBJ:#x}",
        f"    ldr  x0, [sp, #{SAVED_STATE:#x}]",
        f"    add  x1, sp, #{KEY_GHSI:#x}",
        "    bl   RAW_OBJECT_FIELD",
        # weekday = ((epoch / 86400) + 4) % 7
        f"    ldr  x0, [sp, #{SAVED_STATE:#x}]",
        "    bl   SERVER_NOW_EPOCH",
        "    movz x10, #0x5180",  # 86400 seconds, low half
        "    movk x10, #0x1, lsl #16",  # 86400 = 0x15180
        "    udiv x11, x0, x10",
        "    add  x11, x11, #4",
        "    mov  x12, #7",
        "    udiv x13, x11, x12",
        "    msub x14, x13, x12, x11",
    ]
    lines += ["    adr  x15, DAYTABLE", "    add  x15, x15, x14, lsl #2", "    br   x15", "DAYTABLE:"]
    for index in range(len(LIT_WEEKDAYS)):
        lines += [f"    b    DAY{index}"]
    for index, addr in enumerate(LIT_WEEKDAYS):
        lines += [f"DAY{index}:", *_lit("x1", addr)]
        if index != len(LIT_WEEKDAYS) - 1:
            lines.append("    b    DAYOK")
    lines += [
        "DAYOK:",
        f"    add  x0, sp, #{KEY_DAY:#x}",
        "    bl   STRING_CTOR",
        # id = int_field(info, "<weekday>_crs_idx", -1)
        f"    add  x0, sp, #{TEMP_OBJ:#x}",
        f"    add  x1, sp, #{KEY_DAY:#x}",
        "    mov  x2, #-1",
        "    bl   INT_FIELD",
        f"    str  x0, [sp, #{SAVED_IDX:#x}]",
        f"    add  x0, sp, #{KEY_DAY:#x}",
        "    bl   STRING_DTOR",
        *_destroy(TEMP_OBJ),
        f"    ldr  x0, [sp, #{SAVED_IDX:#x}]",
        "    cmp  x0, #1",
        "    b.lt FALLBACK",
        f"    str  x0, [sp, #{SAVED_IDX:#x}]",
    ]
    return lines


def build_source() -> str:
    lines: list[str] = [
        f"    sub  sp, sp, #{FRAME:#x}",
        f"    stp  x29, x30, [sp, #{FRAME - 0x20:#x}]",
        "    mov  x29, sp",
        f"    str  x19, [sp, #{SAVED_OUT:#x}]",  # the projection pointer comes in x19
        "    add  x9, x0, #8",  # &state_json
        f"    str  x9, [sp, #{SAVED_STATE:#x}]",
        f"    strb wzr, [sp, #{HAS_REQ:#x}]",
        f"    strb wzr, [sp, #{USE_STOCK:#x}]",
        *_make_string(KEY_CRS, LIT_CRS_IDX),
        *_make_string(KEY_IDS, LIT_CRS_IDX_LIST),
        # which hero fights as the mercenary today; nothing configured -> keep the stock payload
        *_resolve_merc_id(),
        # request buffer: {"crs_idx_list":[<id>]}
        f"    add  x10, sp, #{BUF_REQ:#x}",
    ]
    for word in (0x7263227B, 0x64695F73, 0x696C5F78, 0x3A227473):
        low, high = word & 0xFFFF, (word >> 16) & 0xFFFF
        lines += [
            f"    movz w11, #{low:#x}",
            f"    movk w11, #{high:#x}, lsl #16",
            "    str  w11, [x10], #4",
        ]
    lines += [
        "    mov  w11, #0x5b",  # '['
        "    strb w11, [x10], #1",
        f"    add  x12, sp, #{BUF_DIGITS:#x}",
        f"    ldr  x13, [sp, #{SAVED_IDX:#x}]",
        "    mov  w14, #10",
        "    mov  w15, #0",
        "itoa:",
        "    udiv x16, x13, x14",
        "    msub x17, x16, x14, x13",
        "    add  x17, x17, #0x30",
        "    strb w17, [x12, x15]",
        "    add  x15, x15, #1",
        "    mov  x13, x16",
        "    cbnz x13, itoa",
        "flip:",
        "    sub  x15, x15, #1",
        "    ldrb w17, [x12, x15]",
        "    strb w17, [x10], #1",
        "    cbnz x15, flip",
        "    mov  w11, #0x5d",  # ']'
        "    strb w11, [x10], #1",
        "    mov  w11, #0x7d",  # '}'
        "    strb w11, [x10], #1",
        "    strb wzr, [x10]",
        f"    add  x0, sp, #{REQ_STR:#x}",
        f"    add  x1, sp, #{BUF_REQ:#x}",
        "    bl   STRING_CTOR",
        "    mov  w9, #1",
        f"    strb w9, [sp, #{HAS_REQ:#x}]",
        # the five slots that carry the player's own data
        *_find_owned(LIT_CREATURES, 0x08, missing="MISSING_HERO"),
        *_find_owned(LIT_COSTUMES, 0x20, missing="NO_COSTUME"),
        "    b    AFTER_COSTUME",
        "NO_COSTUME:",
        *_destroy(TEMP_OUT),  # retain the stock JSON null instead of an empty fragment
        "AFTER_COSTUME:",
        *_filter_owned(LIT_EQUIPMENTS, 0x38),
        *_filter_owned(LIT_RUNES, 0x50),
        *_filter_owned(LIT_SOULGEARS, 0x80),
        # the unfiltered lists the client resolves the costume/soulgear references against
        *_lit("x1", LIT_COSTUMES),
        "    mov  x2, #0x68",
        "    bl   ALL_OF",
        *_lit("x1", LIT_SOULGEARS),
        "    mov  x2, #0x98",
        "    bl   ALL_OF",
        "    b    DONE",
        "MISSING_HERO:",
        *_destroy(TEMP_OUT),
        "FALLBACK:",
        "    mov  w9, #1",
        f"    strb w9, [sp, #{USE_STOCK:#x}]",
        "DONE:",
        *_destroy(KEY_CRS),
        *_destroy(KEY_IDS),
        *_destroy(KEY_GHSI),
        f"    ldrb w9, [sp, #{HAS_REQ:#x}]",
        "    cbz  w9, SKIPREQ",
        *_destroy(REQ_STR),
        "SKIPREQ:",
        f"    ldrb w9, [sp, #{USE_STOCK:#x}]",
        f"    ldr  x0, [sp, #{SAVED_STATE:#x}]",
        "    sub  x0, x0, #8",
        f"    ldp  x29, x30, [sp, #{FRAME - 0x20:#x}]",
        f"    add  sp, sp, #{FRAME:#x}",
        "    cbz  w9, SELF_DONE",
        "    ldr  x8, [x0, #0x20]",
        "    cmp  x8, x23",
        "    b.eq STOCK_REJECT_SELF",
        "    b    STOCK_HIRE",
        "SELF_DONE:",
        "    b    EPILOGUE",
        "ALL_OF:",
        f"    str  x30, [sp, #{BUF_DIGITS:#x}]",
        f"    str  x2, [sp, #{BUF_DIGITS + 8:#x}]",
        f"    add  x0, sp, #{KEY_LIST:#x}",
        "    bl   STRING_CTOR",
        f"    add  x8, sp, #{TEMP_ARR:#x}",
        f"    ldr  x0, [sp, #{SAVED_STATE:#x}]",
        f"    add  x1, sp, #{KEY_LIST:#x}",
        "    bl   RAW_ARRAY_FIELD",
        *_destroy(KEY_LIST),
        f"    ldr  x0, [sp, #{SAVED_OUT:#x}]",
        f"    ldr  x2, [sp, #{BUF_DIGITS + 8:#x}]",
        "    add  x0, x0, x2",
        f"    add  x1, sp, #{TEMP_ARR:#x}",
        "    bl   STRING_ASSIGN",
        *_destroy(TEMP_ARR),
        f"    ldr  x30, [sp, #{BUF_DIGITS:#x}]",
        "    ret",
    ]
    return "\n".join(lines)


def build_cave() -> bytes:
    return assemble_cave(build_source(), base=CAVE_VADDR, symbols=SYMBOLS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hex", action="store_true", help="print hex only")
    parser.add_argument("--listing", action="store_true", help="print generated assembly")
    args = parser.parse_args(argv)

    if args.listing:
        print(build_source())
        return 0
    code = build_cave()
    if args.hex:
        print(code.hex())
        return 0
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    print(f"; {len(code)} bytes, {len(code) // 4} instructions")
    for ins in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, CAVE_VADDR):
        target = ""
        if ins.mnemonic.startswith("b"):
            try:
                target = f"   -> 0x{int(ins.op_str.lstrip('#'), 16):x}"
            except ValueError:
                target = ""
        print(f"0x{ins.address:x}  {ins.mnemonic:8s} {ins.op_str}{target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
