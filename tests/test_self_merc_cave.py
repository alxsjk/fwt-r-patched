"""Emulates the self-mercenary projection cave.

The cave no longer borrows the synthetic roster: it reads the player's own mercenary out of the
save. The weekday entry gives the id, then ownership lists are filtered by it --
`creatures` and `costumes` through `find_object_by_int_field_json`, `equipments`, `runes` and
`soulgears` through `raw_array_field` + `select_rows_by_requested_ids_json` -- and each result
is assigned into a projection slot:

    +0x08 hired_info | +0x20 hired_costume | +0x38 hired_equips
    +0x50 hired_runes | +0x80 hired_soulgears

The helpers are stubbed here; a "string" is the libc++ short form (size << 1 in byte 0, the
characters inline), which is all the cave manipulates. What is checked: the request the cave
builds for the filter, the list names it asks for, where each result lands, that every
temporary is released, and that a save with no mercenary configured keeps the stock payload.
"""

from __future__ import annotations

import pytest

unicorn = pytest.importorskip("unicorn")

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X29,
)

from core.core_patches import (  # noqa: E402
    GUILD_RAID_MERCENARY_CAVE_BYTES,
    GUILD_RAID_MERCENARY_CAVE_VADDR,
    GUILD_RAID_MERCENARY_EPILOGUE,
)
from tools import gen_merc_cave as gen  # noqa: E402
from tools.gen_merc_cave import (  # noqa: E402
    BUF_REQ,
    FIND_OBJECT,
    FRAME,
    INT_FIELD,
    RAW_ARRAY_FIELD,
    RAW_OBJECT_FIELD,
    SELECT_ROWS,
    SERVER_NOW_EPOCH,
    STRING_ASSIGN,
    STRING_CTOR,
    STRING_DTOR,
)

CAVE = GUILD_RAID_MERCENARY_CAVE_VADDR
EPILOGUE = GUILD_RAID_MERCENARY_EPILOGUE  # marks the projection valid, then returns
SCRATCH = 0x1000_0000
OUT = SCRATCH + 0x2000
STATE = SCRATCH + 0x3000
STACK = SCRATCH + 0x80000
CONFIGURED = 49
# 2026-11-12 12:00:00 UTC, a Thursday: ((epoch / 86400) + 4) % 7 == 4
THURSDAY = 1762948800


def _map(uc: Uc) -> None:
    uc.mem_map(SCRATCH, 0x100000)
    # one span covers every address the cave reaches: int_field 0x7E08B8, raw_array_field
    # 0x87A64C, find_object 0x897F14, the epilogue 0x9302C4, select_rows 0x911F50, the
    # std::string helpers at 0xAD9... and the cave itself at 0xB34860
    uc.mem_map(0x7D0000, 0x500000)
    for page in _literal_pages():
        uc.mem_map(page, 0x1000)  # the field-name literals the cave materialises
    uc.mem_write(CAVE, GUILD_RAID_MERCENARY_CAVE_BYTES)
    uc.mem_write(OUT, b"\x00" * 0xB0)
    uc.mem_write(STATE, b'{"hired_soldier_idx":49}\x00')
    uc.mem_write(EPILOGUE, bytes.fromhex("28008052"))  # mov w8,#1, so it can be fetched
    literals = {
        gen.LIT_HIRED_SOLDIER_IDX: b"hired_soldier_idx",
        gen.LIT_CRS_IDX: b"crs_idx",
        gen.LIT_CRS_IDX_LIST: b"crs_idx_list",
        gen.LIT_GUILD_HIRED_INFO: b"guild_hired_soldier_info",
        gen.LIT_CREATURES: b"creatures",
        gen.LIT_COSTUMES: b"costumes",
        gen.LIT_EQUIPMENTS: b"equipments",
        gen.LIT_RUNES: b"runes",
        gen.LIT_SOULGEARS: b"soulgears",
    }
    for index, addr in enumerate(gen.LIT_WEEKDAYS):
        weekdays = (b"sun", b"mon", b"tue", b"wed", b"thu", b"fri", b"sat")
        literals[addr] = weekdays[index] + b"_crs_idx"
    for addr, text in literals.items():
        uc.mem_write(addr, text + b"\x00")


def _literal_pages() -> list[int]:
    """Every 4 KB page the generator points a literal at, straight from its constants."""
    literals = [
        gen.LIT_HIRED_SOLDIER_IDX,
        gen.LIT_CRS_IDX,
        gen.LIT_CRS_IDX_LIST,
        gen.LIT_GUILD_HIRED_INFO,
        gen.LIT_CREATURES,
        gen.LIT_COSTUMES,
        gen.LIT_RUNES,
        gen.LIT_SOULGEARS,
        gen.LIT_EQUIPMENTS,
        *gen.LIT_WEEKDAYS,
    ]
    # Include both the literal's page and the next page because the stub reads 64 bytes
    pages: set[int] = set()
    for addr in literals:
        pages.add(addr & ~0xFFF)
        pages.add((addr + 64) & ~0xFFF)
    return sorted(pages)


_FREE_TEXT = {"next": SCRATCH + 0x40000}
_LONG_STR = 0xFF  # marker the stubs use for "characters live at the pointer in slot 16"


def _fake_string(uc: Uc, dest: int, text: bytes) -> None:
    """Short form inline from +1; anything longer parks the text in scratch and points at it.

    The cave never inspects the inside of a string -- it only passes the reference around and
    copies 24 bytes with ``operator=`` -- so the stub layout only has to be self-consistent.
    """
    if len(text) <= 22:
        uc.mem_write(dest, bytes([len(text) << 1]) + text + b"\x00" * (23 - len(text)))
        return
    base = _FREE_TEXT["next"]
    _FREE_TEXT["next"] += 0x100
    uc.mem_write(base, text + b"\x00")
    header = (
        bytes([_LONG_STR]) + b"\x00" * 7
        + len(text).to_bytes(8, "little")
        + base.to_bytes(8, "little")
    )
    uc.mem_write(dest, header[:24])


def _read_string(uc: Uc, addr: int) -> bytes:
    first = uc.mem_read(addr, 1)[0]
    if first == _LONG_STR:
        length = int.from_bytes(bytes(uc.mem_read(addr + 8, 8)), "little")
        ptr = int.from_bytes(bytes(uc.mem_read(addr + 16, 8)), "little")
        return bytes(uc.mem_read(ptr, length))
    return bytes(uc.mem_read(addr + 1, first >> 1))


def _run(configured_id: int | None = CONFIGURED, *, missing_hero: bool = False,
         missing_costume: bool = False) -> dict:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    _map(uc)
    _fake_string(uc, OUT + 0x20, b"null")

    calls: list[str] = []
    stops: list[str] = []
    requests: list[bytes] = []
    lists: list[bytes] = []
    stubs = {
        STRING_CTOR: "ctor",
        STRING_ASSIGN: "assign",
        STRING_DTOR: "dtor",
        INT_FIELD: "int_field",
        RAW_ARRAY_FIELD: "raw_array",
        RAW_OBJECT_FIELD: "raw_object",
        FIND_OBJECT: "find",
        SELECT_ROWS: "select",
        SERVER_NOW_EPOCH: "epoch",
    }

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        name = stubs.get(address)
        if name is None:
            if address in (EPILOGUE, gen.STOCK_HIRE, gen.STOCK_REJECT_SELF):
                stops.append(hex(address))
                uc_.emu_stop()
            return

        calls.append(name)
        if name == "ctor":
            dest = uc_.reg_read(UC_ARM64_REG_X0)
            ptr = uc_.reg_read(UC_ARM64_REG_X1)
            text = bytes(uc_.mem_read(ptr, 64)).split(b"\x00")[0]
            _fake_string(uc_, dest, text)
        elif name == "assign":
            dest = uc_.reg_read(UC_ARM64_REG_X0)
            src = uc_.reg_read(UC_ARM64_REG_X1)
            uc_.mem_write(dest, bytes(uc_.mem_read(src, 24)))
        elif name == "int_field":
            uc_.reg_write(UC_ARM64_REG_X0, 0 if configured_id is None else configured_id)
        elif name == "epoch":
            uc_.reg_write(UC_ARM64_REG_X0, THURSDAY)
        elif name == "dtor":
            pass
        else:
            if name in ("raw_array", "raw_object", "find"):
                lists.append(_read_string(uc_, uc_.reg_read(UC_ARM64_REG_X1)))
            else:
                requests.append(_read_string(uc_, uc_.reg_read(UC_ARM64_REG_X1)))
            missing = name == "find" and (
                (lists[-1] == b"creatures" and missing_hero)
                or (lists[-1] == b"costumes" and missing_costume)
            )
            _fake_string(uc_, uc_.reg_read(UC_ARM64_REG_X8), b"" if missing else f"<{name}>".encode())
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_X0, STATE - 8)  # StateSnapshot: +0x08 is the JSON string
    uc.reg_write(UC_ARM64_REG_X19, OUT)
    uc.reg_write(UC_ARM64_REG_X23, 123)
    uc.reg_write(UC_ARM64_REG_SP, STACK)
    uc.reg_write(UC_ARM64_REG_X29, STACK)
    uc.reg_write(UC_ARM64_REG_LR, 0xDEADBEEF)
    uc.emu_start(CAVE, 0, 0, 20000)
    return {
        "calls": calls,
        "stops": stops,
        "requests": requests,
        "lists": lists,
        "out": bytes(uc.mem_read(OUT, 0xB0)),
        "raw_request": bytes(uc.mem_read(STACK - FRAME + BUF_REQ, 48)).split(b"\x00")[0],
    }


def test_cave_reads_the_players_own_mercenary() -> None:
    result = _run()
    assert result["stops"] == [hex(EPILOGUE)], "the cave leaves through the epilogue"
    assert result["raw_request"] == b'{"crs_idx_list":[49]}', result["raw_request"]
    assert result["lists"] == [
        b"guild_hired_soldier_info",
        b"creatures",
        b"costumes",
        b"equipments",
        b"runes",
        b"soulgears",
        b"costumes",  # all_costumes
        b"soulgears",  # all_soulgears
    ]

    out = result["out"]
    assert out[0] == 0, "the stock valid flag is left as it was"
    for offset, marker in {
        0x08: b"<find>",
        0x20: b"<find>",
        0x38: b"<select>",
        0x50: b"<select>",
        0x80: b"<select>",
        0x68: b"<raw_array>",
        0x98: b"<raw_array>",
    }.items():
        length = out[offset] >> 1
        assert out[offset + 1 : offset + 1 + length] == marker, hex(offset)


def test_every_builder_runs_the_expected_number_of_times() -> None:
    calls = _run()["calls"]
    assert calls.count("epoch") == 1, "the weekday comes from the server clock"
    assert calls.count("raw_object") == 1, "guild_hired_soldier_info"
    assert calls.count("int_field") == 1, "the weekday field answers, so no fallback"
    assert calls.count("find") == 2
    assert calls.count("raw_array") == 5
    assert calls.count("select") == 3
    assert calls.count("assign") == 7, "one per filled slot"
    assert calls.count("dtor") >= 8, "temporaries are released"


def test_nothing_configured_keeps_the_stock_projection() -> None:
    result = _run(configured_id=None)
    assert result["stops"] == [hex(gen.STOCK_HIRE)]
    assert result["raw_request"] == b"", "the request is never built"
    # the weekday map is read before the decision, but no ownership list is touched
    assert result["lists"] == [b"guild_hired_soldier_info"]
    assert result["out"][0x20:0x25] == b"\x08null", "the stock costume is left alone"


def test_missing_costume_keeps_json_null() -> None:
    result = _run(missing_costume=True)
    assert result["stops"] == [hex(EPILOGUE)]
    assert result["out"][0x20:0x25] == b"\x08null"


def test_missing_configured_hero_uses_selected_stock_hire() -> None:
    result = _run(missing_hero=True)
    assert result["stops"] == [hex(gen.STOCK_HIRE)]
    assert result["lists"] == [b"guild_hired_soldier_info", b"creatures"]


def test_cave_fits_the_dead_function_it_lives_in() -> None:
    assert gen.build_cave() == GUILD_RAID_MERCENARY_CAVE_BYTES
    assert len(GUILD_RAID_MERCENARY_CAVE_BYTES) % 4 == 0
    assert len(GUILD_RAID_MERCENARY_CAVE_BYTES) <= 0x478  # next cave starts at 0xB34CD8
