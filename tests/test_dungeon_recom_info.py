"""Emulates the DUNGEON_RECOM_INFO handler cave.

The stock server never answers the client's pre-battle
`DUNGEON_RECOM_INFO` request with a `recom_list`, so the mercenary
auto-select has no candidates. The cave wraps the only dispatch call in
`fwt::EmbeddedStub::handle_json_request`: it scans the request payload for
the CMD (both libc++ string layouts), forwards every other CMD untouched,
echoes `packet_no` through the server's own `int_field`, and builds
`recom_list` with `friend_list_json` after loading the state snapshot.

Everything the cave calls is stubbed here with a self-consistent libc++
layout (short: size<<1 in byte 0, characters inline; long: bit0 set, size at
+8, pointer at +0x10). What is checked: the passthrough leaves `x8/x0/x1`
and the response buffer for the dispatcher, the matched path serves the full
`recom_list` response into the caller's sret, the fallback answers the plain
ack, edge-length payloads cannot walk past the buffer, single-digit
`packet_no` echoes survive the digit flip, and every temporary is released.
"""

from __future__ import annotations

import hashlib
import re

import pytest

unicorn = pytest.importorskip("unicorn")

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X29,
)

from core.core_patches import PatchOptions, apply_all_patches  # noqa: E402
from core.dungeon_recom_info import (  # noqa: E402
    CAVE_BYTES,
    CAVE_ORIGINAL_SHA256,
    CAVE_SIZE,
    CAVE_VADDR,
    HOOK_ORIGINAL,
    HOOK_VADDR,
    apply_dungeon_recom_info,
    dungeon_recom_info_state,
    inspect_dungeon_recom_info,
)
from core.patch_inspector import inspect_native_so  # noqa: E402
from tools import gen_dungeon_recom_cave as gen  # noqa: E402

NEEDLE = b"DUNGEON_RECOM_INFO"
SCRATCH = 0x1000_0000
OUT = SCRATCH + 0x2000
REQUEST = SCRATCH + 0x10000
CONFIG = SCRATCH + 0x15000
STACK = SCRATCH + 0x80000
SENTINEL = SCRATCH + 0x90000
MARK_X19 = 0x1234_5000
MARK_X20 = 0x1234_6000
MARK_X21 = 0x1234_7000
MARK_X29 = 0x1234_8000

LIST_TEXT = b'[{"friend_idx":9900175,"lord_level":50}]'
STATE_JSON = b'{"friends":[{"friend_idx":9900175}]}'
RESPONSE_FULL = (
    b'{"CMD":"DUNGEON_RECOM_INFO","packet_no":69'
    b',"ERROR":0,"msg":"","recom_list":' + LIST_TEXT + b"}"
)
RESPONSE_ACK = b'{"CMD":"DUNGEON_RECOM_INFO","packet_no":69,"ERROR":0,"msg":""}'


def _offset(data: bytes):
    from core.elf_mapping import read_load_segments, translate_vaddr

    segments = read_load_segments(bytes(data))
    return lambda vaddr: translate_vaddr(segments, vaddr)


def test_apply_and_inspect_reference_so(reference_buffers: tuple[bytes, bytes]) -> None:
    so_bytes, dex_bytes = reference_buffers
    offset = _offset(so_bytes)

    assert dungeon_recom_info_state(so_bytes, offset) == "stock"
    assert inspect_dungeon_recom_info(so_bytes, offset) is False
    cave_off = offset(CAVE_VADDR)
    assert len(so_bytes[cave_off : cave_off + CAVE_SIZE]) == CAVE_SIZE
    assert (
        hashlib.sha256(so_bytes[cave_off : cave_off + CAVE_SIZE]).hexdigest() == CAVE_ORIGINAL_SHA256
    )
    site_off = offset(HOOK_VADDR)
    assert bytes(so_bytes[site_off : site_off + 4]) == HOOK_ORIGINAL

    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(),  # always-on bug fix: no option to enable
    )
    assert result.counts["dungeon_recom_info"] == 2
    assert dungeon_recom_info_state(result.so_bytes, offset) == "patched"
    assert inspect_dungeon_recom_info(result.so_bytes, offset) is True

    reports = inspect_native_so(result.so_bytes)
    assert reports["dungeon_recom_info"].active is True

    # Idempotency
    assert apply_dungeon_recom_info(bytearray(result.so_bytes), offset) == 0
    again = apply_all_patches(
        result.so_bytes,
        dex_bytes,
        PatchOptions(allow_unknown=True),
    )
    assert again.counts["dungeon_recom_info"] == 0
    assert again.so_bytes == result.so_bytes


def test_rejects_corrupted_site_or_cave(reference_buffers: tuple[bytes, bytes]) -> None:
    so_bytes, _ = reference_buffers
    offset = _offset(so_bytes)

    bad_site = bytearray(so_bytes)
    bad_site[offset(HOOK_VADDR)] ^= 1
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_dungeon_recom_info(bad_site, offset)

    bad_cave = bytearray(so_bytes)
    bad_cave[offset(CAVE_VADDR)] ^= 1
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_dungeon_recom_info(bad_cave, offset)


def test_generator_matches_module_and_cave_fits() -> None:
    assert gen.build_cave() == CAVE_BYTES
    assert len(CAVE_BYTES) % 4 == 0
    # parseEncoding spans 0xB301F8..0xB3101C (3620 B); the cave must stay inside
    assert len(CAVE_BYTES) <= 0xB3101C - CAVE_VADDR
    # the hook replaces the one dispatch call of handle_json_request
    word = int.from_bytes(HOOK_ORIGINAL, "little")
    assert word >> 26 == 0x25  # BL
    assert HOOK_VADDR + ((word & 0x03FFFFFF) << 2) == gen.DISPATCH


# ---------------------------------------------------------------------------
# Unicorn emulation
# ---------------------------------------------------------------------------

_FREE_TEXT = {"next": SCRATCH + 0x40000}
_LONG_STR = 0xFF  # marker: characters live at the pointer in slot +0x10


def _fake_string(uc: Uc, dest: int, text: bytes) -> None:
    """libc++ layout as the cave reads it: bit0 set -> long, else size<<1."""
    if len(text) <= 22:
        uc.mem_write(dest, bytes([len(text) << 1]) + text + b"\x00" * (23 - len(text)))
        return
    base = _FREE_TEXT["next"]
    _FREE_TEXT["next"] += 0x100
    uc.mem_write(base, text + b"\x00")
    header = (
        bytes([_LONG_STR])
        + b"\x00" * 7
        + len(text).to_bytes(8, "little")
        + base.to_bytes(8, "little")
    )
    uc.mem_write(dest, header[:24])


def _read_string(uc: Uc, addr: int) -> bytes:
    first = uc.mem_read(addr, 1)[0]
    if first & 1:
        length = int.from_bytes(bytes(uc.mem_read(addr + 8, 8)), "little")
        ptr = int.from_bytes(bytes(uc.mem_read(addr + 16, 8)), "little")
        return bytes(uc.mem_read(ptr, length))
    return bytes(uc.mem_read(addr + 1, first >> 1))


def _run(request: bytes, *, state_valid: bool = True) -> dict:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(SCRATCH, 0x100000)
    # one span covers every helper (0x7DDECC..0xAD913C) and the cave at 0xB301F8
    uc.mem_map(0x7D0000, 0x500000)
    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    _fake_string(uc, REQUEST, request)
    uc.mem_write(OUT, b"\x00" * 0x40)
    uc.mem_write(CONFIG, b"\x00" * 0x20)

    calls: list[str] = []
    dispatch_regs: dict[str, int] = {}
    friend_state: list[bytes] = []
    friend_keys: list[bytes] = []
    int_requests: list[int] = []
    int_keys: list[bytes] = []
    int_defaults: list[int] = []

    stubs = {
        gen.DISPATCH: "dispatch",
        gen.LOAD_SNAPSHOT: "snapshot",
        gen.SNAPSHOT_DTOR: "snapshot_dtor",
        gen.FRIEND_LIST_JSON: "friend_list",
        gen.STRING_CTOR: "ctor",
        gen.STRING_CONCAT: "concat",
        gen.STRING_DTOR: "dtor",
        gen.INT_FIELD: "int_field",
    }

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        name = stubs.get(address)
        if name is None:
            return
        calls.append(name)
        if name == "dispatch":
            dispatch_regs["x8"] = uc_.reg_read(UC_ARM64_REG_X8)
            dispatch_regs["x0"] = uc_.reg_read(UC_ARM64_REG_X0)
            dispatch_regs["x1"] = uc_.reg_read(UC_ARM64_REG_X1)
            uc_.mem_write(dispatch_regs["x8"], b"DSPX")
            uc_.reg_write(UC_ARM64_REG_X0, dispatch_regs["x8"])
        elif name == "snapshot":
            snap = uc_.reg_read(UC_ARM64_REG_X8)
            uc_.mem_write(snap, b"\x01" if state_valid else b"\x00")
            if state_valid:
                _fake_string(uc_, snap + 8, STATE_JSON)
        elif name == "snapshot_dtor":
            pass
        elif name == "friend_list":
            friend_state.append(_read_string(uc_, uc_.reg_read(UC_ARM64_REG_X0)))
            friend_keys.append(_read_string(uc_, uc_.reg_read(UC_ARM64_REG_X1)))
            _fake_string(uc_, uc_.reg_read(UC_ARM64_REG_X8), LIST_TEXT)
        elif name == "int_field":
            text = _read_string(uc_, uc_.reg_read(UC_ARM64_REG_X0))
            int_requests.append(uc_.reg_read(UC_ARM64_REG_X0))
            int_keys.append(_read_string(uc_, uc_.reg_read(UC_ARM64_REG_X1)))
            default = uc_.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
            int_defaults.append(default)
            match = re.search(rb'"packet_no"\s*:\s*(\d+)', text)
            uc_.reg_write(UC_ARM64_REG_X0, int(match.group(1)) if match else default)
        elif name == "ctor":
            dest = uc_.reg_read(UC_ARM64_REG_X0)
            ptr = uc_.reg_read(UC_ARM64_REG_X1)
            text = bytes(uc_.mem_read(ptr, 64)).split(b"\x00")[0]
            _fake_string(uc_, dest, text)
        elif name == "concat":
            left = _read_string(uc_, uc_.reg_read(UC_ARM64_REG_X0))
            right = _read_string(uc_, uc_.reg_read(UC_ARM64_REG_X1))
            out = uc_.reg_read(UC_ARM64_REG_X8)
            _fake_string(uc_, out, left + right)
            uc_.reg_write(UC_ARM64_REG_X0, out)
        elif name == "dtor":
            pass
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_X8, OUT)
    uc.reg_write(UC_ARM64_REG_X0, CONFIG)
    uc.reg_write(UC_ARM64_REG_X1, REQUEST)
    uc.reg_write(UC_ARM64_REG_X19, MARK_X19)
    uc.reg_write(UC_ARM64_REG_X20, MARK_X20)
    uc.reg_write(UC_ARM64_REG_X21, MARK_X21)
    uc.reg_write(UC_ARM64_REG_X29, MARK_X29)
    uc.reg_write(UC_ARM64_REG_SP, STACK)
    uc.reg_write(UC_ARM64_REG_LR, SENTINEL)
    uc.emu_start(CAVE_VADDR, SENTINEL, 0, 200000)

    return {
        "calls": calls,
        "counts": {name: calls.count(name) for name in set(stubs.values())},
        "dispatch_regs": dispatch_regs,
        "friend_state": friend_state,
        "friend_keys": friend_keys,
        "int_requests": int_requests,
        "int_keys": int_keys,
        "int_defaults": int_defaults,
        "response": _read_string(uc, OUT),
        "raw_out": bytes(uc.mem_read(OUT, 0x40)),
        "x19": uc.reg_read(UC_ARM64_REG_X19),
        "x20": uc.reg_read(UC_ARM64_REG_X20),
        "x21": uc.reg_read(UC_ARM64_REG_X21),
        "x29": uc.reg_read(UC_ARM64_REG_X29),
    }


def test_other_cmds_reach_the_dispatcher_untouched() -> None:
    request = b'{"CMD":"GET_FRIEND_LIST","access_code":"local-access-code","packet_no":27}'
    result = _run(request)
    assert result["counts"]["dispatch"] == 1
    assert result["counts"]["snapshot"] == 0
    assert result["counts"]["ctor"] == 0
    assert result["dispatch_regs"]["x8"] == OUT
    assert result["dispatch_regs"]["x0"] == CONFIG
    assert result["dispatch_regs"]["x1"] == REQUEST
    assert result["raw_out"][:4] == b"DSPX"
    assert result["x19"] == MARK_X19
    assert result["x20"] == MARK_X20
    assert result["x21"] == MARK_X21
    assert result["x29"] == MARK_X29


def test_short_layout_request_also_passes_through() -> None:
    result = _run(b'{"CMD":"KEEPALIVE"}')
    assert result["counts"]["dispatch"] == 1
    assert result["counts"]["snapshot"] == 0


def test_matched_request_serves_the_friend_array() -> None:
    request = (
        b'{"dg_code":"700100","access_code":"local-access-code",'
        b'"CMD":"DUNGEON_RECOM_INFO","packet_no":69}'
    )
    result = _run(request)
    assert result["counts"]["dispatch"] == 0
    assert result["counts"]["snapshot"] == 1
    assert result["counts"]["friend_list"] == 1
    assert result["counts"]["int_field"] == 1
    assert result["counts"]["ctor"] == 6
    assert result["counts"]["concat"] == 4
    assert result["counts"]["dtor"] == 10
    assert result["counts"]["snapshot_dtor"] == 1
    assert result["friend_state"] == [STATE_JSON]
    assert result["friend_keys"] == [b"friends"]
    assert result["int_requests"] == [REQUEST]
    assert result["int_keys"] == [b"packet_no"]
    assert result["int_defaults"] == [900]
    assert result["response"] == RESPONSE_FULL
    assert result["x19"] == MARK_X19
    assert result["x20"] == MARK_X20
    assert result["x21"] == MARK_X21
    assert result["x29"] == MARK_X29


def test_state_unavailable_answers_the_plain_ack() -> None:
    request = (
        b'{"dg_code":"700100","access_code":"local-access-code",'
        b'"CMD":"DUNGEON_RECOM_INFO","packet_no":69}'
    )
    result = _run(request, state_valid=False)
    assert result["counts"]["dispatch"] == 0
    assert result["counts"]["snapshot"] == 1
    assert result["counts"]["friend_list"] == 0
    assert result["counts"]["concat"] == 2
    assert result["counts"]["snapshot_dtor"] == 0
    assert result["response"] == RESPONSE_ACK


def test_needle_at_the_end_of_the_payload_is_found() -> None:
    filler = b'{"dg_code":"700100","packet_no":5,'
    request = filler + b'"CMD":"' + NEEDLE + b'"}'
    # the needle ends two bytes before the payload's last byte
    assert request[-len(NEEDLE) - 2 : -2] == NEEDLE
    result = _run(request)
    assert result["counts"]["friend_list"] == 1
    assert result["response"].startswith(b'{"CMD":"DUNGEON_RECOM_INFO","packet_no":5,')


def test_single_digit_packet_no_survives_the_flip() -> None:
    request = (
        b'{"dg_code":"700100","access_code":"local-access-code",'
        b'"CMD":"DUNGEON_RECOM_INFO","packet_no":7}'
    )
    result = _run(request)
    assert b'"packet_no":7,"ERROR":0' in result["response"]


def test_missing_packet_no_echoes_the_default() -> None:
    request = b'{"dg_code":"700100","CMD":"' + NEEDLE + b'"}'
    result = _run(request, state_valid=False)
    assert b'"packet_no":900,' in result["response"]


def test_payload_shorter_than_the_needle_passes_through() -> None:
    result = _run(b'{"CMD":"PING"}')
    assert result["counts"]["dispatch"] == 1
    assert result["counts"]["snapshot"] == 0


def test_exact_needle_length_without_match_passes_through() -> None:
    # 19 bytes, no match: the old counter would have walked past the buffer
    result = _run(b"XXXXXXXXXXXXXXXXXXX")
    assert result["counts"]["dispatch"] == 1


def test_exact_needle_length_with_match_is_served() -> None:
    # 19 bytes exactly: the only position must be scanned, then matched
    result = _run(NEEDLE, state_valid=False)
    assert result["counts"]["snapshot"] == 1
    assert result["response"] == b'{"CMD":"DUNGEON_RECOM_INFO","packet_no":900,"ERROR":0,"msg":""}'
