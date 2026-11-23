"""DUNGEON_RECOM_INFO friend recommendation fix (Feature 08.08).

The stock embedded server never implements `DUNGEON_RECOM_INFO`: the client
asks for the per-dungeon recommended friend mercenaries right before a battle
(its `Result_DUNGEON_RECOM_INFO` parses `recom_list`), and the stub answers the
generic {"CMD":..,"packet_no":..,"ERROR":0,"msg":""} ack with no list at all.
The pre-battle "auto select" option therefore never has a candidate and no
mercenary is picked automatically, even though manual friend selection works.

This always-on server fix wraps the only dispatch call inside
`fwt::EmbeddedStub::handle_json_request` (`0x7DAED0`, `bl 0x7E4030`), where
`x8` is the response sret buffer, `x0` the config whose first member is the
state-path `std::string`, and `x1` the request `std::string`:

* the cave byte-scans the request for `"DUNGEON_RECOM_INFO"` without any C++
  call (`x8/x0/x1` and the link register stay intact) and forwards every
  other CMD to the stock dispatcher -- one short scan of overhead;
* on a match it answers
  `{"CMD":"DUNGEON_RECOM_INFO","packet_no":<echo>,"ERROR":0,"msg":"","recom_list":[...]}`,
  echoing `packet_no` via the server's own `int_field` (`0x7E08B8`), loading
  the state via `load_state_snapshot` (`0x7DDECC`) and building
  `recom_list` with `friend_list_json` (`0x8D5674`) -- the same friend array
  source `GET_FRIEND_LIST` serves as `friend_lists` and `START_GAME` as
  `recommend_list`, so the auto-select finally has candidates to rank;
* if the state cannot be loaded it answers the plain ack (recom_list absent),
  which is exactly the stock behavior.

The cave lives at `0xB301F8` in the unused
`itanium_demangle::AbstractManglingParser::parseEncoding` body (3620 B,
demangler-only profile, same dead-code family as the shipped campaign caves),
rebuilt by `tools/gen_dungeon_recom_cave.py`.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from functools import partial

from core.elf_mapping import read_load_segments, translate_vaddr

HOOK_VADDR = 0x7DAED0  # fwt::EmbeddedStub::handle_json_request: bl dispatch_json_impl
HOOK_ORIGINAL = bytes.fromhex("58240094")  # bl 0x7E4030

CAVE_VADDR = 0xB301F8  # AbstractManglingParser::parseEncoding (demangler-only)
CAVE_BYTES = bytes.fromhex(
    "29004039890000372afd41d32b040091030000142a0440f92b0840f94c4500f1"
    "0d0300548da88ad2cde9a8f2ade8c9f2cde9ebf24eaa88d26ee8a9f2aee9cbf2"
    "2ec9e9f2cfe88952700140f91f020deb4000005408000014700540f91f020eeb"
    "4000005404000014702140791f020f6b000100546b0500918c0500f161feff54"
    "fd7bbfa96dcff297fd7bc1a8c0035fd6ff430bd1fd7b00a9fd030091f35301f9"
    "f45701f9f55b01f9f30308aaf40300aaf50301aae08304910100009021101391"
    "3eaff297e00315aae1830491827080527cc1f297ec030a91ed0300aa4e0180d2"
    "0f0080d2ad0000b511068052f1030a39ff070a3914000014b009ce9a11b60e9b"
    "31c2009191692f38ef050091ed0310aa4dffffb5f00500d1e90500d1290110cb"
    "3f0110ebea000054916970388a6969388a69303891692938100600f1e1feff54"
    "9f692f38e0830791e1030a911baff297e08304917ca3fe97e8830091e00314aa"
    "ddb6f297e983403949070034e0030591010000902138139110aff297e8830991"
    "e0a30091e1030591bd94f697e0830591010000902158139108aff297e8030891"
    "e0830591e1830791ecc4f297e00306910100009021fc139100aff297e8830891"
    "e0030891e1030691e4c4f297e8030991e0830891e1830991e0c4f297e0830691"
    "0100009021841491f4aef297e80313aae0030991e1830691d8c4f297e0830591"
    "51a3fe97e08307914fa3fe97e00306914da3fe97e08306914ba3fe97e0030891"
    "49a3fe97e083089147a3fe97e003099145a3fe97e083099143a3fe97e0030591"
    "41a3fe97e083009175c1f29719000014e08305910100009021581391d7aef297"
    "e8030891e0830591e1830791bbc4f297e003079101000090218c1491cfaef297"
    "e80313aae0030891e1030791b3c4f297e08305912ca3fe97e08307912aa3fe97"
    "e003079128a3fe97e003089126a3fe97e00313aaf35341f9f45741f9f55b41f9"
    "fd7b40a9ff430b91c0035fd67061636b65745f6e6f00667269656e6473007b22"
    "434d44223a2244554e47454f4e5f5245434f4d5f494e464f222c227061636b65"
    "745f6e6f223a002c224552524f52223a302c226d7367223a22222c227265636f"
    "6d5f6c697374223a007d002c224552524f52223a302c226d7367223a22227d00"
)
CAVE_SIZE = len(CAVE_BYTES)
CAVE_ORIGINAL_SHA256 = "1c4f039749e9b48f784dffab7f5246398a8434458ac58bf2f12bb5ac2c1c5cd1"

CAVES: tuple[tuple[int, bytes, str], ...] = (
    (CAVE_VADDR, CAVE_BYTES, CAVE_ORIGINAL_SHA256),
)
HOOKS: tuple[tuple[int, bytes, int], ...] = (
    (HOOK_VADDR, HOOK_ORIGINAL, CAVE_VADDR),
)


def _branch_link(source: int, target: int) -> bytes:
    diff = target - source
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise ValueError("Unsupported ARM64 branch-link distance")
    return struct.pack("<I", 0x94000000 | ((diff >> 2) & 0x03FFFFFF))


def dungeon_recom_info_state(
    data: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> str:
    """Return 'stock', 'patched', or raise ValueError on mixed/unexpected bytes."""
    if offset is None:
        offset = partial(translate_vaddr, read_load_segments(bytes(data)))
    states: list[str] = []
    for addr, original, target in HOOKS:
        off = offset(addr)
        current = bytes(data[off : off + 4])
        states.append(
            "stock"
            if current == original
            else "patched"
            if current == _branch_link(addr, target)
            else "invalid"
        )
    for addr, payload, digest in CAVES:
        off = offset(addr)
        current = bytes(data[off : off + len(payload)])
        states.append(
            "stock"
            if hashlib.sha256(current).hexdigest() == digest
            else "patched"
            if current == payload
            else "invalid"
        )
    if len(set(states)) != 1 or states[0] == "invalid":
        raise ValueError("Unexpected or partially patched DUNGEON_RECOM_INFO code")
    return states[0]


def apply_dungeon_recom_info(
    buf: bytearray, offset: Callable[[int], int] | None = None
) -> int:
    """Install the DUNGEON_RECOM_INFO handler cave."""
    if offset is None:
        offset = partial(translate_vaddr, read_load_segments(bytes(buf)))
    state = dungeon_recom_info_state(buf, offset)
    if state == "patched":
        return 0
    for addr, payload, _digest in CAVES:
        off = offset(addr)
        buf[off : off + len(payload)] = payload
    for addr, _original, target in HOOKS:
        off = offset(addr)
        buf[off : off + 4] = _branch_link(addr, target)
    return len(HOOKS) + len(CAVES)


def inspect_dungeon_recom_info(
    buf: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> bool:
    """Return True if the DUNGEON_RECOM_INFO hook and cave are intact."""
    try:
        return dungeon_recom_info_state(buf, offset) == "patched"
    except (IndexError, TypeError, ValueError):
        return False
