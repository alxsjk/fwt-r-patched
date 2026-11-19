"""Reference-checked composition for the experimental Alex Awakening patch.

The caller must provide the original reference ELF and the already-patched ELF.
The patch remains gated on complete runtime and packaging verification.
"""

from __future__ import annotations

import hashlib
import io

from elftools.elf.elffile import ELFFile

from core.alex_awakening_client import (
    CLIENT_CAVE_START,
    RELEASE_LATE_HOOK_EXPECTED,
    RELEASE_LATE_HOOK_SITE,
    assemble_client_cave,
)
from core.alex_awakening_native import (
    _BACKWALK_CAVE,
    _BACKWALK_STRIDE,
    _CANDIDATE_COST,
    BACKWALK_SPECS,
    CANDIDATE_COST_ROW,
    _candidate_in_memory,
)
from core.elf_mapping import read_load_segments, translate_vaddr


def _server_ranges(reference: bytes) -> list[tuple[int, int]]:
    elf = ELFFile(io.BytesIO(reference))
    segments = list(elf.iter_segments())
    writable = [
        index for index, segment in enumerate(segments)
        if segment["p_type"] == "PT_LOAD" and int(segment["p_flags"]) & 2
        and int(segment["p_vaddr"]) + int(segment["p_memsz"]) == 0xBE6268
    ]
    if len(writable) != 1:
        raise ValueError("Unexpected writable segment")
    ph_offset = int(elf.header["e_phoff"]) + writable[0] * int(elf.header["e_phentsize"]) + 40
    loads = read_load_segments(reference)
    specs = [
        (0x9029B8, 4), (0xB34D44, 288), (0x6DADFC, 24),
        (0x8C39D0, 4), (0x800E00, 4),
        (_CANDIDATE_COST, len(CANDIDATE_COST_ROW) * 4),
        (_BACKWALK_CAVE, len(BACKWALK_SPECS) * _BACKWALK_STRIDE),
        *((site, 4) for _name, site, *_rest in BACKWALK_SPECS),
    ]
    return [(ph_offset, 8)] + [
        (translate_vaddr(loads, address, size), size) for address, size in specs
    ]


def apply_alex_awakening(reference: bytes, patched: bytes, *, diagnostics: bool = False) -> bytes:
    """Compose native and client hooks, rejecting overlap with other patches."""
    if len(reference) != len(patched):
        raise ValueError("Unexpected patched server length")
    candidate = _candidate_in_memory(reference)
    output = bytearray(patched)
    for offset, size in _server_ranges(reference):
        if patched[offset:offset + size] != reference[offset:offset + size]:
            raise ValueError(f"Alex Awakening overlaps an existing patch at {offset:#x}")
        output[offset:offset + size] = candidate[offset:offset + size]

    late_branch, cave_bytes = assemble_client_cave(diagnostics=diagnostics)
    loads = read_load_segments(reference)
    cave_offset = translate_vaddr(loads, CLIENT_CAVE_START, len(cave_bytes))
    late_offset = translate_vaddr(loads, RELEASE_LATE_HOOK_SITE, len(late_branch))
    for offset, size in ((cave_offset, len(cave_bytes)), (late_offset, len(late_branch))):
        if patched[offset:offset + size] != reference[offset:offset + size]:
            raise ValueError(f"Alex Awakening overlaps an existing patch at {offset:#x}")
    if patched[late_offset:late_offset + len(late_branch)] != RELEASE_LATE_HOOK_EXPECTED:
        raise ValueError("Unexpected post-AppSealing call")
    output[cave_offset:cave_offset + len(cave_bytes)] = cave_bytes
    output[late_offset:late_offset + len(late_branch)] = late_branch
    return bytes(output)


def inspect_alex_awakening_native(data: bytes | bytearray) -> bool:
    """Independently check the fixed reference-build native patch fingerprints."""
    raw = bytes(data)
    loads = read_load_segments(raw)
    hashes = (
        (0xB2EA8C, 4012, "cde20c9ae09969390e68cb6fa36894a18e5d97fe243737f14f86137841ac0aa4"),
        (0xB34D44, 524, "080c6b41acf00777b178b811ff2cb34e65b79427e6a75605535a874327508091"),
    )
    signatures = (
        (0x6DADFC, "860113008101100082011000840110008301100085011000"),
        (0x9029B8, "e3c80814"), (0x8C39D0, "0ec50914"),
        (0x800E00, "10d00c14"), (0xA3608C, "76fb0314"),
        (0x8C3B70, "cdc40914"), (0xA11EF4, "fc8b0414"),
        (0xAB3378, "c5ed0194"),
    )
    for address, size, expected_digest in hashes:
        offset = translate_vaddr(loads, address, size)
        if hashlib.sha256(raw[offset:offset + size]).hexdigest() != expected_digest:
            return False
    for address, expected_hex in signatures:
        expected = bytes.fromhex(expected_hex)
        offset = translate_vaddr(loads, address, len(expected))
        if raw[offset:offset + len(expected)] != expected:
            return False
    elf = ELFFile(io.BytesIO(raw))
    return any(
        segment["p_type"] == "PT_LOAD" and int(segment["p_flags"]) & 2
        and int(segment["p_vaddr"]) + int(segment["p_memsz"]) == 0xBE62C8
        and int(segment["p_memsz"]) == 0x3618
        for segment in elf.iter_segments()
    )
