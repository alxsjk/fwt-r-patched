"""Tests for ELF/symbol analysis scripts in tools/."""

from __future__ import annotations

import struct
import subprocess
from types import SimpleNamespace

import pytest

from tools import dump_fn, find_string_refs, patch_audit


def _synthetic_elf(segments: list[tuple[int, int, int, int]], total_size: int) -> bytes:
    """Build a minimal ELF64 image with PT_LOAD headers (vaddr, filesz, offset, flags)."""
    phentsize, phnum = 56, len(segments)
    phoff = 64
    blob = bytearray(max(total_size, phoff + phentsize * phnum))
    blob[:4] = b"\x7fELF"
    blob[4] = 2  # ELFCLASS64
    blob[5] = 1  # little-endian
    struct.pack_into("<Q", blob, 0x20, phoff)
    struct.pack_into("<H", blob, 0x36, phentsize)
    struct.pack_into("<H", blob, 0x38, phnum)
    for index, (vaddr, filesz, offset, flags) in enumerate(segments):
        base = phoff + index * phentsize
        struct.pack_into("<II", blob, base, 1, flags)  # PT_LOAD
        struct.pack_into("<Q", blob, base + 0x08, offset)
        struct.pack_into("<Q", blob, base + 0x10, vaddr)
        struct.pack_into("<Q", blob, base + 0x20, filesz)
    return bytes(blob)


def _adrp(rd: int, pc: int, target_page: int) -> bytes:
    pages = (target_page - (pc & ~0xFFF)) >> 12
    immlo = pages & 0x3
    immhi = (pages >> 2) & 0x7FFFF
    word = 0x90000000 | (immlo << 29) | (immhi << 5) | rd
    return struct.pack("<I", word)


def _add_imm(rd: int, rn: int, imm12: int) -> bytes:
    word = 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd
    return struct.pack("<I", word)


def _movz(rd: int, imm16: int) -> bytes:
    word = 0xD2800000 | ((imm16 & 0xFFFF) << 5) | rd
    return struct.pack("<I", word)


def test_load_symbols_invokes_nm_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, dict[str, object]]] = []
    sample_stdout = (
        "0000000000102000 0000000000000040 T (anonymous namespace)::fn_two()\n"
        "0000000000101000 0000000000000020 T fn_one()\n"
        "not_hex not_hex T ignored\n"
    )

    def fake_run(cmd: object, **kwargs: object) -> SimpleNamespace:
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout=sample_stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)

    unsafe_path = "/tmp/dir name; $(touch pwn); 'quoted'/lib.so"
    names, spans, starts = dump_fn.load_symbols(unsafe_path)
    assert patch_audit.symbols(unsafe_path) == (names, spans, starts)

    assert len(calls) == 2
    for cmd, kwargs in calls:
        assert isinstance(cmd, list)
        assert cmd == ["nm", "-C", "-S", "--defined-only", "--", unsafe_path]
        assert kwargs.get("shell") is False

    assert starts == [0x101000, 0x102000]
    assert spans == [(0x101000, 0x20), (0x102000, 0x40)]
    assert names == {0x101000: "fn_one()", 0x102000: "fn_two()"}


def test_patch_audit_resolves_per_segment_deltas_and_unmapped_offsets() -> None:
    segments_spec = [
        (0x1000, 0x1000, 0x1000, 4),  # .rodata: delta 0
        (0x12000, 0x1000, 0x2000, 5),  # .text (PF_X): delta 0x10000
        (0x2B000, 0x1000, 0x3000, 6),  # .data: delta 0x28000
    ]
    blob = _synthetic_elf(segments_spec, total_size=0x4000)
    segments = dump_fn.parse_segments(blob)
    exec_segments = dump_fn.parse_exec_segments(blob)

    assert exec_segments == [(0x12000, 0x13000, 0x2000)]
    assert dump_fn.offset_to_vaddr(0x1010, segments) == 0x1010
    assert dump_fn.offset_to_vaddr(0x2020, segments) == 0x12020
    assert dump_fn.offset_to_vaddr(0x3030, segments) == 0x2B030
    assert dump_fn.offset_to_vaddr(0x80, segments) is None

    names = {0x1000: "kTable", 0x12000: "fn_text", 0x2B000: "gState"}
    spans = [(0x1000, 0x40), (0x12000, 0x80), (0x2B000, 0x50)]
    starts = [0x1000, 0x12000, 0x2B000]

    assert patch_audit.resolve_run_location(0x1010, segments, names, spans, starts) == (
        0x1010,
        "0x1010 kTable",
    )
    assert patch_audit.resolve_run_location(0x2020, segments, names, spans, starts) == (
        0x12020,
        "0x12020 fn_text",
    )
    assert patch_audit.resolve_run_location(0x3030, segments, names, spans, starts) == (
        0x2B030,
        "0x2b030 gState",
    )
    assert patch_audit.resolve_run_location(0x10, segments, names, spans, starts) == (
        None,
        "off=0x10 (unmapped)",
    )


def test_find_string_refs_handles_segments_interleaved_adrp_and_dump() -> None:
    segments_spec = [
        (0x1000, 0x1000, 0x1000, 4),  # .rodata (delta 0)
        (0x12000, 0x1000, 0x2000, 5),  # .text (PF_X, delta 0x10000)
        (0x2B000, 0x1000, 0x3000, 6),  # .data (delta 0x28000 != 0)
    ]
    raw = bytearray(_synthetic_elf(segments_spec, total_size=0x4000))

    # String placed in .data at file offset 0x3040 -> runtime VA 0x2B040.
    needle = b"SHOP_EVENT_RESET\x00"
    raw[0x3040 : 0x3040 + len(needle)] = needle

    # Emit interleaved adrp + add instructions in .text at offset 0x2000 (VA 0x12000):
    #   0x12000: adrp x0, #0x2b000
    #   0x12004: adrp x8, #0x1000      (interleaved; must NOT clobber x0's page)
    #   0x12008: add  x0, x0, #0x40    -> materializes 0x2B040 (HIT)
    #   0x1200c: adrp x1, #0x2b000
    #   0x12010: movz x1, #0           (clobbers x1; must clear tracked[x1])
    #   0x12014: add  x1, x1, #0x40    -> must NOT trigger false hit
    code = b"".join([
        _adrp(0, 0x12000, 0x2B000),
        _adrp(8, 0x12004, 0x1000),
        _add_imm(0, 0, 0x40),
        _adrp(1, 0x1200C, 0x2B000),
        _movz(1, 0),
        _add_imm(1, 1, 0x40),
    ])
    raw[0x2000 : 0x2000 + len(code)] = code
    blob = bytes(raw)

    segments = dump_fn.parse_segments(blob)
    exec_segments = dump_fn.parse_exec_segments(blob)
    vaddrs = find_string_refs.find_string_vaddrs(blob, "SHOP_EVENT_RESET", segments)
    assert vaddrs == [0x2B040]

    hits = find_string_refs.find_adrp_add_refs(blob, set(vaddrs), exec_segments)
    assert hits == [0x12008]

    disasm_lines = find_string_refs.dump_context(blob, hits[0], segments)
    assert any("0x12008: add" in line for line in disasm_lines)
