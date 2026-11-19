"""vaddr -> file offset must follow the PT_LOAD map, not one constant delta.

The reference ``libfwt_local_server.so`` is laid out as four PT_LOADs and only
the first one starts at offset 0, so ``file offset = vaddr - 0x4000`` (the
constant the disassembly helper used to apply everywhere) silently reads the
wrong bytes for ``.rodata`` (delta 0) and for ``.data.rel.ro`` (delta 0x8000).
That misread is what made the rune tables look like they had a 16-byte stride.

These tests pin the mapping to the invariants that matter:
``.rodata`` is 1:1 with the file, ``.text`` is shifted, ``.bss`` is unmapped.
"""

from __future__ import annotations

import struct

import pytest

from tools.dump_fn import file_offset, parse_segments

# Addresses measured in the reference APK (libfwt_local_server.so 13,379,896 B).
RODATA_RUNE_TYPES = 0x61E134  # kFwtRuneRewardTypeRows: 17 rows of 16 B
TEXT_PICK_RUNE = 0x982C1C  # pick_battle_rune_code
BSS_START = 0xBE2F70  # NOBITS: not present in file


def _synthetic_elf(segments: list[tuple[int, int, int]]) -> bytes:
    """Builds a minimal ELF64 header + program headers for the given PT_LOADs."""
    phentsize, phnum = 56, len(segments)
    phoff = 64
    blob = bytearray(phoff + phentsize * phnum)
    blob[:4] = b"\x7fELF"
    blob[4] = 2  # ELFCLASS64
    blob[5] = 1  # little endian
    struct.pack_into("<Q", blob, 0x20, phoff)
    struct.pack_into("<H", blob, 0x36, phentsize)
    struct.pack_into("<H", blob, 0x38, phnum)
    for index, (vaddr, filesz, offset) in enumerate(segments):
        base = phoff + index * phentsize
        struct.pack_into("<I", blob, base, 1)  # PT_LOAD
        struct.pack_into("<Q", blob, base + 0x08, offset)
        struct.pack_into("<Q", blob, base + 0x10, vaddr)
        struct.pack_into("<Q", blob, base + 0x20, filesz)
    return bytes(blob)


def test_parse_segments_reads_every_load_from_a_synthetic_elf():
    loads = [(0x0, 0x1000, 0x0), (0x2000, 0x1000, 0x1800)]
    # parse_segments reports [vaddr_start, vaddr_end, file_offset].
    expected = [(0x0, 0x1000, 0x0), (0x2000, 0x3000, 0x1800)]
    assert parse_segments(_synthetic_elf(loads)) == expected


def test_parse_segments_rejects_a_non_elf_blob():
    with pytest.raises(ValueError, match="not an ELF file"):
        parse_segments(b"not an elf at all")


def test_file_offset_is_none_outside_the_mapped_file():
    segments = parse_segments(_synthetic_elf([(0x1000, 0x2000, 0x800)]))
    assert file_offset(0x1800, segments) == 0x1000
    assert file_offset(0x3000, segments) is None


def test_segment_deltas_match_the_reference_library(reference_buffers):
    so_bytes, _ = reference_buffers
    segments = parse_segments(so_bytes)
    assert len(segments) == 4
    deltas = [vaddr - offset for vaddr, _end, offset in segments]
    # LOAD1 (rodata) 1:1, then .text, .data.rel.ro and .data each shifted further.
    assert deltas == [0x0, 0x4000, 0x8000, 0xC000]


def test_rodata_is_read_at_its_own_address(reference_buffers):
    so_bytes, _ = reference_buffers
    segments = parse_segments(so_bytes)
    assert file_offset(RODATA_RUNE_TYPES, segments) == RODATA_RUNE_TYPES
    # The rune type table: group 0 is three rows of weight 1000 for types 0, 1, 2.
    first_three = [struct.unpack_from("<iiii", so_bytes, RODATA_RUNE_TYPES + i * 16) for i in range(3)]
    assert first_three == [(0, 1000, 0, 0), (0, 1000, 1, 0), (0, 1000, 2, 0)]


def test_text_is_shifted_by_the_second_load(reference_buffers):
    so_bytes, _ = reference_buffers
    segments = parse_segments(so_bytes)
    offset = file_offset(TEXT_PICK_RUNE, segments)
    assert offset == TEXT_PICK_RUNE - 0x4000
    # pick_battle_rune_code opens with "sub sp, sp, #0xe0" (0xd10383ff -> ff 83 03 d1).
    assert so_bytes[offset : offset + 4] == bytes.fromhex("ff8303d1")


def test_bss_has_no_file_offset(reference_buffers):
    so_bytes, _ = reference_buffers
    assert file_offset(BSS_START, parse_segments(so_bytes)) is None
