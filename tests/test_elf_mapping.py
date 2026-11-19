from __future__ import annotations

import struct

import pytest

from core.elf_mapping import (
    canonicalize_segments,
    project_segments,
    read_load_segments,
    translate_vaddr,
)


def _elf() -> bytes:
    data = bytearray(0x400)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 183)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 2)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 0x100, 0x100, 1)
    struct.pack_into("<IIQQQQQQ", data, 120, 1, 5, 0x300, 0x200, 0, 0x40, 0x40, 1)
    data[0x300:0x340] = b"A" * 0x40
    return bytes(data)


def test_segment_translation_and_projection():
    original = _elf()
    segments = read_load_segments(original)
    assert translate_vaddr(segments, 0x210, 4) == 0x310
    canonical, mapping = canonicalize_segments(original, ((0, 0x100, 0), (0x200, 0x240, 0)))
    before = bytes(canonical)
    canonical[0x210:0x214] = b"test"
    output = project_segments(original, before, canonical, mapping)
    assert output[0x310:0x314] == b"test"
    assert output[0x210:0x214] == original[0x210:0x214]


def test_invalid_overlapping_segment_and_unmapped_change_are_rejected():
    data = bytearray(_elf())
    struct.pack_into("<Q", data, 120 + 8, 0x80)
    with pytest.raises(ValueError, match="Overlapping"):
        read_load_segments(data)
    original = _elf()
    canonical, mapping = canonicalize_segments(original, ((0, 0x100, 0), (0x200, 0x240, 0)))
    before = bytes(canonical)
    canonical[0x180] = 1
    with pytest.raises(ValueError, match="outside mapped"):
        project_segments(original, before, canonical, mapping)


@pytest.mark.parametrize("moved_vaddr", [0x7DAC80, 0xB4CDF0])
def test_shifted_reference_library_is_patched_and_inspected(reference_buffers, moved_vaddr):
    from core.core_patches import ELF_SEGMENTS, PatchOptions, apply_all_patches
    from core.patch_inspector import inspect_native_so

    so, dex = reference_buffers
    baseline = apply_all_patches(so, dex, PatchOptions(campaign_xp=True))
    shifted = bytearray(so)
    phoff = struct.unpack_from("<Q", shifted, 32)[0]
    entsize, count = struct.unpack_from("<HH", shifted, 54)
    for index in range(count):
        at = phoff + index * entsize
        kind, _, offset, vaddr, _, filesz, _, align = struct.unpack_from("<IIQQQQQQ", shifted, at)
        if kind == 1 and vaddr == moved_vaddr:
            new_offset = ((len(shifted) + align - 1) // align) * align + offset % align
            shifted.extend(bytes(new_offset + filesz - len(shifted)))
            shifted[new_offset:new_offset + filesz] = so[offset:offset + filesz]
            struct.pack_into("<Q", shifted, at + 8, new_offset)
            break
    else:
        pytest.fail("reference executable segment missing")
    result = apply_all_patches(bytes(shifted), dex, PatchOptions(campaign_xp=True, allow_unknown=True))
    canonical, _ = canonicalize_segments(result.so_bytes, ELF_SEGMENTS)
    assert canonical[0x7D6C80:0x7D6C80 + 0x36E170] == baseline.so_bytes[0x7D6C80:0x7D6C80 + 0x36E170]
    assert canonical[0xB44DF0:0xB44DF0 + 0x91EC0] == baseline.so_bytes[0xB44DF0:0xB44DF0 + 0x91EC0]
    assert inspect_native_so(result.so_bytes)["campaign_xp"].active
