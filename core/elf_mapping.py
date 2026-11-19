"""Validated ELF64 file-backed segment mappings for the native patcher."""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class LoadSegment:
    vaddr: int
    offset: int
    size: int

    def file_offset(self, address: int, size: int = 1) -> int:
        if size < 0 or address < self.vaddr or address + size > self.vaddr + self.size:
            raise ValueError(f"Address 0x{address:x} is outside the file-backed segment")
        return self.offset + address - self.vaddr


def read_load_segments(data: bytes | bytearray) -> tuple[LoadSegment, ...]:
    """Parse and validate little-endian AArch64 ELF64 PT_LOAD ranges."""
    if len(data) < 64 or bytes(data[:6]) != b"\x7fELF\x02\x01":
        raise ValueError("Native library is not a little-endian ELF64 file")
    if struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Native library is not AArch64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    if entsize < 56 or not count or phoff + entsize * count > len(data):
        raise ValueError("Invalid ELF program headers")
    segments = []
    for index in range(count):
        at = phoff + index * entsize
        kind, _flags, offset, vaddr, _paddr, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, at
        )
        if kind != 1:
            continue
        if (filesz > memsz or offset + filesz > len(data) or
                (align > 1 and (align & (align - 1) or offset % align != vaddr % align))):
            raise ValueError("Invalid ELF PT_LOAD file range or alignment")
        if filesz:
            segments.append(LoadSegment(vaddr, offset, filesz))
    if not segments:
        raise ValueError("ELF has no file-backed PT_LOAD segments")
    for key in (lambda s: s.offset, lambda s: s.vaddr):
        ordered = sorted(segments, key=key)
        for left, right in zip(ordered, ordered[1:], strict=False):
            if key(left) + left.size > key(right):
                raise ValueError("Overlapping ELF PT_LOAD ranges")
    return tuple(segments)


def translate_vaddr(segments: tuple[LoadSegment, ...], address: int, size: int = 1) -> int:
    matches = [s for s in segments if s.vaddr <= address and address + size <= s.vaddr + s.size]
    if len(matches) != 1:
        raise ValueError(f"Address 0x{address:x} is not in exactly one file-backed PT_LOAD")
    return matches[0].file_offset(address, size)


def canonicalize_segments(
    data: bytes | bytearray, reference: tuple[tuple[int, int, int], ...]
) -> tuple[bytearray, tuple[tuple[int, int, int], ...]]:
    """Map supported virtual ranges to the patch engine's reference offsets.

    Returns the canonical buffer and (canonical offset, input offset, size)
    mappings. Virtual ranges must match the supported reference; file offsets
    are taken from the input's own PT_LOAD headers.
    """
    segments = read_load_segments(data)
    mappings = []
    for start, end, bias in reference:
        source = translate_vaddr(segments, start, end - start)
        destination = start - bias
        if destination + end - start > len(data):
            raise ValueError("Native library is too small for canonical mapping")
        mappings.append((destination, source, end - start))
    if mappings[0][1] != 0:
        raise ValueError("ELF header segment must begin at file offset zero")
    original = bytes(data)
    canonical = bytearray(original)
    for dest, source, size in mappings:
        if source != dest:
            canonical[source:source + size] = bytes(size)
    for dest, source, size in mappings:
        canonical[dest:dest + size] = original[source:source + size]
    return canonical, tuple(mappings)


def project_segments(
    original: bytes, before: bytes, after: bytearray, mappings: tuple[tuple[int, int, int], ...]
) -> bytes:
    """Project canonical patch results back to the input's actual ELF offsets."""
    if len(before) != len(after) or len(original) != len(after):
        raise ValueError("Native patch unexpectedly resized the ELF")
    output = bytearray(original)
    previous = 0
    for dest, source, size in sorted(mappings):
        if before[previous:dest] != after[previous:dest]:
            raise ValueError("Native patch changed bytes outside mapped PT_LOAD ranges")
        output[source:source + size] = after[dest:dest + size]
        previous = dest + size
    if before[previous:] != after[previous:]:
        raise ValueError("Native patch changed bytes outside mapped PT_LOAD ranges")
    return bytes(output)
