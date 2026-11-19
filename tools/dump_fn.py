"""Disassemble one function of libfwt_local_server.so with resolved references.

Usage: python dump_fn.py 0xA2E65C [outfile]
Strips nothing: prints every instruction, annotating adrp+add pairs with the
string/address they materialise and bl/b with the symbol they reach.

vaddr -> file offset is resolved **per PT_LOAD segment**: the .so has
LOAD1 (vaddr 0 == offset 0, holds .rodata, delta 0), LOAD2 (.text, delta
0x4000) and LOAD3/4 (.data, .data.rel.ro, .bss, delta 0x4000). Using one
constant delta reads .rodata 16 KB off and silently shows the wrong table.
"""

from __future__ import annotations

import bisect
import contextlib
import struct
import subprocess
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

LIB = str(
    Path(__file__).resolve().parents[1]
    / "output"
    / "unpacked_ref"
    / "lib"
    / "arm64-v8a"
    / "libfwt_local_server.so"
)
DELTA = 0x4000  # legacy constant: only correct for LOAD2/LOAD3, kept for callers
PT_LOAD = 1
PF_X = 1


def _iter_load_segments(blob: bytes) -> list[tuple[int, int, int, int]]:
    """Return [(vaddr_start, vaddr_end, file_offset, p_flags)] for every PT_LOAD."""
    if blob[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    phoff = struct.unpack_from("<Q", blob, 0x20)[0]
    phentsize = struct.unpack_from("<H", blob, 0x36)[0]
    phnum = struct.unpack_from("<H", blob, 0x38)[0]
    segments: list[tuple[int, int, int, int]] = []
    for index in range(phnum):
        base = phoff + index * phentsize
        p_type, p_flags = struct.unpack_from("<II", blob, base)
        if p_type != PT_LOAD:
            continue
        p_offset = struct.unpack_from("<Q", blob, base + 0x08)[0]
        p_vaddr = struct.unpack_from("<Q", blob, base + 0x10)[0]
        p_filesz = struct.unpack_from("<Q", blob, base + 0x20)[0]
        segments.append((p_vaddr, p_vaddr + p_filesz, p_offset, p_flags))
    return segments


def parse_segments(blob: bytes) -> list[tuple[int, int, int]]:
    """Return [(vaddr_start, vaddr_end, file_offset)] for every PT_LOAD in ``blob``."""
    return [(start, end, offset) for start, end, offset, _ in _iter_load_segments(blob)]


def parse_exec_segments(blob: bytes) -> list[tuple[int, int, int]]:
    """Return [(vaddr_start, vaddr_end, file_offset)] for executable PT_LOAD segments."""
    return [
        (start, end, offset)
        for start, end, offset, flags in _iter_load_segments(blob)
        if (flags & PF_X) and end > start
    ]


def load_segments(lib: str | Path) -> list[tuple[int, int, int]]:
    """Read ``lib`` and return its PT_LOAD mapping."""
    with open(lib, "rb") as handle:
        return parse_segments(handle.read())


def file_offset(vaddr: int, segments: list[tuple[int, int, int]]) -> int | None:
    """Map a runtime address to its file offset, or None when unmapped (.bss)."""
    for start, end, offset in segments:
        if start <= vaddr < end:
            return offset + (vaddr - start)
    return None


def offset_to_vaddr(offset: int, segments: list[tuple[int, int, int]]) -> int | None:
    """Map a file offset back to its runtime virtual address, or None if unmapped."""
    for start, end, seg_off in segments:
        if seg_off <= offset < seg_off + (end - start):
            return start + (offset - seg_off)
    return None


def load_symbols(lib: str | Path) -> tuple[dict[int, str], list[tuple[int, int]], list[int]]:
    """Load defined symbols from ``lib`` using ``nm`` without a shell."""
    out = subprocess.run(
        ["nm", "-C", "-S", "--defined-only", "--", str(lib)],
        shell=False,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    names: dict[int, str] = {}
    spans: list[tuple[int, int]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            start, size = int(parts[0], 16), int(parts[1], 16)
        except ValueError:
            continue
        names[start] = " ".join(parts[3:]).replace("(anonymous namespace)::", "")
        spans.append((start, size))
    spans.sort()
    return names, spans, [s for s, _ in spans]


def main() -> None:
    start = int(sys.argv[1], 0)
    with open(LIB, "rb") as handle:
        blob = handle.read()
    names, spans, starts = load_symbols(LIB)
    segments = load_segments(LIB)
    size = next((sz for st, sz in spans if st == start), 0x200)

    def symbol_at(v: int) -> str:
        if v in names:
            return names[v][:56]
        i = bisect.bisect_right(starts, v) - 1
        if i < 0:
            return "?"
        st, sz = spans[i]
        return f"{names[st][:44]}+0x{v - st:x}" if st <= v < st + sz else "?"

    def text_at(v: int) -> str:
        offset = file_offset(v, segments)
        if offset is None or not 0x160000 <= v < 0xBE4000:
            return ""
        end = blob.find(b"\x00", offset)
        try:
            return blob[offset:end].decode("utf-8")[:40]
        except UnicodeDecodeError:
            return ""

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    tracked: dict[str, int] = {}
    print(f"; 0x{start:x} size 0x{size:x} {symbol_at(start)}", file=sys.stderr)
    code_offset = file_offset(start, segments)
    if code_offset is None:
        raise SystemExit(f"0x{start:x} is outside segments mapped in the file")
    for ins in md.disasm(blob[code_offset : code_offset + size], start):
        note = ""
        if ins.mnemonic == "adrp":
            fields = [f.strip() for f in ins.op_str.split(",")]
            if len(fields) == 2:
                with contextlib.suppress(ValueError):
                    tracked[fields[0]] = int(fields[1].lstrip("#"), 0)
        elif ins.mnemonic == "add":
            fields = [f.strip() for f in ins.op_str.split(",")]
            if len(fields) == 3 and fields[1] in tracked:
                target = -1
                with contextlib.suppress(ValueError):
                    target = tracked[fields[1]] + int(fields[2].lstrip("#"), 0)
                if target >= 0:
                    note = f"  ; =0x{target:x} {text_at(target)}"
        elif ins.mnemonic in ("bl", "b"):
            with contextlib.suppress(ValueError):
                note = f"  ; {symbol_at(int(ins.op_str.lstrip('#'), 0))}"
        print(f"0x{ins.address:x}: {ins.mnemonic:7s} {ins.op_str}{note}")


if __name__ == "__main__":
    main()
