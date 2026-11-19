#!/usr/bin/env python3
"""Find references to an ELF string (adrp+add) and disassemble surrounding context.

Usage: python find_string_refs.py "SHOP_BUY_CONTENTS" [--dump] [--lib PATH]
Prints addresses that materialize the string address; with --dump, disassembles
a context window around each reference.
"""
from __future__ import annotations

import argparse
import bisect
import contextlib
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.dump_fn import (  # noqa: E402
    load_symbols,
    offset_to_vaddr,
    parse_exec_segments,
    parse_segments,
)

LIB = str(
    _REPO_ROOT
    / "output"
    / "unpacked_ref"
    / "lib"
    / "arm64-v8a"
    / "libfwt_local_server.so"
)

_REG_WRITE_MNEMONICS = frozenset({
    "adr",
    "ldr",
    "ldrb",
    "ldrh",
    "ldrsb",
    "ldrsh",
    "ldrsw",
    "ldur",
    "ldxr",
    "ldaxr",
    "mov",
    "movz",
    "movn",
    "movk",
    "sub",
    "subs",
    "orr",
    "and",
    "ands",
    "eor",
    "lsl",
    "lsr",
    "asr",
    "madd",
    "msub",
})
_PAIR_LOAD_MNEMONICS = frozenset({"ldp", "ldnp", "ldaxp", "ldxp"})


def symbol_at(
    addr: int,
    names: dict[int, str],
    spans: list[tuple[int, int]],
    starts: list[int],
) -> str:
    """Resolve ``addr`` against preloaded symbol spans."""
    idx = bisect.bisect_right(starts, addr) - 1
    if idx < 0:
        return "?"
    start, size = spans[idx]
    if start <= addr < start + size:
        return f"{names[start][:90]}+0x{addr - start:x}"
    return "?"


def find_string_vaddrs(
    blob: bytes, text: str, segments: list[tuple[int, int, int]]
) -> list[int]:
    """Return sorted runtime VAs for every NUL-terminated occurrence of ``text``."""
    needle = text.encode("utf-8") + b"\x00"
    vaddrs: set[int] = set()
    pos = 0
    while True:
        found = blob.find(needle, pos)
        if found < 0:
            break
        va = offset_to_vaddr(found, segments)
        if va is not None:
            vaddrs.add(va)
        pos = found + 1
    return sorted(vaddrs)


def find_adrp_add_refs(
    blob: bytes,
    target_vaddrs: set[int],
    exec_segments: list[tuple[int, int, int]],
) -> list[int]:
    """Scan executable PT_LOAD segments for ``adrp`` + ``add`` materializing ``target_vaddrs``."""
    if not target_vaddrs:
        return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    hits: list[int] = []
    for seg_va, seg_end, seg_off in exec_segments:
        seg_size = seg_end - seg_va
        tracked: dict[str, int] = {}
        for ins in md.disasm(blob[seg_off : seg_off + seg_size], seg_va):
            if ins.mnemonic == "adrp":
                fields = [f.strip() for f in ins.op_str.split(",")]
                if len(fields) == 2:
                    try:
                        tracked[fields[0]] = int(fields[1].lstrip("#"), 0)
                    except ValueError:
                        tracked.pop(fields[0], None)
            elif ins.mnemonic == "add":
                fields = [f.strip() for f in ins.op_str.split(",")]
                if len(fields) == 3:
                    dest, src, imm_str = fields
                    base_page = tracked.get(src)
                    tracked.pop(dest, None)
                    if base_page is not None:
                        with contextlib.suppress(ValueError):
                            if base_page + int(imm_str.lstrip("#"), 0) in target_vaddrs:
                                hits.append(ins.address)
            elif ins.mnemonic in _PAIR_LOAD_MNEMONICS:
                fields = [f.strip() for f in ins.op_str.split(",", 2)]
                for reg in fields[:2]:
                    tracked.pop(reg, None)
            elif ins.mnemonic in _REG_WRITE_MNEMONICS and ins.op_str:
                dest = ins.op_str.split(",", 1)[0].strip()
                tracked.pop(dest, None)
    return hits


def dump_context(
    blob: bytes, hit: int, segments: list[tuple[int, int, int]]
) -> list[str]:
    """Disassemble a small window around runtime VA ``hit`` within its PT_LOAD segment."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for seg_va, seg_end, seg_off in segments:
        if seg_va <= hit < seg_end:
            off = seg_off + (hit - seg_va)
            start = max(seg_off, off - 0x40)
            end = min(seg_off + (seg_end - seg_va), off + 0x60)
            base = seg_va + (start - seg_off)
            return [
                f"  0x{ins.address:x}: {ins.mnemonic:7s} {ins.op_str}"
                for ins in md.disasm(blob[start:end], base)
            ]
    return []


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", help="NUL-terminated string to locate")
    parser.add_argument(
        "--dump", action="store_true", help="Disassemble context around each reference"
    )
    parser.add_argument(
        "--lib", default=LIB, help=f"Path to ELF shared library (default: {LIB})"
    )
    args = parser.parse_args(argv)

    data = Path(args.lib).read_bytes()
    segments = parse_segments(data)
    exec_segments = parse_exec_segments(data)
    target_vaddrs = find_string_vaddrs(data, args.text, segments)
    if not target_vaddrs:
        print(f"string {args.text!r} not found")
        return
    addr_list = ", ".join(f"0x{va:x}" for va in target_vaddrs)
    print(f"string at {addr_list}")

    hits = find_adrp_add_refs(data, set(target_vaddrs), exec_segments)
    names, spans, starts = load_symbols(args.lib)

    print(f"references: {len(hits)}")
    for hit in hits:
        print(f"  0x{hit:x}  in {symbol_at(hit, names, spans, starts)}")
    if args.dump:
        for hit in hits:
            print(f"\n=== disassembly around 0x{hit:x} ===")
            for line in dump_context(data, hit, segments):
                print(line)


if __name__ == "__main__":
    main()
