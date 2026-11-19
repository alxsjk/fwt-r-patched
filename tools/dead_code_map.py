#!/usr/bin/env python3
"""Static dead-code map for carving new AArch64 code caves.

The patch engine places every hook in a "code cave" carved out of
``libfwt_local_server.so``. Space in ``.text`` is the scarce resource: there is no
zeroed or NOP-padded run large enough to host a cave, so every cave has to be cut
out of code that is **provably unreachable** in this build.

This tool answers "which code is unreachable?" with four independent signals and
prints the candidates ranked by size:

1. **direct calls** — ``BL``/``B`` targets decoded with capstone;
2. **indirect references** — ``R_AARCH64_RELATIVE`` addends and internal
   ``JUMP_SLOT`` symbols (the only way a function can be called through a pointer
   in a PIE library);
3. **pointer literals** — 8-byte words in data sections that match a function
   start (catches static tables built without relocations);
4. **exported symbols** — anything in ``.dynsym`` can be resolved by name at
   runtime, so it is never a candidate.

Reachability is a BFS from the roots (exported functions, entry point and every
pointer-referenced function). Whatever the BFS never reaches is reported with its
confidence level. A static map is *evidence*, not proof: the candidates still have
to be confirmed on a device with a ``brk #0`` trap build
(``tools/lab_trap_apk.py``).

Usage:
    python tools/dead_code_map.py                      # markdown to stdout
    python tools/dead_code_map.py --json out.json
    python tools/dead_code_map.py --so path/to/lib.so
    python tools/dead_code_map.py --min-size 128 --top 40
"""

from __future__ import annotations

import argparse
import bisect
import fnmatch
import io
import json
import struct
import zipfile
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APK = PROJECT_ROOT / "source" / "fwt_0.682_offline_v1574.apk"
SO_ENTRY = "lib/arm64-v8a/libfwt_local_server.so"

R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1026
R_AARCH64_JUMP_SLOT = 1025
R_AARCH64_RELATIVE = 1027

# Code caves the patch engine already uses.  Their presence in the candidate list
# is the sanity check for this whole analysis: they were chosen because they are
# unused, so the map must agree.
KNOWN_CAVE_RANGES = (
    ("lan_redirect FLAN shim", 0xAB6858, 0xAB7650),
    ("pvp/recycle/gem caves (insertion_sort)", 0xAC81B0, 0xAC82C8),
    ("dev/rune/kraken/fang/exp caves (parseType)", 0xB29EBC, 0xB2AE18),
    ("alex_awakening client hooks (parseExpr)", 0xB2EA8C, 0xB2FAA0),
    ("campaign/event/guild/client caves (NewExpr::printLeft)", 0xB33314, 0xB3384C),
    ("merc/cylinder/event_count/alex caves (parseUnnamedTypeName)", 0xB34860, 0xB34F50),
    ("rune_box_random_roll (DtorName::printLeft)", 0xB3981C, 0xB39860),
)


@dataclass
class Function:
    name: str
    address: int
    size: int
    exported: bool
    reachable: bool = False
    pointer_referenced: bool = False
    direct_calls: int = 0

    @property
    def end(self) -> int:
        return self.address + self.size


@dataclass
class Candidate:
    name: str
    address: int
    size: int
    confidence: str
    reasons: list[str] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.address + self.size


def load_so(apk: Path | None, so_path: Path | None) -> bytes:
    if so_path is not None:
        return Path(so_path).read_bytes()
    if apk is None or not apk.is_file():
        raise SystemExit(
            f"[ERROR] reference APK not found at {apk}; pass --apk or --so"
        )
    with zipfile.ZipFile(apk) as archive:
        return archive.read(SO_ENTRY)


def section_bytes(elf: ELFFile, name: str) -> tuple[int, bytes]:
    section = elf.get_section_by_name(name)
    if section is None:
        return 0, b""
    return section["sh_addr"], section.data()


def collect_functions(elf: ELFFile, text_start: int, text_end: int) -> list[Function]:
    """Collects FUNC symbols with a size, merging .symtab and .dynsym."""
    exported_names: set[str] = set()
    dynsym = elf.get_section_by_name(".dynsym")
    if isinstance(dynsym, SymbolTableSection):
        for symbol in dynsym.iter_symbols():
            if symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_value"]:
                exported_names.add(symbol.name)

    seen: dict[tuple[int, int], Function] = {}
    symtab = elf.get_section_by_name(".symtab")
    if isinstance(symtab, SymbolTableSection):
        for symbol in symtab.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            address = symbol["st_value"]
            size = symbol["st_size"]
            if not size or not (text_start <= address < text_end):
                continue
            key = (address, size)
            if key in seen:
                continue
            seen[key] = Function(
                name=symbol.name or f"sub_{address:x}",
                address=address,
                size=size,
                exported=symbol.name in exported_names,
            )
    functions = sorted(seen.values(), key=lambda item: item.address)
    return functions


def collect_branch_targets(
    text_start: int, text: bytes, functions: list[Function]
) -> tuple[dict[int, set[int]], set[int]]:
    """Returns (call edges, function addresses materialized inside .text).

    Materialization matters as much as calls: a function whose address is loaded
    with ``adrp``+``add`` and handed to ``dl_iterate_phdr``, ``__cxa_atexit``,
    ``pthread_create`` or a JNI registrar is alive even though nothing branches to
    it. Missing that signal is exactly how a naive "no BL" scan labels a live
    callback as dead code.
    """
    starts = [function.address for function in functions]

    def containing(address: int) -> int | None:
        index = bisect.bisect_right(starts, address) - 1
        if index < 0:
            return None
        function = functions[index]
        if function.address <= address < function.end:
            return index
        return None

    edges: dict[int, set[int]] = {}
    materialized: set[int] = set()
    start_set = set(starts)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = False  # parsing op_str is ~20x faster than detail mode
    registers: dict[str, int] = {}
    for instruction in decoder.disasm(text, text_start):
        mnemonic = instruction.mnemonic
        parts = [part.strip() for part in instruction.op_str.split(",")]
        if mnemonic == "adrp" and len(parts) == 2:
            try:
                registers[parts[0]] = int(parts[1].lstrip("#"), 16)
            except ValueError:
                registers.pop(parts[0], None)
            continue
        if mnemonic == "add" and len(parts) == 3 and parts[2].startswith("#"):
            base = registers.get(parts[1])
            if base is not None:
                try:
                    value = base + int(parts[2].lstrip("#"), 0)
                except ValueError:
                    value = None
                if value is not None:
                    registers[parts[0]] = value
                    if value in start_set:
                        materialized.add(value)
                    continue
            registers.pop(parts[0], None)
            continue
        if mnemonic in ("bl", "b") or mnemonic.startswith("b."):
            operand = instruction.op_str.strip()
            if operand.startswith("#"):
                try:
                    target = int(operand[1:], 16)
                except ValueError:
                    target = None
                if target is not None:
                    source = containing(instruction.address)
                    destination = containing(target)
                    if source is not None and destination is not None:
                        edges.setdefault(source, set()).add(destination)
                        functions[source].direct_calls += 1
        if parts and parts[0]:
            registers.pop(parts[0], None)
    return edges, materialized


def collect_indirect_references(
    elf: ELFFile, text_start: int, text_end: int, data_sections: list[str]
) -> tuple[set[int], set[int]]:
    """Returns (relative/jump-slot targets, pointer-literal targets)."""
    relocated: set[int] = set()
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        linked = elf.get_section(section["sh_link"])
        symbols = linked if isinstance(linked, SymbolTableSection) else None
        for relocation in section.iter_relocations():
            kind = relocation["r_info_type"]
            if kind == R_AARCH64_RELATIVE:
                addend = relocation["r_addend"]
                if text_start <= addend < text_end:
                    relocated.add(addend)
            elif kind in (R_AARCH64_JUMP_SLOT, R_AARCH64_GLOB_DAT, R_AARCH64_ABS64):
                index = relocation["r_info_sym"]
                if symbols is None or index >= symbols.num_symbols():
                    continue
                symbol = symbols.get_symbol(index)
                value = symbol["st_value"]
                if symbol["st_shndx"] != "SHN_UNDEF" and text_start <= value < text_end:
                    relocated.add(value)

    literals: set[int] = set()
    for name in data_sections:
        _address, data = section_bytes(elf, name)
        if not data:
            continue
        for offset in range(0, len(data) - 8, 8):
            value = struct.unpack_from("<Q", data, offset)[0]
            if text_start <= value < text_end:
                literals.add(value)
    return relocated, literals


DEFAULT_PROFILES: dict[str, tuple[str, ...]] = {
    "conservative": (),
    # The demangler family is what the shipped campaign/event/guild caves already
    # overwrite (0xb33314), so treating it as never executed matches practice.
    # Mangled names put the namespace in the middle, hence the leading wildcard.
    "demangler-only": ("*itanium_demangle*",),
    # LAN builds do not start the on-device HTTP server (the spawn BLs are NOPed).
    "lan-mode": ("*itanium_demangle*", "*fwt_run_http_server*"),
    # If the game throws a C++ exception it is already broken, so the whole
    # exception/demangling machinery is fair game (the shipped cave relies on it).
    "error-paths": (
        "*itanium_demangle*",
        "*__cxa*",
        "*__cxxabiv1*",
        "*libunwind*",
    ),
}


def build_map(
    so_bytes: bytes, min_size: int, profiles: dict[str, tuple[str, ...]] | None = None
) -> dict:
    elf = ELFFile(io.BytesIO(so_bytes))
    text_start, text = section_bytes(elf, ".text")
    text_end = text_start + len(text)
    functions = collect_functions(elf, text_start, text_end)
    starts = {function.address for function in functions}

    edges, materialized = collect_branch_targets(text_start, text, functions)
    relocated, literals = collect_indirect_references(
        elf, text_start, text_end, [".data.rel.ro", ".data", ".rodata", ".got"]
    )
    relocated &= starts
    literals &= starts
    start_to_index = {function.address: index for index, function in enumerate(functions)}

    root_addresses: set[int] = set()
    for function in functions:
        if function.exported:
            root_addresses.add(function.address)
    for address in materialized | relocated | literals:
        root_addresses.add(address)
        index = start_to_index.get(address)
        if index is not None:
            functions[index].pointer_referenced = True

    def reachable_from(roots: set[int], excluded: set[int]) -> set[int]:
        reached: set[int] = set()
        queue: deque[int] = deque(
            sorted(start_to_index[address] for address in roots if address in start_to_index)
        )
        while queue:
            index = queue.popleft()
            if index in reached or index in excluded:
                continue
            reached.add(index)
            for target in edges.get(index, ()):
                if target not in reached and target not in excluded:
                    queue.append(target)
        return reached

    def candidates_for(excluded: set[int], reached: set[int]) -> list[Candidate]:
        result: list[Candidate] = []
        for index, function in enumerate(functions):
            if index in reached or function.exported or function.size < min_size:
                continue
            if index in excluded:
                # The profile asserts this code never runs; that assertion *is* the
                # space we are looking for, so it belongs in the candidate list.
                result.append(
                    Candidate(
                        name=function.name,
                        address=function.address,
                        size=function.size,
                        confidence="assumed",
                        reasons=["matched an assumed-dead profile pattern"],
                    )
                )
                continue
            result.append(
                Candidate(
                    name=function.name,
                    address=function.address,
                    size=function.size,
                    confidence="high",
                    reasons=[
                        "not called by any BL/B",
                        "address never materialized (adrp+add) or relocated",
                    ],
                )
            )
        result.sort(key=lambda item: (-item.size, item.address))
        return result

    conservative_reached = reachable_from(root_addresses, set())

    profiles = profiles or DEFAULT_PROFILES
    profile_reports: dict[str, dict] = {}
    for name, patterns in profiles.items():
        excluded: set[int] = set()
        matched: list[str] = []
        for pattern in patterns:
            for index, function in enumerate(functions):
                if fnmatch.fnmatchcase(function.name, pattern):
                    excluded.add(index)
                    matched.append(function.name)
        reached = reachable_from(root_addresses, excluded)
        candidates = candidates_for(excluded, reached)
        profile_reports[name] = {
            "patterns": list(patterns),
            "matched": matched,
            "reachable": len(reached),
            "candidates": [asdict(candidate) for candidate in candidates],
            "candidate_bytes": sum(candidate.size for candidate in candidates),
        }
    aggressive_reached = profile_reports[next(iter(profiles))]["reachable"]

    # Bytes in .text that no FUNC symbol claims (alignment gaps, unreachable tails).
    gaps: list[tuple[int, int]] = []
    cursor = text_start
    for function in functions:
        if function.address > cursor:
            gaps.append((cursor, function.address - cursor))
        cursor = max(cursor, function.end)
    if cursor < text_end:
        gaps.append((cursor, text_end - cursor))
    gaps.sort(key=lambda item: -item[1])

    index_of = {function.address: index for index, function in enumerate(functions)}

    def containing_name(address: int) -> str:
        index = bisect.bisect_right(sorted(index_of), address) - 1
        if index < 0:
            return "?"
        start = sorted(index_of)[index]
        function = functions[index_of[start]]
        if function.address <= address < function.end:
            return f"{function.name} (0x{function.address:x}, {function.size} B)"
        return "outside any sized function"

    known = [
        {
            "label": label,
            "range": f"0x{start:x}..0x{end:x}",
            "contains": containing_name(start),
        }
        for label, start, end in KNOWN_CAVE_RANGES
    ]

    return {
        "text": {"start": text_start, "size": len(text)},
        "functions": {
            "with_size": sum(1 for function in functions if function.size),
            "exported": sum(1 for function in functions if function.exported),
            "pointer_referenced": sum(
                1 for function in functions if function.pointer_referenced
            ),
            "reachable_conservative": len(conservative_reached),
            "reachable_aggressive": aggressive_reached,
        },
        "edges": sum(len(targets) for targets in edges.values()),
        "materialized": len(materialized),
        "relocations_into_text": len(relocated),
        "pointer_literals_into_text": len(literals),
        "profiles": profile_reports,
        "candidates_conservative": profile_reports["conservative"]["candidates"]
        if "conservative" in profile_reports
        else [],
        "candidate_bytes_conservative": profile_reports["conservative"]["candidate_bytes"]
        if "conservative" in profile_reports
        else 0,
        "largest_gaps": [
            {"address": f"0x{address:x}", "size": size} for address, size in gaps[:10]
        ],
        "known_caves": known,
        "min_size": min_size,
    }


def render_markdown(report: dict, top: int = 25) -> str:
    functions = report["functions"]
    lines: list[str] = []
    lines.append("# Dead-code map for code caves (generated)\n")
    lines.append(
        "> Generated by `tools/dead_code_map.py`. Do not edit by hand: rerun the\n"
        "> tool. Static evidence only — a candidate becomes usable after a `brk #0`\n"
        "> trap build survives a full game session (`tools/lab_trap_apk.py`).\n"
    )
    lines.append("## Summary\n")
    lines.append(
        f"- `.text` at `0x{report['text']['start']:x}`, "
        f"{report['text']['size']} bytes"
    )
    lines.append(
        f"- functions with a size: {functions['with_size']} "
        f"(exported in `.dynsym`: {functions['exported']})"
    )
    lines.append(f"- direct call edges decoded: {report['edges']}")
    lines.append(
        f"- function addresses materialized with `adrp`+`add`: {report['materialized']}, "
        f"relocated: {report['relocations_into_text']}, "
        f"pointer literals: {report['pointer_literals_into_text']}"
    )
    lines.append(
        f"- reachable, nothing assumed dead: {functions['reachable_conservative']}\n"
    )

    lines.append("## What the caves already in use overwrite\n")
    lines.append(
        "This is the project's own precedent for what counts as dead in this build:\n"
    )
    for entry in report["known_caves"]:
        lines.append(f"- {entry['label']} `{entry['range']}` → {entry['contains']}")
    lines.append("")

    header = "| # | size | address | symbol |"
    divider = "| --- | --- | --- | --- |"
    for name, profile in report["profiles"].items():
        lines.append(
            f"## Profile `{name}` — {len(profile['candidates'])} functions, "
            f"{profile['candidate_bytes']} bytes\n"
        )
        if profile["patterns"]:
            lines.append(
                "Assumed never executed: "
                + ", ".join(f"`{pattern}`" for pattern in profile["patterns"])
                + f" ({len(profile['matched'])} symbol(s) matched)\n"
            )
        candidates = profile["candidates"][:top]
        if not candidates:
            lines.append("_None._\n")
            continue
        lines.append(header)
        lines.append(divider)
        for index, candidate in enumerate(candidates, start=1):
            lines.append(
                f"| {index} | {candidate['size']} | `0x{candidate['address']:x}` | "
                f"`{candidate['name']}` |"
            )
        lines.append("")

    lines.append("## Largest unclaimed byte runs in `.text`\n")
    for gap in report["largest_gaps"][:6]:
        lines.append(f"- `{gap['address']}` — {gap['size']} bytes")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, default=DEFAULT_APK, help="base APK")
    parser.add_argument("--so", type=Path, help="standalone .so (instead of the APK)")
    parser.add_argument("--min-size", type=int, default=96, help="minimum cave size")
    parser.add_argument("--json", type=Path, help="also write the raw report as JSON")
    parser.add_argument(
        "--from-json",
        type=Path,
        help="render an existing JSON report instead of re-analysing the library",
    )
    parser.add_argument("--top", type=int, default=25, help="candidates in the tables")
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        metavar="NAME=GLOB[,GLOB]",
        help=(
            "extra reachability profile: symbols matching a glob are treated as "
            "never executed, so their callees stop counting as reachable. "
            "Default profiles: "
            + "; ".join(f"{k}={','.join(v) or '-'}" for k, v in DEFAULT_PROFILES.items())
        ),
    )
    args = parser.parse_args()

    profiles = dict(DEFAULT_PROFILES)
    for item in args.profile:
        if "=" not in item:
            parser.error(f"--profile expects NAME=GLOB[,GLOB]; got {item!r}")
        name, globs = item.split("=", 1)
        patterns = tuple(part for part in globs.split(",") if part.strip())
        profiles[name.strip()] = patterns

    if args.from_json is not None:
        report = json.loads(args.from_json.read_text(encoding="utf-8"))
        print(render_markdown(report, args.top))
        return 0

    so_bytes = load_so(args.apk, args.so)
    report = build_map(so_bytes, args.min_size, profiles)
    print(render_markdown(report, args.top))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[OK] JSON report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
