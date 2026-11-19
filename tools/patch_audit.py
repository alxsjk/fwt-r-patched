"""Audit a patched libfwt_local_server.so against the reference build.

Answers one question for the patch review: *where* did the patch touch the binary, and
does every touched region belong to a declared feature?  Anything outside the known
sites/caves is either a feature that forgot to register its range or a patch that is
writing somewhere it should not.

Usage:
    python tools/patch_audit.py reference.so patched.so
"""

from __future__ import annotations

import bisect
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.dump_fn import load_symbols, offset_to_vaddr, parse_segments  # noqa: E402

symbols = load_symbols


def resolve_run_location(
    offset: int,
    segments: list[tuple[int, int, int]],
    names: dict[int, str],
    spans: list[tuple[int, int]],
    starts: list[int],
) -> tuple[int | None, str]:
    """Resolve a differing file offset via ELF PT_LOADs to ``(vaddr, label)``."""
    vaddr = offset_to_vaddr(offset, segments)
    if vaddr is None:
        return None, f"off=0x{offset:x} (unmapped)"
    idx = bisect.bisect_right(starts, vaddr) - 1
    if idx < 0:
        return vaddr, f"0x{vaddr:x} ?"
    start, size = spans[idx]
    if start <= vaddr < start + size:
        return vaddr, f"0x{vaddr:x} {names[start][:56]}"
    return vaddr, f"0x{vaddr:x} (gap after {names[start][:40]})"


def differing_runs(reference: bytes, patched: bytes) -> list[tuple[int, int]]:
    """Contiguous runs of differing bytes, as (offset, length) pairs."""
    if len(reference) != len(patched):
        raise SystemExit(f"size mismatch: {len(reference)} vs {len(patched)}")
    runs: list[tuple[int, int]] = []
    start: int | None = None
    for i, (a, b) in enumerate(zip(reference, patched, strict=True)):
        if a != b:
            if start is None:
                start = i
        elif start is not None:
            runs.append((start, i - start))
            start = None
    if start is not None:
        runs.append((start, len(reference) - start))
    return runs


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        raise SystemExit("Usage: python tools/patch_audit.py <reference.so> <patched.so>")
    ref_path, patched_path = args
    with open(ref_path, "rb") as handle:
        reference = handle.read()
    with open(patched_path, "rb") as handle:
        patched = handle.read()

    segments = parse_segments(reference)
    names, spans, starts = load_symbols(ref_path)
    runs = differing_runs(reference, patched)
    total = sum(length for _, length in runs)
    print(f"{len(runs)} modified regions, {total} bytes")
    print(f"{'vaddr':>12} {'bytes':>6}  where")
    for offset, length in runs:
        vaddr, label = resolve_run_location(offset, segments, names, spans, starts)
        addr_col = f"0x{vaddr:x}" if vaddr is not None else f"off:0x{offset:x}"
        print(f"{addr_col:>12} {length:>6}  {label}")


if __name__ == "__main__":
    main()
