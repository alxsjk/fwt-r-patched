#!/usr/bin/env python3
"""Builds a laboratory APK with ``brk #0`` traps planted in candidate caves.

Static reachability (``tools/dead_code_map.py``) is evidence, never proof:
this build turns a candidate into an experiment. ``brk #0`` raises SIGTRAP, so if
the game executes the trapped code the process dies immediately — and if a full
session (lobby, shop, gem, arena, stage, battle) survives, that region was dead
in practice.

The lab build is deliberately small: no gameplay patches, plus the dev manifest
(``debuggable`` + ``-dev`` versionName) so the run can be inspected without root.

Usage:
    python tools/lab_trap_apk.py --trap 0xaafdf8 -o output/FWT-lab-dev.apk
    python tools/lab_trap_apk.py --trap 0xb243d0 --trap 0xb245dc -o output/FWT-lab-dev.apk

Install it, play, then check whether the process is still alive:

    adb install -r output/FWT-lab-dev.apk
    adb shell pidof com.nexon.fwar        # empty output right after a crash
    adb logcat -d | grep -i -E "SIGTRAP|DEBUG.*signal|Fatal signal"
"""

from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.apk_tooling import (  # noqa: E402
    _rewrite_zip_entries_to_file,
    locate_tools,
    repack_and_sign_apk,
)
from core.core_patches import DevOptions, PatchOptions  # noqa: E402
from core.elf_mapping import read_load_segments, translate_vaddr  # noqa: E402

DEFAULT_APK = PROJECT_ROOT / "source" / "fwt_0.682_offline_v1574.apk"
DEFAULT_KEYSTORE = PROJECT_ROOT / "keystore" / "fwt_reborn_lan.jks"
SO_ENTRY = "lib/arm64-v8a/libfwt_local_server.so"

# BRK #0 -> SIGTRAP.  AArch64 BRK encoding: 1101 0100 001 imm16 000 00
BRK_ZERO = struct.pack("<I", 0xD4200000)


def apply_traps(so_bytes: bytes, addresses: list[int]) -> bytes:
    """Writes ``brk #0`` at each virtual address (size preserving)."""
    patched = bytearray(so_bytes)
    segments = read_load_segments(so_bytes)
    for address in addresses:
        try:
            offset = translate_vaddr(segments, address, 4)
        except ValueError as error:
            raise SystemExit(f"[ERROR] trap 0x{address:x}: {error}") from error
        if offset + 4 > len(patched):
            raise SystemExit(f"[ERROR] trap 0x{address:x} is outside the file")
        if patched[offset : offset + 4] == BRK_ZERO:
            continue
        patched[offset : offset + 4] = BRK_ZERO
    return bytes(patched)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, default=DEFAULT_APK, help="base APK")
    parser.add_argument(
        "--trap",
        action="append",
        required=True,
        metavar="VADDR",
        help="virtual address of the function to trap (hex, e.g. 0xaafdf8)",
    )
    parser.add_argument(
        "-o", "--output", type=Path, required=True, help="lab APK to write"
    )
    parser.add_argument(
        "--keystore", type=Path, default=DEFAULT_KEYSTORE, help="signing keystore"
    )
    args = parser.parse_args()

    addresses = [int(value, 16) for value in args.trap]
    if not args.apk.is_file():
        print(f"[ERROR] base APK not found: {args.apk}", file=sys.stderr)
        return 1
    output: Path = args.output
    if "-dev" not in output.stem:
        print(
            "[ERROR] a laboratory build must keep the '-dev' marker in the file "
            f"name (got {output.name})",
            file=sys.stderr,
        )
        return 1

    print(f"Reading {args.apk.name}...")
    with zipfile.ZipFile(args.apk) as archive:
        so_bytes = archive.read(SO_ENTRY)

    trapped = apply_traps(so_bytes, addresses)
    segments = read_load_segments(so_bytes)
    for address in addresses:
        offset = translate_vaddr(segments, address, 4)
        print(
            f"  trap 0x{address:x} -> file offset 0x{offset:x} "
            f"(was {so_bytes[offset:offset + 4].hex()})"
        )

    work = output.parent
    work.mkdir(parents=True, exist_ok=True)
    trapped_apk = work / (output.stem + "-trapped-input.apk")
    print(f"Staging the trapped library into {trapped_apk.name}...")
    _rewrite_zip_entries_to_file(args.apk, {SO_ENTRY: trapped}, trapped_apk)

    tools = locate_tools()
    if not tools.has_packaging_tools:
        print("[ERROR] zipalign/apksigner/keytool not found", file=sys.stderr)
        return 1

    print("Aligning and signing the laboratory APK...")
    result = repack_and_sign_apk(
        trapped_apk,
        output,
        PatchOptions(
            allow_unknown=True,
            align_16k=True,
            dev=DevOptions(enabled=True, debuggable=True),
        ),
        tools,
        args.keystore,
        log_fn=lambda message: print(f"  {message}"),
    )
    trapped_apk.unlink(missing_ok=True)
    print(
        f"\n[OK] {output} ({output.stat().st_size / (1024 * 1024):.1f} MiB, "
        f"so_sha256={result.so_sha256[:16]}...)"
    )
    print(
        "Next: adb install -r it, play a full session, then check "
        "`adb shell pidof com.nexon.fwar` and `adb logcat -d | grep -i sigtrap`."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
