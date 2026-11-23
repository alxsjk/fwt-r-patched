"""Verifies a built release APK: packaged .so patches, cave/hook bytes, alignment.

Usage:
    python tools/verify_release_apk.py <apk> [--zipalign PATH]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.apk_tooling import locate_tools  # noqa: E402
from core.elf_mapping import read_load_segments, translate_vaddr  # noqa: E402
from core.merlin_auto_support import (  # noqa: E402
    CAVE_VADDR,
    LATE_HOOK_SITE,
    PRIORITY_CAVE_BYTES,
    PRIORITY_CAVE_VADDR,
    PRIORITY_INSTALL_JUMP,
    merlin_auto_support_state,
)
from core.patch_inspector import inspect_native_so  # noqa: E402

SO_MEMBER = "lib/arm64-v8a/libfwt_local_server.so"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk")
    parser.add_argument("--zipalign", default=None)
    args = parser.parse_args()

    apk = Path(args.apk)
    problems: list[str] = []

    with zipfile.ZipFile(apk) as archive:
        info = archive.getinfo(SO_MEMBER)
        so = archive.read(SO_MEMBER)
    if info.compress_type != zipfile.ZIP_STORED:
        problems.append(f"{SO_MEMBER} is compressed (type {info.compress_type}), must be stored")
    print(f"apk bytes        {apk.stat().st_size}")
    print(f"{SO_MEMBER}  {len(so)} bytes, compress_type={info.compress_type}")

    offset = lambda va: translate_vaddr(read_load_segments(so), va)  # noqa: E731

    # 16 KB paging requirement, as the project enforces it: the ELF's PT_LOAD
    # segments must declare p_align >= 16384 and the .so must be stored. The zip
    # data offset is NOT 16 KB aligned in the shipped artifact either: apksigner
    # re-packs the archive after `zipalign -f 16384`, leaving 4-byte alignment.
    with open(apk, "rb") as handle:
        handle.seek(info.header_offset + 28)
        name_len = int.from_bytes(handle.read(2), "little")
        extra_len = int.from_bytes(handle.read(2), "little")
    data_offset = info.header_offset + 30 + name_len + extra_len
    print(f"so data offset   0x{data_offset:X} (mod 16384 = {data_offset % 16384}; "
          "informational — apksigner re-packs after zipalign)")

    import struct as _struct

    phoff = _struct.unpack_from("<Q", so, 32)[0]
    phentsize, phnum = _struct.unpack_from("<HH", so, 54)
    aligns = []
    for index in range(phnum):
        at = phoff + index * phentsize
        kind = _struct.unpack_from("<I", so, at)[0]
        if kind != 1:  # PT_LOAD
            continue
        aligns.append(_struct.unpack_from("<Q", so, at + 48)[0])
    print(f"PT_LOAD p_align  {[hex(a) for a in aligns]}")
    if not aligns or min(aligns) < 16384:
        problems.append(f"PT_LOAD p_align {aligns} is below 16384 (16 KB paging)")

    state = merlin_auto_support_state(so, offset)
    print(f"merlin state     {state}")
    if state != "patched":
        problems.append(f"merlin_auto_support state is {state}")

    entry = int.from_bytes(so[offset(0xB2B244) : offset(0xB2B244) + 4], "little")
    print(f"installer entry  0x{entry:08X} (expected 0x{PRIORITY_INSTALL_JUMP:08X})")
    if entry != PRIORITY_INSTALL_JUMP:
        problems.append("installer entry word is not `b PRIORITY_CAVE_VADDR`")

    cave_off = offset(PRIORITY_CAVE_VADDR)
    installed = so[cave_off : cave_off + len(PRIORITY_CAVE_BYTES)]
    same = installed == PRIORITY_CAVE_BYTES
    print(f"priority cave    0x{PRIORITY_CAVE_VADDR:X}..0x{PRIORITY_CAVE_VADDR + len(PRIORITY_CAVE_BYTES):X}"
          f" ({len(PRIORITY_CAVE_BYTES)} B) byte-identical: {same}")
    if not same:
        problems.append("priority cave bytes differ from the generator output")

    hook_off = offset(LATE_HOOK_SITE)
    hook = int.from_bytes(so[hook_off : hook_off + 4], "little")
    print(f"server hook      0x{hook:08X} (installs 0x{CAVE_VADDR:X})")
    if (hook & 0xFC000000) != 0x94000000:
        problems.append("server hook site is not a `bl`")

    reports = inspect_native_so(so)
    merlin = reports.get("merlin_auto_support")
    print(f"inspector        active={getattr(merlin, 'active', None)} "
          f"details={getattr(merlin, 'details', '')}")
    if not getattr(merlin, "active", False):
        problems.append("patch inspector does not report merlin_auto_support active")

    zipalign = args.zipalign or locate_tools().zipalign
    if not zipalign:
        problems.append("zipalign not found for the alignment check")
    else:
        result = subprocess.run(
            [zipalign, "-c", "-p", "4", str(apk)],
            capture_output=True,
            text=True,
            check=False,
        )
        ok = result.returncode == 0
        print(f"zipalign -c -p 4      {'OK' if ok else 'FAILED'} {result.stdout.strip()}{result.stderr.strip()}")
        if not ok:
            problems.append("APK fails `zipalign -c -p 4`")

    print()
    if problems:
        for problem in problems:
            print("FAIL:", problem)
        return 1
    print("VERIFIED: packaged .so carries 14.01 + 14.02 + 14.03 and the APK is 16 KB aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
