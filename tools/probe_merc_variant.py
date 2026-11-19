"""Builds a variant self-mercenary library that only fills the slots you ask for.

The full cave calls five builders in a row; when one of them throws, the dispatcher answers
`ERROR=-101` and nothing tells which call was at fault. This tool produces a library with a
chosen subset of the slots filled, straight from the pristine reference `.so`, so the probe can
bisect the failure without touching `core_patches` or the recorded cave digest.

Usage:
    python tools/probe_merc_variant.py --slots info --out lib-info.so
    python tools/probe_merc_variant.py --slots info,equips --out /tmp/lib-info-equips.so
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.elf_mapping import read_load_segments, translate_vaddr  # noqa: E402
from tools import gen_merc_cave as gen  # noqa: E402
from tools.asm_cave import assemble_cave  # noqa: E402

REFERENCE_APK = Path(__file__).resolve().parents[1] / "source" / "fwt_0.682_offline_v1574.apk"
SO_ENTRY = "lib/arm64-v8a/libfwt_local_server.so"
SITE = 0x930100  # stock: b.eq 0x9302c4


def _variant_source(slots: set[str]) -> str:
    """The full source with the slots that were not requested dropped."""
    full_source = gen.build_source()
    blocks = {
        "info": gen._find_owned(gen.LIT_CREATURES, 0x08, missing="MISSING_HERO"),
        "costume": gen._find_owned(gen.LIT_COSTUMES, 0x20, missing="NO_COSTUME"),
        "equips": gen._filter_owned(gen.LIT_EQUIPMENTS, 0x38),
        "runes": gen._filter_owned(gen.LIT_RUNES, 0x50),
        "soulgears": gen._filter_owned(gen.LIT_SOULGEARS, 0x80),
        "all_costumes": [*gen._lit("x1", gen.LIT_COSTUMES), "    mov  x2, #0x68", "    bl   ALL_OF"],
        "all_soulgears": [*gen._lit("x1", gen.LIT_SOULGEARS), "    mov  x2, #0x98", "    bl   ALL_OF"],
    }
    output = full_source
    for name, block in blocks.items():
        if name in slots:
            continue
        text = "\n".join(block)
        if text not in output:
            raise SystemExit(f"block {name} not found in generated source")
        output = output.replace(text + "\n", "", 1)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slots", default="info,costume,equips,runes,soulgears,all_costumes,all_soulgears")
    parser.add_argument("--out", required=True)
    parser.add_argument("--apk", default=str(REFERENCE_APK))
    args = parser.parse_args(argv)

    requested = {s.strip() for s in args.slots.split(",") if s.strip()}
    source = _variant_source(requested)
    code = assemble_cave(source, base=gen.CAVE_VADDR, symbols=gen.SYMBOLS)
    print(f"variant cave: {len(code)} bytes | slots: {sorted(requested)}")

    with zipfile.ZipFile(args.apk) as z:
        buf = bytearray(z.read(SO_ENTRY))
    segments = read_load_segments(buf)

    cave_off = translate_vaddr(segments, gen.CAVE_VADDR, len(code))
    buf[cave_off : cave_off + len(code)] = code
    jump = assemble_cave(
        "    b    CAVE", base=SITE, symbols={"CAVE": gen.CAVE_VADDR}
    )
    site_off = translate_vaddr(segments, SITE, 4)
    buf[site_off : site_off + 4] = jump
    Path(args.out).write_bytes(bytes(buf))
    print("wrote:", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
