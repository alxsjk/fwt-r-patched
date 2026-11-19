"""Builds a lib whose self projection writes markers into the four unknown slots.

The projection has seven string slots and the stock path fills only three (+0x08 info, +0x20
costume, +0x38 equips). Which response field the remaining four feed is unknown, and the
serialiser cannot be found by xref, so this measures it: the cave keeps doing what it does and
then stamps "SL50" / "SL68" / "SL80" / "SL98" (libc++ short strings, size 4) into +0x50, +0x68,
+0x80 and +0x98. Probing REQ_START_GAME_GUILD then shows which JSON field carries which marker.

Usage:
    python tools/mark_projection_slots.py --in <lib with --guild-raid-mercenary> --out <marked lib>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.core_patches import (  # noqa: E402
    GUILD_RAID_MERCENARY_CAVE_VADDR,
    GUILD_RAID_MERCENARY_EPILOGUE,
)
from core.elf_mapping import read_load_segments, translate_vaddr  # noqa: E402
from tools.asm_cave import assemble_cave  # noqa: E402

MARKERS = {
    0x50: "SL50",
    0x68: "SL68",
    0x80: "SL80",
    0x98: "SL98",
}


def _word_u32(text: str) -> int:
    """Little-endian u32 for the four characters."""
    data = text.encode()
    if len(data) != 4:
        raise ValueError("the marker must be four bytes")
    return int.from_bytes(data, "little")


def build_marker_block(block_va: int) -> bytes:
    """Assembly that stamps the four markers, then jumps to the epilogue."""
    lines = []
    for offset, text in MARKERS.items():
        word = _word_u32(text)
        low = word & 0xFFFF
        high = (word >> 16) & 0xFFFF
        lines += [
            "    mov  w8, #8                 // short string, size 4",
            f"    strb w8, [x19, #{offset:#x}]",
            f"    movz w9, #{low:#x}",
            f"    movk w9, #{high:#x}, lsl #16",
            f"    str  w9, [x19, #{offset + 1:#x}]",
            f"    strb wzr, [x19, #{offset + 5:#x}]",
        ]
    lines.append("    b    EPILOGUE")
    return assemble_cave(
        "\n".join(lines), base=block_va, symbols={"EPILOGUE": GUILD_RAID_MERCENARY_EPILOGUE}
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", dest="output_path", required=True)
    parser.add_argument(
        "--block",
        default="0xB34980",
        help="where to place the marker block (after the current cave, inside the same dead function)",
    )
    args = parser.parse_args(argv)

    block_va = int(args.block, 16)
    code = build_marker_block(block_va)
    buf = bytearray(Path(args.input_path).read_bytes())
    segments = read_load_segments(buf)

    # the current cave ends with "b epilogue": redirect it to the new marker block
    cave = translate_vaddr(segments, GUILD_RAID_MERCENARY_CAVE_VADDR, 0x200)
    window = bytes(buf[cave:cave + 0x200])
    target_off = None
    for i in range(0, len(window) - 4, 4):
        # b <epilogue>: opcode 0x14000000 + imm26
        value = int.from_bytes(window[i:i + 4], "little")
        if value >> 26 != 0b000101:
            continue
        imm26 = value & 0x03FFFFFF
        if imm26 & (1 << 25):
            imm26 -= 1 << 26
        dest = GUILD_RAID_MERCENARY_CAVE_VADDR + i + imm26 * 4
        if dest == GUILD_RAID_MERCENARY_EPILOGUE:
            target_off = i
    if target_off is None:
        print("did not find 'b epilogue' at the end of the cave", file=sys.stderr)
        return 2

    jump = assemble_cave(
        "    b    BLOCK", base=GUILD_RAID_MERCENARY_CAVE_VADDR + target_off, symbols={"BLOCK": block_va}
    )
    buf[cave + target_off:cave + target_off + 4] = jump
    block_off = translate_vaddr(segments, block_va, len(code))
    buf[block_off:block_off + len(code)] = code
    Path(args.output_path).write_bytes(bytes(buf))
    print(f"branch at 0x{GUILD_RAID_MERCENARY_CAVE_VADDR + target_off:x} -> 0x{block_va:x} "
          f"({len(code)} marker bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
