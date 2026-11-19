"""Assembles cave code from real AArch64 assembly text.

The caves in `core/core_patches.py` are built by hand-composing encoder calls.  That is fine
for a dozen instructions, but a routine that reads the save, calls builders whose signatures
matter and copies libc++ strings is far too large to encode instruction by instruction
without mistakes.  Keystone assembles the same text a disassembler shows, so the cave can be
written the way it is read.

Symbolic branches are resolved by substitution: pass the addresses a name stands for and the
`bl`/`b`/`b.<cond>` operands are rewritten to `#0x...` before assembling.  Names that are not
in the map are left alone, so labels defined inside the cave (`again:`) still work and a typo
fails inside keystone instead of silently branching to zero.  Keeping this in
Python (no keystone in the patch modules) means the patch engine still emits byte-exact
caves without a new runtime dependency.

Example
-------
>>> code = assemble_cave(
...     '''
...         mov  x0, #1
...         bl   BUILDER
...         b    EPILOGUE
...     ''',
...     base=0xB34860,
...     symbols={"BUILDER": 0xA6B304, "EPILOGUE": 0x9302C4},
... )
>>> len(code)
12
"""

from __future__ import annotations

import re

import keystone

_COMMENT = re.compile(r"(?://|;).*$")
_BRANCH = re.compile(r"\b(b|bl|b\.[a-z]{2})\s+([A-Za-z_][A-Za-z0-9_]*)\b")


def assemble_cave(
    source: str,
    base: int,
    symbols: dict[str, int] | None = None,
) -> bytes:
    """Assembles `source` as AArch64 code that will live at `base`.

    Every named operand of a branch must appear in `symbols`; anything else raises, so a typo
    cannot silently assemble into a branch to address zero.
    """
    symbols = dict(symbols or {})
    lines = []
    for raw_line in source.splitlines():
        cleaned = _COMMENT.sub("", raw_line).strip()
        if cleaned:
            lines.append(cleaned)

    def resolve(match: re.Match[str]) -> str:
        mnemonic, name = match.group(1), match.group(2)
        if name not in symbols:
            # a label defined inside the cave: leave it for keystone
            return match.group(0)
        return f"{mnemonic} #0x{symbols[name]:x}"

    text = "\n".join(lines)
    text = _BRANCH.sub(resolve, text)

    assembler = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    try:
        code, _count = assembler.asm(text, addr=base)
    except keystone.KsError as exc:  # pragma: no cover - surfaced to the caller
        raise ValueError(f"keystone failed to assemble the cave at 0x{base:x}: {exc}") from exc
    return bytes(code)
