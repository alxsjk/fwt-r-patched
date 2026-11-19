"""Native ELF construction for the experimental Alex Awakening integration.

Based on the separately emulated laboratory prototypes; runtime validation remains required.
"""

from __future__ import annotations

import hashlib
import io
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

from core.core_patches import REFERENCE_SO_SHA256
from core.elf_mapping import read_load_segments, translate_vaddr

_CODE = 0xB34D44

_DONE = 0x9029BC

_DONOR = 0xBA6DC0

_SCRATCH = 0xBE6268

_SOURCE = int.from_bytes(b"00130185", "little")

_TARGET = int.from_bytes(b"00130186", "little")

_SOURCE_RODATA = 0x3B2C08

_BACKWALK_CAVE = 0xB34E64

_BACKWALK_STRIDE = 64

BACKWALK_SPECS: tuple[tuple[str, int, str, str, str, str, int, int, int], ...] = (
    ("identity", 0xA3608C, "5ae300b1", "x20", "x21", "x26", 0xA36094, 0xA360D4, 0xA360E8),
    ("gene_match", 0x8C3B70, "9ce300b1", "x21", "x22", "x28", 0x8C3B78, 0x8C3BB8, 0x8C3BE0),
    ("achievement", 0xA11EF4, "94e200b1", "x22", "x23", "x20", 0xA11EFC, 0xA11F3C, 0xA11F50),
)

def _constant(reg: str, value: int) -> str:
    instructions = [f"movz {reg}, #{value & 0xffff}"]
    instructions.extend(f"movk {reg}, #{(value >> shift) & 0xffff}, lsl #{shift}"
                        for shift in (16, 32, 48))
    return "\n".join(instructions)

def make_stub() -> bytes:
    """Assemble the reference-specific evolution lookup stub."""
    source = f"""
        cmp x21, #8
        b.ne missing
        ldr x8, [x22]
        {_constant('x9', _SOURCE)}
        cmp x8, x9
        b.ne missing
        adrp x16, {_SCRATCH & ~0xfff:#x}
        add x16, x16, #{_SCRATCH & 0xfff}
    lock:
        ldaxr w8, [x16]
        cmp w8, #2
        b.eq ready
        cbnz w8, lock
        mov w9, #1
        stlxr w10, w9, [x16]
        cbnz w10, lock
        add x20, x16, #8
        add x8, x16, #64
        str x8, [x20]
        add x8, x16, #80
        str x8, [x20, #8]
        adrp x17, {_DONOR & ~0xfff:#x}
        add x17, x17, #{_DONOR & 0xfff}
        ldp x8, x9, [x17, #16]
        stp x8, x9, [x20, #16]
        ldp x8, x9, [x17, #32]
        stp x8, x9, [x20, #32]
        ldr x8, [x17, #48]
        str x8, [x20, #48]
        {_constant('x8', _SOURCE)}
        str x8, [x16, #64]
        strb wzr, [x16, #72]
        {_constant('x8', _TARGET)}
        str x8, [x16, #80]
        strb wzr, [x16, #88]
        mov w8, #2
        stlr w8, [x16]
    ready:
        add x20, x16, #8
        b {_DONE:#x}
    missing:
        mov x20, xzr
        b {_DONE:#x}
    """
    code, count = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(source, addr=_CODE)
    if not count or code is None:
        raise RuntimeError("Could not assemble prototype")
    return bytes(code)

def make_backwalk_stubs() -> bytes:
    """Assemble backward rebirth-table stubs mapping 00130186 -> 00130185."""
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    chunks = bytearray()
    for idx, (_name, _site, _orig, len_reg, ptr_reg, inc_reg,
              loop_cont, hit_addr, miss_addr) in enumerate(BACKWALK_SPECS):
        addr = _BACKWALK_CAVE + idx * _BACKWALK_STRIDE
        source = f"""
            adds {inc_reg}, {inc_reg}, #0x38
            b.eq check_alex
            b {loop_cont:#x}
        check_alex:
            cmp {len_reg}, #8
            b.ne miss
            ldr x8, [{ptr_reg}]
            {_constant('x9', _TARGET)}
            cmp x8, x9
            b.ne miss
            adrp x1, {_SOURCE_RODATA & ~0xfff:#x}
            add x1, x1, #{_SOURCE_RODATA & 0xfff}
            b {hit_addr:#x}
        miss:
            b {miss_addr:#x}
        """
        code, count = ks.asm(source, addr=addr)
        if not count or code is None or len(code) != _BACKWALK_STRIDE:
            raise RuntimeError(f"Unexpected backwalk stub size at {addr:#x}: "
                               f"{0 if code is None else len(code)}")
        chunks.extend(code)
    return bytes(chunks)

_SKILL = 0x100185

_ID_CAVE = 0xB34E08

_COST_CAVE = 0xB34E40

_CANDIDATE_COST = 0xB34F24

CANDIDATE_COST_ROW: tuple[int, ...] = (_SKILL, 10, 20, 30, 40, 50, 60, 70, 80, 90, -1)

_ID_FOUND = 0x8C3A14

_ID_NEXT = 0x8C39D4

_COST_FOUND = 0x800E04

_COST_MISSING = 0x800E10

def make_candidate_cost_row() -> bytes:
    """Serialize the 44-byte synthetic SkillLevelTable row for 0x100185."""
    return struct.pack("<11i", *CANDIDATE_COST_ROW)

def _assemble(source: str, address: int) -> bytes:
    code, count = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(source, addr=address)
    if not count or code is None:
        raise ValueError("Could not assemble prototype")
    return bytes(code)

def prototype() -> tuple[bytes, bytes]:
    # Reproduce the original equal branch before applying the new exception.
    # x13 is the last compared table value and is retained on the found path.
    recognition = _assemble(f"""
        b.ne check_candidate
        b {_ID_FOUND:#x}
    check_candidate:
        movz w14, #0x0185
        movk w14, #0x10, lsl #16
        cmp x19, x14
        b.ne not_candidate
        b {_ID_FOUND:#x}
    not_candidate:
        b {_ID_NEXT:#x}
    """, _ID_CAVE)
    cost = _assemble(f"""
        movz w9, #0x0185
        movk w9, #0x10, lsl #16
        cmp x11, x9
        b.eq candidate_cost
        b {_COST_MISSING:#x}
    candidate_cost:
        adrp x9, {_CANDIDATE_COST & ~0xfff:#x}
        add x9, x9, #{_CANDIDATE_COST & 0xfff}
        mov x8, x11
        b {_COST_FOUND:#x}
    """, _COST_CAVE)
    if _ID_CAVE + len(recognition) > _COST_CAVE or _COST_CAVE + len(cost) > 0xB34E64:
        raise ValueError("Prototype ranges overlap or exceed the modeled function")
    return recognition, cost

_MISS = 0x9029B8

_CAVE_HASH = "a0905ad8aa1789b5f7d4cc4eb8ada9f0a4026fd37715b53733f6189b31ba2dd4"

_SKILL_CAVE_HASH = "f7d9bfc0d3807a6612f1fbf33498e7c04692cc12482773ad95e3d621196d1e7d"

_BACKWALK_CAVE_HASH = "ede02cdd0a16cfdcd3853fa6b39dc2e4b77ccb9f17d45f2422358d0709a38066"

_CANDIDATE_COST_HASH = "fae6324032ae44c1e97b723f207a97e888aeaddb6f69b3e1fb6451a974208ace"

def _candidate_in_memory(original: bytes) -> bytes:
    """Construct the validated evolution and skill edits in an ELF copy."""
    if hashlib.sha256(original).hexdigest() != REFERENCE_SO_SHA256:
        raise ValueError("Server is not the supported original reference SO")
    elf = ELFFile(io.BytesIO(original))
    phoff = int(elf.header["e_phoff"])
    phsize = int(elf.header["e_phentsize"])
    segments = list(elf.iter_segments())
    final = [i for i, segment in enumerate(segments)
             if segment["p_type"] == "PT_LOAD"
             and int(segment["p_flags"]) & 2
             and int(segment["p_vaddr"]) + int(segment["p_memsz"]) == _SCRATCH]
    if len(final) != 1:
        raise ValueError("Unexpected writable segment layout")
    segment = segments[final[0]]
    extension = 96
    new_end = _SCRATCH + extension
    if new_end > ((_SCRATCH + 0x3FFF) & ~0x3FFF):
        raise ValueError("Candidate crosses a 16 KiB boundary")
    if any(s["p_type"] == "PT_LOAD" and int(s["p_vaddr"]) >= _SCRATCH
           and int(s["p_vaddr"]) < new_end for s in segments):
        raise ValueError("Candidate collides with another load segment")
    for section in elf.iter_sections():
        if (int(section["sh_flags"]) & 2 and int(section["sh_size"]) > 0
                and int(section["sh_addr"]) < new_end
                and int(section["sh_addr"]) + int(section["sh_size"]) > _SCRATCH):
            raise ValueError("Candidate overlaps an allocated ELF section")
        if isinstance(section, RelocationSection) and any(
            _SCRATCH <= int(rel["r_offset"]) < new_end for rel in section.iter_relocations()
        ):
            raise ValueError("Candidate overlaps a dynamic relocation")
    loads = read_load_segments(original)
    cave_offset = translate_vaddr(loads, _CODE, 196)
    hook_offset = translate_vaddr(loads, _MISS, 4)
    hero_offset = translate_vaddr(loads, 0x6DADFC, 24)
    skill_cave_offset = translate_vaddr(loads, _ID_CAVE, 92)
    id_hook_offset = translate_vaddr(loads, 0x8C39D0, 4)
    cost_hook_offset = translate_vaddr(loads, 0x800E00, 4)
    backwalk_size = len(BACKWALK_SPECS) * _BACKWALK_STRIDE
    backwalk_cave_offset = translate_vaddr(loads, _BACKWALK_CAVE, backwalk_size)
    candidate_cost_row = make_candidate_cost_row()
    candidate_cost_offset = translate_vaddr(loads, _CANDIDATE_COST, len(candidate_cost_row))
    backwalk_hooks = [
        (idx, site, translate_vaddr(loads, site, 4), bytes.fromhex(orig_hex))
        for idx, (_name, site, orig_hex, *_rest) in enumerate(BACKWALK_SPECS)
    ]
    if hashlib.sha256(original[cave_offset:cave_offset + 196]).hexdigest() != _CAVE_HASH:
        raise ValueError("Unexpected candidate code region")
    if original[hook_offset:hook_offset + 4] != bytes.fromhex("f4031faa"):
        raise ValueError("Unexpected lookup miss instruction")
    if original[hero_offset:hero_offset + 24] != bytes.fromhex(
        "8601130081011000820110008401100083011000ffffffff"
    ):
        raise ValueError("Unexpected six-star Alex skill row")
    if hashlib.sha256(original[skill_cave_offset:skill_cave_offset + 92]).hexdigest() \
            != _SKILL_CAVE_HASH:
        raise ValueError("Unexpected skill candidate code region")
    if (original[id_hook_offset:id_hook_offset + 4] != bytes.fromhex("20020054")
            or original[cost_hook_offset:cost_hook_offset + 4] != bytes.fromhex("04000014")):
        raise ValueError("Unexpected skill recognition or cost instruction")
    if hashlib.sha256(original[backwalk_cave_offset:backwalk_cave_offset + backwalk_size]).hexdigest() \
            != _BACKWALK_CAVE_HASH:
        raise ValueError("Unexpected backwalk candidate code region")
    if hashlib.sha256(
        original[candidate_cost_offset:candidate_cost_offset + len(candidate_cost_row)]
    ).hexdigest() != _CANDIDATE_COST_HASH:
        raise ValueError("Unexpected skill cost-row candidate region")
    for _idx, site, offset, expected_bytes in backwalk_hooks:
        if original[offset:offset + 4] != expected_bytes:
            raise ValueError(f"Unexpected backwalk hook instruction at {site:#x}")
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    branch, _ = ks.asm(f"b {_CODE:#x}", addr=_MISS)
    stub = make_stub()
    recognition, cost = prototype()
    backwalk_stubs = make_backwalk_stubs()
    if branch is None or len(branch) != 4 or len(stub) != 196:
        raise ValueError("Unexpected assembled prototype size")
    result = bytearray(original)
    struct.pack_into("<Q", result, phoff + final[0] * phsize + 40,
                     int(segment["p_memsz"]) + extension)
    result[hook_offset:hook_offset + 4] = bytes(branch)
    result[cave_offset:cave_offset + len(stub)] = stub
    struct.pack_into("<I", result, hero_offset + 20, 0x100185)
    for site, target, offset in ((0x8C39D0, _ID_CAVE, id_hook_offset),
                                 (0x800E00, _COST_CAVE, cost_hook_offset)):
        jump, _ = ks.asm(f"b {target:#x}", addr=site)
        if jump is None or len(jump) != 4:
            raise ValueError("Unexpected skill branch size")
        result[offset:offset + 4] = bytes(jump)
    result[skill_cave_offset:skill_cave_offset + len(recognition)] = recognition
    cost_cave_offset = translate_vaddr(loads, _COST_CAVE, len(cost))
    result[cost_cave_offset:cost_cave_offset + len(cost)] = cost
    result[candidate_cost_offset:candidate_cost_offset + len(candidate_cost_row)] = candidate_cost_row
    for idx, site, offset, _expected_bytes in backwalk_hooks:
        target = _BACKWALK_CAVE + idx * _BACKWALK_STRIDE
        jump, _ = ks.asm(f"b {target:#x}", addr=site)
        if jump is None or len(jump) != 4:
            raise ValueError(f"Unexpected backwalk branch size at {site:#x}")
        result[offset:offset + 4] = bytes(jump)
    result[backwalk_cave_offset:backwalk_cave_offset + len(backwalk_stubs)] = backwalk_stubs
    candidate = bytes(result)
    reread = ELFFile(io.BytesIO(candidate))
    changed_segment = list(reread.iter_segments())[final[0]]
    if (int(changed_segment["p_memsz"]) != int(segment["p_memsz"]) + extension
            or int(changed_segment["p_filesz"]) != int(segment["p_filesz"])
            or int(changed_segment["p_align"]) != int(segment["p_align"])):
        raise ValueError("Candidate program header did not round-trip")
    return candidate
