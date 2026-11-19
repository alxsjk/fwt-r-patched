"""Emulate the original server lookup plus a candidate hook in memory only.

The supported original ELF is read-only. The simulated libc and string helper,
permissive memory map, and emulated hook do not establish on-device safety.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X28,
)

from core.core_patches import REFERENCE_SO_SHA256
from core.elf_mapping import read_load_segments, translate_vaddr
from tools.lab_alex_server_rule import (
    _BACKWALK_CAVE,
    _BACKWALK_STRIDE,
    _CODE,
    _SCRATCH,
    _SOURCE_RODATA,
    BACKWALK_SPECS,
    make_backwalk_stubs,
    make_stub,
)
from tools.lab_alex_skill_server import (
    _CANDIDATE_COST,
    _COST_CAVE,
    _COST_FOUND,
    _COST_MISSING,
    _DONOR_COST,
    _ID_CAVE,
    _ID_FOUND,
    _ID_NEXT,
    make_candidate_cost_row,
    prototype,
)

_LOOKUP = 0x902920
_MISS = 0x9029B8
_RETURN = 0xC10000
_INPUT = 0xC00000
_SRET = 0xC00100
_STACK = 0xD0F000
_CAVE_HASH = "a0905ad8aa1789b5f7d4cc4eb8ada9f0a4026fd37715b53733f6189b31ba2dd4"
_SKILL_CAVE_HASH = "f7d9bfc0d3807a6612f1fbf33498e7c04692cc12482773ad95e3d621196d1e7d"
_BACKWALK_CAVE_HASH = "ede02cdd0a16cfdcd3853fa6b39dc2e4b77ccb9f17d45f2422358d0709a38066"
_CANDIDATE_COST_HASH = "fae6324032ae44c1e97b723f207a97e888aeaddb6f69b3e1fb6451a974208ace"


def _candidate_in_memory(original: bytes) -> bytes:
    """Model the ELF header, hook and cave changes without writing an ELF."""
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


def exercise(server: Path, base: int = 0) -> None:
    candidate = _candidate_in_memory(server.read_bytes())
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if base & 0x3FFF:
        raise ValueError("Simulated load base must be 16 KiB aligned")
    vm.mem_map(base, 0xD10000)
    with io.BytesIO(candidate) as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                vm.mem_write(base + int(segment["p_vaddr"]), segment.data())
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection) and section.header.sh_type == "SHT_RELA":
                for relocation in section.iter_relocations():
                    address = int(relocation["r_offset"])
                    if 0xBA0610 <= address < 0xBA8020:
                        vm.mem_write(base + address,
                                     struct.pack("<Q", base + int(relocation["r_addend"])))

    def string_at(address: int) -> bytes:
        result = bytearray()
        for offset in range(256):
            char = bytes(vm.mem_read(address + offset, 1))
            if char == b"\0":
                return bytes(result)
            result.extend(char)
        raise ValueError("Unterminated emulated string")

    stop_targets: set[int] = set()

    def helper(uc: Uc, address: int, _size: int, _user: object) -> None:
        address -= base
        if address in stop_targets:
            uc.emu_stop()
            return
        if address == 0x987770:  # padded_creature_code_json, mocked short string
            src = int(uc.reg_read(UC_ARM64_REG_X0))
            first = bytes(uc.mem_read(src, 1))[0]
            if first < 0x30 and (first & 1) == 0:
                value = bytes(uc.mem_read(src + 1, first >> 1))
            else:
                value = string_at(src)
            if len(value) > 20:
                raise ValueError("Only short input strings are supported")
            uc.mem_write(int(uc.reg_read(UC_ARM64_REG_X8)),
                         bytes([len(value) << 1]) + value + b"\0")
        elif address == 0xB45EC0:  # std::string::assign(dst, cstr), short SSO only
            dst = int(uc.reg_read(UC_ARM64_REG_X0))
            value = string_at(int(uc.reg_read(UC_ARM64_REG_X1)))
            if len(value) > 22:
                raise ValueError("Only short assigned strings are supported")
            uc.mem_write(dst, bytes([len(value) << 1]) + value + b"\0")
        elif address == 0xB45FD0:  # strlen
            uc.reg_write(UC_ARM64_REG_X0, len(string_at(int(uc.reg_read(UC_ARM64_REG_X0)))))
        elif address == 0xB45F50:  # memcmp; only equality is used by lookup
            left = int(uc.reg_read(UC_ARM64_REG_X0))
            right = int(uc.reg_read(UC_ARM64_REG_X1))
            size = int(uc.reg_read(UC_ARM64_REG_X2))
            uc.reg_write(UC_ARM64_REG_X0, int(bytes(uc.mem_read(left, size))
                                             != bytes(uc.mem_read(right, size))))
        else:
            return
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    vm.hook_add(UC_HOOK_CODE, helper)
    assert struct.unpack("<I", bytes(vm.mem_read(base + 0x6DAE10, 4)))[0] == 0x100185
    assert bytes(vm.mem_read(base + 0x6DADF8, 4)) == bytes.fromhex("ffffffff")

    stop_targets.update((_ID_FOUND, _ID_NEXT))
    for skill, last, destination in ((0x100185, 0, _ID_FOUND),
                                     (1234, 0, _ID_NEXT),
                                     (1234, 1234, _ID_FOUND)):
        vm.reg_write(UC_ARM64_REG_X19, skill)
        vm.reg_write(UC_ARM64_REG_X13, last)
        vm.emu_start(base + 0x8C39CC, base + 0xD00000, count=30)
        assert vm.reg_read(UC_ARM64_REG_PC) == base + destination
    stop_targets.clear()
    stop_targets.update((_COST_FOUND, _COST_MISSING))
    for skill, destination in ((0x100185, _COST_FOUND), (1234, _COST_MISSING)):
        vm.reg_write(UC_ARM64_REG_X11, skill)
        vm.reg_write(UC_ARM64_REG_X4, 3)
        vm.reg_write(UC_ARM64_REG_X8, 0x5555)
        vm.emu_start(base + 0x800E00, base + 0xD00000, count=30)
        assert vm.reg_read(UC_ARM64_REG_PC) == base + destination
        assert vm.reg_read(UC_ARM64_REG_X4) == 3
        if skill == 0x100185:
            assert vm.reg_read(UC_ARM64_REG_X9) == base + _CANDIDATE_COST
            assert vm.reg_read(UC_ARM64_REG_X8) == skill
        else:
            assert vm.reg_read(UC_ARM64_REG_X8) == 0x5555
    stop_targets.clear()
    stop_targets.add(0x800E28)
    for level in range(1, 10):
        vm.mem_write(base + _STACK + 0x1C0, struct.pack("<Q", 0x100185))
        vm.reg_write(UC_ARM64_REG_SP, base + _STACK)
        vm.reg_write(UC_ARM64_REG_X11, 0x100185)
        vm.reg_write(UC_ARM64_REG_X4, level)
        vm.reg_write(UC_ARM64_REG_X8, 0x5555)
        vm.emu_start(base + 0x800E00, base + 0xD00000, count=50)
        assert vm.reg_read(UC_ARM64_REG_PC) == base + 0x800E28
        assert vm.reg_read(UC_ARM64_REG_X5) == level * 10
    vm.mem_write(base + _STACK + 0x1C0, struct.pack("<Q", 0x100185))
    vm.reg_write(UC_ARM64_REG_SP, base + _STACK)
    vm.reg_write(UC_ARM64_REG_X11, 0x100185)
    vm.reg_write(UC_ARM64_REG_X4, 10)
    vm.reg_write(UC_ARM64_REG_X8, 0x5555)
    vm.emu_start(base + 0x800E00, base + 0xD00000, count=50)
    assert vm.reg_read(UC_ARM64_REG_PC) == base + 0x800E28
    assert vm.reg_read(UC_ARM64_REG_X5) == 0
    vm.mem_write(base + _STACK + 0x1C0, struct.pack("<Q", 1234))
    vm.reg_write(UC_ARM64_REG_SP, base + _STACK)
    vm.reg_write(UC_ARM64_REG_X11, 1234)
    vm.reg_write(UC_ARM64_REG_X4, 3)
    vm.reg_write(UC_ARM64_REG_X8, 0x5555)
    vm.emu_start(base + 0x800E00, base + 0xD00000, count=50)
    assert vm.reg_read(UC_ARM64_REG_PC) == base + 0x800E28
    assert vm.reg_read(UC_ARM64_REG_X5) == 8
    vm.mem_write(base + _STACK + 0x1C0, struct.pack("<Q", 1049717))
    vm.reg_write(UC_ARM64_REG_X11, 1049717)
    vm.reg_write(UC_ARM64_REG_X9, base + _DONOR_COST)
    vm.reg_write(UC_ARM64_REG_X4, 3)
    vm.emu_start(base + 0x800DE4, base + 0xD00000, count=50)
    assert vm.reg_read(UC_ARM64_REG_PC) == base + 0x800E28
    assert vm.reg_read(UC_ARM64_REG_X5) == 5
    stop_targets.clear()

    def lookup(code: bytes) -> int:
        vm.mem_write(base + _INPUT, code + b"\0")
        vm.reg_write(UC_ARM64_REG_X0, base + _INPUT)
        vm.reg_write(UC_ARM64_REG_SP, base + _STACK)
        vm.reg_write(UC_ARM64_REG_LR, base + _RETURN)
        vm.emu_start(base + _LOOKUP, base + _RETURN, count=50000)
        if vm.reg_read(UC_ARM64_REG_PC) != base + _RETURN:
            raise AssertionError("Lookup did not return")
        return int(vm.reg_read(UC_ARM64_REG_X0))

    assert lookup(b"00130184") == base + 0xBA19C0
    assert lookup(b"00130187") == 0
    assert lookup(b"00130185") == base + _SCRATCH + 8
    for index in (0, 1, 100, 278, 557):
        address = base + 0xBA0610 + 56 * index
        source_ptr = struct.unpack("<Q", bytes(vm.mem_read(address, 8)))[0]
        assert lookup(string_at(source_ptr)) == address
    assert lookup(b"00130184") == base + 0xBA19C0
    assert lookup(b"00130185") == base + _SCRATCH + 8

    def identity(code: bytes) -> bytes:
        vm.mem_write(base + _INPUT, bytes([len(code) << 1]) + code + b"\0")
        vm.mem_write(base + _SRET, bytes(24))
        vm.reg_write(UC_ARM64_REG_X0, base + _INPUT)
        vm.reg_write(UC_ARM64_REG_X8, base + _SRET)
        vm.reg_write(UC_ARM64_REG_SP, base + _STACK)
        vm.reg_write(UC_ARM64_REG_LR, base + _RETURN)
        vm.emu_start(base + 0xA3603C, base + _RETURN, count=200000)
        if vm.reg_read(UC_ARM64_REG_PC) != base + _RETURN:
            raise AssertionError("Identity lookup did not return")
        length = bytes(vm.mem_read(base + _SRET, 1))[0] >> 1
        return bytes(vm.mem_read(base + _SRET + 1, length))

    assert identity(b"00130186") == b"00130181"
    assert identity(b"00130185") == b"00130181"
    assert identity(b"00130181") == b"00130181"
    assert identity(b"00110386") == b"00110381"
    assert identity(b"00130187") == b"00130187"

    reg_map = {"x20": UC_ARM64_REG_X20, "x21": UC_ARM64_REG_X21,
               "x22": UC_ARM64_REG_X22, "x23": UC_ARM64_REG_X23,
               "x26": UC_ARM64_REG_X26, "x28": UC_ARM64_REG_X28}
    for _name, site, _orig, len_reg, ptr_reg, inc_reg, loop_cont, hit_addr, miss_addr in BACKWALK_SPECS:
        stop_targets.clear()
        stop_targets.update((loop_cont, hit_addr, miss_addr))
        for code, inc_val, expected_pc in (
            (b"00130186", (-0x38) & 0xFFFFFFFFFFFFFFFF, hit_addr),
            (b"00130187", (-0x38) & 0xFFFFFFFFFFFFFFFF, miss_addr),
            (b"00130186", (-0x70) & 0xFFFFFFFFFFFFFFFF, loop_cont),
        ):
            vm.mem_write(base + _INPUT, code + b"\0")
            vm.reg_write(reg_map[len_reg], len(code))
            vm.reg_write(reg_map[ptr_reg], base + _INPUT)
            vm.reg_write(reg_map[inc_reg], inc_val)
            vm.reg_write(UC_ARM64_REG_X1, 0x5555)
            vm.emu_start(base + site, base + 0xD00000, count=30)
            assert vm.reg_read(UC_ARM64_REG_PC) == base + expected_pc
            if expected_pc == hit_addr:
                assert vm.reg_read(UC_ARM64_REG_X1) == base + _SOURCE_RODATA
    stop_targets.clear()

    print(f"Evolution, backwalk, skill recognition and cost branches passed at {base:#x}; "
          "no binary changed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    args = parser.parse_args()
    exercise(args.server)
    exercise(args.server, base=0x4000000000)
