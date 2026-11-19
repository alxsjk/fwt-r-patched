"""Emulate an uninstalled Alex evolution lookup prototype on synthetic memory.

This laboratory script does not read, modify, or emit a game binary.  Its
addresses model one candidate layout, not verified safe patch locations.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_PC,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
)

from core.core_patches import REFERENCE_SO_SHA256

_CODE = 0xB34D44
_DONE = 0x9029BC
_DONOR = 0xBA6DC0
_SCRATCH = 0xBE6268
_INPUT = 0xC00000
_SOURCE = int.from_bytes(b"00130185", "little")
_TARGET = int.from_bytes(b"00130186", "little")
_SOURCE_RODATA = 0x3B2C08
_BACKWALK_CAVE = 0xB34E64
_BACKWALK_STRIDE = 64

# (name, hook_site, original_hex, len_reg, ptr_reg, inc_reg, loop_cont, hit_addr, miss_addr)
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
    """Assemble a candidate only; output is never installed into an ELF."""
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


def _reference_donor_tail(path: Path) -> bytes:
    if hashlib.sha256(path.read_bytes()).hexdigest() != REFERENCE_SO_SHA256:
        raise ValueError("Server is not the supported original reference SO")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                    and int(s["p_vaddr"]) <= _DONOR
                    and int(s["p_vaddr"]) + int(s["p_filesz"]) >= _DONOR + 56]
        if len(segments) != 1:
            raise ValueError("Donor rule is not uniquely mapped")
        segment = segments[0]
        stream.seek(int(segment["p_offset"]) + _DONOR + 16 - int(segment["p_vaddr"]))
        tail = stream.read(40)
    if len(tail) != 40 or struct.unpack_from("<II", tail) != (5, 70):
        raise ValueError("Unexpected reference donor rule")
    return tail


def exercise(server: Path | None = None) -> None:
    """Check match, non-match, durable strings and reuse with synthetic data."""
    code = make_stub()
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for start, size in ((0x900000, 0x10000), (0xB30000, 0x10000),
                        (0xBA6000, 0x1000), (0xBE6000, 0x1000),
                        (_INPUT, 0x1000)):
        vm.mem_map(start, size)
    vm.mem_write(_CODE, code)
    donor_tail = _reference_donor_tail(server) if server else bytes(range(40))
    vm.mem_write(_DONOR + 16, donor_tail)

    reached_return = False

    def stop(uc: Uc, address: int, _size: int, _user: object) -> None:
        nonlocal reached_return
        if address == _DONE:
            reached_return = True
            uc.emu_stop()

    vm.hook_add(UC_HOOK_CODE, stop)

    def run(value: bytes, length: int) -> int:
        nonlocal reached_return
        reached_return = False
        vm.mem_write(_INPUT, value.ljust(8, b"\0"))
        vm.reg_write(UC_ARM64_REG_X21, length)
        vm.reg_write(UC_ARM64_REG_X22, _INPUT)
        vm.reg_write(UC_ARM64_REG_X20, 0xDEADBEEF)
        vm.reg_write(UC_ARM64_REG_X0, 0x12345678)
        vm.emu_start(_CODE, _DONE + 4, count=1000)
        if not reached_return:
            raise AssertionError("Prototype did not reach its return address")
        if vm.reg_read(UC_ARM64_REG_X0) != 0x12345678:
            raise AssertionError("Prototype corrupted an unrelated register")
        return int(vm.reg_read(UC_ARM64_REG_X20))

    assert run(b"00130184", 8) == 0
    assert run(b"00130185", 7) == 0
    rule = run(b"00130185", 8)
    assert rule == _SCRATCH + 8
    source_ptr, target_ptr = struct.unpack("<QQ", bytes(vm.mem_read(rule, 16)))
    assert bytes(vm.mem_read(source_ptr, 9)) == b"00130185\0"
    assert bytes(vm.mem_read(target_ptr, 9)) == b"00130186\0"
    assert bytes(vm.mem_read(rule + 16, 40)) == donor_tail
    assert run(b"00130185", 8) == rule
    assert run(b"00130186", 8) == 0
    # Interleave two independent CPU contexts one instruction at a time, both
    # accessing the same synthetic data. This is not a substitute for real
    # Android thread scheduling or loader validation.
    vm.mem_write(_SCRATCH, bytes(96))
    vm.mem_write(_INPUT, b"00130185")
    contexts = []
    for _ in range(2):
        vm.reg_write(UC_ARM64_REG_PC, _CODE)
        vm.reg_write(UC_ARM64_REG_X21, 8)
        vm.reg_write(UC_ARM64_REG_X22, _INPUT)
        contexts.append(vm.context_save())
    for _ in range(2000):
        if all(context.reg_read(UC_ARM64_REG_PC) == _DONE for context in contexts):
            break
        for index, context in enumerate(contexts):
            vm.context_restore(context)
            pc = int(vm.reg_read(UC_ARM64_REG_PC))
            if pc != _DONE:
                vm.emu_start(pc, _DONE, count=1)
                contexts[index] = vm.context_save()
    else:
        raise AssertionError("Interleaved prototype did not finish")
    assert all(context.reg_read(UC_ARM64_REG_X20) == rule for context in contexts)
    assert bytes(vm.mem_read(_SCRATCH + 64, 9)) == b"00130185\0"
    assert bytes(vm.mem_read(_SCRATCH + 80, 9)) == b"00130186\0"
    print(f"Synthetic lookup prototype passed; {len(code)} code bytes. No game files changed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, help="Optional original server SO to read")
    exercise(parser.parse_args().server)
