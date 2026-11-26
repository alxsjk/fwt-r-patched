"""Tests for Feature 08.07 (KB-001): ConvertHexU32 non-hex inventory sync guard."""
from __future__ import annotations

import struct

import pytest

from core.convert_hex_guard import (
    CAVE_BYTES,
    CAVE_VADDR,
    LATE_HOOK_SITE,
    apply_convert_hex_guard,
)
from core.core_patches import PatchOptions, apply_all_patches, validate_cave_layout
from core.elf_mapping import read_load_segments, translate_vaddr
from core.patch_inspector import inspect_native_so


def test_generated_payload_matches_frozen_bytes() -> None:
    pytest.importorskip("keystone")
    from tools.gen_convert_hex_guard import generate

    assert generate() == CAVE_BYTES


def test_patch_and_inspect_native_so_and_idempotence(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    validate_cave_layout()
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(),
    )
    assert result.counts["convert_hex_guard"] == 2
    reports = inspect_native_so(result.so_bytes)
    assert reports["convert_hex_guard"].active

    again = apply_all_patches(
        result.so_bytes,
        dex_bytes,
        PatchOptions(allow_unknown=True),
    )
    assert again.counts["convert_hex_guard"] == 0
    assert again.so_bytes == result.so_bytes


@pytest.mark.parametrize("address", [CAVE_VADDR, LATE_HOOK_SITE])
def test_invalid_bytes_rejected_before_mutation(
    reference_buffers: tuple[bytes, bytes],
    address: int,
) -> None:
    buf = bytearray(reference_buffers[0])
    segments = read_load_segments(buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    buf[offset(address)] ^= 1
    before = bytes(buf)
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_convert_hex_guard(buf, offset)
    assert bytes(buf) == before


def test_unicorn_emulation_installer_and_hex_guard(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W0,
        UC_ARM64_REG_W1,
        UC_ARM64_REG_W3,
        UC_ARM64_REG_W4,
        UC_ARM64_REG_W20,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X19,
    )

    so_buf = bytearray(reference_buffers[0])
    segments = read_load_segments(so_buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    apply_convert_hex_guard(so_buf, offset)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    IL2CPP_BASE = 0x40000000
    STACK_TOP = 0x08008000
    STOP_ADDR = 0x09000000
    STR_OBJ = 0x13570000

    for addr, size in (
        (0x00AB3000, 0x10000),
        (0x00B2B000, 0x4000),
        (0x00BE3000, 0x2000),
        (0x08000000, 0x10000),
        (STOP_ADDR, 0x1000),
        (STR_OBJ, 0x1000),
        (IL2CPP_BASE + 0x011A9000, 0x4000),
        (IL2CPP_BASE + 0x01811000, 0x4000),
    ):
        uc.mem_map(addr, size)

    uc.mem_write(LATE_HOOK_SITE, bytes(so_buf[offset(LATE_HOOK_SITE):offset(LATE_HOOK_SITE) + 4]))
    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    uc.mem_write(0x00BE3798, struct.pack("<Q", IL2CPP_BASE))
    expected_words = (0x321C03E1, 0xAA1303E0, 0xAA1F03E2, 0x97E66033)
    uc.mem_write(IL2CPP_BASE + 0x0181178C, b"".join(struct.pack("<I", w) for w in expected_words))
    ret_insn = struct.pack("<I", 0xD65F03C0)
    for rva in (0x011A9864, 0x0181179C, 0x018117A0):
        uc.mem_write(IL2CPP_BASE + rva, ret_insn)
    uc.mem_write(0x00AB575C, ret_insn)
    uc.mem_write(0x00AB3374, struct.pack("<I", 0xD503201F))

    events: list[tuple[str, int]] = []
    state = {"to_int32_calls": 0, "to_int32_ret": 0}

    def hook_code(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address == 0x00AB575C:
            base = engine.reg_read(UC_ARM64_REG_X0)
            rva = engine.reg_read(UC_ARM64_REG_W1)
            exp_ptr = engine.reg_read(UC_ARM64_REG_X2)
            patch_ptr = engine.reg_read(UC_ARM64_REG_X3)
            count = engine.reg_read(UC_ARM64_REG_W4)
            name_ptr = engine.reg_read(UC_ARM64_REG_X5)
            assert base == IL2CPP_BASE
            assert rva == 0x0181178C
            assert count == 4
            assert engine.mem_read(exp_ptr, 16) == engine.mem_read(base + rva, 16)
            assert bytes(engine.mem_read(name_ptr, 17)) == b"convert_hex_guard"
            engine.mem_write(base + rva, bytes(engine.mem_read(patch_ptr, 16)))
            engine.reg_write(UC_ARM64_REG_W0, 1)
            events.append(("helper_installed", rva))
        elif address == IL2CPP_BASE + 0x011A9864:
            state["to_int32_calls"] += 1
            assert engine.reg_read(UC_ARM64_REG_X0) == STR_OBJ
            assert engine.reg_read(UC_ARM64_REG_W1) == 16
            assert engine.reg_read(UC_ARM64_REG_X2) == 0
            engine.reg_write(UC_ARM64_REG_W0, state["to_int32_ret"])
            events.append(("to_int32", state["to_int32_ret"]))
        elif address == IL2CPP_BASE + 0x0181179C:
            events.append(("ret_ok", engine.reg_read(UC_ARM64_REG_W0)))
            engine.emu_stop()
        elif address == IL2CPP_BASE + 0x018117A0:
            events.append(("ret_neg1", engine.reg_read(UC_ARM64_REG_W20)))
            engine.emu_stop()
        elif address == 0x00AB3374:
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    # 1. Run installer at 0xAB3370; verify x0, x1, x2 preserved and w3 = w20.
    uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM64_REG_X0, 4)
    uc.reg_write(UC_ARM64_REG_X1, 0x11112222)
    uc.reg_write(UC_ARM64_REG_X2, 0x33334444)
    uc.reg_write(UC_ARM64_REG_W20, 77)
    uc.emu_start(LATE_HOOK_SITE, 0x00AB3374 + 4)
    assert events == [("helper_installed", 0x0181178C)]
    assert uc.reg_read(UC_ARM64_REG_X0) == 4
    assert uc.reg_read(UC_ARM64_REG_X1) == 0x11112222
    assert uc.reg_read(UC_ARM64_REG_X2) == 0x33334444
    assert uc.reg_read(UC_ARM64_REG_W3) == 77
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP

    def run_hex(text: str) -> list[tuple[str, int]]:
        events.clear()
        state["to_int32_calls"] = 0
        encoded = text.encode("utf-16-le")
        uc.mem_write(STR_OBJ + 0x10, struct.pack("<I", len(text)))
        uc.mem_write(STR_OBJ + 0x14, encoded)
        if len(text) <= 8 and all(c in "0123456789abcdefABCDEF" for c in text) and text:
            state["to_int32_ret"] = int(text, 16)
        else:
            state["to_int32_ret"] = 0
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM64_REG_X19, STR_OBJ)
        uc.reg_write(UC_ARM64_REG_W20, 0)
        uc.reg_write(UC_ARM64_REG_LR, STOP_ADDR)
        uc.emu_start(IL2CPP_BASE + 0x0181178C, STOP_ADDR)
        assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
        return list(events)

    assert run_hex("2040031") == [("to_int32", 0x2040031), ("ret_ok", 0x2040031)]
    assert run_hex("C") == [("to_int32", 0xC), ("ret_ok", 0xC)]
    assert run_hex("aF09") == [("to_int32", 0xAF09), ("ret_ok", 0xAF09)]

    for bad in ("13000K", "13000Y", "", "123456789", "2040/31"):
        assert run_hex(bad) == [("ret_neg1", 0xFFFFFFFF)]
        assert state["to_int32_calls"] == 0
