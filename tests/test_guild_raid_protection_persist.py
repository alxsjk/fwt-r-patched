"""Tests for Feature 07.09: Absolute Protection persists for all hits (07.09)."""
from __future__ import annotations

import struct

import pytest

from core.core_patches import PatchOptions, apply_all_patches, validate_cave_layout
from core.elf_mapping import read_load_segments, translate_vaddr
from core.guild_raid_protection_persist import (
    CAVE_BYTES,
    CAVE_VADDR,
    CLIENT_EXPECTED_WORD,
    CLIENT_REPLACEMENT_WORD,
    CLIENT_RVA,
    GET_MULTI_TARGET_VADDR,
    LATE_HOOK_SITE,
    REMOVE_MULTI_TARGET_VADDR,
    apply_guild_raid_protection_persist,
)
from core.patch_inspector import inspect_native_so


def test_generated_payload_matches_frozen_bytes() -> None:
    pytest.importorskip("keystone")
    from tools.gen_guild_raid_protection_persist import (
        expected_client_word,
        generate,
        replacement_client_word,
    )

    assert generate() == CAVE_BYTES
    assert expected_client_word() == CLIENT_EXPECTED_WORD
    assert replacement_client_word() == CLIENT_REPLACEMENT_WORD


def test_client_words_decode_to_expected_targets() -> None:
    pytest.importorskip("capstone")
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    (expected,) = md.disasm(struct.pack("<I", CLIENT_EXPECTED_WORD), CLIENT_RVA)
    assert expected.mnemonic == "bl"
    assert int(expected.op_str[1:], 16) == REMOVE_MULTI_TARGET_VADDR
    (replacement,) = md.disasm(struct.pack("<I", CLIENT_REPLACEMENT_WORD), CLIENT_RVA)
    assert replacement.mnemonic == "bl"
    assert int(replacement.op_str[1:], 16) == GET_MULTI_TARGET_VADDR


def test_patch_and_inspect_native_so_and_idempotence(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    validate_cave_layout()
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_protection_persist=True),
    )
    assert result.counts["guild_raid_protection_persist"] == 2
    reports = inspect_native_so(result.so_bytes)
    assert reports["guild_raid_protection_persist"].active

    again = apply_all_patches(
        result.so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_protection_persist=True, allow_unknown=True),
    )
    assert again.counts["guild_raid_protection_persist"] == 0
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
        apply_guild_raid_protection_persist(buf, offset)
    assert bytes(buf) == before


def test_surgical_diff_only_hook_and_cave(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    so_bytes, dex_bytes = reference_buffers
    base = apply_all_patches(so_bytes, dex_bytes, PatchOptions())
    patched = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_protection_persist=True),
    )
    assert patched.so_bytes != base.so_bytes
    diffs = {
        idx
        for idx, (a, b) in enumerate(
            zip(bytes(base.so_bytes), bytes(patched.so_bytes), strict=True)
        )
        if a != b
    }
    segments = read_load_segments(so_bytes)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    hook_range = set(range(offset(LATE_HOOK_SITE), offset(LATE_HOOK_SITE) + 4))
    cave_range = set(range(offset(CAVE_VADDR), offset(CAVE_VADDR) + len(CAVE_BYTES)))
    # The cave is written over original code, so positions where the payload
    # coincides with the stock bytes do not appear in a content diff; assert
    # instead that no byte outside the two ranges changed and that both
    # ranges carry the exact expected content.
    assert diffs <= hook_range | cave_range
    assert hook_range <= diffs
    assert patched.so_bytes[offset(CAVE_VADDR):offset(CAVE_VADDR) + len(CAVE_BYTES)] == (
        CAVE_BYTES
    )
    assert base.so_bytes[offset(CAVE_VADDR):offset(CAVE_VADDR) + len(CAVE_BYTES)] == (
        bytes(so_bytes[offset(CAVE_VADDR):offset(CAVE_VADDR) + len(CAVE_BYTES)])
    )
    assert base.so_bytes[offset(LATE_HOOK_SITE):offset(LATE_HOOK_SITE) + 4] == (
        bytes(so_bytes[offset(LATE_HOOK_SITE):offset(LATE_HOOK_SITE) + 4])
    )


def test_unicorn_emulation_installer(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W0,
        UC_ARM64_REG_W1,
        UC_ARM64_REG_W4,
        UC_ARM64_REG_W8,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X20,
    )

    so_buf = bytearray(reference_buffers[0])
    segments = read_load_segments(so_buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    apply_guild_raid_protection_persist(so_buf, offset)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    # Hook/cave/cache/PLT pages inside the server image, stack, and a fake
    # il2cpp mapping for the client target site. The cave returns to the
    # instruction after the hook (`LATE_HOOK_SITE + 4`), like the real flow.
    IL2CPP_BASE = 0x40000000
    STACK_TOP = 0x08008000
    RETURN_SITE = LATE_HOOK_SITE + 4

    for addr, size in (
        (0x00AB3000, 0x10000),
        (0x00B2A000, 0x4000),
        (0x00B41000, 0x8000),  # PLT: cache flush / log / sysconf / mprotect
        (0x00BE3000, 0x2000),
        (0x08000000, 0x10000),
        (IL2CPP_BASE + (CLIENT_RVA & ~0xFFF), 0x4000),
    ):
        uc.mem_map(addr, size)

    uc.mem_write(LATE_HOOK_SITE, bytes(so_buf[offset(LATE_HOOK_SITE):offset(LATE_HOOK_SITE) + 4]))
    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    uc.mem_write(0x00BE3798, struct.pack("<Q", IL2CPP_BASE))
    uc.mem_write(
        IL2CPP_BASE + CLIENT_RVA,
        struct.pack("<I", CLIENT_EXPECTED_WORD),
    )
    ret_insn = struct.pack("<I", 0xD65F03C0)
    for stub in (0x00AB575C, 0x00B464B0, 0x00B476C0, 0x00B476D0, 0x00B41794):
        uc.mem_write(stub, ret_insn)

    events: list[str] = []
    state: dict[str, object] = {"helper_mode": "write"}
    sentinels = {
        UC_ARM64_REG_X0: 0x1122334455667788,
        UC_ARM64_REG_X1: 0x99AABBCCDDEEFF00,
        UC_ARM64_REG_X2: 0xA1A1A1A1A1A1A1A1,
        UC_ARM64_REG_X3: 0xB2B2B2B2B2B2B2B2,
        UC_ARM64_REG_X4: 0xC3C3C3C3C3C3C3C3,
        UC_ARM64_REG_X5: 0xD4D4D4D4D4D4D4D4,
        UC_ARM64_REG_X19: 0xE5E5E5E5E5E5E5E5,
        UC_ARM64_REG_X20: 0xF6F6F6F6F6F6F6F6,
    }

    def hook_code(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address == 0x00AB575C:
            base = engine.reg_read(UC_ARM64_REG_X0)
            rva = engine.reg_read(UC_ARM64_REG_W1)
            expected_ptr = engine.reg_read(UC_ARM64_REG_X2)
            patch_ptr = engine.reg_read(UC_ARM64_REG_X3)
            count = engine.reg_read(UC_ARM64_REG_W4)
            name_ptr = engine.reg_read(UC_ARM64_REG_X5)
            assert base == IL2CPP_BASE
            assert rva == CLIENT_RVA
            assert count == 1
            assert struct.unpack("<I", bytes(engine.mem_read(expected_ptr, 4)))[0] == (
                CLIENT_EXPECTED_WORD
            )
            assert struct.unpack("<I", bytes(engine.mem_read(patch_ptr, 4)))[0] == (
                CLIENT_REPLACEMENT_WORD
            )
            assert bytes(engine.mem_read(name_ptr, 18)) == b"ap_shield_persist\x00"
            if state["helper_mode"] == "write":
                engine.mem_write(base + rva, bytes(engine.mem_read(patch_ptr, 4)))
                engine.reg_write(UC_ARM64_REG_W0, 1)
                events.append("helper_installed")
            else:
                engine.reg_write(UC_ARM64_REG_W0, 0)
                events.append("helper_refused")
        elif address == 0x00B464B0:
            events.append("log")
        elif address == 0x00B476C0:
            engine.reg_write(UC_ARM64_REG_X0, 0x4000)
            events.append("sysconf")
        elif address == 0x00B476D0:
            events.append(f"mprotect_w2_{engine.reg_read(UC_ARM64_REG_X2)}")
            engine.reg_write(UC_ARM64_REG_W0, 0)
        elif address == 0x00B41794:
            events.append("cache_flush")
        elif address == RETURN_SITE:
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    def run() -> None:
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        for reg, value in sentinels.items():
            uc.reg_write(reg, value)
        uc.emu_start(LATE_HOOK_SITE, RETURN_SITE)

    def client_word() -> int:
        raw = bytes(uc.mem_read(IL2CPP_BASE + CLIENT_RVA, 4))
        return int(struct.unpack("<I", raw)[0])

    def assert_preserved() -> None:
        assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
        for reg, value in sentinels.items():
            assert uc.reg_read(reg) == value
        assert uc.reg_read(UC_ARM64_REG_W8) == 1

    # 1. Helper cooperates: single helper call, diagnostic pre/post logs, no
    # raw fallback needed, registers preserved.
    events.clear()
    state["helper_mode"] = "write"
    run()
    assert events == ["log", "helper_installed", "log"]
    assert client_word() == CLIENT_REPLACEMENT_WORD
    assert_preserved()

    # 2. Helper refuses (the observed on-device behavior): the cave detects
    # the unchanged stock word and applies the patch itself via
    # sysconf + mprotect RWX + write + icache flush + mprotect RX.
    events.clear()
    state["helper_mode"] = "refuse"
    uc.mem_write(IL2CPP_BASE + CLIENT_RVA, struct.pack("<I", CLIENT_EXPECTED_WORD))
    run()
    assert events == [
        "log",
        "helper_refused",
        "sysconf",
        "mprotect_w2_7",
        "cache_flush",
        "mprotect_w2_5",
        "log",
    ]
    assert client_word() == CLIENT_REPLACEMENT_WORD
    assert_preserved()

    # 3. Fail-safe: without a cached il2cpp base the cave logs the skip and
    # still replays the displaced instruction and returns cleanly.
    events.clear()
    uc.mem_write(0x00BE3798, struct.pack("<Q", 0))
    uc.mem_write(IL2CPP_BASE + CLIENT_RVA, struct.pack("<I", CLIENT_EXPECTED_WORD))
    run()
    assert events == ["log"]
    assert client_word() == CLIENT_EXPECTED_WORD
    assert_preserved()
