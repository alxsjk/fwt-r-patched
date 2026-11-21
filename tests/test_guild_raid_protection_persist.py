"""Tests for Feature 07.09: Absolute Protection persists for all hits (07.09)."""
from __future__ import annotations

import struct

import pytest

from core.core_patches import PatchOptions, apply_all_patches, validate_cave_layout
from core.elf_mapping import read_load_segments, translate_vaddr
from core.guild_raid_protection_persist import (
    ARM64_NOP,
    CAVE_BYTES,
    CAVE_VADDR,
    CLIENT_EXPECTED_WORD,
    CLIENT_REPLACEMENT_WORD,
    CLIENT_RVA,
    EXPIRY_ID_EXPECTED,
    EXPIRY_ID_RVA,
    EXPIRY_SKIP_EXPECTED,
    EXPIRY_SKIP_RVA,
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
        UC_ARM64_REG_X9,
        UC_ARM64_REG_X10,
        UC_ARM64_REG_X11,
        UC_ARM64_REG_X12,
        UC_ARM64_REG_X13,
        UC_ARM64_REG_X14,
        UC_ARM64_REG_X15,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X20,
    )

    so_buf = bytearray(reference_buffers[0])
    segments = read_load_segments(so_buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    apply_guild_raid_protection_persist(so_buf, offset)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
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
        (IL2CPP_BASE + (EXPIRY_SKIP_RVA & ~0xFFF), 0x4000),
    ):
        uc.mem_map(addr, size)

    uc.mem_write(LATE_HOOK_SITE, bytes(so_buf[offset(LATE_HOOK_SITE):offset(LATE_HOOK_SITE) + 4]))
    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    uc.mem_write(0x00BE3798, struct.pack("<Q", IL2CPP_BASE))
    targets = (
        (CLIENT_RVA, CLIENT_EXPECTED_WORD, CLIENT_REPLACEMENT_WORD),
        (EXPIRY_SKIP_RVA, EXPIRY_SKIP_EXPECTED, ARM64_NOP),
        (EXPIRY_ID_RVA, EXPIRY_ID_EXPECTED, ARM64_NOP),
    )

    def reset_client_words() -> None:
        for rva, expected_word, _ in targets:
            uc.mem_write(IL2CPP_BASE + rva, struct.pack("<I", expected_word))

    reset_client_words()
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
    expected_by_rva = {rva: (exp, rep) for rva, exp, rep in targets}

    def clobber_scratch(engine: Uc) -> None:
        for idx, reg in enumerate((
            UC_ARM64_REG_X9,
            UC_ARM64_REG_X10,
            UC_ARM64_REG_X11,
            UC_ARM64_REG_X12,
            UC_ARM64_REG_X13,
            UC_ARM64_REG_X14,
            UC_ARM64_REG_X15,
        )):
            engine.reg_write(reg, 0xDEAD0000 + idx)

    def hook_code(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address == 0x00AB575C:
            base = engine.reg_read(UC_ARM64_REG_X0)
            rva = engine.reg_read(UC_ARM64_REG_W1)
            expected_ptr = engine.reg_read(UC_ARM64_REG_X2)
            patch_ptr = engine.reg_read(UC_ARM64_REG_X3)
            count = engine.reg_read(UC_ARM64_REG_W4)
            name_ptr = engine.reg_read(UC_ARM64_REG_X5)
            assert base == IL2CPP_BASE
            assert rva in expected_by_rva
            exp_word, rep_word = expected_by_rva[rva]
            assert count == 1
            assert struct.unpack("<I", bytes(engine.mem_read(expected_ptr, 4)))[0] == exp_word
            assert struct.unpack("<I", bytes(engine.mem_read(patch_ptr, 4)))[0] == rep_word
            assert bytes(engine.mem_read(name_ptr, 18)) == b"ap_shield_persist\x00"
            clobber_scratch(engine)
            if state["helper_mode"] == "write":
                engine.mem_write(base + rva, bytes(engine.mem_read(patch_ptr, 4)))
                engine.reg_write(UC_ARM64_REG_W0, 1)
                events.append("helper_installed")
            else:
                engine.reg_write(UC_ARM64_REG_W0, 0)
                events.append("helper_refused")
        elif address == 0x00B464B0:
            clobber_scratch(engine)
            events.append("log")
        elif address == 0x00B476C0:
            clobber_scratch(engine)
            engine.reg_write(UC_ARM64_REG_X0, 0x4000)
            events.append("sysconf")
        elif address == 0x00B476D0:
            prot = engine.reg_read(UC_ARM64_REG_X2)
            assert engine.reg_read(UC_ARM64_REG_X1) == 0x4000
            assert (engine.reg_read(UC_ARM64_REG_X0) & 0x3FFF) == 0
            clobber_scratch(engine)
            events.append(f"mprotect_w2_{prot}")
            engine.reg_write(UC_ARM64_REG_W0, 0)
        elif address == 0x00B41794:
            clobber_scratch(engine)
            events.append("cache_flush")
        elif address == RETURN_SITE:
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    def run() -> None:
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        for reg, value in sentinels.items():
            uc.reg_write(reg, value)
        uc.emu_start(LATE_HOOK_SITE, RETURN_SITE)

    def client_word(rva: int) -> int:
        raw = bytes(uc.mem_read(IL2CPP_BASE + rva, 4))
        return int(struct.unpack("<I", raw)[0])

    def assert_preserved() -> None:
        assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
        for reg, value in sentinels.items():
            assert uc.reg_read(reg) == value
        assert uc.reg_read(UC_ARM64_REG_W8) == 1

    # 1. Helper cooperates across all 3 sites, diagnostic pre/post logs, no fallback needed.
    events.clear()
    state["helper_mode"] = "write"
    run()
    assert events == ["log", "helper_installed", "log"] * 3
    for rva, _, rep in targets:
        assert client_word(rva) == rep
    assert_preserved()

    # 2. Helper refuses: fallback applies all 3 patches via sysconf + mprotect RWX + flush + RX.
    events.clear()
    state["helper_mode"] = "refuse"
    reset_client_words()
    run()
    assert events == [
        "log",
        "helper_refused",
        "sysconf",
        "mprotect_w2_7",
        "cache_flush",
        "mprotect_w2_5",
        "log",
    ] * 3
    for rva, _, rep in targets:
        assert client_word(rva) == rep
    assert_preserved()

    # 3. Fail-safe: without a cached il2cpp base the cave logs the skip and leaves words stock.
    events.clear()
    uc.mem_write(0x00BE3798, struct.pack("<Q", 0))
    reset_client_words()
    run()
    assert events == ["log"]
    for rva, exp, _ in targets:
        assert client_word(rva) == exp
    assert_preserved()
