"""Tests for Feature 07.10: Guild Raid lord-skill per-turn auto-cast gate."""
from __future__ import annotations

import struct

import pytest

from core.core_patches import PatchOptions, apply_all_patches, validate_cave_layout
from core.elf_mapping import read_load_segments, translate_vaddr
from core.guild_raid_skill_turn_gate import (
    CAVE_BYTES,
    CAVE_VADDR,
    LATE_HOOK_SITE,
    STATE_SLOT_VADDR,
    apply_guild_raid_skill_turn_gate,
)
from core.patch_inspector import inspect_native_so

SKILL_SHELLING = 0x20000001
SKILL_FIRE_SUPPORT = 0x20000002
SKILL_ABS_PROTECTION = 0x20000003
SKILL_COMBAT_SUPPORT = 0x20000004

FAKE_INSTANCE_A = 0xF00D0000
FAKE_INSTANCE_B = 0xBEEF0000


def test_generated_payload_matches_frozen_bytes() -> None:
    pytest.importorskip("keystone")
    from tools.gen_guild_raid_skill_turn_gate import EXPECTED_WORDS, RVA_GATE_SITE, generate

    assert generate() == CAVE_BYTES
    assert RVA_GATE_SITE == 0x018E6FF0
    assert EXPECTED_WORDS == (0x2A1403E0, 0xAA1F03E1, 0x97FC1B68, 0x370019C0)


def test_expected_words_decode_to_displaced_block() -> None:
    pytest.importorskip("capstone")
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

    from tools.gen_guild_raid_skill_turn_gate import (
        EXPECTED_WORDS,
        RVA_GATE_SITE,
        RVA_HOLD,
        RVA_STOCK_GATE_CALL,
    )

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    words = [struct.pack("<I", w) for w in EXPECTED_WORDS]
    (insn,) = md.disasm(words[0], RVA_GATE_SITE)
    assert insn.mnemonic == "mov"
    assert insn.op_str == "w0, w20"
    (insn,) = md.disasm(words[1], RVA_GATE_SITE + 4)
    assert insn.mnemonic == "mov"
    assert insn.op_str == "x1, xzr"
    (insn,) = md.disasm(words[2], RVA_GATE_SITE + 8)
    assert insn.mnemonic == "bl"
    assert int(insn.op_str[1:], 16) == RVA_STOCK_GATE_CALL
    (insn,) = md.disasm(words[3], RVA_GATE_SITE + 12)
    assert insn.mnemonic == "tbnz"
    assert int(insn.op_str.split(", ")[-1][1:], 16) == RVA_HOLD


def test_patch_and_inspect_native_so_and_idempotence(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    validate_cave_layout()
    so_bytes, dex_bytes = reference_buffers
    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_skill_turn_gate=True),
    )
    assert result.counts["guild_raid_skill_turn_gate"] == 2
    reports = inspect_native_so(result.so_bytes)
    assert reports["guild_raid_skill_turn_gate"].active

    again = apply_all_patches(
        result.so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_skill_turn_gate=True, allow_unknown=True),
    )
    assert again.counts["guild_raid_skill_turn_gate"] == 0
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
        apply_guild_raid_skill_turn_gate(buf, offset)
    assert bytes(buf) == before


def test_surgical_diff_only_hook_and_cave(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    so_bytes, dex_bytes = reference_buffers
    base = apply_all_patches(so_bytes, dex_bytes, PatchOptions())
    patched = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(guild_raid_skill_turn_gate=True),
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
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X20,
    )

    from tools.gen_guild_raid_skill_turn_gate import (
        EXPECTED_WORDS,
        RVA_GATE_SITE,
    )

    so_buf = bytearray(reference_buffers[0])
    segments = read_load_segments(so_buf)
    offset = lambda addr: translate_vaddr(segments, addr)  # noqa: E731
    apply_guild_raid_skill_turn_gate(so_buf, offset)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    IL2CPP_BASE = 0x40000000
    STACK_TOP = 0x08008000
    RETURN_SITE = LATE_HOOK_SITE + 4

    for addr, size in (
        (0x00AB3000, 0x10000),
        (0x00B30000, 0x2000),
        (0x00BE3000, 0x2000),
        (0x08000000, 0x10000),
        (IL2CPP_BASE + (RVA_GATE_SITE & ~0xFFF), 0x2000),
    ):
        uc.mem_map(addr, size)

    uc.mem_write(LATE_HOOK_SITE, bytes(so_buf[offset(LATE_HOOK_SITE):offset(LATE_HOOK_SITE) + 4]))
    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    uc.mem_write(0x00BE3798, struct.pack("<Q", IL2CPP_BASE))
    for i, word in enumerate(EXPECTED_WORDS):
        uc.mem_write(IL2CPP_BASE + RVA_GATE_SITE + 4 * i, struct.pack("<I", word))
    ret_insn = struct.pack("<I", 0xD65F03C0)
    uc.mem_write(0x00AB575C, ret_insn)

    handler_addr = CAVE_VADDR + 0x7C
    stub = struct.pack("<IIQ", 0x58000050, 0xD61F0200, handler_addr)

    events: list[str] = []
    state: dict[str, object] = {"helper_mode": "write"}
    from unicorn.arm64_const import UC_ARM64_REG_X1
    sentinels = {
        UC_ARM64_REG_X0: 0x0000000000000004,
        UC_ARM64_REG_X1: 0xA1A1A1A1A1A1A1A1,
        UC_ARM64_REG_X2: 0xB2B2B2B2B2B2B2B2,
        UC_ARM64_REG_X3: 0xC3C3C3C3C3C3C3C3,
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
            assert rva == RVA_GATE_SITE
            assert count == 4
            for i, word in enumerate(EXPECTED_WORDS):
                assert struct.unpack(
                    "<I", bytes(engine.mem_read(expected_ptr + 4 * i, 4))
                )[0] == word
            assert bytes(engine.mem_read(patch_ptr, 16)) == stub
            assert bytes(engine.mem_read(name_ptr, 22)) == b"guild_skill_turn_gate\x00"
            if state["helper_mode"] == "write":
                engine.mem_write(base + rva, stub)
                engine.reg_write(UC_ARM64_REG_W0, 1)
                events.append("helper_installed")
            else:
                engine.reg_write(UC_ARM64_REG_W0, 0)
                events.append("helper_refused")
        elif address == RETURN_SITE:
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    def run() -> None:
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        for reg, value in sentinels.items():
            uc.reg_write(reg, value)
        uc.emu_start(LATE_HOOK_SITE, RETURN_SITE)

    def client_word(i: int) -> int:
        raw = bytes(uc.mem_read(IL2CPP_BASE + RVA_GATE_SITE + 4 * i, 4))
        return int(struct.unpack("<I", raw)[0])

    def assert_preserved() -> None:
        assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
        for reg, value in sentinels.items():
            assert uc.reg_read(reg) == value
        # displaced word replayed before ret
        assert uc.reg_read(UC_ARM64_REG_W4) == 0xE5E5E5E5

    # 1. Helper cooperates: stub installed over the 4 stock words.
    events.clear()
    state["helper_mode"] = "write"
    run()
    assert events == ["helper_installed"]
    for i in range(4):
        assert client_word(i) == struct.unpack("<I", stub[4 * i:4 * i + 4])[0]
    assert_preserved()

    # 2. Helper refuses: no fallback in this cave — words stay stock, no crash.
    events.clear()
    state["helper_mode"] = "refuse"
    for i, word in enumerate(EXPECTED_WORDS):
        uc.mem_write(IL2CPP_BASE + RVA_GATE_SITE + 4 * i, struct.pack("<I", word))
    run()
    assert events == ["helper_refused"]
    for i, word in enumerate(EXPECTED_WORDS):
        assert client_word(i) == word
    assert_preserved()

    # 3. No cached il2cpp base: installer skips silently, replays and returns.
    events.clear()
    uc.mem_write(0x00BE3798, struct.pack("<Q", 0))
    run()
    assert events == []
    assert_preserved()


def test_unicorn_runtime_gate_matrix() -> None:
    """Runtime body matrix, started at the installed stub each time."""
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X20,
        UC_ARM64_REG_X21,
        UC_ARM64_REG_X30,
    )

    from tools.gen_guild_raid_skill_turn_gate import (
        RVA_GAME_STAGE_GET_INSTANCE,
        RVA_GAME_STAGE_GET_TURN,
        RVA_GATE_SITE,
        RVA_HOLD,
        RVA_RESUME,
        RVA_STOCK_GATE_CALL,
    )

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    IL2CPP_BASE = 0x40000000
    STACK_TOP = 0x08008000
    STUB_ADDR = IL2CPP_BASE + RVA_GATE_SITE
    RESUME = IL2CPP_BASE + RVA_RESUME
    HOLD = IL2CPP_BASE + RVA_HOLD
    STOCK_GATE = IL2CPP_BASE + RVA_STOCK_GATE_CALL
    GET_INSTANCE = IL2CPP_BASE + RVA_GAME_STAGE_GET_INSTANCE
    GET_TURN = IL2CPP_BASE + RVA_GAME_STAGE_GET_TURN
    handler_addr = CAVE_VADDR + 0x7C

    for addr, size in (
        (0x00B30000, 0x2000),
        (0x00BE3000, 0x2000),
        (0x00BE6000, 0x1000),
        (0x08000000, 0x10000),
        (IL2CPP_BASE + 0x018E6000, 0x2000),
        (IL2CPP_BASE + 0x1640000, 0x2000),
        (IL2CPP_BASE + 0x17ED000, 0x2000),
    ):
        uc.mem_map(addr, size)

    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    uc.mem_write(0x00BE3798, struct.pack("<Q", IL2CPP_BASE))
    stub = struct.pack("<IIQ", 0x58000050, 0xD61F0200, handler_addr)
    uc.mem_write(STUB_ADDR, stub)

    # Literal-pool stubs: fixed code (`ldr w0/x0, #8; ret`) reading a data word
    # placed after the return. Unicorn caches translated blocks, so rewriting
    # CODE between runs would keep serving the first version; rewriting the
    # DATA pool after the ret is always honored.

    def set_stock_gate(bit: int) -> None:
        uc.mem_write(STOCK_GATE, struct.pack("<III", 0x18000040, 0xD65F03C0, bit))

    def set_instance(ptr: int) -> None:
        uc.mem_write(GET_INSTANCE, struct.pack("<IIQ", 0x58000040, 0xD65F03C0, ptr))

    def set_turn(turn: int) -> None:
        uc.mem_write(GET_TURN, struct.pack("<III", 0x18000040, 0xD65F03C0, turn))

    def preload_state(instance: int, turn: int, mask: int) -> None:
        uc.mem_write(
            STATE_SLOT_VADDR,
            struct.pack("<QII", instance, turn, mask),
        )

    def read_state() -> tuple[int, int, int]:
        raw = bytes(uc.mem_read(STATE_SLOT_VADDR, 16))
        instance, turn, mask = struct.unpack("<QII", raw)
        return instance, turn, mask

    exits: list[str] = []

    def hook_code(engine: Uc, address: int, _size: int, _user: object) -> None:
        if address in (RESUME, HOLD):
            exits.append("resume" if address == RESUME else "hold")
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    def run(skill: int) -> str:
        exits.clear()
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM64_REG_X19, 0x1111111111111111)
        uc.reg_write(UC_ARM64_REG_X20, skill)
        uc.reg_write(UC_ARM64_REG_X21, 0xA21A21A21A21A21A)
        uc.reg_write(UC_ARM64_REG_X30, 0xCAFEBABE)
        uc.emu_start(STUB_ADDR, 0)
        assert exits
        assert exits[-1] in ("resume", "hold")
        # frame discipline: sp/x19/x21 intact, skill id intact, x30 free (stock flow
        # returns through the saved frame, not the live link register)
        assert uc.reg_read(UC_ARM64_REG_SP) == STACK_TOP
        assert uc.reg_read(UC_ARM64_REG_X19) == 0x1111111111111111
        assert uc.reg_read(UC_ARM64_REG_X20) == skill
        assert uc.reg_read(UC_ARM64_REG_X21) == 0xA21A21A21A21A21A
        return exits[-1]

    # a) First cast of the turn: stock gate passes, cast granted and marked.
    preload_state(0, 0, 0)
    set_stock_gate(0)
    set_instance(FAKE_INSTANCE_A)
    set_turn(0)
    assert run(SKILL_SHELLING) == "resume"
    assert read_state() == (FAKE_INSTANCE_A, 0, 0b001)

    # b) Same turn, same skill: held, mask untouched.
    assert run(SKILL_SHELLING) == "hold"
    assert read_state() == (FAKE_INSTANCE_A, 0, 0b001)

    # c) Other skills still cast on the same turn, each marked on its own bit.
    assert run(SKILL_ABS_PROTECTION) == "resume"
    assert read_state() == (FAKE_INSTANCE_A, 0, 0b011)
    assert run(SKILL_COMBAT_SUPPORT) == "resume"
    assert read_state() == (FAKE_INSTANCE_A, 0, 0b111)
    assert run(SKILL_COMBAT_SUPPORT) == "hold"

    # d) Turn advance: mask clears, every skill may cast again.
    set_turn(1)
    assert run(SKILL_SHELLING) == "resume"
    assert read_state() == (FAKE_INSTANCE_A, 1, 0b001)

    # e) Fire Support passes through unmarked, every time.
    for _ in range(3):
        assert run(SKILL_FIRE_SUPPORT) == "resume"
    assert read_state() == (FAKE_INSTANCE_A, 1, 0b001)

    # f) Unexpected ids fail open and are never marked.
    assert run(0x20000005) == "resume"
    assert run(SKILL_SHELLING - 1) == "resume"
    assert read_state() == (FAKE_INSTANCE_A, 1, 0b001)

    # g) Stock hold gate precedes the mask: bit set -> hold, nothing marked.
    preload_state(0, 0, 0)
    set_stock_gate(1)
    assert run(SKILL_SHELLING) == "hold"
    assert read_state() == (0, 0, 0)

    # h) Null GameStage instance fails open without marking.
    set_stock_gate(0)
    set_instance(0)
    assert run(SKILL_ABS_PROTECTION) == "resume"
    assert read_state() == (0, 0, 0)

    # i) New battle (instance change) resets the mask even mid-turn.
    set_instance(FAKE_INSTANCE_B)
    set_turn(5)
    preload_state(FAKE_INSTANCE_A, 5, 0b111)
    assert run(SKILL_ABS_PROTECTION) == "resume"
    assert read_state() == (FAKE_INSTANCE_B, 5, 0b010)
    assert run(SKILL_ABS_PROTECTION) == "hold"
