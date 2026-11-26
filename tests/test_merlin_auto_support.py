"""Tests for Merlin Slot-1 Auto Support (Feature 14.01: --merlin-auto-support)."""
from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

import pytest

from core.core_patches import (
    EXPECTED_PATCH_COUNTS,
    IDEMPOTENT_PATCHES,
    PatchOptions,
    apply_all_patches,
    validate_cave_layout,
)
from core.elf_mapping import read_load_segments, translate_vaddr
from core.merlin_auto_support import (
    AWAKE_CD_HELPER_RVA,
    CAVE_BYTES,
    CAVE_ORIGINAL_SHA256,
    CAVE_SIZE,
    CAVE_VADDR,
    CLIENT_HOOK_TARGETS,
    IL2CPP_BASE_CACHE,
    LATE_HOOK_ORIGINAL,
    LATE_HOOK_SITE,
    MAGIC_INFUSION_SKILL_ID,
    PATCH_IL2CPP_HELPER,
    PRIORITY_BODY_OFFSET,
    PRIORITY_CAVE_BYTES,
    PRIORITY_CAVE_ORIGINAL_SHA256,
    PRIORITY_CAVE_SIZE,
    PRIORITY_CAVE_VADDR,
    PRIORITY_CLIENT_SITE,
    PRIORITY_CLIENT_WORDS,
    PRIORITY_INSTALL_JUMP,
    PRIORITY_INSTALL_JUMP_OFFSET,
    PRIORITY_POWER_OFFSET,
    PRIORITY_POWER_VADDR,
    SKILL_EFFECT_TABLE_GET_DATA,
    SKILL_EFFECT_TYPE_OFFSET,
    SKILL_EFFECT_VALUE_OFFSET,
    TAIL_CAVE_BYTES,
    TAIL_CAVE_ORIGINAL_SHA256,
    TAIL_CAVE_SIZE,
    TAIL_CAVE_VADDR,
    apply_merlin_auto_support,
    inspect_merlin_auto_support,
    merlin_auto_support_state,
)
from core.patch_inspector import expected_feature_keys, inspect_native_so

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_APK = PROJECT_ROOT / "source" / "fwt_0.682_offline_v1574.apk"


def _offset(so_bytes: bytes | bytearray):
    segments = read_load_segments(bytes(so_bytes))
    return lambda addr: translate_vaddr(segments, addr)


def test_constants_and_cave_layout_consistent() -> None:
    validate_cave_layout()
    assert len(CAVE_BYTES) == CAVE_SIZE
    assert CAVE_VADDR >= 0xB2B1B4
    assert CAVE_VADDR + CAVE_SIZE <= 0xB2B750
    assert len(TAIL_CAVE_BYTES) == TAIL_CAVE_SIZE
    # Tail cave lives in the remaining free parseName tail, past the main cave
    # and trait_multi_unique's 0xB2B530..0xB2B620 slice, inside parseName.
    assert TAIL_CAVE_VADDR >= CAVE_VADDR + CAVE_SIZE
    assert TAIL_CAVE_VADDR >= 0xB2B620
    assert TAIL_CAVE_VADDR + TAIL_CAVE_SIZE <= 0xB2B750
    # 14.02 cave sits in the dead parseEncoding tail, after dungeon_recom_info.
    assert PRIORITY_CAVE_VADDR == 0xB30538
    assert len(PRIORITY_CAVE_BYTES) == PRIORITY_CAVE_SIZE
    assert PRIORITY_CAVE_VADDR >= 0xB30538
    assert PRIORITY_CAVE_VADDR + PRIORITY_CAVE_SIZE <= 0xB3101C
    # the 14.01 installer's tail `ret` is replaced by `b PRIORITY_CAVE_VADDR`
    assert PRIORITY_INSTALL_JUMP_OFFSET == 0x90
    assert struct.pack("<I", PRIORITY_INSTALL_JUMP) == CAVE_BYTES[0x90:0x94]
    assert PRIORITY_INSTALL_JUMP == 0x140014BD
    # 14.03: both cross-ally compare calls now target the awaken_power helper
    assert PRIORITY_POWER_OFFSET == 0x354
    assert PRIORITY_POWER_VADDR == PRIORITY_CAVE_VADDR + PRIORITY_POWER_OFFSET == 0xB3088C
    assert PRIORITY_POWER_OFFSET + 4 <= PRIORITY_CAVE_SIZE

    def _bl(site: int, target: int) -> int:
        return 0x94000000 | (((target - site) >> 2) & 0x03FFFFFF)

    assert struct.pack("<I", _bl(0xB2B468, PRIORITY_POWER_VADDR)) == CAVE_BYTES[0x2B4:0x2B8]
    assert struct.pack("<I", _bl(0xB2B474, PRIORITY_POWER_VADDR)) == CAVE_BYTES[0x2C0:0x2C4]
    # no `slot_index_in_camp` call survives in the compare body
    assert struct.pack("<I", _bl(0xB2B468, 0xB2B2F0)) not in CAVE_BYTES
    assert struct.pack("<I", _bl(0xB2B474, 0xB2B2F0)) not in CAVE_BYTES
    # the helper ends with `ret` followed by the 100.0f scaling constant
    assert PRIORITY_CAVE_BYTES[-4:] == struct.pack("<I", 0x42C80000)
    assert AWAKE_CD_HELPER_RVA == 0x1606428
    assert EXPECTED_PATCH_COUNTS["merlin_auto_support"] == 4
    assert "merlin_auto_support" in IDEMPOTENT_PATCHES
    assert MAGIC_INFUSION_SKILL_ID == 1053188
    assert CLIENT_HOOK_TARGETS[-1][1] == PRIORITY_CLIENT_SITE == 0x1A35F68
    assert CLIENT_HOOK_TARGETS[-1][2] == PRIORITY_CLIENT_WORDS


def test_capstone_disassembles_entire_cave_without_gaps() -> None:
    cs_mod = pytest.importorskip("capstone")
    md = cs_mod.Cs(cs_mod.CS_ARCH_ARM64, cs_mod.CS_MODE_ARM)
    # Code section stops before trailing literal pool + string at offset 0x350 (848 B)
    # Verify prologue stlrb w8, [x9] and overall instruction decoding before literal data
    insns = list(md.disasm(CAVE_BYTES[:0x350], CAVE_VADDR))
    assert len(insns) > 150
    assert insns[0].mnemonic == "stlrb"
    assert insns[0].op_str == "w8, [x9]"
    assert b"merlin_auto_support\x00" in CAVE_BYTES
    # The Awake CD == 1 test calls the tail cave instead of reading [skill+0x30]
    swap = next(i for i in insns if i.address == 0xB2B3CC)
    assert swap.mnemonic == "bl"
    assert swap.op_str == "#0xb2b620"
    tail_insns = list(md.disasm(TAIL_CAVE_BYTES, TAIL_CAVE_VADDR))
    assert len(tail_insns) == 12
    assert tail_insns[0].mnemonic == "stp"
    assert tail_insns[0].op_str == "x8, x9, [sp, #-0x20]!"
    assert tail_insns[-1].mnemonic == "ret"

    # 14.02: the installer chain ends in `b 0xB30538` instead of `ret`, and the
    # priority cave builds the client stub at runtime (a static `.quad` body
    # address would be the link-time VA and crash the client).
    entry = next(i for i in insns if i.address == 0xB2B244)
    assert entry.mnemonic == "b"
    assert entry.op_str == f"#0x{PRIORITY_CAVE_VADDR:x}"

    assert b"merlin_auto_support_priority\x00" in PRIORITY_CAVE_BYTES
    installer_len = PRIORITY_BODY_OFFSET - 16 - 32  # installer | expected | tag | body
    installer_insns = list(
        md.disasm(PRIORITY_CAVE_BYTES[:installer_len], PRIORITY_CAVE_VADDR)
    )
    assert installer_insns[0].mnemonic == "sub"
    assert any(
        insn.mnemonic == "bl" and insn.op_str == f"#0x{PATCH_IL2CPP_HELPER:x}"
        for insn in installer_insns
    )
    assert any(
        insn.mnemonic == "adr" and insn.op_str == f"x9, #0x{PRIORITY_CAVE_VADDR:x}"
        for insn in installer_insns
    ), "installer must derive the body address PC-relatively"
    assert any(
        insn.mnemonic == "add" and insn.op_str == f"x9, x9, #0x{PRIORITY_BODY_OFFSET:x}"
        for insn in installer_insns
    ), "installer must add the body delta"
    # the stub words are composed with movz/movk, never stored as a literal quad
    assert b"\x50\x00\x00\x58\x00\x02\x1f\xd6" not in PRIORITY_CAVE_BYTES
    assert [i.address for i in installer_insns if i.mnemonic == "ret"] == [
        PRIORITY_CAVE_VADDR + installer_len - 4
    ]

    body_va = PRIORITY_CAVE_VADDR + PRIORITY_BODY_OFFSET
    body_insns = list(
        md.disasm(
            PRIORITY_CAVE_BYTES[PRIORITY_BODY_OFFSET:PRIORITY_POWER_OFFSET], body_va
        )
    )
    assert len(body_insns) > 80
    assert not [i for i in body_insns if i.mnemonic == "ret"]
    assert [i.mnemonic for i in body_insns].count("br") == 2

    # 14.03 helper: a normal function, ends in `ret` right before its literal
    helper_insns = list(
        md.disasm(
            PRIORITY_CAVE_BYTES[PRIORITY_POWER_OFFSET : PRIORITY_CAVE_SIZE - 4],
            PRIORITY_POWER_VADDR,
        )
    )
    assert len(helper_insns) > 40
    assert helper_insns[0].mnemonic == "sub"
    assert helper_insns[-1].mnemonic == "ret"
    # scaled by 100 and truncated to an integer, never summed as raw floats
    assert any(i.mnemonic == "fcvtzs" for i in helper_insns)
    assert any(i.mnemonic == "blr" for i in helper_insns)


@pytest.mark.integration
def test_client_hook_words_match_decrypted_client_image() -> None:
    """Guards the four-word patterns against the real client.

    Opt-in: point FWT_IL2CPP_CODE_BIN at the decrypted `libil2cpp` code image
    (VA == file offset). A wrong expected word makes PATCH_IL2CPP_HELPER decline
    silently at boot, so this is the only check that catches a hand-encoded word.
    """
    image = os.environ.get("FWT_IL2CPP_CODE_BIN")
    if not image:
        pytest.skip("set FWT_IL2CPP_CODE_BIN to the decrypted libil2cpp code image")
    code = Path(image).read_bytes()
    for name, rva, words in CLIENT_HOOK_TARGETS:
        got = struct.unpack("<4I", code[rva : rva + 16])
        assert got == words, f"{name} @ 0x{rva:x}: expected {words}, got {got}"


def test_expected_feature_keys_includes_merlin_auto_support() -> None:
    keys = expected_feature_keys(PatchOptions(merlin_auto_support=True))
    assert "merlin_auto_support" in keys
    assert "merlin_auto_support" not in expected_feature_keys(PatchOptions())


def test_cli_flags_enable_merlin_auto_support(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from fwt_patcher import build_parser, run_cli

    in_apk = tmp_path / "in.apk"
    in_apk.write_bytes(b"PK")
    recorded: list[PatchOptions] = []

    def _fake_repack(**kwargs) -> None:
        recorded.append(kwargs["options"])
        raise RuntimeError("stop-after-capture")

    monkeypatch.setattr("fwt_patcher.repack_and_sign_apk", _fake_repack)
    for cli_flag in ("--merlin-auto-support", "--all"):
        out_apk = tmp_path / f"out_{cli_flag.strip('-')}.apk"
        args = build_parser().parse_args(
            ["--input", str(in_apk), "--output", str(out_apk), cli_flag]
        )
        assert run_cli(args) == 1

    assert len(recorded) == 2
    assert recorded[0].merlin_auto_support is True
    assert recorded[1].merlin_auto_support is True


def test_apply_and_inspect_reference_so(reference_buffers: tuple[bytes, bytes]) -> None:
    so_bytes, dex_bytes = reference_buffers
    offset = _offset(so_bytes)

    assert merlin_auto_support_state(so_bytes, offset) == "stock"
    assert inspect_merlin_auto_support(so_bytes, offset) is False
    cave_off = offset(CAVE_VADDR)
    assert hashlib.sha256(so_bytes[cave_off : cave_off + CAVE_SIZE]).hexdigest() == CAVE_ORIGINAL_SHA256
    tail_off = offset(TAIL_CAVE_VADDR)
    assert hashlib.sha256(so_bytes[tail_off : tail_off + TAIL_CAVE_SIZE]).hexdigest() == TAIL_CAVE_ORIGINAL_SHA256
    priority_off = offset(PRIORITY_CAVE_VADDR)
    assert (
        hashlib.sha256(
            so_bytes[priority_off : priority_off + PRIORITY_CAVE_SIZE]
        ).hexdigest()
        == PRIORITY_CAVE_ORIGINAL_SHA256
    )
    site_off = offset(LATE_HOOK_SITE)
    assert bytes(so_bytes[site_off : site_off + 4]) == LATE_HOOK_ORIGINAL
    # stock wording at the 14.02 installer entry is `b 0xB2B634`, replaced by the
    # 14.01 cave with `ret` and now by `b PRIORITY_CAVE_VADDR`
    assert bytes(
        so_bytes[cave_off + PRIORITY_INSTALL_JUMP_OFFSET : cave_off + PRIORITY_INSTALL_JUMP_OFFSET + 4]
    ) == struct.pack("<I", 0x140000FC)

    result = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(merlin_auto_support=True),
    )
    assert result.counts["merlin_auto_support"] == 4
    assert merlin_auto_support_state(result.so_bytes, offset) == "patched"
    assert inspect_merlin_auto_support(result.so_bytes, offset) is True
    assert (
        bytes(
            result.so_bytes[
                cave_off + PRIORITY_INSTALL_JUMP_OFFSET : cave_off + PRIORITY_INSTALL_JUMP_OFFSET + 4
            ]
        )
        == struct.pack("<I", PRIORITY_INSTALL_JUMP)
    )

    reports = inspect_native_so(result.so_bytes)
    assert reports["merlin_auto_support"].active is True

    # Idempotency
    assert apply_merlin_auto_support(bytearray(result.so_bytes), offset) == 0
    again = apply_all_patches(
        result.so_bytes,
        dex_bytes,
        PatchOptions(merlin_auto_support=True, allow_unknown=True),
    )
    assert again.counts["merlin_auto_support"] == 0
    assert again.so_bytes == result.so_bytes


def test_rejects_corrupted_site_or_cave(reference_buffers: tuple[bytes, bytes]) -> None:
    so_bytes, _ = reference_buffers
    offset = _offset(so_bytes)

    bad_site = bytearray(so_bytes)
    bad_site[offset(LATE_HOOK_SITE)] ^= 1
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_merlin_auto_support(bad_site, offset)

    bad_cave = bytearray(so_bytes)
    bad_cave[offset(CAVE_VADDR)] ^= 1
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_merlin_auto_support(bad_cave, offset)

    bad_tail = bytearray(so_bytes)
    bad_tail[offset(TAIL_CAVE_VADDR)] ^= 1
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_merlin_auto_support(bad_tail, offset)

    bad_priority = bytearray(so_bytes)
    bad_priority[offset(PRIORITY_CAVE_VADDR)] ^= 1
    with pytest.raises(ValueError, match="Unexpected or partially patched"):
        apply_merlin_auto_support(bad_priority, offset)


def _setup_unicorn_runtime():
    unicorn = pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    # Map server code page (0xAB0000..0xB30000), server RW page (0xBE0000..0xBF0000),
    # fake IL2CPP space (0x10000000..0x13000000), heap (0x20000000..0x20100000), stack (0x30000000..0x30100000)
    uc.mem_map(0xAB0000, 0x90000)
    uc.mem_map(0xBE0000, 0x10000)
    uc.mem_map(0x10000000, 0x3000000)
    uc.mem_map(0x20000000, 0x100000)
    uc.mem_map(0x30000000, 0x100000)

    # Write cave + bl at LATE_HOOK_SITE
    uc.mem_write(CAVE_VADDR, CAVE_BYTES)
    uc.mem_write(TAIL_CAVE_VADDR, TAIL_CAVE_BYTES)
    uc.mem_write(PRIORITY_CAVE_VADDR, PRIORITY_CAVE_BYTES)
    diff = CAVE_VADDR - LATE_HOOK_SITE
    uc.mem_write(LATE_HOOK_SITE, struct.pack("<I", 0x94000000 | ((diff >> 2) & 0x03FFFFFF)))
    # Write a RET right after LATE_HOOK_SITE (simulating fallthrough exit sentinel)
    sentinel_end = 0xAB3304
    uc.mem_write(sentinel_end, struct.pack("<I", 0xD65F03C0))

    # Write PATCH_IL2CPP_HELPER sentinel (`ret` instruction)
    uc.mem_write(PATCH_IL2CPP_HELPER, struct.pack("<I", 0xD65F03C0))

    # Write stock words at the 4 IL2CPP target RVAs
    il2cpp_base = 0x10000000
    for _name, rva, exp_words in CLIENT_HOOK_TARGETS:
        uc.mem_write(il2cpp_base + rva, struct.pack("<4I", *exp_words))

    # Emulate the client awake-cooldown helper (libil2cpp RVA 0x1606428):
    # awake ? max(0, SkillData._cooltime - [skill + 0x30]) : -1. The real
    # helper adds buff/stage/Lord-rule adjustments; this model keeps the plain
    # difference, which is all the cave contract needs.
    keystone = pytest.importorskip("keystone")
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    stub, _ = ks.asm(
        """
        ldr x8, [x0, #0x18]
        ldrb w9, [x8, #0x4c]
        ldrb w10, [x8, #0x4d]
        orr w10, w10, #1
        cmp w10, #5
        b.ne not_awake
        ldr w10, [x0, #0x30]
        sub w0, w9, w10
        b.ge done
        mov w0, #0
        b done
        not_awake:
        mov w0, #-1
        done:
        ret
        """,
        addr=il2cpp_base + AWAKE_CD_HELPER_RVA,
    )
    uc.mem_write(il2cpp_base + AWAKE_CD_HELPER_RVA, bytes(stub))

    return unicorn, uc, il2cpp_base


def test_unicorn_installer_installs_all_five_hooks_and_skips_when_base_zero() -> None:
    unicorn, uc, il2cpp_base = _setup_unicorn_runtime()
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W8,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X9,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X20,
        UC_ARM64_REG_X30,
    )

    installed: list[tuple[int, int, tuple[int, ...], bytes, int, str]] = []
    covault_flag_addr = 0xBE3AD4

    def _hook_code(_uc, address: int, _size: int, _user) -> None:
        if address == PATCH_IL2CPP_HELPER:
            base = _uc.reg_read(UC_ARM64_REG_X0)
            rva = _uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
            exp_ptr = _uc.reg_read(UC_ARM64_REG_X2)
            rep_ptr = _uc.reg_read(UC_ARM64_REG_X3)
            nwords = _uc.reg_read(UC_ARM64_REG_X4) & 0xFFFFFFFF
            name_ptr = _uc.reg_read(UC_ARM64_REG_X5)
            exp = struct.unpack("<4I", _uc.mem_read(exp_ptr, 16))
            rep = bytes(_uc.mem_read(rep_ptr, 16))
            raw_name = bytes(_uc.mem_read(name_ptr, 32)).split(b"\x00", 1)[0].decode("ascii")
            installed.append((base, rva, exp, rep, nwords, raw_name))
            # Perform real write just like PATCH_IL2CPP_HELPER
            assert bytes(_uc.mem_read(base + rva, 16)) == struct.pack("<4I", *exp)
            _uc.mem_write(base + rva, rep)

    h = uc.hook_add(unicorn.UC_HOOK_CODE, _hook_code)
    try:
        # 1) base == 0 skips safely
        uc.mem_write(IL2CPP_BASE_CACHE, b"\x00" * 8)
        uc.mem_write(covault_flag_addr, b"\x00")
        uc.reg_write(UC_ARM64_REG_SP, 0x30080000)
        uc.reg_write(UC_ARM64_REG_W8, 1)
        uc.reg_write(UC_ARM64_REG_X9, covault_flag_addr)
        uc.reg_write(UC_ARM64_REG_X19, 0x1234)
        uc.reg_write(UC_ARM64_REG_X20, 0x5678)
        uc.reg_write(UC_ARM64_REG_X30, 0xAB0000)  # unused because sentinel RET at 0xAB3304 stops
        uc.emu_start(LATE_HOOK_SITE, 0xAB3304)
        assert uc.mem_read(covault_flag_addr, 1) == b"\x01"
        assert uc.reg_read(UC_ARM64_REG_X19) == 0x1234
        assert uc.reg_read(UC_ARM64_REG_X20) == 0x5678
        assert uc.reg_read(UC_ARM64_REG_SP) == 0x30080000
        assert installed == []

        # 2) base != 0 installs all 5 hooks and preserves x19, x20, sp
        uc.mem_write(IL2CPP_BASE_CACHE, struct.pack("<Q", il2cpp_base))
        uc.mem_write(covault_flag_addr, b"\x00")
        uc.reg_write(UC_ARM64_REG_SP, 0x30080000)
        uc.reg_write(UC_ARM64_REG_W8, 1)
        uc.reg_write(UC_ARM64_REG_X9, covault_flag_addr)
        uc.reg_write(UC_ARM64_REG_X19, 0x11)
        uc.reg_write(UC_ARM64_REG_X20, 0x22)
        uc.emu_start(LATE_HOOK_SITE, 0xAB3304)
        assert uc.mem_read(covault_flag_addr, 1) == b"\x01"
        assert uc.reg_read(UC_ARM64_REG_X19) == 0x11
        assert uc.reg_read(UC_ARM64_REG_X20) == 0x22
        assert uc.reg_read(UC_ARM64_REG_SP) == 0x30080000
        assert [row[1] for row in installed] == [rva for _, rva, _ in CLIENT_HOOK_TARGETS]
        assert [row[4] for row in installed] == [4] * len(CLIENT_HOOK_TARGETS)
        # 14.01 tags its four sites; 14.02's installer (reached through the
        # installer tail) tags the InitActing site
        assert [row[5] for row in installed] == [
            "merlin_auto_support",
            "merlin_auto_support",
            "merlin_auto_support",
            "merlin_auto_support",
            "merlin_auto_support_priority",
        ]
        # the InitActing site received the absolute stub + body address
        written = bytes(uc.mem_read(il2cpp_base + PRIORITY_CLIENT_SITE, 16))
        assert written[:8] == struct.pack("<2I", 0x58000050, 0xD61F0200)
        body_va = struct.unpack("<Q", written[8:])[0]
        assert PRIORITY_CAVE_VADDR < body_va < PRIORITY_CAVE_VADDR + PRIORITY_CAVE_SIZE
    finally:
        uc.hook_del(h)


class _HeapAllocator:
    def __init__(self, uc, base: int = 0x20001000) -> None:
        self.uc = uc
        self.ptr = base

    def alloc(self, size: int) -> int:
        addr = self.ptr
        self.uc.mem_write(addr, b"\x00" * size)
        self.ptr += (size + 15) & ~15
        return addr

    def make_skill(
        self,
        skill_id: int,
        remain_cd: int,
        *,
        awake: bool,
        cooltime: int = 2,
        effect_ids: tuple[int, ...] = (),
    ) -> int:
        # remain_cd models [Skill + 0x30] (turns elapsed); cooltime models
        # SkillData._cooltime so the stub computes the true remaining cooldown.
        sdata = self.alloc(0x80)
        struct_w = struct.pack("<I", skill_id)
        self.uc.mem_write(sdata + 0x10, struct_w)
        for idx, effect_id in enumerate(effect_ids[:4]):
            self.uc.mem_write(sdata + 0x3C + 4 * idx, struct.pack("<i", effect_id))
        self.uc.mem_write(sdata + 0x4C, bytes([cooltime & 0xFF]))
        self.uc.mem_write(sdata + 0x4D, bytes([4 if awake else 0]))
        sk = self.alloc(0x40)
        self.uc.mem_write(sk + 0x18, struct.pack("<Q", sdata))
        self.uc.mem_write(sk + 0x30, struct.pack("<i", remain_cd))
        return sk

    def make_effect_row(
        self, value: float, *, effect_type: int = 0
    ) -> int:
        """Fake SkillEffectTable row: `_skillEffectType` and `_effectValue`."""
        row = self.alloc(0x60)
        self.uc.mem_write(row + SKILL_EFFECT_TYPE_OFFSET, bytes([effect_type & 0xFF]))
        self.uc.mem_write(row + SKILL_EFFECT_VALUE_OFFSET, struct.pack("<f", value))
        return row

    def make_char(
        self,
        *,
        char_type: int = 0,
        is_auto: int = 1,
        is_dead: int = 0,
        camp: int = 0,
        skills: list[int] | None = None,
    ) -> int:
        ch = self.alloc(0x200)
        self.uc.mem_write(ch + 0x18, bytes([char_type]))
        self.uc.mem_write(ch + 0x78, struct.pack("<Q", camp))
        self.uc.mem_write(ch + 0x11A, bytes([is_dead]))
        self.uc.mem_write(ch + 0x1C0, bytes([is_auto]))
        if skills is not None:
            arr = self.alloc(0x20 + 8 * len(skills))
            self.uc.mem_write(arr + 0x18, struct.pack("<I", len(skills)))
            for idx, sk in enumerate(skills):
                self.uc.mem_write(arr + 0x20 + 8 * idx, struct.pack("<Q", sk))
            sc = self.alloc(0x40)
            self.uc.mem_write(sc + 0x18, struct.pack("<Q", arr))
            self.uc.mem_write(ch + 0x40, struct.pack("<Q", sc))
        return ch

    def make_camp(self, members: list[int], *, camp_type: int = 0) -> int:
        camp = self.alloc(0x40)
        arr = self.alloc(0x20 + 8 * len(members))
        self.uc.mem_write(arr + 0x18, struct.pack("<I", len(members)))
        for idx, ch in enumerate(members):
            self.uc.mem_write(arr + 0x20 + 8 * idx, struct.pack("<Q", ch))
        lst = self.alloc(0x30)
        self.uc.mem_write(lst + 0x10, struct.pack("<Q", arr))
        self.uc.mem_write(lst + 0x18, struct.pack("<I", len(members)))
        self.uc.mem_write(camp + 0x18, bytes([camp_type]))
        self.uc.mem_write(camp + 0x20, struct.pack("<Q", lst))
        for ch in members:
            self.uc.mem_write(ch + 0x78, struct.pack("<Q", camp))
        return camp


def _install_effect_lookup(uc, base: int, rows: dict[int, int]):
    """Fakes SkillEffectTableManager::GetData(id) -> SkillEffectTable row pointer."""
    import unicorn
    from unicorn.arm64_const import UC_ARM64_REG_W0, UC_ARM64_REG_X0

    site = base + SKILL_EFFECT_TABLE_GET_DATA
    uc.mem_write(site, struct.pack("<I", 0xD65F03C0))  # ret

    def _on_lookup(_uc, address: int, _size: int, _user) -> None:
        if address != site:
            return
        effect_id = _uc.reg_read(UC_ARM64_REG_W0) & 0xFFFFFFFF
        _uc.reg_write(UC_ARM64_REG_X0, rows.get(effect_id, 0))

    return uc.hook_add(unicorn.UC_HOOK_CODE, _on_lookup, begin=site, end=site)


def _install_via_unicorn(uc) -> None:
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W8,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X9,
    )

    il2cpp_base = 0x10000000
    uc.mem_write(IL2CPP_BASE_CACHE, struct.pack("<Q", il2cpp_base))

    # Run installer and write trampolines via Python hook simulating PATCH_IL2CPP_HELPER
    import unicorn

    def _helper(_uc, address: int, _size: int, _u) -> None:
        if address == PATCH_IL2CPP_HELPER:
            base = _uc.reg_read(UC_ARM64_REG_X0)
            rva = _uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
            rep_ptr = _uc.reg_read(UC_ARM64_REG_X3)
            _uc.mem_write(base + rva, bytes(_uc.mem_read(rep_ptr, 16)))

    h = uc.hook_add(unicorn.UC_HOOK_CODE, _helper)
    try:
        uc.reg_write(UC_ARM64_REG_SP, 0x30080000)
        uc.reg_write(UC_ARM64_REG_W8, 1)
        uc.reg_write(UC_ARM64_REG_X9, 0xBE3AD4)
        uc.emu_start(LATE_HOOK_SITE, 0xAB3304)
    finally:
        uc.hook_del(h)


@pytest.mark.parametrize("target_rva", [0x20EDBCC, 0x20F1AF0])
def test_unicorn_is_use_support_skill_state(target_rva: int) -> None:
    _, uc, base = _setup_unicorn_runtime()
    _install_via_unicorn(uc)
    from unicorn.arm64_const import (
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W0,
        UC_ARM64_REG_W8,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X29,
        UC_ARM64_REG_X30,
    )

    heap = _HeapAllocator(uc)
    magic_infusion = heap.make_skill(MAGIC_INFUSION_SKILL_ID, 0, awake=False)
    other_skill = heap.make_skill(1053190, 0, awake=False)
    merlin = heap.make_char(
        skills=[magic_infusion, heap.make_skill(1053189, 1, awake=True)]
    )
    ally_cd1 = heap.make_char(skills=[heap.make_skill(1010001, 1, awake=True)])
    ally_cd2 = heap.make_char(skills=[heap.make_skill(1020001, 2, awake=True)])
    ally_cd0 = heap.make_char(skills=[heap.make_skill(1030001, 0, awake=True)])
    ally_non_awake_cd1 = heap.make_char(skills=[heap.make_skill(1040001, 1, awake=False)])
    ally_dead_cd1 = heap.make_char(is_dead=1, skills=[heap.make_skill(1050001, 1, awake=True)])
    # Regression fixtures: _cooltime != 2 breaks the old [skill+0x30] == 1 test.
    # cd=3 elapsed=2 -> true remaining 1 (old check wrongly rejected).
    ally_cd3_elapsed2 = heap.make_char(skills=[heap.make_skill(1060001, 2, awake=True, cooltime=3)])
    # cd=3 elapsed=1 -> true remaining 2 (old check wrongly accepted).
    ally_cd3_elapsed1 = heap.make_char(skills=[heap.make_skill(1070001, 1, awake=True, cooltime=3)])

    camp = heap.make_camp(
        [
            merlin,
            ally_cd1,
            ally_cd2,
            ally_cd0,
            ally_non_awake_cd1,
            ally_dead_cd1,
            ally_cd3_elapsed2,
            ally_cd3_elapsed1,
        ]
    )
    phase = heap.alloc(0x60)
    uc.mem_write(phase + 0x20, struct.pack("<Q", merlin))
    uc.mem_write(phase + 0x38, struct.pack("<Q", magic_infusion))
    uc.mem_write(phase + 0x40, bytes([0]))

    ret_sentinel = 0x10000100
    resume_addr = base + target_rva + 0x10
    stop_addrs = {ret_sentinel, resume_addr}
    for sa in stop_addrs:
        uc.mem_write(sa, struct.pack("<I", 0xD503201F))  # nop sentinel

    import unicorn

    def _stop_hook(_uc, address: int, _size: int, _u) -> None:
        if address in stop_addrs:
            _uc.emu_stop()

    h = uc.hook_add(unicorn.UC_HOOK_CODE, _stop_hook)
    try:
        def _call(target: int, skill: int = magic_infusion, phase_ptr: int = phase) -> tuple[int, int]:
            uc.reg_write(UC_ARM64_REG_SP, 0x30080000)
            uc.reg_write(UC_ARM64_REG_X0, phase_ptr)
            uc.reg_write(UC_ARM64_REG_X1, target)
            uc.reg_write(UC_ARM64_REG_X2, skill)
            uc.reg_write(UC_ARM64_REG_X19, 0xCAFE)
            uc.reg_write(UC_ARM64_REG_X29, 0xBEEF)
            uc.reg_write(UC_ARM64_REG_X30, ret_sentinel)
            uc.emu_start(base + target_rva, 0, count=200)
            return uc.reg_read(UC_ARM64_REG_W0) & 0xFFFFFFFF, uc.reg_read(UC_ARM64_REG_PC)

        # Qualifying ally (Awake CD == 1) -> returns 1 directly to caller
        w0, pc = _call(ally_cd1)
        assert (w0, pc) == (1, ret_sentinel)
        assert uc.reg_read(UC_ARM64_REG_SP) == 0x30080000

        # Self-target even if Merlin's own Awake has CD == 1 -> rejected (0)
        w0, pc = _call(merlin)
        assert (w0, pc) == (0, ret_sentinel)

        # True remaining cooldown == 1 with _cooltime == 3 (elapsed 2) -> accepted;
        # the old [skill + 0x30] == 1 check rejected this ally.
        w0, pc = _call(ally_cd3_elapsed2)
        assert (w0, pc) == (1, ret_sentinel)
        assert uc.reg_read(UC_ARM64_REG_SP) == 0x30080000

        # True remaining cooldown == 2 with _cooltime == 3 (elapsed 1) -> rejected;
        # the old [skill + 0x30] == 1 check wrongly accepted this ally.
        w0, pc = _call(ally_cd3_elapsed1)
        assert (w0, pc) == (0, ret_sentinel)

        # Dead ally, Awake CD == 2, Awake CD == 0, non-Awake CD == 1 -> rejected (0)
        for bad_ally in (ally_dead_cd1, ally_cd2, ally_cd0, ally_non_awake_cd1):
            w0, pc = _call(bad_ally)
            assert (w0, pc) == (0, ret_sentinel)

        # Non-Merlin / non-Auto / non-Slot-1 / non-PlayerCamp -> fallthrough replays prologue to resume_addr
        # 1) Different skill (e.g., healing skill)
        uc.mem_write(phase + 0x38, struct.pack("<Q", other_skill))
        _, pc = _call(ally_cd1, skill=other_skill)
        assert pc == resume_addr
        assert uc.reg_read(UC_ARM64_REG_SP) == 0x30080000 - 0x20
        assert uc.reg_read(UC_ARM64_REG_W8) == 0
        uc.mem_write(phase + 0x38, struct.pack("<Q", magic_infusion))

        # 2) Manual mode (_isAutoPlay == 0)
        uc.mem_write(merlin + 0x1C0, bytes([0]))
        _, pc = _call(ally_cd1)
        assert pc == resume_addr
        uc.mem_write(merlin + 0x1C0, bytes([1]))

        # 3) Enemy camp (_campType == 1)
        uc.mem_write(camp + 0x18, bytes([1]))
        _, pc = _call(ally_cd1)
        assert pc == resume_addr
        uc.mem_write(camp + 0x18, bytes([0]))

        # 4) Merlin in Slot 2 instead of Slot 1
        camp2 = heap.make_camp([ally_cd1, merlin, ally_cd2])
        assert camp2 != camp
        _, pc = _call(ally_cd1)
        assert pc == resume_addr
    finally:
        uc.hook_del(h)


@pytest.mark.parametrize("target_rva", [0x20EEF2C, 0x20F3338])
def test_unicorn_compare_find_target_step(target_rva: int) -> None:
    _, uc, base = _setup_unicorn_runtime()
    _install_via_unicorn(uc)
    from unicorn.arm64_const import (
        UC_ARM64_REG_PC,
        UC_ARM64_REG_S0,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W6,
        UC_ARM64_REG_W9,
        UC_ARM64_REG_X6,
        UC_ARM64_REG_X8,
        UC_ARM64_REG_X20,
        UC_ARM64_REG_X21,
        UC_ARM64_REG_X22,
        UC_ARM64_REG_X23,
        UC_ARM64_REG_X24,
        UC_ARM64_REG_X25,
    )

    heap = _HeapAllocator(uc)
    rows = {
        9001: heap.make_effect_row(6.50),  # ally in slot 2 -> 650%
        9002: heap.make_effect_row(2.44),  # ally in slot 3 -> 244%
        9003: heap.make_effect_row(4.25),  # ally in slot 4 -> 425%
        9004: heap.make_effect_row(4.25),  # ally in slot 5 -> 425% (tie)
    }
    lookup = _install_effect_lookup(uc, base, rows)
    uc.mem_write(IL2CPP_BASE_CACHE, struct.pack("<Q", base))

    magic_infusion = heap.make_skill(MAGIC_INFUSION_SKILL_ID, 0, awake=False)
    other_skill = heap.make_skill(1053190, 0, awake=False)
    merlin = heap.make_char(skills=[magic_infusion])
    slot2 = heap.make_char(skills=[heap.make_skill(1053189, 1, awake=True, effect_ids=(9001,))])
    slot3 = heap.make_char(skills=[heap.make_skill(1053190, 1, awake=True, effect_ids=(9002,))])
    slot4 = heap.make_char(skills=[heap.make_skill(1053191, 1, awake=True, effect_ids=(9003,))])
    slot5 = heap.make_char(skills=[heap.make_skill(1053192, 1, awake=True, effect_ids=(9004,))])
    no_awake = heap.make_char(skills=[heap.make_skill(1053193, 1, awake=False)])
    heap.make_camp([merlin, slot2, slot3, slot4, slot5, no_awake])

    phase = heap.alloc(0x60)
    uc.mem_write(phase + 0x20, struct.pack("<Q", merlin))
    uc.mem_write(phase + 0x38, struct.pack("<Q", magic_infusion))

    best_info = heap.alloc(0x50)
    cont_addr = base + target_rva + 0x10
    accept_addr = base + target_rva + 0x40
    reject_addr = base + target_rva + 0x64
    stop_addrs = {cont_addr, accept_addr, reject_addr}
    for stop_addr in stop_addrs:
        uc.mem_write(stop_addr, struct.pack("<I", 0xD503201F))

    import unicorn

    def _stop_hook(_uc, address: int, _size: int, _u) -> None:
        if address in stop_addrs:
            _uc.emu_stop()

    h = uc.hook_add(unicorn.UC_HOOK_CODE, _stop_hook)
    try:
        def _run_cmp(*, prev_char: int, best_cnt: int, cand_char: int, s0_f: float, s1_f: float) -> int:
            uc.mem_write(best_info + 0x10, struct.pack("<Q", prev_char))
            uc.mem_write(best_info + 0x28, struct.pack("<I", best_cnt))
            uc.mem_write(best_info + 0x38, struct.pack("<f", s1_f))
            uc.reg_write(UC_ARM64_REG_SP, 0x30080000)
            uc.reg_write(UC_ARM64_REG_X22, phase)
            uc.reg_write(UC_ARM64_REG_X21, cand_char)
            uc.reg_write(UC_ARM64_REG_X8, best_info)
            uc.reg_write(UC_ARM64_REG_W9, best_cnt)
            uc.reg_write(UC_ARM64_REG_X20, 0xDEAD)
            uc.reg_write(UC_ARM64_REG_X23, 3)
            uc.reg_write(UC_ARM64_REG_X24, 0xCAFE)
            uc.reg_write(UC_ARM64_REG_X25, 999)
            uc.reg_write(UC_ARM64_REG_W6, 7)
            uc.reg_write(UC_ARM64_REG_S0, struct.unpack("<I", struct.pack("<f", s0_f))[0])
            uc.emu_start(base + target_rva, 0, count=400)
            assert uc.reg_read(UC_ARM64_REG_SP) == 0x30080000
            assert uc.reg_read(UC_ARM64_REG_X20) == 0xDEAD
            assert uc.reg_read(UC_ARM64_REG_X23) == 3
            assert uc.reg_read(UC_ARM64_REG_X24) == 0xCAFE
            assert uc.reg_read(UC_ARM64_REG_X25) == 999
            assert uc.reg_read(UC_ARM64_REG_X6) == 7
            return int(uc.reg_read(UC_ARM64_REG_PC))

        # First candidate (best_cnt == 0) always accepts
        assert _run_cmp(prev_char=0, best_cnt=0, cand_char=slot4, s0_f=1.0, s1_f=0.0) == accept_addr
        # 425% (slot 4) beats 244% (slot 3) even though slot 3 owns the lower team slot
        assert _run_cmp(prev_char=slot3, best_cnt=1, cand_char=slot4, s0_f=1.0, s1_f=0.2) == accept_addr
        # 244% (slot 3) loses to 650% (slot 2)
        assert _run_cmp(prev_char=slot2, best_cnt=1, cand_char=slot3, s0_f=0.1, s1_f=1.0) == reject_addr
        # An ally without an awakening skill never outranks one that has it
        assert _run_cmp(prev_char=slot2, best_cnt=1, cand_char=no_awake, s0_f=1.0, s1_f=0.1) == reject_addr
        assert _run_cmp(prev_char=no_awake, best_cnt=1, cand_char=slot3, s0_f=5.0, s1_f=4.0) == accept_addr
        # Equal power and same ally on another tile both replay the stock distance rule
        assert _run_cmp(prev_char=slot4, best_cnt=1, cand_char=slot5, s0_f=0.8, s1_f=0.8) == cont_addr
        assert _run_cmp(prev_char=slot3, best_cnt=1, cand_char=slot3, s0_f=0.8, s1_f=0.8) == cont_addr

        # Non-Merlin skill falls back to stock HP-rate rule: lower HP wins, higher HP continues
        uc.mem_write(phase + 0x38, struct.pack("<Q", other_skill))
        assert _run_cmp(prev_char=slot4, best_cnt=1, cand_char=slot5, s0_f=0.1, s1_f=1.0) == accept_addr
        assert _run_cmp(prev_char=slot4, best_cnt=1, cand_char=slot5, s0_f=1.0, s1_f=0.2) == cont_addr
    finally:
        uc.hook_del(h)
        uc.hook_del(lookup)


def test_unicorn_awaken_power_helper() -> None:
    """14.03: `awaken_power` ranks by summed damage multipliers of the Awakening skill."""
    _, uc, base = _setup_unicorn_runtime()
    _install_via_unicorn(uc)
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W0,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X22,
        UC_ARM64_REG_X30,
    )

    heap = _HeapAllocator(uc)
    rows = {
        9001: heap.make_effect_row(2.44),
        9002: heap.make_effect_row(3.23),
        9003: heap.make_effect_row(9.99, effect_type=8),  # stun: not damage
    }
    lookup = _install_effect_lookup(uc, base, rows)
    uc.mem_write(IL2CPP_BASE_CACHE, struct.pack("<Q", base))

    two_hits = heap.make_char(
        skills=[heap.make_skill(1053189, 1, awake=True, effect_ids=(9001, 9002, 9000))]
    )
    stun_only = heap.make_char(
        skills=[heap.make_skill(1053190, 1, awake=True, effect_ids=(9003,))]
    )
    not_awake = heap.make_char(
        skills=[heap.make_skill(1053191, 1, awake=False, effect_ids=(9002,))]
    )
    no_skills = heap.make_char()

    helper = PRIORITY_POWER_VADDR
    ret_sentinel = 0x10000100
    uc.mem_write(ret_sentinel, struct.pack("<I", 0xD503201F))
    uc.reg_write(UC_ARM64_REG_X30, ret_sentinel)

    def _rank(char: int) -> int:
        uc.reg_write(UC_ARM64_REG_SP, 0x30080000)
        uc.reg_write(UC_ARM64_REG_X2, char)
        uc.reg_write(UC_ARM64_REG_X19, 0x1111)
        uc.reg_write(UC_ARM64_REG_X22, 0x2222)
        uc.emu_start(helper, ret_sentinel, count=400)
        assert uc.reg_read(UC_ARM64_REG_SP) == 0x30080000
        assert uc.reg_read(UC_ARM64_REG_X19) == 0x1111
        assert uc.reg_read(UC_ARM64_REG_X22) == 0x2222
        return int(uc.reg_read(UC_ARM64_REG_W0) & 0xFFFFFFFF)

    try:
        # 2.44 + 3.23 = 5.67 -> rank 0x7FFF - 567; the unknown effect id is skipped
        assert _rank(two_hits) == 0x7FFF - 567
        # a stun-only awakening skill deals no damage
        assert _rank(stun_only) == 0x7FFF
        # a non-awakening skill is never read for power
        assert _rank(not_awake) == 0x7FFF
        # no skill container at all
        assert _rank(no_skills) == 0x7FFF
    finally:
        uc.hook_del(lookup)


# --------------------------------------------------------------------------
# Feature 14.02: InitActing hook body (skill priority over cell moves)
# --------------------------------------------------------------------------

_PRIORITY_CLIENT_RVAS = {
    "get_item": 0x2022E98,
    "is_enable": 0x1A36BA8,
    "init_method": 0xE4DCB4,
    "object_new": 0xE4DD80,
    "support_ctor": 0x20ECE08,
    "set_state": 0x217E748,
    "execute": 0x217E83C,
    "is_executed": 0x217E90C,
}
_PRIORITY_RESUME_STOCK = 0x1A35F78
_PRIORITY_RESUME_TAKEN = 0x1A35F7C
_PRIORITY_VTABLE_STUB = 0xB3F000  # spare slot in the mapped server code page
_MERLIN_SLOTS = [1053186, 1053187, 1053188, 1053185, 1053189]


def _run_priority_body(
    *,
    slot_ids: list[int | None] | None = None,
    enable: set[int] | None = None,
    vtable_accept: set[int] | None = None,
    executed: int = 1,
    char_type: int = 0,
    is_auto: int = 1,
    camp_type: int = 0,
    appointed_tile: int = 0,
    appointed_skill: int = -1,
    slot_one: bool = True,
    pre_used: int = -1,
    start: int = 4,
    stop: int = 0,
) -> tuple[str | None, list[tuple], object, int]:
    """Emulates the 14.02 body from the installed client stub and reports the exit.

    Returns (exit_name, calls, uc, ai_ptr) where exit_name is 'stock' or 'taken'.
    """
    unicorn, uc, base = _setup_unicorn_runtime()
    # client static data (base + 0x39AD548 .. base + 0x3CD46E5) lives past the
    # 0x3000000-byte client window the shared harness maps.
    uc.mem_map(0x13000000, 0x1000000)
    _install_via_unicorn(uc)

    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_W1,
        UC_ARM64_REG_W2,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X19,
    )

    heap = _HeapAllocator(uc)
    usage = heap.alloc(0x10)
    uc.mem_write(usage, struct.pack("<I", 0x11))
    typeinfo = heap.alloc(0x10)
    uc.mem_write(typeinfo, struct.pack("<Q", 0xCAFEBABE))
    uc.mem_write(base + 0x39AD548, struct.pack("<Q", usage))
    uc.mem_write(base + 0x39D78A0, struct.pack("<Q", typeinfo))
    uc.mem_write(base + 0x3CD46E5, b"\x00")

    wanted = _MERLIN_SLOTS if slot_ids is None else slot_ids
    skill_ptrs = [
        0 if skill_id is None else heap.make_skill(skill_id, 0, awake=False)
        for skill_id in wanted
    ]
    merlin = heap.make_char(skills=skill_ptrs, char_type=char_type, is_auto=is_auto)
    filler = heap.make_char()
    members = [merlin, filler] if slot_one else [filler, merlin]
    heap.make_camp(members, camp_type=camp_type)

    ai = heap.alloc(0x200)
    ctrl = heap.alloc(0x40)
    uct = heap.alloc(0x400)
    uc.mem_write(uct + 0x340, struct.pack("<Q", _PRIORITY_VTABLE_STUB))
    uc.mem_write(uct + 0x348, struct.pack("<Q", 0))
    uc.mem_write(ai, struct.pack("<Q", uct))
    uc.mem_write(ai + 0x18, struct.pack("<Q", merlin))
    uc.mem_write(ai + 0x58, struct.pack("<i", pre_used))
    uc.mem_write(ai + 0x70, struct.pack("<Q", ctrl))
    uc.mem_write(ai + 0x7C, struct.pack("<i", start))
    uc.mem_write(ai + 0x80, struct.pack("<i", stop))
    uc.mem_write(ai + 0x90, struct.pack("<Q", appointed_tile))
    uc.mem_write(ai + 0x98, struct.pack("<i", appointed_skill))

    enable = enable or set()
    vtable_accept = vtable_accept or set()
    state = heap.alloc(0x60)

    calls: list[tuple] = []
    exits: dict[str, str] = {}
    resume_stock = base + _PRIORITY_RESUME_STOCK
    resume_taken = base + _PRIORITY_RESUME_TAKEN
    for _name, rva in _PRIORITY_CLIENT_RVAS.items():
        uc.mem_write(base + rva, struct.pack("<I", 0xD65F03C0))
    for addr in (resume_stock, resume_taken, _PRIORITY_VTABLE_STUB):
        uc.mem_write(addr, struct.pack("<I", 0xD65F03C0))

    def _hook(_uc, address: int, _size: int, _user) -> None:
        if address in (resume_stock, resume_taken):
            exits["which"] = "stock" if address == resume_stock else "taken"
            _uc.emu_stop()
            return
        index = _uc.reg_read(UC_ARM64_REG_W1) & 0xFFFFFFFF
        if address == _PRIORITY_VTABLE_STUB:
            calls.append(("vtable", index, _uc.reg_read(UC_ARM64_REG_W2) & 1))
            _uc.reg_write(UC_ARM64_REG_X0, 1 if index in vtable_accept else 0)
            return
        for name, rva in _PRIORITY_CLIENT_RVAS.items():
            if address != base + rva:
                continue
            calls.append((name, index))
            if name == "get_item":
                _uc.reg_write(
                    UC_ARM64_REG_X0, skill_ptrs[index] if 0 <= index < len(skill_ptrs) else 0
                )
            elif name == "is_enable":
                _uc.reg_write(UC_ARM64_REG_X0, 1 if index in enable else 0)
            elif name == "object_new":
                _uc.reg_write(UC_ARM64_REG_X0, state)
            elif name == "is_executed":
                _uc.reg_write(UC_ARM64_REG_X0, executed)
            return

    h = uc.hook_add(unicorn.UC_HOOK_CODE, _hook)
    try:
        sp0 = 0x30080000
        uc.reg_write(UC_ARM64_REG_SP, sp0)
        uc.reg_write(UC_ARM64_REG_X0, ai)
        uc.reg_write(UC_ARM64_REG_X19, ai)
        uc.emu_start(base + PRIORITY_CLIENT_SITE, 0, count=4000)
        assert uc.reg_read(UC_ARM64_REG_SP) == sp0, "body must restore sp on both exits"
        assert uc.reg_read(UC_ARM64_REG_X19) == ai, "body must preserve x19"
    finally:
        uc.hook_del(h)
    return exits.get("which"), calls, uc, ai


def test_unicorn_priority_body_casts_magic_infusion_over_cell() -> None:
    exit_name, calls, _uc, _ai = _run_priority_body()
    assert exit_name == "taken"
    names = [row[0] for row in calls]
    assert "vtable" not in names  # Awake rung was not usable
    assert ("support_ctor", 2) in calls
    assert [row[0] for row in calls][-4:] == [
        "support_ctor",
        "set_state",
        "execute",
        "is_executed",
    ]


def test_unicorn_priority_body_falls_back_to_cell_when_support_declines() -> None:
    exit_name, calls, _uc, _ai = _run_priority_body(executed=0)
    assert exit_name == "stock"
    # the full support sequence still ran, it just declined
    assert [row[0] for row in calls][-4:] == [
        "support_ctor",
        "set_state",
        "execute",
        "is_executed",
    ]


def test_unicorn_priority_body_casts_awake_when_usable() -> None:
    exit_name, calls, _uc, _ai = _run_priority_body(
        enable={4}, vtable_accept={4}, executed=1
    )
    assert exit_name == "taken"
    assert ("vtable", 4, 1) in calls
    # the Awakening rung accepted the turn, so Magic infusion was never attempted
    assert not any(row[0] == "support_ctor" for row in calls)


def test_unicorn_priority_body_awake_declined_falls_through_to_support() -> None:
    exit_name, calls, _uc, _ai = _run_priority_body(enable={4}, vtable_accept=set())
    assert exit_name == "taken"
    assert ("vtable", 4, 1) in calls
    assert ("support_ctor", 2) in calls


@pytest.mark.parametrize(
    "override",
    [
        {"slot_one": False},
        {"is_auto": 0},
        {"char_type": 6},
        {"camp_type": 1},
        {"appointed_tile": 0x1234},
        {"appointed_skill": 2},
    ],
    ids=[
        "slot-2",
        "manual",
        "mercenary",
        "enemy-camp",
        "semi-auto-tile",
        "semi-auto-skill",
    ],
)
def test_unicorn_priority_body_guard_matrix_exits_stock_without_calls(override) -> None:
    exit_name, calls, _uc, _ai = _run_priority_body(**override)
    assert exit_name == "stock"
    assert calls == [], "guard must reject before any client call"


@pytest.mark.parametrize(
    "override",
    [
        {"slot_ids": [1053186, 1053187, 1053170, 1053185, 1053189]},
        {"pre_used": 2},
    ],
    ids=["no-magic-infusion", "pre-used-skill"],
)
def test_unicorn_priority_body_scan_misses_exit_stock(override) -> None:
    exit_name, calls, _uc, _ai = _run_priority_body(**override)
    assert exit_name == "stock"
    # the scan legitimately reads skill slots, but nothing is ever cast
    assert {row[0] for row in calls} <= {"get_item"}
    assert not any(row[0] in {"vtable", "support_ctor"} for row in calls)

