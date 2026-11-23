"""Tests for hero Trait (Potential) max-quality and duplicate-slot patches."""

from __future__ import annotations

import struct

import pytest

capstone = pytest.importorskip("capstone")
unicorn = pytest.importorskip("unicorn")

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_FP,
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X27,
    UC_ARM64_REG_X28,
)

from core.core_patches import (
    ELF_SEGMENTS,
    EXPECTED_PATCH_COUNTS,
    POTENTIAL_DATA_ROW_COUNT,
    POTENTIAL_DATA_ROW_SIZE,
    POTENTIAL_DATA_TABLE_VADDR,
    POTENTIAL_DATA_WEIGHT_COUNT,
    POTENTIAL_DATA_WEIGHT_OFFSET,
    POTENTIAL_DEDUP_ORIGINAL,
    POTENTIAL_DEDUP_REPLACEMENT,
    POTENTIAL_DEDUP_SITE,
    POTENTIAL_DEDUP_TARGET,
    POTENTIAL_GRADE_ROW_SIZE,
    POTENTIAL_GRADE_TABLE_VADDR,
    POTENTIAL_IMMUNITY_ROWS,
    POTENTIAL_IMMUNITY_WEIGHT,
    POTENTIAL_MULTI_UNIQUE_BATCH_CALL_VADDR,
    POTENTIAL_MULTI_UNIQUE_BATCH_INIT_VADDR,
    POTENTIAL_MULTI_UNIQUE_CAVE_BYTES,
    POTENTIAL_MULTI_UNIQUE_CAVE_SIZE,
    POTENTIAL_MULTI_UNIQUE_CAVE_VADDR,
    POTENTIAL_MULTI_UNIQUE_PASS1_FILTER_VADDR,
    POTENTIAL_MULTI_UNIQUE_PASS2_EMPTY_VADDR,
    POTENTIAL_MULTI_UNIQUE_PASS2_FILTER_VADDR,
    POTENTIAL_TOP_QUALITY,
    PatchOptions,
    apply_all_patches,
    apply_trait_allow_duplicates,
    apply_trait_immunity_weight_x2,
    apply_trait_max_quality,
    apply_trait_multi_unique,
    encode_arm64_branch,
    potential_immunity_weight_state,
    potential_multi_unique_sites,
    potential_top_quality_state,
    seg_offset,
)
from core.patch_inspector import expected_feature_keys, inspect_native_so
from fwt_patcher import build_parser

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def _disasm(blob: bytes, addr: int) -> list[str]:
    return [f"{insn.mnemonic} {insn.op_str}" for insn in MD.disasm(blob, addr)]


def _synthetic_trait_so() -> bytearray:
    """Builds a minimal canonical-layout buffer covering trait tables and site."""
    size = max(
        seg_offset(POTENTIAL_DATA_TABLE_VADDR) + POTENTIAL_DATA_ROW_COUNT * POTENTIAL_DATA_ROW_SIZE,
        seg_offset(POTENTIAL_GRADE_TABLE_VADDR) + POTENTIAL_DATA_ROW_COUNT * POTENTIAL_GRADE_ROW_SIZE,
        seg_offset(POTENTIAL_DEDUP_SITE) + 4,
    )
    # Place valid ELF64 PT_LOAD headers matching ELF_SEGMENTS so inspect_native_so accepts it.
    seg_end_max = max(end - delta for _start, end, delta in ELF_SEGMENTS)
    buf = bytearray(max(size, seg_end_max))
    buf[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", buf, 18, 183)
    struct.pack_into("<Q", buf, 32, 64)
    struct.pack_into("<HH", buf, 54, 56, len(ELF_SEGMENTS))
    for i, (start, end, delta) in enumerate(ELF_SEGMENTS):
        file_off = start - delta
        filesz = end - start
        struct.pack_into(
            "<IIQQQQQQ",
            buf,
            64 + i * 56,
            1,
            5,
            file_off,
            start,
            start,
            filesz,
            filesz,
            1,
        )
    data_off = seg_offset(POTENTIAL_DATA_TABLE_VADDR)
    grade_off = seg_offset(POTENTIAL_GRADE_TABLE_VADDR)
    immunity_by_row = {
        row_idx: (pid, ptype, col, orig_weight)
        for row_idx, pid, ptype, col, orig_weight in POTENTIAL_IMMUNITY_ROWS
    }
    for idx in range(POTENTIAL_DATA_ROW_COUNT):
        if idx in immunity_by_row:
            pid, ptype, col, orig_weight = immunity_by_row[idx]
            weights = [0] * POTENTIAL_DATA_WEIGHT_COUNT
            weights[col] = orig_weight
            grade = POTENTIAL_TOP_QUALITY
        else:
            pid = 1000 + idx
            ptype = 1 if idx < 5 else (2 if idx < 10 else 10 + idx)
            weights = [0] * POTENTIAL_DATA_WEIGHT_COUNT
            grade = 5
            if idx < 5:
                weights[0] = (5 - idx) * 100
                grade = idx + 1
            elif idx < 10:
                weights[0] = 250
                grade = 5 if idx in (8, 9) else 2
        struct.pack_into(
            f"<2i{POTENTIAL_DATA_WEIGHT_COUNT}i",
            buf,
            data_off + idx * POTENTIAL_DATA_ROW_SIZE,
            pid,
            ptype,
            *weights,
        )
        struct.pack_into(
            "<3i",
            buf,
            grade_off + idx * POTENTIAL_GRADE_ROW_SIZE,
            pid,
            grade,
            100 + grade * 20,
        )
    buf[seg_offset(POTENTIAL_DEDUP_SITE) : seg_offset(POTENTIAL_DEDUP_SITE) + 4] = (
        POTENTIAL_DEDUP_ORIGINAL
    )
    for _label, site, original, _replacement in potential_multi_unique_sites():
        off = seg_offset(site)
        buf[off : off + len(original)] = original
    return buf


def _potential_pools(
    so_bytes: bytes,
) -> dict[tuple[int, int], list[tuple[int, int, int]]]:
    data_off = seg_offset(POTENTIAL_DATA_TABLE_VADDR)
    grade_off = seg_offset(POTENTIAL_GRADE_TABLE_VADDR)
    pools: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
    for idx in range(POTENTIAL_DATA_ROW_COUNT):
        row_off = data_off + idx * POTENTIAL_DATA_ROW_SIZE
        pid, ptype = struct.unpack_from("<2i", so_bytes, row_off)
        weights = struct.unpack_from(
            f"<{POTENTIAL_DATA_WEIGHT_COUNT}i",
            so_bytes,
            row_off + POTENTIAL_DATA_WEIGHT_OFFSET,
        )
        _gid, grade, _cp = struct.unpack_from(
            "<3i", so_bytes, grade_off + idx * POTENTIAL_GRADE_ROW_SIZE
        )
        for col, weight in enumerate(weights):
            if weight > 0:
                pools.setdefault((ptype, col), []).append((pid, weight, grade))
    return pools


def test_trait_dedup_branch_encoding_and_disassembly() -> None:
    assert (
        encode_arm64_branch(POTENTIAL_DEDUP_SITE, POTENTIAL_DEDUP_TARGET)
        == POTENTIAL_DEDUP_REPLACEMENT
    )
    assert _disasm(POTENTIAL_DEDUP_ORIGINAL, POTENTIAL_DEDUP_SITE) == [
        f"b.eq #0x{POTENTIAL_DEDUP_TARGET:x}"
    ]
    assert _disasm(POTENTIAL_DEDUP_REPLACEMENT, POTENTIAL_DEDUP_SITE) == [
        f"b #0x{POTENTIAL_DEDUP_TARGET:x}"
    ]


def test_synthetic_trait_max_quality_and_validation() -> None:
    buf = _synthetic_trait_so()
    before = _potential_pools(bytes(buf))
    changed = apply_trait_max_quality(buf)
    assert changed == 10
    after = _potential_pools(bytes(buf))
    assert set(after) == set(before)
    for key, members in after.items():
        assert all(grade == POTENTIAL_TOP_QUALITY for _pid, _w, grade in members)
        assert sum(w for _pid, w, _g in members) == sum(w for _pid, w, _g in before[key])
    # Idempotency (2 synthetic pools + 3 immunity pools)
    assert potential_top_quality_state(bytes(buf)) == ({}, 5)
    assert apply_trait_max_quality(buf) == 0

    # Validation errors
    bad_id = _synthetic_trait_so()
    struct.pack_into("<i", bad_id, seg_offset(POTENTIAL_GRADE_TABLE_VADDR), 999999)
    with pytest.raises(ValueError, match="names id"):
        apply_trait_max_quality(bad_id)

    bad_grade = _synthetic_trait_so()
    struct.pack_into("<i", bad_grade, seg_offset(POTENTIAL_GRADE_TABLE_VADDR) + 4, 6)
    with pytest.raises(ValueError, match="out of range"):
        apply_trait_max_quality(bad_grade)

    bad_weight = _synthetic_trait_so()
    struct.pack_into(
        "<i",
        bad_weight,
        seg_offset(POTENTIAL_DATA_TABLE_VADDR) + POTENTIAL_DATA_WEIGHT_OFFSET,
        -1,
    )
    with pytest.raises(ValueError, match="negative"):
        apply_trait_max_quality(bad_weight)


def test_synthetic_trait_allow_duplicates_and_inspector() -> None:
    buf = _synthetic_trait_so()
    assert apply_trait_allow_duplicates(buf) == 1
    assert apply_trait_allow_duplicates(buf) == 0
    assert (
        bytes(buf[seg_offset(POTENTIAL_DEDUP_SITE) : seg_offset(POTENTIAL_DEDUP_SITE) + 4])
        == POTENTIAL_DEDUP_REPLACEMENT
    )

    bad = _synthetic_trait_so()
    bad[seg_offset(POTENTIAL_DEDUP_SITE) : seg_offset(POTENTIAL_DEDUP_SITE) + 4] = b"\x00\x00\x00\x00"
    with pytest.raises(ValueError, match="Unexpected"):
        apply_trait_allow_duplicates(bad)

    report = inspect_native_so(bytes(buf))
    assert report["trait_allow_duplicates"].active is True
    assert report["trait_max_quality"].active is False

    apply_trait_max_quality(buf)
    report2 = inspect_native_so(bytes(buf))
    assert report2["trait_max_quality"].active is True
    assert report2["trait_allow_duplicates"].active is True


def test_trait_dedup_bypass_unicorn_emulation() -> None:
    """Emulates the 0x8BFF70..0x8C00F0 vector-cleanup bypass in Unicorn."""
    code_base = 0x8BF000
    stack_base = 0x900000
    heap_buf = 0x910000
    free_stub = 0xB45EE0

    # Patch site at 0x8BFF74: patched instruction + cleanup stub at 0x8C00F0..0x8C0138.
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(code_base, 0x4000)
    uc.mem_map(stack_base, 0x4000)
    uc.mem_map(0xB45000, 0x2000)

    # Place cmp x28, x20; b 0x8C00F0 at 0x8BFF70..0x8BFF78
    uc.mem_write(0x8BFF70, bytes.fromhex("9f0314eb") + POTENTIAL_DEDUP_REPLACEMENT)
    # At 0x8BFF78 (if branch NOT taken): trap marker -> write x0 = 0xDEAD and stop
    trap_addr = 0x8BFF78
    # At 0x8C00F0: cbz x28, 0x8C0138; mov x0, x28; stur x28, [x29, #-0x30]; bl 0xB45EE0
    # 0x8C0138: target reached cleanly
    cleanup = (
        bytes.fromhex("5c0200b4")  # cbz x28, #0x8c0138
        + bytes.fromhex("e0031caa")  # mov x0, x28
        + bytes.fromhex("bc031df8")  # stur x28, [x29, #-0x30]
        + encode_arm64_branch(0x8C00FC, free_stub, link=True)
    )
    uc.mem_write(0x8C00F0, cleanup)
    # free_stub just returns (`ret`)
    uc.mem_write(free_stub, bytes.fromhex("c0035fd6"))

    fp = stack_base + 0x2000
    uc.reg_write(UC_ARM64_REG_SP, stack_base + 0x1000)
    uc.reg_write(UC_ARM64_REG_FP, fp)
    uc.reg_write(UC_ARM64_REG_LR, 0x8C0138)
    # Simulate non-empty vector (x28 != x20) and zero-initialized std::set size at [x29, #-0x10]
    uc.reg_write(UC_ARM64_REG_X28, heap_buf)
    uc.reg_write(UC_ARM64_REG_X20, heap_buf + 0x18)
    uc.mem_write(fp - 0x10, struct.pack("<Q", 0))

    uc.emu_start(0x8BFF70, 0x8C0100, count=20)
    assert uc.reg_read(UC_ARM64_REG_X0) == heap_buf
    assert struct.unpack("<Q", uc.mem_read(fp - 0x10, 8))[0] == 0
    assert uc.reg_read(UC_ARM64_REG_SP) == stack_base + 0x1000
    assert trap_addr != 0x8C00F0


def test_trait_cli_flags_and_expected_feature_keys() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "--trait-max-quality",
            "--trait-allow-duplicates",
            "--trait-multi-unique",
            "--trait-immunity-weight-x2",
        ]
    )
    assert args.trait_max_quality is True
    assert args.trait_allow_duplicates is True
    assert args.trait_multi_unique is True
    assert args.trait_immunity_weight_x2 is True

    keys = expected_feature_keys(
        PatchOptions(
            trait_max_quality=True,
            trait_allow_duplicates=True,
            trait_multi_unique=True,
            trait_immunity_weight_x2=True,
        )
    )
    assert keys["trait_max_quality"] == "Traits: Max Quality Rolls"
    assert keys["trait_allow_duplicates"] == "Allow Duplicate Hero Traits"
    assert keys["trait_multi_unique"] == "Traits: Unique Batch Rolls"
    assert keys["trait_immunity_weight_x2"] == "Traits: Immunity Weight x2 (Slots 3-5)"


def test_trait_multi_unique_cave_encoding_and_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib

    import core.core_patches as core_patches

    decoded = list(MD.disasm(POTENTIAL_MULTI_UNIQUE_CAVE_BYTES, POTENTIAL_MULTI_UNIQUE_CAVE_VADDR))
    assert len(decoded) * 4 == POTENTIAL_MULTI_UNIQUE_CAVE_SIZE == 240
    assert POTENTIAL_MULTI_UNIQUE_CAVE_VADDR + POTENTIAL_MULTI_UNIQUE_CAVE_SIZE <= 0xB2B750

    zero_cave_sha = hashlib.sha256(b"\x00" * POTENTIAL_MULTI_UNIQUE_CAVE_SIZE).hexdigest()
    monkeypatch.setattr(
        core_patches, "POTENTIAL_MULTI_UNIQUE_CAVE_ORIGINAL_SHA256", zero_cave_sha
    )

    buf = _synthetic_trait_so()
    assert apply_trait_multi_unique(buf) == EXPECTED_PATCH_COUNTS["trait_multi_unique"] == 7
    assert apply_trait_multi_unique(buf) == 0

    for _label, site, _orig, repl in potential_multi_unique_sites():
        off = seg_offset(site)
        assert bytes(buf[off : off + len(repl)]) == repl

    # Mismatched hook byte fails before touching any site or cave.
    bad = _synthetic_trait_so()
    bad_off = seg_offset(potential_multi_unique_sites()[-1][1])
    bad[bad_off : bad_off + 4] = b"\x00\x00\x00\x00"
    before_bad = bytes(bad)
    with pytest.raises(ValueError, match="Unexpected instruction"):
        apply_trait_multi_unique(bad)
    assert bytes(bad) == before_bad

    # Mismatched original cave byte fails before touching any site or cave.
    bad_cave = _synthetic_trait_so()
    bad_cave[seg_offset(POTENTIAL_MULTI_UNIQUE_CAVE_VADDR)] ^= 0xFF
    before_cave = bytes(bad_cave)
    with pytest.raises(ValueError, match="Unexpected trait multi unique cave"):
        apply_trait_multi_unique(bad_cave)
    assert bytes(bad_cave) == before_cave

    report = inspect_native_so(bytes(buf))
    assert report["trait_multi_unique"].active is True


def test_synthetic_trait_immunity_weight_x2_and_commutativity() -> None:
    buf_a = _synthetic_trait_so()
    assert potential_immunity_weight_state(bytes(buf_a)) == (0, 3, 3)
    assert apply_trait_immunity_weight_x2(buf_a) == EXPECTED_PATCH_COUNTS["trait_immunity_weight_x2"] == 3
    assert apply_trait_immunity_weight_x2(buf_a) == 0
    assert potential_immunity_weight_state(bytes(buf_a)) == (3, 0, 3)
    apply_trait_max_quality(buf_a)

    # Applying max_quality before immunity_weight_x2 produces the exact same buffer.
    buf_b = _synthetic_trait_so()
    apply_trait_max_quality(buf_b)
    apply_trait_immunity_weight_x2(buf_b)
    assert bytes(buf_a) == bytes(buf_b)

    report = inspect_native_so(bytes(buf_a))
    assert report["trait_immunity_weight_x2"].active is True
    assert report["trait_max_quality"].active is True

    bad_pid = _synthetic_trait_so()
    struct.pack_into(
        "<i",
        bad_pid,
        seg_offset(POTENTIAL_DATA_TABLE_VADDR) + 300 * POTENTIAL_DATA_ROW_SIZE,
        999999,
    )
    with pytest.raises(ValueError, match="Unexpected potential immunity row"):
        apply_trait_immunity_weight_x2(bad_pid)

    bad_weight = _synthetic_trait_so()
    struct.pack_into(
        "<i",
        bad_weight,
        seg_offset(POTENTIAL_DATA_TABLE_VADDR)
        + 301 * POTENTIAL_DATA_ROW_SIZE
        + POTENTIAL_DATA_WEIGHT_OFFSET
        + 12 * 4,
        12345,
    )
    with pytest.raises(ValueError, match="Unexpected immunity weight"):
        apply_trait_immunity_weight_x2(bad_weight)


def test_trait_multi_unique_unicorn_emulation() -> None:
    """Emulates batch_init, batch_choose, pass1_filter, pass2_filter, and pass2_empty."""
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x6CB000, 0x8000)   # kFwtPotentialDataRows at 0x6CBBC8
    uc.mem_map(0x8BF000, 0x3000)   # choose_potential_code_json stub + targets
    uc.mem_map(0xB2B000, 0x2000)   # cave at 0xB2B530
    uc.mem_map(0x900000, 0x4000)   # stack

    uc.mem_write(POTENTIAL_MULTI_UNIQUE_CAVE_VADDR, POTENTIAL_MULTI_UNIQUE_CAVE_BYTES)
    # Populate table row 300 (id=35001, ptype=35) and row 10 (id=1010, ptype=4)
    uc.mem_write(0x6CBBC8 + 300 * POTENTIAL_DATA_ROW_SIZE, struct.pack("<2i", 35001, 35))
    uc.mem_write(0x6CBBC8 + 10 * POTENTIAL_DATA_ROW_SIZE, struct.pack("<2i", 1010, 4))

    # Stub choose_potential_code_json at 0x8BFDF0: returns x22 as chosen id and captures x4 in x23
    # (mov x23, x4; mov x0, x22; ret -> e.g. aa1603e0 / c0035fd6)
    ks_ret = bytes.fromhex("f70304aa") + bytes.fromhex("e00316aa") + bytes.fromhex("c0035fd6")
    uc.mem_write(0x8BFDF0, ks_ret)

    sp = 0x902000
    fp = 0x903000
    stop = 0x8C0FF0
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_FP, fp)

    # 1. batch_init resets x27=0 and sets w24=1
    uc.reg_write(UC_ARM64_REG_X27, 0x123456789)
    uc.reg_write(UC_ARM64_REG_X24, 0)
    uc.reg_write(UC_ARM64_REG_LR, stop)
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_BATCH_INIT_VADDR, stop, count=10)
    assert uc.reg_read(UC_ARM64_REG_X24) == 1
    assert uc.reg_read(UC_ARM64_REG_X27) == 0

    # 2. batch_choose records ptype=35 then ptype=4 into x27 and forwards (mask<<1)|1 in x4
    from unicorn.arm64_const import UC_ARM64_REG_X22, UC_ARM64_REG_X23

    uc.reg_write(UC_ARM64_REG_X22, 35001)
    uc.reg_write(UC_ARM64_REG_LR, stop)
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_BATCH_CALL_VADDR, stop, count=5000)
    assert uc.reg_read(UC_ARM64_REG_PC) == stop
    assert uc.reg_read(UC_ARM64_REG_X0) == 35001
    assert uc.reg_read(UC_ARM64_REG_X23) == 1  # first draw sees empty batch mask
    assert uc.reg_read(UC_ARM64_REG_X27) == (1 << 35)

    uc.reg_write(UC_ARM64_REG_X22, 1010)
    uc.reg_write(UC_ARM64_REG_LR, stop)
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_BATCH_CALL_VADDR, stop, count=5000)
    assert uc.reg_read(UC_ARM64_REG_PC) == stop
    assert uc.reg_read(UC_ARM64_REG_X0) == 1010
    assert uc.reg_read(UC_ARM64_REG_X23) == (((1 << 35) << 1) | 1)
    assert uc.reg_read(UC_ARM64_REG_X27) == ((1 << 35) | (1 << 4))

    # 3. pass1_filter skips ptype=35 (to 0x8C01A8) and keeps ptype=1 (restoring [fp-0x10] to x8)
    mask_flags = (((1 << 35) | (1 << 4)) << 1) | 1
    uc.mem_write(sp + 0x40, struct.pack("<Q", mask_flags))
    uc.mem_write(fp - 0x10, struct.pack("<Q", 0xCAFEBABE))
    uc.mem_write(0x903800, struct.pack("<2i", 35001, 35))
    uc.reg_write(UC_ARM64_REG_X19, 0x903800)
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_PASS1_FILTER_VADDR, 0x8C01A8, count=20)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x8C01A8

    uc.mem_write(0x903800, struct.pack("<2i", 1001, 1))
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_PASS1_FILTER_VADDR, 0x8C01EC, count=20)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x8C01EC
    assert uc.reg_read(UC_ARM64_REG_X8) == 0xCAFEBABE

    # 4. pass2_filter skips ptype=4 (to 0x8C04E4) and passes all when single-roll (flags == 1)
    uc.mem_write(fp - 0x28, struct.pack("<Q", 0xBEEF1234))
    uc.mem_write(0x903800, struct.pack("<2i", 1010, 4))
    uc.reg_write(UC_ARM64_REG_X21, 0x903800)
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_PASS2_FILTER_VADDR, 0x8C04E4, count=20)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x8C04E4

    uc.mem_write(sp + 0x40, struct.pack("<Q", 1))  # single roll: batch mask == 0
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_PASS2_FILTER_VADDR, 0x8C0528, count=20)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x8C0528
    assert uc.reg_read(UC_ARM64_REG_X8) == 0xBEEF1234

    # 5. pass2_empty: non-empty -> 0x8C07D0; empty w/ batch mask -> clear mask (keep bit 0) & replay 0x8C04C8; empty w/o mask -> 0x8C0D24
    uc.reg_write(UC_ARM64_REG_X26, 0x903900)
    uc.reg_write(UC_ARM64_REG_X28, 0x903908)
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_PASS2_EMPTY_VADDR, 0x8C07D0, count=10)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x8C07D0

    uc.mem_write(sp + 0x40, struct.pack("<Q", mask_flags))
    uc.reg_write(UC_ARM64_REG_X28, 0x903900)  # empty vector
    uc.emu_start(POTENTIAL_MULTI_UNIQUE_PASS2_EMPTY_VADDR, 0x8C04C8, count=20)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x8C04C8
    assert struct.unpack("<Q", uc.mem_read(sp + 0x40, 8))[0] == 1  # bit 0 preserved!

    uc.emu_start(POTENTIAL_MULTI_UNIQUE_PASS2_EMPTY_VADDR, 0x8C0D24, count=20)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x8C0D24


def test_trait_patches_against_reference_so(reference_buffers) -> None:
    original, dex = reference_buffers
    before = _potential_pools(original)
    assert len(before) == 58

    result = apply_all_patches(
        original,
        dex,
        PatchOptions(
            trait_max_quality=True,
            trait_allow_duplicates=True,
            trait_multi_unique=True,
            trait_immunity_weight_x2=True,
        ),
    )
    assert result.counts["trait_max_quality"] == EXPECTED_PATCH_COUNTS["trait_max_quality"] == 130
    assert (
        result.counts["trait_allow_duplicates"]
        == EXPECTED_PATCH_COUNTS["trait_allow_duplicates"]
        == 1
    )
    assert (
        result.counts["trait_multi_unique"]
        == EXPECTED_PATCH_COUNTS["trait_multi_unique"]
        == 7
    )
    assert (
        result.counts["trait_immunity_weight_x2"]
        == EXPECTED_PATCH_COUNTS["trait_immunity_weight_x2"]
        == 3
    )

    after = _potential_pools(result.so_bytes)
    assert set(after) == set(before)
    immunity_cols = {(35, 6), (36, 12), (37, 9)}
    for key, members in after.items():
        assert len(members) == 1
        assert members[0][2] == POTENTIAL_TOP_QUALITY
        expected_weight = (
            POTENTIAL_IMMUNITY_WEIGHT
            if key in immunity_cols
            else sum(w for _pid, w, _g in before[key])
        )
        assert members[0][1] == expected_weight

    # Idempotency on second pass
    second_buf = bytearray(result.so_bytes)
    assert apply_trait_max_quality(second_buf) == 0
    assert apply_trait_allow_duplicates(second_buf) == 0
    assert apply_trait_multi_unique(second_buf) == 0
    assert apply_trait_immunity_weight_x2(second_buf) == 0
    assert bytes(second_buf) == result.so_bytes

    report = inspect_native_so(result.so_bytes)
    assert report["trait_max_quality"].active is True
    assert report["trait_allow_duplicates"].active is True
    assert report["trait_multi_unique"].active is True
    assert report["trait_immunity_weight_x2"].active is True
