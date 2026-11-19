"""Phase 3 + 4: the dispatch-log cave with a persistent hit counter.

Two levels of proof, because "the bytes look right" is not a test:

* **emulation** (unicorn) runs the cave the way the CPU would — the hook branch,
  the saved registers, the guarded ``mprotect``, the counter increment, the ``bl``
  into the ``__android_log_print`` PLT stub (stubbed with ``ret`` and
  instrumented), the truncation argument, the replayed ``sub sp, sp, #0x90`` and
  the branch back to the real function;
* the encoder self-test disassembles the cave with capstone and checks every
  mnemonic, so a wrong opcode cannot pass silently.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import pytest

from core.core_patches import (
    DEV_COUNTER_MAGIC_OFFSET,
    DEV_COUNTER_VALUE_OFFSET,
    DEV_DUMP_FLAG_OFFSET,
    DEV_DUMP_RESPONSE,
    DEV_LOG_CAVE_SIZE,
    DEV_LOG_CAVE_VADDR,
    DEV_LOG_HOOK_ORIGINAL,
    DEV_LOG_HOOK_VADDR,
    DEV_LOG_PLT_MPROTECT,
    DEV_LOG_PLT_PRINT,
    DEV_MARKER_MAGIC_OFFSET,
    DEV_MARKER_TAG,
    DEV_SRET_OFFSET,
    DEV_START_TICK_OFFSET,
    DEV_TIMING_CAVE_SIZE,
    DEV_TIMING_CAVE_VADDR,
    DEV_TIMING_HOOK_SITES,
    DEV_TIMING_RET,
    _build_dev_log_cave,
    _build_dev_timing_cave,
    apply_dev_dispatch_log,
    apply_dev_handler_timing,
    dev_build_marker,
    dev_log_tag,
    encode_add_imm,
    encode_add_sp,
    encode_add_w_imm,
    encode_adrp,
    encode_cbnz_w,
    encode_ldp_sp,
    encode_ldr_w,
    encode_ldr_x,
    encode_ldrb,
    encode_mov_w,
    encode_movk_x,
    encode_movz_w,
    encode_movz_x,
    encode_mrs_cntfrq,
    encode_mrs_cntvct,
    encode_mul,
    encode_ret,
    encode_stp_pre_index,
    encode_stp_sp,
    encode_str_w,
    encode_str_x,
    encode_strb,
    encode_sub_sp,
    encode_sub_x,
    encode_udiv,
    find_dev_build_marker,
    seg_offset,
)

HOOK_AFTER = DEV_LOG_HOOK_VADDR + 4
RET = struct.pack("<I", 0xD65F03C0)
BRANCH_TO_CAVE = struct.pack(
    "<I", 0x14000000 | (((DEV_LOG_CAVE_VADDR - DEV_LOG_HOOK_VADDR) // 4) & 0x03FFFFFF)
)


# -- encoders -------------------------------------------------------------
def test_encoders_round_trip_through_capstone():
    pytest.importorskip("capstone")
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cases = [
        (encode_sub_sp(0x90), "sub", "sp, sp, #0x90"),
        (encode_add_sp(0x60), "add", "sp, sp, #0x60"),
        (encode_stp_sp(0, 1, 0x10), "stp", "x0, x1, [sp, #0x10]"),
        (encode_ldp_sp(8, 9, 0x30), "ldp", "x8, x9, [sp, #0x30]"),
        (encode_str_w(11, 10, 0), "str", "w11, [x10]"),
        (encode_ldr_w(11, 10, 0), "ldr", "w11, [x10]"),
        (encode_ldrb(8, 9, 0), "ldrb", "w8, [x9]"),
        (encode_strb(8, 9, 0), "strb", "w8, [x9]"),
        (encode_movz_x(1, 0x1000), "mov", "x1, #0x1000"),
        (encode_mov_w(3, 11), "add", "w3, w11, #0"),  # mov w3, w11
        (encode_add_w_imm(11, 11, 1), "add", "w11, w11, #1"),
        (encode_movz_w(0, 4), "mov", "w0, #4"),
        (encode_add_imm(1, 1, 0x120), "add", "x1, x1, #0x120"),
    ]
    for blob, mnemonic, operands in cases:
        (instruction,) = list(decoder.disasm(blob, 0))
        assert instruction.mnemonic == mnemonic, (blob.hex(), instruction.mnemonic)
        assert instruction.op_str == operands, (blob.hex(), instruction.op_str)


def test_cbnz_encodes_the_right_target():
    pytest.importorskip("capstone")
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    pc = DEV_LOG_CAVE_VADDR + 0x24
    target = DEV_LOG_CAVE_VADDR + 0x40
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    (instruction,) = list(decoder.disasm(encode_cbnz_w(8, pc, target), pc))
    assert instruction.mnemonic == "cbnz"
    assert int(instruction.op_str.split("#")[1], 16) == target


def test_stp_pre_index_matches_the_real_hook_instruction():
    """The encoder must reproduce the byte at the hook site exactly."""
    assert encode_stp_pre_index(29, 30, -0x60) == DEV_LOG_HOOK_ORIGINAL


def test_adrp_pages():
    pytest.importorskip("capstone")
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    pc, target = DEV_LOG_CAVE_VADDR, DEV_LOG_CAVE_VADDR + 0x100
    (instruction,) = list(decoder.disasm(encode_adrp(pc, target, 1), pc))
    assert instruction.mnemonic == "adrp"
    page = int(instruction.op_str.split("#")[1], 16)
    assert page == target & ~0xFFF


# -- the cave ------------------------------------------------------------
def test_cave_fits_the_budget():
    cave = _build_dev_log_cave(DEV_LOG_CAVE_VADDR, limit=1024, version="9.9.9")
    assert len(cave) <= DEV_LOG_CAVE_SIZE
    assert len(cave) % 4 == 0


def test_cave_starts_with_its_own_frame():
    """First instruction of the cave must not touch the incoming arguments."""
    cave = _build_dev_log_cave(DEV_LOG_CAVE_VADDR, limit=64)
    assert cave[:4] == encode_sub_sp(0x90)


def test_cave_state_block_starts_zeroed():
    """Magic byte and counter must be zero in the file: the magic gates mprotect."""
    cave = _build_dev_log_cave(DEV_LOG_CAVE_VADDR, limit=1024, version="9.9.9")
    assert cave[DEV_COUNTER_MAGIC_OFFSET] == 0
    counter = cave[DEV_COUNTER_VALUE_OFFSET : DEV_COUNTER_VALUE_OFFSET + 4]
    assert counter == b"\x00\x00\x00\x00"


def test_cave_contains_both_plt_calls():
    cave = _build_dev_log_cave(DEV_LOG_CAVE_VADDR, limit=1024, version="9.9.9")
    assert any(
        cave[offset : offset + 4]
        == struct.pack(
            "<I",
            0x94000000
            | (((DEV_LOG_PLT_MPROTECT - (DEV_LOG_CAVE_VADDR + offset)) // 4) & 0x03FFFFFF),
        )
        for offset in range(0, len(cave) - 4, 4)
    )
    assert any(
        cave[offset : offset + 4]
        == struct.pack(
            "<I",
            0x94000000
            | (((DEV_LOG_PLT_PRINT - (DEV_LOG_CAVE_VADDR + offset)) // 4) & 0x03FFFFFF),
        )
        for offset in range(0, len(cave) - 4, 4)
    )


def test_tag_includes_the_version():
    assert dev_log_tag() == "FWTR-DEV"
    assert dev_log_tag("2.5.26") == "FWTR-DEV-v2.5.26"


# -- installing into the real library ------------------------------------
def test_apply_dev_dispatch_log_writes_the_hook(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_dev_dispatch_log(buf, limit=1024, version="9.9.9") == 1
    hook = seg_offset(DEV_LOG_HOOK_VADDR)
    assert bytes(buf[hook : hook + 4]) == BRANCH_TO_CAVE
    cave = seg_offset(DEV_LOG_CAVE_VADDR)
    assert bytes(buf[cave : cave + 4]) == encode_sub_sp(0x90)
    assert len(buf) == len(so_bytes)


def test_apply_dev_dispatch_log_is_idempotent(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_dev_dispatch_log(buf) == 1
    once = bytes(buf)
    assert apply_dev_dispatch_log(buf) == 0
    assert bytes(buf) == once


def test_apply_dev_dispatch_log_rejects_an_unknown_hook_site(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    offset = seg_offset(DEV_LOG_HOOK_VADDR)
    buf[offset : offset + 4] = b"\x1f\x20\x03\xd5"  # nop
    with pytest.raises(ValueError, match="dev log hook site"):
        apply_dev_dispatch_log(buf)


# -- emulation -----------------------------------------------------------
@dataclass
class LogCall:
    """One observed __android_log_print call, with its strings resolved."""

    prio: int
    tag: bytes
    fmt: bytes
    arg3: int
    arg4: int
    string: bytes  # string reachable through the pointer argument


@dataclass
class Emulation:
    """What the cave passed to the log call, and what it left behind."""

    prio: int
    tag: bytes
    fmt: bytes
    arg3: int
    arg4: int
    payload: bytes  # string reachable through the payload argument
    sp_after: int
    stack: int
    pc_after: int
    regs_after: dict[str, int]
    mprotect_calls: int
    mprotect_args: tuple[int, int, int] | None
    calls: list[LogCall]
    marker_texts: list[bytes]


def _emulate(
    limit: int,
    payload: bytes,
    runs: int = 1,
    counters: bool = True,
    log: bool = True,
    marker: str = "",
    mprotect_succeeds: bool = True,
) -> Emulation:
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X8,
        UC_ARM64_REG_X9,
        UC_ARM64_REG_X12,
        UC_ARM64_REG_X13,
        UC_ARM64_REG_X19,
    )

    stack_top = 0x10080000
    payload_addr = 0x7F0000
    sentinel = 0x20000000
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x700000, 0x100000)  # hook site + payload
    uc.mem_map(0xB00000, 0x200000)  # cave + PLT stubs
    uc.mem_map(stack_top - 0x100000, 0x100000)
    uc.mem_map(sentinel, 0x1000)

    string_obj = 0x7E0000  # a libc++ std::string in long mode
    uc.mem_write(payload_addr, payload)
    # libc++ long mode: [0]=capacity (bit0 = long flag), [8]=size, [16]=data pointer
    uc.mem_write(
        string_obj,
        struct.pack("<QQQ", (len(payload) << 1) | 1, len(payload), payload_addr),
    )
    uc.mem_write(sentinel, RET)
    uc.mem_write(DEV_LOG_PLT_PRINT, RET)  # both PLT targets are observed only
    uc.mem_write(DEV_LOG_PLT_MPROTECT, RET)
    uc.mem_write(HOOK_AFTER, RET)  # return into the "real" function body
    uc.mem_write(
        DEV_LOG_CAVE_VADDR,
        _build_dev_log_cave(
            DEV_LOG_CAVE_VADDR,
            limit=limit,
            version="9.9.9",
            counters=counters,
            log=log,
            marker=marker,
        ),
    )
    uc.mem_write(DEV_LOG_HOOK_VADDR, BRANCH_TO_CAVE)

    def read_cstr(address: int) -> bytes:
        out = bytearray()
        for index in range(256):
            byte = uc.mem_read(address + index, 1)[0]
            if byte == 0:
                break
            out.append(byte)
        return bytes(out)

    calls: list[LogCall] = []
    mprotect_calls = 0
    mprotect_args: tuple[int, int, int] | None = None

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        nonlocal mprotect_calls, mprotect_args
        if address == DEV_LOG_PLT_MPROTECT:
            mprotect_calls += 1
            mprotect_args = (
                uc_.reg_read(UC_ARM64_REG_X0),
                uc_.reg_read(UC_ARM64_REG_X1),
                uc_.reg_read(UC_ARM64_REG_X2),
            )
            uc_.reg_write(UC_ARM64_REG_X0, 0 if mprotect_succeeds else 22)  # 0 / EINVAL
        elif address == DEV_LOG_PLT_PRINT:
            # A real __android_log_print may clobber every caller-saved register;
            # poison the scratch ones so the cave cannot rely on them surviving.
            for scratch in (UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X9):
                uc_.reg_write(scratch, 0xDEAD0000 | (scratch & 0xFFF))
            regs = [
                uc_.reg_read(register)
                for register in (
                    UC_ARM64_REG_X0,
                    UC_ARM64_REG_X1,
                    UC_ARM64_REG_X2,
                    UC_ARM64_REG_X3,
                    UC_ARM64_REG_X4,
                    UC_ARM64_REG_X5,
                )
            ]
            fmt = read_cstr(regs[2])
            tag = read_cstr(regs[1])
            if tag == b"FWTR-DEV-BUILD":
                pointer = regs[3]  # the marker passes only the string
            elif counters and log and limit:
                pointer = regs[5]  # counter, limit, payload
            elif counters and log or limit:
                pointer = regs[4]  # one precision argument before the payload
            else:
                pointer = regs[3]  # the payload is the only argument
            calls.append(
                LogCall(
                    prio=regs[0],
                    tag=tag,
                    fmt=fmt,
                    arg3=regs[3],
                    arg4=regs[4],
                    string=read_cstr(pointer),
                )
            )

    uc.hook_add(UC_HOOK_CODE, on_code)

    stack = stack_top - 0x1000
    for _ in range(runs):
        uc.reg_write(UC_ARM64_REG_SP, stack)
        uc.reg_write(UC_ARM64_REG_X0, 0x701000)  # config pointer
        uc.reg_write(UC_ARM64_REG_X1, string_obj)  # &std::string with the JSON body
        uc.reg_write(UC_ARM64_REG_X2, 0xAAA)
        uc.reg_write(UC_ARM64_REG_X3, 0xBBB)
        uc.reg_write(UC_ARM64_REG_X4, 0xCCC)
        uc.reg_write(UC_ARM64_REG_X5, 0xDDD)
        uc.reg_write(UC_ARM64_REG_X8, 0xEEE)
        uc.reg_write(UC_ARM64_REG_X9, 0xFFF)
        uc.reg_write(UC_ARM64_REG_X19, 0x1234)
        uc.reg_write(UC_ARM64_REG_LR, sentinel)
        uc.emu_start(DEV_LOG_HOOK_VADDR, sentinel, count=600)

    marker_texts = [call.string for call in calls if call.tag == b"FWTR-DEV-BUILD"]
    payload_calls = [call for call in calls if call.tag != b"FWTR-DEV-BUILD"]
    primary = payload_calls[0] if payload_calls else calls[0]
    return Emulation(
        prio=primary.prio,
        tag=primary.tag,
        fmt=primary.fmt,
        arg3=primary.arg3,
        arg4=primary.arg4,
        payload=primary.string,
        sp_after=uc.reg_read(UC_ARM64_REG_SP),
        stack=stack,
        pc_after=uc.reg_read(UC_ARM64_REG_PC),
        regs_after={
            "x0": uc.reg_read(UC_ARM64_REG_X0),
            "x1": uc.reg_read(UC_ARM64_REG_X1),
            "x2": uc.reg_read(UC_ARM64_REG_X2),
            "x3": uc.reg_read(UC_ARM64_REG_X3),
            "x4": uc.reg_read(UC_ARM64_REG_X4),
            "x5": uc.reg_read(UC_ARM64_REG_X5),
            "x8": uc.reg_read(UC_ARM64_REG_X8),
            "x9": uc.reg_read(UC_ARM64_REG_X9),
            "x19": uc.reg_read(UC_ARM64_REG_X19),
        },
        mprotect_calls=mprotect_calls,
        mprotect_args=mprotect_args,
        calls=calls,
        marker_texts=marker_texts,
    )


def test_cave_logs_the_payload_with_truncation():
    payload = b'{"cmd":"GET_MY_INFO","user_index":993838}'
    result = _emulate(limit=24, payload=payload)
    assert result.prio == 4  # ANDROID_LOG_INFO
    assert result.tag == b"FWTR-DEV-v9.9.9"
    assert result.fmt == b"%u %.*s"
    assert result.arg3 == 1  # first hit: the counter
    assert result.arg4 == 24  # truncation limit
    assert result.payload == payload


def test_cave_logs_the_whole_body_when_limit_is_zero():
    payload = b'{"cmd":"GET_MY_INFO"}'
    result = _emulate(limit=0, payload=payload)
    assert result.fmt == b"%u %s"
    assert result.arg3 == 1
    assert result.payload == payload


def test_counter_increments_across_calls_and_mprotect_runs_once():
    result = _emulate(limit=16, payload=b"{}", runs=3)
    assert [call.arg3 for call in result.calls] == [1, 2, 3], (
        "the counter must persist across calls"
    )
    assert result.mprotect_calls == 1, "the magic byte must gate the syscall"
    assert result.mprotect_args is not None
    page, length, protection = result.mprotect_args
    assert page == DEV_LOG_CAVE_VADDR & ~0x3FFF, "16 KB aligned for Android 15 pages"
    assert length == 0x4000, "must cover the state block, which lives in the next page"
    assert page + length > DEV_LOG_CAVE_VADDR + 0x284, "state block inside the range"
    assert protection == 7  # PROT_READ | PROT_WRITE | PROT_EXEC


def test_cave_without_counters_makes_no_page_writable():
    """--dev-log without --dev-counters must not touch page permissions."""
    result = _emulate(limit=16, payload=b"{}", counters=False)
    assert result.fmt == b"%.*s"
    assert result.arg3 == 16  # the limit, not a counter
    assert result.payload == b"{}"
    assert result.mprotect_calls == 0


def test_cave_preserves_every_clobbered_register():
    result = _emulate(limit=16, payload=b"{}")
    assert result.regs_after["x0"] == 0x701000
    assert result.regs_after["x1"] == 0x7E0000  # &std::string
    assert result.regs_after["x2"] == 0xAAA
    assert result.regs_after["x3"] == 0xBBB
    assert result.regs_after["x4"] == 0xCCC
    assert result.regs_after["x5"] == 0xDDD
    assert result.regs_after["x8"] == 0xEEE
    assert result.regs_after["x9"] == 0xFFF
    assert result.regs_after["x19"] == 0x1234


def test_cave_replays_the_hook_instruction_and_returns():
    result = _emulate(limit=16, payload=b"{}")
    # The displaced `stp x29, x30, [sp, #-0x60]!` must have been applied exactly once.
    assert result.sp_after == result.stack - 0x60
    # Control must land back in the function body, then return to the caller.
    assert result.pc_after == 0x20000000

# -- build marker (phase 5) ----------------------------------------------
def test_build_marker_is_stable_and_order_independent():
    one = dev_build_marker("2.5.26", ("log_dispatch", "hit_counters", "build_marker"), 39)
    two = dev_build_marker("2.5.26", ("build_marker", "hit_counters", "log_dispatch"), 39)
    other = dev_build_marker("2.5.26", ("build_marker",), 39)
    assert one == two, "the fingerprint must not depend on the argument order"
    assert one != other, "different instrumentation must produce a different marker"
    assert one.startswith("FWTR-DEV v2.5.26 fp=")
    assert "flags=build_marker,hit_counters,log_dispatch" in one


def test_build_marker_changes_with_the_patch_count():
    assert dev_build_marker("2.5.26", ("build_marker",), 39) != dev_build_marker(
        "2.5.26", ("build_marker",), 40
    )


def test_cave_state_block_zeroes_the_marker_magic():
    cave = _build_dev_log_cave(
        DEV_LOG_CAVE_VADDR, limit=16, version="9.9.9", marker="FWTR-DEV v9.9.9"
    )
    assert cave[DEV_MARKER_MAGIC_OFFSET] == 0, "marker must log once, then latch"
    assert len(cave) <= DEV_LOG_CAVE_SIZE


def test_marker_is_embedded_and_findable(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    marker = dev_build_marker("9.9.9", ("build_marker", "log_dispatch"), 39)
    assert apply_dev_dispatch_log(buf, limit=16, version="9.9.9", marker=marker) == 1
    assert find_dev_build_marker(buf) == marker

    clean = bytearray(so_bytes)
    assert find_dev_build_marker(clean) is None, "a release .so has no marker"


def test_marker_is_logged_exactly_once_per_process():
    marker = dev_build_marker("9.9.9", ("build_marker", "log_dispatch"), 39)
    result = _emulate(limit=16, payload=b"{}", runs=3, marker=marker)
    assert len(result.marker_texts) == 1, "three dispatches, one marker line"
    assert result.marker_texts[0] == marker.encode()
    marker_call = next(call for call in result.calls if call.tag == b"FWTR-DEV-BUILD")
    assert marker_call.fmt == b"%s"
    assert marker_call.prio == 4
    assert DEV_MARKER_TAG == "FWTR-DEV-BUILD"


def test_marker_only_cave_never_logs_payloads():
    marker = dev_build_marker("9.9.9", ("build_marker",), 12)
    result = _emulate(limit=0, payload=b'{"cmd":"SECRET"}', runs=2, log=False, marker=marker)
    assert result.marker_texts == [marker.encode()]
    assert all(call.tag == b"FWTR-DEV-BUILD" for call in result.calls)
    assert b"SECRET" not in b"".join(call.string for call in result.calls)
    assert result.mprotect_calls == 1
    assert result.sp_after == result.stack - 0x60
    assert result.pc_after == 0x20000000


def test_cave_without_log_or_marker_is_rejected():
    buf = bytearray(0x500000)
    with pytest.raises(ValueError, match="needs at least one"):
        apply_dev_dispatch_log(buf, log=False, marker="")


def test_standalone_counters_increment_and_feed_response_tags(reference_buffers):
    """--dev-counters must increment the counter even when --dev-log is off."""
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X8,
    )

    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_dev_dispatch_log(buf, counters=True, log=False, marker="") == 1
    assert apply_dev_dispatch_log(buf, counters=True, log=False, marker="") == 0

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x700000, 0x200000)
    uc.mem_map(0xB00000, 0x200000)
    uc.mem_map(0x10000000, 0x100000)
    uc.mem_map(0x20000000, 0x1000)

    req_buf = 0x7F0000
    req_str = 0x7E0000
    resp_str = 0x7E1000
    resp_body = b'{"ok":true}'
    uc.mem_write(req_buf, b"{}")
    uc.mem_write(req_str, struct.pack("<QQQ", 5, 2, req_buf))
    # Short-mode std::string at resp_str: len=11 -> byte0=(11<<1), inline chars follow
    uc.mem_write(resp_str, bytes([len(resp_body) << 1]) + resp_body + b"\x00")

    uc.mem_write(0x20000000, RET)
    uc.mem_write(DEV_LOG_PLT_PRINT, RET)
    uc.mem_write(DEV_LOG_PLT_MPROTECT, RET)
    uc.mem_write(HOOK_AFTER, RET)
    uc.mem_write(
        DEV_LOG_CAVE_VADDR,
        _build_dev_log_cave(
            DEV_LOG_CAVE_VADDR,
            limit=64,
            version="9.9.9",
            counters=True,
            log=False,
            timing=True,
            capture_sret=True,
        ),
    )
    uc.mem_write(
        DEV_TIMING_CAVE_VADDR,
        _build_dev_timing_cave(
            DEV_TIMING_CAVE_VADDR,
            version="9.9.9",
            response_tag="FWTR-DEV-R-v9.9.9",
            limit=64,
        ),
    )
    uc.mem_write(DEV_LOG_HOOK_VADDR, BRANCH_TO_CAVE)

    log_calls: list[tuple[bytes, int]] = []

    def read_cstr(address: int) -> bytes:
        raw = bytes(uc.mem_read(address, 64))
        return raw.split(b"\x00", 1)[0]

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        if address == DEV_LOG_PLT_MPROTECT:
            uc_.reg_write(UC_ARM64_REG_X0, 0)
        elif address == DEV_LOG_PLT_PRINT:
            tag = read_cstr(uc_.reg_read(UC_ARM64_REG_X1))
            arg3 = uc_.reg_read(UC_ARM64_REG_X3)
            log_calls.append((tag, arg3))

    uc.hook_add(UC_HOOK_CODE, on_code)

    stack = 0x10040000
    for run in (1, 2, 3):
        uc.reg_write(UC_ARM64_REG_SP, stack)
        uc.reg_write(UC_ARM64_REG_X0, 0x701000)
        uc.reg_write(UC_ARM64_REG_X1, req_str)
        uc.reg_write(UC_ARM64_REG_X2, 0)
        uc.reg_write(UC_ARM64_REG_X3, 0)
        uc.reg_write(UC_ARM64_REG_X4, 0)
        uc.reg_write(UC_ARM64_REG_X5, 0)
        uc.reg_write(UC_ARM64_REG_X8, resp_str)
        uc.reg_write(UC_ARM64_REG_LR, 0x20000000)
        uc.emu_start(DEV_LOG_HOOK_VADDR, 0x20000000, count=600)

        uc.reg_write(UC_ARM64_REG_SP, stack)
        uc.reg_write(UC_ARM64_REG_X0, resp_str)
        uc.reg_write(UC_ARM64_REG_X1, 0)
        uc.reg_write(UC_ARM64_REG_LR, 0x20000000)
        uc.emu_start(DEV_TIMING_CAVE_VADDR, 0x20000000, count=600)

        counter_val = struct.unpack(
            "<I", uc.mem_read(DEV_LOG_CAVE_VADDR + DEV_COUNTER_VALUE_OFFSET, 4)
        )[0]
        assert counter_val == run

    assert all(not tag.startswith(b"FWTR-DEV-v") for tag, _ in log_calls)
    response_counters = [
        arg3 for tag, arg3 in log_calls if tag == b"FWTR-DEV-R-v9.9.9"
    ]
    assert response_counters == [1, 2, 3]

# -- handler timing (phase 6) --------------------------------------------
def test_timing_encoders_round_trip():
    pytest.importorskip("capstone")
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cases = [
        (encode_mrs_cntvct(11), "mrs", "x11, cntvct_el0"),
        (encode_mrs_cntfrq(13), "mrs", "x13, cntfrq_el0"),
        (encode_mul(12, 12, 14), "mul", "x12, x12, x14"),
        (encode_udiv(12, 12, 13), "udiv", "x12, x12, x13"),
        (encode_sub_x(12, 11, 10), "sub", "x12, x11, x10"),
        (encode_str_x(30, 31, 0x10), "str", "x30, [sp, #0x10]"),
        (encode_ldr_x(1, 31, 0x08), "ldr", "x1, [sp, #8]"),
        (encode_movk_x(14, 0xF, 16), "movk", "x14, #0xf, lsl #16"),
        (encode_ret(), "ret", ""),
    ]
    for blob, mnemonic, operands in cases:
        (instruction,) = list(decoder.disasm(blob, 0))
        assert instruction.mnemonic == mnemonic, (blob.hex(), instruction.mnemonic)
        assert instruction.op_str == operands, (blob.hex(), instruction.op_str)


def test_timing_cave_ends_with_the_replayed_ret():
    cave = _build_dev_timing_cave(DEV_TIMING_CAVE_VADDR, version="9.9.9")
    assert len(cave) <= DEV_TIMING_CAVE_SIZE
    # The code section ends with the displaced `ret`; the strings follow it.
    code_end = cave.index(DEV_TIMING_RET) + 4
    assert cave[code_end:].startswith(b"FWTR-DEV-T-v9.9.9\x00"), (
        "the ret must be the last instruction before the strings"
    )
    assert b"%lu us\x00" in cave
    assert b"FWTR-DEV-T-v9.9.9\x00" in cave


def test_entry_cave_samples_the_counter_only_with_timing():
    with_timing = _build_dev_log_cave(
        DEV_LOG_CAVE_VADDR, limit=16, version="9.9.9", timing=True
    )
    without = _build_dev_log_cave(DEV_LOG_CAVE_VADDR, limit=16, version="9.9.9")
    assert encode_mrs_cntvct(11) in with_timing
    assert encode_mrs_cntvct(11) not in without


def test_handler_timing_hooks_every_ret(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_dev_handler_timing(buf, version="9.9.9") == len(DEV_TIMING_HOOK_SITES)
    for site in DEV_TIMING_HOOK_SITES:
        offset = seg_offset(site)
        expected = struct.pack(
            "<I", 0x14000000 | (((DEV_TIMING_CAVE_VADDR - site) // 4) & 0x03FFFFFF)
        )
        assert bytes(buf[offset : offset + 4]) == expected, hex(site)
    cave = seg_offset(DEV_TIMING_CAVE_VADDR)
    assert bytes(buf[cave + DEV_TIMING_CAVE_SIZE - 4 : cave + DEV_TIMING_CAVE_SIZE]) != b""
    assert len(buf) == len(so_bytes)


def test_handler_timing_is_idempotent(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    assert apply_dev_handler_timing(buf) == len(DEV_TIMING_HOOK_SITES)
    once = bytes(buf)
    assert apply_dev_handler_timing(buf) == 0
    assert bytes(buf) == once


def test_handler_timing_rejects_a_drifted_build(reference_buffers):
    so_bytes, _dex = reference_buffers
    buf = bytearray(so_bytes)
    offset = seg_offset(DEV_TIMING_HOOK_SITES[0])
    buf[offset : offset + 4] = b"\x1f\x20\x03\xd5"  # nop instead of ret
    with pytest.raises(ValueError, match="timing hook site"):
        apply_dev_handler_timing(buf)


def test_timing_cave_computes_microseconds_from_the_device_counter():
    """Pins the arithmetic: (now - start) * 1e6 / cntfrq, in microseconds.

    unicorn reports a fixed ``cntvct_el0`` (62,500,000) and ``cntfrq_el0 == 0``, so
    the test injects the frequency a real device would expose (25 MHz) right after
    the ``mrs`` and checks the exact value handed to the log call.
    """
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X11,
        UC_ARM64_REG_X13,
    )

    counter = 62_500_000  # injected: what cntvct_el0 reads at exit
    frequency = 25_000_000  # injected: a 25 MHz counter
    elapsed_ticks = 25_000  # 1 ms of ticks

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0xB00000, 0x200000)  # caves + state + PLT stubs
    uc.mem_map(0x10000000, 0x40000)  # stack
    uc.mem_map(0x20000000, 0x1000)  # sentinel
    uc.mem_write(0x20000000, RET)
    uc.mem_write(DEV_LOG_PLT_PRINT, RET)
    uc.mem_write(
        DEV_TIMING_CAVE_VADDR, _build_dev_timing_cave(DEV_TIMING_CAVE_VADDR, version="9.9.9")
    )
    # The entry cave wrote the start tick here.
    uc.mem_write(
        DEV_LOG_CAVE_VADDR + DEV_START_TICK_OFFSET,
        struct.pack("<Q", counter - elapsed_ticks),
    )

    logged: dict[str, int] = {}

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        # unicorn's cntvct_el0 follows host time, so the counter and the frequency
        # are injected right after their `mrs`: the cave's own sub/mul/udiv is what
        # gets tested, deterministically.
        if address == DEV_TIMING_CAVE_VADDR + 0x20:
            uc_.reg_write(UC_ARM64_REG_X11, counter)
        elif address == DEV_TIMING_CAVE_VADDR + 0x28:
            uc_.reg_write(UC_ARM64_REG_X13, frequency)
        elif address == DEV_LOG_PLT_PRINT:
            logged["prio"] = uc_.reg_read(UC_ARM64_REG_X0)
            logged["us"] = uc_.reg_read(UC_ARM64_REG_X3)

    uc.hook_add(UC_HOOK_CODE, on_code)
    stack = 0x1003F000
    uc.reg_write(UC_ARM64_REG_SP, stack)
    uc.reg_write(UC_ARM64_REG_X0, 0xCAFE)  # the handler's return value
    uc.reg_write(UC_ARM64_REG_X1, 0xBEEF)
    uc.reg_write(UC_ARM64_REG_LR, 0x20000000)
    uc.emu_start(DEV_TIMING_CAVE_VADDR, 0x20000000, count=200)

    assert logged["prio"] == 4
    assert logged["us"] == elapsed_ticks * 1_000_000 // frequency == 1000
    assert uc.reg_read(UC_ARM64_REG_X0) == 0xCAFE, "the return value must survive"
    assert uc.reg_read(UC_ARM64_REG_X1) == 0xBEEF
    assert uc.reg_read(UC_ARM64_REG_SP) == stack, "the frame must be released"
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x20000000, "control returns to the caller"

def test_mprotect_failure_falls_back_to_the_stack_instead_of_crashing():
    """If mprotect is refused (unexpected page size), nothing may fault."""
    result = _emulate(limit=16, payload=b"{}", runs=2, mprotect_succeeds=False)
    assert result.mprotect_calls == 2, "a failed mprotect is retried every call"
    assert len(result.calls) == 2, "the log still happens"
    assert result.payload == b"{}"
    assert result.sp_after == result.stack - 0x60
    assert result.pc_after == 0x20000000

# -- exit cave: timing + response (phase 6 + 7) ---------------------------
def _emulate_exit_cave(response_text: bytes, limit: int):
    """Runs the exit cave with a fake long-mode std::string as the return value."""
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
    )

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x700000, 0x100000)
    uc.mem_map(0xB00000, 0x200000)
    uc.mem_map(0x10000000, 0x40000)
    uc.mem_map(0x20000000, 0x1000)
    uc.mem_write(0x20000000, RET)
    uc.mem_write(DEV_LOG_PLT_PRINT, RET)

    text_addr, obj_addr = 0x7F0000, 0x7E0000
    uc.mem_write(text_addr, response_text)
    uc.mem_write(
        obj_addr, struct.pack("<QQQ", (len(response_text) << 1) | 1, len(response_text), text_addr)
    )
    uc.mem_write(DEV_LOG_CAVE_VADDR + DEV_COUNTER_VALUE_OFFSET, struct.pack("<I", 41))
    # the entry cave stored the std::string* it received in x8 here
    uc.mem_write(DEV_LOG_CAVE_VADDR + DEV_SRET_OFFSET, struct.pack("<Q", obj_addr))
    uc.mem_write(
        DEV_TIMING_CAVE_VADDR,
        _build_dev_timing_cave(
            DEV_TIMING_CAVE_VADDR, version="9.9.9", response_tag="FWTR-DEV-R-v9.9.9", limit=limit
        ),
    )

    calls: list[dict[str, object]] = []

    def read_cstr(address: int) -> bytes:
        out = bytearray()
        for index in range(256):
            byte = uc.mem_read(address + index, 1)[0]
            if byte == 0:
                break
            out.append(byte)
        return bytes(out)

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        if address == DEV_LOG_PLT_PRINT:
            calls.append(
                {
                    "tag": read_cstr(uc_.reg_read(UC_ARM64_REG_X1)),
                    "fmt": read_cstr(uc_.reg_read(UC_ARM64_REG_X2)),
                    "x3": uc_.reg_read(UC_ARM64_REG_X3),
                    "x4": uc_.reg_read(UC_ARM64_REG_X4),
                    "x5": uc_.reg_read(UC_ARM64_REG_X5),
                }
            )

    uc.hook_add(UC_HOOK_CODE, on_code)
    stack = 0x1003F000
    uc.reg_write(UC_ARM64_REG_SP, stack)
    uc.reg_write(UC_ARM64_REG_X0, obj_addr)
    uc.reg_write(UC_ARM64_REG_X1, 0xBEEF)
    uc.reg_write(UC_ARM64_REG_LR, 0x20000000)
    uc.emu_start(DEV_TIMING_CAVE_VADDR, 0x20000000, count=300)
    final = {
        "x0": uc.reg_read(UC_ARM64_REG_X0),
        "x1": uc.reg_read(UC_ARM64_REG_X1),
        "sp": uc.reg_read(UC_ARM64_REG_SP),
        "pc": uc.reg_read(UC_ARM64_REG_PC),
        "stack": stack,
    }
    return calls, final, read_cstr


def test_exit_cave_logs_amount_and_response():
    calls, final, read_cstr = _emulate_exit_cave(b'{"result":true}', limit=64)
    assert len(calls) == 2, "one timing line plus one response line"
    timing, response = calls
    assert timing["tag"] == b"FWTR-DEV-T-v9.9.9"
    assert timing["fmt"] == b"%lu us"
    assert response["tag"] == b"FWTR-DEV-R-v9.9.9"
    assert response["fmt"] == b"%u %.*s"
    assert response["x3"] == 41, "counter read from the state block"
    assert response["x4"] == 64, "the truncation limit is the precision"
    assert read_cstr(response["x5"]) == b'{"result":true}'
    assert final["x0"] == 0x7E0000, "x0 passes through untouched"
    assert final["x1"] == 0xBEEF
    assert final["sp"] == final["stack"], "the frame is released"
    assert final["pc"] == 0x20000000, "control goes back to the caller"


def test_exit_cave_without_response_only_logs_the_timing():
    cave = _build_dev_timing_cave(DEV_TIMING_CAVE_VADDR, version="9.9.9")
    assert b"FWTR-DEV-R" not in cave

# -- phase 8: DEV_DUMP command -------------------------------------------
def _emulate_dump_entry(payload: bytes):
    """Runs the entry cave and returns the DEV_DUMP flag it left behind."""
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
    )

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x700000, 0x200000)
    uc.mem_map(0xB00000, 0x200000)
    uc.mem_map(0x10000000, 0x100000)
    uc.mem_map(0x20000000, 0x1000)
    uc.mem_write(0x20000000, RET)
    uc.mem_write(DEV_LOG_PLT_PRINT, RET)
    uc.mem_write(DEV_LOG_PLT_MPROTECT, RET)
    uc.mem_write(HOOK_AFTER, RET)
    uc.mem_write(
        DEV_LOG_CAVE_VADDR,
        _build_dev_log_cave(
            DEV_LOG_CAVE_VADDR,
            limit=64,
            version="9.9.9",
            counters=True,
            log=True,
            dev_dump=True,
        ),
    )
    uc.mem_write(DEV_LOG_HOOK_VADDR, BRANCH_TO_CAVE)

    text_addr, obj_addr = 0x7F0000, 0x800000  # both inside the 0x700000 region
    uc.mem_write(text_addr, payload)
    uc.mem_write(
        obj_addr,
        struct.pack("<QQQ", (len(payload) << 1) | 1, len(payload), text_addr),
    )

    def on_code(uc_: Uc, address: int, size: int, _data) -> None:
        if address == DEV_LOG_PLT_MPROTECT:
            uc_.reg_write(UC_ARM64_REG_X0, 0)  # mprotect returned 0: page is writable

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_SP, 0x1003F000)
    uc.reg_write(UC_ARM64_REG_X1, obj_addr)
    uc.reg_write(UC_ARM64_REG_LR, 0x20000000)
    uc.emu_start(DEV_LOG_HOOK_VADDR, 0x20000000, count=600)
    flag = uc.mem_read(DEV_LOG_CAVE_VADDR + DEV_DUMP_FLAG_OFFSET, 1)[0]
    return flag


def test_dev_dump_command_sets_the_flag():
    assert _emulate_dump_entry(b'{"CMD":"DEV_DUMP","what":"shop"}') == 1


def test_other_commands_leave_the_flag_clear():
    for payload in (b'{"CMD":"GET_MY_INFO"}', b'{"CMD":"DEV_DUMPX"}', b'{}', b""):
        assert _emulate_dump_entry(payload) == 0, payload


def _emulate_dump_exit(mode: str):
    """Runs the exit cave with the dump flag set and returns the rewritten buffer."""
    pytest.importorskip("unicorn")
    from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc
    from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_SP

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x700000, 0x100000)
    uc.mem_map(0xB00000, 0x200000)
    uc.mem_map(0x10000000, 0x100000)
    uc.mem_map(0x20000000, 0x1000)
    uc.mem_write(0x20000000, RET)
    uc.mem_write(DEV_LOG_PLT_PRINT, RET)
    uc.mem_write(
        DEV_TIMING_CAVE_VADDR,
        _build_dev_timing_cave(DEV_TIMING_CAVE_VADDR, version="9.9.9", dev_dump=True),
    )
    obj_addr, heap_addr = 0x7E0000, 0x7A0000  # both inside the mapped region
    if mode == "short":
        # a libc++ short string: length in byte0 (len<<1), characters inline at +1
        original = b'{"ERROR":1}'
        blob = bytearray(24)
        blob[0] = len(original) << 1
        blob[1 : 1 + len(original)] = original
        uc.mem_write(obj_addr, bytes(blob))
    else:
        original = b'{"ERROR":1,"unknown_command":true}'
        uc.mem_write(heap_addr, original)
        uc.mem_write(
            obj_addr, struct.pack("<QQQ", (len(original) << 1) | 1, len(original), heap_addr)
        )
    # the entry cave saw a DEV_DUMP request
    uc.mem_write(DEV_LOG_CAVE_VADDR + DEV_DUMP_FLAG_OFFSET, b"\x01")
    uc.mem_write(DEV_LOG_CAVE_VADDR + DEV_SRET_OFFSET, struct.pack("<Q", obj_addr))
    uc.reg_write(UC_ARM64_REG_SP, 0x1003F000)
    uc.reg_write(UC_ARM64_REG_LR, 0x20000000)
    uc.emu_start(DEV_TIMING_CAVE_VADDR, 0x20000000, count=400)
    flag = uc.mem_read(DEV_LOG_CAVE_VADDR + DEV_DUMP_FLAG_OFFSET, 1)[0]
    if mode == "short":
        header = uc.mem_read(obj_addr, 1)[0]
        size = header >> 1
        body = bytes(uc.mem_read(obj_addr + 1, size))
    else:
        size = struct.unpack("<Q", bytes(uc.mem_read(obj_addr + 8, 8)))[0]
        body = bytes(uc.mem_read(heap_addr, size))
    tail = uc.mem_read(obj_addr + 1 + size, 1)[0] if mode == "short" else uc.mem_read(heap_addr + size, 1)[0]
    assert tail == 0, "the payload must be NUL terminated for the log line"
    return body, size, flag


def test_dev_dump_rewrites_a_long_mode_response():
    body, size, flag = _emulate_dump_exit("long")
    assert body == DEV_DUMP_RESPONSE
    assert size == len(DEV_DUMP_RESPONSE)
    assert flag == 0, "the flag is cleared so only one response is rewritten"


def test_dev_dump_rewrites_a_short_mode_response():
    body, size, flag = _emulate_dump_exit("short")
    assert body == DEV_DUMP_RESPONSE
    assert size == len(DEV_DUMP_RESPONSE)
    assert flag == 0


def test_exit_cave_without_dump_leaves_the_response_alone():
    cave = _build_dev_timing_cave(DEV_TIMING_CAVE_VADDR, version="9.9.9")
    assert DEV_DUMP_RESPONSE not in cave
