"""Experimental instruction-level checks; these do not prove gameplay behavior."""
from __future__ import annotations

import struct

import pytest

unicorn = pytest.importorskip("unicorn")
capstone = pytest.importorskip("capstone")
pytest.importorskip("keystone")
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_LR,
    UC_ARM64_REG_NZCV,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X12,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X14,
    UC_ARM64_REG_X15,
    UC_ARM64_REG_X16,
    UC_ARM64_REG_X17,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X29,
)

from tools.gen_owned_costume_caves import CAVES, generate  # noqa: E402

STACK = 0x10000000
SP = STACK + 0x1000
CHOOSE_FP = STACK + 0x4000
PARENT_FP = STACK + 0x5000
STOPS = {0x9846AC, 0x9846BC, 0x9846D4}


def _run(which: int, code: str, *, ret: int = 0x990C80, current: int = 1,
         count: int = 3, base: int = 0):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(base + 0x980000, 0x30000)
    uc.mem_map(base + 0xB2A000, 0x1000)
    uc.mem_map(STACK, 0x10000)
    for address, blob in zip(CAVES, generate(), strict=True):
        uc.mem_write(base + address, blob)
    uc.mem_write(CHOOSE_FP, struct.pack('<QQ', PARENT_FP, base + ret))
    raw = code.encode('ascii')
    uc.mem_write(PARENT_FP - 0x88, bytes((len(raw) * 2,)) + raw + b'\0')
    uc.mem_write(SP + 0x40, struct.pack('<Q', count if which == 1 else 77))
    values = ((UC_ARM64_REG_SP, SP), (UC_ARM64_REG_X29, CHOOSE_FP),
              (UC_ARM64_REG_LR, 0x111111), (UC_ARM64_REG_X8, 0xA5),
              (UC_ARM64_REG_X9, 8), (UC_ARM64_REG_X11, count),
              (UC_ARM64_REG_X12, 2), (UC_ARM64_REG_X20, current if which == 1 else 0x33),
              (UC_ARM64_REG_X21, 0x44), (UC_ARM64_REG_X22, current))
    saved = ((UC_ARM64_REG_X13, 0x1313), (UC_ARM64_REG_X14, 0x1414),
             (UC_ARM64_REG_X15, 0x1515), (UC_ARM64_REG_X16, 0x1616),
             (UC_ARM64_REG_X17, 0x1717))
    for register, value in (*values, *saved):
        uc.reg_write(register, value)
    uc.reg_write(UC_ARM64_REG_NZCV, 0x60000000)
    hits: list[int] = []
    def stop(u, address, _size, _data):
        if address - base in STOPS:
            hits.append(address - base)
            u.emu_stop()
    uc.hook_add(UC_HOOK_CODE, stop)
    uc.emu_start(base + CAVES[which], 0, count=200)
    assert len(hits) == 1
    assert all(uc.reg_read(reg) == value for reg, value in saved)
    assert uc.reg_read(UC_ARM64_REG_NZCV) == 0x60000000
    assert uc.reg_read(UC_ARM64_REG_SP) == SP
    assert uc.reg_read(UC_ARM64_REG_LR) == 0x111111
    assert uc.reg_read(UC_ARM64_REG_X22) == current
    return uc, hits[0]


@pytest.mark.parametrize('base', [0, 0x30000000, 0x7200000000])
@pytest.mark.parametrize('code', ['75150', '75186'])
def test_eligible_selection_is_sequential_for_both_packages(code, base):
    for index in range(3):
        uc, target = _run(0, code, current=index, base=base)
        assert target == 0x9846AC
        assert uc.reg_read(UC_ARM64_REG_X20) == index
        assert struct.unpack('<Q', uc.mem_read(SP + 0x40, 8))[0] == 3
        uc, target = _run(1, code, current=index, base=base)
        assert target == 0x9846BC
        assert uc.reg_read(UC_ARM64_REG_X8) == 24


@pytest.mark.parametrize('code', ['75150', '75186'])
@pytest.mark.parametrize('index', [3, 4, 99])
def test_out_of_bounds_fails_using_native_cleanup(code, index):
    _, target = _run(1, code, current=index)
    assert target == 0x9846D4


@pytest.mark.parametrize('code', ['75151', '75187', '75156', '75180', '751500', ''])
@pytest.mark.parametrize('which', [0, 1])
def test_other_components_keep_original_behavior(code, which):
    uc, target = _run(which, code)
    assert target == (0x9846AC if which == 0 else 0x9846BC)
    if which == 0:
        assert uc.reg_read(UC_ARM64_REG_X20) == 2
        assert struct.unpack('<Q', uc.mem_read(SP + 0x40, 8))[0] == 77
    else:
        assert uc.reg_read(UC_ARM64_REG_X8) == 24


@pytest.mark.parametrize('which', [0, 1])
def test_wrong_return_address_keeps_original_behavior(which):
    uc, target = _run(which, '75150', ret=0x990C84)
    assert target == (0x9846AC if which == 0 else 0x9846BC)
    if which == 0:
        assert struct.unpack('<Q', uc.mem_read(SP + 0x40, 8))[0] == 77


def test_no_calls_in_experimental_caves():
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for address, blob in zip(CAVES, generate(), strict=True):
        assert all(i.mnemonic not in ('bl', 'blr') for i in md.disasm(blob, address))


def test_reference_hooks_and_cave_bytes(reference_buffers: tuple[bytes, bytes]) -> None:
    """Reject changed native layouts before any future integration."""
    import hashlib

    from tools.dump_fn import file_offset, parse_segments
    from tools.gen_owned_costume_caves import HOOKS

    so, _ = reference_buffers
    segments = parse_segments(so)
    originals = ('94a50b9b', '08038052')
    expected = (
        '60771df02628a9fe5ea968dd2bac1de15550ae110e0fa907d1adc13aaab53ee9',
        '31368080e019814eaa6cbb8b14250e8e3de66c52a403ffc30066492e1b1de692',
    )
    for addr, value in zip(HOOKS, originals, strict=True):
        offset = file_offset(addr, segments)
        assert offset is not None
        assert so[offset:offset + 4].hex() == value
    for addr, blob, digest in zip(CAVES, generate(), expected, strict=True):
        offset = file_offset(addr, segments)
        assert offset is not None
        assert hashlib.sha256(so[offset:offset + len(blob)]).hexdigest() == digest


@pytest.mark.parametrize('code', ['75150', '75186'])
def test_hundred_eligible_codes_reach_last_and_refuse_next(code):
    for index in (0, 49, 99):
        uc, target = _run(0, code, current=index, count=100, base=0x30000000)
        assert target == 0x9846AC
        assert uc.reg_read(UC_ARM64_REG_X20) == index
        uc, target = _run(1, code, current=index, count=100, base=0x30000000)
        assert target == 0x9846BC
    _, target = _run(1, code, current=100, count=100, base=0x30000000)
    assert target == 0x9846D4
