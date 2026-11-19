"""Instruction-level tests for the experimental package-scoped Claim All hook."""
from __future__ import annotations

import struct

import pytest

pytest.importorskip('unicorn')
pytest.importorskip('keystone')
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_LR,
    UC_ARM64_REG_NZCV,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W8,
    UC_ARM64_REG_W9,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X14,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X28,
)

from tools.gen_costume_claim_hook import BASE, CLIENT_EXPECTED, HANDLER, generate  # noqa: E402

STACK = 0x10000000
SP = STACK + 0x3000
CLIENT_OFFSET = 0x1600000


def _machine(base: int) -> Uc:
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    client = base + CLIENT_OFFSET
    for address, size in ((base + 0xAB0000, 0x10000), (base + 0xB2A000, 0x2000),
                          (base + 0xBE3000, 0x1000), (STACK, 0x10000),
                          (client + 0x1625000, 0x1000)):
        u.mem_map(address, size)
    installer, handler = generate()
    u.mem_write(base + BASE, installer)
    u.mem_write(base + HANDLER, handler)
    u.mem_write(base + 0xBE3798, struct.pack('<Q', client))
    u.reg_write(UC_ARM64_REG_SP, SP)
    u.reg_write(UC_ARM64_REG_LR, 0x12345678)
    return u


@pytest.mark.parametrize('base', [0, 0x30000000, 0x7200000000])
@pytest.mark.parametrize(('product', 'found', 'dest'), [
    (75150, 1, 0x162575C), (75186, 1, 0x162575C),
    (75151, 1, 0x162585C), (75187, 1, 0x162585C),
    (99999, 0, 0x162575C), (99999, 1, 0x162585C),
])
def test_handler_scopes_claim_all_to_two_packages(base, product, found, dest):
    u = _machine(base)
    client = base + CLIENT_OFFSET
    mail, enum = STACK + 0x5000, STACK + 0x6000
    u.mem_write(mail + 0x30, struct.pack('<I', product))
    u.mem_write(enum, struct.pack('<Q', 0xABCDEF))
    for reg, value in ((UC_ARM64_REG_X26, mail), (UC_ARM64_REG_X22, enum),
                       (UC_ARM64_REG_X0, found), (UC_ARM64_REG_W8, 1),
                       (UC_ARM64_REG_W9, 7), (UC_ARM64_REG_X13, 0x1313),
                       (UC_ARM64_REG_X14, 0x1414)):
        u.reg_write(reg, value)
    u.reg_write(UC_ARM64_REG_NZCV, 0x60000000)
    hits = []
    def stop(uc, address, _size, _data):
        if address in (client + 0x162575C, client + 0x162585C):
            hits.append(address)
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, stop)
    u.emu_start(base + HANDLER, 0, count=200)
    assert hits == [client + dest]
    assert u.reg_read(UC_ARM64_REG_SP) == SP
    assert u.reg_read(UC_ARM64_REG_X13) == 0x1313
    assert u.reg_read(UC_ARM64_REG_X14) == 0x1414
    assert u.reg_read(UC_ARM64_REG_NZCV) == 0x60000000
    if dest == 0x162585C:
        assert u.reg_read(UC_ARM64_REG_X1) == 0


@pytest.mark.parametrize('base', [0, 0x30000000, 0x7200000000])
def test_installer_uses_expected_client_bytes_and_relocated_handler(base):
    u = _machine(base)
    client = base + CLIENT_OFFSET
    u.mem_write(SP + 0x10, struct.pack('<Q', 0x2828))
    calls = []
    def intercept(uc, address, _size, _data):
        if address == base + 0xAB575C:
            calls.append((uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
                          bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X2), 4)),
                          bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X3), 4)),
                          uc.reg_read(UC_ARM64_REG_X4)))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        if address == base + 0xAB3394:
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, intercept)
    u.emu_start(base + BASE, 0, count=200)
    assert len(calls) == 1
    actual_client, rva, expected, replacement, words = calls[0]
    assert (actual_client, rva, expected, words) == (client, 0x1625858, CLIENT_EXPECTED, 1)
    displacement = (base + HANDLER - (client + rva)) // 4
    assert struct.unpack('<I', replacement)[0] == 0x14000000 | (displacement & 0x3ffffff)
    assert u.reg_read(UC_ARM64_REG_X28) == 0x2828
    assert u.reg_read(UC_ARM64_REG_SP) == SP
