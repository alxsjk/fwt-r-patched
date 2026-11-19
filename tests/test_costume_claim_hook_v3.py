"""Instruction checks for the experimental absolute client trampoline."""
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
    UC_ARM64_REG_W19,
    UC_ARM64_REG_W21,
    UC_ARM64_REG_W24,
    UC_ARM64_REG_W25,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X14,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X28,
)

from tools.gen_costume_claim_hook_v3 import (  # noqa: E402
    BASE,
    CLIENT_EXPECTED,
    CLIENT_SITE,
    HANDLER,
    generate,
)

STACK = 0x10000000
SP = STACK + 0x3000
CLIENT = 0x50000000


def machine(base: int) -> Uc:
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address, size in ((base + 0xAB0000, 0x10000), (base + 0xB2A000, 0x2000),
                          (base + 0xBE3000, 0x1000), (STACK, 0x10000),
                          (CLIENT + 0x1625000, 0x1000), (CLIENT + 0x1C06000, 0x1000)):
        u.mem_map(address, size)
    installer, handler = generate()
    u.mem_write(base + BASE, installer)
    u.mem_write(base + HANDLER, handler)
    u.mem_write(base + 0xBE3798, struct.pack('<Q', CLIENT))
    u.reg_write(UC_ARM64_REG_SP, SP)
    u.reg_write(UC_ARM64_REG_LR, 0x12345678)
    return u


@pytest.mark.parametrize('base', [0, 0x30000000, 0x7200000000])
@pytest.mark.parametrize(('product', 'found', 'result'), [
    (75150, 1, 0), (75186, 1, 0), (75151, 1, 1),
    (75187, 1, 1), (99999, 0, 0), (99999, 1, 1),
])
def test_handler_invokes_original_and_scopes_result(base, product, found, result):
    u = machine(base)
    mail = STACK + 0x5000
    u.mem_write(mail + 0x30, struct.pack('<I', product))
    for reg, value in ((UC_ARM64_REG_X26, mail), (UC_ARM64_REG_X0, 0x1234),
                       (UC_ARM64_REG_X1, 0x5678), (UC_ARM64_REG_X2, 0),
                       (UC_ARM64_REG_W25, 5), (UC_ARM64_REG_W19, 9)):
        u.reg_write(reg, value)
    hits = []
    def intercept(uc, address, _size, _data):
        if address == CLIENT + 0x1C0665C:
            assert uc.reg_read(UC_ARM64_REG_X0) == 0x1234
            assert uc.reg_read(UC_ARM64_REG_X1) == 0x5678
            hits.append('original')
            uc.reg_write(UC_ARM64_REG_X0, found)
            uc.reg_write(UC_ARM64_REG_X13, 0x1313)
            uc.reg_write(UC_ARM64_REG_X14, 0x1414)
            uc.reg_write(UC_ARM64_REG_NZCV, 0x60000000)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        if address == CLIENT + 0x1625854:
            hits.append('return')
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, intercept)
    u.emu_start(base + HANDLER, 0, count=200)
    assert hits == ['original', 'return']
    assert u.reg_read(UC_ARM64_REG_X0) == result
    assert u.reg_read(UC_ARM64_REG_SP) == SP
    assert u.reg_read(UC_ARM64_REG_X13) == 0x1313
    assert u.reg_read(UC_ARM64_REG_X14) == 0x1414
    assert u.reg_read(UC_ARM64_REG_NZCV) == 0x60000000
    assert u.reg_read(UC_ARM64_REG_W8) == 1
    assert u.reg_read(UC_ARM64_REG_W21) == 5
    assert u.reg_read(UC_ARM64_REG_W24) == 9
    assert u.reg_read(UC_ARM64_REG_LR) == CLIENT + 0x1625848


@pytest.mark.parametrize('base', [0, 0x30000000, 0x7200000000])
def test_installer_writes_exact_trampoline_at_verified_site(base):
    u = machine(base)
    u.mem_write(SP + 0x10, struct.pack('<Q', 0x2828))
    calls = []
    def intercept(uc, address, _size, _data):
        if address == base + 0xAB575C:
            calls.append((uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
                          bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X2), 16)),
                          bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X3), 16)),
                          uc.reg_read(UC_ARM64_REG_X4)))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        if address == base + 0xAB3394:
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, intercept)
    u.emu_start(base + BASE, 0, count=200)
    assert len(calls) == 1
    client, rva, expected, replacement, words = calls[0]
    assert (client, rva, expected, words) == (CLIENT, CLIENT_SITE, CLIENT_EXPECTED, 4)
    assert replacement[:8] == bytes.fromhex('5000005800021fd6')
    assert struct.unpack('<Q', replacement[8:])[0] == base + HANDLER
    assert u.reg_read(UC_ARM64_REG_X28) == 0x2828
    assert u.reg_read(UC_ARM64_REG_SP) == SP
