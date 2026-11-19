"""Instruction-level tests for laboratory equipment-tier proposal."""
from __future__ import annotations

import struct

import pytest

pytest.importorskip('unicorn')
pytest.importorskip('keystone')
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X25,
    UC_ARM64_REG_X29,
)

from tools.gen_equipment_tier_lab import CAVE, generate  # noqa: E402


@pytest.mark.parametrize(('level', 'expected'), [(9,10),(10,15),(11,15),(14,15),(15,20),(16,20),
                                           (19,20),(20,26),(21,26),(25,26),(26,27)])
@pytest.mark.parametrize('material_type', [0,1,2])
def test_tier_cap(level, expected, material_type):
    u=Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0xA18000,0x1000)
    u.mem_map(0xB2A000,0x1000)
    u.mem_map(0x10000000,0x10000)
    u.reg_write(UC_ARM64_REG_SP,0x10002000)
    u.reg_write(UC_ARM64_REG_X29,0x10003000)
    u.mem_write(0x10003000,struct.pack("<Q",0x10004000))
    u.mem_write(0x10004028,struct.pack("<Q",material_type))
    u.mem_write(CAVE,generate())
    u.reg_write(UC_ARM64_REG_X8,level)
    u.reg_write(UC_ARM64_REG_X25,9520)
    def stop(uc,addr,_size,_data):
        if addr==0xA188C0:
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,stop)
    u.emu_start(CAVE,0,count=100)
    assert u.reg_read(UC_ARM64_REG_X10)==(expected if material_type==1 else level+1)
    assert u.reg_read(UC_ARM64_REG_X8)==level
    assert u.reg_read(UC_ARM64_REG_X25)==9520
