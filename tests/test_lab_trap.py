"""Phase 2: laboratory trap builds (`brk #0`).

The trap is the experiment that turns static evidence into a fact, so the bytes
matter: ``brk #0`` raises SIGTRAP, and a build that silently trapped nothing
would produce a meaningless "survived the session" result.
"""

from __future__ import annotations

import struct

import pytest

from core.core_patches import seg_offset
from tools.lab_trap_apk import BRK_ZERO, apply_traps


def test_brk_encoding_is_sigtrap():
    assert bytes.fromhex("000020d4") == BRK_ZERO
    assert struct.unpack("<I", BRK_ZERO)[0] == 0xD4200000


def test_apply_traps_writes_brk(reference_buffers):
    so_bytes, _dex = reference_buffers
    address = 0xB33314  # inside the demangler function the project already carves
    offset = seg_offset(address)
    original = so_bytes[offset : offset + 4]
    trapped = apply_traps(so_bytes, [address])
    assert trapped[offset : offset + 4] == BRK_ZERO
    assert trapped[offset : offset + 4] != original
    assert len(trapped) == len(so_bytes)
    # Everything else is untouched.
    assert trapped[:offset] == so_bytes[:offset]
    assert trapped[offset + 4 :] == so_bytes[offset + 4 :]


def test_apply_traps_multiple_addresses(reference_buffers):
    so_bytes, _dex = reference_buffers
    addresses = [0xB243D0, 0xB245DC]
    trapped = apply_traps(so_bytes, addresses)
    for address in addresses:
        offset = seg_offset(address)
        assert trapped[offset : offset + 4] == BRK_ZERO


def test_apply_traps_is_idempotent(reference_buffers):
    so_bytes, _dex = reference_buffers
    once = apply_traps(so_bytes, [0xB243D0])
    assert apply_traps(once, [0xB243D0]) == once


def test_apply_traps_rejects_addresses_outside_the_file(reference_buffers):
    so_bytes, _dex = reference_buffers
    with pytest.raises(SystemExit):
        apply_traps(so_bytes, [0xFFFFFFF0])
