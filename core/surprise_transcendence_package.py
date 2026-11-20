"""Checked, length-preserving catalog edits for Surprise Sale offer 75103."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

# Package 103114 is shared by other offers. Its replacement for 75103 uses
# two unused package-definition slots and two unlisted, unpriced shop rows.
_OFFER_ADDRESSES = (0x32589A, 0x51F76D)
_ROWS = (
    (
        _OFFER_ADDRESSES, 943,
        "ff455886082d2c19f3c7596ebc54ef608afbcab6f6cd34f1cb3a4dac25b5d9eb",
        "9ba0c998c31b3c398ce67c444dee6bbb36a3e26d02d356f23e56e3d51d48505e",
        {"package_code": "103899", "price_jewelry": 500},
    ),
    (
        (0x218A72, 0x298AD3), 187,
        "820703f94ae22bb279da78d6663caf6bec16d93c656ff76618ebfa916b5e2620",
        "0f8f589a3fc4b867a9c7dbde07f889e53bd1ad02d58f9b9c27d15d926eb234a0",
        {
            "package_code": "103899",
            "shop_code": ["65024", "65026"],
            "package_img": "135#GUI_BannerMain_001",
            "package_img_2nd": 130431,
        },
    ),
    (
        (0x2F14E4,), 788,
        "22894dbafa46a1c1d5619c170e15e004420ca339a6d93b4e2e900584da59f4db",
        "83ffb7a84a202f1f01e2707912c320299efad4bb218151ba3a7b473fbdf28fd1",
        {
            "item_code": "130006",
            "item_count": 10,
            "shop_name": ["Ultimate Equipment Transcendence Ticket", *(["Ultimate"] * 4)],
        },
    ),
    (
        (0x2F17F9,), 790,
        "d741e9281c606dec76bc3a5d5c3cb66111a639174b12c44bbbde94a01b8709f9",
        "558383edf16e3f945bdaa8761dbb58170b9413e760af4a07476bd7233e753d1d",
        {
            "item_code": "130000",
            "item_count": 10,
            "shop_name": ["Universal Transcendence Ticket", *(["Universal"] * 4)],
        },
    ),
)


def _record_digest(raw: bytes | bytearray, address: int) -> str:
    # The daily event limit patch can change the offer's limit_type from 4 to 1.
    if address in _OFFER_ADDRESSES:
        raw = raw.replace(b'"limit_type":1,', b'"limit_type":4,', 1)
    return hashlib.sha256(raw).hexdigest()


def apply_surprise_transcendence_package(buf: bytearray, offset: Callable[[int], int]) -> int:
    """Apply the isolated offer only after verifying all six records."""
    pending: list[tuple[int, int, bytes]] = []
    for addresses, size, stock_hash, patched_hash, updates in _ROWS:
        for address in addresses:
            start = offset(address)
            raw = buf[start:start + size]
            digest = _record_digest(raw, address)
            if digest == patched_hash:
                continue
            if digest != stock_hash:
                raise ValueError(f"Unexpected Surprise Sale record at 0x{address:x}")
            row = json.loads(raw)
            row.update(updates)
            encoded = json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(encoded) > size:
                raise ValueError(f"Surprise Sale record at 0x{address:x} exceeds its slot")
            replacement = encoded[:-1] + b" " * (size - len(encoded)) + b"}"
            if _record_digest(replacement, address) != patched_hash:
                raise ValueError(f"Unexpected Surprise Sale replacement at 0x{address:x}")
            pending.append((start, size, replacement))
    for start, size, replacement in pending:
        buf[start:start + size] = replacement
    return len(pending)


def inspect_surprise_transcendence_package(
    buf: bytes | bytearray, offset: Callable[[int], int],
) -> bool:
    """Verify both offer entries, both package entries, and both delivery rows."""
    for addresses, size, _, patched_hash, _ in _ROWS:
        for address in addresses:
            start = offset(address)
            if _record_digest(buf[start:start + size], address) != patched_hash:
                return False
    return True
