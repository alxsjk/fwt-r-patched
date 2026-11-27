"""Strict, length-preserving limits for the two Lucky Costume products.

The change only modifies embedded catalog records. The inspector does not
independently establish that purchase enforcement or daily reset works.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_STOCK_HASHES = {
    "75151": "5f1c249582158339816c67ba486153912c190bab966f249891f6ec1ba3d47ed1",
    "75187": "813aaecb1118a0e010b871a88f9e9c118f806f01d0b42ef878e9ac64e410bac4",
}
_STOCK_SHOP_NAMES = {
    "75151": ["행운의 코스튬 특별 박스 3"] * 5,
    "75187": ["행운의 코스튬 특별 박스 4"] * 5,
}
_EN_SHOP_NAMES = {
    "75151": ["Lucky Costume Special Box 3"] * 5,
    "75187": ["Lucky Costume Special Box 4"] * 5,
}
_ROWS = re.compile(
    rb'\{(?=[^{}]*?"shop_code":"(75151|75187)")'
    rb'(?=[^{}]*?"shop_kind":7(?:,|\}))[^{}]*?\}'
)
_LIMIT = re.compile(rb'"limit_max":(200| 10)(?=,|\})')


def _hash_row(row: dict[str, Any]) -> str:
    payload = json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _read_rows(data: bytes | bytearray) -> list[tuple[re.Match[bytes], str, str]]:
    result: list[tuple[re.Match[bytes], str, str]] = []
    for match in _ROWS.finditer(data):
        code = match.group(1).decode("ascii")
        try:
            row = json.loads(match.group(0))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(f"Invalid costume package row {code}") from exc
        limit = _LIMIT.findall(match.group(0))
        if len(limit) != 1 or row.get("limit_type") != 1:
            raise ValueError(f"Unexpected costume package limit for {code}")
        state = "stock" if limit[0] == b"200" else "patched"
        if row.get("limit_max") != (200 if state == "stock" else 10):
            raise ValueError(f"Unexpected costume package limit for {code}")
        row["limit_max"] = 200
        if row.get("shop_name") == _EN_SHOP_NAMES[code]:
            row["shop_name"] = list(_STOCK_SHOP_NAMES[code])
        if _hash_row(row) != _STOCK_HASHES[code]:
            raise ValueError(f"Unexpected costume package row {code}")
        result.append((match, code, state))
    if len(result) != 4 or any(sum(code == entry[1] for entry in result) != 2 for code in _STOCK_HASHES):
        raise ValueError("Expected exactly two copies of each costume package row")
    if len({state for _, _, state in result}) != 1:
        raise ValueError("Mixed stock and patched costume package rows")
    return result


def inspect_costume_package_limits(data: bytes | bytearray) -> bool:
    """Check all four modified catalog records, not reset or enforcement."""
    try:
        return _read_rows(data)[0][2] == "patched"
    except ValueError:
        return False


def apply_costume_package_limits(buf: bytearray) -> int:
    """Set both purchase records to ten per day without changing their length."""
    rows = _read_rows(buf)
    if rows[0][2] == "patched":
        return 0
    changes = []
    for match, _, _ in rows:
        limit = _LIMIT.search(match.group(0))
        if limit is None:
            raise ValueError("Missing validated costume package limit")
        changes.append(match.start() + limit.start(1))
    for offset in changes:
        buf[offset:offset + 3] = b" 10"
    return len(changes)
