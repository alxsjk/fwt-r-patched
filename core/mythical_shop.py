"""Length-preserving native catalog edits for the Mythical Stone shop offer.

This module edits offer data only. It does not implement or prove daily reset
or server-side purchase-limit enforcement. Apply after other event-shop edits.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_OFFER_PATTERN = re.compile(
    rb'\{[^{}]*?"shop_code":"(2330278|2331278)"[^{}]*?\}'
)
_STOCK_HASHES = {
    "2330278": "8b2a10cd1ff19c68bdcfd1f9301f30bd01fc8314324a33231db2f9033389a559",
    "2331278": "0405db571032354cea5c1df78233edbc709890d87f8e1da1cdd5b7a4fa76bfe5",
}
_STOCK_NAME = "균형의 옥"
_STONE_NAMES = ["Mythical Stone", "Mythical Stone", "Mythic Stone", "Mythic Stone", "Mythic Stone"]
_JADE_NAMES = [_STOCK_NAME] * 4 + ["균형의옥"]
_JADE_NAMES_EN = ["Balance Jade"] * 5


def _hash_row(row: dict[str, Any]) -> str:
    payload = json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _normalize(row: dict[str, Any], code: str, patched: bool) -> dict[str, Any]:
    """Restore fields varied by supported patches for a reference-profile check."""
    normalized = dict(row)
    normalized["price_count"] = 2000 if code == "2330278" else 3500
    normalized["limit_type"] = 4
    if patched:
        normalized["limit_max"] = 3 if code == "2330278" else 4
        normalized["shop_name"] = [_STOCK_NAME] * 5
        if code == "2330278":
            normalized["item_code"] = "210002"
            normalized["item_count"] = 10
    return normalized


def _classify(row: dict[str, Any], code: str) -> str:
    """Classify one record, rejecting anything beyond known option combinations."""
    if code == "2330278":
        stock = (
            row.get("item_code") == "210002"
            and row.get("item_count") == 10
            and row.get("price_count") in (2000, 200)
            and row.get("limit_type") in (1, 4)
            and row.get("limit_max") == 3
            and row.get("shop_name") == [_STOCK_NAME] * 5
        )
        patched = (
            row.get("item_code") == "2040031"
            and row.get("item_count") == 1
            and row.get("price_count") == 50
            and row.get("limit_type") == 1
            and row.get("limit_max") == 100
            and row.get("shop_name") == _STONE_NAMES
        )
    else:
        stock = (
            row.get("price_count") in (3500, 350)
            and row.get("limit_type") in (1, 4)
            and row.get("limit_max") == 4
            and row.get("shop_name") == [_STOCK_NAME] * 5
        )
        patched = (
            row.get("price_count") in (3500, 350)
            and row.get("limit_type") == 1
            and row.get("limit_max") == 20
            and row.get("shop_name") in (_JADE_NAMES, _JADE_NAMES_EN)
        )
    state = "stock" if stock else "patched" if patched else "unknown"
    if state == "unknown" or _hash_row(_normalize(row, code, state == "patched")) != _STOCK_HASHES[code]:
        raise ValueError(f"Unexpected Mythical Stone shop row {code}")
    return state


def _read_rows(data: bytes | bytearray) -> list[tuple[re.Match[bytes], dict[str, Any], str]]:
    found: list[tuple[re.Match[bytes], dict[str, Any], str]] = []
    for match in _OFFER_PATTERN.finditer(data):
        code = match.group(1).decode("ascii")
        try:
            row = json.loads(match.group(0))
            state = _classify(row, code)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(f"Invalid Mythical Stone shop row {code}") from exc
        found.append((match, row, state))
    if len(found) != 4 or [str(r[1]["shop_code"]) for r in found].count("2330278") != 2:
        raise ValueError("Expected exactly two copies of each target shop row")
    if len({state for _, _, state in found}) != 1:
        raise ValueError("Mixed stock and patched Mythical Stone shop rows")
    for code in _STOCK_HASHES:
        copies = [r for _, r, _ in found if r["shop_code"] == code]
        if copies[0] != copies[1]:
            raise ValueError(f"Inconsistent copies of shop row {code}")
    if found[0][2] == "stock":
        first = next(r for _, r, _ in found if r["shop_code"] == "2330278")
        second = next(r for _, r, _ in found if r["shop_code"] == "2331278")
        if (first["price_count"], second["price_count"]) not in ((2000, 3500), (200, 350)):
            raise ValueError("Inconsistent event-shop price profile")
        if first["limit_type"] != second["limit_type"]:
            raise ValueError("Inconsistent event-shop limit profile")
    return found


def inspect_mythical_shop(data: bytes | bytearray) -> bool:
    """Return whether all four offer records match the patched catalog profile.

    This is only a catalog check; it does not check purchase or reset behavior.
    """
    try:
        rows = _read_rows(data)
        return rows[0][2] == "patched"
    except ValueError:
        return False


def apply_mythical_shop(buf: bytearray) -> int:
    """Patch both copies of each offer in place; reject unknown/mixed inputs.

    Run after event-discount and event-limit table patches. The final localized
    jade name loses one space to retain the binary record's exact length.
    """
    rows = _read_rows(buf)
    if rows[0][2] == "patched":
        return 0
    changes: list[tuple[int, int, bytes]] = []
    for match, row, _ in rows:
        if row["shop_code"] == "2330278":
            row.update(item_code="2040031", item_count=1, price_count=50,
                       limit_type=1, limit_max=100, shop_name=_STONE_NAMES)
        else:
            row.update(limit_type=1, limit_max=20, shop_name=_JADE_NAMES)
        encoded = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        available = match.end() - match.start() - len(encoded)
        if available < 0:
            raise ValueError("Target shop row exceeds its original binary length")
        replacement = encoded[:-1] + b" " * available + b"}"
        changes.append((match.start(), match.end(), replacement))
    for start, end, replacement in changes:
        buf[start:end] = replacement
    return len(changes)
