"""Strict, length-preserving edits to the reference hero shop offers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_CODES = ("2250278", "1103", "1104")
_HASHES = {
    "2250278": "c6d51752dd573cf6b9b0be01011469148056352fc709fc0f5818b41f28308ca7",
    "1103": "768466c6ea79f2b701859ae7ed8d2e5c11d12825ccd91cf474f1a6a09ed56b45",
    "1104": "258debfbcb04af205fa3aedd6d8c04d74facac8075ece37474bc29c36c37c083",
}
_FRAGMENT_HASH = "d9025cf0a90592ebdf728f02aa69feb380a6022d0aa5173bd51064b62007e31b"
_STOCK_NAMES = {"2250278": "쌍둥이 메이드 스푸키", "1103": "다이아", "1104": "다이아"}


def _digest(row: dict[str, Any]) -> str:
    raw = json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _normalize(row: dict[str, Any], code: str) -> tuple[str, dict[str, Any]]:
    result = dict(row)
    if code == "2250278":
        stock = row.get("item_category") == 20 and row.get("item_code") == "220095"
        patched = (row.get("item_category") == 18 and row.get("item_code") == "120741"
                   and row.get("item_count") == 1 and row.get("price_count") == 5
                   and row.get("limit_type") == 255 and row.get("limit_max") == 255
                   and row.get("shop_name") == ["Evan"] * 5)
        if stock and (row.get("price_count") not in (1000, 100)
                      or row.get("limit_type") not in (1, 3)):
            raise ValueError("Unexpected Evan source profile")
        if patched:
            result.update(item_category=20, item_code="220095", item_count=1,
                          limit_max=1, shop_name=[_STOCK_NAMES[code]] * 5)
        result.update(price_count=1000, limit_type=3)
    elif code == "1103":
        stock = row.get("item_category") == 17 and row.get("item_code") == "100001"
        patched = (row.get("item_category") == 18 and row.get("item_code") == "130181"
                   and row.get("item_count") == 1 and row.get("price_count") == 1
                   and row.get("limit_type") == 255 and row.get("limit_max") == 255
                   and row.get("shop_name") == ["Alex"] * 5)
        if stock and (row.get("price_count") not in (50, 5)
                      or row.get("limit_type") not in (1, 4)):
            raise ValueError("Unexpected Alex source profile")
        if patched:
            result.update(item_category=17, item_code="100001", item_count=40,
                          limit_max=1, shop_name=[_STOCK_NAMES[code]] * 5)
        result.update(price_count=50, limit_type=4)
    else:
        stock = row.get("item_count") == 60 and row.get("shop_name") == ["다이아"] * 5
        patched = (
            row.get("item_count") == 100
            and row.get("shop_name") in (["Diamond"] + ["다이아"] * 4, ["Diamond"] * 5)
        )
        if row.get("price_count") not in (100, 10) or row.get("limit_type") not in (1, 4):
            raise ValueError("Unexpected diamond source profile")
        if patched:
            result.update(item_count=60, shop_name=["다이아"] * 5)
        result.update(price_count=100, limit_type=4)
    state = "stock" if stock else "patched" if patched else "unknown"
    if state == "unknown" or _digest(result) != _HASHES[code]:
        raise ValueError(f"Unexpected hero shop row {code}")
    return state, row


def _fragment(raw: bytes) -> str:
    original = raw
    patched = b'"item_count":100' in raw
    if patched:
        raw = raw.replace(b'"item_count":100', b'"item_count":60', 1)
        en_frag = b'"shop_name":[      "Diamond","Diamond","Diamond","Diamond","'
        if en_frag in raw:
            raw = raw.replace(
                en_frag,
                '"shop_name":["다이아","다이아","다이아","다이아","'.encode(),
                1,
            )
        else:
            raw = raw.replace(b'"shop_name":["Diamond"', '"shop_name":["다이아"'.encode(), 1)
        raw = raw.replace(b'"item_count":60, ', b'"item_count":60,', 1)
    raw = re.sub(rb'"price_count":\s*(?:100|10)(?=,)', b'"price_count":100', raw, count=1)
    raw = re.sub(rb'"limit_type":(?:1|4)(?=,)', b'"limit_type":4', raw, count=1)
    if hashlib.sha256(raw).hexdigest() != _FRAGMENT_HASH:
        raise ValueError("Unexpected fragmented diamond row")
    if patched and original.count(b'"item_count":100') != 1:
        raise ValueError("Invalid fragmented diamond row")
    return "patched" if patched else "stock"


def _rows(data: bytes | bytearray) -> list[tuple[int, int, str, str, dict[str, Any] | None]]:
    result: list[tuple[int, int, str, str, dict[str, Any] | None]] = []
    for code in _CODES:
        marker = ('"shop_code":"' + code + '"').encode()
        positions = [m.start() for m in re.finditer(re.escape(marker), data)]
        if len(positions) != 2:
            raise ValueError(f"Expected two copies of hero shop row {code}")
        for position in positions:
            start = data.rfind(b"{", 0, position)
            end_brace = data.find(b"}", position)
            end_nul = data.find(b"\0", position)
            if start < 0 or end_brace < 0 or end_nul < 0:
                raise ValueError(f"Incomplete hero shop row {code}")
            end = min(end_brace + 1, end_nul)
            raw = bytes(data[start:end])
            if not raw.endswith(b"}"):
                if code != "1104":
                    raise ValueError(f"Unexpected fragmented hero shop row {code}")
                result.append((start, end, code, _fragment(raw), None))
            else:
                try:
                    state, row = _normalize(json.loads(raw), code)
                except (ValueError, TypeError, UnicodeError) as exc:
                    raise ValueError(f"Invalid hero shop row {code}") from exc
                result.append((start, end, code, state, row))
    if len({entry[3] for entry in result}) != 1:
        raise ValueError("Mixed stock and patched hero shop rows")
    for code in _CODES:
        copies = [entry for entry in result if entry[2] == code]
        full = [entry[4] for entry in copies if entry[4] is not None]
        if len(full) == 2 and full[0] != full[1]:
            raise ValueError(f"Inconsistent copies of hero shop row {code}")
        if code == "1104" and len(full) == 1:
            fragment = next(entry for entry in copies if entry[4] is None)
            raw = bytes(data[fragment[0]:fragment[1]])
            for field in ("price_count", "limit_type", "limit_max"):
                match = re.search(('"' + field + r'":\s*(\d+)').encode(), raw)
                if match is None or int(match.group(1)) != full[0][field]:
                    raise ValueError("Inconsistent copies of hero shop row 1104")
    return result


def inspect_hero_shop_offers(data: bytes | bytearray) -> bool:
    try:
        return _rows(data)[0][3] == "patched"
    except ValueError:
        return False


def apply_hero_shop_offers(buf: bytearray) -> int:
    rows = _rows(buf)
    if rows[0][3] == "patched":
        return 0
    changes = []
    for start, end, code, _, row in rows:
        if row is None:
            raw = bytes(buf[start:end]).replace(b'"item_count":60', b'"item_count":100', 1)
            raw = raw.replace('"shop_name":["다이아"'.encode(), b'"shop_name":["Diamond"', 1)
            raw = raw.replace(b'"item_count":100,', b'"item_count":100, ', 1)
        else:
            if code == "2250278":
                row.update(item_category=18, item_code="120741", item_count=1,
                           price_count=5, limit_type=255, limit_max=255, shop_name=["Evan"] * 5)
            elif code == "1103":
                row.update(item_category=18, item_code="130181", item_count=1,
                           price_count=1, limit_type=255, limit_max=255, shop_name=["Alex"] * 5)
            else:
                row.update(item_count=100, shop_name=["Diamond"] + ["다이아"] * 4)
            raw = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if code == "1104" and row["price_count"] == 10:
                raw = raw.replace(b'"price_count":10,', b'"price_count": 10,', 1)
            padding = end - start - len(raw)
            if padding < 0:
                raise ValueError(f"Hero shop row {code} exceeds its allocated size")
            raw = raw[:-1] + b" " * padding + b"}"
        if len(raw) != end - start:
            raise ValueError(f"Hero shop row {code} changed length")
        changes.append((start, end, raw))
    for start, end, raw in changes:
        buf[start:end] = raw
    return len(changes)
