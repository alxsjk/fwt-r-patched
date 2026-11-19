from __future__ import annotations

import json

import pytest

from core.costume_package_limits import apply_costume_package_limits, inspect_costume_package_limits


def _row(code: str) -> bytes:
    third = code == "75151"
    row = {
        "idx": 479569 if third else 479623,
        "shop_code": code,
        "shop_kind": 7,
        "numbering": "",
        "item_count": 1,
        "item_count_bonus": -1,
        "package_code": "103126" if third else "103132",
        "package_group_code": "215",
        "item_category": 255,
        "item_code": "-1",
        "first_bonus": -1,
        "gacha_weight_no": -1,
        "gacha_weight_10": -1,
        "price_cash": 10 if third else -1,
        "price_cash_sale": -1,
        "price_jewelry": -1 if third else 100,
        "price_friendship_point": -1,
        "price_coin": -1,
        "price_gold": -1,
        "tab_pos": "4",
        "display_image": "UI_75_0012",
        "display_order": "3",
        "shop_open": "1",
        "discount_rate": 0.0,
        "frame": 255,
        "icon_tag": 1,
        "sell_country": -1,
        "limit_type": 1,
        "limit_max": 200,
        "limit_hide": 255,
        "tab_id": -1,
        "shop_name": ["행운의 코스튬 특별 박스 " + ("3" if third else "4")] * 5,
        "shop_desc": ["-1"] * 5,
        "reg_date": "2026-06-22 12:00:00",
        "price_item_code": -1,
        "price_item_count": -1,
        "point": -1,
    }
    return json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def test_limit_patch_preserves_size_prices_other_fields_and_is_idempotent() -> None:
    first = _row("75151")
    second = _row("75187")
    calendar = b'{"shop_code":"75151","shop_type":2}'
    before = b"before" + calendar + first + second + first + second + b"after"
    buf = bytearray(before)
    assert apply_costume_package_limits(buf) == 4
    assert len(buf) == len(before)
    assert bytes(buf) == before.replace(b'"limit_max":200', b'"limit_max": 10')
    assert calendar in buf
    assert inspect_costume_package_limits(buf)
    after = bytes(buf)
    assert apply_costume_package_limits(buf) == 0
    assert bytes(buf) == after


def test_unknown_row_fails_closed_without_mutation() -> None:
    first = _row("75151")
    second = _row("75187")
    broken = second.replace(b'"price_jewelry":100', b'"price_jewelry":200')
    buf = bytearray(first + second + first + broken)
    before = bytes(buf)
    with pytest.raises(ValueError, match="Unexpected costume package row"):
        apply_costume_package_limits(buf)
    assert bytes(buf) == before
    assert not inspect_costume_package_limits(buf)


def test_mixed_rows_are_rejected_without_mutation() -> None:
    first = _row("75151")
    second = _row("75187")
    buf = bytearray(first + second + first + second)
    apply_costume_package_limits(buf)
    buf[:len(first)] = first
    before = bytes(buf)
    with pytest.raises(ValueError, match="Mixed stock and patched"):
        apply_costume_package_limits(buf)
    assert bytes(buf) == before
    assert not inspect_costume_package_limits(buf)


def test_missing_record_is_rejected() -> None:
    buf = bytearray(_row("75151") + _row("75187"))
    before = bytes(buf)
    with pytest.raises(ValueError, match="Expected exactly two copies"):
        apply_costume_package_limits(buf)
    assert bytes(buf) == before
