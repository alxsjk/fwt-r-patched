from __future__ import annotations

import json

import pytest

from core.mythical_shop import apply_mythical_shop, inspect_mythical_shop


def _offer(code: str, *, discounted: bool = False, daily: bool = False) -> bytes:
    first = code == "2330278"
    row = {
        "idx": 36897400 if first else 36901496,
        "shop_code": code,
        "shop_content": 2,
        "event_code": 278,
        "item_category": 17,
        "item_code": "210002",
        "item_count": 10 if first else 20,
        "item_value": -1,
        "gacha_weight_no": -1,
        "gacha_weight_10": -1,
        "price_code": "-1",
        "price_count": (200 if first else 350) if discounted else (2000 if first else 3500),
        "tab_pos": 3,
        "display_image": "-1",
        "display_order": 2 if first else 3,
        "frame": 0,
        "limit_type": 1 if daily else 4,
        "limit_max": 3 if first else 4,
        "main_shop_code": -1,
        "tab_id": -1,
        "shop_name": ["균형의 옥"] * 5,
        "shop_desc": [""] * 5,
        "discount": 0,
    }
    payload = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # Existing discount retains the field width with a leading JSON space.
    if discounted:
        payload = payload.replace(b'"price_count":', b'"price_count": ', 1)
    return payload


@pytest.mark.parametrize("discounted", [False, True])
@pytest.mark.parametrize("daily", [False, True])
def test_catalog_patch_is_length_preserving_and_idempotent(discounted: bool, daily: bool) -> None:
    one = _offer("2330278", discounted=discounted, daily=daily)
    two = _offer("2331278", discounted=discounted, daily=daily)
    original = b"prefix[" + one + b"," + two + b"]separator[" + one + b"," + two + b"]suffix"
    buf = bytearray(original)
    assert apply_mythical_shop(buf) == 4
    assert len(buf) == len(original)
    assert bytes(buf[:7]) == b"prefix["
    assert bytes(buf[-7:]) == b"]suffix"
    assert inspect_mythical_shop(buf)
    chunks = bytes(buf)[7:-7].split(b"]separator[")
    parsed = [json.loads(b"[" + chunk + b"]") for chunk in chunks]
    assert parsed[0] == parsed[1]
    stone, jade = parsed[0]
    assert (stone["item_code"], stone["item_count"], stone["price_count"]) == ("2040031", 1, 50)
    assert (stone["limit_type"], stone["limit_max"]) == (1, 100)
    assert stone["shop_name"][:2] == ["Mythical Stone"] * 2
    assert (jade["item_code"], jade["item_count"], jade["limit_type"], jade["limit_max"]) == (
        "210002", 20, 1, 20
    )
    assert jade["price_count"] == (350 if discounted else 3500)
    assert jade["shop_name"][-1] == "균형의옥"
    patched = bytes(buf)
    assert apply_mythical_shop(buf) == 0
    assert bytes(buf) == patched


def test_unexpected_record_is_rejected_without_mutation() -> None:
    one = _offer("2330278")
    two = _offer("2331278")
    tampered = two.replace(b'"item_count":20', b'"item_count":21')
    buf = bytearray(one + two + one + tampered)
    before = bytes(buf)
    with pytest.raises(ValueError, match="Invalid Mythical Stone shop row"):
        apply_mythical_shop(buf)
    assert bytes(buf) == before
    assert not inspect_mythical_shop(buf)


def test_partial_patch_is_rejected_without_mutation() -> None:
    one = _offer("2330278")
    two = _offer("2331278")
    complete = bytearray(one + two + one + two)
    apply_mythical_shop(complete)
    mixed = bytearray(one + two + bytes(complete)[len(one) + len(two):])
    before = bytes(mixed)
    with pytest.raises(ValueError, match="Mixed stock and patched"):
        apply_mythical_shop(mixed)
    assert bytes(mixed) == before
    assert not inspect_mythical_shop(mixed)


@pytest.mark.parametrize("discounted", [False, True])
@pytest.mark.parametrize("daily", [False, True])
def test_reference_catalog_composes_with_shop_options(
    reference_buffers: tuple[bytes, bytes], discounted: bool, daily: bool
) -> None:
    from core.core_patches import PatchOptions, apply_all_patches
    from core.patch_inspector import inspect_native_so

    so, dex = reference_buffers
    result = apply_all_patches(
        so,
        dex,
        PatchOptions(
            mythical_stone_shop=True,
            event_discount=discounted,
            event_limits_daily=daily,
        ),
    )
    assert result.counts["mythical_stone_shop"] == 4
    assert inspect_native_so(result.so_bytes)["mythical_stone_shop"].active

