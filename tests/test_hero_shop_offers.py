from __future__ import annotations

import re

import pytest

from core.core_patches import PatchOptions, apply_all_patches
from core.hero_shop_offers import apply_hero_shop_offers, inspect_hero_shop_offers
from core.patch_inspector import inspect_native_so


@pytest.mark.parametrize("discounts", [False, True])
@pytest.mark.parametrize("limits", [False, True])
def test_hero_shop_composes_with_existing_options(
    reference_buffers: tuple[bytes, bytes], discounts: bool, limits: bool
) -> None:
    so, dex = reference_buffers
    result = apply_all_patches(
        so, dex, PatchOptions(
            hero_shop_offers=True, event_discount=discounts,
            campaign_shop_discount=discounts, event_gene_unlimited=limits,
            event_limits_daily=limits,
        ),
    )
    patched = result.so_bytes
    assert len(patched) == len(so)
    assert result.counts["hero_shop_offers"] == 6
    assert inspect_hero_shop_offers(patched)
    reports = inspect_native_so(patched)
    assert reports["hero_shop_offers"].active
    for key, enabled in (("event_discount", discounts), ("campaign_shop_discount", discounts),
                         ("event_gene_unlimited", limits), ("event_limits_daily", limits)):
        if enabled:
            assert reports[key].active, reports[key].details
    for code, item, price in ((b"2250278", b"120741", b"5"), (b"1103", b"130181", b"1")):
        rows = re.findall(rb'"shop_code":"' + code + rb'"[^{}\x00]*?\}', patched)
        assert len(rows) == 2
        assert all(b'"item_category":18' in row and b'"item_code":"' + item + b'"' in row
                   and b'"price_count":' + price + b',' in row
                   and b'"limit_type":255,"limit_max":255' in row for row in rows)
    diamonds = re.findall(rb'"shop_code":"1104"[^{}\x00]*', patched)
    assert len(diamonds) == 2
    assert all(b'"item_count":100,' in row for row in diamonds)
    repeat = bytearray(patched)
    assert apply_hero_shop_offers(repeat) == 0
    assert repeat == patched


def test_modified_or_partial_catalog_is_rejected_atomically(
    reference_buffers: tuple[bytes, bytes],
) -> None:
    so, _ = reference_buffers
    damaged = bytearray(so)
    start = damaged.index(b'"shop_code":"1103"')
    pos = damaged.index(b'"item_count":40', start)
    damaged[pos:pos + len(b'"item_count":40')] = b'"item_count":41'
    before = bytes(damaged)
    with pytest.raises(ValueError, match="hero shop row"):
        apply_hero_shop_offers(damaged)
    assert bytes(damaged) == before
    assert not inspect_hero_shop_offers(damaged)
