"""Unit and reference-APK tests for full English localization (08.01)."""
from __future__ import annotations

import hashlib
import json
import zipfile
from functools import partial
from pathlib import Path

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from core.core_patches import (
    EXPECTED_PATCH_COUNTS,
    PatchOptions,
    apply_all_patches,
)
from core.costume_packages import inspect_costume_packages
from core.dex_smali import find_apktool_jar, find_java_executable
from core.elf_mapping import read_load_segments, translate_vaddr
from core.english_localization import (
    SHIPYARD_EN_ASSET_PATH,
    STRINGTABLE_EN_ASSET_PATH,
    apply_english_server_catalog,
    inspect_english_localization_assets,
    inspect_english_server_catalog,
    inspect_shipyarddata_english_rows,
    inspect_stringtable_english_rows,
    patch_shipyarddata_english_rows,
    patch_stringtable_english_rows,
)
from core.english_localization_data import (
    JSON_BOUNDARY_PATCHES,
    JSON_KR_TO_EN,
    RODATA_STR_PATCHES,
    SHIPYARD_EN_FIXES,
    STRINGTABLE_EN_FIXES,
    TEXT_SSO_PATCHES,
)
from core.hero_shop_offers import inspect_hero_shop_offers
from core.mythical_shop import inspect_mythical_shop
from core.patch_inspector import inspect_native_so
from core.surprise_transcendence_package import inspect_surprise_transcendence_package

ROOT = Path(__file__).resolve().parents[1]
REF_APK = ROOT / "source" / "fwt_0.682_offline_v1574.apk"


def _has_hangul(text: str) -> bool:
    return any("\uac00" <= ch <= "\ud7a3" for ch in text)


def test_translation_tables_have_no_hangul_and_fit_byte_budgets() -> None:
    assert len(JSON_KR_TO_EN) >= 1700
    for kr, en in JSON_KR_TO_EN.items():
        assert _has_hangul(kr)
        assert en.strip(), f"Empty JSON EN entry for {kr!r}"
        assert not _has_hangul(en), f"Hangul in JSON EN entry for {kr!r}: {en!r}"

    for vaddr, kr, en in RODATA_STR_PATCHES:
        assert _has_hangul(kr)
        assert en.strip(), f"Empty .rodata EN at 0x{vaddr:x}"
        assert not _has_hangul(en), f"Hangul in .rodata EN at 0x{vaddr:x}: {en!r}"
        assert len(en.encode("utf-8")) <= len(kr.encode("utf-8")), (
            f"Overflow at 0x{vaddr:x}: {en!r}"
        )

    # Fixed-length memcpy / SSO strings must match byte length exactly
    exact_len_vaddrs = {0x3EA282, 0x3F16F4, 0x40B370, 0x547533, 0x466B4D}
    seen_exact = set()
    for vaddr, kr, en in RODATA_STR_PATCHES:
        if vaddr in exact_len_vaddrs:
            assert len(en.encode("utf-8")) == len(kr.encode("utf-8")), (
                f"Fixed-memcpy length mismatch at 0x{vaddr:x}"
            )
            seen_exact.add(vaddr)
    assert seen_exact == exact_len_vaddrs

    for vaddr, length, _sha, rep in JSON_BOUNDARY_PATCHES:
        assert len(rep) == length, f"Boundary length mismatch at 0x{vaddr:x}"
        assert not _has_hangul(rep.decode("utf-8"))


def test_text_sso_instructions_disassemble_cleanly() -> None:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    expected = {
        0xA4B17C: ("mov", "w9, #0x7470"),
        0xA4B184: ("movk", "w9, #0x73, lsl #16"),
    }
    for vaddr, _orig, patched in TEXT_SSO_PATCHES:
        insns = list(md.disasm(patched, vaddr))
        assert len(insns) == 1
        assert (insns[0].mnemonic, insns[0].op_str) == expected[vaddr]


def test_stringtable_and_shipyard_helpers_idempotent_and_fail_closed() -> None:
    st_rows = [{"_id": rid, "_text": kr} for rid, (kr, _) in STRINGTABLE_EN_FIXES.items()]
    assert not inspect_stringtable_english_rows(st_rows)[0]
    assert patch_stringtable_english_rows(st_rows) == len(STRINGTABLE_EN_FIXES)
    assert patch_stringtable_english_rows(st_rows) == 0
    assert inspect_stringtable_english_rows(st_rows)[0]

    bad_st = list(st_rows)
    bad_st[0] = {"_id": bad_st[0]["_id"], "_text": "unexpected"}
    with pytest.raises(ValueError, match="Unexpected stringtableenglish row"):
        patch_stringtable_english_rows(bad_st)

    sy_rows = [{"_shipyardType": st, "_name": kr} for st, (kr, _) in SHIPYARD_EN_FIXES.items()]
    assert not inspect_shipyarddata_english_rows(sy_rows)[0]
    assert patch_shipyarddata_english_rows(sy_rows) == len(SHIPYARD_EN_FIXES)
    assert patch_shipyarddata_english_rows(sy_rows) == 0
    assert inspect_shipyarddata_english_rows(sy_rows)[0]


def test_inspect_english_localization_assets_enforces_plaintext_stringtable(
    tmp_path: Path,
) -> None:
    zpath = tmp_path / "res.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr(STRINGTABLE_EN_ASSET_PATH, b"NOT_UNITYFS_ENCRYPTED")
        zf.writestr(SHIPYARD_EN_ASSET_PATH, b"encrypted")
    with zipfile.ZipFile(zpath, "r") as zf:
        ok, msg = inspect_english_localization_assets(zf)
    assert not ok
    assert "must remain plaintext UnityFS" in msg


def test_boundary_split_arrays_decode_to_valid_json() -> None:
    # Pair consecutive left/right entries (excluding the 4 standalone 9-language event headers)
    pairs = JSON_BOUNDARY_PATCHES[:-4]
    assert len(pairs) % 2 == 0
    for idx in range(0, len(pairs), 2):
        _lva, _ll, _ls, l_rep = pairs[idx]
        _rva, _rl, _rs, r_rep = pairs[idx + 1]
        arr = json.loads((l_rep + r_rep).decode("utf-8"))
        assert isinstance(arr, list)
        assert len(arr) == 5
        assert all(isinstance(item, str) and not _has_hangul(item) for item in arr)


@pytest.mark.integration
def test_reference_full_english_and_shop_compatibility() -> None:
    if not REF_APK.is_file():
        pytest.skip("Reference APK not present in source/")
    jar = find_apktool_jar()
    if jar is None or find_java_executable() is None:
        pytest.skip("apktool or Java runtime not available")

    with zipfile.ZipFile(REF_APK) as zf:
        so_bytes = zf.read("lib/arm64-v8a/libfwt_local_server.so")
        dex_bytes = zf.read("classes8.dex")

    # 1. Standalone English localization
    res_en = apply_all_patches(
        so_bytes, dex_bytes, PatchOptions(english_localization=True), apktool_jar=jar
    )
    assert res_en.counts["english_localization"] == EXPECTED_PATCH_COUNTS["english_localization"]
    segs = read_load_segments(res_en.so_bytes)
    off_fn = partial(translate_vaddr, segs)
    ok, msg = inspect_english_server_catalog(res_en.so_bytes, off_fn)
    assert ok, msg
    assert inspect_native_so(res_en.so_bytes)["english_localization"].active

    # 2. Combined with all shop patches (02.07, 02.09, 02.10) + full catalog
    res_combo = apply_all_patches(
        so_bytes,
        dex_bytes,
        PatchOptions(
            english_localization=True,
            event_discount=True,
            event_gene_unlimited=True,
            event_limits_daily=True,
            campaign_shop_discount=True,
            mythical_stone_shop=True,
            hero_shop_offers=True,
            surprise_transcendence_package=True,
            costume_packages_all=True,
        ),
        apktool_jar=jar,
    )
    segs_c = read_load_segments(res_combo.so_bytes)
    off_c = partial(translate_vaddr, segs_c)
    ok_c, msg_c = inspect_english_server_catalog(res_combo.so_bytes, off_c)
    assert ok_c, msg_c
    assert inspect_hero_shop_offers(res_combo.so_bytes)
    assert inspect_mythical_shop(res_combo.so_bytes)
    assert inspect_surprise_transcendence_package(res_combo.so_bytes, off_c)
    assert inspect_costume_packages(res_combo.so_bytes, off_c)
    rep = inspect_native_so(res_combo.so_bytes)
    assert rep["english_localization"].active
    assert rep["hero_shop_offers"].active
    assert rep["mythical_stone_shop"].active
    assert rep["surprise_transcendence_package"].active
    assert rep["costume_packages_all"].active

    # Verify idempotency on already-translated raw SO
    buf = bytearray(res_en.so_bytes)
    assert apply_english_server_catalog(buf, off_fn) == 0
    assert hashlib.sha256(buf).hexdigest() == res_en.so_sha256
