"""Server-side & client-datatable English localization helpers (feature 08.01).

Translates embedded Korean JSON catalogs, NUL-split JSON boundary fragments,
small NUL-terminated C++ strings in ``.rodata`` (with exact-byte-length
guarantees and the two-instruction SSO fix at ``0xA4B17C``/``0xA4B184``),
and leftover Korean rows in ``stringtableenglish.unity3d`` and
``shipyarddataenglish.unity3d``.
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections.abc import Callable
from functools import partial
from typing import Any

from core.elf_mapping import read_load_segments, translate_vaddr
from core.english_localization_data import (
    JSON_BOUNDARY_PATCHES,
    JSON_KR_TO_EN,
    RODATA_STR_PATCHES,
    SHIPYARD_EN_FIXES,
    STRINGTABLE_EN_FIXES,
    TEXT_SSO_PATCHES,
)

RODATA_VADDR_START = 0x16F710
RODATA_VADDR_END = 0x7994EC

# Boundary entry 0x215DE1 (shop_code "1104") shifts by 2 bytes when
# apply_hero_shop_offers() runs first ("item_count":60 -> "item_count":100, ).
_HERO_1104_LEFT_VADDR = 0x215DE1
_HERO_1104_LEFT_LEN = 50
_HERO_1104_LEFT_PATCHED_SHA256 = (
    "654f288b5c2ea647dd82c9be33e3d612b700ee273293c0b6f842dc97d987623d"
)
_HERO_1104_LEFT_PATCHED_REP = b'":[      "Diamond","Diamond","Diamond","Diamond","'

_ARRAY_START_RE = re.compile(rb'(?:"[a-zA-Z0-9_]*"|):\[')
_HANGUL_BYTES_RE = re.compile(rb"[\xea-\xed][\x80-\xbf]{2}")

STRINGTABLE_EN_ASSET_PATH = "files/Resources/datatable/stringtableenglish.unity3d"
SHIPYARD_EN_ASSET_PATH = "files/Resources/datatable/shipyarddataenglish.unity3d"


def _has_hangul(text: str) -> bool:
    return any("\uac00" <= ch <= "\ud7a3" for ch in text)


def _scan_json_array_end(buf: bytes, start_bracket: int) -> int | None:
    """Return index right after the matching ``]`` of a JSON array, or None on NUL/invalid."""
    i = start_bracket + 1
    n = len(buf)
    depth = 1
    in_str = False
    esc = False
    while i < n:
        b = buf[i]
        if b == 0:
            return None
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:
                esc = True
            elif b == 0x22:
                in_str = False
        else:
            if b == 0x22:
                in_str = True
            elif b == 0x5B:
                depth += 1
            elif b == 0x5D:
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return None


def _map_five_slot(sub: list[str]) -> list[str]:
    return [JSON_KR_TO_EN[v] if _has_hangul(v) else v for v in sub]


def _encode_array_in_place(vals: list[Any], max_bytes: int) -> bytes:
    """Encode a 1D (5-slot) or 2D (list of 5-slot) string array inside ``max_bytes``."""
    if vals and isinstance(vals[0], list):
        mapped_2d = [_map_five_slot(sub) for sub in vals]
        encoded = json.dumps(mapped_2d, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) <= max_bytes:
            return encoded[:-1] + b" " * (max_bytes - len(encoded)) + b"]"
        for short in ("Item", "I"):
            compact_2d = [[s[0], s[1], short, short, short] for s in mapped_2d]
            encoded = json.dumps(compact_2d, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            if len(encoded) <= max_bytes:
                return encoded[:-1] + b" " * (max_bytes - len(encoded)) + b"]"
        raise ValueError(f"Translated 2D JSON array exceeds {max_bytes} bytes: {mapped_2d!r}")

    mapped = _map_five_slot(vals)
    encoded = json.dumps(mapped, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded[:-1] + b" " * (max_bytes - len(encoded)) + b"]"
    for short in ("Item", "I"):
        compact = [mapped[0], mapped[1], short, short, short]
        encoded = json.dumps(compact, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) <= max_bytes:
            return encoded[:-1] + b" " * (max_bytes - len(encoded)) + b"]"
    raise ValueError(f"Translated 5-slot JSON array exceeds {max_bytes} bytes: {mapped!r}")


def _is_translatable_str_array(vals: object) -> bool:
    if not isinstance(vals, list) or not vals:
        return False
    if len(vals) == 5 and all(isinstance(v, str) for v in vals):
        return any(_has_hangul(v) for v in vals)
    return all(
        isinstance(sub, list) and len(sub) == 5 and all(isinstance(v, str) for v in sub)
        for sub in vals
    ) and any(_has_hangul(v) for sub in vals for v in sub)


def _iter_rodata_json_arrays(
    ro_slice: memoryview | bytes | bytearray,
    ro_file_offset: int,
) -> list[tuple[int, bytes, list[Any]]]:
    """Return ``(file_offset, raw_array_bytes, decoded_list)`` for every Hangul 1D/2D array."""
    found: list[tuple[int, bytes, list[Any]]] = []
    pos = 0
    raw = bytes(ro_slice)
    for part in raw.split(b"\x00"):
        part_len = len(part)
        if b"[" in part and _HANGUL_BYTES_RE.search(part):
            try:
                part.decode("utf-8")
            except UnicodeDecodeError:
                pos += part_len + 1
                continue

            # Handle top-level array chunk like 0x56F543 ("[\"...\"]") as well as key:[...]
            if part.startswith(b'["'):
                arr_end = _scan_json_array_end(part, 0)
                if arr_end is not None:
                    arr_bytes = part[0:arr_end]
                    if _HANGUL_BYTES_RE.search(arr_bytes):
                        try:
                            vals = json.loads(arr_bytes.decode("utf-8"))
                        except (ValueError, UnicodeDecodeError):
                            vals = None
                        if _is_translatable_str_array(vals):
                            found.append((ro_file_offset + pos, arr_bytes, vals))

            cursor = 0
            for match in _ARRAY_START_RE.finditer(part):
                if match.start() < cursor:
                    continue
                arr_start = match.end() - 1
                arr_end = _scan_json_array_end(part, arr_start)
                if arr_end is None:
                    continue
                arr_bytes = part[arr_start:arr_end]
                if not _HANGUL_BYTES_RE.search(arr_bytes):
                    continue
                try:
                    vals = json.loads(arr_bytes.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if _is_translatable_str_array(vals):
                    found.append((ro_file_offset + pos + arr_start, arr_bytes, vals))
                    cursor = arr_end
        pos += part_len + 1
    return found


def apply_english_server_catalog(
    buf: bytearray,
    offset_fn: Callable[[int], int],
) -> int:
    """Translate embedded server JSON catalogs and ``.rodata`` C++ UI strings in-place.

    Idempotent and fail-closed on unexpected bytes or missing mappings.
    """
    pending: list[tuple[int, bytes]] = []

    # 1. NUL-split JSON boundary fragments and 9-language event header arrays
    for vaddr, length, stock_sha, rep_bytes in JSON_BOUNDARY_PATCHES:
        off = offset_fn(vaddr)
        cur = bytes(buf[off : off + length])
        if cur == rep_bytes:
            continue
        cur_sha = hashlib.sha256(cur).hexdigest()
        if vaddr == _HERO_1104_LEFT_VADDR and length == _HERO_1104_LEFT_LEN:
            if cur == _HERO_1104_LEFT_PATCHED_REP:
                continue
            if cur_sha == _HERO_1104_LEFT_PATCHED_SHA256:
                pending.append((off, _HERO_1104_LEFT_PATCHED_REP))
                continue
        if cur_sha != stock_sha:
            raise ValueError(
                f"Unexpected JSON boundary bytes at 0x{vaddr:x} (sha256={cur_sha})"
            )
        if len(rep_bytes) != length:
            raise ValueError(f"JSON boundary replacement length mismatch at 0x{vaddr:x}")
        pending.append((off, rep_bytes))

    # Apply boundary patches on a trial buffer first so JSON scan skips already-fixed boundaries
    trial = bytearray(buf)
    for off, rep in pending:
        trial[off : off + len(rep)] = rep

    # 2. All intact 1D/2D 5-slot JSON arrays inside .rodata
    ro_start = offset_fn(RODATA_VADDR_START)
    ro_end = ro_start + (RODATA_VADDR_END - RODATA_VADDR_START)
    json_edits: list[tuple[int, bytes]] = []
    for file_off, arr_bytes, vals in _iter_rodata_json_arrays(
        memoryview(trial)[ro_start:ro_end], ro_start
    ):
        try:
            rep = _encode_array_in_place(vals, len(arr_bytes))
        except KeyError as exc:
            raise ValueError(
                f"Untranslated Korean string in JSON array at 0x{file_off:x}: {exc}"
            ) from exc
        if len(rep) != len(arr_bytes):
            raise ValueError(f"JSON array length mismatch at 0x{file_off:x}")
        if rep != arr_bytes:
            json_edits.append((file_off, rep))

    # 3. Small NUL-terminated C++ strings in .rodata
    rodata_edits: list[tuple[int, bytes]] = []
    for vaddr, kr_str, en_str in RODATA_STR_PATCHES:
        orig_b = kr_str.encode("utf-8") + b"\x00"
        en_raw = en_str.encode("utf-8")
        if len(en_raw) > len(orig_b) - 1:
            raise ValueError(
                f"English replacement exceeds byte budget at 0x{vaddr:x}: "
                f"{len(en_raw)} > {len(orig_b) - 1}"
            )
        rep = en_raw + b"\x00" * (len(orig_b) - len(en_raw))
        off = offset_fn(vaddr)
        cur = bytes(trial[off : off + len(orig_b)])
        if cur == rep:
            continue
        if cur != orig_b:
            raise ValueError(
                f"Unexpected .rodata string at 0x{vaddr:x}: {cur!r} (expected {orig_b!r})"
            )
        rodata_edits.append((off, rep))

    # 4. Two-instruction ARM64 SSO update for 0x466B4D ("5+ attempts")
    text_edits: list[tuple[int, bytes]] = []
    for vaddr, orig_insn, patched_insn in TEXT_SSO_PATCHES:
        off = offset_fn(vaddr)
        cur = bytes(trial[off : off + len(orig_insn)])
        if cur == patched_insn:
            continue
        if cur != orig_insn:
            raise ValueError(
                f"Unexpected instruction at SSO patch 0x{vaddr:x}: {cur.hex()}"
            )
        text_edits.append((off, patched_insn))

    all_edits = pending + json_edits + rodata_edits + text_edits
    for off, rep in all_edits:
        buf[off : off + len(rep)] = rep
    return len(all_edits)


def inspect_english_server_catalog(
    data: bytes | bytearray,
    offset_fn: Callable[[int], int] | None = None,
) -> tuple[bool, str]:
    """Verify that server JSON catalogs, boundary fragments, and C++ strings are English."""
    if offset_fn is None:
        segments = read_load_segments(data)
        offset_fn = partial(translate_vaddr, segments)

    boundary_ok = 0
    for vaddr, length, _stock_sha, rep_bytes in JSON_BOUNDARY_PATCHES:
        off = offset_fn(vaddr)
        cur = bytes(data[off : off + length])
        if cur == rep_bytes or (
            vaddr == _HERO_1104_LEFT_VADDR and cur == _HERO_1104_LEFT_PATCHED_REP
        ):
            boundary_ok += 1
    if boundary_ok != len(JSON_BOUNDARY_PATCHES):
        return (
            False,
            f"JSON boundaries {boundary_ok}/{len(JSON_BOUNDARY_PATCHES)} translated",
        )

    ro_start = offset_fn(RODATA_VADDR_START)
    ro_end = ro_start + (RODATA_VADDR_END - RODATA_VADDR_START)
    remaining_arrays = _iter_rodata_json_arrays(memoryview(data)[ro_start:ro_end], ro_start)
    if remaining_arrays:
        return (
            False,
            f"{len(remaining_arrays)} Korean JSON array(s) remain in server catalog",
        )

    ro_ok = 0
    for vaddr, kr_str, en_str in RODATA_STR_PATCHES:
        orig_len = len(kr_str.encode("utf-8")) + 1
        en_raw = en_str.encode("utf-8")
        rep = en_raw + b"\x00" * (orig_len - len(en_raw))
        off = offset_fn(vaddr)
        if bytes(data[off : off + orig_len]) == rep:
            ro_ok += 1
    if ro_ok != len(RODATA_STR_PATCHES):
        return (
            False,
            f".rodata UI strings {ro_ok}/{len(RODATA_STR_PATCHES)} translated",
        )

    sso_ok = 0
    for vaddr, _orig_insn, patched_insn in TEXT_SSO_PATCHES:
        off = offset_fn(vaddr)
        if bytes(data[off : off + len(patched_insn)]) == patched_insn:
            sso_ok += 1
    if sso_ok != len(TEXT_SSO_PATCHES):
        return False, f"SSO text patches {sso_ok}/{len(TEXT_SSO_PATCHES)} active"

    return (
        True,
        f"{len(JSON_BOUNDARY_PATCHES)} boundary fragments, 0 Korean JSON arrays, "
        f"{ro_ok} .rodata UI strings translated",
    )


def patch_stringtable_english_rows(rows: list[dict[str, Any]]) -> int:
    """Replace the 10 leftover Korean rows in ``stringtableenglish.unity3d``."""
    seen: set[int] = set()
    to_update: list[tuple[dict[str, Any], str]] = []
    for row in rows:
        rid = row.get("_id")
        if rid not in STRINGTABLE_EN_FIXES:
            continue
        if rid in seen:
            raise ValueError(f"Duplicate stringtableenglish row _id={rid}")
        seen.add(rid)
        stock_kr, en_text = STRINGTABLE_EN_FIXES[rid]
        cur = row.get("_text")
        if cur == en_text:
            continue
        if cur != stock_kr:
            raise ValueError(f"Unexpected stringtableenglish row {rid}: {cur!r}")
        to_update.append((row, en_text))
    if seen != set(STRINGTABLE_EN_FIXES):
        missing = sorted(set(STRINGTABLE_EN_FIXES) - seen)
        raise ValueError(f"stringtableenglish missing row(s): {missing}")
    for row, en_text in to_update:
        row["_text"] = en_text
    return len(to_update)


def inspect_stringtable_english_rows(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Check whether all 10 leftover Korean rows in ``stringtableenglish.unity3d`` are English."""
    found: dict[int, Any] = {}
    for row in rows:
        rid = row.get("_id")
        if rid in STRINGTABLE_EN_FIXES:
            found[rid] = row.get("_text")
    if len(found) != len(STRINGTABLE_EN_FIXES):
        return False, f"stringtableenglish found {len(found)}/{len(STRINGTABLE_EN_FIXES)} target rows"
    patched = sum(1 for rid, (_, en) in STRINGTABLE_EN_FIXES.items() if found[rid] == en)
    stock = sum(1 for rid, (kr, _) in STRINGTABLE_EN_FIXES.items() if found[rid] == kr)
    total = len(STRINGTABLE_EN_FIXES)
    if patched == total:
        return True, f"All {total} leftover Korean rows translated"
    if stock == total:
        return False, f"Original leftover Korean rows ({total})"
    return False, f"Partially translated ({patched}/{total} rows)"


def patch_shipyarddata_english_rows(rows: list[dict[str, Any]]) -> int:
    """Replace the 4 leftover Korean repair labels in ``shipyarddataenglish.unity3d``."""
    seen: set[int] = set()
    to_update: list[tuple[dict[str, Any], str]] = []
    for row in rows:
        stype = row.get("_shipyardType")
        if stype not in SHIPYARD_EN_FIXES:
            continue
        if stype in seen:
            raise ValueError(f"Duplicate shipyarddataenglish row _shipyardType={stype}")
        seen.add(stype)
        stock_kr, en_text = SHIPYARD_EN_FIXES[stype]
        cur = row.get("_name")
        if cur == en_text:
            continue
        if cur != stock_kr:
            raise ValueError(f"Unexpected shipyarddataenglish row {stype}: {cur!r}")
        to_update.append((row, en_text))
    if seen != set(SHIPYARD_EN_FIXES):
        missing = sorted(set(SHIPYARD_EN_FIXES) - seen)
        raise ValueError(f"shipyarddataenglish missing row(s): {missing}")
    for row, en_text in to_update:
        row["_name"] = en_text
    return len(to_update)


def inspect_shipyarddata_english_rows(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Check whether all 4 leftover Korean rows in ``shipyarddataenglish.unity3d`` are English."""
    found: dict[int, Any] = {}
    for row in rows:
        stype = row.get("_shipyardType")
        if stype in SHIPYARD_EN_FIXES:
            found[stype] = row.get("_name")
    if len(found) != len(SHIPYARD_EN_FIXES):
        return False, f"shipyarddataenglish found {len(found)}/{len(SHIPYARD_EN_FIXES)} target rows"
    patched = sum(1 for st, (_, en) in SHIPYARD_EN_FIXES.items() if found[st] == en)
    total = len(SHIPYARD_EN_FIXES)
    if patched == total:
        return True, f"All {total} shipyard rows translated"
    return False, f"shipyarddataenglish {patched}/{total} rows translated"


def inspect_english_localization_assets(inner_zip: zipfile.ZipFile) -> tuple[bool, str]:
    """Verify ``stringtableenglish.unity3d`` and ``shipyarddataenglish.unity3d``."""
    import UnityPy

    from core.apk_tooling import _decrypt_datatable

    checks: list[tuple[str, Callable[[list[dict[str, Any]]], tuple[bool, str]]]] = [
        (STRINGTABLE_EN_ASSET_PATH, inspect_stringtable_english_rows),
        (SHIPYARD_EN_ASSET_PATH, inspect_shipyarddata_english_rows),
    ]
    details: list[str] = []
    for asset_path, fn in checks:
        try:
            raw = inner_zip.read(asset_path)
        except KeyError:
            return False, f"{asset_path} missing from resource archive"
        clear, _k, _v = _decrypt_datatable(raw)
        env = UnityPy.load(clear)
        rows: list[dict[str, Any]] = []
        for obj in env.objects:
            if obj.type.name == "MonoBehaviour":
                tree = obj.read_typetree()
                data = tree.get("_data")
                if isinstance(data, list):
                    rows = data
                    break
        ok, msg = fn(rows)
        if not ok:
            return False, msg
        details.append(msg)
    return True, "; ".join(details)
