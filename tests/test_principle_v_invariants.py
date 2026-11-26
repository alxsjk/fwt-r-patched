"""Synthetic unit tests for Constitution Principle V and release-gate invariants."""
from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from core.core_patches import DevOptions, PatchOptions, validate_patch_options
from core.patch_inspector import (
    BASELINE_BUGFIX_KEYS,
    FeatureReport,
    InspectionReport,
    check_apk_alignment,
    verify_dex_checksums,
    verify_release_report,
)


def _minimal_elf64(*, align: int = 16384, endian: int = 1) -> bytes:
    buf = bytearray(64 + 56)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2  # ELF64
    buf[5] = endian  # 1 = LE
    struct.pack_into("<Q", buf, 32, 64)  # e_phoff
    struct.pack_into("<H", buf, 54, 56)  # e_phentsize
    struct.pack_into("<H", buf, 56, 1)   # e_phnum
    struct.pack_into("<I", buf, 64, 1)   # PT_LOAD
    struct.pack_into("<Q", buf, 64 + 48, align)
    return bytes(buf)


def _write_16k_aligned_zip(path: Path, entry_name: str, payload: bytes, *, stored: bool = True) -> None:
    if stored:
        # Place local header so data_offset lands on a 16384-byte boundary.
        with zipfile.ZipFile(path, "w") as zf:
            info = zipfile.ZipInfo(entry_name)
            info.compress_type = zipfile.ZIP_STORED
            pad = (16384 - ((30 + len(entry_name.encode())) % 16384)) % 16384
            info.extra = b"\x00" * pad
            zf.writestr(info, payload)
    else:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(entry_name, payload)


def test_check_apk_alignment_valid_and_failure_paths(tmp_path: Path) -> None:
    valid_apk = tmp_path / "valid.apk"
    _write_16k_aligned_zip(valid_apk, "lib/arm64-v8a/libtest.so", _minimal_elf64(align=16384))
    ok, msg = check_apk_alignment(valid_apk)
    assert ok, msg

    compressed_apk = tmp_path / "compressed.apk"
    _write_16k_aligned_zip(compressed_apk, "lib/arm64-v8a/libtest.so", _minimal_elf64(align=16384), stored=False)
    ok, _ = check_apk_alignment(compressed_apk)
    assert not ok

    low_align_apk = tmp_path / "low_align.apk"
    _write_16k_aligned_zip(low_align_apk, "lib/arm64-v8a/libtest.so", _minimal_elf64(align=4096))
    ok, _ = check_apk_alignment(low_align_apk)
    assert not ok

    bad_elf_apk = tmp_path / "bad_endian.apk"
    _write_16k_aligned_zip(bad_elf_apk, "lib/arm64-v8a/libtest.so", _minimal_elf64(align=16384, endian=2))
    ok, _ = check_apk_alignment(bad_elf_apk)
    assert not ok


def test_verify_dex_checksums_valid_and_corrupt() -> None:
    dex = bytearray(0x70)
    dex[:8] = b"dex\n035\x00"
    sig = hashlib.sha1(dex[32:]).digest()
    dex[12:32] = sig
    adler = zlib.adler32(dex[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", dex, 8, adler)

    ok, _ = verify_dex_checksums(dex)
    assert ok

    bad_sig = bytearray(dex)
    bad_sig[32] ^= 0xFF
    ok, msg = verify_dex_checksums(bad_sig)
    assert not ok
    assert "SHA-1" in msg

    bad_adler = bytearray(dex)
    bad_adler[8] ^= 0xFF
    ok, msg = verify_dex_checksums(bad_adler)
    assert not ok
    assert "Adler32" in msg


def test_verify_release_report_rejects_baseline_only_apk() -> None:
    baseline_features = {
        key: FeatureReport(name=key, active=True, status="Active", details="always-on")
        for key in BASELINE_BUGFIX_KEYS
    }
    report = InspectionReport(
        is_valid_apk=True,
        has_so=True,
        has_dex=True,
        alignment_16k=True,
        is_signed=True,
        dex_checksum_valid=True,
        build_identity="release",
        build_options=PatchOptions(),
        features=baseline_features,
    )
    problems = verify_release_report(report)
    assert any("unpatched" in p.lower() for p in problems), problems


def test_validate_patch_options_rejects_invalid_ranges() -> None:
    with pytest.raises(ValueError, match="rune_quality_factor"):
        validate_patch_options(PatchOptions(rune_quality_factor=-1))
    with pytest.raises(ValueError, match="IPv4"):
        validate_patch_options(PatchOptions(lan_redirect=True, server_ip="not-an-ip"))
    with pytest.raises(ValueError, match="between 0 and 65535"):
        validate_patch_options(PatchOptions(dev=DevOptions(enabled=True, log_body_limit=70000)))
    with pytest.raises(ValueError, match="dev master switch"):
        validate_patch_options(PatchOptions(dev=DevOptions(enabled=False, keep_version=True)))


def test_versioned_output_path_boundary_markers() -> None:
    from core.version import APP_VERSION, versioned_output_path

    # "-developer" must not be mistaken for "-dev"
    out = versioned_output_path(Path("app-developer.apk"), dev=True)
    assert out.name == f"app-developer-{APP_VERSION}-dev.apk"
    # Switching dev -> release must strip "-dev" instead of producing "-dev-...-release"
    rel = versioned_output_path(Path(f"app-{APP_VERSION}-dev.apk"), dev=False)
    assert rel.name == f"app-{APP_VERSION}-release.apk"


def test_dex_smali_const_wide_and_apktool_sha256_fail_closed(tmp_path: Path) -> None:
    from core.dex_smali import _replace_const_wide_literal, _run_apktool

    src = "    const-wide/32 v0, 0x33e23c58\n"
    upgraded = _replace_const_wide_literal(src, "0x33e23c58", 0x1_0000_0000)
    assert "const-wide v0, 0x100000000" in upgraded

    fake_jar = tmp_path / "evil_apktool.jar"
    fake_jar.write_bytes(b"not-a-valid-apktool-jar")
    with pytest.raises(RuntimeError, match="unexpected SHA-256"):
        _run_apktool(fake_jar, ["--version"], "fake apktool")


def test_inspect_apk_rejects_duplicate_core_entries(tmp_path: Path) -> None:
    from core.patch_inspector import inspect_apk

    dup_apk = tmp_path / "dup.apk"
    with zipfile.ZipFile(dup_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"first")
        zf.writestr("AndroidManifest.xml", b"second")
    report = inspect_apk(dup_apk)
    assert not report.is_valid_apk
    assert "Duplicate core APK" in report.error_message


def test_register_release_handles_dict_format_and_escapes_markdown() -> None:
    from tools.register_release import render

    md = render(
        [
            {
                "date": "2026-11-25 22:00",
                "version": "2.5.60|test",
                "kind": "release",
                "features": ["all|extra"],
                "sha256": "a" * 64,
                "bytes": 123,
                "file": "test.apk",
                "notes": "note",
            }
        ]
    )
    assert "2.5.60\\|test" in md
    assert "all\\|extra" in md


def test_axml_append_string_clears_sorted_flag_and_handles_non_bmp() -> None:
    from core.axml import RES_STRING_POOL_TYPE, RES_XML_TYPE, AxmlDocument

    # Minimal valid AXML with 1 UTF-16 string and SORTED_FLAG (0x0001) set.
    s0 = struct.pack("<H", 1) + "a".encode("utf-16-le") + b"\x00\x00"
    while len(s0) % 4:
        s0 += b"\x00"
    pool_header_size = 28
    strings_start = pool_header_size + 4
    pool_size = strings_start + len(s0)
    pool = (
        struct.pack("<HHI", RES_STRING_POOL_TYPE, pool_header_size, pool_size)
        + struct.pack("<IIIII", 1, 0, 0x0001, strings_start, 0)
        + struct.pack("<I", 0)
        + s0
    )
    doc_bytes = struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(pool)) + pool
    doc = AxmlDocument(doc_bytes)
    updated, idx = doc.append_string("v1\U0001F680")
    assert idx == 1
    new_flags = struct.unpack_from("<I", updated, 8 + 16)[0]
    assert (new_flags & 0x0001) == 0
    assert AxmlDocument(updated).string_at(1) == "v1\U0001F680"
