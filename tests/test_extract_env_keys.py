"""Tests for the cipher key extractor (tools/extract_env_keys.py)."""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from tools.extract_env_keys import (
    ASSEMBLY_FLAG_BYTE,
    build_env_values,
    parse_secret_strings,
    read_assembly_blob,
    update_env_file,
)

# Synthetic stand-ins with the reference layout sizes; no real secret appears here.
SYNTHETIC_STRINGS = [
    "a" * 32,
    "b" * 16,
    "1234567",
    "7654321",
    "c" * 32,
    "d" * 16,
    "x2",
] + [f"filler-{index:02d}" for index in range(8)]


def _encode_table(strings: list[str]) -> bytes:
    """Encodes strings the way the Assembly blob does (length prefix + UTF-16LE)."""
    chunks = [b"\x00"]
    for text in strings:
        encoded = text.encode("utf-16-le")
        size = len(encoded)
        if size < 0x80:
            chunks.append(bytes([size]))
        elif size < 0x4000:
            chunks.append(bytes([0x80 | (size >> 8), size & 0xFF]))
        else:
            chunks.append(
                bytes(
                    [
                        0xC0 | (size >> 24),
                        (size >> 16) & 0xFF,
                        (size >> 8) & 0xFF,
                        size & 0xFF,
                    ]
                )
            )
        chunks.append(encoded)
    return b"".join(chunks)


def _build_blob(strings: list[str], key: bytes, iv: bytes) -> bytes:
    """Builds a synthetic Assembly blob with a caller-chosen DES key."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    payload = compressor.compress(_encode_table(strings)) + compressor.flush()
    pad = 8 - len(payload) % 8
    padded = payload + bytes([pad]) * pad
    encryptor = Cipher(TripleDES(key * 3), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return bytes([ASSEMBLY_FLAG_BYTE, 0x00, 0x00, 0xF5]) + iv + key + ciphertext


def test_parse_secret_strings_round_trips_a_synthetic_blob() -> None:
    blob = _build_blob(SYNTHETIC_STRINGS, key=b"TESTKEY!", iv=b"TESTIV!!")
    assert parse_secret_strings(blob) == SYNTHETIC_STRINGS


def test_parse_secret_strings_rejects_short_and_wrong_flag_blobs() -> None:
    with pytest.raises(ValueError, match="too short"):
        parse_secret_strings(b"\x0a" + b"\x00" * 40)
    with pytest.raises(ValueError, match="Unexpected Assembly blob flags"):
        parse_secret_strings(b"\x0b" + b"\x00" * 100)


def test_parse_secret_strings_rejects_corrupt_deflate_as_value_error() -> None:
    key, iv = b"TESTKEY!", b"TESTIV!!"
    bad_payload = b"\xff" * 64
    pad = 8 - len(bad_payload) % 8
    padded = bad_payload + bytes([pad]) * pad
    encryptor = Cipher(TripleDES(key * 3), modes.CBC(iv)).encryptor()
    blob = bytes([ASSEMBLY_FLAG_BYTE, 0x00, 0x00, 0x01]) + iv + key + encryptor.update(padded) + encryptor.finalize()
    with pytest.raises(ValueError, match="corrupt compressed Assembly blob"):
        parse_secret_strings(blob)


def test_build_env_values_maps_the_project_convention() -> None:
    values = build_env_values(SYNTHETIC_STRINGS)
    assert values["FWT_CACHE_CRYPT_KEY"] == "a" * 32
    assert values["FWT_CACHE_CRYPT_IV"] == "b" * 16
    assert values["FWT_DATATABLE_CRYPT_KEY"] == "a" * 32
    assert values["FWT_DATATABLE_CRYPT_IV"] == "b" * 16
    assert values["FWT_DATATABLE_CRYPT_KEY_REVERSED"] == "a" * 32
    assert values["FWT_DATATABLE_CRYPT_IV_REVERSED"] == "b" * 16
    assert values["FWT_NETWORK_CRYPT_KEY"] == "c" * 32
    assert values["FWT_NETWORK_CRYPT_IV"] == "d" * 16
    assert values["FWT_ID_KEY_START"] == "1234567"
    assert values["FWT_ID_KEY_END"] == "7654321"
    assert len(values) == 10


def test_build_env_values_rejects_unexpected_layout() -> None:
    with pytest.raises(ValueError, match="unexpected secret string sizes"):
        build_env_values(["short"] * 6)


def test_update_env_file_replaces_placeholders_and_appends(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "FWT_DEBUG=1\n"
        "# local note\n"
        "FWT_CACHE_CRYPT_KEY=CHANGE_ME_32_BYTES\n"
        "FWT_DEVICE=192.0.2.10:5555\n",
        encoding="utf-8",
    )
    written = update_env_file(
        env, {"FWT_CACHE_CRYPT_KEY": "a" * 32, "FWT_ID_KEY_START": "1234567"}
    )
    text = env.read_text(encoding="utf-8")
    assert f"FWT_CACHE_CRYPT_KEY={'a' * 32}" in text
    assert "FWT_ID_KEY_START=1234567" in text
    assert "FWT_DEBUG=1" in text
    assert "FWT_DEVICE=192.0.2.10:5555" in text
    assert "# local note" in text
    assert "CHANGE_ME" not in text
    assert written == ["FWT_CACHE_CRYPT_KEY", "FWT_ID_KEY_START"]


def test_update_env_file_creates_from_example_template(tmp_path: Path) -> None:
    example = tmp_path / ".env.example"
    example.write_text("FWT_DEBUG=1\nFWT_ID_KEY_END=CHANGE_ME\n", encoding="utf-8")
    env = tmp_path / ".env"
    update_env_file(env, {"FWT_ID_KEY_END": "7654321"}, example_path=example)
    text = env.read_text(encoding="utf-8")
    assert "FWT_DEBUG=1" in text
    assert "FWT_ID_KEY_END=7654321" in text


def test_update_env_file_dry_run_leaves_the_file_untouched(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("FWT_DEBUG=1\n", encoding="utf-8")
    update_env_file(env, {"FWT_ID_KEY_START": "1234567"}, dry_run=True)
    assert env.read_text(encoding="utf-8") == "FWT_DEBUG=1\n"


def test_reference_apk_extracts_the_expected_secret_layout(reference_apk: Path) -> None:
    blob = read_assembly_blob(reference_apk)
    strings = parse_secret_strings(blob)
    assert len(strings) == 15
    assert [len(text) for text in strings[:6]] == [32, 16, 7, 7, 32, 16]
    assert all(text.isascii() and text.isprintable() for text in strings[:6])
    values = build_env_values(strings)
    assert len(values) == 10
    assert all("CHANGE_ME" not in value for value in values.values())
    assert values["FWT_DATATABLE_CRYPT_KEY_REVERSED"] == values["FWT_CACHE_CRYPT_KEY"][::-1]
    assert values["FWT_DATATABLE_CRYPT_IV_REVERSED"] == values["FWT_CACHE_CRYPT_IV"][::-1]
