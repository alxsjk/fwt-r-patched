#!/usr/bin/env python3
"""Extract the client cipher keys from your own copy of the offline APK.

The game client keeps its secret strings in a Unity ``TextAsset`` named
``Assembly`` (resource path ``DefineResources/Assembly``) stored inside
``assets/bin/Data/datapack.unity3d``. The 484-byte blob embeds its own
single-DES key and IV, so this tool ships no secret values of its own:
every value it writes is read from the APK file you supply.

Writes these variables to ``.env`` (created from ``.env.example`` when absent):

- ``FWT_CACHE_CRYPT_KEY`` / ``FWT_CACHE_CRYPT_IV``
- ``FWT_DATATABLE_CRYPT_KEY`` / ``FWT_DATATABLE_CRYPT_IV``
  (plus the ``_REVERSED`` forms used by the project's ``.env`` convention)
- ``FWT_NETWORK_CRYPT_KEY`` / ``FWT_NETWORK_CRYPT_IV``
- ``FWT_ID_KEY_START`` / ``FWT_ID_KEY_END``

Usage::

    python tools/extract_env_keys.py [--apk PATH] [--env PATH] [--dry-run]

The APK defaults to ``FWT_SOURCE_APK`` from the environment, then to
``source/fwt_0.682_offline_v1574.apk`` (the same file the patcher expects).
Only key lengths are printed; secret values are never echoed.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import tempfile
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path

import UnityPy
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

DATAPACK_MEMBER = "assets/bin/Data/datapack.unity3d"
ASSEMBLY_NAME = "Assembly"
# Blob header flag byte: bit 1 = DES-encrypted, bit 3 = raw-deflate compressed.
ASSEMBLY_FLAG_BYTE = 0x0A
# Byte sizes of the first six secret strings in the reference layout.
EXPECTED_STRING_SIZES = (32, 16, 7, 7, 32, 16)


def default_apk_path() -> Path:
    """Resolves the base APK from ``FWT_SOURCE_APK`` or the default source path."""
    from_env = os.environ.get("FWT_SOURCE_APK")
    if from_env:
        return Path(from_env)
    return Path("source") / "fwt_0.682_offline_v1574.apk"


def read_assembly_blob(apk_path: Path) -> bytes:
    """Reads the ``Assembly`` TextAsset bytes from the APK's Unity data pack.

    Raises ``FileNotFoundError`` when the APK is missing and ``ValueError``
    when the pack or the TextAsset is absent (for example on a non-reference
    build).
    """
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    with zipfile.ZipFile(apk_path) as archive:
        if DATAPACK_MEMBER not in archive.namelist():
            raise ValueError(
                f"{DATAPACK_MEMBER} is missing from the APK; "
                "is this the offline Korean build (0.682 v1574)?"
            )
        with tempfile.TemporaryDirectory(prefix="fwt-datapack-") as tmp:
            datapack = Path(tmp) / "datapack.unity3d"
            with archive.open(DATAPACK_MEMBER) as src, datapack.open("wb") as dst:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    dst.write(chunk)
            with datapack.open("rb") as fh:
                bundle = UnityPy.load(fh)
                for obj in bundle.objects:
                    if obj.type.name != "TextAsset":
                        continue
                    data = obj.read()
                    if str(getattr(data, "m_Name", "")) != ASSEMBLY_NAME:
                        continue
                    script = data.m_Script
                    if isinstance(script, str):
                        return script.encode("utf-8", "surrogateescape")
                    raw: bytes = bytes(script)
                    return raw
    raise ValueError(f"TextAsset {ASSEMBLY_NAME!r} not found in {DATAPACK_MEMBER}")


def parse_secret_strings(blob: bytes) -> list[str]:
    """Decrypts and inflates the ``Assembly`` blob into its secret strings."""
    if len(blob) < 64:
        raise ValueError(f"Assembly blob is too short: {len(blob)} bytes")
    if blob[0] != ASSEMBLY_FLAG_BYTE:
        raise ValueError(
            f"Unexpected Assembly blob flags 0x{blob[0]:02x} "
            f"(expected 0x{ASSEMBLY_FLAG_BYTE:02x}); unsupported build?"
        )
    iv, key, ciphertext = blob[4:12], blob[12:20], blob[20:]
    decryptor = Cipher(TripleDES(key * 3), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad = padded[-1]
    if not 1 <= pad <= 8 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding in the Assembly blob")
    try:
        table = zlib.decompress(padded[:-pad], -15)
    except zlib.error as exc:
        raise ValueError(f"corrupt compressed Assembly blob: {exc}") from exc

    strings: list[str] = []
    pos = 1
    try:
        while pos < len(table):
            first = table[pos]
            pos += 1
            if first < 0x80:
                size = first
            elif first < 0xC0:
                size = ((first & 0x3F) << 8) | table[pos]
                pos += 1
            else:
                size = ((first & 0x1F) << 24) | (table[pos] << 16)
                size |= (table[pos + 1] << 8) | table[pos + 2]
                pos += 3
            strings.append(table[pos:pos + size].decode("utf-16-le"))
            pos += size
    except IndexError as exc:
        raise ValueError("malformed string table in the Assembly blob") from exc
    return strings


def build_env_values(strings: Sequence[str]) -> dict[str, str]:
    """Maps the parsed secret strings to the project's ``.env`` variables.

    The datatable AES pair is the cache pair with its bytes reversed (the
    client derives it that way), matching the documented ``.env`` convention.
    """
    sizes = tuple(len(item) for item in strings[:6])
    if sizes != EXPECTED_STRING_SIZES:
        raise ValueError(
            f"unexpected secret string sizes {sizes}; "
            f"expected {EXPECTED_STRING_SIZES} - unsupported build?"
        )
    cache_key, cache_iv, id_start, id_end, net_key, net_iv = strings[:6]
    return {
        "FWT_CACHE_CRYPT_KEY": cache_key,
        "FWT_CACHE_CRYPT_IV": cache_iv,
        "FWT_DATATABLE_CRYPT_KEY": cache_key,
        "FWT_DATATABLE_CRYPT_IV": cache_iv,
        "FWT_DATATABLE_CRYPT_KEY_REVERSED": cache_key[::-1],
        "FWT_DATATABLE_CRYPT_IV_REVERSED": cache_iv[::-1],
        "FWT_NETWORK_CRYPT_KEY": net_key,
        "FWT_NETWORK_CRYPT_IV": net_iv,
        "FWT_ID_KEY_START": id_start,
        "FWT_ID_KEY_END": id_end,
    }


def update_env_file(
    env_path: Path,
    values: Mapping[str, str],
    example_path: Path | None = None,
    *,
    dry_run: bool = False,
) -> list[str]:
    """Merges ``values`` into the ``.env`` file, preserving unrelated content.

    When ``env_path`` does not exist, starts from ``example_path`` (defaults
    to ``.env.example`` beside ``env_path``) so the remaining template
    variables survive. Returns the sorted names of the variables written.
    """
    if example_path is None:
        example_path = env_path.parent / ".env.example"
    if env_path.is_file():
        lines = env_path.read_text(encoding="utf-8").splitlines()
    elif example_path.is_file():
        lines = example_path.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    remaining = dict(values)
    seen_managed: set[str] = set()
    merged: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            name = stripped.split("=", 1)[0].strip()
            if name in remaining:
                merged.append(f"{name}={remaining.pop(name)}")
                seen_managed.add(name)
                continue
            if name in seen_managed:
                continue
        merged.append(line)
    merged.extend(f"{name}={value}" for name, value in remaining.items())

    if not dry_run:
        env_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = env_path.with_name(f".{env_path.name}.{os.getpid()}.tmp")
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(merged) + "\n")
            except Exception:
                with contextlib.suppress(OSError):
                    os.close(fd)
                raise
            tmp_path.replace(env_path)
            with contextlib.suppress(OSError):
                os.chmod(env_path, 0o600)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
    return sorted(values)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(
        description="Extract the client cipher keys from your own offline APK."
    )
    parser.add_argument(
        "--apk",
        type=Path,
        default=None,
        help="path to the offline base APK (default: $FWT_SOURCE_APK, then "
        "source/fwt_0.682_offline_v1574.apk)",
    )
    parser.add_argument(
        "--env",
        type=Path,
        default=Path(".env"),
        help="target .env file (default: .env in the current directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be written without touching the .env file",
    )
    args = parser.parse_args(argv)

    apk_path = args.apk if args.apk is not None else default_apk_path()
    print(f"Reading {DATAPACK_MEMBER} from {apk_path} ...")
    try:
        blob = read_assembly_blob(apk_path)
        strings = parse_secret_strings(blob)
        values = build_env_values(strings)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Found {len(strings)} secret strings; prepared {len(values)} cipher variables:")
    for name, value in sorted(values.items()):
        print(f"  {name}: {len(value)} chars")
    written = update_env_file(args.env, values, dry_run=args.dry_run)
    if args.dry_run:
        print(f"Dry run: nothing written ({len(written)} variables ready for {args.env}).")
    else:
        print(f"Wrote {len(written)} cipher variables to {args.env}.")
        print("Features that edit encrypted datatables are now enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
