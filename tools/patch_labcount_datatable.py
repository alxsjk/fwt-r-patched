#!/usr/bin/env python3
"""Patch the external LaboratoryCount datatable to a 3-hour lab charge.

In the 0.682 client, ``LaboratoryCount`` belongs to the Mana Stone Compactor
(``tool_type 2``), the 5-charge machine whose recharge timer the historical
``flask_3h`` flag targets.  The daily Energy Flask (``tool_type 3``) uses
``laboratorytimezone.unity3d`` and already has 3-hour windows, so it is not
changed by this tool.

The offline client loads ``laboratorycount.unity3d`` from its external
``files/Resources/datatable`` directory.  This tool decrypts the datatable,
sets every ``_cooltime`` row to 10800 seconds (3 hours), re-encrypts it with the
datatable key/IV from ``.env`` and optionally pushes it to a connected device
through adb.  It never modifies the APK or the client library.

Run with the optional data dependencies (UnityPy/cryptography are not project
runtime dependencies):

    uv run --with UnityPy --with attrs --with Pillow --with cryptography \
        python tools/patch_labcount_datatable.py \
        --input laboratorycount.unity3d \
        --output laboratorycount.3h.unity3d

Add ``--push --device 192.0.2.10:5555`` to replace the external datatable
on the device (the original is pulled to ``<output>.orig`` first).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import UnityPy
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:  # pragma: no cover - dependency hint
    raise SystemExit(
        "Missing optional dependency. Run with: uv run --with UnityPy "
        "--with attrs --with Pillow --with cryptography python "
        "tools/patch_labcount_datatable.py ..."
    ) from exc

DEFAULT_REMOTE = "/sdcard/Android/data/com.nexon.fwar/files/Resources/datatable/laboratorycount.unity3d"
DEFAULT_COOLTIME = 10800


def _load_env() -> dict[str, str]:
    path = Path(__file__).resolve().parents[1] / ".env"
    if not path.is_file():
        return {}
    try:
        from dotenv import dotenv_values

        return {k: v for k, v in dotenv_values(path).items() if v is not None}
    except ImportError:
        pass
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("\"'")
    return env


def _decrypt(data: bytes, key: str, iv: str) -> bytes:
    decryptor = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode())).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _encrypt(data: bytes, key: str, iv: str) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode())).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _key_candidates(env: dict[str, str], clear_input: bool) -> list[tuple[str, str, str]]:
    base_key = env.get("FWT_DATATABLE_CRYPT_KEY", "")
    base_iv = env.get("FWT_DATATABLE_CRYPT_IV", "")
    rev_key = env.get("FWT_DATATABLE_CRYPT_KEY_REVERSED", "")
    rev_iv = env.get("FWT_DATATABLE_CRYPT_IV_REVERSED", "")
    candidates = [
        ("rev/rev", rev_key, rev_iv),
        ("base/base", base_key, base_iv),
        ("rev/base", rev_key, base_iv),
        ("base/rev", base_key, rev_iv),
    ]
    valid = [item for item in candidates if len(item[1]) == 32 and len(item[2]) == 16]
    if clear_input:
        # The reference decryption helper uses the reversed pair for encryption.
        return [item for item in candidates[:1] if len(item[1]) == 32 and len(item[2]) == 16] or valid[:1]
    return valid


def _choose_clear(raw: bytes, env: dict[str, str]) -> tuple[bytes, str, str, bool]:
    if raw.startswith(b"UnityFS"):
        candidates = _key_candidates(env, clear_input=True)
        if not candidates:
            raise SystemExit("input is already clear but .env has no datatable key")
        label, key, iv = candidates[0]
        return raw, key, iv, False
    for _label, key, iv in _key_candidates(env, clear_input=False):
        try:
            clear = _decrypt(raw, key, iv)
        except Exception:
            continue
        if clear.startswith(b"UnityFS"):
            return clear, key, iv, True
    raise SystemExit("could not decrypt input with .env datatable keys")


def _patch_clear(clear: bytes, cooltime: int) -> bytes:
    with tempfile.TemporaryDirectory(
        prefix="fwt-labcount-", ignore_cleanup_errors=True
    ) as tmp:
        source = Path(tmp) / "laboratorycount.unity3d"
        source.write_bytes(clear)
        env = UnityPy.load(str(source))
        changed = 0
        for obj in env.objects:
            if obj.type.name != "MonoBehaviour":
                continue
            tree = obj.read_typetree()
            rows = tree.get("_data")
            if not isinstance(rows, list):
                continue
            for row in rows:
                if "_cooltime" in row:
                    row["_cooltime"] = cooltime
                    changed += 1
            obj.save_typetree(tree)
        if changed == 0:
            raise SystemExit("no _cooltime rows found")
        return bytes(getattr(env.file, "save")())  # noqa: B009


def _find_adb(explicit: str | None) -> str:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    located_adb: str | None = None
    try:
        from core.apk_tooling import locate_tools

        located_adb = locate_tools().adb
    except Exception:
        pass

    candidates = [
        explicit,
        os.environ.get("ADB"),
        located_adb,
        shutil.which("adb"),
        r"C:\Program Files\Netease\MuMuPlayer\nx_main\adb.exe",
        "/usr/bin/adb",
        str(Path.home() / "Android" / "Sdk" / "platform-tools" / "adb"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("adb not found; pass --adb")


def _push(adb: str, device: str | None, local: Path, remote: str, backup: Path) -> None:
    prefix = [adb]
    if device:
        prefix += ["-s", device]
    backup.parent.mkdir(parents=True, exist_ok=True)
    if backup.exists():
        raise SystemExit(
            f"refusing to overwrite existing backup {backup}; move it or pass a "
            "timestamped --output"
        )
    with backup.open("wb") as fh:
        result = subprocess.run(prefix + ["exec-out", "cat", remote], stdout=fh, timeout=30)
    if result.returncode != 0 or backup.stat().st_size == 0:
        backup.unlink(missing_ok=True)
        raise SystemExit(
            f"could not back up {remote}; refusing to push and destroy the only copy"
        )
    try:
        subprocess.run(prefix + ["push", str(local), remote], check=True, timeout=120)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"adb push failed: {exc}") from exc
    print(f"pushed {local} -> {remote}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch LaboratoryCount to a 3-hour Energy Flask")
    parser.add_argument("--input", type=Path, required=True, help="Encrypted or decrypted laboratorycount.unity3d")
    parser.add_argument("--output", type=Path, default=Path("laboratorycount.3h.unity3d"))
    parser.add_argument("--cooltime", type=int, default=DEFAULT_COOLTIME)
    parser.add_argument("--push", action="store_true", help="Push the result to the device")
    parser.add_argument("--device", default=os.environ.get("FWT_DEVICE"))
    parser.add_argument("--adb", default=None)
    parser.add_argument("--remote", default=DEFAULT_REMOTE)
    args = parser.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input not found: {args.input}")
    if args.cooltime < 60:
        raise SystemExit("--cooltime must be at least 60 seconds")
    env = _load_env()
    raw = args.input.read_bytes()
    clear, key, iv, was_encrypted = _choose_clear(raw, env)
    patched = _patch_clear(clear, args.cooltime)
    output = _encrypt(patched, key, iv)
    if _decrypt(output, key, iv) != patched:
        raise SystemExit("re-encryption round-trip failed; refusing to write output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    partial = args.output.with_name(args.output.name + ".tmp")
    partial.write_bytes(output)
    partial.replace(args.output)
    print(
        f"patched rows -> _cooltime={args.cooltime}; "
        f"input={len(raw)} bytes output={len(output)} bytes"
    )

    # Verify decrypt/readback before pushing.
    check = _decrypt(output, key, iv)
    with tempfile.TemporaryDirectory(
        prefix="fwt-labcount-check-", ignore_cleanup_errors=True
    ) as tmp:
        check_path = Path(tmp) / "check.unity3d"
        check_path.write_bytes(check)
        check_env = UnityPy.load(str(check_path))
        values = []
        for obj in check_env.objects:
            if obj.type.name == "MonoBehaviour":
                tree = obj.read_typetree()
                for row in tree.get("_data", []):
                    if "_cooltime" in row:
                        values.append(row["_cooltime"])
    if not values or set(values) != {args.cooltime}:
        raise SystemExit(f"verification failed: {sorted(set(values))}")
    print(f"verified {len(values)} rows at _cooltime={args.cooltime}")

    if args.push:
        adb = _find_adb(args.adb)
        backup = args.output.with_suffix(args.output.suffix + ".orig")
        if backup.exists():
            stamp = time.strftime("%Y%m%d_%H%M%S")
            backup = args.output.with_suffix(args.output.suffix + f".orig-{stamp}")
        _push(adb, args.device, args.output, args.remote, backup)
        print(f"original backup: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
