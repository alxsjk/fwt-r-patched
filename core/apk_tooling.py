#!/usr/bin/env python3
"""FWT Reborn - APK Packaging, Alignment, Signing, and ADB Tooling.

Handles cross-platform discovery of Android build tools (zipalign, apksigner,
keytool, adb), repacking APKs with uncompressed page-aligned shared libraries,
signing with v1+v2 schemes, and interacting with ADB devices over USB or Wi-Fi.
"""

from __future__ import annotations

import contextlib
import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import threading
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Optional

from core.axml import patch_debuggable, patch_version_name
from core.core_patches import (
    DEV_OUTPUT_SUFFIX,
    LIMIT_BREAK_FIXED_GOLD,
    LIMIT_BREAK_FIXED_MATERIAL,
    LIMIT_BREAK_MAX_LEVEL,
    RECYCLE_SIX_STAR_CLIENT_ASSETS,
    RECYCLE_SIX_STAR_GROUP_SLOT,
    RECYCLE_SIX_STAR_GROUPS,
    REFERENCE_DEX_SHA256,
    REFERENCE_SO_SHA256,
    WORLDBOSS_CYCLE_REWARD_GOLD_RES,
    WORLDBOSS_CYCLE_REWARD_ITEM_RES,
    WORLDBOSS_CYCLE_REWARD_TARGET_COUNT,
    WORLDBOSS_CYCLE_REWARD_TARGET_TYPES,
    WORLDBOSS_KRAKEN_SCALE_CODE,
    WORLDBOSS_REWARD_CLIENT_ASSETS,
    PatchOptions,
    PatchResult,
    apply_all_patches,
    limit_break_step10_target,
    recycle_six_star_assignment,
)
from core.dex_smali import ResourceContract, ensure_apktool_jar
from core.guild_raid_fire_support import (
    GUILD_SKILL_DATA_CLIENT_ASSET_PATH,
    inspect_guildskilldata_rows,
    patch_guildskilldata_rows,
)
from core.guild_raid_qol_assets import (
    GUILD_SKILL_INFO_CLIENT_ASSETS,
    MONSTER_DATA_CLIENT_ASSET_PATH,
    inspect_guildskilldata_max_rows,
    inspect_guildskillinfo_max_rows,
    inspect_monsterdata_boss_car_rows,
    patch_guildskilldata_max_rows,
    patch_guildskillinfo_max_rows,
    patch_monsterdata_boss_car_rows,
)
from core.version import BUILD_IDENTITY_ENTRY

PACKAGE_NAME = "com.nexon.fwar"
REMOTE_SAVE_PATH = "/data/data/com.nexon.fwar/files/fwt/fwt_server_state_v1.json"
# Keystore defaults can be overridden without editing the source.
KEYSTORE_ALIAS = os.environ.get("FWT_KEY_ALIAS", "fwtreborn")
KEYSTORE_PASSWORD = os.environ.get("FWT_KEYSTORE_PASS", "android")
# The local server writes a user-readable save copy here. This makes backup
# work on non-rooted devices (the game itself creates the file).
EXTERNAL_SAVE_BACKUP = "/sdcard/Download/fwt/fwt_server_state_v1.json"

# Sacred Lands (set group 4028) shipped with grade 1 in the client table while
# every one of its equipment pieces is grade 4. The wrong grade hides it from
# the grade-4 rotation and ticket lists. It is also missing from the explicit
# ticket group tables, so restore both pieces of data.
SACRED_LANDS_SET_GROUP = 4028
SACRED_LANDS_ORIGINAL_GRADE = 1
SACRED_LANDS_ITEM_GRADE = 4
SACRED_LANDS_TICKET_LISTS = (10001, 10004)

# Unknown Paradise crystal skills (Core Processing Plant) cost 50 Kraken Scales
# per level in crystalskillcost.unity3d.  The 90% discount shows 5 in the UI.
CRYSTAL_SKILL_COST_FIELDS = ("_crsCost1", "_crsCost2", "_crsCost3")
CRYSTAL_SKILL_SCALE_COST = 50
CRYSTAL_SKILL_SCALE_COST_DISCOUNTED = 5

LIMIT_BREAK_CLIENT_ASSET_PATH = "files/Resources/datatable/limitbreakcost.unity3d"
RUNE_UPGRADE_CLIENT_ASSET_PATH = "files/Resources/datatable/runeenchant.unity3d"
RANDOPTION_CLIENT_ASSET_PATH = "files/Resources/datatable/randoptiontable.unity3d"
RUNE_OPTION_CLIENT_ASSET_PATH = "files/Resources/datatable/runeoption.unity3d"
EQUIP_SUCCESS_CLIENT_ASSET_PATH = (
    "files/Resources/datatable/equipsuccessprobability.unity3d"
)
OPTION_PERCENT_VALUE_TYPE = 2
OPTION_FLAT_VALUE_TYPES = (1, 4)
OPTION_WEIGHT_FIELDS = tuple(f"_weight{i}" for i in range(1, 7))
RUNE_OPTION_FLAT_VALUE_TYPE = 1
RUNE_OPTION_WEIGHT_FIELD = "_weight"
EQUIP_SUCCESS_10_TARGET = 100000
LIMIT_BREAK_CLIENT_PROFILE_SHA256: dict[str, str] = {
    "512de44f756f889bb19fffe1b27483aa58d216e084f6157686a9e9fac9605b55": "stock",
    "bb382678163cc656d405c5c73e9974aba6db609330576e8ad8b8aa7ca17f2e89": "limit_break_gold_half",
    "c255460913e6a82c0636cb993295d823dd7c2e36285fe53617403def08c578cd": "limit_break_cost_half",
    "957c601024640e1c474f48cf4f8ccb2c07f55e078d4ff2a7debc415c6964de49": "limit_break_cost_tenth",
    # Every row at the flat 1,000,000 gold + 100 materials price.
    "48095e9ab1af36c4ba79cdb9c5116a319595baba0a76c9a5fa8564dc28cbce51": "limit_break_cost_fixed",
}
WORLDBOSS_REWARD_CLIENT_STOCK_SHA256 = (
    "c9f12f436718aa5dfe40dfc0ed9c747f2bf47a04702887cdd0fb57107d1615a5"
)
WORLDBOSS_REWARD_CLIENT_PATCHED_SHA256 = (
    "1f5dd3a4b512e0083986d0da50ba2d8e78aa04724eecea88ef451c6662d20492"
)


_AES_KEY_SIZES = frozenset({16, 24, 32})
_AES_IV_SIZE = 16


def _read_cipher_override(
    env_name: str, *, valid_sizes: frozenset[int], label: str
) -> str | None:
    """Reads a datatable cipher override, ignoring empty or CHANGE_ME placeholders."""
    raw = os.environ.get(env_name)
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned or cleaned.startswith("CHANGE_ME"):
        return None
    if len(cleaned.encode("utf-8")) not in valid_sizes:
        allowed = "/".join(str(size) for size in sorted(valid_sizes))
        raise ValueError(f"{env_name} must be {allowed} bytes for datatable {label}")
    return cleaned


def _datatable_crypto_keys() -> tuple[tuple[str, str], ...]:
    """Returns the configured AES key/IV pairs for offline datatable bundles."""
    base_key = _read_cipher_override(
        "FWT_DATATABLE_CRYPT_KEY", valid_sizes=_AES_KEY_SIZES, label="key"
    )
    base_iv = _read_cipher_override(
        "FWT_DATATABLE_CRYPT_IV", valid_sizes=frozenset({_AES_IV_SIZE}), label="IV"
    )
    if not base_key or not base_iv:
        raise ValueError(
            "Missing datatable AES credentials: set FWT_DATATABLE_CRYPT_KEY and "
            "FWT_DATATABLE_CRYPT_IV in .env or the environment (see .env.example)."
        )

    rev_key = _read_cipher_override(
        "FWT_DATATABLE_CRYPT_KEY_REVERSED", valid_sizes=_AES_KEY_SIZES, label="key"
    )
    rev_iv = _read_cipher_override(
        "FWT_DATATABLE_CRYPT_IV_REVERSED",
        valid_sizes=frozenset({_AES_IV_SIZE}),
        label="IV",
    )
    return (
        (rev_key or base_key[::-1], rev_iv or base_iv[::-1]),
        (base_key, base_iv),
    )


def limit_break_client_divisor(*, tenth: bool) -> int:
    """How much the client's own `limitbreakcost` datatable is divided by.

    The screen and the button gate read that datatable, not the server table, so the discount has
    to be applied in both places to look right.  Only the 90% profile remains.
    """
    if tenth:
        return 10
    return 1


def _decrypt_datatable(data: bytes) -> tuple[bytes, str, str]:
    """Decrypts a UnityFS datatable, returning the key/IV that matched."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    for key, iv in _datatable_crypto_keys():
        try:
            dec = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode())).decryptor()
            padded = dec.update(data) + dec.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            clear = unpadder.update(padded) + unpadder.finalize()
            if clear.startswith(b"UnityFS"):
                return clear, key, iv
        except Exception:
            continue
    if data.startswith(b"UnityFS"):
        keys = _datatable_crypto_keys()[0]
        return data, keys[0], keys[1]
    raise ValueError("Failed to decrypt UnityFS datatable: no known AES key matched")


def _encrypt_datatable(clear: bytes, key: str, iv: str) -> bytes:
    """Re-encrypts a patched UnityFS datatable with the original key/IV."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    if len(key_bytes) not in _AES_KEY_SIZES or len(iv_bytes) != _AES_IV_SIZE:
        raise ValueError("Invalid datatable AES key/IV length")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(clear) + padder.finalize()
    enc = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes)).encryptor()
    return enc.update(padded) + enc.finalize()


@dataclass
class ToolPaths:
    zipalign: Optional[str] = None
    apksigner: Optional[str] = None
    keytool: Optional[str] = None
    adb: Optional[str] = None

    @property
    def missing_packaging_tools(self) -> list[str]:
        missing: list[str] = []
        if not self.zipalign:
            missing.append("zipalign")
        if not self.apksigner:
            missing.append("apksigner")
        if not self.keytool:
            missing.append("keytool")
        return missing

    @property
    def has_packaging_tools(self) -> bool:
        return not self.missing_packaging_tools

    @property
    def has_adb(self) -> bool:
        return bool(self.adb)


def describe_missing_packaging_tools(tools: ToolPaths) -> str:
    """Returns an actionable explanation for missing Android/JDK build tools."""
    missing = tools.missing_packaging_tools
    if not missing:
        return "All required packaging tools are available."
    missing_text = ", ".join(missing)
    return (
        f"Missing required packaging tools: {missing_text}.\n"
        "These are external Android SDK Build-Tools/JDK binaries, not Python "
        "packages; `pip install -r requirements.txt` does not install them.\n"
        "Install Android SDK Build-Tools (zipalign, apksigner) and a JDK 17+ "
        "(keytool), then make them available through PATH or set "
        "ANDROID_HOME/ANDROID_SDK_ROOT and JAVA_HOME (for example in .env).\n"
        "Linux/macOS helper: bash scripts/setup-linux-toolchain.sh\n"
        "Check the detected paths with: python fwt_patcher.py --check-tools\n"
        "See README.md > System Requirements and Troubleshooting."
    )


def _version_key(path: str) -> tuple[int, ...]:
    """Numeric sort key so build-tools/35 beats build-tools/9 (lexical would not)."""
    text = str(path)
    match = re.search(r"build-tools[\\/]([^\\/]+)", text)
    return tuple(int(part) for part in re.findall(r"\d+", match.group(1) if match else text))


def _find_binary(name: str, fallback_patterns: list[str]) -> Optional[str]:
    """Finds an executable in system PATH or fallback glob patterns."""
    found = shutil.which(name)
    if found:
        return found
    for pat in fallback_patterns:
        matches = sorted(glob.glob(pat), key=_version_key, reverse=True)
        if matches:
            return matches[0]
    return None


def _keystore_alias() -> str:
    return os.environ.get("FWT_KEY_ALIAS", KEYSTORE_ALIAS)


def _keystore_password() -> str:
    return os.environ.get("FWT_KEYSTORE_PASS", KEYSTORE_PASSWORD)


def _tool_env(*, include_keystore_pass: bool = False) -> dict[str, str]:
    """Returns the subprocess environment with JAVA_HOME/bin on PATH.

    apksigner is a shell/batch wrapper that invokes ``java``; when only
    JAVA_HOME is configured (common in .env setups), the wrapper fails
    unless the JDK bin directory is explicitly on PATH.
    """
    env = os.environ.copy()
    if include_keystore_pass:
        env["FWT_KEYSTORE_PASS"] = _keystore_password()
    else:
        env.pop("FWT_KEYSTORE_PASS", None)
    java_home = env.get("JAVA_HOME")
    if java_home:
        java_bin = os.path.join(java_home, "bin")
        path_parts = env.get("PATH", "").split(os.pathsep)
        if java_bin not in path_parts:
            env["PATH"] = java_bin + os.pathsep + env.get("PATH", "")
    return env


# Avoid console flashes when the Tkinter app calls adb/apksigner from a worker.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run_tool(
    args: list[str],
    description: str,
    timeout: int = 600,
) -> subprocess.CompletedProcess:
    """Runs an external tool and surfaces its stderr when it fails."""
    needs_keystore_pass = any("FWT_KEYSTORE_PASS" in str(arg) for arg in args)
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=_tool_env(include_keystore_pass=needs_keystore_pass),
            stdin=subprocess.DEVNULL,
            creationflags=_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{description} timed out after {timeout}s") from exc
    except OSError as exc:
        raise RuntimeError(f"{description} could not be started: {exc}") from exc
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(
            f"{description} failed (exit {result.returncode})"
            + (f":\n{details}" if details else "")
        )
    return result


def locate_tools() -> ToolPaths:
    """Discovers SDK tools across Windows and Linux environments."""
    is_windows = (os.name == "nt")
    user_home = Path.home()

    sdk_roots = [
        r for r in (
            os.environ.get("ANDROID_SDK_ROOT", ""),
            os.environ.get("ANDROID_HOME", ""),
            str(user_home / "android-sdk"),
            str(user_home / "AppData" / "Local" / "Android" / "Sdk"),
            str(user_home / "Android" / "Sdk"),
            "/opt/android-sdk",
            "/usr/lib/android-sdk",
        ) if r
    ]

    zipalign_patterns = [
        os.path.join(r, "build-tools", "*", "zipalign.exe" if is_windows else "zipalign")
        for r in sdk_roots
    ] + (["/usr/bin/zipalign"] if not is_windows else [])

    apksigner_patterns = [
        os.path.join(r, "build-tools", "*", "apksigner.bat" if is_windows else "apksigner")
        for r in sdk_roots
    ] + (["/usr/bin/apksigner"] if not is_windows else [])

    keytool_patterns = (
        [
            r"C:\Program Files\Eclipse Adoptium\*\bin\keytool.exe",
            r"C:\Program Files\Java\*\bin\keytool.exe",
            r"C:\Program Files (x86)\Java\*\bin\keytool.exe",
        ] if is_windows else [
            "/usr/lib/jvm/*/bin/keytool",
            "/usr/bin/keytool",
        ]
    )
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        keytool_patterns.insert(
            0, os.path.join(java_home, "bin", "keytool.exe" if is_windows else "keytool")
        )

    adb_patterns = [
        os.path.join(r, "platform-tools", "adb.exe" if is_windows else "adb")
        for r in sdk_roots
    ] + (["/usr/bin/adb"] if not is_windows else [])

    return ToolPaths(
        zipalign=_find_binary("zipalign", zipalign_patterns),
        apksigner=_find_binary("apksigner.bat" if is_windows else "apksigner", apksigner_patterns),
        keytool=_find_binary("keytool.exe" if is_windows else "keytool", keytool_patterns),
        adb=_find_binary("adb.exe" if is_windows else "adb", adb_patterns),
    )


def ensure_local_keystore(keystore_path: Path, keytool_bin: str) -> None:
    """Generates a reproducible development signing keystore if missing."""
    if keystore_path.is_file() and keystore_path.stat().st_size > 0:
        # Fail here with a clear message instead of ten minutes later inside
        # apksigner (truncated keystore, changed FWT_KEYSTORE_PASS, missing alias).
        try:
            _run_tool(
                [
                    keytool_bin, "-list",
                    "-keystore", str(keystore_path),
                    "-alias", _keystore_alias(),
                    "-storepass:env", "FWT_KEYSTORE_PASS",
                ],
                "keytool keystore validation",
                timeout=60,
            )
        except RuntimeError as exc:
            raise RuntimeError(
                f"Signing keystore {keystore_path} cannot be opened with "
                "FWT_KEYSTORE_PASS/FWT_KEY_ALIAS. Restore the original keystore "
                "or remove it to generate a new one (existing installs will then "
                "require an uninstall/reinstall)."
            ) from exc
        return
    keystore_path.parent.mkdir(parents=True, exist_ok=True)
    _run_tool(
        [
            keytool_bin, "-genkeypair", "-v",
            "-keystore", str(keystore_path),
            "-storetype", "PKCS12",
            "-alias", _keystore_alias(),
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-storepass:env", "FWT_KEYSTORE_PASS",
            "-keypass:env", "FWT_KEYSTORE_PASS",
            "-dname", "CN=FWT Reborn Patched, OU=Dev, O=Local, L=Local, S=Local, C=US",
        ],
        "keytool keystore generation",
        timeout=120,
    )
    with contextlib.suppress(OSError):
        os.chmod(keystore_path, 0o600)


def is_signature_file(filename: str) -> bool:
    """Identifies existing signature entries in META-INF/."""
    norm = filename.replace("\\", "/")
    if not norm.startswith("META-INF/"):
        return False
    upper = norm.upper()
    return (
        upper == "META-INF/MANIFEST.MF"
        or upper.endswith((".SF", ".RSA", ".DSA", ".EC"))
        or Path(upper).name.startswith("SIG-")
    )


def _dos_datetime(date_time: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    year, month, day, hour, minute, second = date_time
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    return dos_time, dos_date


def _read_at(handle: BinaryIO, offset: int, size: int) -> bytes:
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise ValueError(f"Truncated ZIP read at 0x{offset:x} ({size} bytes)")
    return data


def _copy_range(
    source: BinaryIO, destination: BinaryIO, offset: int, size: int
) -> None:
    source.seek(offset)
    remaining = size
    while remaining:
        chunk = source.read(min(8 * 1024 * 1024, remaining))
        if not chunk:
            raise ValueError(f"Truncated ZIP entry data at 0x{offset:x}")
        destination.write(chunk)
        remaining -= len(chunk)


def _rewrite_zip_entries_to_file(
    raw_path: Path,
    replacements: dict[str, bytes],
    output_path: Path,
) -> None:
    """Rewrites selected ZIP entries to a file without loading the archive in RAM.

    Recompressing the whole 771 MiB archive made its SHA depend on the host
    zlib implementation. Only the selected datatables change, so every other
    local record is copied verbatim from the source file and the central
    directory is rebuilt around them.
    """
    with (
        zipfile.ZipFile(raw_path, "r") as source,
        raw_path.open("rb") as raw_file,
        output_path.open("wb") as output,
    ):
        infos = source.infolist()
        central_start = source.start_dir
        available = {info.filename for info in infos}
        missing = set(replacements) - available
        if missing:
            raise ValueError(
                "Internal resource archive is missing expected entr(ies): "
                + ", ".join(sorted(missing))
            )

        ordered = sorted(infos, key=lambda item: item.header_offset)
        next_offsets = [item.header_offset for item in ordered[1:]] + [central_start]
        new_offsets: dict[int, int] = {}
        output_size = 0

        for info, next_offset in zip(ordered, next_offsets, strict=True):
            new_offsets[info.header_offset] = output_size
            replacement = replacements.get(info.filename)
            if replacement is None:
                size = next_offset - info.header_offset
                _copy_range(raw_file, output, info.header_offset, size)
                output_size += size
                continue

            local_header = _read_at(raw_file, info.header_offset, 30)
            (
                signature,
                version,
                flags,
                _method,
                mod_time,
                mod_date,
                _crc,
                _compressed_size,
                _uncompressed_size,
                name_length,
                extra_length,
            ) = struct.unpack("<IHHHHHIIIHH", local_header)
            if signature != 0x04034B50:
                raise ValueError(f"Invalid local ZIP header for {info.filename}")
            name_start = info.header_offset + 30
            name = _read_at(raw_file, name_start, name_length)
            extra = _read_at(raw_file, name_start + name_length, extra_length)
            crc = zlib.crc32(replacement) & 0xFFFFFFFF
            # Preserve the UTF-8 flag, drop the data-descriptor flag and store
            # the replacement uncompressed (platform-independent bytes).
            flags &= 0x0800
            blob = (
                struct.pack(
                    "<IHHHHHIIIHH",
                    0x04034B50,
                    version,
                    flags,
                    0,
                    mod_time,
                    mod_date,
                    crc,
                    len(replacement),
                    len(replacement),
                    len(name),
                    len(extra),
                )
                + name
                + extra
                + replacement
            )
            output.write(blob)
            output_size += len(blob)

        central_directory = bytearray()
        for info in infos:
            # Read the raw name length from the local header (preserves the
            # original encoding, including non-ASCII names).
            local_header = _read_at(raw_file, info.header_offset, 30)
            name_length = struct.unpack_from("<H", local_header, 26)[0]
            name = _read_at(raw_file, info.header_offset + 30, name_length)
            replacement = replacements.get(info.filename)
            if replacement is None:
                extra = info.extra
                flags = info.flag_bits
                method = info.compress_type
                crc = info.CRC
                compressed_size = info.compress_size
                uncompressed_size = info.file_size
            else:
                # Zip64/extra size fields would be stale after the replacement.
                extra = b""
                flags = info.flag_bits & 0x0800
                method = 0
                crc = zlib.crc32(replacement) & 0xFFFFFFFF
                compressed_size = len(replacement)
                uncompressed_size = len(replacement)

            comment = info.comment or b""
            dos_time, dos_date = _dos_datetime(info.date_time)
            central_directory += struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                (info.create_system << 8) | info.create_version,
                info.extract_version,
                flags,
                method,
                dos_time,
                dos_date,
                crc,
                compressed_size,
                uncompressed_size,
                len(name),
                len(extra),
                len(comment),
                info.volume,
                info.internal_attr,
                info.external_attr,
                new_offsets[info.header_offset],
            )
            central_directory += name + extra + comment

        if (
            len(infos) >= 0xFFFF
            or output_size > 0xFFFFFFFF
            or len(central_directory) > 0xFFFFFFFF
        ):
            raise ValueError(
                "Internal resource archive requires ZIP64; raw-entry rewrite "
                "is not supported"
            )
        central_offset = output_size
        output.write(central_directory)
        output.write(
            struct.pack(
                "<IHHHHIIH",
                0x06054B50,
                0,
                0,
                len(infos),
                len(infos),
                len(central_directory),
                central_offset,
                0,
            )
        )

    # Fail early if the rebuilt archive cannot be parsed. Reading only the
    # replacement entries keeps this validation cheap.
    with zipfile.ZipFile(output_path, "r") as check:
        if len(check.infolist()) != len(infos):
            raise ValueError("Rebuilt resource archive lost entries")
        for entry_name, expected in replacements.items():
            if check.read(entry_name) != expected:
                raise ValueError(
                    f"Rebuilt resource archive mismatches {entry_name}"
                )


def _rewrite_zip_entries(raw_zip: bytes, replacements: dict[str, bytes]) -> bytes:
    """Bytes wrapper used by tests; production uses the file-backed version."""
    with tempfile.TemporaryDirectory(prefix="fwt-zip-rewrite-") as tmp:
        source = Path(tmp) / "source.zip"
        target = Path(tmp) / "target.zip"
        source.write_bytes(raw_zip)
        _rewrite_zip_entries_to_file(source, replacements, target)
        return target.read_bytes()


def _restore_sacred_lands_set_rows(tree: dict) -> int:
    """Sets the Sacred Lands set rows back to grade 4 in a SetItemTable tree."""
    rows = tree.get("_data")
    if not isinstance(rows, list):
        return 0
    changed = 0
    for row in rows:
        if int(row.get("_setgroupid", -1)) != SACRED_LANDS_SET_GROUP:
            continue
        current = int(row.get("_itemGrade", -1))
        if current == SACRED_LANDS_ITEM_GRADE:
            continue
        if current != SACRED_LANDS_ORIGINAL_GRADE:
            raise ValueError(
                f"unexpected Sacred Lands item grade: {current} "
                f"(expected {SACRED_LANDS_ORIGINAL_GRADE})"
            )
        row["_itemGrade"] = SACRED_LANDS_ITEM_GRADE
        changed += 1
    return changed


def _restore_sacred_lands_select_rows(tree: dict) -> int:
    """Adds Sacred Lands to the grade-4 set selection ticket lists."""
    rows = tree.get("_data")
    if not isinstance(rows, list):
        return 0
    existing = {
        (int(row.get("_equipListId", -1)), int(row.get("_equipCode", -1)))
        for row in rows
    }
    changed = 0
    for list_id in SACRED_LANDS_TICKET_LISTS:
        key = (list_id, SACRED_LANDS_SET_GROUP)
        if key in existing:
            continue
        rows.append(
            {"_equipListId": list_id, "_equipCode": SACRED_LANDS_SET_GROUP}
        )
        existing.add(key)
        changed += 1
    return changed


def inspect_sacred_lands_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Checks the client datatables for the Sacred Lands restoration patch.

    ``archive`` is the nested ``assets/fwt_resources_v1.zip`` opened from the
    APK. Only the small set/selection bundles are read, so this stays cheap
    even though the full resource archive is hundreds of megabytes.
    """
    try:
        import cryptography  # noqa: F401
        import UnityPy
    except ImportError:
        return False, "Optional dependencies (UnityPy/cryptography) not available"

    names = archive.namelist()
    set_names = [
        name
        for name in names
        if re.match(
            r"files/Resources/(?:datatable/)?setitemtable[a-z]*\.unity3d$", name
        )
    ]
    if not set_names:
        return False, "SetItemTable bundles not found in the resource archive"

    total_rows = 0
    graded_rows = 0
    for name in set_names:
        try:
            clear, _key, _iv = _decrypt_datatable(archive.read(name))
            env = UnityPy.load(clear)
            for obj in env.objects:
                if obj.type.name != "MonoBehaviour":
                    continue
                rows = obj.read_typetree().get("_data") or []
                for row in rows:
                    if int(row.get("_setgroupid", -1)) != SACRED_LANDS_SET_GROUP:
                        continue
                    total_rows += 1
                    if int(row.get("_itemGrade", -1)) == SACRED_LANDS_ITEM_GRADE:
                        graded_rows += 1
        except Exception:
            continue

    lists_found = 0
    list_name = "files/Resources/datatable/equipselectlist.unity3d"
    if list_name in names:
        try:
            clear, _key, _iv = _decrypt_datatable(archive.read(list_name))
            env = UnityPy.load(clear)
            present = set()
            for obj in env.objects:
                if obj.type.name != "MonoBehaviour":
                    continue
                rows = obj.read_typetree().get("_data") or []
                for row in rows:
                    if int(row.get("_equipCode", -1)) == SACRED_LANDS_SET_GROUP:
                        present.add(int(row.get("_equipListId", -1)))
            lists_found = sum(
                1 for list_id in SACRED_LANDS_TICKET_LISTS if list_id in present
            )
        except Exception:
            lists_found = 0

    active = (
        total_rows > 0
        and graded_rows == total_rows
        and lists_found == len(SACRED_LANDS_TICKET_LISTS)
    )
    details = (
        f"{graded_rows}/{total_rows} set row(s) at grade {SACRED_LANDS_ITEM_GRADE}; "
        f"{lists_found}/{len(SACRED_LANDS_TICKET_LISTS)} ticket list(s) include "
        f"group {SACRED_LANDS_SET_GROUP}"
    )
    return active, details


def _read_datatable_rows(
    archive: zipfile.ZipFile,
    entry_name: str,
    *,
    label: str,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Decrypts an encrypted Unity datatable bundle and returns its ``_data`` rows."""
    try:
        import cryptography  # noqa: F401
        import UnityPy
    except ImportError:
        return None, "Optional dependencies (UnityPy/cryptography) not available"

    if entry_name not in archive.namelist():
        return None, f"{label} not found in the resource archive"
    try:
        clear, _key, _iv = _decrypt_datatable(archive.read(entry_name))
        env = UnityPy.load(clear)
        rows: list[dict[str, Any]] = []
        for obj in env.objects:
            if obj.type.name == "MonoBehaviour":
                rows.extend(obj.read_typetree().get("_data") or [])
    except Exception as exc:  # noqa: BLE001
        return None, f"{label} check failed: {exc}"

    if not rows:
        return None, f"{label} has no rows"
    return rows, None


def inspect_crystal_skill_cost_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Checks the client crystal skill costs for the 90% discount patch."""
    rows, error = _read_datatable_rows(
        archive,
        "files/Resources/datatable/crystalskillcost.unity3d",
        label="crystalskillcost.unity3d",
    )
    if rows is None:
        return False, error or "crystalskillcost.unity3d unavailable"
    discounted = 0
    for row in rows:
        if all(
            int(row.get(field, -1)) == CRYSTAL_SKILL_SCALE_COST_DISCOUNTED
            for field in CRYSTAL_SKILL_COST_FIELDS
        ):
            discounted += 1
    active = discounted == len(rows)
    return (
        active,
        f"{discounted}/{len(rows)} crystal skill row(s) at "
        f"{CRYSTAL_SKILL_SCALE_COST_DISCOUNTED} Kraken Scales",
    )


def inspect_equipment_percent_options_assets(
    archive: zipfile.ZipFile,
) -> tuple[bool, str]:
    """Checks that every flat equipment-option row has zero roll weight."""
    rows, error = _read_datatable_rows(
        archive,
        RANDOPTION_CLIENT_ASSET_PATH,
        label="randoptiontable.unity3d",
    )
    if rows is None:
        return False, error or "randoptiontable.unity3d unavailable"
    flat_rows = [row for row in rows if int(row.get("_valueType", 0)) in OPTION_FLAT_VALUE_TYPES]
    weighted_flat = [
        row
        for row in flat_rows
        if any(int(row.get(field, 0)) != 0 for field in OPTION_WEIGHT_FIELDS)
    ]
    percent_rows = [
        row
        for row in rows
        if int(row.get("_valueType", 0)) == OPTION_PERCENT_VALUE_TYPE
        and any(int(row.get(field, 0)) > 0 for field in OPTION_WEIGHT_FIELDS)
    ]
    active = not weighted_flat and bool(percent_rows)
    details = (
        f"{len(percent_rows)} percentage row(s) weighted; "
        f"{len(weighted_flat)}/{len(flat_rows)} flat row(s) still weighted"
    )
    return active, details


def inspect_rune_option_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Checks that every flat rune-option row has zero selection weight."""
    rows, error = _read_datatable_rows(
        archive,
        RUNE_OPTION_CLIENT_ASSET_PATH,
        label="runeoption.unity3d",
    )
    if rows is None:
        return False, error or "runeoption.unity3d unavailable"
    flat_rows = [
        row
        for row in rows
        if int(row.get("_valueType", 0)) == RUNE_OPTION_FLAT_VALUE_TYPE
    ]
    weighted_flat = [
        row for row in flat_rows if int(row.get(RUNE_OPTION_WEIGHT_FIELD, 0)) != 0
    ]
    percent_rows = [
        row
        for row in rows
        if int(row.get("_valueType", 0)) != RUNE_OPTION_FLAT_VALUE_TYPE
        and int(row.get(RUNE_OPTION_WEIGHT_FIELD, 0)) > 0
    ]
    active = not weighted_flat and bool(percent_rows)
    details = (
        f"{len(percent_rows)} percentage row(s) weighted; "
        f"{len(weighted_flat)}/{len(flat_rows)} flat row(s) still weighted"
    )
    return active, details


def inspect_equipment_upgrade_10_assets(
    archive: zipfile.ZipFile,
) -> tuple[bool, str]:
    """Checks the +9 -> +10 success probabilities in equipsuccessprobability."""
    rows, error = _read_datatable_rows(
        archive,
        EQUIP_SUCCESS_CLIENT_ASSET_PATH,
        label="equipsuccessprobability.unity3d",
    )
    if rows is None:
        return False, error or "equipsuccessprobability.unity3d unavailable"
    row = next(
        (item for item in rows if int(item.get("_baseEquipEnchant", -1)) == 9),
        None,
    )
    if row is None:
        return False, "equipsuccessprobability has no +9 row"
    values = [int(row.get(f"_successProb{i}", -1)) for i in range(1, 7)]
    active = all(value == EQUIP_SUCCESS_10_TARGET for value in values)
    details = (
        f"+9 -> +10 success probabilities: {', '.join(str(v) for v in values)}"
    )
    return active, details


def inspect_guild_raid_fire_support_assets(
    archive: zipfile.ZipFile,
) -> tuple[bool, str]:
    """Checks Fire Support minion damage values in guildskilldata.unity3d."""
    rows, error = _read_datatable_rows(
        archive,
        GUILD_SKILL_DATA_CLIENT_ASSET_PATH,
        label="guildskilldata.unity3d",
    )
    if rows is None:
        return False, error or "guildskilldata.unity3d unavailable"
    return inspect_guildskilldata_rows(rows)


def inspect_guild_raid_skills_max_assets(
    archive: zipfile.ZipFile,
) -> tuple[bool, str]:
    """Checks maxed Guild Raid skill effects and Absolute Protection MP slot."""
    rows, error = _read_datatable_rows(
        archive,
        GUILD_SKILL_DATA_CLIENT_ASSET_PATH,
        label="guildskilldata.unity3d",
    )
    if rows is None:
        return False, error or "guildskilldata.unity3d unavailable"
    ok_data, detail_data = inspect_guildskilldata_max_rows(rows)

    info_ok = 0
    info_failed: list[str] = []
    for asset_path in GUILD_SKILL_INFO_CLIENT_ASSETS:
        info_rows, info_err = _read_datatable_rows(
            archive,
            asset_path,
            label=Path(asset_path).name,
        )
        if info_rows is None:
            info_failed.append(f"{Path(asset_path).name}: {info_err or 'unavailable'}")
            continue
        bundle_ok, bundle_detail = inspect_guildskillinfo_max_rows(info_rows)
        if bundle_ok:
            info_ok += 1
        else:
            info_failed.append(f"{Path(asset_path).name}: {bundle_detail}")

    total_info = len(GUILD_SKILL_INFO_CLIENT_ASSETS)
    if ok_data and info_ok == total_info:
        return True, f"{detail_data}; Absolute Protection 100% MP across {total_info}/{total_info} skill info bundles"
    if not ok_data and info_ok == 0:
        return False, f"{detail_data}; Absolute Protection effect03 stock ({total_info} bundles)"
    problems = [] if ok_data else [detail_data]
    problems.extend(info_failed)
    return False, "; ".join(problems)


def inspect_guild_raid_boss_no_counter_assets(
    archive: zipfile.ZipFile,
) -> tuple[bool, str]:
    """Checks 0% counterattack rate for Guild Raid bosses in monsterdata.unity3d."""
    rows, error = _read_datatable_rows(
        archive,
        MONSTER_DATA_CLIENT_ASSET_PATH,
        label="monsterdata.unity3d",
    )
    if rows is None:
        return False, error or "monsterdata.unity3d unavailable"
    return inspect_monsterdata_boss_car_rows(rows)


def _worldboss_cycle_client_digest(rows: list[dict[str, Any]]) -> tuple[int, str]:
    """Returns `(target_row_count, sha256_hex)` for World Boss rank/grade client rows."""
    signature = [
        (
            int(row.get("_rewardType", -1)),
            int(row.get("_reward1Type", -1)),
            int(row.get("_reward1Value01", -1)),
            int(row.get("_reward1Value02", -1)),
        )
        for row in rows
        if row.get("_rewardType") in WORLDBOSS_CYCLE_REWARD_TARGET_TYPES
    ]
    digest = hashlib.sha256(repr(signature).encode("ascii")).hexdigest()
    return len(signature), digest


def inspect_honor_reward_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Checks the client Battle of Honor reward preview table (6 -> 60)."""
    rows, error = _read_datatable_rows(
        archive,
        "files/Resources/datatable/honorreward.unity3d",
        label="honorreward.unity3d",
    )
    if rows is None:
        return False, error or "honorreward.unity3d unavailable"
    win_rows = [row for row in rows if row.get("_resultType") == 1]
    if not win_rows:
        return False, "honorreward.unity3d has no win reward rows (_resultType == 1)"
    patched = sum(1 for row in win_rows if int(row.get("_rewardItemCount", 0)) == 60)
    active = patched == len(win_rows)
    return (
        active,
        f"{patched}/{len(win_rows)} Battle of Honor win row(s) at 60 coins",
    )


def inspect_worldboss_reward_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Checks all 7 client worldbossreward tables for 10x final rank/grade rewards."""
    matched_bundles = 0
    for entry_name in WORLDBOSS_REWARD_CLIENT_ASSETS:
        label = Path(entry_name).name
        rows, error = _read_datatable_rows(archive, entry_name, label=label)
        if rows is None:
            return False, error or f"{label} unavailable"
        count, digest = _worldboss_cycle_client_digest(rows)
        if count != WORLDBOSS_CYCLE_REWARD_TARGET_COUNT:
            return (
                False,
                f"{label} has {count}/{WORLDBOSS_CYCLE_REWARD_TARGET_COUNT} rank/grade rows",
            )
        if digest == WORLDBOSS_REWARD_CLIENT_PATCHED_SHA256:
            matched_bundles += 1
        elif digest != WORLDBOSS_REWARD_CLIENT_STOCK_SHA256:
            return False, f"{label} has unexpected rank/grade rewards ({digest[:12]})"
    active = matched_bundles == len(WORLDBOSS_REWARD_CLIENT_ASSETS)
    return (
        active,
        f"{matched_bundles}/{len(WORLDBOSS_REWARD_CLIENT_ASSETS)} World Boss reward "
        "bundle(s) at 10x rank/grade",
    )


def inspect_mode_drops_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Checks both honorreward and worldbossreward client tables for mode_drops_x10."""
    honor_ok, honor_msg = inspect_honor_reward_assets(archive)
    wb_ok, wb_msg = inspect_worldboss_reward_assets(archive)
    return honor_ok and wb_ok, f"{honor_msg}; {wb_msg}"


def _group_recycle_six_star_rows(
    rows: list[dict[str, Any]],
) -> dict[int, list[dict[str, Any]]]:
    """Groups datatable `_data` rows belonging to target alchemy reward weights."""
    by_group: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        group = row.get("_weightNo")
        if group in RECYCLE_SIX_STAR_GROUPS:
            by_group.setdefault(group, []).append(row)
    return by_group


def inspect_recycle_six_star_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Checks all client alchemy reward tables for native 6★ set piece overrides."""
    total_rows = 0
    matched_rows = 0
    checked_assets = 0
    for entry_name in RECYCLE_SIX_STAR_CLIENT_ASSETS:
        label = Path(entry_name).name
        rows, error = _read_datatable_rows(archive, entry_name, label=label)
        if rows is None:
            return False, error or f"{label} unavailable"
        by_group = _group_recycle_six_star_rows(rows)
        checked_assets += 1
        if not by_group:
            continue
        for group, group_rows in by_group.items():
            targets = recycle_six_star_assignment(
                [
                    (int(row.get("_weightValue", 0)), int(row.get("_equipCode", 0)))
                    for row in group_rows
                ],
                RECYCLE_SIX_STAR_GROUP_SLOT[group],
            )
            total_rows += len(group_rows)
            matched_rows += sum(
                1
                for row, target in zip(group_rows, targets, strict=True)
                if (int(row.get("_weightValue", 0)), int(row.get("_equipCode", 0)))
                == target
            )
    if total_rows == 0:
        return False, "client equipreward tables have no alchemy reward groups"
    active = (
        checked_assets == len(RECYCLE_SIX_STAR_CLIENT_ASSETS)
        and matched_rows == total_rows
    )
    return (
        active,
        f"{matched_rows}/{total_rows} alchemy row(s) across "
        f"{checked_assets}/{len(RECYCLE_SIX_STAR_CLIENT_ASSETS)} bundle(s)",
    )


def _limit_break_profile_from_rows(
    rows: list[dict[str, Any]],
) -> tuple[str | None, str]:
    """Returns `(matched_profile, sha256_hex)` for limitbreakcost `_data` rows."""
    pairs = [(int(row["_cost"]), int(row["_rewardValue02"])) for row in rows]
    digest = hashlib.sha256(repr(pairs).encode("ascii")).hexdigest()
    return LIMIT_BREAK_CLIENT_PROFILE_SHA256.get(digest), digest


def _limit_break_target_profile(options: PatchOptions) -> str:
    """Returns the limitbreakcost client profile name targeted by `options`."""
    if options.limit_break_cost_fixed:
        return "limit_break_cost_fixed"
    return "limit_break_cost_tenth"


def inspect_limit_break_cost_assets(
    archive: zipfile.ZipFile,
) -> tuple[str | None, str]:
    """Identifies the active limit-break discount profile in limitbreakcost.unity3d."""
    rows, error = _read_datatable_rows(
        archive,
        LIMIT_BREAK_CLIENT_ASSET_PATH,
        label="limitbreakcost.unity3d",
    )
    if rows is None:
        return None, error or "limitbreakcost.unity3d unavailable"
    try:
        profile, digest = _limit_break_profile_from_rows(rows)
    except (KeyError, TypeError, ValueError) as exc:
        return None, f"limitbreakcost.unity3d missing cost fields: {exc}"
    if profile is None:
        return None, f"Unknown limitbreakcost.unity3d table (sha {digest[:12]})"
    return profile, f"client table matches {profile} ({len(rows)} rows)"


def _limit_break_step_profile_from_rows(
    rows: list[dict[str, Any]],
) -> tuple[str | None, str]:
    """Returns ``('stock' | 'limit_break_step_10' | None, sha256_hex)`` for level steps."""
    pairs = [(int(row["_levelBefore"]), int(row["_levelAfter"])) for row in rows]
    digest = hashlib.sha256(repr(pairs).encode("ascii")).hexdigest()
    if not pairs:
        return None, digest
    if not all(70 <= before < LIMIT_BREAK_MAX_LEVEL for before, _ in pairs):
        return None, digest
    if all(after == before + 2 for before, after in pairs):
        return "stock", digest
    if all(after == limit_break_step10_target(before) for before, after in pairs):
        return "limit_break_step_10", digest
    return None, digest


def inspect_limit_break_step_assets(
    archive: zipfile.ZipFile,
) -> tuple[bool, str]:
    """Checks whether limitbreakcost.unity3d uses +10 limit-break steps to Lv 120."""
    rows, error = _read_datatable_rows(
        archive,
        LIMIT_BREAK_CLIENT_ASSET_PATH,
        label="limitbreakcost.unity3d",
    )
    if rows is None:
        return False, error or "limitbreakcost.unity3d unavailable"
    try:
        profile, digest = _limit_break_step_profile_from_rows(rows)
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"limitbreakcost.unity3d missing level fields: {exc}"
    if profile == "limit_break_step_10":
        return True, f"client table uses +10 steps to Lv 120 ({len(rows)} rows)"
    if profile == "stock":
        return False, f"client table uses stock +2 steps ({len(rows)} rows)"
    return False, f"Unknown limitbreakcost.unity3d level steps (sha {digest[:12]})"


RUNE_UPGRADE_CLIENT_STOCK = {
    12: ((5188, 5707, 6278, 9414, 10986, 12555),
         (8500, 17000, 34000, 59500, 74800, 136000)),
    13: ((5707, 6278, 6906, 10355, 12085, 13811),
         (9200, 18400, 36800, 64400, 80960, 147200)),
    14: ((6278, 6906, 7597, 11391, 13294, 15192),
         (9950, 19900, 39800, 69650, 87560, 159200)),
}


def _rune_upgrade_profile_from_rows(rows: list[dict[str, Any]]) -> tuple[str | None, str]:
    """Returns `("stock" | "patched" | None, sha256_hex)` for runeenchant rows."""
    selected = [
        row for row in rows if int(row.get("_baseRuneEnchant", -1)) in RUNE_UPGRADE_CLIENT_STOCK
    ]
    projection = []
    for row in sorted(selected, key=lambda r: int(r["_baseRuneEnchant"])):
        failures = tuple(int(row.get(f"_failProb{g}", -1)) for g in range(1, 7))
        costs = tuple(
            int(row.get("_goldCost" if g == 1 else f"_goldCost{g}", -1))
            for g in range(1, 7)
        )
        projection.append((int(row["_baseRuneEnchant"]), failures, costs))
    digest = hashlib.sha256(repr(projection).encode("ascii")).hexdigest()
    if len(projection) != 3:
        return None, digest
    profile = "stock"
    for level, failures, costs in projection:
        old_failures, old_costs = RUNE_UPGRADE_CLIENT_STOCK[level]
        if failures == old_failures and costs == old_costs:
            continue
        if failures == (0,) * 6 and costs == tuple(value // 10 for value in old_costs):
            profile = "patched"
            continue
        return None, digest
    return profile, digest


def inspect_rune_upgrade_assets(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Identifies whether runeenchant.unity3d already carries the discount."""
    rows, error = _read_datatable_rows(
        archive,
        RUNE_UPGRADE_CLIENT_ASSET_PATH,
        label="runeenchant.unity3d",
    )
    if rows is None:
        return False, error or "runeenchant.unity3d unavailable"
    try:
        profile, digest = _rune_upgrade_profile_from_rows(rows)
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"runeenchant.unity3d missing upgrade fields: {exc}"
    if profile == "patched":
        return True, f"client table patched ({len(rows)} rows)"
    if profile == "stock":
        return False, f"client table is stock ({len(rows)} rows)"
    return False, f"Unknown runeenchant.unity3d table (sha {digest[:12]})"


SHOP_CONTENTS_SENTINEL_SHOP_ID = 5209
SHOP_CONTENTS_SENTINEL_STOCK = 900000
SHOP_CONTENTS_SENTINEL_DISCOUNTED = 90000
SHOP_FRIEND_SENTINEL_STOCK = 49500
SHOP_FRIEND_SENTINEL_DISCOUNTED = 4950
SHOP_FRIEND_SENTINEL_DISCOUNTED_JAPAN = 400
SHOP_EVENT_COIN_SENTINEL_DISCOUNTED = 3
SHOP_CAMPAIGN_COIN_SENTINEL_DISCOUNTED = 1500
SHOP_EVENT_GENE_SENTINEL_SHOP_ID = 1114113
SHOP_EVENT_GENE_SENTINEL_STOCK = 100
SHOP_EVENT_GENE_SENTINEL_UNLIMITED = 255

# SHA-256 of the selected, discounted client-table columns in the supported
# reference APK.  The projections contain only integers and exclude unrelated
# fields, so independently enabled shop options do not affect each other.
_SHOP_CONTENT_PROFILES = {
    "default": (
        "ddca781afdd85115dcb80690508906801b39cd8150ded5140775149bc523eb3e",
        "7c4cbc602bbc12fd9f141ac75a1c7be8f64bf28af0aa0d531fce707ea5878254",
    ),
    "japanese": (
        "32b2ddf3f892055a1c781a4905210a9a3f6a0b01a2d1b243521d47717b57f697",
        "40208179bec03c724cd9770d9012570dbfd6f03690a7b6a701cdaa8c01bf49f0",
    ),
}
_SHOP_DATA_PROFILES = {
    "default": (
        "68cde351e304b1fed70ced7ea17b1e13491d4f0389a8aafc94f721e3eca3fb5a",
        "bda8b150e57fe8cc6fb2f5b06d492d827700e32c857aa90b6c2c8c2cfff19c31",
        "09a011737ead2606848244387c2c7e5c1fe5c20dd5917bd9c290a7c6b552a966",
    ),
    "japan": (
        "18696b802ce638432c1f0bed3dd5788098025da146c6aa05ff02a67752b57b00",
        "9b5eab0b878b8bd55b55890f5d323abf43e7014ccd1854122796ea2f06ae2002",
        "99e18b1d68f40a001d15b4e8ec2450872a13d073521d50fee05dd32fc80cb70e",
    ),
    "japanese": (
        "de54845fae1a100bae59245e93b78db01fd4aeeb605ad965eac8f4cb3b1205d9",
        "29a62a3ab8b7c4fe84ddaf8b8856971c9c59ae93cbd7acc91725539ba148f5d4",
        "0671168a97dc434a581023c19a61557e33a40ff48696ac5c8d119270918361f3",
    ),
}
_SHOP_LANGUAGES = ("", "chinese", "english", "german", "japanese", "spanish", "thai")
_SHOP_LIMIT_PROFILES = {
    ("shopcontentsdata", "default"): (
        "27eb6acf655dfb2bedf26ff978a0b8fb6ef102adcec029bbbed012610c041f5d",
    ),
    ("shopcontentsdata", "japanese"): (
        "6a4048a3d7a94cda5a5791bdb3121b1717cd4be22413cc229086a624bd0bde7d",
    ),
    ("shopdata", "default"): (
        "4ef72504a1a8688124b188e0b7d684392046b4e88396c159f382a6af11e58479",
        "46c9bab7cfbf72da42a3d3eb84a533e83d4da7172a704b3d49fb2f79d4ef7ca6",
    ),
    ("shopdata", "japan"): (
        "0a25652506ac018d6703f02d56405d0a13dbd2b43472a644db0c9e55101ef5f0",
        "9523efa21280535ad8e374856e1f4ffe7189f5ef883a36adbc8abd16e043be01",
    ),
    ("shopdata", "japanese"): (
        "ce6f33de2579b30d00ebceda95b0701465d92e713277a8af3c99ac4222db3ddc",
        "b0e5fc82fd220fc2aaeb35f7bec26b95a6566f3942878424a063a98f4b818e3e",
    ),
}


def inspect_shop_assets(archive: zipfile.ZipFile) -> dict[str, tuple[bool, str]]:
    """Check all supported client shop tables independently of the native patch."""
    keys = ("event_discount", "campaign_shop_discount", "event_gene_unlimited", "event_limits_daily")
    failures: dict[str, list[str]] = {key: [] for key in keys}

    def compare(key: str, label: str, values: list[Any], expected: str) -> None:
        digest = hashlib.sha256(repr(values).encode("ascii")).hexdigest()
        if digest != expected:
            failures[key].append(label)

    for prefix, languages in (("shopcontentsdata", _SHOP_LANGUAGES),
                              ("shopdata", (*_SHOP_LANGUAGES, "japan"))):
        for language in languages:
            label = f"{prefix}{language}.unity3d"
            path = f"files/Resources/datatable/{label}"
            rows, error = _read_datatable_rows(archive, path, label=label)
            relevant = keys if prefix == "shopdata" else (
                "event_discount", "campaign_shop_discount", "event_limits_daily"
            )
            if rows is None:
                for key in relevant:
                    failures[key].append(error or label)
                continue
            if prefix == "shopcontentsdata":
                event_hash, campaign_hash = _SHOP_CONTENT_PROFILES.get(
                    language, _SHOP_CONTENT_PROFILES["default"]
                )
                compare("event_discount", label, [int(r.get("_purchaseNum", 0))
                        for r in rows if r.get("_content") == 2], event_hash)
                compare("campaign_shop_discount", label,
                        [int(r.get("_purchaseNum", 0)) for r in rows], campaign_hash)
                limits = rows
            else:
                event_hash, campaign_hash, genes_hash = _SHOP_DATA_PROFILES.get(
                    language, _SHOP_DATA_PROFILES["default"]
                )
                compare("event_discount", label, [int(r.get("_coinPrice", -1))
                        for r in rows if r.get("_category") == 11], event_hash)
                compare("campaign_shop_discount", label, [
                    (int(r.get("_friendPrice", -1)),
                     int(r.get("_coinPrice", -1)) if r.get("_category") == 6 else None)
                    for r in rows
                ], campaign_hash)
                compare("event_gene_unlimited", label, [
                    (int(r.get("_purchaselimittype", 255)),
                     int(r.get("_purchasecountperlimit", 255)))
                    for r in rows if r.get("_category") == 11
                    and int(r.get("_itemCategory", 0)) == 18
                ], genes_hash)
                limits = [r for r in rows if r.get("_category") in (6, 11)]
            values = [int(r.get("_purchaselimittype", -1)) for r in limits]
            digest = hashlib.sha256(repr(values).encode("ascii")).hexdigest()
            expected_limits = _SHOP_LIMIT_PROFILES.get(
                (prefix, language), _SHOP_LIMIT_PROFILES[(prefix, "default")]
            )
            if digest not in expected_limits:
                failures["event_limits_daily"].append(label)

    return {key: (not issues, "client tables verified" if not issues else
                  "client table mismatch or missing: " + ", ".join(issues))
            for key, issues in failures.items()}


def _discount_client_price(value: int) -> int:
    """ceil(value / 10) with a minimum of one, matching the server discount."""
    return max(1, (value + 9) // 10)


def _shop_contents_prices_patched(rows: list[dict[str, Any]]) -> bool:
    """True when the campaign/event prices already carry the 90% discount.

    Every localized table ships a 900,000-price row; after the discount the
    largest price is 90,000, which makes a reliable per-file marker.
    """
    prices = [int(row.get("_purchaseNum", 0)) for row in rows]
    return bool(prices) and max(prices) == SHOP_CONTENTS_SENTINEL_DISCOUNTED


def _shop_contents_limits_patched(rows: list[dict[str, Any]]) -> bool:
    return not any(int(row.get("_purchaselimittype", -1)) in (3, 4) for row in rows)


def _shop_friends_patched(rows: list[dict[str, Any]]) -> bool:
    friends = [
        int(row.get("_friendPrice", -1))
        for row in rows
        if int(row.get("_friendPrice", -1)) > 0
    ]
    if not friends:
        return True
    maximum = max(friends)
    return maximum in (
        SHOP_FRIEND_SENTINEL_DISCOUNTED,
        SHOP_FRIEND_SENTINEL_DISCOUNTED_JAPAN,
    )


def _shop_coins_patched(
    rows: list[dict[str, Any]],
    category: int,
    sentinel: int,
) -> bool:
    coins = [
        int(row.get("_coinPrice", -1))
        for row in rows
        if int(row.get("_category", -1)) == category and int(row.get("_coinPrice", -1)) > 0
    ]
    return not coins or max(coins) <= sentinel


def _shop_genes_patched(rows: list[dict[str, Any]]) -> bool:
    return not any(
        int(row.get("_category", -1)) == 11
        and int(row.get("_itemCategory", 0)) == 18
        and int(row.get("_purchaselimittype", 255)) != 255
        for row in rows
    )


def _patch_equipment_percent_options_rows(rows: list[dict[str, Any]]) -> int:
    """Drops flat equipment-option rows from the roll by zeroing their weights.

    Value type 2 is percentage-based. Types 1 and 4 are flat. Type 4 stores
    a scaled value, such as 0.0067 for +67 Defense. Every
    equip/grade pair keeps at least one percentage row, so the slot still has
    a valid pool after the flat rows are removed.
    """
    changed = 0
    percent_rows = 0
    for row in rows:
        value_type = int(row.get("_valueType", 0))
        if value_type == OPTION_PERCENT_VALUE_TYPE:
            if any(int(row.get(field, 0)) > 0 for field in OPTION_WEIGHT_FIELDS):
                percent_rows += 1
            continue
        if value_type not in OPTION_FLAT_VALUE_TYPES:
            raise ValueError(f"unexpected equipment option value type: {value_type}")
        for field in OPTION_WEIGHT_FIELDS:
            if int(row.get(field, 0)) != 0:
                row[field] = 0
                changed += 1
    if percent_rows == 0:
        raise ValueError("randoptiontable has no percentage rows with weight")
    return changed


def _patch_rune_option_percent_rows(rows: list[dict[str, Any]]) -> int:
    """Zeroes the selection weight of every flat rune-option row.

    ``_valueType`` 1 marks the fixed-value attributes (+1905 HP, +300 Crit);
    the rune picker skips any row whose ``_weight`` is below 1, so zeroing it
    removes the flat rows from the draw while the percentage variants keep
    their weights.
    """
    changed = 0
    flat_rows = 0
    percent_weighted = 0
    for row in rows:
        weight = int(row.get(RUNE_OPTION_WEIGHT_FIELD, 0))
        if int(row.get("_valueType", 0)) == RUNE_OPTION_FLAT_VALUE_TYPE:
            flat_rows += 1
            if weight != 0:
                row[RUNE_OPTION_WEIGHT_FIELD] = 0
                changed += 1
        elif weight > 0:
            percent_weighted += 1
    if percent_weighted == 0:
        raise ValueError("runeoptiontable has no percentage rows with weight")
    return changed


def _patch_equip_success_10_rows(rows: list[dict[str, Any]]) -> int:
    """Makes the +9 -> +10 equipment upgrade roll always succeed."""
    changed = 0
    target_rows = 0
    for row in rows:
        if int(row.get("_baseEquipEnchant", -1)) != 9:
            continue
        target_rows += 1
        for field in (f"_successProb{i}" for i in range(1, 7)):
            if int(row.get(field, -1)) != EQUIP_SUCCESS_10_TARGET:
                row[field] = EQUIP_SUCCESS_10_TARGET
                changed += 1
    if target_rows != 1:
        raise ValueError(f"expected one +9 success row, found {target_rows}")
    return changed


def _patch_rune_upgrade_rows(rows: list[dict[str, Any]]) -> int:
    """Zeroes the failure chance and discounts the gold for +12→+15 client rows.

    The guaranteed +12 price is completed by the startup cave that rewrites
    ``RuneGradeUpPopup.GetEnchantCoast``; ``runedecidedenchant`` stays stock.
    """
    stock = {
        12: ((5188, 5707, 6278, 9414, 10986, 12555),
             (8500, 17000, 34000, 59500, 74800, 136000)),
        13: ((5707, 6278, 6906, 10355, 12085, 13811),
             (9200, 18400, 36800, 64400, 80960, 147200)),
        14: ((6278, 6906, 7597, 11391, 13294, 15192),
             (9950, 19900, 39800, 69650, 87560, 159200)),
    }
    selected = [r for r in rows if int(r.get("_baseRuneEnchant", -1)) in stock]
    if len(selected) != 3 or {int(r["_baseRuneEnchant"]) for r in selected} != set(stock):
        raise ValueError("expected one rune upgrade row for each level 12–14")
    states = []
    for row in selected:
        level = int(row["_baseRuneEnchant"])
        if any(int(row.get(f"_successProb{g}", -1)) != 30000 for g in range(1, 7)):
            raise ValueError(f"unexpected rune upgrade success weights at level {level}")
        failures = tuple(int(row.get(f"_failProb{g}", -1)) for g in range(1, 7))
        costs = tuple(int(row.get("_goldCost" if g == 1 else f"_goldCost{g}", -1))
                      for g in range(1, 7))
        old_failures, old_costs = stock[level]
        if failures == old_failures and costs == old_costs:
            states.append("stock")
        elif failures == (0,) * 6 and costs == tuple(v // 10 for v in old_costs):
            states.append("patched")
        else:
            raise ValueError(f"unexpected rune upgrade client row {level}")
    if len(set(states)) != 1:
        raise ValueError("mixed rune upgrade client profiles")
    if states[0] == "patched":
        return 0
    for row in selected:
        for grade in range(1, 7):
            row[f"_failProb{grade}"] = 0
            cost_field = "_goldCost" if grade == 1 else f"_goldCost{grade}"
            row[cost_field] //= 10
    return 3


def _patch_shop_contents_table(
    data: bytes, options: PatchOptions, label: str
) -> bytes | None:
    """Patches campaign/event shop prices and daily limits in a client datatable."""
    import UnityPy

    clear, key, iv = _decrypt_datatable(data)
    env = UnityPy.load(clear)
    changed = 0
    for obj in env.objects:
        if obj.type.name != "MonoBehaviour":
            continue
        tree = obj.read_typetree()
        rows = tree.get("_data") or []
        if not rows:
            continue
        prices_done = _shop_contents_prices_patched(rows)
        limits_done = _shop_contents_limits_patched(rows)
        for row in rows:
            content = row.get("_content")
            discount = bool(
                options.campaign_shop_discount or (
                    options.event_discount and content == 2
                )
            )
            if discount and not prices_done:
                price = int(row.get("_purchaseNum", 0))
                if price > 0:
                    row["_purchaseNum"] = _discount_client_price(price)
                    changed += 1
            if (
                options.event_limits_daily
                and not limits_done
                and int(row.get("_purchaselimittype", -1)) in (3, 4)
            ):
                row["_purchaselimittype"] = 1
                changed += 1
        if changed:
            obj.save_typetree(tree)
    if not changed:
        return None
    new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
    patched = _encrypt_datatable(new_clear, key, iv)
    return patched if patched != data else None


def _patch_shop_data_table(
    data: bytes, options: PatchOptions, label: str
) -> bytes | None:
    """Patches friend prices, event-shop genes and event limits in shopdata."""
    import UnityPy

    clear, key, iv = _decrypt_datatable(data)
    env = UnityPy.load(clear)
    changed = 0
    for obj in env.objects:
        if obj.type.name != "MonoBehaviour":
            continue
        tree = obj.read_typetree()
        rows = tree.get("_data") or []
        if not rows:
            continue
        friends_done = _shop_friends_patched(rows)
        campaign_coins_done = _shop_coins_patched(
            rows, 6, SHOP_CAMPAIGN_COIN_SENTINEL_DISCOUNTED
        )
        event_coins_done = _shop_coins_patched(
            rows, 11, SHOP_EVENT_COIN_SENTINEL_DISCOUNTED
        )
        genes_done = _shop_genes_patched(rows)
        limits_done = _shop_contents_limits_patched(rows)
        for row in rows:
            category = row.get("_category")
            if options.campaign_shop_discount and not friends_done:
                friend = int(row.get("_friendPrice", -1))
                if friend > 0:
                    row["_friendPrice"] = _discount_client_price(friend)
                    changed += 1
            coin_discount = bool(
                (
                    options.campaign_shop_discount
                    and category == 6
                    and not campaign_coins_done
                )
                or (
                    options.event_discount
                    and category == 11
                    and not event_coins_done
                )
            )
            if coin_discount:
                coin = int(row.get("_coinPrice", -1))
                if coin > 0:
                    row["_coinPrice"] = _discount_client_price(coin)
                    changed += 1
            if (
                options.event_gene_unlimited
                and not genes_done
                and category == 11
                and int(row.get("_itemCategory", 0)) == 18
                and int(row.get("_purchaselimittype", 255)) != 255
            ):
                row["_purchaselimittype"] = 255
                row["_purchasecountperlimit"] = 255
                changed += 1
            if (
                options.event_limits_daily
                and not limits_done
                and category in (6, 11)
                and int(row.get("_purchaselimittype", -1)) in (3, 4)
            ):
                row["_purchaselimittype"] = 1
                changed += 1
        if changed:
            obj.save_typetree(tree)
    if not changed:
        return None
    new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
    patched = _encrypt_datatable(new_clear, key, iv)
    return patched if patched != data else None


def _patch_resources_zip_file(
    raw_zip: Path,
    options: PatchOptions,
    *,
    work_dir: Path,
    log_fn: Optional[Callable[[str], None]] = None,
) -> tuple[Path, ResourceContract | None]:
    """Patches datatables in assets/fwt_resources_v1.zip using a file-backed rewrite."""
    try:
        import cryptography  # noqa: F401
        import UnityPy
    except ImportError as exc:
        if needs_resource_archive_patch(options):
            raise RuntimeError(
                "Internal datatable asset patching requires 'UnityPy' and "
                "'cryptography', which are missing in this Python environment "
                f"({exc}). Install runtime dependencies or disable asset-backed "
                "patches."
            ) from exc
        if log_fn:
            log_fn(
                "Optional dependencies (UnityPy/cryptography) not available; "
                "skipping internal datatable assets patching."
            )
        return raw_zip, None

    replacements: dict[str, bytes] = {}
    archive_additions: dict[str, bytes] = {}
    failures: list[str] = []
    with zipfile.ZipFile(raw_zip, "r") as archive:
        for info in archive.infolist():
            if (
                options.sacred_lands_restore
                and re.match(
                    r"files/Resources/(?:datatable/)?setitemtable[a-z]*\.unity3d$",
                    info.filename,
                )
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows_changed = _restore_sacred_lands_set_rows(tree)
                        if rows_changed:
                            obj.save_typetree(tree)
                            changed += rows_changed
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                f"Patched {info.filename}: Sacred Lands set grade "
                                f"{SACRED_LANDS_ORIGINAL_GRADE} -> {SACRED_LANDS_ITEM_GRADE} "
                                f"({changed} row(s))"
                            )
                except Exception as exc:
                    failures.append(f"{info.filename}: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch {info.filename}: {exc}")

            elif (
                info.filename == "files/Resources/datatable/equipselectlist.unity3d"
                and options.sacred_lands_restore
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows_changed = _restore_sacred_lands_select_rows(tree)
                        if rows_changed:
                            obj.save_typetree(tree)
                            changed += rows_changed
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                "Patched equipselectlist.unity3d: Sacred Lands added "
                                f"to {changed} set selection list(s)"
                            )
                except Exception as exc:
                    failures.append(f"equipselectlist.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch equipselectlist.unity3d: {exc}")

            elif (
                info.filename in RECYCLE_SIX_STAR_CLIENT_ASSETS
                and options.recycle_six_star
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data", [])
                        by_group = _group_recycle_six_star_rows(rows)
                        object_changed = 0
                        for group, group_rows in by_group.items():
                            targets = recycle_six_star_assignment(
                                [
                                    (
                                        int(row.get("_weightValue", 0)),
                                        int(row.get("_equipCode", 0)),
                                    )
                                    for row in group_rows
                                ],
                                RECYCLE_SIX_STAR_GROUP_SLOT[group],
                            )
                            if all(
                                (
                                    int(row.get("_weightValue", 0)),
                                    int(row.get("_equipCode", 0)),
                                )
                                == target
                                for row, target in zip(
                                    group_rows, targets, strict=True
                                )
                            ):
                                continue
                            for row, (weight, code) in zip(
                                group_rows, targets, strict=True
                            ):
                                row["_weightValue"] = weight
                                row["_equipCode"] = code
                                object_changed += 1
                        if object_changed:
                            changed += object_changed
                            obj.save_typetree(tree)
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                f"Patched {info.filename}: alchemy reward rows -> "
                                f"6-star set pieces ({changed} rows)"
                            )
                except Exception as exc:
                    failures.append(f"{info.filename}: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch {info.filename}: {exc}")

            elif (
                info.filename == "files/Resources/datatable/honorreward.unity3d"
                and options.mode_drops_x10
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name == "MonoBehaviour":
                            tree = obj.read_typetree()
                            for row in tree.get("_data", []):
                                if row.get("_resultType") == 1:
                                    count = int(row.get("_rewardItemCount", 6))
                                    if count == 6:
                                        row["_rewardItemCount"] = 60
                                        changed += 1
                                    elif count != 60:
                                        raise ValueError(
                                            f"unexpected PVP honor reward count: {count}"
                                        )
                            obj.save_typetree(tree)
                    new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                    patched = _encrypt_datatable(new_clear, k, v)
                    if patched != data:
                        replacements[info.filename] = patched
                    if log_fn and changed:
                        log_fn(
                            "Patched honorreward.unity3d: 10x PVP win honor coins (6 -> 60)"
                        )
                except Exception as exc:
                    failures.append(f"honorreward.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch honorreward.unity3d: {exc}")

            elif (
                info.filename in WORLDBOSS_REWARD_CLIENT_ASSETS
                and options.mode_drops_x10
            ):
                label = Path(info.filename).name
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    wb_behaviours: list[tuple[Any, dict[str, Any]]] = []
                    wb_rows: list[dict[str, Any]] = []
                    for obj in env.objects:
                        if obj.type.name == "MonoBehaviour":
                            tree = obj.read_typetree()
                            wb_behaviours.append((obj, tree))
                            wb_rows.extend(tree.get("_data") or [])
                    count, digest = _worldboss_cycle_client_digest(wb_rows)
                    if count != WORLDBOSS_CYCLE_REWARD_TARGET_COUNT:
                        raise ValueError(
                            f"expected {WORLDBOSS_CYCLE_REWARD_TARGET_COUNT} "
                            f"rank/grade rows, got {count}"
                        )
                    if digest == WORLDBOSS_REWARD_CLIENT_PATCHED_SHA256:
                        if log_fn:
                            log_fn(f"Skipped {label}: rank/grade rewards already 10x")
                    elif digest != WORLDBOSS_REWARD_CLIENT_STOCK_SHA256:
                        raise ValueError(
                            f"unexpected World Boss reward rows (sha {digest[:12]})"
                        )
                    else:
                        changed = 0
                        for obj, tree in wb_behaviours:
                            object_changed = 0
                            for row in tree.get("_data") or []:
                                if (
                                    row.get("_rewardType")
                                    not in WORLDBOSS_CYCLE_REWARD_TARGET_TYPES
                                ):
                                    continue
                                res_type = int(row.get("_reward1Type", -1))
                                if res_type == WORLDBOSS_CYCLE_REWARD_GOLD_RES:
                                    row["_reward1Value01"] = (
                                        int(row["_reward1Value01"]) * 10
                                    )
                                    object_changed += 1
                                elif res_type == WORLDBOSS_CYCLE_REWARD_ITEM_RES:
                                    if (
                                        int(row.get("_reward1Value01", -1))
                                        != WORLDBOSS_KRAKEN_SCALE_CODE
                                    ):
                                        raise ValueError(
                                            f"unexpected Kraken item code: {row.get('_reward1Value01')}"
                                        )
                                    row["_reward1Value02"] = (
                                        int(row["_reward1Value02"]) * 10
                                    )
                                    object_changed += 1
                                else:
                                    raise ValueError(
                                        f"unexpected reward resource type: {res_type}"
                                    )
                            if object_changed:
                                changed += object_changed
                                obj.save_typetree(tree)
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn and changed:
                            log_fn(
                                f"Patched {label}: 10x World Boss final rank/grade rewards ({changed} rows)"
                            )
                except Exception as exc:
                    failures.append(f"{label}: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch {label}: {exc}")

            elif (
                info.filename == "files/Resources/datatable/limitbreakcost.unity3d"
                and (
                    options.limit_break_cost_tenth
                    or options.limit_break_cost_fixed
                    or options.limit_break_step_10
                )
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    behaviours: list[tuple[Any, dict[str, Any]]] = []
                    all_rows: list[dict[str, Any]] = []
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        behaviours.append((obj, tree))
                        all_rows.extend(tree.get("_data") or [])
                    if not all_rows:
                        raise ValueError("limitbreakcost.unity3d has no rows")

                    wants_cost = bool(
                        options.limit_break_cost_tenth or options.limit_break_cost_fixed
                    )
                    wants_step = bool(options.limit_break_step_10)
                    needs_cost_patch = False
                    needs_step_patch = False
                    target_profile = ""
                    fixed_target = False
                    divisor = 1

                    if wants_cost:
                        target_profile = _limit_break_target_profile(options)
                        divisor = limit_break_client_divisor(
                            tenth=options.limit_break_cost_tenth,
                        )
                        current_profile, digest = _limit_break_profile_from_rows(all_rows)
                        fixed_target = target_profile == "limit_break_cost_fixed"
                        upgradeable = {"stock"} | (
                            {"limit_break_cost_tenth"} if fixed_target else set()
                        )
                        if current_profile == target_profile:
                            pass
                        elif current_profile not in upgradeable:
                            if current_profile is not None:
                                raise ValueError(
                                    f"limitbreakcost.unity3d already matches "
                                    f"conflicting profile {current_profile!r} "
                                    f"(expected 'stock' or {target_profile!r})"
                                )
                            raise ValueError(
                                f"unexpected limitbreakcost.unity3d table "
                                f"(sha {digest[:12]}; expected 'stock' or {target_profile!r})"
                            )
                        else:
                            needs_cost_patch = True

                    if wants_step:
                        step_profile, step_digest = _limit_break_step_profile_from_rows(
                            all_rows
                        )
                        if step_profile == "limit_break_step_10":
                            pass
                        elif step_profile == "stock":
                            needs_step_patch = True
                        else:
                            raise ValueError(
                                f"unexpected limitbreakcost.unity3d level steps "
                                f"(sha {step_digest[:12]}; expected 'stock' or 'limit_break_step_10')"
                            )

                    if not needs_cost_patch and not needs_step_patch:
                        if log_fn:
                            skip_label = target_profile or "limit_break_step_10"
                            log_fn(
                                "Skipped limitbreakcost.unity3d: client table "
                                f"already matches {skip_label}"
                            )
                    else:
                        for obj, tree in behaviours:
                            for row in tree.get("_data") or []:
                                if needs_cost_patch:
                                    if fixed_target:
                                        row["_cost"] = LIMIT_BREAK_FIXED_GOLD
                                        row["_rewardValue02"] = LIMIT_BREAK_FIXED_MATERIAL
                                    else:
                                        cost = int(row.get("_cost", 0))
                                        if cost <= 0:
                                            raise ValueError(
                                                f"invalid limit break client cost: {cost}"
                                            )
                                        row["_cost"] = cost // divisor
                                        material = int(row.get("_rewardValue02", 0))
                                        if material <= 0:
                                            raise ValueError(
                                                f"invalid limit break client material: {material}"
                                            )
                                        row["_rewardValue02"] = material // divisor
                                if needs_step_patch:
                                    level_before = int(row["_levelBefore"])
                                    row["_levelAfter"] = limit_break_step10_target(
                                        level_before
                                    )
                            obj.save_typetree(tree)
                        if needs_cost_patch:
                            patched_profile, patched_digest = _limit_break_profile_from_rows(
                                all_rows
                            )
                            if patched_profile != target_profile:
                                raise ValueError(
                                    "patched limitbreakcost.unity3d hash mismatch: "
                                    f"{patched_digest[:12]} (expected {target_profile})"
                                )
                        if needs_step_patch:
                            patched_step, patched_step_digest = (
                                _limit_break_step_profile_from_rows(all_rows)
                            )
                            if patched_step != "limit_break_step_10":
                                raise ValueError(
                                    "patched limitbreakcost.unity3d level-step mismatch: "
                                    f"{patched_step_digest[:12]}"
                                )
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                "Patched limitbreakcost.unity3d: client limit-break "
                                "table updated to match server"
                            )
                except Exception as exc:
                    failures.append(f"limitbreakcost.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch limitbreakcost.unity3d: {exc}")

            elif (
                info.filename == "files/Resources/datatable/runeenchant.unity3d"
                and options.rune_upgrade_discount
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data") or []
                        if not any(
                            int(row.get("_baseRuneEnchant", -1)) in (12, 13, 14)
                            for row in rows
                        ):
                            continue
                        count = _patch_rune_upgrade_rows(rows)
                        if count:
                            obj.save_typetree(tree)
                            changed += count
                    if not changed:
                        if log_fn:
                            log_fn(
                                "Skipped runeenchant.unity3d: client rows already "
                                "discounted"
                            )
                    else:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                "Patched runeenchant.unity3d: +12..+15 always "
                                "succeed and cost a tenth"
                            )
                except Exception as exc:
                    failures.append(f"runeenchant.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch runeenchant.unity3d: {exc}")

            elif (
                info.filename == "files/Resources/datatable/crystalskillcost.unity3d"
                and options.crystal_skill_90_off
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        for row in tree.get("_data", []):
                            for field in CRYSTAL_SKILL_COST_FIELDS:
                                cost = int(row.get(field, 0))
                                if cost <= 0:
                                    raise ValueError(
                                        f"invalid crystal skill client cost: {cost}"
                                    )
                                discounted = cost if cost <= 5 else max(1, cost // 10)
                                if discounted != cost:
                                    row[field] = discounted
                                    changed += 1
                        obj.save_typetree(tree)
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                    if log_fn:
                        log_fn(
                            "Patched crystalskillcost.unity3d: crystal skill "
                            f"costs 50 -> 5 Kraken Scales ({changed} field(s))"
                        )
                except Exception as exc:
                    failures.append(f"crystalskillcost.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch crystalskillcost.unity3d: {exc}")

            elif info.filename == RANDOPTION_CLIENT_ASSET_PATH and (
                options.equipment_percent_options
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data") or []
                        delta = _patch_equipment_percent_options_rows(rows)
                        if delta:
                            obj.save_typetree(tree)
                            changed += delta
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                "Patched randoptiontable.unity3d: flat option "
                                f"weights removed ({changed} weight(s))"
                            )
                    elif log_fn:
                        log_fn(
                            "Skipped randoptiontable.unity3d: flat option "
                            "weights already zero"
                        )
                except Exception as exc:
                    failures.append(f"randoptiontable.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch randoptiontable.unity3d: {exc}")

            elif info.filename == RUNE_OPTION_CLIENT_ASSET_PATH and (
                options.rune_quality_factor > 0
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data") or []
                        delta = _patch_rune_option_percent_rows(rows)
                        if delta:
                            obj.save_typetree(tree)
                            changed += delta
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                "Patched runeoption.unity3d: flat option "
                                f"weights removed ({changed} weight(s))"
                            )
                    elif log_fn:
                        log_fn(
                            "Skipped runeoption.unity3d: flat option "
                            "weights already zero"
                        )
                except Exception as exc:
                    failures.append(f"runeoption.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch runeoption.unity3d: {exc}")

            elif info.filename == EQUIP_SUCCESS_CLIENT_ASSET_PATH and (
                options.equipment_upgrade_10_guarantee
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data") or []
                        delta = _patch_equip_success_10_rows(rows)
                        if delta:
                            obj.save_typetree(tree)
                            changed += delta
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")())  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                "Patched equipsuccessprobability.unity3d: "
                                f"+10 upgrade success -> {EQUIP_SUCCESS_10_TARGET} "
                                f"({changed} field(s))"
                            )
                    elif log_fn:
                        log_fn(
                            "Skipped equipsuccessprobability.unity3d: +10 "
                            "success already guaranteed"
                        )
                except Exception as exc:
                    failures.append(f"equipsuccessprobability.unity3d: {exc}")
                    if log_fn:
                        log_fn(
                            f"Failed to patch equipsuccessprobability.unity3d: {exc}"
                        )

            elif info.filename == GUILD_SKILL_DATA_CLIENT_ASSET_PATH and (
                options.guild_raid_fire_support or options.guild_raid_skills_max
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data") or []
                        delta = 0
                        if options.guild_raid_fire_support:
                            delta += patch_guildskilldata_rows(rows)
                        if options.guild_raid_skills_max:
                            delta += patch_guildskilldata_max_rows(rows)
                        if delta:
                            obj.save_typetree(tree)
                            changed += delta
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")(packer="original"))  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                f"Patched guildskilldata.unity3d: {changed} Guild Raid skill effect row(s) updated"
                            )
                    elif log_fn:
                        log_fn(
                            "Skipped guildskilldata.unity3d: requested Guild Raid skill effects already patched"
                        )
                except Exception as exc:
                    failures.append(f"guildskilldata.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch guildskilldata.unity3d: {exc}")

            elif (
                info.filename in GUILD_SKILL_INFO_CLIENT_ASSETS
                and options.guild_raid_skills_max
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data") or []
                        delta = patch_guildskillinfo_max_rows(rows)
                        if delta:
                            obj.save_typetree(tree)
                            changed += delta
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")(packer="original"))  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                f"Patched {Path(info.filename).name}: Absolute Protection gains 100% maxMP restore"
                            )
                    elif log_fn:
                        log_fn(
                            f"Skipped {Path(info.filename).name}: Absolute Protection already includes 100% maxMP restore"
                        )
                except Exception as exc:
                    failures.append(f"{Path(info.filename).name}: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch {Path(info.filename).name}: {exc}")

            elif (
                info.filename == MONSTER_DATA_CLIENT_ASSET_PATH
                and options.guild_raid_boss_no_counter
            ):
                data = archive.read(info.filename)
                try:
                    clear, k, v = _decrypt_datatable(data)
                    env = UnityPy.load(clear)
                    changed = 0
                    for obj in env.objects:
                        if obj.type.name != "MonoBehaviour":
                            continue
                        tree = obj.read_typetree()
                        rows = tree.get("_data") or []
                        delta = patch_monsterdata_boss_car_rows(rows)
                        if delta:
                            obj.save_typetree(tree)
                            changed += delta
                    if changed:
                        new_clear = bytes(getattr(env.file, "save")(packer="original"))  # noqa: B009
                        patched = _encrypt_datatable(new_clear, k, v)
                        if patched != data:
                            replacements[info.filename] = patched
                        if log_fn:
                            log_fn(
                                f"Patched monsterdata.unity3d: {changed} Guild Raid boss row(s) set to 0% counter rate"
                            )
                    elif log_fn:
                        log_fn(
                            "Skipped monsterdata.unity3d: Guild Raid boss counter rates already 0%"
                        )
                except Exception as exc:
                    failures.append(f"monsterdata.unity3d: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch monsterdata.unity3d: {exc}")

            elif re.match(
                r"files/Resources/datatable/shopcontentsdata[a-z]*\.unity3d$",
                info.filename,
            ) and (
                options.event_discount
                or options.event_limits_daily
                or options.campaign_shop_discount
            ):
                data = archive.read(info.filename)
                try:
                    shop_patched = _patch_shop_contents_table(
                        data, options, info.filename
                    )
                    if shop_patched is not None:
                        replacements[info.filename] = shop_patched
                        if log_fn:
                            log_fn(
                                "Patched shopcontentsdata: campaign/event prices "
                                "and daily limits match the server rules"
                            )
                except Exception as exc:
                    failures.append(f"shopcontentsdata: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch shopcontentsdata: {exc}")

            elif re.match(
                r"files/Resources/datatable/shopdata[a-z]*\.unity3d$",
                info.filename,
            ) and (
                options.event_discount
                or options.event_gene_unlimited
                or options.event_limits_daily
                or options.campaign_shop_discount
            ):
                data = archive.read(info.filename)
                try:
                    shop_patched = _patch_shop_data_table(
                        data, options, info.filename
                    )
                    if shop_patched is not None:
                        replacements[info.filename] = shop_patched
                        if log_fn:
                            log_fn(
                                "Patched shopdata: friend prices, event genes and "
                                "event limits match the server rules"
                            )
                except Exception as exc:
                    failures.append(f"shopdata: {exc}")
                    if log_fn:
                        log_fn(f"Failed to patch shopdata: {exc}")

        if options.alex_awakening:
            from core.alex_awakening_assets import _PATH, _patch_gate, prepare_assets

            try:
                alex_assets = prepare_assets(archive)
                alex_assets[_PATH] = _patch_gate(archive.read(_PATH))
                overlap = set(alex_assets) & set(replacements)
                if overlap:
                    raise ValueError(f"Alex resources overlap other patches: {sorted(overlap)}")
                replacements.update(alex_assets)
                if log_fn:
                    log_fn(f"Prepared Alex Awakening in {len(alex_assets)} resource tables")
            except Exception as exc:
                failures.append(f"Alex Awakening resources: {exc}")

        if options.alex_rebalance:
            from core.alex_rebalance import prepare_alex_rebalance_assets

            try:
                rebalance_assets = prepare_alex_rebalance_assets(
                    archive,
                    existing_replacements=replacements,
                )
                if rebalance_assets:
                    replacements.update(rebalance_assets)
                    if log_fn:
                        log_fn(
                            f"Prepared Alex Skill, Passive & Awake Rebalance in {len(rebalance_assets)} resource tables"
                        )
                elif log_fn:
                    log_fn("Skipped Alex Rebalance: target skill and effect tables already updated")
            except Exception as exc:
                failures.append(f"Alex Rebalance resources: {exc}")

        if options.alex_heros_mark:
            from core.alex_heros_mark import prepare_alex_heros_mark_assets

            try:
                mark_replacements, mark_additions = prepare_alex_heros_mark_assets(
                    archive,
                    existing_replacements=replacements,
                )
                if mark_replacements:
                    replacements.update(mark_replacements)
                    if log_fn:
                        log_fn(
                            f"Prepared Alex's Hero's Mark in {len(mark_replacements)} resource tables"
                        )
                elif log_fn:
                    log_fn("Skipped Alex Hero's Mark: all target tables already updated")
                if mark_additions:
                    archive_additions.update(mark_additions)
                    if log_fn:
                        log_fn(f"Alex Hero's Mark icon addition: {list(mark_additions)}")
            except Exception as exc:
                failures.append(f"Alex Hero's Mark resources: {exc}")

    if failures:
        raise RuntimeError(
            "Requested datatable patch(es) failed; refusing to emit a partially "
            "patched resource archive: " + " | ".join(failures)
        )
    if not replacements:
        return raw_zip, None
    patched_path = work_dir / "fwt_resources_patched.zip"
    _rewrite_zip_entries_to_file(raw_zip, replacements, patched_path)
    # Append new archive members (e.g., the Hero's Mark icon) after the rewrite
    # so they are included in the resource contract computation below.
    if archive_additions:
        with zipfile.ZipFile(patched_path, "a") as out:
            for name, data in archive_additions.items():
                out.writestr(name, data, compress_type=zipfile.ZIP_STORED)
    return patched_path, ResourceContract.from_archive_path(patched_path)


def _patch_dev_manifest(
    raw_manifest: bytes,
    options: PatchOptions,
    log: Callable[[str], None],
) -> bytes:
    """Applies the dev-only manifest edits (``-dev`` versionName, debuggable).

    A dev build always gets the ``-dev`` versionName suffix so it is identifiable
    on the device (Settings > Apps) without inspecting the file name.  The
    ``debuggable`` flag is only set when the caller asked for it: it is what makes
    ``adb shell run-as`` and JDWP work without root.
    """
    if options.dev.keep_version:
        # Some builds must stay indistinguishable from the release to the game's own
        # version/anti-tamper checks; the dev identity then comes only from the
        # binary marker (--dev-marker) and the file name.
        patched = raw_manifest
        log("Dev manifest: android:versionName kept as-is (--dev-keep-version)")
    else:
        patched, old_name, new_name = patch_version_name(raw_manifest, DEV_OUTPUT_SUFFIX)
        if new_name != old_name:
            log(f"Dev manifest: android:versionName {old_name} -> {new_name}")
    if options.dev.debuggable:
        already = patch_debuggable(raw_manifest, enabled=True) == raw_manifest
        patched = patch_debuggable(patched, enabled=True)
        log(
            "Dev manifest: android:debuggable=true "
            + ("(already set)" if already else "(run-as/JDWP available without root)")
        )
        log(
            "WARNING: on a real device, debuggable=true made the patched build hang "
            "at the sponsor screen (valofe/vfun) while the same build without it ran "
            "fine; a lab build with no gameplay patches was unaffected. Omit "
            "--dev-debuggable when the build is meant to be played."
        )
    return patched


def needs_resource_archive_patch(options: PatchOptions) -> bool:
    """Return True when any enabled patch modifies ``assets/fwt_resources_v1.zip``."""
    return bool(
        options.mode_drops_x10
        or options.alex_awakening
        or options.alex_rebalance
        or options.alex_heros_mark
        or options.limit_break_cost_tenth
        or options.limit_break_cost_fixed
        or options.limit_break_step_10
        or options.crystal_skill_90_off
        or options.recycle_six_star
        or options.sacred_lands_restore
        or options.event_discount
        or options.event_gene_unlimited
        or options.event_limits_daily
        or options.campaign_shop_discount
        or options.equipment_percent_options
        or options.equipment_upgrade_10_guarantee
        or options.rune_upgrade_discount
        or options.rune_quality_factor > 0
        or options.guild_raid_fire_support
        or options.guild_raid_skills_max
        or options.guild_raid_boss_no_counter
    )


def repack_and_sign_apk(
    input_apk: Path,
    output_apk: Path,
    options: PatchOptions,
    tools: ToolPaths,
    keystore_path: Path,
    log_fn: Optional[Callable[[str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> PatchResult:
    """Patches native SO, DEX, repacks, aligns (16 KB) and signs the output APK."""
    def log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    def check_cancel() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise RuntimeError("Build cancelled by user.")

    check_cancel()

    if not tools.has_packaging_tools:
        raise RuntimeError(describe_missing_packaging_tools(tools))
    zipalign = tools.zipalign
    apksigner = tools.apksigner
    keytool = tools.keytool
    assert zipalign
    assert apksigner
    assert keytool

    input_apk = Path(input_apk)
    output_apk = Path(output_apk)
    if input_apk.resolve() == output_apk.resolve():
        raise ValueError(
            "Input and output APK paths are identical. Refusing to overwrite the base APK."
        )
    if not input_apk.is_file():
        raise FileNotFoundError(f"Base APK not found: {input_apk}")

    input_size = input_apk.stat().st_size
    output_apk.parent.mkdir(parents=True, exist_ok=True)
    free_bytes = shutil.disk_usage(output_apk.parent).free
    # The streaming resource rewrite keeps the raw and patched nested archives
    # on disk alongside the unsigned/aligned/signed APKs.
    required_bytes = int(input_size * 4) + 256 * 1024 * 1024
    if free_bytes < required_bytes:
        raise RuntimeError(
            f"Not enough free disk space in {output_apk.parent}: "
            f"{free_bytes / (1024**3):.1f} GiB available, "
            f"{required_bytes / (1024**3):.1f} GiB required for temporary files."
        )

    log(f"Reading base APK: {input_apk.name} ({input_size / (1024*1024):.1f} MiB)")
    ensure_local_keystore(keystore_path, keytool)

    with tempfile.TemporaryDirectory(dir=str(output_apk.parent), prefix=".fwt_work_") as work_str:
        work_dir = Path(work_str)
        unsigned_apk = work_dir / "unsigned.apk"
        aligned_apk = work_dir / "aligned.apk"
        signed_apk = work_dir / "signed.apk"

        with zipfile.ZipFile(input_apk, "r") as src_zf, zipfile.ZipFile(unsigned_apk, "w") as dst_zf:
            names = set(src_zf.namelist())
            required_entries = {
                "lib/arm64-v8a/libfwt_local_server.so",
                "classes8.dex",
            }
            missing = sorted(required_entries - names)
            if missing:
                raise RuntimeError(
                    "Base APK is missing required entries: " + ", ".join(missing)
                )

            raw_so = src_zf.read("lib/arm64-v8a/libfwt_local_server.so")
            raw_dex = src_zf.read("classes8.dex")
            pristine_input = (
                hashlib.sha256(raw_so).hexdigest() == REFERENCE_SO_SHA256
                and hashlib.sha256(raw_dex).hexdigest() == REFERENCE_DEX_SHA256
            )
            build_identity = "dev" if options.dev.enabled else (
                "release" if pristine_input else "unverified"
            )

            resources_archive: Path | None = None
            resource_contract: ResourceContract | None = None
            if needs_resource_archive_patch(options):
                if "assets/fwt_resources_v1.zip" not in names:
                    raise RuntimeError(
                        "Requested datatable patches require assets/fwt_resources_v1.zip, "
                        "but it is missing from the input APK."
                    )
                else:
                    log("Patching internal datatable assets...")
                    raw_resources_path = work_dir / "fwt_resources_raw.zip"
                    with (
                        src_zf.open("assets/fwt_resources_v1.zip") as source,
                        raw_resources_path.open("wb") as destination,
                    ):
                        shutil.copyfileobj(
                            source, destination, length=8 * 1024 * 1024
                        )
                    patched, contract = _patch_resources_zip_file(
                        raw_resources_path,
                        options,
                        work_dir=work_dir,
                        log_fn=log,
                    )
                    if contract is None:
                        raw_resources_path.unlink(missing_ok=True)
                    else:
                        resources_archive = patched
                        resource_contract = contract
                        raw_resources_path.unlink(missing_ok=True)
                        log(
                            "Resource contract: "
                            f"SHA-256 {contract.sha256_hex[:12]}..., "
                            f"{contract.file_count} files, "
                            f"{contract.uncompressed_bytes} bytes"
                        )

            apktool_jar = None
            if options.english_localization or resource_contract is not None:
                apktool_jar = ensure_apktool_jar(log)

            log("Applying binary bytecode patches to native core and DEX...")
            result = apply_all_patches(
                raw_so,
                raw_dex,
                options,
                resource_contract=resource_contract,
                apktool_jar=apktool_jar,
                log_fn=log,
            )
            log(
                "Patch counts: "
                + ", ".join(f"{name}={count}" for name, count in result.counts.items())
            )
            for warning in result.warnings:
                log(f"WARNING: {warning}")

            manifest_bytes: bytes | None = None
            if options.dev.enabled:
                if "AndroidManifest.xml" not in names:
                    raise RuntimeError(
                        "Dev build requested but the base APK has no AndroidManifest.xml"
                    )
                log("Patching dev manifest (versionName/debuggable)...")
                manifest_bytes = _patch_dev_manifest(
                    src_zf.read("AndroidManifest.xml"), options, log
                )

            entry_count = len(src_zf.infolist())
            log(f"Repacking {entry_count} entries (storing all .so uncompressed for 16 KB paging)...")

            for index, info in enumerate(src_zf.infolist()):
                if index % 256 == 0:
                    check_cancel()
                if is_signature_file(info.filename) or info.filename == BUILD_IDENTITY_ENTRY:
                    continue

                out_info = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
                out_info.create_system = info.create_system
                out_info.external_attr = info.external_attr

                if info.is_dir():
                    dst_zf.writestr(out_info, b"")
                elif info.filename == "AndroidManifest.xml" and manifest_bytes is not None:
                    out_info.compress_type = info.compress_type
                    dst_zf.writestr(out_info, manifest_bytes)
                elif info.filename == "lib/arm64-v8a/libfwt_local_server.so":
                    out_info.compress_type = zipfile.ZIP_STORED
                    dst_zf.writestr(out_info, result.so_bytes)
                elif info.filename.endswith(".so"):
                    # Android 16 requires all .so to be stored uncompressed
                    out_info.compress_type = zipfile.ZIP_STORED
                    dst_zf.writestr(out_info, src_zf.read(info.filename))
                elif info.filename == "classes8.dex":
                    out_info.compress_type = info.compress_type
                    dst_zf.writestr(out_info, result.dex_bytes)
                elif (
                    info.filename == "assets/fwt_resources_v1.zip"
                    and resources_archive is not None
                ):
                    out_info.compress_type = info.compress_type
                    with (
                        resources_archive.open("rb") as rf,
                        dst_zf.open(out_info, "w") as df,
                    ):
                        shutil.copyfileobj(rf, df, length=8 * 1024 * 1024)
                else:
                    out_info.compress_type = info.compress_type
                    with src_zf.open(info, "r") as sf, dst_zf.open(out_info, "w") as df:
                        shutil.copyfileobj(sf, df, length=8 * 1024 * 1024)

            identity_info = zipfile.ZipInfo(BUILD_IDENTITY_ENTRY, date_time=(1980, 1, 1, 0, 0, 0))
            identity_payload = {"identity": build_identity, "options": asdict(options)}
            dst_zf.writestr(
                identity_info, json.dumps(identity_payload, sort_keys=True, separators=(",", ":"))
            )

        check_cancel()
        # 2. Zipalign (16 KB page-alignment for Android 16)
        if options.align_16k:
            log("Aligning APK with zipalign (-f 16384 for 16 KB kernel paging)...")
            zipalign_args = [zipalign, "-f", "16384", str(unsigned_apk), str(aligned_apk)]
        else:
            log("Aligning APK with zipalign (-p -f 4)...")
            zipalign_args = [zipalign, "-p", "-f", "4", str(unsigned_apk), str(aligned_apk)]
        _run_tool(zipalign_args, "zipalign", timeout=600)
        unsigned_apk.unlink(missing_ok=True)

        check_cancel()
        # 3. Sign APK with apksigner (v1 + v2; v3 is enabled by default)
        log("Signing APK with apksigner (v1 + v2 signature scheme)...")
        _run_tool(
            [
                apksigner, "sign",
                "--ks", str(keystore_path),
                "--ks-key-alias", _keystore_alias(),
                "--ks-pass", "env:FWT_KEYSTORE_PASS",
                "--key-pass", "env:FWT_KEYSTORE_PASS",
                "--v1-signing-enabled", "true",
                "--v2-signing-enabled", "true",
                "--out", str(signed_apk),
                str(aligned_apk),
            ],
            "apksigner",
            timeout=600,
        )

        check_cancel()
        log("Verifying the signed APK before replacing the previous build...")
        _run_tool(
            [apksigner, "verify", "--print-certs", str(signed_apk)],
            "apksigner verify",
            timeout=600,
        )
        # Atomic replace so a failure never leaves a truncated output APK.  Keep
        # the previous good build as .prev so a failed verification downstream
        # is recoverable.
        if output_apk.exists():
            output_apk.replace(output_apk.with_name(output_apk.name + ".prev"))
        signed_apk.replace(output_apk)

    out_mb = output_apk.stat().st_size / (1024 * 1024)
    log(f"Success! Output APK ready: {output_apk.name} ({out_mb:.1f} MiB)")
    return result


def _validate_save_data(data: object) -> str | None:
    if not isinstance(data, dict) or not data:
        return "Backup is not a savegame object."
    markers = {"lord", "heroes", "equipments", "items", "stage_clear_info"}
    if not markers & data.keys():
        return f"Backup does not look like a FWT savegame (expected one of {sorted(markers)})."
    return None


class AdbHelper:
    """Manages ADB interactions with connected Android devices."""

    def __init__(self, adb_bin: Optional[str] = None):
        self.adb = adb_bin or locate_tools().adb

    def run_cmd(self, args: list[str], timeout: int = 30) -> tuple[int, str, str]:
        if not self.adb:
            return 1, "", "ADB executable not found"
        try:
            res = subprocess.run(
                [self.adb] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
                stdin=subprocess.DEVNULL,
                creationflags=_NO_WINDOW,
            )
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except subprocess.TimeoutExpired:
            return 1, "", f"ADB command timed out after {timeout}s"
        except Exception as exc:
            return 1, "", str(exc)

    def list_devices(self) -> list[dict[str, str]]:
        """Returns connected devices, including unauthorized/offline states."""
        code, out, err = self.run_cmd(["devices", "-l"])
        if code != 0:
            return []

        devices = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            state = parts[1]
            # "no permissions (user in plugdev group...)" is a single state
            # token followed by a reason; keep it visible to the caller.
            if state == "no":
                state = "no permissions"
            elif state not in {
                "device",
                "offline",
                "unauthorized",
                "recovery",
                "sideload",
                "bootloader",
            }:
                state = "unknown"
            dev_id = parts[0]
            model = ""
            for p in parts[2:]:
                if p.startswith("model:"):
                    model = p.split(":", 1)[1]
                    break
            devices.append({
                "id": dev_id,
                "model": model or "Android Device",
                "state": state,
                "label": f"{dev_id} ({model or 'Device'}, {state})",
                "error": err,
            })
        return devices

    def connect(self, ip_port: str) -> tuple[bool, str]:
        """Connects to a Wi-Fi ADB target (e.g. 192.0.2.10:5555)."""
        target = ip_port.strip()
        if not target:
            return False, "Target IP:Port cannot be empty"
        if ":" not in target:
            target += ":5555"
        code, out, err = self.run_cmd(["connect", target], timeout=10)
        msg = out or err
        if "connected to" in msg.lower():
            return True, msg
        return False, msg

    def wait_for_device(self, device_id: str, timeout: int = 30) -> bool:
        """Waits until the device finishes reconnecting (e.g. after adb root)."""
        code, _out, _err = self.run_cmd(["-s", device_id, "wait-for-device"], timeout=timeout)
        return code == 0

    def _is_shell_root(self, device_id: str) -> bool:
        code, out, _err = self.run_cmd(["-s", device_id, "shell", "id"], timeout=10)
        return code == 0 and "uid=0" in out

    def ensure_root(self, device_id: str) -> bool:
        """Attempts adb root and confirms that the shell really is uid 0."""
        self.run_cmd(["-s", device_id, "root"], timeout=15)
        self.wait_for_device(device_id, timeout=30)
        return self._is_shell_root(device_id)

    def _has_su_root(self, device_id: str) -> bool:
        """Return True when ``su`` is available and yields uid 0."""
        code, out, _err = self.run_cmd(
            ["-s", device_id, "shell", "su -c id"], timeout=10
        )
        return code == 0 and "uid=0" in out

    def package_state(self, device_id: str) -> str:
        """Returns ``installed``, ``not_installed`` or ``unknown``.

        Treating an adb/offline failure as "not installed" silently disables
        the pre-install save backup, so the three states are kept distinct.
        """
        code, out, err = self.run_cmd(
            ["-s", device_id, "shell", "pm", "path", PACKAGE_NAME], timeout=15
        )
        if code == 0:
            return "installed" if out.startswith("package:") else "not_installed"
        if code != 0 and not err:
            return "unknown"
        return "unknown"

    def is_package_installed(self, device_id: str) -> bool:
        """Backwards-compatible boolean wrapper around package_state()."""
        return self.package_state(device_id) == "installed"

    def uninstall_apk(self, device_id: str) -> tuple[bool, str]:
        """Uninstalls the package. This deletes app data; back up the save first."""
        code, out, err = self.run_cmd(
            ["-s", device_id, "uninstall", PACKAGE_NAME], timeout=60
        )
        combined = (out + "\n" + err).strip()
        if code == 0 and ("Success" in combined or "not installed" in combined.lower()):
            return True, combined or "Package uninstalled."
        return False, combined or "Uninstall failed."

    def backup_save(self, device_id: str, output_path: Path) -> tuple[bool, str]:
        """Pulls single-player save JSON from connected device into output_path.

        The original APK is not debuggable, so run-as only works if the
        installed package is debuggable. In practice this requires root/an
        emulator; the error message says so explicitly.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        partial = output_path.with_name(output_path.name + ".part")
        partial.unlink(missing_ok=True)
        errors: list[str] = []
        root_ok = False

        def accept(
            path: Path, message: str, success_msg: str | None = None
        ) -> tuple[bool, str] | None:
            if not path.is_file() or path.stat().st_size == 0:
                return None
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig"))
            except Exception as exc:
                path.unlink(missing_ok=True)
                errors.append(f"{message} returned invalid JSON: {exc}")
                return None
            validation_error = _validate_save_data(data)
            if validation_error:
                path.unlink(missing_ok=True)
                errors.append(f"{message}: {validation_error}")
                return None
            path.replace(output_path)
            size = output_path.stat().st_size
            msg = (
                success_msg.format(size=size)
                if success_msg is not None
                else f"Save successfully backed up ({size:,} bytes)"
            )
            return True, msg

        def try_pull(
            remote_path: str,
            label: str,
            fallback_err: str,
            *,
            success_msg: str | None = None,
        ) -> tuple[bool, str] | None:
            code, out, err = self.run_cmd(
                ["-s", device_id, "pull", remote_path, str(partial)], timeout=30
            )
            if code == 0:
                accepted = accept(partial, label, success_msg)
                if accepted is not None:
                    return accepted
            partial.unlink(missing_ok=True)
            if code != 0:
                errors.append(f"{label}: {err or out or fallback_err}")
            return None

        def try_shell_cat(
            shell_cmd: str, label: str, fallback_err: str
        ) -> tuple[bool, str] | None:
            code, out, err = self.run_cmd(
                ["-s", device_id, "shell", shell_cmd], timeout=30
            )
            cleaned = out.lstrip("\ufeff") if out else ""
            if code == 0 and cleaned.startswith("{"):
                try:
                    json.loads(cleaned)
                except Exception as exc:
                    errors.append(f"{label} output returned invalid JSON: {exc}")
                    partial.unlink(missing_ok=True)
                    return None
                partial.write_text(cleaned, encoding="utf-8")
                accepted = accept(
                    partial,
                    label,
                    f"Save backed up via {label} ({{size:,}} bytes)",
                )
                if accepted is not None:
                    return accepted
            else:
                errors.append(f"{label}: {err or out or fallback_err}")
            partial.unlink(missing_ok=True)
            return None

        # 1. Direct adb pull from private sandbox (avoids dropping TCP via `adb root`
        #    when adbd already has permission).
        result = try_pull(REMOTE_SAVE_PATH, "adb pull", "permission denied")
        if result is not None:
            return result

        # 2. Switch adbd to root and retry pulling the live private save before
        #    shell fallbacks or shared-storage backups that may be stale.
        root_ok = self.ensure_root(device_id)
        if root_ok:
            result = try_pull(
                REMOTE_SAVE_PATH, "adb pull (after root)", "permission denied"
            )
            if result is not None:
                return result

        # 3. Fallback: su -c cat on live private sandbox
        result = try_shell_cat(
            f"su -c 'cat {REMOTE_SAVE_PATH}'", "su", "root unavailable"
        )
        if result is not None:
            return result

        # 4. Fallback: run-as on live private sandbox (only if APK is debuggable)
        result = try_shell_cat(
            f"run-as {PACKAGE_NAME} cat files/fwt/fwt_server_state_v1.json",
            "run-as",
            "package is not debuggable",
        )
        if result is not None:
            return result

        # 5. Last resort: game-generated copy on shared storage (may lag behind
        #    the live private save).
        result = try_pull(
            EXTERNAL_SAVE_BACKUP,
            "external copy",
            "not found",
            success_msg=(
                f"Save backed up from {EXTERNAL_SAVE_BACKUP} "
                "({size:,} bytes; game-generated copy)"
            ),
        )
        if result is not None:
            return result

        partial.unlink(missing_ok=True)

        hint = (
            " Root is available."
            if root_ok
            else " Backup requires root/an emulator: the original APK is debuggable=false, "
            "so run-as cannot read its private data."
        )
        return False, (
            f"Could not pull savegame from {REMOTE_SAVE_PATH}."
            + hint
            + " Details: "
            + " | ".join(errors)
        )

    def restore_save(self, device_id: str, backup_path: Path) -> tuple[bool, str]:
        """Restores a JSON save on a rooted device (best effort).

        Android's app-private data is only writable as root. This method pushes
        the JSON to /data/local/tmp and copies it into the app data directory
        with the package's uid/gid. It is intentionally conservative and
        returns a clear error when root is unavailable.
        """
        backup_path = Path(backup_path)
        if not backup_path.is_file():
            return False, f"Backup file not found: {backup_path}"
        try:
            data = json.loads(backup_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            return False, f"Backup is not valid JSON: {exc}"
        validation_error = _validate_save_data(data)
        if validation_error:
            return False, validation_error
        package_state = self.package_state(device_id)
        if package_state == "unknown":
            return False, (
                "Could not determine whether the package is installed "
                "(adb/device error); refusing to restore."
            )
        if package_state == "not_installed":
            return False, f"{PACKAGE_NAME} is not installed; install the APK before restoring."
        if not (self.ensure_root(device_id) or self._has_su_root(device_id)):
            return False, (
                "Restore requires root. The app is not debuggable, so run-as cannot write "
                "to /data/data. Restore the JSON manually on a rooted device."
            )

        # A randomized name avoids the world-writable /data/local/tmp symlink
        # attack and concurrent-run collisions.
        remote_tmp = f"/data/local/tmp/fwt_restore_{secrets.token_hex(8)}.json"
        code, out, err = self.run_cmd(
            ["-s", device_id, "push", str(backup_path), remote_tmp], timeout=60
        )
        if code != 0:
            return False, f"Could not push backup to device: {err or out}"
        remote_cmd = (
            "set -e; "
            "mkdir -p /data/data/com.nexon.fwar/files/fwt; "
            f"if [ -f {REMOTE_SAVE_PATH} ]; then "
            f"cp -p {REMOTE_SAVE_PATH} {REMOTE_SAVE_PATH}.bak.$(date +%s); fi; "
            f"cp {remote_tmp} {REMOTE_SAVE_PATH}; "
            f"cmp -s {remote_tmp} {REMOTE_SAVE_PATH}; "
            f"chown $(stat -c %u:%g /data/data/com.nexon.fwar) {REMOTE_SAVE_PATH}; "
            f"chmod 600 {REMOTE_SAVE_PATH}; "
            f"restorecon {REMOTE_SAVE_PATH} 2>/dev/null || true"
        )
        if self._is_shell_root(device_id):
            # adbd itself is root (common on emulators like MuMu), so no su
            # binary is needed.
            code, out, err = self.run_cmd(
                ["-s", device_id, "shell", remote_cmd], timeout=30
            )
        else:
            code, out, err = self.run_cmd(
                ["-s", device_id, "shell", f"su -c '{remote_cmd}'"], timeout=30
            )
        self.run_cmd(["-s", device_id, "shell", f"rm -f {remote_tmp}"], timeout=10)
        if code != 0:
            return False, f"Could not restore save: {err or out}"
        return True, f"Save restored to {REMOTE_SAVE_PATH}."

    def install_apk(
        self,
        device_id: str,
        apk_path: Path,
        log_fn: Optional[Callable[[str], None]] = None,
        *,
        allow_downgrade: bool = False,
    ) -> tuple[bool, str]:
        """Installs the APK on the device using adb install -r."""
        def log(msg: str) -> None:
            if log_fn:
                log_fn(msg)

        apk_path = Path(apk_path)
        if not apk_path.is_file():
            return False, f"APK file not found: {apk_path}"

        log(f"Installing {apk_path.name} to device {device_id}...")
        log("This may take 30-120 seconds for a ~1 GB package...")

        command = ["-s", device_id, "install", "-r"]
        if allow_downgrade:
            command.append("-d")
        command.append(str(apk_path))
        code, out, err = self.run_cmd(command, timeout=1200)
        combined = (out + "\n" + err).strip()
        if code == 0 and "Success" in combined:
            log("Installation completed successfully!")
            return True, "Installation successful!"
        if "timed out" in combined.lower():
            return False, (
                "Installation timed out; its result is unknown. The existing package "
                "may still be installed. Verify the device before retrying."
            )
        hint = ""
        if (
            "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in combined
            or "signatures do not match" in combined.lower()
        ):
            hint = (
                "\n\nThe installed app is signed with a different key. Back up the save, "
                f"uninstall {PACKAGE_NAME} (this deletes app data), then install again. "
                "Keep keystore/fwt_reborn_lan.jks so future updates use the same key."
            )
        log(f"Installation failed: {combined}")
        return False, f"Installation failed: {combined}{hint}"
