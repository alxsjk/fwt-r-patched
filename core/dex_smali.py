#!/usr/bin/env python3
"""Safe DEX bootstrap editing through apktool/smali.

The 0.682 bootstrap keeps its UI strings hard-coded in
``FwtResourceBootstrapActivity``.  Rewriting the strings in place is not safe:
the DEX string table must remain lexicographically sorted, and ART aborts the
process when it is not.  This module therefore decodes ``classes8.dex`` with
apktool, applies the changes to the smali sources, and reassembles it, letting
smali rebuild a correctly sorted string table.

The same pass updates the bundled-resource contract (archive SHA-256, file
count and uncompressed size) when the internal ``fwt_resources_v1.zip`` is
patched.  Without that update a fresh install rejects the modified archive as
"resource size exceeds the expected limit".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]

APKTOOL_VERSION = "3.0.3"
APKTOOL_URL = (
    "https://github.com/iBotPeaches/Apktool/releases/download/"
    f"v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"
)
APKTOOL_SHA256 = "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"

# Contract embedded in the unmodified 0.682 v1574 bootstrap.
REFERENCE_RESOURCE_SHA256 = (
    "A687D7C576D98EFED71AA3748B8FDB96F28AF70B4E6777719E1474FA0B3C7BBD"
)
REFERENCE_RESOURCE_FILE_COUNT = 8697
REFERENCE_RESOURCE_UNCOMPRESSED_BYTES = 870464600
# The bootstrap independently hashes these critical datatables after
# extraction. Any patch that changes one of them must update the matching
# constant in the DEX as well.
REFERENCE_CRITICAL_FILE_HASHES = {
    "Resources/datatable/regiondata.unity3d": (
        "C83C4DAC5EC739577FD6E52F3A4FC51CB21CD8B4A9E5EFA0C48AC3D32DBB968B"
    ),
    "Resources/datatable/dungeondata.unity3d": (
        "E9C64A4275F8044B4EFECD4BFDBAE919CD0D31CA44272BE55C11961FE4729C98"
    ),
    "Resources/datatable/equipselectlist.unity3d": (
        "A6AE382943B1786F2CB469FC82FA2BC9A01786D5FC08B67DD6765312B936C36E"
    ),
}

BOOTSTRAP_FILE_GLOB = "FwtResourceBootstrapActivity*.smali"
SMALI_CONST_STRING_RE = re.compile(
    r'(const-string(?:/jumbo)?\s+\S+,\s+)("(?:[^"\\]|\\.)*")'
)
SAVECOPY_METHOD_RE = re.compile(
    r"(?ms)^\.method private static saveCopy"
    r"\(Ljava/lang/String;Ljava/lang/String;\)Ljava/lang/String;\n"
    r".*?^\.end method\n?"
)
SAVECOPY_METHOD = """\
.method private static saveCopy(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    return-object p1
.end method
"""

# All hard-coded Korean strings in FwtResourceBootstrapActivity and its inner
# classes.  Values match the English client localization.
BOOTSTRAP_TEXT: dict[str, str] = {
    "내장 리소스를 확인하는 중입니다…": "Checking game resources...",
    "최초 실행에만 시간이 걸립니다. 앱을 종료하지 마세요.": (
        "First-time setup may take a while. Please keep this app open."
    ),
    "판타지워택틱스R 오프라인 리소스 준비": "Preparing Fantasy War Tactics R",
    "다시 시도": "Retry",
    "리소스를 설치하는 중입니다…": "Installing game resources...",
    "%,d / %,d개 · %.1f / %.1f MiB\n%s": "%,d / %,d files · %.1f / %.1f MiB\n%s",
    "게임을 시작합니다…": "Starting game...",
    "새 기기의 세이브 데이터 사용 방법을 선택해 주세요.": (
        "Choose how to use save data on this device."
    ),
    "리소스 준비에 실패했습니다.": "Could not prepare game resources.",
    "\n저장 공간을 확인한 뒤 다시 시도해 주세요.": (
        "\nCheck available storage and try again."
    ),
    "리소스 저장 경로를 만들 수 없습니다.": (
        "Could not create the resource storage directory."
    ),
    "설치 완료 검증을 통과하지 못했습니다.": "Resource installation verification failed.",
    "앱 전용 외부 저장소를 사용할 수 없습니다.": "App storage is unavailable.",
    "구버전 리소스 완료표시를 정리할 수 없습니다: ": (
        "Could not remove an old resource marker: "
    ),
    "이전 쿠쿠상자 임시 파일을 지울 수 없습니다.": (
        "Could not remove a temporary resource file."
    ),
    "쿠쿠상자 패치 크기가 계약을 초과했습니다.": (
        "A resource patch exceeds its expected size."
    ),
    "기존 쿠쿠상자 리소스를 교체할 수 없습니다.": (
        "Could not replace an existing resource."
    ),
    "쿠쿠상자 리소스를 확정할 수 없습니다.": "Could not finalize a resource.",
    "쿠쿠상자 패치 검증에 실패했습니다.": "Resource patch verification failed.",
    "쿠쿠상자 리소스 폴더를 만들 수 없습니다.": "Could not create a resource folder.",
    "이전 임시 파일을 지울 수 없습니다: ": "Could not remove a temporary file: ",
    "내장 리소스 크기가 계약을 초과했습니다.": (
        "Resource size exceeds the expected limit."
    ),
    "리소스 크기 불일치: ": "Resource size mismatch: ",
    "기존 리소스를 교체할 수 없습니다: ": "Could not replace a resource: ",
    "리소스를 확정할 수 없습니다: ": "Could not finalize a resource: ",
    "리소스 폴더를 만들 수 없습니다: ": "Could not create a resource folder: ",
    "리소스 경로가 설치 범위를 벗어났습니다: ": (
        "Resource path is outside the installation directory: "
    ),
    "허용되지 않은 리소스 항목: ": "Invalid resource entry: ",
    "필수 리소스가 없습니다: ": "Required resource is missing: ",
    "내장 리소스 계약 불일치: files=": "Resource count or size mismatch: files=",
    "완료표시가 비정상적으로 큽니다.": "Resource marker is unexpectedly large.",
    "설치 범위를 벗어난 경로: ": "Path is outside the installation directory: ",
    "허용되지 않은 상대 경로: ": "Invalid relative path: ",
    "SHA-256 검증을 사용할 수 없습니다.": "SHA-256 verification is unavailable.",
    "이전 완료표시 임시 파일을 지울 수 없습니다.": (
        "Could not remove the temporary resource marker."
    ),
    "이전 완료표시를 교체할 수 없습니다.": "Could not replace the resource marker.",
    "완료표시를 확정할 수 없습니다.": "Could not finalize the resource marker.",
    # Additional strings that only appear in the offline bootstrap (the
    # reference lab client inherits them from the original APK).
    "리소스 준비가 완료되었습니다.": "Game resources ready.",
    "세이브 데이터": "Save Data",
    (
        "Download/fwt에 다른 기기나 PC에서 복사한 백업은 Android 저장소 보호 정책에 따라 "
        "최초 한 번 직접 선택해야 합니다."
    ): (
        "A backup copied from another device or PC to Download/fwt must be selected "
        "once because of Android storage protection."
    ),
    "백업 불러오기": "Load Backup",
    "새 게임": "New Game",
    "세이브 백업을 복원했습니다.": "Save backup restored.",
    "세이브 백업을 불러올 수 없습니다": "Could not load the save backup",
    (
        "fwt_server_state_v1.json 또는 Android가 만든 fwt_server_state_v1 (숫자).json "
        "형식의 유효한 FWT 백업을 선택해 주세요."
    ): (
        "Please select a valid FWT backup named fwt_server_state_v1.json or "
        "fwt_server_state_v1 (number).json."
    ),
    "다시 선택": "Choose Again",
    "시스템 파일 선택기를 열 수 없습니다.": "Could not open the system file picker.",
}


@dataclass(frozen=True)
class BootstrapChanges:
    """Number of translation and resource-contract edits applied to smali."""

    translation: int = 0
    contract: int = 0


@dataclass(frozen=True)
class ResourceContract:
    """Integrity values the bootstrap expects for ``fwt_resources_v1.zip``."""

    sha256_hex: str
    file_count: int
    uncompressed_bytes: int
    critical_hashes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        sha = self.sha256_hex.strip().upper()
        if len(sha) != 64 or any(ch not in "0123456789ABCDEF" for ch in sha):
            raise ValueError(f"Invalid resource archive SHA-256: {self.sha256_hex!r}")
        if self.file_count < 0 or self.uncompressed_bytes < 0:
            raise ValueError("Resource contract values cannot be negative")
        object.__setattr__(self, "sha256_hex", sha)
        normalized: list[tuple[str, str]] = []
        for path, value in self.critical_hashes:
            digest = value.strip().upper()
            if len(digest) != 64 or any(ch not in "0123456789ABCDEF" for ch in digest):
                raise ValueError(f"Invalid critical file SHA-256 for {path!r}")
            normalized.append((path, digest))
        object.__setattr__(self, "critical_hashes", tuple(normalized))

    @classmethod
    def from_archive(cls, raw_zip: bytes | bytearray) -> ResourceContract:
        """Computes the contract from the final (already patched) archive bytes."""
        import io

        with zipfile.ZipFile(io.BytesIO(raw_zip), "r") as archive:
            infos = archive.infolist()
            critical: list[tuple[str, str]] = []
            for relative_path in REFERENCE_CRITICAL_FILE_HASHES:
                entry_name = f"files/{relative_path}"
                try:
                    content = archive.read(entry_name)
                except KeyError:
                    continue
                critical.append(
                    (relative_path, hashlib.sha256(content).hexdigest().upper())
                )
        return cls(
            sha256_hex=hashlib.sha256(raw_zip).hexdigest(),
            file_count=len(infos),
            uncompressed_bytes=sum(info.file_size for info in infos),
            critical_hashes=tuple(critical),
        )

    @classmethod
    def from_archive_path(cls, path: Path) -> ResourceContract:
        """Computes the contract from a file without loading the archive in RAM."""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            critical: list[tuple[str, str]] = []
            for relative_path in REFERENCE_CRITICAL_FILE_HASHES:
                entry_name = f"files/{relative_path}"
                try:
                    content = archive.read(entry_name)
                except KeyError:
                    continue
                critical.append(
                    (relative_path, hashlib.sha256(content).hexdigest().upper())
                )
        return cls(
            sha256_hex=digest.hexdigest(),
            file_count=len(infos),
            uncompressed_bytes=sum(info.file_size for info in infos),
            critical_hashes=tuple(critical),
        )


def _cache_root() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
    else:
        base = os.environ.get("XDG_CACHE_HOME")
        root = Path(base) if base else Path.home() / ".cache"
    return root / "fwt-re-patched" / "tools"


def find_apktool_jar() -> Optional[Path]:
    """Finds apktool without downloading it."""
    candidates: list[Path] = []
    env_path = os.environ.get("FWT_APKTOOL_JAR")
    if env_path:
        candidates.append(Path(env_path).expanduser())
    candidates.extend(
        [
            PROJECT_ROOT / "tools" / "apktool.jar",
            _cache_root() / f"apktool_{APKTOOL_VERSION}.jar",
            _cache_root() / "apktool.jar",
        ]
    )
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            # A sandboxed/ACL-restricted cache path must not abort the whole
            # build; continue looking and let the caller decide whether to
            # download or skip.
            continue
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_apktool_jar(log_fn: Optional[Callable[[str], None]] = None) -> Path:
    """Returns an apktool jar, downloading the pinned release on first use."""
    expected_sha = APKTOOL_SHA256.lower()
    env_path = os.environ.get("FWT_APKTOOL_JAR")
    if env_path:
        explicit = Path(env_path).expanduser()
        if not explicit.is_file():
            raise RuntimeError(f"Configured FWT_APKTOOL_JAR does not exist: {explicit}")
        digest = _sha256_file(explicit).lower()
        if digest != expected_sha:
            raise RuntimeError(
                f"Configured FWT_APKTOOL_JAR at {explicit} has unexpected SHA-256 "
                f"{digest} (expected {APKTOOL_SHA256})"
            )
        return explicit

    candidates = [
        PROJECT_ROOT / "tools" / "apktool.jar",
        _cache_root() / f"apktool_{APKTOOL_VERSION}.jar",
        _cache_root() / "apktool.jar",
    ]
    for existing in candidates:
        try:
            if not existing.is_file():
                continue
        except OSError:
            continue
        digest = _sha256_file(existing).lower()
        if digest == expected_sha:
            return existing
        if existing.parent == _cache_root():
            if log_fn:
                log_fn(f"Cached apktool is corrupt ({digest}); re-downloading")
            existing.unlink()
        elif log_fn:
            log_fn(
                f"Skipping {existing} (SHA-256 {digest} does not match pinned "
                f"{APKTOOL_SHA256})"
            )

    destination = _cache_root() / f"apktool_{APKTOOL_VERSION}.jar"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if log_fn:
        log_fn(f"Downloading apktool {APKTOOL_VERSION} (one-time setup)...")
    request = urllib.request.Request(APKTOOL_URL, headers={"User-Agent": "fwt-re-patched"})
    temporary = destination.with_suffix(".tmp")
    try:
        with urllib.request.urlopen(request, timeout=180) as response, temporary.open("wb") as out:
            shutil.copyfileobj(response, out)
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        if digest != APKTOOL_SHA256:
            raise RuntimeError(
                f"Downloaded apktool has unexpected SHA-256 {digest} "
                f"(expected {APKTOOL_SHA256})"
            )
        temporary.replace(destination)
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError(
            f"Could not download apktool. Install apktool {APKTOOL_VERSION} and set "
            f"FWT_APKTOOL_JAR, or allow access to {APKTOOL_URL}. Error: {exc}"
        ) from exc
    if log_fn:
        log_fn(f"apktool ready at {destination}")
    return destination


def find_java_executable() -> Optional[Path]:
    """Finds the Java runtime executable without failing when absent."""
    java = shutil.which("java")
    if java:
        return Path(java)
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if candidate.is_file():
            return candidate
    return None


def _java_executable() -> str:
    java = find_java_executable()
    if java is not None:
        return str(java)
    raise RuntimeError(
        "Java runtime not found. Install a JRE/JDK or set JAVA_HOME before building."
    )


def _run_apktool(jar: Path, args: list[str], description: str) -> None:
    command = [_java_executable(), "-jar", str(jar), *args]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{description} timed out after 600s") from exc
    except OSError as exc:
        raise RuntimeError(f"{description} could not be started: {exc}") from exc
    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(
            f"{description} failed (exit {result.returncode})"
            + (f":\n{details}" if details else "")
        )


def _replace_smali_strings(
    text: str,
    replacements: dict[str, str],
) -> tuple[str, dict[str, int]]:
    counts = dict.fromkeys(replacements, 0)

    def replace(match: re.Match[str]) -> str:
        try:
            value = json.loads(match.group(2))
        except json.JSONDecodeError:
            return match.group(0)
        if value not in replacements:
            return match.group(0)
        counts[value] += 1
        translated = json.dumps(replacements[value], ensure_ascii=True)
        return match.group(1) + translated

    return SMALI_CONST_STRING_RE.sub(replace, text), counts


def _replace_const_wide_literal(text: str, old_hex: str, value: int) -> str:
    """Replaces a const-wide literal, upgrading /16 to /32 when necessary."""
    pattern = re.compile(
        rf"const-wide/(16|32)(\s+\S+,\s*){re.escape(old_hex)}\b"
    )

    def replace(match: re.Match[str]) -> str:
        prefix = f"const-wide/{'16' if value <= 0x7FFF else '32'}"
        return f"{prefix}{match.group(2)}0x{value:x}"

    text = pattern.sub(replace, text)
    # Static final field initializers keep their long suffix.
    text = re.sub(
        rf"\b{re.escape(old_hex)}L\b",
        f"0x{value:x}L",
        text,
    )
    return text


def _patch_resource_contract(text: str, contract: ResourceContract) -> tuple[str, int]:
    """Updates all archive integrity constants in one smali file."""
    changed = 0
    old_sha = REFERENCE_RESOURCE_SHA256
    if old_sha in text:
        count = text.count(old_sha)
        text = text.replace(old_sha, contract.sha256_hex)
        changed += count

    old_files = f"files={REFERENCE_RESOURCE_FILE_COUNT}"
    if old_files in text:
        count = text.count(old_files)
        text = text.replace(
            old_files, f"files={contract.file_count}"
        )
        changed += count

    old_bytes = f"bytes={REFERENCE_RESOURCE_UNCOMPRESSED_BYTES}"
    if old_bytes in text:
        count = text.count(old_bytes)
        text = text.replace(
            old_bytes, f"bytes={contract.uncompressed_bytes}"
        )
        changed += count

    before = text
    text = _replace_const_wide_literal(text, "0x21f9", contract.file_count)
    text = _replace_const_wide_literal(text, "0x33e23c58", contract.uncompressed_bytes)
    if text != before:
        changed += 1

    for relative_path, new_sha in contract.critical_hashes:
        reference_sha = REFERENCE_CRITICAL_FILE_HASHES.get(relative_path)
        if not reference_sha or new_sha == reference_sha:
            continue
        if reference_sha in text:
            count = text.count(reference_sha)
            text = text.replace(reference_sha, new_sha)
            changed += count
    return text, changed


def _assert_no_bootstrap_hangul(files: list[Path]) -> None:
    remaining: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for match in SMALI_CONST_STRING_RE.finditer(text):
            try:
                value = json.loads(match.group(2))
            except json.JSONDecodeError:
                continue
            if re.search(r"[\uac00-\ud7a3]", value):
                remaining.append(value)
    if remaining:
        unique = list(dict.fromkeys(remaining))
        preview = ", ".join(repr(item) for item in unique[:5])
        raise ValueError(
            f"Untranslated Korean bootstrap string(s) remain ({len(unique)}): {preview}"
        )


def patch_bootstrap_smali_directory(
    directory: Path,
    *,
    translate: bool,
    contract: Optional[ResourceContract],
) -> BootstrapChanges:
    """Edits the decoded bootstrap smali files and returns per-category counts."""
    files = sorted(directory.glob(BOOTSTRAP_FILE_GLOB))
    main_file = directory / "FwtResourceBootstrapActivity.smali"
    if main_file not in files:
        raise ValueError(
            f"Bootstrap smali not found under {directory}; the input DEX is not the "
            "supported 0.682 v1574 build"
        )

    translation_changes = 0
    contract_changes = 0
    found: dict[str, int] = {}
    for path in files:
        text = path.read_text(encoding="utf-8")
        if translate:
            text, counts = _replace_smali_strings(text, BOOTSTRAP_TEXT)
            for key, count in counts.items():
                found[key] = found.get(key, 0) + count
                translation_changes += count
        if contract is not None:
            text, file_contract_changes = _patch_resource_contract(text, contract)
            contract_changes += file_contract_changes
        path.write_text(text, encoding="utf-8")

    if translate:
        missing = [key for key in BOOTSTRAP_TEXT if not found.get(key)]
        if missing:
            preview = ", ".join(repr(item) for item in missing[:5])
            raise ValueError(
                f"Missing expected bootstrap string(s) ({len(missing)}): {preview}"
            )

        text = main_file.read_text(encoding="utf-8")
        patched, replacements = SAVECOPY_METHOD_RE.subn(SAVECOPY_METHOD, text, count=1)
        if replacements != 1:
            raise ValueError("Could not locate the bootstrap saveCopy() method")
        main_file.write_text(patched, encoding="utf-8")
        translation_changes += 1
        _assert_no_bootstrap_hangul(files)

    if contract is not None:
        expected_sha = contract.sha256_hex
        expected_files = f"files={contract.file_count}"
        expected_bytes = f"bytes={contract.uncompressed_bytes}"
        for path in files:
            text = path.read_text(encoding="utf-8")
            if expected_sha != REFERENCE_RESOURCE_SHA256 and REFERENCE_RESOURCE_SHA256 in text:
                raise ValueError(
                    f"Resource SHA-256 was not fully updated in {path.name}"
                )
            if (
                contract.file_count != REFERENCE_RESOURCE_FILE_COUNT
                and f"files={REFERENCE_RESOURCE_FILE_COUNT}" in text
            ):
                raise ValueError(
                    f"Resource file count was not fully updated in {path.name}"
                )
            if (
                contract.uncompressed_bytes != REFERENCE_RESOURCE_UNCOMPRESSED_BYTES
                and f"bytes={REFERENCE_RESOURCE_UNCOMPRESSED_BYTES}" in text
            ):
                raise ValueError(
                    f"Resource byte count was not fully updated in {path.name}"
                )
        main_text = main_file.read_text(encoding="utf-8")
        if expected_sha not in main_text:
            raise ValueError("Resource SHA-256 is missing from the bootstrap fields")
        if expected_files not in main_text:
            raise ValueError("Resource file count is missing from the bootstrap fields")
        if expected_bytes not in main_text:
            raise ValueError("Resource byte count is missing from the bootstrap fields")
    return BootstrapChanges(
        translation=translation_changes,
        contract=contract_changes,
    )


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("Truncated uleb128")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 35:
            raise ValueError("Invalid uleb128")


def read_dex_strings(dex_bytes: bytes) -> list[str]:
    """Returns the DEX string table in index order."""
    if len(dex_bytes) < 0x70 or dex_bytes[:4] != b"dex\n":
        raise ValueError("Invalid DEX header")
    count, string_ids_off = struct.unpack_from("<II", dex_bytes, 0x38)
    if string_ids_off + count * 4 > len(dex_bytes):
        raise ValueError("Truncated DEX string_ids table")
    strings: list[str] = []
    for index in range(count):
        data_off = struct.unpack_from("<I", dex_bytes, string_ids_off + index * 4)[0]
        if data_off >= len(dex_bytes):
            raise ValueError("Truncated DEX string data")
        _utf16_length, cursor = _read_uleb128(dex_bytes, data_off)
        end = dex_bytes.find(b"\x00", cursor)
        if end < 0:
            raise ValueError("Unterminated DEX string")
        try:
            # DEX uses MUTF-8: U+0000 is the overlong C0 80 and non-BMP
            # characters are CESU-8 surrogate pairs.  surrogatepass keeps both
            # valid instead of rejecting an otherwise valid DEX file.
            raw = dex_bytes[cursor:end].replace(b"\xc0\x80", b"\x00")
            strings.append(raw.decode("utf-8", "surrogatepass"))
        except UnicodeDecodeError as exc:
            raise ValueError(f"Invalid MUTF-8 in DEX string #{index}") from exc
    return strings


def verify_dex_string_order(dex_bytes: bytes) -> None:
    """Raises when the DEX string table is not strictly lexicographically sorted."""
    strings = read_dex_strings(dex_bytes)
    keys = [value.encode("utf-16-be", "surrogatepass") for value in strings]
    for index in range(1, len(keys)):
        if keys[index - 1] >= keys[index]:
            raise ValueError(
                "DEX string table is not sorted at index "
                f"{index}: {strings[index - 1]!r} >= {strings[index]!r}"
            )


def rebuild_dex(
    dex_bytes: bytes,
    *,
    translate: bool,
    contract: Optional[ResourceContract],
    apktool_jar: Path,
    log_fn: Optional[Callable[[str], None]] = None,
) -> tuple[bytes, BootstrapChanges]:
    """Decodes, edits and reassembles ``classes8.dex`` with apktool."""
    with tempfile.TemporaryDirectory(prefix="fwt-dex-") as temporary:
        work = Path(temporary)
        mini_apk = work / "mini.apk"
        decoded = work / "decoded"
        rebuilt = work / "rebuilt.apk"
        with zipfile.ZipFile(mini_apk, "w") as archive:
            archive.writestr("classes.dex", dex_bytes)

        if log_fn:
            log_fn("Decoding classes8.dex with apktool...")
        _run_apktool(
            apktool_jar,
            ["d", "-f", "-o", str(decoded), str(mini_apk)],
            "apktool decode",
        )
        smali_dir = decoded / "smali" / "com" / "nexon" / "fwar"
        changes = patch_bootstrap_smali_directory(
            smali_dir, translate=translate, contract=contract
        )


        if log_fn:
            log_fn("Reassembling classes8.dex with apktool...")
        _run_apktool(
            apktool_jar,
            ["b", str(decoded), "-o", str(rebuilt)],
            "apktool build",
        )
        with zipfile.ZipFile(rebuilt, "r") as archive:
            patched = archive.read("classes.dex")
    verify_dex_string_order(patched)
    if log_fn:
        log_fn(
            "Rebuilt classes8.dex ("
            f"{changes.translation} translation, {changes.contract} contract edits)"
        )
    return patched, changes
