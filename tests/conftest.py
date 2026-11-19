from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REFERENCE_APK = PROJECT_ROOT / "source" / "fwt_0.682_offline_v1574.apk"
REFERENCE_SO_NAME = "lib/arm64-v8a/libfwt_local_server.so"
REFERENCE_DEX_NAME = "classes8.dex"
REFERENCE_MANIFEST_NAME = "AndroidManifest.xml"
REFERENCE_ARSC_NAME = "resources.arsc"


def pytest_collection_modifyitems(config, items) -> None:
    """Marks every test that needs the proprietary APK as integration."""
    for item in items:
        fixture_names = getattr(item, "fixturenames", ())
        if any(name in fixture_names for name in ("reference_apk", "reference_buffers", "reference_manifest")):
            item.add_marker(pytest.mark.integration)


def _install_win32_unicorn_faulthandler_guard() -> None:
    """Temporarily disable faulthandler around ``Uc.mem_map`` on Windows."""
    # Compared via a variable so mypy does not const-fold the platform test
    # and flag the Windows-only body below as unreachable on non-Windows hosts.
    _is_win32 = sys.platform == "win32"
    if not _is_win32:
        return
    try:
        import faulthandler
        import functools

        import unicorn
    except ImportError:
        return
    original = getattr(unicorn.Uc, "mem_map", None)
    if original is None or getattr(original, "_fwt_faulthandler_guarded", False):
        return

    @functools.wraps(original)
    def _guarded_mem_map(self, *args, **kwargs):
        was_enabled = faulthandler.is_enabled()
        if was_enabled:
            faulthandler.disable()
        try:
            return original(self, *args, **kwargs)
        finally:
            if was_enabled:
                faulthandler.enable()

    _guarded_mem_map._fwt_faulthandler_guarded = True  # type: ignore[attr-defined]
    unicorn.Uc.mem_map = _guarded_mem_map  # type: ignore[method-assign]


_install_win32_unicorn_faulthandler_guard()


_DATATABLE_ENV_VARS = (
    "FWT_DATATABLE_CRYPT_KEY",
    "FWT_DATATABLE_CRYPT_IV",
    "FWT_DATATABLE_CRYPT_KEY_REVERSED",
    "FWT_DATATABLE_CRYPT_IV_REVERSED",
)
_INITIAL_DATATABLE_ENV = {
    name: os.environ[name] for name in _DATATABLE_ENV_VARS if name in os.environ
}


def _load_integration_datatable_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore datatable AES credentials from shell env or local .env for integration tests."""
    values: dict[str, str] = {}
    env_file = PROJECT_ROOT / ".env"
    if env_file.is_file():
        try:
            from dotenv import dotenv_values

            for k, v in dotenv_values(env_file).items():
                if k in _DATATABLE_ENV_VARS and v:
                    values[k] = v
        except ImportError:
            pass
    values.update(_INITIAL_DATATABLE_ENV)
    for k, v in values.items():
        monkeypatch.setenv(k, v)


@pytest.fixture(autouse=True)
def _hermetic_fwt_env(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keeps the developer's .env out of non-integration unit tests."""
    for name in (
        "FWT_DEBUG",
        "FWT_DEVICE",
        "FWT_OUTPUT_APK",
        "FWT_SOURCE_APK",
        "FWT_KEYSTORE",
        "FWT_KEYSTORE_PASS",
        "FWT_KEY_ALIAS",
        *_DATATABLE_ENV_VARS,
    ):
        monkeypatch.delenv(name, raising=False)
    if request.node.get_closest_marker("integration") is not None:
        _load_integration_datatable_env(monkeypatch)


@pytest.fixture(scope="session")
def reference_apk() -> Path:
    if not REFERENCE_APK.is_file():
        pytest.skip(
            "reference APK not present; integration tests require "
            "source/fwt_0.682_offline_v1574.apk"
        )
    return REFERENCE_APK


@pytest.fixture(scope="session")
def reference_buffers() -> tuple[bytes, bytes]:
    if not REFERENCE_APK.is_file():
        pytest.skip(
            "reference APK not present; integration tests require "
            "source/fwt_0.682_offline_v1574.apk"
        )
    with zipfile.ZipFile(REFERENCE_APK) as archive:
        return archive.read(REFERENCE_SO_NAME), archive.read(REFERENCE_DEX_NAME)


@pytest.fixture(scope="session")
def reference_manifest() -> tuple[bytes, bytes]:
    """Binary AndroidManifest.xml plus resources.arsc (for aapt2 validation)."""
    if not REFERENCE_APK.is_file():
        pytest.skip(
            "reference APK not present; integration tests require "
            "source/fwt_0.682_offline_v1574.apk"
        )
    with zipfile.ZipFile(REFERENCE_APK) as archive:
        return archive.read(REFERENCE_MANIFEST_NAME), archive.read(REFERENCE_ARSC_NAME)
