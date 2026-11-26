"""Binary manifest (AXML) patching for the dev build — phase 1.

The interesting assertion is the last group: the patched manifest is handed to
``aapt2`` (the same tool Android's build system uses), which must read
``debuggable=true`` and ``versionName="...-dev"`` out of it.  A self-consistent
parser alone would only prove that the parser agrees with itself.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from core.axml import (
    ATTR_DEBUGGABLE_ID,
    TYPE_INT_BOOLEAN,
    AxmlDocument,
    patch_debuggable,
    patch_version_name,
    read_manifest_info,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _aapt2() -> str | None:
    import os

    exe = "aapt2.exe" if os.name == "nt" else "aapt2"
    candidates: list[str | None] = [
        shutil.which("aapt2"),
        str(Path.home() / "opt" / "android-build-tools" / exe),
    ]
    for env_key in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        root = os.environ.get(env_key)
        if root:
            for match in sorted((Path(root) / "build-tools").glob(f"*/{exe}"), reverse=True):
                candidates.append(str(match))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


# -- parsing --------------------------------------------------------------
def test_manifest_parses(reference_manifest):
    manifest, _arsc = reference_manifest
    document = AxmlDocument(manifest)
    assert len(document.elements) > 100
    assert document.element("manifest").name == "manifest"
    assert "application" in {element.name for element in document.elements}
    info = read_manifest_info(manifest)
    assert info["versionName"] == "0.682"
    assert info["versionCode"] == 247
    assert info["debuggable"] == 0


def test_string_pool_indexes_are_consistent(reference_manifest):
    manifest, _arsc = reference_manifest
    document = AxmlDocument(manifest)
    # Every string index used by an element name must resolve to real text.
    for element in document.elements[:50]:
        assert element.name
        for attribute in element.attributes:
            assert attribute.name


def test_reference_manifest_is_aligned(reference_manifest):
    manifest, _arsc = reference_manifest
    assert len(manifest) % 4 == 0
    assert struct.unpack_from("<I", manifest, 4)[0] == len(manifest)


# -- debuggable -----------------------------------------------------------
def test_patch_debuggable_flips_the_boolean(reference_manifest):
    manifest, _arsc = reference_manifest
    patched = patch_debuggable(manifest)
    assert len(patched) == len(manifest)  # size preserving
    assert read_manifest_info(patched)["debuggable"] == 1
    application = AxmlDocument(patched).element("application")
    attribute = application.attribute("debuggable", ATTR_DEBUGGABLE_ID)
    assert attribute.data_type == TYPE_INT_BOOLEAN
    assert attribute.data == 1


def test_patch_debuggable_is_idempotent(reference_manifest):
    manifest, _arsc = reference_manifest
    once = patch_debuggable(manifest)
    assert patch_debuggable(once) == once


def test_patch_debuggable_rejects_non_boolean(reference_manifest):
    manifest, _arsc = reference_manifest
    document = AxmlDocument(manifest)
    attribute = document.element("application").attribute("debuggable", ATTR_DEBUGGABLE_ID)
    broken = bytearray(manifest)
    broken[attribute.offset + 15] = 0x10  # pretend it is an int, not a boolean
    with pytest.raises(ValueError, match="not stored as a boolean"):
        patch_debuggable(bytes(broken))


# -- versionName ----------------------------------------------------------
def test_patch_version_name_appends_the_suffix(reference_manifest):
    manifest, _arsc = reference_manifest
    patched, old, new = patch_version_name(manifest, "-dev")
    assert (old, new) == ("0.682", "0.682-dev")
    assert len(patched) > len(manifest)
    # AXML chunks must stay 4-byte aligned and the XML size must match the file.
    assert len(patched) % 4 == 0
    assert struct.unpack_from("<I", patched, 4)[0] == len(patched)
    assert read_manifest_info(patched)["versionName"] == "0.682-dev"
    # Nothing else moved semantically.
    assert read_manifest_info(patched)["versionCode"] == 247
    assert len(AxmlDocument(patched).elements) == len(AxmlDocument(manifest).elements)


def test_patch_version_name_is_idempotent(reference_manifest):
    manifest, _arsc = reference_manifest
    once, _old, _new = patch_version_name(manifest, "-dev")
    twice, old, new = patch_version_name(once, "-dev")
    assert twice == once
    assert old == new == "0.682-dev"


def test_combined_dev_manifest(reference_manifest):
    manifest, _arsc = reference_manifest
    patched, _old, _new = patch_version_name(manifest, "-dev")
    patched = patch_debuggable(patched)
    info = read_manifest_info(patched)
    assert info["debuggable"] == 1
    assert info["versionName"] == "0.682-dev"
    assert info["versionCode"] == 247


# -- independent validation (aapt2) --------------------------------------
@pytest.mark.parametrize("with_dev", [False, True])
def test_aapt2_reads_the_manifest(reference_manifest, tmp_path, with_dev):
    aapt2 = _aapt2()
    if aapt2 is None:
        pytest.skip("aapt2 not available")
    assert aapt2 is not None  # narrows the type for the type checkers
    manifest, arsc = reference_manifest
    expected_version = "0.682"
    if with_dev:
        manifest = patch_debuggable(patch_version_name(manifest, "-dev")[0])
        expected_version = "0.682-dev"

    mini = tmp_path / "mini.apk"
    with zipfile.ZipFile(mini, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("resources.arsc", arsc)

    badging = subprocess.run(
        [aapt2, "dump", "badging", str(mini)], capture_output=True, text=True
    )
    assert badging.returncode == 0, badging.stderr[-2000:]
    first_line = badging.stdout.splitlines()[0]
    assert f"versionName='{expected_version}'" in first_line

    tree = subprocess.run(
        [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(mini)],
        capture_output=True,
        text=True,
    )
    assert tree.returncode == 0, tree.stderr[-2000:]
    assert f'versionName(0x0101021c)="{expected_version}"' in tree.stdout
    assert (
        "debuggable(0x0101000f)=true" in tree.stdout
    ) == with_dev
