"""Build a DEV-only APK to test Alex's client Awakening screen.

This experiment changes only the client evolution table. It does not implement
the server rule or the Awake skill: do not execute the Awakening transaction.
It must never be packaged as a release. Invoke with ``python -m``.
"""

from __future__ import annotations

import copy
import hashlib
import zipfile
from pathlib import Path
from typing import Any

import UnityPy

import core.apk_tooling as apk_tooling
import fwt_patcher
from core.dex_smali import ResourceContract
from core.version import APP_VERSION

_PATH = "files/Resources/datatable/creaturerebirth.unity3d"
_REFERENCE_SHA256 = "45dd51a62066ed7aa5b09e172c45271dd3e283c11df9ebe29c29203f3ef36206"
_ALEX_FIVE = 0x130185
_ALEX_SIX = 0x130186


def _patch_gate(data: bytes) -> bytes:
    if hashlib.sha256(data).hexdigest() != _REFERENCE_SHA256:
        raise ValueError("Unexpected reference evolution asset; refusing lab build")
    clear, key, iv = apk_tooling._decrypt_datatable(data)
    env = UnityPy.load(clear)
    objects = [obj for obj in env.objects if obj.type.name == "MonoBehaviour"]
    if len(objects) != 1:
        raise ValueError("Unexpected evolution table layout")
    tree = objects[0].read_typetree()
    rows: list[dict[str, Any]] = tree.get("_data") or []
    if len(rows) != 558 or any(row.get("_creatureId") == _ALEX_FIVE for row in rows):
        raise ValueError("Unexpected evolution rules or preexisting Alex rule")
    donors = [row for row in rows if row.get("_creatureId") == 1249317
              and row.get("_creatureId2") == 1249318 and row.get("_grade") == 5]
    if len(donors) != 1:
        raise ValueError("Expected one peer Awakening rule")
    clone = copy.deepcopy(donors[0])
    clone.update(_creatureId=_ALEX_FIVE, _creatureId2=_ALEX_SIX)
    rows.append(clone)
    objects[0].save_typetree(tree)
    encoded = apk_tooling._encrypt_datatable(bytes(getattr(env.file, "save")()), key, iv)  # noqa: B009
    decoded, _, _ = apk_tooling._decrypt_datatable(encoded)
    found = [row for obj in UnityPy.load(decoded).objects if obj.type.name == "MonoBehaviour"
             for row in (obj.read_typetree().get("_data") or [])
             if row.get("_creatureId") == _ALEX_FIVE]
    if len(found) != 1 or found[0] != clone:
        raise ValueError("Alex client rule did not survive the asset round-trip")
    return encoded


def main() -> int:
    """Create a DEV-identified, uninstalled, client-gate-only lab APK."""
    fwt_patcher._load_env_file()
    output = f"output/FWT-Reborn-Alex-Awake-Gate-{APP_VERSION}-dev.apk"
    args = fwt_patcher.build_parser().parse_args(
        ["--all", "--dev", "--dev-keep-version", "--output", output]
    )
    original = apk_tooling._patch_resources_zip_file

    def lab_resources(raw_zip: Path, options: Any, *, work_dir: Path,
                      log_fn: Any = None) -> tuple[Path, ResourceContract | None]:
        patched, _ = original(raw_zip, options, work_dir=work_dir, log_fn=log_fn)
        with zipfile.ZipFile(patched) as archive:
            replacement = _patch_gate(archive.read(_PATH))
        lab_path = work_dir / "fwt_resources_alex_gate_lab.zip"
        apk_tooling._rewrite_zip_entries_to_file(patched, {_PATH: replacement}, lab_path)
        if log_fn:
            log_fn("LAB ONLY: Alex client Awake gate; server rule and skill are not implemented")
        return lab_path, ResourceContract.from_archive_path(lab_path)

    apk_tooling._patch_resources_zip_file = lab_resources
    try:
        return fwt_patcher.run_cli(args)
    finally:
        apk_tooling._patch_resources_zip_file = original


if __name__ == "__main__":
    raise SystemExit(main())
