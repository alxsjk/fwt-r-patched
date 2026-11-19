from __future__ import annotations

from pathlib import Path
from typing import Any

import fwt_patcher
from core.apk_tooling import ToolPaths
from core.core_patches import PatchResult
from core.patch_inspector import InspectionReport


def _setup_cli_env(
    tmp_path: Path,
    monkeypatch: Any,
    events: list[str],
    *,
    verify_problems: list[str] | None = None,
) -> tuple[Path, Path, Path]:
    in_apk = tmp_path / "base.apk"
    in_apk.write_bytes(b"base")
    out_apk = tmp_path / "out.apk"
    keystore = tmp_path / "test.jks"
    keystore.write_bytes(b"ks")

    class _FakeAdb:
        def __init__(self, _adb_path: str | None) -> None:
            pass

        def list_devices(self) -> list[dict[str, str]]:
            return [{"id": "emu:5555", "state": "device"}]

        def package_state(self, _device_id: str) -> str:
            return "installed"

        def backup_save(self, _device_id: str, _output: Path) -> tuple[bool, str]:
            events.append("backup")
            return True, "backed up"

        def uninstall_apk(self, _device_id: str) -> tuple[bool, str]:
            events.append("uninstall")
            return True, "uninstalled"

        def install_apk(
            self, _device_id: str, _apk_path: Path, log_fn: Any = None
        ) -> tuple[bool, str]:
            events.append("install")
            return True, "installed"

    def _fake_repack(
        input_apk: Path,
        output_apk: Path,
        options: Any,
        tools: Any,
        keystore_path: Path,
        log_fn: Any = None,
    ) -> PatchResult:
        del input_apk, options, tools, keystore_path, log_fn
        events.append("repack")
        output_apk.write_bytes(b"patched")
        return PatchResult(
            so_bytes=b"so",
            dex_bytes=b"dex",
            so_sha256="a" * 64,
            dex_sha256="b" * 64,
        )

    def _fake_inspect(_apk_path: Path) -> InspectionReport:
        events.append("inspect")
        return InspectionReport(
            is_valid_apk=True,
            has_so=True,
            has_dex=True,
            alignment_16k=True,
            is_signed=True,
            dex_checksum_valid=True,
        )

    def _fake_verify(_report: InspectionReport, _opts: Any) -> list[str]:
        events.append("verify")
        return list(verify_problems or [])

    monkeypatch.setattr(
        fwt_patcher,
        "locate_tools",
        lambda: ToolPaths(
            zipalign="/sdk/zipalign",
            apksigner="/sdk/apksigner",
            keytool="/jdk/keytool",
            adb="/sdk/adb",
        ),
    )
    monkeypatch.setattr(fwt_patcher, "AdbHelper", _FakeAdb)
    monkeypatch.setattr(fwt_patcher, "repack_and_sign_apk", _fake_repack)
    monkeypatch.setattr(fwt_patcher, "inspect_apk", _fake_inspect)
    monkeypatch.setattr(fwt_patcher, "verify_report", _fake_verify)
    return in_apk, out_apk, keystore


def test_uninstall_with_install_builds_and_verifies_before_uninstalling(
    tmp_path: Path, monkeypatch
) -> None:
    events: list[str] = []
    in_apk, out_apk, keystore = _setup_cli_env(tmp_path, monkeypatch, events)
    parser = fwt_patcher.build_parser()
    args = parser.parse_args(
        [
            "--input",
            str(in_apk),
            "--output",
            str(out_apk),
            "--keystore",
            str(keystore),
            "--device",
            "emu:5555",
            "--campaign-gold",
            "--uninstall",
            "--install",
        ]
    )

    assert fwt_patcher.run_cli(args) == 0
    assert events == ["backup", "repack", "inspect", "verify", "uninstall", "install"]


def test_uninstall_with_install_skips_uninstall_when_verification_fails(
    tmp_path: Path, monkeypatch
) -> None:
    events: list[str] = []
    in_apk, out_apk, keystore = _setup_cli_env(
        tmp_path, monkeypatch, events, verify_problems=["verification failed"]
    )
    parser = fwt_patcher.build_parser()
    args = parser.parse_args(
        [
            "--input",
            str(in_apk),
            "--output",
            str(out_apk),
            "--keystore",
            str(keystore),
            "--device",
            "emu:5555",
            "--campaign-gold",
            "--uninstall",
            "--install",
        ]
    )

    assert fwt_patcher.run_cli(args) == 1
    assert events == ["backup", "repack", "inspect", "verify"]


def test_standalone_uninstall_runs_without_building(
    tmp_path: Path, monkeypatch
) -> None:
    events: list[str] = []
    _setup_cli_env(tmp_path, monkeypatch, events)
    parser = fwt_patcher.build_parser()
    args = parser.parse_args(["--uninstall", "--device", "emu:5555"])

    assert fwt_patcher.run_cli(args) == 0
    assert events == ["uninstall"]
