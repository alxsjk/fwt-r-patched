from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

from core.core_patches import PatchOptions
from core.patch_inspector import FeatureReport, InspectionReport
from core.version import APP_VERSION, versioned_output_path
from tools import create_distribution_zip
from tools.create_distribution_zip import (
    _refuse_dev_build,
    build_suite_zip,
    default_patched_apk_path,
    stage_apk_only,
)


def test_versioned_output_path_adds_version(tmp_path: Path) -> None:
    output = versioned_output_path(tmp_path / "FWT-Reborn-Patcher-Suite.zip")
    assert output.name == f"FWT-Reborn-Patcher-Suite-{APP_VERSION}.zip"


def test_versioned_output_path_keeps_existing_version(tmp_path: Path) -> None:
    output = tmp_path / f"FWT-Reborn-Patcher-Suite-{APP_VERSION}.zip"
    assert versioned_output_path(output) == output


def test_suite_zip_excludes_secrets_and_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "suite.zip"
    build_suite_zip(output)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
    assert "fwt-reborn-suite/fwt_patcher.py" in names
    assert "fwt-reborn-suite/CHANGELOG.md" in names
    assert "fwt-reborn-suite/gui/feature_catalog.py" in names
    assert "fwt-reborn-suite/docs/FEATURE_CATALOG.md" in names
    assert not any(name.endswith(".env") for name in names)
    assert not any(
        name.endswith((".apk", ".jar", ".jks", ".keystore", ".pem", ".key", ".so", ".dex", ".dat", ".local.json"))
        for name in names
    )
    assert not any(name.startswith("fwt-reborn-suite/backups/") for name in names)
    assert not any(name.startswith("fwt-reborn-suite/keystore/") for name in names)


def test_suite_zip_excludes_stray_binaries_and_local_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_fake_root(tmp_path)
    (root / "tools").mkdir()
    (root / "docs").mkdir()
    (root / "tools" / "keep.py").write_text("ok = True\n", encoding="utf-8")
    (root / "tools" / "scratch.so").write_bytes(b"\x7fELF")
    (root / "tools" / "table.dat").write_bytes(b"DATA")
    (root / "docs" / "keys.local.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(create_distribution_zip, "PROJECT_ROOT", root)
    output = tmp_path / "dist" / "suite.zip"
    build_suite_zip(output)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
    assert "fwt-reborn-suite/CHANGELOG.md" in names
    assert "fwt-reborn-suite/tools/keep.py" in names
    assert "fwt-reborn-suite/tools/scratch.so" not in names
    assert "fwt-reborn-suite/tools/table.dat" not in names
    assert "fwt-reborn-suite/docs/keys.local.json" not in names


def test_distribution_refuses_dev_build(tmp_path: Path) -> None:
    """A dev build must never be staged or packaged for distribution."""
    with pytest.raises(SystemExit) as exc:
        _refuse_dev_build(tmp_path / f"FWT-Reborn-Patched-{APP_VERSION}-dev.apk")
    assert exc.value.code == 1


def test_distribution_accepts_release_build(tmp_path: Path) -> None:
    _refuse_dev_build(tmp_path / f"FWT-Reborn-Patched-{APP_VERSION}.apk")


def _make_fake_root(tmp_path: Path) -> Path:
    for name in (
        "fwt_patcher.py",
        "run_gui.bat",
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "pyproject.toml",
        "requirements.txt",
        ".env.example",
    ):
        (tmp_path / name).write_text("ok\n", encoding="utf-8")
    (tmp_path / "output").mkdir()
    return tmp_path


def test_default_patched_apk_path_uses_release_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(create_distribution_zip, "PROJECT_ROOT", tmp_path)
    expected = tmp_path / "output" / f"FWT-Reborn-Patched-{APP_VERSION}-release.apk"
    assert default_patched_apk_path() == expected


def test_suite_zip_include_patched_apk_uses_release_and_verifies_zip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_fake_root(tmp_path)
    monkeypatch.setattr(create_distribution_zip, "PROJECT_ROOT", root)
    release_apk = default_patched_apk_path()
    release_apk.write_bytes(b"PK\x03\x04dummy")
    monkeypatch.setattr(create_distribution_zip, "_verify_release_apk", lambda _path: None)

    testzip_calls = 0
    orig_testzip = zipfile.ZipFile.testzip

    def _spy_testzip(self: zipfile.ZipFile) -> str | None:
        nonlocal testzip_calls
        testzip_calls += 1
        return orig_testzip(self)

    monkeypatch.setattr(zipfile.ZipFile, "testzip", _spy_testzip)

    out_zip = root / "dist" / "suite.zip"
    build_suite_zip(out_zip, include_patched_apk=True)

    assert testzip_calls == 1
    with zipfile.ZipFile(out_zip) as archive:
        assert f"fwt-reborn-suite/output/{release_apk.name}" in archive.namelist()


def test_stage_apk_only_rejects_unpatched_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _make_fake_root(tmp_path)
    monkeypatch.setattr(create_distribution_zip, "PROJECT_ROOT", root)
    release_apk = default_patched_apk_path()
    release_apk.write_bytes(b"apk-bytes")

    report = InspectionReport(
        is_valid_apk=True,
        has_so=True,
        has_dex=True,
        alignment_16k=True,
        is_signed=True,
        dex_checksum_valid=True,
        build_identity="release",
        build_options=PatchOptions(),
        features={
            "no_win_box": FeatureReport(
                name="Hide Phantom Win Boxes",
                active=True,
                status="Active (is_win_box always false)",
            ),
            "hero_exp_cap": FeatureReport(
                name="Hero EXP Cap & Limit Break Floor",
                active=True,
                status="Active (battle/expedition EXP clamped; Lv70 LB floor)",
            ),
            "convert_hex_guard": FeatureReport(
                name="Non-Hex Inventory Sync Guard (KB-001)",
                active=True,
                status="Patched (returns -1 on non-hex item_code)",
            ),
        },
    )
    monkeypatch.setattr(create_distribution_zip, "inspect_apk", lambda _p: report)

    with pytest.raises(SystemExit) as exc:
        stage_apk_only(root / f"staged-{APP_VERSION}-release.apk")
    assert exc.value.code == 1
    assert "unpatched" in capsys.readouterr().err


def test_stage_apk_only_accepts_patched_apk_and_main_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_fake_root(tmp_path)
    monkeypatch.setattr(create_distribution_zip, "PROJECT_ROOT", root)
    release_apk = default_patched_apk_path()
    release_apk.write_bytes(b"patched-apk-bytes")

    report = InspectionReport(
        is_valid_apk=True,
        has_so=True,
        has_dex=True,
        alignment_16k=True,
        is_signed=True,
        dex_checksum_valid=True,
        build_identity="release",
        build_options=PatchOptions(),
        features={
            "no_win_box": FeatureReport(
                name="Hide Phantom Win Boxes",
                active=True,
                status="Active (is_win_box always false)",
            ),
            "hero_exp_cap": FeatureReport(
                name="Hero EXP Cap & Limit Break Floor",
                active=True,
                status="Active (battle/expedition EXP clamped; Lv70 LB floor)",
            ),
            "convert_hex_guard": FeatureReport(
                name="Non-Hex Inventory Sync Guard (KB-001)",
                active=True,
                status="Patched (returns -1 on non-hex item_code)",
            ),
            "dungeon_recom_info": FeatureReport(
                name="Mercenary Auto-Select Recommendations (DUNGEON_RECOM_INFO)",
                active=True,
                status="Patched (recom_list served from friends)",
            ),
            "campaign_gold": FeatureReport(
                name="10x Campaign Gold & Drops",
                active=True,
                status="Patched",
            ),
        },
    )
    monkeypatch.setattr(create_distribution_zip, "inspect_apk", lambda _p: report)

    staged = root / "copy" / f"staged-{APP_VERSION}-release.apk"
    stage_apk_only(staged)
    assert staged.read_bytes() == b"patched-apk-bytes"

    captured_out: list[Path] = []
    monkeypatch.setattr(create_distribution_zip, "stage_apk_only", captured_out.append)
    monkeypatch.setattr(sys, "argv", ["create_distribution_zip.py", "--apk-only"])
    create_distribution_zip.main()
    assert captured_out == [release_apk]


def test_suite_zip_rejects_invalid_apk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _make_fake_root(tmp_path)
    monkeypatch.setattr(create_distribution_zip, "PROJECT_ROOT", root)
    default_patched_apk_path().write_bytes(b"invalid")
    with pytest.raises(SystemExit):
        build_suite_zip(root / "suite.zip", include_patched_apk=True)


def test_release_report_rejects_renamed_dev(tmp_path: Path) -> None:
    from core.patch_inspector import inspect_apk, verify_release_report
    from core.version import BUILD_IDENTITY_ENTRY

    apk = tmp_path / "release.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(BUILD_IDENTITY_ENTRY, b"dev")
    report = inspect_apk(apk)
    assert report.build_identity == "dev"
    assert any("identity is dev" in problem for problem in verify_release_report(report))


def test_release_report_checks_the_recorded_recipe() -> None:
    from core.patch_inspector import verify_release_report

    report = InspectionReport(
        is_valid_apk=True, has_so=True, has_dex=True, alignment_16k=True,
        is_signed=True, dex_checksum_valid=True, build_identity="release",
        build_options=PatchOptions(event_discount=True),
        features={
            "no_win_box": FeatureReport("fix", True, "active"),
            "hero_exp_cap": FeatureReport("fix", True, "active"),
            "campaign_gold": FeatureReport("gold", True, "active"),
            "event_discount": FeatureReport("event", False, "partial"),
        },
    )
    assert any("Event Shop Discount" in problem for problem in verify_release_report(report))
    report.build_options = None
    assert any("options are missing" in problem for problem in verify_release_report(report))


def test_register_release_rejects_dev_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from tools import register_release

    apk = tmp_path / "release.apk"
    apk.write_bytes(b"dev")
    monkeypatch.setattr(register_release, "inspect_apk", lambda _path: InspectionReport(
        is_valid_apk=True, has_so=True, has_dex=True, alignment_16k=True,
        is_signed=True, dex_checksum_valid=True, build_identity="dev",
        build_options=PatchOptions(),
        features={
            "no_win_box": FeatureReport("fix", True, "active"),
            "hero_exp_cap": FeatureReport("fix", True, "active"),
        },
    ))
    monkeypatch.setattr(sys, "argv", ["register_release.py", str(apk)])
    with pytest.raises(SystemExit, match="identity is dev"):
        register_release.main()
