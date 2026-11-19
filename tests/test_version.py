from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from core.version import APP_NAME, APP_VERSION, versioned_output_path
from fwt_patcher import build_parser

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_version_matches_app_version() -> None:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == APP_VERSION


def test_changelog_contains_current_release() -> None:
    changelog = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{APP_VERSION}]" in changelog
    assert "## [Unreleased]" in changelog


def test_versioned_output_path_does_not_match_a_longer_version() -> None:
    # "2.5.250" contains "2.5.25" as a substring but is a different version.
    longer = Path(f"FWT-Reborn-Patched-{APP_VERSION}0.apk")
    assert versioned_output_path(longer).stem.endswith(APP_VERSION + "-release")
    already = Path(f"FWT-Reborn-Patched-{APP_VERSION}-release.apk")
    assert versioned_output_path(already) == already


def test_versioned_output_path_marks_the_build_kind() -> None:
    release = versioned_output_path(Path("FWT-Reborn-Patched.apk"))
    assert release.name == f"FWT-Reborn-Patched-{APP_VERSION}-release.apk"
    dev = versioned_output_path(Path("FWT-Reborn-Patched.apk"), dev=True)
    assert dev.name == f"FWT-Reborn-Patched-{APP_VERSION}-dev.apk"
    # a dev build never gets the release marker and vice versa
    assert "-release" not in versioned_output_path(Path("x-dev.apk"), dev=True).name
    assert "-dev" not in versioned_output_path(Path("x.apk"), dev=False).name


def test_cli_version_uses_app_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["--version"])
    assert excinfo.value.code == 0
    output = capsys.readouterr().out
    assert APP_NAME in output
    assert APP_VERSION in output
