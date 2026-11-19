from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.core_patches import DevOptions, PatchOptions
from core.version import APP_VERSION
from fwt_patcher import _has_selected_feature, build_parser, parse_lan_endpoint, run_cli

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = PROJECT_ROOT / "fwt_patcher.py"


def _run_cli(*args: str, encoding: str = "cp1252") -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = encoding
    env["FWT_DEBUG"] = ""
    return subprocess.run(
        [sys.executable, str(ENTRYPOINT), *args],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        encoding=encoding,
        errors="replace",
        env=env,
        timeout=120,
    )


def test_help_does_not_crash_on_cp1252():
    result = _run_cli("--help")
    assert result.returncode == 0, result.stderr
    assert "Traceback" not in result.stdout
    assert "usage:" in result.stdout
    assert "--campaign-shop-discount" in result.stdout
    assert "--mode-drops-x10" in result.stdout
    assert "--battle-arena-fix" in result.stdout
    assert "--guild-raid-mercenary" in result.stdout
    assert "--event-limits-daily" in result.stdout
    assert "--sacred-lands-restore" in result.stdout
    assert "--check-tools" in result.stdout


def test_version_does_not_crash_on_cp1252():
    result = _run_cli("--version")
    assert result.returncode == 0, result.stderr
    assert "FWT Reborn Patch" in result.stdout
    assert APP_VERSION in result.stdout


def test_missing_inspect_is_a_clean_error():
    result = _run_cli("--inspect", "does-not-exist.apk")
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "Error:" in result.stderr


def test_missing_inspect_so_is_a_clean_error():
    result = _run_cli("--inspect-so", "does-not-exist.so")
    assert result.returncode == 1
    assert "Traceback" not in result.stderr


def test_parse_lan_endpoint():
    assert parse_lan_endpoint("192.168.1.50") == ("192.168.1.50", 8010)
    assert parse_lan_endpoint("192.168.1.50:9000") == ("192.168.1.50", 9000)


def test_dev_flags_are_listed_in_help():
    result = _run_cli("--help")
    assert result.returncode == 0, result.stderr
    for flag in ("--dev", "--dev-debuggable", "--dev-log", "--dev-log-limit",
                 "--dev-log-commands", "--dev-counters", "--dev-marker",
                 "--dev-timing", "--dev-snapshots", "--dev-endpoint", "--lab-traps"):
        assert flag in result.stdout, flag


def test_dev_parser_defaults():
    args = build_parser().parse_args([])
    assert args.dev is False
    assert args.dev_log is False
    assert args.dev_log_limit == 1024
    assert args.dev_log_commands == ""

    args = build_parser().parse_args(
        ["--dev", "--dev-log", "--dev-log-limit", "256",
         "--dev-log-commands", "GET_MY_INFO"]
    )
    assert args.dev is True
    assert args.dev_log is True
    assert args.dev_log_limit == 256
    assert args.dev_log_commands == "GET_MY_INFO"


def test_dev_instrumentation_requires_master_switch(tmp_path):
    # A dummy input keeps the error path independent of the proprietary APK: the
    # dev validation must fire before anything is read from the file.
    dummy = tmp_path / "dummy.apk"
    dummy.write_bytes(b"")
    result = _run_cli("--all", "--dev-log", "--input", str(dummy))
    assert result.returncode == 2
    assert "master switch" in result.stderr
    assert "--dev" in result.stderr


def test_dev_build_output_name_gets_the_dev_suffix(tmp_path):
    """A --dev build can never be written under a name that looks distributable.

    The name is fixed by ``versioned_output_path(..., dev=True)`` instead of erroring, so
    the marker is always there even when the user types a plain name.
    """
    from core.version import versioned_output_path

    auto = versioned_output_path(tmp_path / "FWT-Reborn.apk", dev=True)
    assert auto.stem.endswith("-dev")
    assert "-release" not in auto.stem
    # the release path gets the other marker, and the two can never collide
    release = versioned_output_path(tmp_path / "FWT-Reborn.apk", dev=False)
    assert release.stem.endswith("-release")
    assert release != auto


def test_parse_lan_endpoint_rejects_bad_input():
    with pytest.raises(argparse.ArgumentTypeError, match="invalid IPv4"):
        parse_lan_endpoint("localhost:8010")
    with pytest.raises(argparse.ArgumentTypeError, match="invalid LAN port"):
        parse_lan_endpoint("192.168.1.50:not-a-port")
    with pytest.raises(argparse.ArgumentTypeError, match="out of range"):
        parse_lan_endpoint("192.168.1.50:70000")
    with pytest.raises(argparse.ArgumentTypeError, match="cannot be empty"):
        parse_lan_endpoint("")


def test_mutually_exclusive_parser_groups():
    parser = build_parser()
    for args in (
        ["--summon-rates", "--summon-50-30-20"],
        ["--stamina-cost-half", "--stamina-cashback"],
        ["--limit-break-gold-half", "--limit-break-cost-half"],
        ["--limit-break-cost-tenth", "--limit-break-cost-fixed"],
        ["--recycle-tickets", "--recycle-six-star"],
        ["--inspect", "a.apk", "--backup"],
    ):
        with pytest.raises(SystemExit):
            parser.parse_args(args)


def test_has_selected_feature_accepts_integer_scale_flags():
    assert not _has_selected_feature(PatchOptions())
    assert not _has_selected_feature(
        PatchOptions(server_ip="10.0.0.2", server_port=9000, align_16k=True, allow_unknown=True)
    )
    assert not _has_selected_feature(PatchOptions(rune_quality_factor=-1))
    assert _has_selected_feature(PatchOptions(rune_quality_factor=10))


@pytest.mark.parametrize(
    ("flag", "value", "attr"),
    [
        ("--rune-quality-factor", "10", "rune_quality_factor"),
    ],
)
def test_cli_accepts_standalone_integer_factor_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag: str,
    value: str,
    attr: str,
):
    dummy_in = tmp_path / "in.apk"
    dummy_in.write_bytes(b"PK")
    out_apk = tmp_path / "out.apk"

    called_opts: list[PatchOptions] = []

    class _BuildCalled(RuntimeError):
        pass

    def _fake_repack(**kwargs):
        called_opts.append(kwargs["options"])
        raise _BuildCalled("reached build")

    monkeypatch.setattr("fwt_patcher.repack_and_sign_apk", _fake_repack)
    parser = build_parser()
    args = parser.parse_args(["--input", str(dummy_in), "--output", str(out_apk), flag, value])
    rc = run_cli(args)
    assert rc == 1  # caught _BuildCalled cleanly inside repack_and_sign_apk handler
    assert len(called_opts) == 1
    assert getattr(called_opts[0], attr) == 10


def test_cli_rejects_zero_integer_factor_with_no_other_features(tmp_path: Path, capsys):
    dummy_in = tmp_path / "in.apk"
    dummy_in.write_bytes(b"PK")
    out_apk = tmp_path / "out.apk"

    parser = build_parser()
    args = parser.parse_args(
        ["--input", str(dummy_in), "--output", str(out_apk), "--rune-quality-factor", "0"]
    )
    rc = run_cli(args)
    assert rc == 2
    assert "no patch features selected" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--ship-parts-90-off", "--ship-parts-half"])
def test_ship_parts_cli_flag_and_legacy_alias(flag: str):
    args = build_parser().parse_args([flag])
    assert args.ship_parts_90_off is True


def test_has_selected_feature_requires_patch_or_dev_instrumentation():
    assert not _has_selected_feature(PatchOptions(dev=DevOptions(enabled=True)))
    assert not _has_selected_feature(
        PatchOptions(dev=DevOptions(enabled=True, keep_version=True))
    )
    assert _has_selected_feature(
        PatchOptions(dev=DevOptions(enabled=True, log_dispatch=True))
    )
    assert _has_selected_feature(
        PatchOptions(dev=DevOptions(enabled=True, debuggable=True))
    )


def test_cli_rejects_bare_dev_flag_with_no_features(tmp_path: Path, capsys):
    dummy_in = tmp_path / "in.apk"
    dummy_in.write_bytes(b"PK")
    out_apk = tmp_path / "out-dev.apk"

    args = build_parser().parse_args(
        ["--input", str(dummy_in), "--output", str(out_apk), "--dev"]
    )
    rc = run_cli(args)
    assert rc == 2
    assert "no patch features selected" in capsys.readouterr().err


def test_cli_accepts_dev_with_instrumentation_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    dummy_in = tmp_path / "in.apk"
    dummy_in.write_bytes(b"PK")
    out_apk = tmp_path / "out-dev.apk"
    called_opts: list[PatchOptions] = []

    class _BuildCalled(RuntimeError):
        pass

    def _fake_repack(**kwargs):
        called_opts.append(kwargs["options"])
        raise _BuildCalled("reached build")

    monkeypatch.setattr("fwt_patcher.repack_and_sign_apk", _fake_repack)
    args = build_parser().parse_args(
        ["--input", str(dummy_in), "--output", str(out_apk), "--dev", "--dev-log"]
    )
    rc = run_cli(args)
    assert rc == 1
    assert len(called_opts) == 1
    assert called_opts[0].dev.enabled is True
    assert called_opts[0].dev.log_dispatch is True


def test_cli_all_with_limit_break_cost_tenth_overrides_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    dummy_in = tmp_path / "in.apk"
    dummy_in.write_bytes(b"PK")
    out_apk = tmp_path / "out.apk"
    called_opts: list[PatchOptions] = []

    class _BuildCalled(RuntimeError):
        pass

    def _fake_repack(**kwargs):
        called_opts.append(kwargs["options"])
        raise _BuildCalled("reached build")

    monkeypatch.setattr("fwt_patcher.repack_and_sign_apk", _fake_repack)
    args = build_parser().parse_args(
        ["--input", str(dummy_in), "--output", str(out_apk), "--all", "--limit-break-cost-tenth"]
    )
    assert run_cli(args) == 1
    assert len(called_opts) == 1
    assert called_opts[0].limit_break_cost_tenth is True
    assert called_opts[0].limit_break_cost_fixed is False


def test_cli_run_cli_rejects_both_limit_break_modes(tmp_path: Path, capsys):
    dummy_in = tmp_path / "in.apk"
    dummy_in.write_bytes(b"PK")
    out_apk = tmp_path / "out.apk"
    args = build_parser().parse_args(["--input", str(dummy_in), "--output", str(out_apk)])
    args.limit_break_cost_tenth = True
    args.limit_break_cost_fixed = True
    assert run_cli(args) == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_register_release_rejects_dev_builds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from core.patch_inspector import InspectionReport
    from tools.register_release import validate_release_apk

    dev_named = tmp_path / "FWT-Reborn-Patched-dev.apk"
    dev_named.write_bytes(b"PK")
    with pytest.raises(ValueError, match="Development builds"):
        validate_release_apk(dev_named)

    disguised = tmp_path / "FWT-Reborn-Patched-release.apk"
    disguised.write_bytes(b"PK")
    monkeypatch.setattr(
        "tools.register_release.inspect_apk",
        lambda _p: InspectionReport(build_identity="dev"),
    )
    with pytest.raises(ValueError, match="Development builds"):
        validate_release_apk(disguised)
