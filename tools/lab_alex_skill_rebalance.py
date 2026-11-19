"""Build and verify a dedicated DEV test APK for Alex's rebalance benchmark.

Now integrated into the main patcher as Feature 12.02 (``--alex-rebalance``)
via :mod:`core.alex_rebalance`. This CLI wrapper remains useful for quick
in-memory datatable round-trip checks and standalone DEV lab APK builds.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

import fwt_patcher
from core.alex_rebalance import (
    inspect_alex_rebalance_assets,
    prepare_alex_rebalance_assets,
)
from core.version import APP_VERSION


def verify_only(reference_apk: Path) -> None:
    """Run in-memory datatable rebalance and round-trip verification."""
    with (
        zipfile.ZipFile(reference_apk) as apk,
        apk.open("assets/fwt_resources_v1.zip") as stream,
        zipfile.ZipFile(stream) as raw_res,
    ):
        replacement = prepare_alex_rebalance_assets(raw_res)
        if len(replacement) != 16:
            raise ValueError(f"Expected 16 rebalanced bundles, got {len(replacement)}")
    print(f"Verified 8 skilldata + 8 skilleffecttable bundles in memory from {reference_apk}.")


def verify_apk(lab_apk: Path) -> None:
    """Verify the built DEV lab APK's build identity and rebalanced tables."""
    with (
        zipfile.ZipFile(lab_apk) as lab,
        lab.open("assets/fwt_resources_v1.zip") as lstream,
        zipfile.ZipFile(lstream) as lzip,
    ):
        identity = json.loads(lab.read("assets/fwt_re_patched_build_type.txt"))
        if identity.get("identity") != "dev":
            raise ValueError(f"Expected DEV build identity, got: {identity}")
        ok, msg = inspect_alex_rebalance_assets(lzip)
        if not ok:
            raise ValueError(msg)
    print(f"Verified DEV identity and {msg} in {lab_apk}.")


def build_lab_apk(input_apk: Path, output_path: Path) -> int:
    """Build the dedicated Alex rebalance DEV test APK using Feature 12.02."""
    fwt_patcher._load_env_file()
    args = fwt_patcher.build_parser().parse_args(
        [
            "--all",
            "--dev",
            "--dev-keep-version",
            "--dev-marker",
            "--input",
            str(input_apk),
            "--output",
            str(output_path),
        ]
    )
    rc = fwt_patcher.run_cli(args)
    if rc == 0:
        verify_apk(output_path)
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true", help="verify in-memory datatable patching only")
    parser.add_argument("--verify", action="store_true", help="verify the generated lab APK")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("source/fwt_0.682_offline_v1574.apk"),
        help="reference base APK path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(f"output/FWT-Reborn-Alex-Rebalance-Lab-{APP_VERSION}-dev.apk"),
        help="output APK path",
    )
    parsed = parser.parse_args()
    if parsed.verify_only:
        verify_only(parsed.input)
        return 0
    if parsed.verify:
        verify_apk(parsed.output)
        return 0
    return build_lab_apk(parsed.input, parsed.output)


if __name__ == "__main__":
    raise SystemExit(main())
