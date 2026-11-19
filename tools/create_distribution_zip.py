#!/usr/bin/env python3
"""FWT Reborn - Distribution Archive Generator.

Packages the patcher suite into a clean, distributable ZIP archive.
Generated filenames always include the patcher version
(`FWT-Reborn-Patcher-Suite-<version>.zip`).
Can create:
  1. Clean modding suite (code + GUI launcher + docs, without proprietary APKs).
  2. Patched game package (suite + local versioned patched APK for personal archival).
  3. Standalone patched APK only (no ZIP wrapper).
"""

from __future__ import annotations

import argparse
import shutil
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.core_patches import DEV_OUTPUT_SUFFIX, is_dev_output_path
from core.patch_inspector import inspect_apk, verify_release_report
from core.version import versioned_output_path

EXCLUDE_DIRS = {
    "__pycache__",
    ".git",
    ".github",
    ".venv",
    "venv",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".gemini",
    "backups",
    "keystore",
    "dist",
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".idsig",
    ".jar",
    ".apk",
    ".so",
    ".dex",
    ".dat",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".jks",
    ".keystore",
    ".pem",
    ".key",
    ".p12",
    ".crt",
    ".pfx",
    ".bak",
    ".orig",
    ".swp",
    ".env",
}

_FIXED_DATE = (1980, 1, 1, 0, 0, 0)


def _refuse_dev_build(path: Path) -> None:
    """A dev build must never be packaged into a distribution artifact."""
    if is_dev_output_path(path):
        print(
            f"[ERROR] {path.name} is a dev build (its name ends with "
            f"'{DEV_OUTPUT_SUFFIX}') and must never be distributed. Generate a "
            "release build without --dev and package that instead.",
            file=sys.stderr,
        )
        sys.exit(1)


def _add_file(zf: zipfile.ZipFile, path: Path, arcname: str, *, stored: bool = False) -> None:
    """Adds a member with a stable timestamp (reproducible archive hashes)."""
    info = zipfile.ZipInfo(arcname, date_time=_FIXED_DATE)
    info.create_system = 3
    info.external_attr = 0o644 << 16
    info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with path.open("rb") as src, zf.open(info, "w") as dst:
        shutil.copyfileobj(src, dst, length=8 * 1024 * 1024)


def default_patched_apk_path() -> Path:
    """Returns the canonical versioned release APK path under output/."""
    return versioned_output_path(
        PROJECT_ROOT / "output" / "FWT-Reborn-Patched.apk",
        dev=False,
    )


def build_suite_zip(
    output_path: Path,
    include_patched_apk: bool = False,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    patched_apk = default_patched_apk_path()
    if include_patched_apk and not patched_apk.is_file():
        sys.exit(f"[ERROR] --include-patched-apk requested but {patched_apk} is missing.")
    if include_patched_apk:
        _refuse_dev_build(patched_apk)
        _verify_release_apk(patched_apk)

    root_files = [
        "fwt_patcher.py",
        "run_gui.bat",
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "pyproject.toml",
        "requirements.txt",
        ".env.example",
    ]
    missing = [name for name in root_files if not (PROJECT_ROOT / name).is_file()]
    if missing:
        sys.exit(f"[ERROR] Required distribution files are missing: {', '.join(missing)}")

    temporary = output_path.with_name(output_path.name + ".tmp")
    temporary.unlink(missing_ok=True)
    print(f"Creating distribution archive: {output_path.name}")
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as zf:
            for name in root_files:
                file_path = PROJECT_ROOT / name
                print(f"  + {name}")
                _add_file(zf, file_path, f"fwt-reborn-suite/{name}")

            for folder in ["core", "gui", "tools", "docs", "scripts"]:
                folder_path = PROJECT_ROOT / folder
                if not folder_path.is_dir():
                    continue
                for p in sorted(folder_path.rglob("*")):
                    rel_parts = p.relative_to(folder_path).parts
                    if any(part in EXCLUDE_DIRS for part in rel_parts):
                        continue
                    if p.suffix.lower() in EXCLUDE_EXTENSIONS or p.name.lower().endswith(".local.json"):
                        continue
                    if p.is_symlink() or not p.is_file():
                        continue
                    if p.resolve() == output_path.resolve() or p.resolve() == temporary.resolve():
                        continue
                    rel = p.relative_to(PROJECT_ROOT)
                    _add_file(zf, p, f"fwt-reborn-suite/{rel.as_posix()}")

            readme_text = (
                "Place the base offline Korean APK here:\n"
                "Filename: fwt_0.682_offline_v1574.apk\n\n"
                "Then run 'run_gui.bat' (Windows) or 'python fwt_patcher.py --gui'.\n"
            )
            zf.writestr("fwt-reborn-suite/source/README.txt", readme_text)

            if include_patched_apk:
                print(
                    f"  + Including patched APK: {patched_apk.name} "
                    f"({patched_apk.stat().st_size / (1024 * 1024):.1f} MiB)"
                )
                _add_file(
                    zf,
                    patched_apk,
                    f"fwt-reborn-suite/output/{patched_apk.name}",
                    stored=True,
                )

        # Verify the central directory and member CRCs before publishing the artifact.
        with zipfile.ZipFile(temporary) as check:
            bad = check.testzip()
            if bad is not None:
                raise RuntimeError(f"Archive verification failed for {bad}")
        temporary.replace(output_path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"[SUCCESS] Archive ready: {output_path} ({size_mb:.2f} MiB)\n")


def _verify_release_apk(apk: Path) -> None:
    problems = verify_release_report(inspect_apk(apk))
    if problems:
        print("[ERROR] Patched APK failed verification: " + "; ".join(problems), file=sys.stderr)
        sys.exit(1)


def stage_apk_only(output_path: Path) -> None:
    """Keeps the standalone APK as-is; no ZIP wrapper is produced."""
    patched_apk = default_patched_apk_path()
    if not patched_apk.is_file():
        print(
            f"[ERROR] Patched APK not found at {patched_apk}. Please generate it first.",
            file=sys.stderr,
        )
        sys.exit(1)
    _refuse_dev_build(patched_apk)
    _refuse_dev_build(output_path)
    _verify_release_apk(patched_apk)

    if output_path.resolve() != patched_apk.resolve():
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(patched_apk, output_path)
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"[SUCCESS] Standalone APK ready: {output_path} ({size_mb:.2f} MiB)\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="FWT Reborn Distribution Archive Generator")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help=(
            "Destination path. The current patcher version is appended to the "
            "filename when it is not already present. Defaults to "
            "output/FWT-Reborn-Patcher-Suite-<version>.zip"
        ),
    )
    parser.add_argument(
        "--include-patched-apk",
        action="store_true",
        help=f"Include local output/{default_patched_apk_path().name} inside the archive (for personal archival only; do not redistribute)",
    )
    parser.add_argument(
        "--apk-only",
        action="store_true",
        help="Keep/copy only the versioned patched APK (no ZIP wrapper)",
    )

    args = parser.parse_args()

    if args.apk_only:
        out = versioned_output_path(args.output or default_patched_apk_path(), dev=False)
        stage_apk_only(out)
    else:
        out = versioned_output_path(
            args.output
            or (PROJECT_ROOT / "output" / "FWT-Reborn-Patcher-Suite.zip")
        )
        build_suite_zip(
            out,
            include_patched_apk=args.include_patched_apk,
        )


if __name__ == "__main__":
    main()
