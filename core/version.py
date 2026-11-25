"""Single source of truth for the FWT Reborn Patch version and metadata."""

from __future__ import annotations

import re
from pathlib import Path

APP_NAME = "FWT Reborn Patch"
APP_VERSION = "2.5.59"
BUILD_IDENTITY_ENTRY = "assets/fwt_re_patched_build_type.txt"
APP_VERSION_DISPLAY = f"v{APP_VERSION}"
APP_RELEASE_DATE = "2026-11-25"
APP_REPO_URL = "https://github.com/alxsjk/fwt-r-patched"
APP_BASE_GAME = "Fantasy War Tactics 0.682 (v1574)"
APP_LICENSE = "MIT"
APP_DESCRIPTION = (
    "Offline client patcher, feature injector, APK alignment/signing and "
    "savegame tooling for Fantasy War Tactics."
)
APP_DISCLAIMER = (
    "Fan-made offline preservation tooling. Use only with game data you own. "
    "Not affiliated with Nexon, VALOFE or the original rights holders."
)


RELEASE_OUTPUT_SUFFIX = "-release"


def versioned_output_path(path: Path, *, dev: bool = False) -> Path:
    """Ensures generated archives/APKs carry the patcher version and a release/dev marker.

    Dev builds carry ``-dev`` and release builds carry ``-release``. Release
    packaging also checks the signed internal identity and validates the APK.
    """
    name = path.stem
    if not re.search(rf"(?<![\d.]){re.escape(APP_VERSION)}(?![\d.])", name):
        name = f"{name}-{APP_VERSION}"
    # Only APKs carry the build-kind marker: the patcher suite zip is not a build of the
    # game and must keep its plain name.
    if path.suffix.lower() == ".apk":
        marker = "-dev" if dev else RELEASE_OUTPUT_SUFFIX
        if marker not in name:
            name = f"{name}{marker}"
    return path.with_name(f"{name}{path.suffix}")
