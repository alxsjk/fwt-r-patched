from __future__ import annotations

from dataclasses import fields
from pathlib import Path

from core.core_patches import PatchOptions
from core.patch_inspector import (
    FeatureReport,
    InspectionReport,
    _reconcile_limit_break_reports,
    expected_feature_keys,
    verify_report,
)
from core.version import APP_RELEASE_DATE, APP_VERSION

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Build plumbing / mode switches verified outside one-to-one feature keys:
# - lan_redirect is checked via "network_mode" + "dex_backup_prompt"
# - stamina_cashback is intentionally a no-op stub blocked by verify_report
_NON_FEATURE_FIELDS = frozenset(
    {
        "input_apk",
        "output_apk",
        "server_ip",
        "server_port",
        "dev",
        "align_16k",
        "allow_unknown",
        "stamina_cashback",
        "lan_redirect",
    }
)

# Non-boolean feature fields enabled with a representative positive scale value.
_INTEGER_FEATURE_SCALES: dict[str, int] = {
    "equipment_option_factor": 10,
    "rune_quality_factor": 10,
}


def test_every_feature_patch_option_is_verifiable() -> None:
    kwargs: dict[str, object] = {}
    feature_fields: set[str] = set()
    for item in fields(PatchOptions):
        if item.name in _NON_FEATURE_FIELDS:
            continue
        if isinstance(item.default, bool):
            kwargs[item.name] = True
            feature_fields.add(item.name)
        elif item.name in _INTEGER_FEATURE_SCALES:
            kwargs[item.name] = _INTEGER_FEATURE_SCALES[item.name]
            feature_fields.add(item.name)
        else:
            raise AssertionError(
                f"Uncategorized PatchOptions field {item.name!r} "
                f"(default={item.default!r}); add it to _INTEGER_FEATURE_SCALES "
                "or _NON_FEATURE_FIELDS."
            )

    all_on = PatchOptions(**kwargs)  # type: ignore[arg-type]
    keys = set(expected_feature_keys(all_on))
    missing = feature_fields - keys
    assert not missing, f"options without an inspector check: {sorted(missing)}"

    # LAN redirect must also require network/backup inspection checks.
    lan_keys = set(expected_feature_keys(PatchOptions(lan_redirect=True)))
    assert {"network_mode", "dex_backup_prompt"} <= lan_keys


def test_limit_break_profile_reconciliation_gates_verify_report() -> None:
    profile_key = "limit_break_cost_tenth"
    features = {
        profile_key: FeatureReport(
            name=profile_key,
            active=True,
            status="Patched",
            details="SO patched",
        ),
        "no_win_box": FeatureReport(
            name="no_win_box",
            active=True,
            status="Active",
            details="always-on bug fix",
        ),
        "hero_exp_cap": FeatureReport(
            name="hero_exp_cap",
            active=True,
            status="Active",
            details="always-on bug fix",
        ),
        "convert_hex_guard": FeatureReport(
            name="convert_hex_guard",
            active=True,
            status="Active",
            details="always-on bug fix",
        ),
    }
    _reconcile_limit_break_reports(
        features,
        client_profile="stock",
        client_details="limitbreakcost stock",
    )
    assert features[profile_key].active is False

    mismatch_report = InspectionReport(
        is_valid_apk=True,
        has_so=True,
        has_dex=True,
        alignment_16k=True,
        is_signed=True,
        dex_checksum_valid=True,
        features=features,
    )
    opts = PatchOptions(limit_break_cost_tenth=True)
    problems = verify_report(mismatch_report, opts)
    assert problems, "verify_report accepted mismatched client table"

    matching = {
        profile_key: FeatureReport(
            name=profile_key,
            active=True,
            status="Patched",
            details="SO patched",
        )
    }
    _reconcile_limit_break_reports(
        matching,
        client_profile=profile_key,
        client_details="limitbreakcost patched",
    )
    assert matching[profile_key].active is True


def _version_key(version: str) -> tuple[int, ...]:
    """Numeric prefix of a version, so ``2.5.39rc1`` sorts as ``(2, 5, 39)``."""
    base = ""
    for char in version:
        if not (char.isdigit() or char == "."):
            break
        base += char
    return tuple(int(part) for part in base.split("."))


def test_changelog_order_and_release_date_match_the_version() -> None:
    text = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    entries: list[tuple[tuple[int, ...], str]] = []
    for line in text.splitlines():
        if line.startswith("## [") and "] - " in line:
            version, date = line[4:].split("] - ", 1)
            entries.append((_version_key(version), date))
    assert entries, "no released changelog entries"
    assert entries[0][0] == _version_key(APP_VERSION)
    assert entries[0][1] == APP_RELEASE_DATE
    assert entries == sorted(entries, reverse=True), "changelog versions are not descending"
