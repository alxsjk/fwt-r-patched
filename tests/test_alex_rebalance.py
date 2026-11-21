"""Unit and APK integration tests for Feature 12.02 (Alex skill/passive/awake rebalance)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from core.alex_awakening_assets import (
    _PATH as REBIRTH_PATH,
)
from core.alex_awakening_assets import (
    _patch_gate as patch_awakening_gate,
)
from core.alex_awakening_assets import (
    inspect_alex_awakening_assets,
)
from core.alex_awakening_assets import (
    prepare_assets as prepare_awakening_assets,
)
from core.alex_rebalance import (
    ALEX_AWAKE_DAMAGE_EFFECT_ID,
    ALEX_AWAKE_SKILL_ID,
    ALEX_PASSIVE_ID,
    ALEX_SKILL_1_ID,
    ALEX_SKILL_2_ID,
    ALEX_SKILL_3_ID,
    AWAKE_EFFECT_IDS,
    AWAKE_THORNBUSH_TOOLTIP,
    BASE_EFFECT_IDS,
    DONOR_COOP_UTILITY_EFFECT,
    DONOR_DR_DOWN_RATE_EFFECT,
    DONOR_PASSIVE_ALL_DMG_REDUCE,
    DONOR_PASSIVE_FINAL_POWER_BUFF,
    DONOR_SWAP_EFFECT_ID,
    DONOR_TILE_CHANGE_THORNBUSH,
    IAN_COOP_EFFECT_ID,
    NEW_AWAKE_THORNBUSH_ID,
    NEW_COOP_UTILITY_10_25_ID,
    NEW_DR_DOWN_RATE_EFFECT_ID,
    NEW_PASSIVE_ALLY_DR_5_25_ID,
    NEW_PASSIVE_COOP_20_ID,
    NEW_PASSIVE_DEBUFF_10_ID,
    SKILLDATA_PATH_RE,
    _read_rows,
    build_rebalance_effect_rows,
    expected_skill_updates,
    inspect_alex_rebalance_assets,
    prepare_alex_rebalance_assets,
)
from core.apk_tooling import needs_resource_archive_patch
from core.core_patches import PatchOptions
from fwt_patcher import _has_selected_feature, build_parser


def _donor_map() -> dict[int, dict[str, object]]:
    template = {
        "_skillEffectId": 0,
        "_effectTarget": 1,
        "_precondition": -1,
        "_preconValue": 0.0,
        "_preconValue2": -1,
        "_effectValue": 0.0,
        "_effectValueFactor": 0.0,
    }
    return {
        donor_id: {**template, "_skillEffectId": donor_id}
        for donor_id in (
            DONOR_DR_DOWN_RATE_EFFECT,
            DONOR_COOP_UTILITY_EFFECT,
            DONOR_PASSIVE_FINAL_POWER_BUFF,
            DONOR_PASSIVE_ALL_DMG_REDUCE,
            DONOR_TILE_CHANGE_THORNBUSH,
        )
    }


def test_expected_skill_updates_geometry_effects_and_tooltips() -> None:
    en_path = "files/Resources/datatable/skilldataenglish.unity3d"
    jp_path = "files/Resources/datatable/skilldatajapanese.unity3d"
    ko_path = "files/Resources/datatable/skilldatakorean.unity3d"

    s1 = expected_skill_updates(en_path, ALEX_SKILL_1_ID, "stock")
    assert (s1["_range"], s1["_skillRangeType"], s1["_skillEffectRange"], s1["_skillEffectRangeType"]) == (5, 13, 5, 19)
    assert s1["_effect02"] == IAN_COOP_EFFECT_ID
    assert "@3-3" in s1["_tooltip"]

    s2 = expected_skill_updates(en_path, ALEX_SKILL_2_ID, "stock")
    assert (s2["_range"], s2["_skillRangeType"], s2["_skillEffectRange"], s2["_skillEffectRangeType"]) == (5, 13, 5, 19)
    assert s2["_effect01"] == NEW_DR_DOWN_RATE_EFFECT_ID
    assert s2["_effect03"] == NEW_COOP_UTILITY_10_25_ID

    s3 = expected_skill_updates(en_path, ALEX_SKILL_3_ID, "stock")
    assert (s3["_range"], s3["_skillRangeType"]) == (3, 13)
    assert (s3["_skillEffectRange"], s3["_skillEffectRangeType"]) == (3, 8)
    assert s3["_effect02"] == NEW_COOP_UTILITY_10_25_ID

    passive = expected_skill_updates(en_path, ALEX_PASSIVE_ID, "stock")
    assert (passive["_effect01"], passive["_effect02"], passive["_effect03"], passive["_effect04"]) == (
        NEW_PASSIVE_DEBUFF_10_ID,
        NEW_PASSIVE_COOP_20_ID,
        NEW_PASSIVE_ALLY_DR_5_25_ID,
        -1,
    )

    awake = expected_skill_updates(en_path, ALEX_AWAKE_SKILL_ID, "stock")
    assert (awake["_skillEffectRange"], awake["_skillEffectRangeType"]) == (0, 0)
    assert (awake["_turnStart"], awake["_turnEnd"]) == (0, 99)
    assert (awake["_effect01"], awake["_effect02"], awake["_effect03"]) == (
        ALEX_AWAKE_DAMAGE_EFFECT_ID,
        DONOR_SWAP_EFFECT_ID,
        NEW_AWAKE_THORNBUSH_ID,
    )
    assert "within 1 cell around the Boss" in awake["_tooltip"]
    assert awake["_tooltip"] == AWAKE_THORNBUSH_TOOLTIP

    assert expected_skill_updates(jp_path, ALEX_SKILL_1_ID, "foo@2-3")["_tooltip"] == "foo@3-3"
    assert expected_skill_updates(ko_path, ALEX_SKILL_1_ID, "-1")["_tooltip"] == "-1"

    with pytest.raises(ValueError, match="Unsupported skill ID"):
        expected_skill_updates(en_path, 999999, "-1")


def test_build_rebalance_effect_rows_standalone_and_combined() -> None:
    donors = _donor_map()

    standalone = build_rebalance_effect_rows(donors, include_awake=False)
    assert tuple(row["_skillEffectId"] for row in standalone) == BASE_EFFECT_IDS
    by_id = {row["_skillEffectId"]: row for row in standalone}

    # Check Lv 1 and Lv 10 (val + 9 * factor) float32 behavior
    dr_down = by_id[NEW_DR_DOWN_RATE_EFFECT_ID]
    assert dr_down["_effectValue"] + 9.0 * dr_down["_effectValueFactor"] == pytest.approx(-0.30, abs=1e-6)

    coop_10_25 = by_id[NEW_COOP_UTILITY_10_25_ID]
    assert coop_10_25["_precondition"] == 78
    assert coop_10_25["_effectValue"] + 9.0 * coop_10_25["_effectValueFactor"] == pytest.approx(0.25, abs=1e-6)

    p_coop = by_id[NEW_PASSIVE_COOP_20_ID]
    assert (p_coop["_effectTarget"], p_coop["_precondition"]) == (0, 78)
    assert p_coop["_effectValue"] == pytest.approx(0.20, abs=1e-6)

    p_dr = by_id[NEW_PASSIVE_ALLY_DR_5_25_ID]
    assert (p_dr["_effectTarget"], p_dr["_precondition"], p_dr["_preconValue"]) == (0, 72, 2.0)
    assert p_dr["_effectValue"] == pytest.approx(-0.05, abs=1e-6)
    assert p_dr["_effectValue"] + 9.0 * p_dr["_effectValueFactor"] == pytest.approx(-0.25, abs=1e-6)

    p_debuff = by_id[NEW_PASSIVE_DEBUFF_10_ID]
    assert (p_debuff["_effectTarget"], p_debuff["_precondition"]) == (0, 39)
    assert p_debuff["_effectValue"] == pytest.approx(0.10, abs=1e-6)

    combined = build_rebalance_effect_rows(donors, include_awake=True)
    assert tuple(row["_skillEffectId"] for row in combined) == BASE_EFFECT_IDS + AWAKE_EFFECT_IDS
    assert len(combined) == 6
    c_by_id = {row["_skillEffectId"]: row for row in combined}
    assert c_by_id[NEW_AWAKE_THORNBUSH_ID]["_effectValue"] == pytest.approx(5.0, abs=1e-6)
    assert c_by_id[NEW_AWAKE_THORNBUSH_ID]["_precondition"] == -1


def test_cli_flag_and_resource_archive_detection() -> None:
    args = build_parser().parse_args(["--alex-rebalance"])
    assert args.alex_rebalance is True
    assert _has_selected_feature(PatchOptions(alex_rebalance=args.alex_rebalance)) is True
    assert needs_resource_archive_patch(PatchOptions(alex_rebalance=True)) is True


def _build_patched_resource_zip(
    source_resources: zipfile.ZipFile,
    replacements: dict[str, bytes],
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for name, data in replacements.items():
            out.writestr(name, data)
        # Keep any non-replaced skilldata/skilleffecttable paths if subsetted
        for name in source_resources.namelist():
            if name not in replacements and (
                "skilldata" in name or "skilleffecttable" in name or name == REBIRTH_PATH
            ):
                out.writestr(name, source_resources.read(name))
    return buf.getvalue()


@pytest.mark.integration
def test_rebalance_standalone_all_16_tables_and_idempotent(reference_apk: Path) -> None:
    with (
        zipfile.ZipFile(reference_apk) as outer,
        outer.open("assets/fwt_resources_v1.zip") as stream,
        zipfile.ZipFile(stream) as resources,
    ):
        assert inspect_alex_rebalance_assets(resources)[0] is False
        replacements = prepare_alex_rebalance_assets(resources)
        assert len(replacements) == 16
        for path, bundle in replacements.items():
            if not SKILLDATA_PATH_RE.fullmatch(path):
                continue
            stock = {row.get("_skillId"): row for row in _read_rows(resources.read(path))}
            patched = {row.get("_skillId"): row for row in _read_rows(bundle)}
            alex = patched[ALEX_SKILL_3_ID]
            jakyak = stock[1056868]  # Do not Chase me
            assert (alex["_range"], alex["_skillRangeType"]) == (
                jakyak["_range"], jakyak["_skillRangeType"]
            ), path
            assert (alex["_skillEffectRange"], alex["_skillEffectRangeType"]) == (
                stock[ALEX_SKILL_3_ID]["_skillEffectRange"],
                stock[ALEX_SKILL_3_ID]["_skillEffectRangeType"],
            ), path
            assert patched[1056868] == jakyak, path

        patched_bytes = _build_patched_resource_zip(resources, replacements)
        with zipfile.ZipFile(io.BytesIO(patched_bytes)) as patched_zip:
            ok, msg = inspect_alex_rebalance_assets(patched_zip)
            assert ok is True, msg
            assert "16 tables" in msg
            assert prepare_alex_rebalance_assets(patched_zip) == {}


@pytest.mark.integration
def test_rebalance_combined_with_alex_awakening_thornbush_and_compat(reference_apk: Path) -> None:
    with (
        zipfile.ZipFile(reference_apk) as outer,
        outer.open("assets/fwt_resources_v1.zip") as stream,
        zipfile.ZipFile(stream) as resources,
    ):
        awake_replacements = {
            **prepare_awakening_assets(resources),
            REBIRTH_PATH: patch_awakening_gate(resources.read(REBIRTH_PATH)),
        }
        rebalance_replacements = prepare_alex_rebalance_assets(
            resources,
            existing_replacements=awake_replacements,
        )
        assert len(rebalance_replacements) == 16
        merged = {**awake_replacements, **rebalance_replacements}

        patched_bytes = _build_patched_resource_zip(resources, merged)
        with zipfile.ZipFile(io.BytesIO(patched_bytes)) as patched_zip:
            rebal_ok, rebal_msg = inspect_alex_rebalance_assets(patched_zip)
            awake_ok, awake_msg = inspect_alex_awakening_assets(patched_zip)
            assert rebal_ok is True, rebal_msg
            assert awake_ok is True, awake_msg
            assert "Thornbush" in rebal_msg
            assert prepare_alex_rebalance_assets(patched_zip) == {}
